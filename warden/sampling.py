"""Sampling meta-review — an out-of-band LLM that judges call *sequences*.

The deterministic layers (integrity, policy, inspector) each look at ONE call at
a time. But some attacks only exist in the shape of a *sequence*: a broad sweep
of reads across the filesystem, then one write to an external endpoint. No single
call is against policy; the pattern is the attack. That is what this layer
watches for.

It is a meta-reviewer: a model that does not perform the task, but reads a trace
of tasks already performed and asks "does this look like exfiltration or
privilege escalation?". Deliberately layered ON TOP of the deterministic checks, never instead
of them — a model can be fooled by a sufficiently obfuscated sequence, so this is
depth, not a gate.

TWO PROPERTIES make it safe to run:

  * It is **out of band**. It reads the audit ledger on a schedule (every N
    calls); it is NEVER on the live call path. A slow or failing reviewer cannot
    delay, block, or break a tool call — the worst it can do is not run. That is
    also why it's periodic: reviewing every single call would blow through a Pro
    plan's usage and add latency to every action for a check that only has signal
    across a window.
  * It sees **shape, not payloads**. The ledger stores only hashes of arguments
    and results, and the summary this layer builds uses just server/tool/verdict
    — never `reason` text (which can carry a matched snippet) and never an
    argument value. Nothing sensitive is sent to the model.

A YES raises a `sampling_flag` — an audit event and a dashboard anomaly — nothing
more. It is a signal to a human, not an automatic block.

BACKENDS. Which model runs the judgment is pluggable and all-$0 for a Pro user:
native MCP Sampling back through the host, the `claude` CLI on the subscription,
a local Ollama model, or a free hosted tier — hidden behind one interface, with a
deterministic stub for tests and a null backend that disables the feature
cleanly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

from warden.verdicts import Decision, Verdict

log = logging.getLogger("warden.sampling")

SYSTEM_PROMPT = (
    "You are a security meta-reviewer for an MCP tool-call gateway. You will be "
    "shown a short, anonymized trace of recent tool calls (server, tool, and the "
    "gateway's verdict — never any argument values or results). Decide whether the "
    "SEQUENCE looks like data exfiltration or privilege escalation: for example a "
    "broad sweep of reads followed by an external write, or repeated attempts to "
    "reach tools that keep getting blocked. Answer with a single line beginning "
    "with YES or NO, followed by one short sentence of reasoning. Be conservative: "
    "only answer YES if the pattern is genuinely suspicious."
)


@dataclass
class SamplingResult:
    suspicious: bool
    reason: str
    backend: str


def parse_yes_no(text: str) -> tuple[bool, str]:
    """Pull a YES/NO + reasoning out of a model completion, tolerantly."""
    stripped = (text or "").strip()
    first = stripped.splitlines()[0].strip() if stripped else ""
    upper = first.upper()
    if upper.startswith("YES"):
        return True, first[3:].lstrip(" :.-—") or "flagged as suspicious"
    if upper.startswith("NO"):
        return False, first[2:].lstrip(" :.-—") or "not suspicious"
    # Ambiguous output → treat as NOT suspicious (this layer must never raise a
    # flag on a parsing accident; false anomalies erode the signal).
    return False, f"unpar-seable model output, treated as NO: {first[:80]!r}"


# ---- backends ----------------------------------------------------------------


class SamplingBackend(ABC):
    """One way to run the YES/NO judgment. `complete` returns raw model text."""

    name: str = "abstract"

    def is_configured(self) -> bool:
        """Cheap check for whether this backend can actually run (binary present,
        key set, …). A backend that isn't configured disables the reviewer."""
        return True

    @abstractmethod
    async def complete(self, system: str, user: str) -> str: ...


class NullSampling(SamplingBackend):
    """No backend — the feature is off. Chosen when config says so, or when a
    named backend isn't actually available on this machine."""

    name = "null"

    def is_configured(self) -> bool:
        return False

    async def complete(self, system: str, user: str) -> str:  # pragma: no cover
        return "NO (sampling disabled)"


class StubSampling(SamplingBackend):
    """Deterministic, offline. Answers from a preset (or the WARDEN_SAMPLING_STUB
    env var, so a spawned Warden subprocess can be driven too). Used by the tests
    and the verify demo so they never depend on a real model or the network."""

    name = "stub"

    def __init__(self, answer: bool | None = None) -> None:
        if answer is None:
            answer = os.environ.get("WARDEN_SAMPLING_STUB", "no").strip().lower() in ("yes", "y", "1", "true")
        self.answer = answer
        self.calls: list[str] = []  # captured prompts, so tests can assert on them

    async def complete(self, system: str, user: str) -> str:
        self.calls.append(user)
        return ("YES suspicious sweep-then-exfil pattern" if self.answer
                else "NO nothing unusual in this window")


class ClaudeCLISampling(SamplingBackend):
    """Shell out to the `claude` CLI (`claude -p <prompt>`). On a Pro/Max
    subscription with ANTHROPIC_API_KEY UNSET this uses the subscription session,
    so it costs $0. Runs in a thread executor — never blocks the event loop."""

    name = "cli"

    def __init__(self, binary: str = "claude") -> None:
        self.binary = binary

    def is_configured(self) -> bool:
        return shutil.which(self.binary) is not None

    async def complete(self, system: str, user: str) -> str:
        def run() -> str:
            proc = subprocess.run(
                [self.binary, "-p", f"{system}\n\n{user}"],
                capture_output=True, text=True, timeout=60,
            )
            return proc.stdout.strip()

        return await asyncio.to_thread(run)


class OllamaSampling(SamplingBackend):
    """A local model via Ollama's HTTP API. Fully offline, no key. Uses urllib so
    it adds no dependency."""

    name = "ollama"

    def __init__(self, model: str = "llama3.2", host: str = "http://localhost:11434") -> None:
        self.model = model
        self.host = host

    def is_configured(self) -> bool:
        return bool(self.host)

    async def complete(self, system: str, user: str) -> str:
        import urllib.request

        def run() -> str:
            body = json.dumps({
                "model": self.model,
                "prompt": f"{system}\n\n{user}",
                "stream": False,
            }).encode()
            req = urllib.request.Request(f"{self.host}/api/generate", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read()).get("response", "")

        return await asyncio.to_thread(run)


class NativeMCPSampling(SamplingBackend):
    """Ask the HOST to run the completion via MCP Sampling (`create_message`).
    $0 and no key — the host owns the model and the human approves it. Needs a
    live server session that supports sampling; provided by main.py at call time."""

    name = "native"

    def __init__(self, session_provider: Callable[[], Any]) -> None:
        # A callable so we read the CURRENT request session lazily (there isn't
        # one at construction time).
        self._session_provider = session_provider

    def is_configured(self) -> bool:
        return self._session_provider is not None

    async def complete(self, system: str, user: str) -> str:
        import mcp.types as types

        session = self._session_provider()
        if session is None:
            raise RuntimeError("no active session for native sampling")
        result = await session.create_message(
            messages=[types.SamplingMessage(
                role="user", content=types.TextContent(type="text", text=user))],
            max_tokens=200,
            system_prompt=system,
        )
        block = result.content
        return getattr(block, "text", "") if block else ""


def select_backend(name: str, *, session_provider: Callable[[], Any] | None = None) -> SamplingBackend:
    """Map a config string to a backend instance, falling back to NullSampling if
    the requested backend isn't actually available (fail safe: the feature turns
    itself off rather than erroring the gateway)."""
    name = (name or "null").strip().lower()
    candidate: SamplingBackend
    if name == "stub":
        candidate = StubSampling()
    elif name == "cli":
        candidate = ClaudeCLISampling()
    elif name == "ollama":
        candidate = OllamaSampling()
    elif name == "native":
        candidate = NativeMCPSampling(session_provider or (lambda: None))
    else:
        candidate = NullSampling()

    if not candidate.is_configured():
        log.warning("sampling backend %r is not available here — meta-review disabled", name)
        return NullSampling()
    log.info("sampling backend: %s", candidate.name)
    return candidate


# ---- the reviewer ------------------------------------------------------------


def summarize_window(rows: list[dict[str, Any]]) -> str:
    """Build the anonymized trace sent to the model: server/tool/verdict only.

    Deliberately NOT included: `reason` (can carry a matched snippet), args/result
    (only hashes exist in the ledger anyway). What's left is pure shape — enough
    to judge a sequence, nothing sensitive to leak."""
    lines = []
    for i, r in enumerate(rows, 1):
        lines.append(f"{i}. {r['server']}/{r['tool']} → {r['verdict']}")
    return "Recent tool-call trace:\n" + "\n".join(lines)


class MetaReviewer:
    """Periodically judges the recent audit window and raises sampling_flag."""

    def __init__(
        self,
        ledger: Any,
        backend: SamplingBackend,
        on_flag: Callable[[Decision], Any] | None = None,
        *,
        every: int = 20,
        window: int = 30,
    ) -> None:
        self.ledger = ledger
        self.backend = backend
        self.on_flag = on_flag
        self.every = max(1, every)
        self.window = window
        self._since_review = 0
        self._tasks: set[asyncio.Task] = set()

    @property
    def enabled(self) -> bool:
        return not isinstance(self.backend, NullSampling)

    def note_call(self) -> None:
        """Called from the seam after each audited call. Cheap: counts, and every
        `every` calls schedules a review as a BACKGROUND task so the live call
        returns immediately. Never awaits, never blocks."""
        if not self.enabled:
            return
        self._since_review += 1
        if self._since_review >= self.every:
            self._since_review = 0
            task = asyncio.create_task(self._safe_review())
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _safe_review(self) -> None:
        try:
            await self.review_now()
        except Exception:
            # A failing reviewer must never surface into the gateway. Log and move
            # on — the deterministic layers are still doing their job.
            log.exception("meta-review failed — ignoring (out-of-band layer)")

    async def review_now(self) -> SamplingResult | None:
        """Pull the recent window, ask the model, and raise a flag on YES.
        Returns the result (or None if there's nothing to review / feature off)."""
        if not self.enabled:
            return None
        rows = self.ledger.all(limit=self.window)
        if not rows:
            return None

        summary = summarize_window(rows)
        raw = await self.backend.complete(SYSTEM_PROMPT, summary)
        suspicious, why = parse_yes_no(raw)
        result = SamplingResult(suspicious=suspicious, reason=why, backend=self.backend.name)

        if suspicious:
            last = rows[-1]
            decision = Decision(
                verdict=Verdict.SAMPLING_FLAG,
                reason=f"meta-review ({self.backend.name}): {why}",
                layer="sampling",
                server=last.get("server", ""),
                tool=last.get("tool", ""),
                agent=last.get("agent", ""),
                details={"window": len(rows), "backend": self.backend.name},
            )
            log.warning("SAMPLING FLAG raised over the last %d calls: %s", len(rows), why)
            if self.on_flag is not None:
                maybe = self.on_flag(decision)
                if isinstance(maybe, Awaitable):
                    await maybe
        return result

    async def drain(self) -> None:
        """Await any in-flight review tasks — used on shutdown and by tests so a
        scheduled review is allowed to finish."""
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
