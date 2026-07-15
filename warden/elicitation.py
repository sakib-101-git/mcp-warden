"""Elicitation gate — pause a sensitive call for a human, then honor the answer.

Some calls should never happen on the model's say-so alone: writing a file,
sending an email, spending money, touching production. Policy tags those
`elicit` (Phase 3). This layer is what `elicit` *means* in practice: the call
does not proceed until a human approves it, and if the human denies it, it is
blocked — every resolution recorded.

The mechanism is one `asyncio.Event` per parked call:

    seam → gate.create(...)          # a pending record + an unset Event
         → gate.wait(id)             # the call's coroutine parks on the Event
    human → gate.resolve(id, yes/no) # sets the Event; wait() wakes and returns

Two surfaces can call `resolve`, and the gate does not care which:
  * **Native MCP Elicitation** toward the host — when the host supports it,
    Warden asks it directly and the host's own approve/deny UI answers. The seam
    fires this and funnels the result into `resolve`.
  * **Out-of-band** — the Phase 8 dashboard's Approve/Deny buttons (and, today,
    the verify script and tests) call `resolve` directly.

Whichever answers first wins; the other becomes an idempotent no-op. And the
gate FAILS CLOSED: a call nobody answers within the timeout is denied, not left
hanging and never silently approved (CLAUDE.md invariant 5).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from warden.verdicts import Decision, Verdict

log = logging.getLogger("warden.elicitation")


@dataclass
class Pending:
    """One call parked awaiting a human decision."""

    id: str
    server: str
    tool: str
    agent: str
    args_summary: str
    what_will_happen: str
    created: float = field(default_factory=time.time)
    # Resolution state. `approved` stays None until someone answers.
    approved: bool | None = None
    resolved_by: str = ""
    _event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)

    def public(self) -> dict[str, Any]:
        """The shape the dashboard/API (Phase 8) reads — no internals."""
        return {
            "id": self.id,
            "server": self.server,
            "tool": self.tool,
            "agent": self.agent,
            "args_summary": self.args_summary,
            "what_will_happen": self.what_will_happen,
            "created": self.created,
        }


class ElicitationGate:
    """The pending-approvals queue and its resolve/await machinery."""

    def __init__(self, default_timeout: float | None = None) -> None:
        # None here = wait indefinitely; main.py sets a real ceiling so a live
        # call can't park forever. Tests want None (they resolve explicitly) or a
        # tiny value (to exercise the timeout).
        self.default_timeout = default_timeout
        self._pending: dict[str, Pending] = {}

    # ---- create / inspect ----------------------------------------------------

    def create(
        self,
        *,
        server: str,
        tool: str,
        agent: str,
        arguments: dict[str, Any] | None = None,
        what_will_happen: str | None = None,
    ) -> Pending:
        """Register a call as pending and return its record (Event unset)."""
        pending = Pending(
            id=uuid.uuid4().hex[:12],
            server=server,
            tool=tool,
            agent=agent,
            args_summary=_summarize_args(arguments or {}),
            what_will_happen=what_will_happen or _describe(server, tool, arguments or {}),
        )
        self._pending[pending.id] = pending
        log.info("PENDING %s — %s/%s by %s: %s", pending.id, server, tool, agent, pending.what_will_happen)
        return pending

    def pending_list(self) -> list[dict[str, Any]]:
        """Everything still awaiting a human, oldest first (dashboard order)."""
        return [p.public() for p in sorted(self._pending.values(), key=lambda p: p.created)]

    def get(self, pending_id: str) -> Pending | None:
        return self._pending.get(pending_id)

    # ---- resolve / await -----------------------------------------------------

    def resolve(self, pending_id: str, approved: bool, resolved_by: str = "") -> bool:
        """Answer a pending call. Returns True if this call actually resolved it,
        False if the id is unknown or it was already answered.

        Idempotent by design: native elicitation and the dashboard can race, and
        the loser must not flip an already-made decision."""
        pending = self._pending.get(pending_id)
        if pending is None:
            log.warning("resolve() for unknown/expired pending id %r — ignored", pending_id)
            return False
        if pending.approved is not None or pending._event.is_set():
            log.info("resolve() for %s ignored — already %s", pending_id,
                     "approved" if pending.approved else "resolved")
            return False
        pending.approved = approved
        pending.resolved_by = resolved_by or "unknown"
        pending._event.set()
        log.info("RESOLVED %s — %s by %s", pending_id, "APPROVED" if approved else "DENIED", pending.resolved_by)
        return True

    async def wait(self, pending_id: str, timeout: float | None = ...) -> Decision:  # type: ignore[assignment]
        """Park until the call is resolved (or times out), then return the
        Decision the seam acts on: ALLOWED → forward, BLOCKED → refuse."""
        pending = self._pending.get(pending_id)
        if pending is None:
            # Nothing to wait for — treat as fail-closed rather than hang.
            return Decision(Verdict.BLOCKED, reason=f"no pending call with id {pending_id}",
                            layer="elicitation")

        eff_timeout = self.default_timeout if timeout is ... else timeout
        try:
            await asyncio.wait_for(pending._event.wait(), timeout=eff_timeout)
        except asyncio.TimeoutError:
            # Fail closed: a call no human answered in time is denied, never
            # waved through. Drop it from the queue so it can't be resolved late.
            self._pending.pop(pending_id, None)
            log.warning("TIMEOUT %s — denied after %ss with no human response", pending_id, eff_timeout)
            return Decision(
                verdict=Verdict.BLOCKED,
                reason=f"no human response within {eff_timeout}s — failing closed (denied)",
                layer="elicitation",
                server=pending.server, tool=pending.tool, agent=pending.agent,
                details={"pending_id": pending_id, "timeout": eff_timeout},
            )

        approved = bool(pending.approved)
        self._pending.pop(pending_id, None)  # resolved calls leave the queue
        verdict = Verdict.ALLOWED if approved else Verdict.BLOCKED
        return Decision(
            verdict=verdict,
            reason=(
                f"human {'approved' if approved else 'denied'} the call "
                f"({pending.resolved_by})"
            ),
            layer="elicitation",
            server=pending.server, tool=pending.tool, agent=pending.agent,
            details={
                "pending_id": pending_id,
                "approved": approved,
                "resolved_by": pending.resolved_by,
                "what_will_happen": pending.what_will_happen,
            },
        )


# ---- helpers -----------------------------------------------------------------


def _summarize_args(arguments: dict[str, Any], limit: int = 200) -> str:
    """A compact, human-readable one-liner of the arguments for the queue."""
    try:
        s = json.dumps(arguments, default=str, separators=(", ", ": "))
    except (TypeError, ValueError):
        s = str(arguments)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _describe(server: str, tool: str, arguments: dict[str, Any]) -> str:
    """Plain-language 'what will happen' when the seam doesn't supply one.

    Deliberately generic — the seam can pass a better sentence for known tools
    (e.g. 'write 412 bytes to /work/out.txt'), but a sensible default means a
    brand-new elicited tool still shows the human something legible."""
    return f"Run {tool!r} on server {server!r} with arguments: {_summarize_args(arguments)}"
