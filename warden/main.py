"""Warden entry point — ingress (server role), the seam, and the pipeline.

The host above us sees Warden as an ordinary MCP server. Downstream, Warden is
an ordinary MCP client (`warden/egress.py`). Between those two roles sits THE
SEAM — `handle_call_tool` — where every security layer hooks in, in a fixed
order (docs/02-ARCHITECTURE.md):

    identity → integrity → policy → inspect(args) → [elicit?]
      → FORWARD → inspect(result) → audit append → return

The order is not decorative. Cheap deterministic checks run before expensive
ones, and everything that can refuse a call runs before we hand anything to a
downstream server.

Two invariants this file must never violate:
  * **stdout is the MCP wire.** All logging goes to stderr. One stray print()
    corrupts the JSON-RPC stream.
  * **Fail closed.** If a security layer raises, the call is BLOCKED — never
    waved through. A crashed guard is a locked door, not an open one.

Live: identity (Phase 3), integrity (Phase 2), policy (Phase 3).
Stubs marked inline: inspector (4), elicitation (5), ledger (6), sampling (7).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time

import mcp.types as types
from mcp import StdioServerParameters
from mcp.server import Server
from mcp.server.stdio import stdio_server

from warden.api import EventHub, WardenAPI
from warden.config import Config, ConfigError, load_config
from warden.egress import DownstreamPool, Egress, child_env
from warden.elicitation import ElicitationGate, Pending
from warden.identity import IdentityResolver
from warden.inspector import Inspector
from warden.integrity import IntegrityChecker
from warden.ledger import Ledger
from warden.policy import PolicyEngine
from warden.sampling import MetaReviewer, select_backend
from warden.verdicts import Decision, Verdict, WardenBlocked

# How long a call may sit awaiting a human before Warden denies it (fail closed).
ELICIT_TIMEOUT = float(os.environ.get("WARDEN_ELICIT_TIMEOUT", "600"))

# ---- CRITICAL: logs to stderr, never stdout ---------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[warden] %(name)s: %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("warden.main")

CONFIG_PATH = os.environ.get("WARDEN_CONFIG", "warden.yaml")


def _load() -> Config:
    """Load config or die. There is no 'run without a policy' mode — that would
    be a proxy with the security switched off, which is worse than no proxy at
    all because it looks like protection."""
    try:
        return load_config(CONFIG_PATH)
    except ConfigError as exc:
        log.error("REFUSING TO START — %s", exc)
        raise SystemExit(2) from exc


CFG = _load()

# ---- The layers (constructed once at startup, called from the seam) ----------
POOL = DownstreamPool(
    [
        Egress(
            name=d.name,
            params=StdioServerParameters(
                command=d.command,
                args=d.args,
                env=child_env(d.env),
                cwd=d.cwd,
            ),
        )
        for d in CFG.downstreams
    ]
)
IDENTITY = IdentityResolver(CFG.agents)


def _build_stores():
    """Pin store + audit ledger + rate limiter, chosen by the cluster backend.

    `sqlite` (default) keeps them local — one self-contained instance. `postgres`
    moves pins + the ledger to Postgres (chain globally ordered by an advisory
    lock) and rate-limit counters to Redis, so N Warden instances share one
    consistent, verifiable chain and one fleet-wide rate ceiling. The cluster
    stores are imported lazily, so psycopg/redis are only needed when selected."""
    if CFG.cluster.backend == "postgres":
        from warden.cluster import PgIntegrityChecker, PgLedger, RedisRateLimiter

        log.info("cluster backend: postgres — stateless multi-instance (shared pins/ledger/limits)")
        integrity = PgIntegrityChecker(CFG.cluster.postgres_dsn)
        ledger = PgLedger(CFG.cluster.postgres_dsn)
        limiter = RedisRateLimiter(CFG.cluster.redis_url) if CFG.cluster.redis_url else None
        return integrity, ledger, limiter
    return IntegrityChecker(db_path=CFG.db_path), Ledger(db_path=CFG.db_path), None


INTEGRITY, LEDGER, _RATE_LIMITER = _build_stores()
POLICY = PolicyEngine(CFG.rules, default_action=CFG.default_action, rate_limiter=_RATE_LIMITER)
INSPECTOR = Inspector()
GATE = ElicitationGate(default_timeout=ELICIT_TIMEOUT)

# The dashboard's live event bus. Always constructed (it is cheap and in-memory)
# so the seam can publish unconditionally; if the API is disabled, nobody reads
# it and the ring buffer is simply never drained. The HTTP server itself is
# started in main(), only when configured — the dashboard is additive.
HUB = EventHub()
API: WardenAPI | None = None


def _current_session():
    """The live MCP server session for the in-flight request, or None. Used by
    native sampling (server→client `create_message`). Resolved at call time, so
    referencing `server` (defined below) before it exists is fine."""
    try:
        return server.request_context.session
    except (LookupError, AttributeError):
        return None


# Sampling meta-review (Phase 7): async, out-of-band. `native` reads the current
# request session lazily; every other backend ignores the provider.
SAMPLER = MetaReviewer(
    ledger=LEDGER,
    backend=select_backend(CFG.sampling.backend, session_provider=_current_session),
    on_flag=lambda decision: LEDGER.append(decision),
    every=CFG.sampling.every,
    window=CFG.sampling.window,
)

# ---- Ingress: the MCP server role we present to the host --------------------
server = Server("mcp-warden")


def _agent() -> str:
    """Step 1 of the pipeline: who is calling?

    The host declares `clientInfo` once, at initialize; we map it to an agent
    label through `agents:` in warden.yaml. Outside a request context (or from a
    host that declared nothing) we fall back to the default label — attribution
    degrades, enforcement does not.
    """
    try:
        client = server.request_context.session.client_params
        name = client.clientInfo.name if client and client.clientInfo else None
    except (LookupError, AttributeError):
        name = None
    return IDENTITY.resolve(name)


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """"What tools do you offer?" — every downstream's tools, aggregated,
    minus any whose definition no longer matches its pin.

    Withholding a rug-pulled tool (rather than listing it as disabled) is the
    safest option and the simplest: a tool the model never sees is a tool the
    model cannot be talked into calling. The hidden instruction inside the
    poisoned description never even enters the model's context — which matters,
    because merely *reading* a poisoned description is most of the attack.
    """
    listed = await POOL.list_tools()

    safe: list[types.Tool] = []
    for exposed, server_name, tool in listed:
        try:
            decision = INTEGRITY.check(server_name, tool)
        except Exception as exc:  # fail closed: a broken checker withholds
            log.exception("integrity check failed for %s/%s — withholding", server_name, tool.name)
            decision = Decision(
                verdict=Verdict.BLOCKED,
                reason=f"internal error in integrity: {exc}",
                layer="integrity",
                server=server_name,
                tool=getattr(tool, "name", "?"),
            )
        if decision.blocked:
            log.warning("withholding tool from host (integrity): %s", decision)
            continue
        # Default-deny also governs the tool list: a tool no rule could ever
        # allow is withheld, so the model never sees it and never reads its
        # (possibly poisoned) description. Per-argument constraints still run at
        # call time — this only decides "reachable in principle?".
        if not POLICY.tool_visible(server_name, tool.name):
            log.info("withholding tool from host (default-deny): %s/%s", server_name, tool.name)
            continue
        # Inspector on the METADATA: a tool description is content the model
        # reads as guidance. A hidden instruction in it (attack A1) is caught
        # here — TOFU's first-sight blind spot — and the tool is withheld before
        # its poisoned description ever enters the model's context.
        try:
            meta = INSPECTOR.scan_metadata(tool.description, server=server_name, tool=tool.name)
        except Exception:
            log.exception("inspector metadata scan failed for %s/%s — withholding", server_name, tool.name)
            continue  # fail closed
        if meta.flagged:
            log.warning("withholding tool from host (poisoned description): %s", meta)
            continue
        # Advertise under the exposed (possibly namespaced) name, while the pin
        # and every policy rule stay keyed to the real one.
        safe.append(tool.model_copy(update={"name": exposed}) if exposed != tool.name else tool)

    log.info(
        "list_tools → %d/%d tools exposed (%d withheld by integrity)",
        len(safe),
        len(listed),
        len(listed) - len(safe),
    )
    return safe


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict):
    """THE SEAM. Every security layer hooks in here, in the documented order.

    The whole body runs inside `try/finally` so that step 8 — audit append —
    happens on EVERY exit path: a clean allow, a flag, and every block (which
    leaves via `raise WardenBlocked`). The ledger must be a complete account, so
    "audit only the happy path" is not an option; the finally clause is what
    guarantees a refused call is recorded exactly like an allowed one.
    """
    agent = _agent()  # ---- 1. Identity ---------------------------- (Phase 3)
    log.info("call_tool ← %s: %s(%r)", agent, name, arguments)
    t0 = time.monotonic()  # for the dashboard's per-call latency (whole pipeline)

    # `outcome` is the headline verdict we will audit for this call; `result_text`
    # is what the host actually receives (redacted), hashed into the audit row.
    # On a block we set `outcome` and raise; on success we pick the headline from
    # (result flag > arg flag > elicit-approval > clean allow) just before return.
    outcome: Decision = Decision(Verdict.BLOCKED, reason="pipeline did not complete",
                                 layer="pipeline", tool=name, agent=agent)
    flag_decision: Decision | None = None
    elicit_decision: Decision | None = None
    result_text: str | None = None
    server_name = ""

    try:
        # Resolve the exposed name the host used back to the real (server, tool).
        # Everything downstream reasons about the REAL pair — a policy rule for
        # `test-downstream/read_file` must never be satisfiable by another
        # server's tool of the same name.
        route = await POOL.resolve(name)
        if route is None:
            outcome = Decision(Verdict.BLOCKED, reason=f"no downstream offers a tool named '{name}'",
                               layer="router", tool=name, agent=agent)
            raise WardenBlocked(outcome)
        egress, real_name = route
        server_name = egress.name
        outcome = Decision(Verdict.BLOCKED, reason="pipeline did not complete",
                           layer="pipeline", server=server_name, tool=real_name, agent=agent)

        # ---- 2. Integrity ------------------------------------- (Phase 2) ---
        decision = await _integrity_gate(egress, real_name, agent)
        if decision.blocked:
            outcome = decision
            raise WardenBlocked(decision)

        # ---- 3. Policy ---------------------------------------- (Phase 3) ---
        decision = _policy_gate(server_name, real_name, arguments or {}, agent)
        if decision.blocked:
            outcome = decision
            raise WardenBlocked(decision)

        # ---- 4. Inspect(arguments) ---------------------------- (Phase 4) ---
        # A normal FINDING is flag + audit, not block (dangerous argument
        # *values* are policy's job, via arg_matches); we do not rewrite outgoing
        # arguments, because that would silently change the call. An internal
        # ERROR fails closed (invariant 5).
        try:
            arg_decision = INSPECTOR.scan_arguments(
                arguments or {}, agent=agent, server=server_name, tool=real_name)
            if arg_decision.flagged:
                log.warning("FLAG(outgoing) %s", arg_decision)
                flag_decision = arg_decision
        except Exception as exc:
            log.exception("inspector(arguments) raised — failing closed")
            outcome = Decision(Verdict.BLOCKED, reason=f"internal error in inspector: {exc}",
                               layer="inspector", server=server_name, tool=real_name, agent=agent)
            raise WardenBlocked(outcome) from exc

        # ---- 5. Elicitation gate ------------------------------ (Phase 5) ---
        if decision.verdict is Verdict.PENDING:
            # Policy said this call needs a human. Park it — the coroutine
            # suspends here until someone approves (→ forward) or denies
            # (→ block), or the timeout fires (→ deny, fail closed).
            gate_decision = await _elicit_gate(server_name, real_name, arguments or {}, agent)
            if gate_decision.blocked:
                outcome = gate_decision
                raise WardenBlocked(gate_decision)
            log.info("APPROVED %s", gate_decision)
            elicit_decision = gate_decision  # audit the human approval, not a generic allow

        # ---- 6. Forward -----------------------------------------------------
        result = await egress.call_tool(real_name, arguments)
        content = result.content

        # ---- 7. Inspect(result) ------------------------------- (Phase 4) ---
        # Results are a first-class injection/exfil vector (A4). Flag injection/
        # PII, REDACT secrets in place. A finding flags; an internal ERROR fails
        # closed — we must NOT hand the host an unscanned result that might carry
        # a secret, so we refuse it rather than return the raw content.
        try:
            content, res_decision = INSPECTOR.scan_result(
                content, agent=agent, server=server_name, tool=real_name)
            if res_decision.flagged:
                log.warning("FLAG(incoming) %s", res_decision)
                flag_decision = res_decision  # a result flag outranks an arg flag as the headline
        except Exception as exc:
            log.exception("inspector(result) raised — failing closed (refusing the unscanned result)")
            outcome = Decision(Verdict.BLOCKED, reason=f"internal error scanning result in inspector: {exc}",
                               layer="inspector", server=server_name, tool=real_name, agent=agent)
            raise WardenBlocked(outcome) from exc

        # Headline verdict for the audit row: a flag (if any) is most salient;
        # else the human approval (if this was an elicit call); else a clean allow.
        outcome = flag_decision or elicit_decision or Decision(
            Verdict.ALLOWED, reason="passed all checks", layer="pipeline",
            server=server_name, tool=real_name, agent=agent)

        result_text = _content_text(content)
        # ---- 9. Return ------------------------------------------------------
        log.info("call_tool → %s: %s returned %d content items", agent, name, len(content))
        return content

    finally:
        # ---- 8. Audit append — EVERY verdict, allow or block --- (Phase 6) ---
        row = None
        try:
            row = LEDGER.append(outcome, args=arguments, result_text=result_text)
            # Sampling meta-review (Phase 7): out-of-band. This only COUNTS and may
            # schedule a background review; it never awaits, so it cannot delay or
            # block the call we are returning.
            SAMPLER.note_call()
        except Exception:
            # A failing ledger must not swallow the real result/exception, but it
            # IS a serious problem — surface it loudly rather than silently.
            log.exception("AUDIT APPEND FAILED for %s/%s — decision was %s", server_name, name, outcome)

        # ---- 9. Dashboard event (Phase 8): best-effort, never load-bearing ---
        # Publish the completed call to the live feed. The audit row above is the
        # source of truth; this is a spectator signal, so any failure is swallowed.
        try:
            HUB.record_call({
                "id": row["seq"] if row else None,
                "ts": outcome.ts,
                "server": server_name,
                "tool": outcome.tool or name,
                "agent": agent,
                "verdict": outcome.verdict.value,
                "reason": outcome.reason,
                "latency_ms": int((time.monotonic() - t0) * 1000),
            })
        except Exception:
            log.debug("dashboard event publish failed — ignoring", exc_info=True)


async def _integrity_gate(egress: Egress, tool_name: str, agent: str) -> Decision:
    """Re-read the tool's live definition and compare it to its pin.

    Wrapped so that ANY failure here — downstream unreachable, database locked,
    malformed definition — becomes a block rather than a passthrough
    (CLAUDE.md invariant 5, fail closed).
    """
    try:
        live = await egress.get_tool(tool_name)
        if live is None:
            # The host asked for a tool this downstream does not offer. Either a
            # stale tool list, or a server that advertises one thing and answers
            # to another. Refuse either way.
            return Decision(
                verdict=Verdict.BLOCKED,
                reason=f"tool '{tool_name}' is not offered by downstream '{egress.name}'",
                layer="integrity",
                server=egress.name,
                tool=tool_name,
                agent=agent,
            )
        return INTEGRITY.check(egress.name, live, agent=agent)
    except Exception as exc:
        log.exception("integrity layer raised — failing closed")
        return Decision(
            verdict=Verdict.BLOCKED,
            reason=f"internal error in integrity: {exc}",
            layer="integrity",
            server=egress.name,
            tool=tool_name,
            agent=agent,
        )


def _policy_gate(server_name: str, tool_name: str, arguments: dict, agent: str) -> Decision:
    """Default-deny + argument constraints, with the same fail-closed wrapper."""
    try:
        return POLICY.check(agent, server_name, tool_name, arguments)
    except Exception as exc:
        log.exception("policy layer raised — failing closed")
        return Decision(
            verdict=Verdict.BLOCKED,
            reason=f"internal error in policy: {exc}",
            layer="policy",
            server=server_name,
            tool=tool_name,
            agent=agent,
        )


async def _elicit_gate(server_name: str, tool_name: str, arguments: dict, agent: str) -> Decision:
    """Park the call awaiting a human, driving whichever approval surface exists.

    Register a pending record, then fire native MCP Elicitation toward the host
    as a best-effort task (it resolves the gate if the host answers). Meanwhile
    the Phase 8 dashboard — or a test — can resolve the same pending id out of
    band. Whichever answers first wins; `gate.wait` returns that decision. Any
    failure fails closed (the gate's own timeout denies)."""
    try:
        pending = GATE.create(
            server=server_name, tool=tool_name, agent=agent, arguments=arguments,
            what_will_happen=_describe_action(server_name, tool_name, arguments),
        )
    except Exception as exc:
        log.exception("elicitation gate raised on create — failing closed")
        return Decision(Verdict.BLOCKED, reason=f"internal error in elicitation: {exc}",
                        layer="elicitation", server=server_name, tool=tool_name, agent=agent)

    # Surface the parked call to the dashboard's pending panel (best-effort).
    try:
        HUB.record_pending({**pending.public(), "reason": pending.what_will_happen})
    except Exception:
        log.debug("dashboard pending publish failed — ignoring", exc_info=True)

    native = asyncio.create_task(_native_elicit(pending))
    decision: Decision
    try:
        decision = await GATE.wait(pending.id)
    finally:
        # If it resolved out of band first, stop bothering the host with a prompt.
        native.cancel()

    # Tell the dashboard this pending id is answered, so it leaves the panel.
    try:
        HUB.record_resolved({"id": pending.id, "verdict": decision.verdict.value})
    except Exception:
        log.debug("dashboard resolved publish failed — ignoring", exc_info=True)
    return decision


async def _native_elicit(pending: Pending) -> None:
    """Ask the host to approve/deny via MCP Elicitation, if it supports it.

    Best-effort: a host that can't elicit (or errors) just leaves the pending
    call for the dashboard to resolve. Never raises into the call path."""
    try:
        session = server.request_context.session
    except (LookupError, AttributeError):
        return
    try:
        caps = mcp_client_elicit_capability()
        if not session.check_client_capability(caps):
            log.info("host does not support elicitation — pending %s awaits the dashboard", pending.id)
            return
        schema = {
            "type": "object",
            "properties": {
                "approve": {"type": "boolean", "description": "Approve this action?", "title": "Approve"}
            },
            "required": ["approve"],
        }
        result = await session.elicit_form(
            message=f"MCP Warden: approve {pending.server}/{pending.tool}?\n{pending.what_will_happen}",
            requestedSchema=schema,
        )
        approved = result.action == "accept" and bool((result.content or {}).get("approve"))
        GATE.resolve(pending.id, approved, resolved_by="host-elicitation")
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("native elicitation failed for %s — leaving it to the out-of-band surface", pending.id)


def mcp_client_elicit_capability() -> types.ClientCapabilities:
    return types.ClientCapabilities(
        elicitation=types.ElicitationCapability(form=types.FormElicitationCapability())
    )


def _content_text(content: list) -> str:
    """The text of a result, joined, for hashing into the audit row. We store a
    hash of what the host received — never the content itself."""
    parts = [getattr(b, "text", "") for b in content if getattr(b, "type", None) == "text"]
    return "\n".join(parts)


def _describe_action(server_name: str, tool_name: str, arguments: dict) -> str:
    """A plain-language 'what will happen' for known sensitive tools, so the
    human sees the consequence, not just a tool name and a JSON blob."""
    if tool_name == "write_file":
        path = arguments.get("path", "?")
        content = arguments.get("content", "")
        return f"Write {len(content)} byte(s) to {path} on '{server_name}'."
    if tool_name in ("run_command", "run_shell"):
        return f"Run this shell command on '{server_name}': {arguments.get('command', '?')!r}"
    if tool_name == "db_query":
        return f"Execute this SQL on '{server_name}': {arguments.get('sql', '?')!r}"
    return f"Call '{tool_name}' on '{server_name}' with arguments {arguments!r}."


# ---- Bootstrap ---------------------------------------------------------------
async def main() -> None:
    log.info("Warden starting… config=%s db=%s", CFG.source, CFG.db_path)
    log.info("downstreams: %s", ", ".join(d.name for d in CFG.downstreams))
    log.info("policy: %s | agents: %s", POLICY.describe(), IDENTITY.describe())
    log.info("sampling: backend=%s every=%d (%s)", CFG.sampling.backend, CFG.sampling.every,
             "enabled" if SAMPLER.enabled else "disabled")
    await POOL.connect_all()
    _start_api()  # optional dashboard API — must never break the MCP serve loop
    log.info("Warden ready. Serving MCP over stdio.")
    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        log.info("Warden shutting down…")
        if API is not None:
            API.stop()
        await SAMPLER.drain()  # let any in-flight meta-review finish
        await POOL.close_all()


def _start_api() -> None:
    """Start the read-only dashboard API if configured. Enabled by `api.enabled`
    in warden.yaml, or by `WARDEN_API_PORT` (which the verify script uses to
    stand one up on a throwaway port). Any failure here is logged and swallowed:
    the dashboard is additive and must never stop Warden from serving MCP."""
    global API
    env_port = os.environ.get("WARDEN_API_PORT")
    enabled = CFG.api.enabled or bool(env_port)
    if not enabled:
        return
    port = int(env_port) if env_port else CFG.api.port

    loop = asyncio.get_running_loop()

    def resolve_pending(pending_id: str, approved: bool) -> bool:
        # A gate's asyncio.Event may only be set from the loop thread; the API
        # runs on worker threads, so marshal the resolve back onto the loop.
        loop.call_soon_threadsafe(GATE.resolve, pending_id, approved, "dashboard")
        return True

    try:
        API = WardenAPI(
            ledger=LEDGER, integrity=INTEGRITY, gate=GATE, pool=POOL,
            config=CFG, hub=HUB, resolve_pending=resolve_pending,
        )
        API.start(host=CFG.api.host, port=port)
    except Exception:
        API = None
        log.exception("dashboard API failed to start — continuing without it")


if __name__ == "__main__":
    asyncio.run(main())
