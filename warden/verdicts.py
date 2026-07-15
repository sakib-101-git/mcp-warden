"""The shared contract every security layer speaks.

This module is deliberately tiny and dependency-free. Every layer (integrity,
policy, inspector, elicitation, ledger, sampling) imports `Verdict` and
`Decision` from here, and the dashboard's badge colors key off the exact same
seven strings. That single shared vocabulary is what stops the system from
drifting into a pile of ad-hoc status strings that nothing can render, filter,
or audit consistently.

RULE (non-negotiable): the enum has exactly seven values. A new
detection type maps onto an existing verdict — `reason` carries the specifics.
Adding an eighth value is a deliberate, documented schema change, never a
convenience.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """What Warden decided about one tool call.

    Subclassing `str` means a Verdict serializes to its plain string value in
    JSON (`json.dumps(Verdict.ALLOWED) == '"allowed"'`), so the ledger, the API
    and the dashboard all see the same token with no conversion layer.
    """

    ALLOWED = "allowed"  # passed all checks           → green
    BLOCKED = "blocked"  # explicit policy deny        → red
    INTEGRITY_BLOCK = "integrity_block"  # TOFU hash mismatch (rug pull) → red
    PENDING = "pending"  # awaiting a human decision   → accent blue
    INJECTION_FLAG = "injection_flag"  # inspector: prompt injection → amber
    PII_FLAG = "pii_flag"  # inspector: PII / secret     → amber
    SAMPLING_FLAG = "sampling_flag"  # async meta-review anomaly   → amber


# Which verdicts stop a call from ever reaching a downstream server.
# `PENDING` is NOT terminal: it means "parked, awaiting a human", and it
# resolves into ALLOWED or BLOCKED later.
TERMINAL_BLOCK = {Verdict.BLOCKED, Verdict.INTEGRITY_BLOCK}

# The three flag verdicts are grouped as "Flagged" in the dashboard filter.
# A flag is an observation, not a veto: the call still completes (possibly with
# redactions), and the flag is what the human sees afterwards.
FLAG_VERDICTS = {Verdict.INJECTION_FLAG, Verdict.PII_FLAG, Verdict.SAMPLING_FLAG}


@dataclass
class Decision:
    """One layer's ruling on one tool call.

    `verdict` is one of the seven; `reason` is the free-text human explanation
    that ends up in the audit log and the dashboard's row subtitle.
    """

    verdict: Verdict
    reason: str = ""  # human-readable specifics
    layer: str = ""  # which layer produced this ("integrity", "policy", …)
    server: str = ""
    tool: str = ""
    agent: str = ""
    ts: float = field(default_factory=time.time)
    # Structured, layer-specific extras (integrity diff, matched patterns,
    # pending id…). Deliberately NOT part of the audit row schema or the API
    # contract — those stay on verdict + reason — so layers can hand rich data
    # to each other without anybody being tempted to invent a new verdict.
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        """True if this decision stops the call from reaching the downstream."""
        return self.verdict in TERMINAL_BLOCK

    @property
    def flagged(self) -> bool:
        """True if this decision is an observation the human should see."""
        return self.verdict in FLAG_VERDICTS

    def __str__(self) -> str:  # for stderr logs
        where = f"{self.server}/{self.tool}" if self.server else self.tool
        return f"{self.verdict.value} [{self.layer}] {where}: {self.reason}"


class WardenBlocked(Exception):
    """Raised inside the seam to refuse a call.

    The MCP SDK turns an exception raised by a `call_tool` handler into a
    `CallToolResult(isError=True, content=[TextContent(str(exc))])`. So the
    text of this exception IS what the host — and therefore the model — reads
    when Warden refuses. That makes it a security surface in its own right: it
    must state the verdict plainly and never leak the payload it just blocked.
    """

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(self._render())

    def _render(self) -> str:
        d = self.decision
        lines = [
            f"[MCP WARDEN] call refused — verdict={d.verdict.value} layer={d.layer}",
            f"tool: {d.server}/{d.tool}" if d.server else f"tool: {d.tool}",
            f"reason: {d.reason}",
        ]
        # Layers may attach a human-readable explanation (e.g. the integrity
        # diff). Showing it here is what makes a block self-explanatory in the
        # host UI instead of a mystery error.
        detail = d.details.get("diff") or d.details.get("explain")
        if detail:
            lines.append("")
            lines.append(str(detail))
        return "\n".join(lines)
