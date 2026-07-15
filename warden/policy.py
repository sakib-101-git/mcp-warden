"""Policy engine — default-deny, plus argument-level constraints.

THE ATTACK (A5, over-privileged access). MCP has no argument constraint
language. You hand an agent a `read_file` tool and you have handed it your whole
filesystem; you hand it `db_query` and you have handed it `DROP TABLE`. The tool
is honest. The *grant* is too wide. One prompt injection later, the agent uses
the full width of the grant and every one of those calls looks legitimate,
because it is: the model was allowed to make it.

THE DEFENSE, in two parts.

1. **Default-deny.** A tool with no matching allow rule does not run. Not "runs
   with a warning" — does not run. This inverts the burden: every capability an
   agent has is one somebody wrote down on purpose. (CLAUDE.md invariant 2.)

2. **Constraints on the arguments, not just the tool name.** `read_file` is not
   a yes/no question. `read_file` *inside the workspace* is fine;
   `read_file("~/.ssh/id_rsa")` is the attack. The primitives:

   path_within  canonicalize the path (symlinks, `..`, `~`) and require it to
                land inside an allowed root. This is where the classic
                `/work/../../etc/passwd` escape dies.
   read_only    reject SQL write verbs (INSERT/UPDATE/DELETE/DROP/…) and stacked
                statements, so a "reporting" tool cannot mutate the database.
   arg_matches  substring/regex deny on argument values — `rm -rf`, `curl … |
                sh`, whatever your incident report last week was about.
   max_len      a 4 MB "filename" is not a filename; it is either an overflow
                probe or an exfiltration channel.
   rate_limit   30 reads/minute is a report. 3,000 is a copy of the database.

Everything about this layer is written to fail closed. An unknown constraint key
blocks. A constraint that cannot find the argument it was written to guard
blocks. A malformed path blocks. The one thing this engine will never do is
shrug and forward the call.
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, Iterable

from warden.config import CONSTRAINT_KEYS, Rule
from warden.verdicts import Decision, Verdict

log = logging.getLogger("warden.policy")

# Argument names a `path_within` constraint is understood to guard. A constraint
# that finds none of these in a call fails closed (see _check_path_within): a
# path rule that silently matches nothing is worse than no rule, because the
# operator believes they are protected.
PATH_ARG_NAMES = {
    "path", "file", "file_path", "filepath", "filename", "dir", "directory",
    "folder", "src", "source", "dst", "dest", "destination", "target", "output",
}

# Same idea for `read_only`: the argument names that carry SQL.
SQL_ARG_NAMES = {"sql", "query", "statement", "stmt", "q"}

# A statement whose FIRST keyword is one of these changes state. Anchoring to the
# statement start (rather than "the verb appears anywhere") is deliberate: it
# lets a legitimate read like `SELECT id FROM t WHERE action = 'DELETE'` through
# — the verb is a string literal, not the operation — while still blocking a
# real `DELETE FROM t`. Multi-statement injections that try to smuggle a write
# after the read are caught separately by the stacked-statement check below, so
# nothing needs the verb to be matched mid-string.
SQL_WRITE_LEADING = re.compile(
    r"^\s*\(?\s*(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|"
    r"REVOKE|ATTACH|DETACH|VACUUM|PRAGMA|EXEC|EXECUTE|CALL)\b",
    re.IGNORECASE,
)
# `SELECT … INTO newtable` writes a table despite leading with SELECT.
SQL_SELECT_INTO = re.compile(r"\bSELECT\b.*\bINTO\b", re.IGNORECASE | re.DOTALL)


def _strings_in(value: Any) -> Iterable[str]:
    """Every string reachable inside an argument value.

    Arguments are JSON: a payload can hide one level down in a list or a nested
    object (`{"opts": {"cmd": "rm -rf /"}}`). A scanner that only looks at
    top-level strings is trivially bypassed by adding a wrapper.
    """
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings_in(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings_in(v)


class PolicyEngine:
    """First matching rule wins; no match means blocked."""

    def __init__(
        self,
        rules: list[Rule],
        default_action: str = "block",
        clock: Callable[[], float] = time.monotonic,
        rate_limiter: Any = None,
    ) -> None:
        self.rules = rules
        self.default_action = default_action
        self._clock = clock  # injectable so rate-limit tests don't sleep
        # (agent, server, tool) → timestamps of recent allowed calls
        self._calls: dict[tuple[str, str, str], deque[float]] = defaultdict(deque)
        # Optional shared limiter (Phase 9): when set (e.g. RedisRateLimiter), rate
        # limits become a fleet-wide ceiling instead of per-instance. It does its
        # own check-and-record, so the in-memory counters below stay untouched.
        self.rate_limiter = rate_limiter

    # ---- the seam entry point ------------------------------------------------

    def check(self, agent: str, server: str, tool: str, arguments: dict[str, Any]) -> Decision:
        arguments = arguments or {}

        def verdict(v: Verdict, reason: str, **details: Any) -> Decision:
            return Decision(
                verdict=v, reason=reason, layer="policy",
                server=server, tool=tool, agent=agent, details=details,
            )

        rule = self._first_match(server, tool, arguments)

        # ---- default-deny ----------------------------------------------------
        if rule is None:
            return verdict(
                Verdict.BLOCKED,
                f"default-deny: no policy rule allows {server}/{tool}. "
                f"Add an allow rule to warden.yaml if this tool is meant to be reachable.",
                default_action=self.default_action,
            )

        if rule.action == "block":
            return verdict(
                Verdict.BLOCKED,
                f"denied by {rule.describe()}",
                rule=rule.index,
            )

        # ---- constraints (they apply to allow AND elicit alike) --------------
        violation = self._check_constraints(rule, arguments)
        if violation is not None:
            return verdict(Verdict.BLOCKED, f"{violation} [{rule.describe()}]", rule=rule.index)

        # ---- rate limit ------------------------------------------------------
        if rule.rate_limit:
            if self.rate_limiter is not None:
                over = self.rate_limiter.check_and_record(agent, server, tool, rule.rate_limit)
            else:
                over = self._rate_limited(agent, server, tool, rule)
            if over is not None:
                return verdict(Verdict.BLOCKED, f"{over} [{rule.describe()}]", rule=rule.index)

        # ---- elicit ----------------------------------------------------------
        if rule.action == "elicit":
            # Phase 5's gate consumes this: PENDING parks the call until a human
            # approves or denies. PENDING is not a block and not an allow — it is
            # a question, and it is the only verdict that resolves into another.
            return verdict(
                Verdict.PENDING,
                f"human approval required by {rule.describe()}",
                rule=rule.index,
            )

        if self.rate_limiter is None:  # the shared limiter already recorded above
            self._record_call(agent, server, tool)
        return verdict(Verdict.ALLOWED, f"allowed by {rule.describe()}", rule=rule.index)

    # ---- list-time visibility ------------------------------------------------

    def tool_visible(self, server: str, tool: str) -> bool:
        """Could this tool EVER be allowed? Decided without arguments, for
        `tools/list`.

        A default-denied tool is withheld from the host entirely, for the same
        reason a rug-pulled one is: a tool the model never sees is a tool it
        cannot be steered into calling, and its description never enters the
        model's context. (The dashboard's own API, Phase 8, can still show
        denied tools — this only governs what we advertise to the model.)

        Only UNCONDITIONAL rules — those without an `arg_matches` selector —
        decide visibility, because an arg-conditional rule (e.g. the global
        `rm -rf` hard block, which matches `*/*` only when an argument contains
        the pattern) says nothing about a tool until a specific call arrives.
        Per-argument *constraints* likewise apply at call time, not here.
        """
        for rule in self.rules:
            if rule.match_args:
                continue  # arg-conditional — cannot settle visibility with no args
            if not fnmatch.fnmatchcase(server, rule.server):
                continue
            if not fnmatch.fnmatchcase(tool, rule.tool):
                continue
            return rule.action in ("allow", "elicit")
        return False  # default-deny

    # ---- matching ------------------------------------------------------------

    def _first_match(self, server: str, tool: str, arguments: dict[str, Any]) -> Rule | None:
        """First rule whose selectors all match. Order in the file is precedence,
        which is what lets a narrow `block` rule sit above a broad `allow`."""
        for rule in self.rules:
            if not fnmatch.fnmatchcase(server, rule.server):
                continue
            if not fnmatch.fnmatchcase(tool, rule.tool):
                continue
            if rule.match_args and not self._args_match(rule.match_args, arguments):
                continue
            return rule
        return None

    @staticmethod
    def _args_match(patterns: dict[str, str], arguments: dict[str, Any]) -> bool:
        """True if EVERY pattern finds its target — an AND, so a selector can be
        made as specific as the operator needs."""
        for arg_name, pattern in patterns.items():
            rx = re.compile(pattern, re.IGNORECASE)
            if arg_name == "*":
                haystack = list(_strings_in(arguments))
            else:
                if arg_name not in arguments:
                    return False
                haystack = list(_strings_in(arguments[arg_name]))
            if not any(rx.search(s) for s in haystack):
                return False
        return True

    # ---- constraints ---------------------------------------------------------

    def _check_constraints(self, rule: Rule, arguments: dict[str, Any]) -> str | None:
        """Return a violation reason, or None if every constraint is satisfied."""
        for key, spec in rule.constraints.items():
            if key not in CONSTRAINT_KEYS:
                # Defense in depth: config.py already rejects unknown keys at
                # startup, but a rule built programmatically must not be able to
                # smuggle one past us. Unknown guard ⇒ no guard ⇒ block.
                return f"unknown constraint {key!r} — failing closed"

            if key == "path_within":
                v = self._check_path_within(spec, arguments)
            elif key == "read_only":
                v = self._check_read_only(spec, arguments)
            elif key == "arg_matches":
                v = self._check_arg_matches(spec, arguments)
            elif key == "max_len":
                v = self._check_max_len(spec, arguments)
            else:  # pragma: no cover — CONSTRAINT_KEYS and this dispatch agree
                v = f"constraint {key!r} is declared but not implemented — failing closed"

            if v is not None:
                return v
        return None

    @staticmethod
    def _check_path_within(roots: list[str], arguments: dict[str, Any]) -> str | None:
        found = [(k, v) for k, v in arguments.items() if k.lower() in PATH_ARG_NAMES and isinstance(v, str)]
        if not found:
            return (
                "path_within is declared but this call has no path argument "
                f"(looked for {sorted(PATH_ARG_NAMES)}) — failing closed"
            )

        allowed = [Path(r) for r in roots]
        for name, raw in found:
            try:
                # expanduser() first (so `~/.ssh/id_rsa` is understood, not
                # treated as a relative directory literally named "~"), then
                # resolve() to collapse `..` and follow symlinks. Both matter:
                # `/work/../../etc/passwd` and a symlink at /work/out → /etc are
                # the same escape wearing different clothes.
                candidate = Path(raw).expanduser().resolve()
            except (OSError, RuntimeError, ValueError) as exc:
                return f"argument {name!r} is not a usable path ({exc}) — failing closed"

            if not any(candidate == root or candidate.is_relative_to(root) for root in allowed):
                return (
                    f"path escape: {name}={raw!r} resolves to {candidate}, "
                    f"outside the allowed root(s) {roots}"
                )
        return None

    @staticmethod
    def _check_read_only(enabled: bool, arguments: dict[str, Any]) -> str | None:
        if not enabled:
            return None
        found = [(k, v) for k, v in arguments.items() if k.lower() in SQL_ARG_NAMES and isinstance(v, str)]
        if not found:
            return (
                "read_only is declared but this call has no SQL argument "
                f"(looked for {sorted(SQL_ARG_NAMES)}) — failing closed"
            )
        for name, sql in found:
            stripped = sql.strip()
            # Stacked statements first: `SELECT 1; DROP TABLE users` passes any
            # single-statement check and ruins your afternoon. A reporting grant
            # has no business issuing more than one statement, so ANY interior
            # `;` (a `;` with content after it) is refused — which also means the
            # write-verb check below only has to reason about one statement.
            if ";" in stripped.rstrip(";"):
                return f"read_only violated: argument {name!r} stacks multiple SQL statements"
            hit = SQL_WRITE_LEADING.match(stripped)
            if hit:
                return f"read_only violated: argument {name!r} begins with the write verb {hit.group(1).upper()!r}"
            if SQL_SELECT_INTO.search(stripped):
                return f"read_only violated: argument {name!r} uses SELECT … INTO, which writes a new table"
        return None

    @staticmethod
    def _check_arg_matches(patterns: dict[str, str], arguments: dict[str, Any]) -> str | None:
        """As a CONSTRAINT, arg_matches is a veto: matching means blocked.
        (As a `match:` selector it is the opposite — it decides which rule
        applies. Same syntax, two jobs, and the yaml section says which.)"""
        for arg_name, pattern in patterns.items():
            rx = re.compile(pattern, re.IGNORECASE)
            targets = (
                arguments.items() if arg_name == "*"
                else [(arg_name, arguments[arg_name])] if arg_name in arguments
                else []
            )
            for name, value in targets:
                for s in _strings_in(value):
                    hit = rx.search(s)
                    if hit:
                        return f"argument {name!r} matches the denied pattern {pattern!r} (matched {hit.group(0)!r})"
        return None

    @staticmethod
    def _check_max_len(limit: int, arguments: dict[str, Any]) -> str | None:
        for name, value in arguments.items():
            for s in _strings_in(value):
                if len(s) > limit:
                    return f"argument {name!r} is {len(s)} chars, over the {limit}-char limit"
        total = len(json.dumps(arguments, default=str))
        if total > limit * 4:
            return f"arguments total {total} chars, over the {limit * 4}-char aggregate limit"
        return None

    # ---- rate limiting -------------------------------------------------------

    def _rate_limited(self, agent: str, server: str, tool: str, rule: Rule) -> str | None:
        now = self._clock()
        key = (agent, server, tool)
        history = self._calls[key]

        for window_name, seconds in (("per_minute", 60.0), ("per_hour", 3600.0)):
            limit = rule.rate_limit.get(window_name)
            if not limit:
                continue
            cutoff = now - seconds
            recent = sum(1 for t in history if t > cutoff)
            if recent >= limit:
                return (
                    f"rate limit exceeded: {recent} call(s) to {tool} by {agent} "
                    f"in the last {window_name.replace('per_', '')} (limit {limit})"
                )
        return None

    def _record_call(self, agent: str, server: str, tool: str) -> None:
        now = self._clock()
        history = self._calls[(agent, server, tool)]
        history.append(now)
        # Keep the window bounded — an hour is the longest limit we support.
        while history and history[0] < now - 3600.0:
            history.popleft()

    # ---- introspection (for the verify scripts and the Phase 8 dashboard) ----

    def describe(self) -> str:
        if not self.rules:
            return "no rules — everything is denied by default"
        return f"{len(self.rules)} rule(s), default={self.default_action}"
