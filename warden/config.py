"""Config — load and validate `warden.yaml`, or refuse to start.

A security gateway whose config file is "mostly parsed" is a gateway with holes
in it. So this module is deliberately pedantic: **any** key it does not
recognize, any action it cannot map, any regex that does not compile, any
environment variable a downstream needs but does not have — is a hard startup
failure with a message naming the exact offending line. Never a warning, never
a default, never "best effort".

That is fail-closed applied at t=0: a typo'd constraint
name (`path_with:` instead of `path_within:`) must not silently become "no
constraint at all", which is precisely how a policy engine ends up allowing what
its author believed it forbade.

Two conveniences that keep the file portable across machines:
  * `command: python` resolves to the interpreter running Warden
    (`sys.executable`), so a committed config works inside anyone's venv.
  * `${VAR}` / `${VAR:-default}` interpolation in downstream commands, args and
    env. A missing `${VAR}` with no default is an error, not an empty string —
    spawning a downstream with a blank credential is a failure worth stopping
    for.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---- What the schema allows. Anything else is a startup failure. -------------

TOP_LEVEL_KEYS = {"version", "db", "downstreams", "defaults", "agents", "policy", "sampling"}
DOWNSTREAM_KEYS = {"name", "command", "args", "env", "cwd"}
DEFAULTS_KEYS = {"action"}
SAMPLING_KEYS = {"backend", "every", "window"}
SAMPLING_BACKENDS = {"null", "stub", "cli", "ollama", "native", "hosted"}
RULE_KEYS = {"match", "action", "constraints", "rate_limit"}
MATCH_KEYS = {"server", "tool", "arg_matches"}
CONSTRAINT_KEYS = {"path_within", "read_only", "arg_matches", "max_len"}
RATE_LIMIT_KEYS = {"per_minute", "per_hour"}

# `deny` and `block` are the same thing; both exist because both read naturally
# in different sentences ("defaults: deny", "action: block").
ACTIONS = {"allow", "deny", "block", "elicit"}
# Default-deny is a product invariant, not a preference. A config
# that tries to default to `allow` is rejected rather than honored.
DEFAULT_ACTIONS = {"deny", "block"}

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(Exception):
    """Malformed configuration. Warden refuses to start."""


# ---- The parsed shapes -------------------------------------------------------


@dataclass(frozen=True)
class DownstreamSpec:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None


@dataclass(frozen=True)
class Rule:
    """One policy line. `index` is its position in the file — the reason text
    quotes it so an operator can find the rule that blocked them."""

    index: int
    action: str  # allow | block | elicit  (deny is normalized to block)
    server: str = "*"  # fnmatch glob
    tool: str = "*"  # fnmatch glob
    match_args: dict[str, str] = field(default_factory=dict)  # selector, not a veto
    constraints: dict[str, Any] = field(default_factory=dict)
    rate_limit: dict[str, int] = field(default_factory=dict)

    def describe(self) -> str:
        return f"rule #{self.index} ({self.server}/{self.tool} → {self.action})"


@dataclass(frozen=True)
class SamplingConfig:
    backend: str = "null"  # null disables the async meta-review cleanly
    every: int = 20  # run a review every N audited calls
    window: int = 30  # how many recent calls the review looks at


@dataclass(frozen=True)
class Config:
    version: int
    db_path: str
    downstreams: list[DownstreamSpec]
    default_action: str
    agents: dict[str, str]
    rules: list[Rule]
    sampling: SamplingConfig
    source: str  # path this came from, for error messages


# ---- Loading -----------------------------------------------------------------


def _interpolate(value: str, where: str) -> str:
    """Expand ${VAR} / ${VAR:-default} from Warden's own environment."""

    def sub(m: re.Match[str]) -> str:
        name, default = m.group(1), m.group(2)
        val = os.environ.get(name)
        if val is not None:
            return val
        if default is not None:
            return default
        raise ConfigError(
            f"{where}: environment variable ${{{name}}} is not set and has no default. "
            f"Refusing to start a downstream with a missing value — write "
            f"${{{name}:-something}} if an empty/default value really is intended."
        )

    return _VAR.sub(sub, value)


def _reject_unknown(got: Any, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(got, dict):
        raise ConfigError(f"{where}: expected a mapping, got {type(got).__name__}")
    unknown = set(got) - allowed
    if unknown:
        raise ConfigError(
            f"{where}: unknown key(s) {sorted(unknown)}. Allowed: {sorted(allowed)}. "
            f"(A typo'd key would silently disable the protection you meant to "
            f"configure, so Warden refuses to start instead.)"
        )
    return got


def _parse_downstream(raw: Any, i: int) -> DownstreamSpec:
    where = f"downstreams[{i}]"
    d = _reject_unknown(raw, DOWNSTREAM_KEYS, where)

    name = d.get("name")
    command = d.get("command")
    if not name or not isinstance(name, str):
        raise ConfigError(f"{where}: 'name' is required (a string)")
    if not command or not isinstance(command, str):
        raise ConfigError(f"{where}: 'command' is required (a string)")

    command = _interpolate(command, f"{where}.command")
    # `python` means "the interpreter running Warden" — keeps a committed config
    # working inside anyone's venv, on any OS, with no absolute paths.
    if command in ("python", "python3"):
        command = sys.executable

    args = d.get("args", []) or []
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ConfigError(f"{where}.args: expected a list of strings")
    args = [_interpolate(a, f"{where}.args") for a in args]

    env_raw = d.get("env", {}) or {}
    if not isinstance(env_raw, dict):
        raise ConfigError(f"{where}.env: expected a mapping of NAME: value")
    env = {str(k): _interpolate(str(v), f"{where}.env.{k}") for k, v in env_raw.items()}

    cwd = d.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        raise ConfigError(f"{where}.cwd: expected a string")

    return DownstreamSpec(name=name, command=command, args=args, env=env, cwd=cwd)


def _parse_constraints(raw: Any, where: str, config_dir: Path) -> dict[str, Any]:
    c = _reject_unknown(raw, CONSTRAINT_KEYS, where)
    out: dict[str, Any] = {}

    if "path_within" in c:
        roots = c["path_within"]
        if isinstance(roots, str):
            roots = [roots]
        if not isinstance(roots, list) or not roots:
            raise ConfigError(f"{where}.path_within: expected a non-empty list of paths")
        # Resolve relative roots against the CONFIG FILE's directory (not the
        # process cwd — a host like Claude Desktop launches Warden from an
        # arbitrary working directory, and a sandbox root that moves with the
        # cwd is not a sandbox).
        resolved: list[str] = []
        for r in roots:
            p = Path(_interpolate(str(r), f"{where}.path_within")).expanduser()
            if not p.is_absolute():
                p = config_dir / p
            resolved.append(str(p.resolve()))
        out["path_within"] = resolved

    if "read_only" in c:
        if not isinstance(c["read_only"], bool):
            raise ConfigError(f"{where}.read_only: expected true/false")
        out["read_only"] = c["read_only"]

    if "arg_matches" in c:
        out["arg_matches"] = _parse_arg_matches(c["arg_matches"], f"{where}.arg_matches")

    if "max_len" in c:
        ml = c["max_len"]
        if isinstance(ml, bool) or not isinstance(ml, int) or ml <= 0:
            raise ConfigError(f"{where}.max_len: expected a positive integer")
        out["max_len"] = ml

    return out


def _parse_arg_matches(raw: Any, where: str) -> dict[str, str]:
    if not isinstance(raw, dict) or not raw:
        raise ConfigError(f"{where}: expected a mapping of argument-name → pattern ('*' = any argument)")
    out: dict[str, str] = {}
    for arg, pattern in raw.items():
        if not isinstance(pattern, str):
            raise ConfigError(f"{where}.{arg}: expected a regex/substring pattern (string)")
        try:
            re.compile(pattern)
        except re.error as exc:
            # An uncompilable pattern is a rule that never fires: exactly the
            # silent hole this module exists to prevent.
            raise ConfigError(f"{where}.{arg}: invalid regex {pattern!r} — {exc}") from exc
        out[str(arg)] = pattern
    return out


def _parse_rule(raw: Any, i: int, config_dir: Path) -> Rule:
    where = f"policy[{i}]"
    r = _reject_unknown(raw, RULE_KEYS, where)

    action = r.get("action")
    if action not in ACTIONS:
        raise ConfigError(f"{where}.action: expected one of {sorted(ACTIONS)}, got {action!r}")
    if action == "deny":
        action = "block"

    match = _reject_unknown(r.get("match", {}) or {}, MATCH_KEYS, f"{where}.match")
    server = match.get("server", "*")
    tool = match.get("tool", "*")
    if not isinstance(server, str) or not isinstance(tool, str):
        raise ConfigError(f"{where}.match: 'server' and 'tool' must be strings (globs allowed)")
    match_args = (
        _parse_arg_matches(match["arg_matches"], f"{where}.match.arg_matches")
        if "arg_matches" in match
        else {}
    )

    constraints = _parse_constraints(r.get("constraints", {}) or {}, f"{where}.constraints", config_dir)

    rl_raw = _reject_unknown(r.get("rate_limit", {}) or {}, RATE_LIMIT_KEYS, f"{where}.rate_limit")
    rate_limit: dict[str, int] = {}
    for k, v in rl_raw.items():
        if isinstance(v, bool) or not isinstance(v, int) or v <= 0:
            raise ConfigError(f"{where}.rate_limit.{k}: expected a positive integer")
        rate_limit[k] = v

    return Rule(
        index=i,
        action=action,
        server=server,
        tool=tool,
        match_args=match_args,
        constraints=constraints,
        rate_limit=rate_limit,
    )


def load_config(path: str | Path) -> Config:
    """Parse and validate a config file. Raises ConfigError — never guesses."""
    p = Path(path).expanduser()
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")

    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{p}: not valid YAML — {exc}") from exc

    if raw is None:
        raise ConfigError(f"{p}: file is empty")
    doc = _reject_unknown(raw, TOP_LEVEL_KEYS, str(p))
    config_dir = p.parent.resolve()

    version = doc.get("version")
    if version != 1:
        raise ConfigError(f"{p}: 'version' must be 1 (got {version!r})")

    downstreams_raw = doc.get("downstreams")
    if not isinstance(downstreams_raw, list) or not downstreams_raw:
        raise ConfigError(f"{p}: 'downstreams' must be a non-empty list")
    downstreams = [_parse_downstream(d, i) for i, d in enumerate(downstreams_raw)]
    names = [d.name for d in downstreams]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        # Two downstreams sharing a name would make every pin and every policy
        # rule ambiguous — the audit log could not tell you which server ran a
        # tool. Refuse.
        raise ConfigError(f"{p}: duplicate downstream name(s): {sorted(dupes)}")

    defaults = _reject_unknown(doc.get("defaults", {}) or {}, DEFAULTS_KEYS, f"{p}: defaults")
    default_action = defaults.get("action", "deny")
    if default_action not in DEFAULT_ACTIONS:
        raise ConfigError(
            f"{p}: defaults.action must be one of {sorted(DEFAULT_ACTIONS)} "
            f"(got {default_action!r}). Default-deny is an invariant of this "
            f"product: a tool with no matching allow rule does not run."
        )
    default_action = "block"

    agents_raw = doc.get("agents", {}) or {}
    if not isinstance(agents_raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in agents_raw.items()
    ):
        raise ConfigError(f"{p}: 'agents' must be a mapping of client-name → agent-label")
    agents = {str(k): str(v) for k, v in agents_raw.items()}

    policy_raw = doc.get("policy", []) or []
    if not isinstance(policy_raw, list):
        raise ConfigError(f"{p}: 'policy' must be a list of rules")
    rules = [_parse_rule(r, i, config_dir) for i, r in enumerate(policy_raw)]

    sampling = _parse_sampling(doc.get("sampling", {}) or {}, f"{p}: sampling")

    db = doc.get("db", "warden.db")
    if not isinstance(db, str):
        raise ConfigError(f"{p}: 'db' must be a path string")
    db_path = Path(db).expanduser()
    if not db_path.is_absolute():
        db_path = config_dir / db_path
    # One env override, so a test run can point at a throwaway store and never
    # poison the operator's real pin/audit database.
    db_final = os.environ.get("WARDEN_DB", str(db_path))

    return Config(
        version=version,
        db_path=db_final,
        downstreams=downstreams,
        default_action=default_action,
        agents=agents,
        rules=rules,
        sampling=sampling,
        source=str(p),
    )


def _parse_sampling(raw: Any, where: str) -> SamplingConfig:
    s = _reject_unknown(raw, SAMPLING_KEYS, where)
    backend = s.get("backend", "null")
    if backend not in SAMPLING_BACKENDS:
        raise ConfigError(f"{where}.backend: expected one of {sorted(SAMPLING_BACKENDS)}, got {backend!r}")
    every = s.get("every", 20)
    window = s.get("window", 30)
    for key, val in (("every", every), ("window", window)):
        if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
            raise ConfigError(f"{where}.{key}: expected a positive integer")
    return SamplingConfig(backend=backend, every=every, window=window)
