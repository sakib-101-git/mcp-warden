"""Identity — which agent is making this call?

MCP has no per-call agent authentication. There is no token on a `tools/call`,
no signed caller assertion, nothing. All a server gets is what the client
declared once, at `initialize`: a name and a version, self-reported and
unverified.

So v1 is deliberately honest about what it can and cannot do:

  * We take `clientInfo.name` from the initialize handshake and map it, through
    `agents:` in warden.yaml, to an agent label ("finance-copilot").
  * That label is what the policy engine keys off, what the audit log records,
    and what the dashboard's "Agent" column shows.
  * It is an ATTRIBUTION mechanism, not an AUTHENTICATION one. A hostile client
    can claim any name it likes. It is exactly as trustworthy as the process
    that launched Warden — which, for a local stdio proxy, is the user's own
    machine, and that is a reasonable trust boundary for v1.

The extension point is `resolve()`: give it a real credential (a signed session
token, an mTLS peer identity, an OAuth subject once MCP's auth spec lands) and
every layer above it starts enforcing on a verified identity with no other code
change. That is why identity is step 1 of the pipeline and its own module rather
than a string literal in main.py.
"""

from __future__ import annotations

import logging

log = logging.getLogger("warden.identity")

# Used when the host declares nothing and the config maps nothing.
FALLBACK_AGENT = "default-agent"


class IdentityResolver:
    """Maps a host's self-declared client name to an agent label."""

    def __init__(self, agents: dict[str, str] | None = None) -> None:
        # Case-insensitive: "Claude Desktop" and "claude desktop" are the same
        # host, and an operator should not have to guess the exact casing the
        # client SDK happens to send.
        self._map = {k.lower(): v for k, v in (agents or {}).items()}
        self._default = self._map.get("default", FALLBACK_AGENT)

    def resolve(self, client_name: str | None) -> str:
        """Return the agent label for this connection.

        Unknown clients get the default label rather than being refused: identity
        here is for attribution and policy scoping, and a call from an unknown
        client still has to pass every other layer. Default-deny lives in the
        policy engine, which is where a *decision* belongs — not here.
        """
        if not client_name:
            return self._default
        return self._map.get(client_name.lower(), self._default)

    def describe(self) -> str:
        if not self._map:
            return f"no agent mapping configured — everything is '{self._default}'"
        return ", ".join(f"{k} → {v}" for k, v in sorted(self._map.items()))
