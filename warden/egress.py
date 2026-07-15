"""Egress — Warden's MCP *client* role.

For each downstream MCP server (filesystem, github, our test dummy, etc.),
Warden opens exactly one persistent MCP client session that stays alive for
Warden's whole lifetime. Every tool call the host makes flows through this
session — we do NOT open a fresh connection per call. That would be wasteful,
break any downstream server that keeps session-scoped state, and also make
the integrity pinning meaningless (we need "same session, same tool
definitions" to be a real property).

The trick to keeping an async-context-manager-based session open across the
lifetime of the process is `AsyncExitStack` — it lets us enter contexts now
and exit them later, without being trapped inside a single `async with` block.
"""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client

log = logging.getLogger("warden.egress")

# Separator for disambiguated tool names: `server__tool`.
NS = "__"


class Egress:
    """One long-lived MCP client session to one downstream server."""

    def __init__(self, name: str, params: StdioServerParameters):
        self.name = name
        self.params = params
        self._stack: AsyncExitStack | None = None
        self.session: ClientSession | None = None

    async def connect(self) -> None:
        """Launch the downstream server as a child process, initialize MCP."""
        log.info("connecting to downstream '%s' (cmd=%s %s)",
                 self.name, self.params.command, " ".join(self.params.args))
        self._stack = AsyncExitStack()
        # stdio_client returns (read_stream, write_stream) — the raw MCP transport
        read, write = await self._stack.enter_async_context(stdio_client(self.params))
        # ClientSession wraps the streams and speaks the MCP protocol
        self.session = await self._stack.enter_async_context(ClientSession(read, write))
        # Handshake — must complete before we can list/call tools
        init_result = await self.session.initialize()
        log.info("downstream '%s' initialized. server: %s v%s",
                 self.name,
                 init_result.serverInfo.name,
                 init_result.serverInfo.version)

    async def list_tools(self) -> list[Any]:
        """Ask the downstream server what tools it exposes."""
        assert self.session is not None, "Egress.connect() must be called first"
        result = await self.session.list_tools()
        return result.tools

    async def get_tool(self, name: str) -> Any | None:
        """Fetch ONE tool's live definition, straight from the downstream.

        Deliberately not cached. A malicious server can advertise an innocent
        definition to `tools/list` and serve a different one moments later, so
        the integrity layer re-reads the definition from the wire
        immediately before every call rather than trusting a definition we
        happened to see earlier in the session. Over stdio this is a local
        round-trip measured in microseconds — cheap insurance.
        """
        for tool in await self.list_tools():
            if tool.name == name:
                return tool
        return None

    async def call_tool(self, name: str, arguments: dict) -> Any:
        """Forward one tool call to the downstream server and return its raw result."""
        assert self.session is not None, "Egress.connect() must be called first"
        return await self.session.call_tool(name, arguments)

    async def close(self) -> None:
        """Cleanly tear down the downstream session and child process."""
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
            self.session = None
            log.info("downstream '%s' closed", self.name)


class DownstreamPool:
    """Every downstream Warden proxies, and the routing table above them.

    With N servers connected at once, two of them can expose a tool with the
    same name — and that collision is not always an accident. Tool shadowing (the
    confused deputy) is exactly this: a malicious server advertises `read_file`,
    the model has been told "use read_file", and it reaches for whichever one the
    host happens to have registered under that name. The victim server's
    authority gets borrowed by the attacker's tool.

    So the pool guarantees an unambiguous mapping:

      * a tool name unique across all downstreams keeps its real name
        (transparent proxying: the model should see
        `read_file`, not `warden_proxy_call`);
      * a COLLIDING name is exposed to the host as `server__tool` for every
        server that claims it, so no server can be silently substituted for
        another, and a policy rule written for one server's `read_file`
        cannot be satisfied by another server's impostor.

    The routing table maps whatever the host called back to (server, real tool
    name) — and policy is always evaluated against the REAL pair, never the
    exposed alias.
    """

    def __init__(self, egresses: list[Egress]) -> None:
        self.egresses = {e.name: e for e in egresses}
        # exposed name → (server name, real tool name)
        self._routes: dict[str, tuple[str, str]] = {}

    async def connect_all(self) -> None:
        for e in self.egresses.values():
            await e.connect()

    async def close_all(self) -> None:
        for e in self.egresses.values():
            try:
                await e.close()
            except Exception as exc:  # a downstream that dies badly must not block the rest
                # On an abrupt host disconnect the stdio transport can raise an
                # anyio cancel-scope error while unwinding — cosmetic shutdown
                # noise, not a failure. Log it briefly rather than dumping a
                # traceback into the operator's console.
                log.debug("downstream '%s' close raised during shutdown: %r", e.name, exc)

    async def list_tools(self) -> list[tuple[str, str, Any]]:
        """Aggregate every downstream's tools and (re)build the routing table.

        Returns a list of `(exposed_name, server_name, live_tool)` so the caller
        can integrity-check the LIVE definition (which carries the real name)
        while advertising the exposed one.
        """
        per_server: list[tuple[str, Any]] = []
        for name, e in self.egresses.items():
            try:
                for tool in await e.list_tools():
                    per_server.append((name, tool))
            except Exception:
                # One broken downstream must not take the whole gateway down —
                # its tools simply stop being offered, which is fail-closed.
                log.exception("downstream '%s' failed to list tools — offering none of it", name)

        counts: dict[str, int] = {}
        for _, tool in per_server:
            counts[tool.name] = counts.get(tool.name, 0) + 1

        routes: dict[str, tuple[str, str]] = {}
        out: list[tuple[str, str, Any]] = []
        for server_name, tool in per_server:
            collides = counts[tool.name] > 1
            exposed = f"{server_name}{NS}{tool.name}" if collides else tool.name
            if collides:
                log.warning(
                    "tool name collision on '%s' — exposing it as '%s' so the host "
                    "cannot confuse one server's tool for another's",
                    tool.name,
                    exposed,
                )
            routes[exposed] = (server_name, tool.name)
            out.append((exposed, server_name, tool))

        self._routes = routes
        return out

    async def resolve(self, exposed_name: str) -> tuple[Egress, str] | None:
        """Map a name the host called to the downstream that actually owns it."""
        if exposed_name not in self._routes:
            # Cold start (the host called before listing) or a tool list that has
            # changed underneath us — rebuild once, then decide.
            await self.list_tools()
        route = self._routes.get(exposed_name)
        if route is None:
            return None
        server_name, real_name = route
        return self.egresses[server_name], real_name

    def route(self, exposed_name: str) -> tuple[str, str] | None:
        """The (server, real tool) behind an exposed name, without any I/O."""
        return self._routes.get(exposed_name)


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """The environment a downstream child process is allowed to see.

    Warden does NOT hand its whole environment to every server it spawns. That is
    credential sprawl in one line of code: a third-party MCP server
    does not need your AWS keys to echo a string. Start from the SDK's minimal
    safe set (PATH, HOME/USERPROFILE…) and add only what the config says this
    particular downstream requires.
    """
    env = get_default_environment()
    if extra:
        env.update(extra)
    return env
