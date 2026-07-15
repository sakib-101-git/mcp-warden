"""Standalone read-only API server for a cluster instance.

In the Phase 9 topology, the MCP-serving instances write to shared Postgres/
Redis, and one or more *stateless* API instances read from the same Postgres to
serve the dashboard. `docker compose` runs two of these behind an nginx round-
robin LB — because they hold no local state, either one answers any request
identically. This entrypoint builds a `WardenAPI` over the Postgres stores and
serves it, with no MCP stdio server attached.

Config comes from the environment (so the container needs no bespoke file):
`WARDEN_POSTGRES_DSN`, `WARDEN_REDIS_URL`, `WARDEN_API_PORT`, `WARDEN_CONFIG`.
"""

from __future__ import annotations

import logging
import os
import sys
import time

from warden.api import EventHub, WardenAPI
from warden.cluster import PgIntegrityChecker, PgLedger
from warden.config import load_config

logging.basicConfig(level=logging.INFO, format="[warden-api] %(name)s: %(message)s", stream=sys.stderr)
log = logging.getLogger("warden.serve_api")


class _EmptyGate:
    """A read-only API instance holds no parked calls of its own (elicitation is
    instance-local). It reports an empty queue and cannot resolve — approve/deny
    belongs on the instance actually holding the paused call."""

    def pending_list(self):
        return []

    def resolve(self, *args, **kwargs):
        return False


class _EmptyPool:
    egresses: dict = {}


def main() -> None:
    cfg = load_config(os.environ.get("WARDEN_CONFIG", "warden.yaml"))
    if cfg.cluster.backend != "postgres" or not cfg.cluster.postgres_dsn:
        raise SystemExit("serve_api needs cluster backend=postgres (set WARDEN_POSTGRES_DSN)")

    ledger = PgLedger(cfg.cluster.postgres_dsn)
    integrity = PgIntegrityChecker(cfg.cluster.postgres_dsn)
    api = WardenAPI(
        ledger=ledger, integrity=integrity, gate=_EmptyGate(), pool=_EmptyPool(),
        config=cfg, hub=EventHub(), resolve_pending=lambda i, a: False,
    )
    port = int(os.environ.get("WARDEN_API_PORT", "8787"))
    api.start("0.0.0.0", port)  # bind all interfaces so the LB can reach it
    log.info("read-only cluster API instance (%s) serving on :%d",
             os.environ.get("INSTANCE", "warden"), port)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        api.stop()


if __name__ == "__main__":
    main()
