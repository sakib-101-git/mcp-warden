"""Cluster stores — Postgres pin store + audit ledger, Redis rate limiter.

Phase 9 (stretch): make Warden *stateless* so N instances can run behind a load
balancer. Everything a single instance kept on local disk (SQLite pins, the
SQLite audit chain) or in memory (rate-limit counters) moves to shared services:

  * **PgLedger** — the append-only hash-chained ledger, in Postgres. The chain's
    one hard requirement is a single global order: with several instances
    appending at once, two must never read the same `prev_hash` and fork the
    chain. A **Postgres advisory lock** (`pg_advisory_xact_lock`) held for the
    duration of each append transaction makes append a global critical section —
    the distributed equivalent of the SQLite ledger's in-process `threading.Lock`.
  * **PgIntegrityChecker** — TOFU pins in Postgres, shared across instances, so a
    tool pinned by instance A is trusted (and rug-pulls caught) on instance B.
  * **RedisRateLimiter** — sliding-window counters in Redis, so a per-agent rate
    limit is enforced across the whole fleet, not per instance.

The hashing, canonicalization, and diffing are reused verbatim from the SQLite
implementations (`warden.ledger`, `warden.integrity`) — only the storage changes,
so a chain written by the cluster verifies with the exact same bytes as a local
one, and `verify_export` works on either.

Dependencies (`psycopg`, `redis`) are imported lazily inside the constructors so
importing this module never fails when the cluster extra isn't installed; you
only pay for it when you actually select `backend: postgres`.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import Any

from warden.integrity import _as_def, human_diff
from warden.ledger import GENESIS_PREV, Ledger, _canonical, _entry_hash, _sha
from warden.verdicts import Decision, Verdict

log = logging.getLogger("warden.cluster")

# A fixed 64-bit key for the audit-chain advisory lock. Every instance locks on
# the same key, so append is serialized across the whole fleet. ("wardn-au".)
AUDIT_LOCK_KEY = 0x7761_7264_6E5F_6175


# ---- audit ledger over Postgres ---------------------------------------------


class PgLedger:
    """Append-only hash-chained audit store in Postgres. Same interface as
    `warden.ledger.Ledger`; global ordering via a Postgres advisory lock."""

    def __init__(self, dsn: str) -> None:
        import psycopg  # lazy: only needed for backend=postgres

        self._psycopg = psycopg
        self.dsn = dsn
        self._lock = threading.Lock()  # one connection per instance; guard it
        self._conn = psycopg.connect(dsn, autocommit=False)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    seq         BIGINT PRIMARY KEY,
                    ts          DOUBLE PRECISION NOT NULL,
                    agent       TEXT NOT NULL,
                    server      TEXT NOT NULL,
                    tool        TEXT NOT NULL,
                    verdict     TEXT NOT NULL,
                    reason      TEXT NOT NULL,
                    args_hash   TEXT NOT NULL,
                    result_hash TEXT NOT NULL,
                    prev_hash   TEXT NOT NULL,
                    entry_hash  TEXT NOT NULL
                )
                """
            )

    def append(self, decision: Decision, *, args: Any = None, result_text: str | None = None) -> dict[str, Any]:
        args_hash = _sha(_canonical(args if args is not None else {}))
        result_hash = _sha(result_text or "")
        with self._lock:
            with self._conn.transaction():
                with self._conn.cursor() as cur:
                    # Global critical section: held until this transaction commits,
                    # so no two instances can read the same prev_hash and fork.
                    cur.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_KEY,))
                    cur.execute("SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1")
                    last = cur.fetchone()
                    seq = 1 if last is None else last[0] + 1
                    prev_hash = GENESIS_PREV if last is None else last[1]

                    row: dict[str, Any] = {
                        "seq": seq,
                        "ts": float(decision.ts or time.time()),
                        "agent": decision.agent or "",
                        "server": decision.server or "",
                        "tool": decision.tool or "",
                        "verdict": decision.verdict.value,
                        "reason": decision.reason or "",
                        "args_hash": args_hash,
                        "result_hash": result_hash,
                        "prev_hash": prev_hash,
                    }
                    row["entry_hash"] = _entry_hash(row)
                    cur.execute(
                        "INSERT INTO audit (seq, ts, agent, server, tool, verdict, reason, "
                        "args_hash, result_hash, prev_hash, entry_hash) VALUES "
                        "(%(seq)s, %(ts)s, %(agent)s, %(server)s, %(tool)s, %(verdict)s, "
                        "%(reason)s, %(args_hash)s, %(result_hash)s, %(prev_hash)s, %(entry_hash)s)",
                        row,
                    )
        log.info("audit #%d %s %s/%s → %s", seq, row["agent"], row["server"], row["tool"], row["verdict"])
        return row

    def _rows(self, limit: int | None = None) -> list[dict[str, Any]]:
        from psycopg.rows import dict_row

        sql = "SELECT * FROM audit ORDER BY seq ASC"
        if limit:
            sql = f"SELECT * FROM (SELECT * FROM audit ORDER BY seq DESC LIMIT {int(limit)}) s ORDER BY seq ASC"
        with self._lock, self._conn.transaction(), self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql)
            return [dict(r) for r in cur.fetchall()]

    def all(self, limit: int | None = None) -> list[dict[str, Any]]:
        return self._rows(limit)

    def count(self) -> int:
        with self._lock, self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM audit")
            return int(cur.fetchone()[0])

    def verify_chain(self) -> dict[str, Any]:
        """Re-walk from genesis, recomputing every hash — identical to the SQLite
        ledger, so a Postgres chain is verified by the same logic and bytes."""
        rows = self._rows()
        prev = GENESIS_PREV
        expected_seq = 1
        for row in rows:
            if row["seq"] != expected_seq:
                return {"ok": False, "broken_seq": row["seq"], "count": len(rows),
                        "detail": f"seq gap: expected {expected_seq}, found {row['seq']}"}
            if row["prev_hash"] != prev:
                return {"ok": False, "broken_seq": row["seq"], "count": len(rows),
                        "detail": f"broken link at seq {row['seq']}"}
            if _entry_hash(row) != row["entry_hash"]:
                return {"ok": False, "broken_seq": row["seq"], "count": len(rows),
                        "detail": f"tampered content at seq {row['seq']}"}
            prev = row["entry_hash"]
            expected_seq += 1
        return {"ok": True, "broken_seq": None, "count": len(rows), "detail": "chain intact"}

    def export_verifiable(self) -> str:
        lines = [_canonical(row) for row in self.all()]
        return "\n".join(lines) + ("\n" if lines else "")

    def export_csv(self) -> str:
        # Reuse the SQLite ledger's CSV writer over our rows.
        import csv
        import io

        rows = self.all()
        buf = io.StringIO()
        buf.write("# MCP Warden audit export — UNVERIFIED convenience copy.\n")
        buf.write("# For a tamper-evident record use the JSONL export (carries the hash chain).\n")
        writer = csv.DictWriter(
            buf,
            fieldnames=["seq", "ts", "agent", "server", "tool", "verdict", "reason",
                        "args_hash", "result_hash", "prev_hash", "entry_hash"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return buf.getvalue()

    # Offline verification is storage-agnostic — reuse the SQLite implementation.
    verify_export = staticmethod(Ledger.verify_export)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# ---- integrity pins over Postgres -------------------------------------------


class PgIntegrityChecker:
    """TOFU pin store in Postgres. Same interface as
    `warden.integrity.IntegrityChecker`, shared across all instances."""

    def __init__(self, dsn: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self.dsn = dsn
        self._lock = threading.Lock()
        self._conn = psycopg.connect(dsn, autocommit=False)
        self._init_db()

    def _init_db(self) -> None:
        with self._lock, self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS pins (
                    server     TEXT NOT NULL,
                    tool       TEXT NOT NULL,
                    hash       TEXT NOT NULL,
                    def_json   TEXT NOT NULL,
                    first_seen DOUBLE PRECISION NOT NULL,
                    approved   INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (server, tool)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS quarantine (
                    server   TEXT NOT NULL,
                    tool     TEXT NOT NULL,
                    hash     TEXT NOT NULL,
                    def_json TEXT NOT NULL,
                    seen     DOUBLE PRECISION NOT NULL,
                    PRIMARY KEY (server, tool)
                )
                """
            )

    def check(self, server: str, live_tool: Any, agent: str = "") -> Decision:
        live_def = _as_def(live_tool)
        tool = live_def["name"]
        live_json = json.dumps(live_def, sort_keys=True, separators=(",", ":"))
        live_hash = _sha(live_json)

        from psycopg.rows import dict_row

        with self._lock, self._conn.transaction(), self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT hash, def_json, first_seen, approved FROM pins WHERE server=%s AND tool=%s",
                        (server, tool))
            row = cur.fetchone()

            if row is None:
                # TOFU. ON CONFLICT DO NOTHING makes concurrent first-sight by two
                # instances safe: one wins the INSERT, both then read the winner.
                now = time.time()
                cur.execute(
                    "INSERT INTO pins (server, tool, hash, def_json, first_seen, approved) "
                    "VALUES (%s, %s, %s, %s, %s, 1) ON CONFLICT (server, tool) DO NOTHING",
                    (server, tool, live_hash, live_json, now),
                )
                cur.execute("SELECT hash, def_json, first_seen FROM pins WHERE server=%s AND tool=%s",
                            (server, tool))
                pinned = cur.fetchone()
                if pinned["hash"] == live_hash:
                    log.info("pinned (TOFU) %s/%s sha256:%s", server, tool, live_hash[:12])
                    return Decision(Verdict.ALLOWED,
                                    reason=f"pinned on first sight (TOFU), sha256:{live_hash[:12]}",
                                    layer="integrity", server=server, tool=tool, agent=agent,
                                    details={"live_hash": live_hash, "pinned": True})
                # A concurrent instance pinned a different definition first — fall
                # through to the mismatch path against that authoritative pin.
                row = pinned

            if row["hash"] == live_hash:
                return Decision(Verdict.ALLOWED,
                                reason=f"definition matches pin sha256:{live_hash[:12]}",
                                layer="integrity", server=server, tool=tool, agent=agent,
                                details={"live_hash": live_hash})

            # Rug pull: quarantine the new definition, hand back a readable diff.
            cur.execute(
                "INSERT INTO quarantine (server, tool, hash, def_json, seen) VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (server, tool) DO UPDATE SET hash=EXCLUDED.hash, "
                "def_json=EXCLUDED.def_json, seen=EXCLUDED.seen",
                (server, tool, live_hash, live_json, time.time()),
            )
            diff = human_diff(row["def_json"], live_json, row["first_seen"])
            log.warning("INTEGRITY BLOCK %s/%s — pinned sha256:%s live sha256:%s",
                        server, tool, row["hash"][:12], live_hash[:12])
            return Decision(
                verdict=Verdict.INTEGRITY_BLOCK,
                reason=(f"tool definition changed since it was pinned "
                        f"(pinned sha256:{row['hash'][:12]}, live sha256:{live_hash[:12]}). "
                        f"Treated as a rug pull until a human reviews the diff and re-approves."),
                layer="integrity", server=server, tool=tool, agent=agent,
                details={"pinned_hash": row["hash"], "live_hash": live_hash,
                         "diff": diff, "first_seen": row["first_seen"]},
            )

    def reapprove(self, server: str, tool: str, live_tool: Any | None = None) -> Decision:
        from psycopg.rows import dict_row

        with self._lock, self._conn.transaction(), self._conn.cursor(row_factory=dict_row) as cur:
            if live_tool is None:
                cur.execute("SELECT hash, def_json FROM quarantine WHERE server=%s AND tool=%s", (server, tool))
                q = cur.fetchone()
                if q is None:
                    return Decision(Verdict.BLOCKED,
                                    reason=f"nothing to re-approve for {server}/{tool} — no quarantined definition",
                                    layer="integrity", server=server, tool=tool)
                new_hash, new_json = q["hash"], q["def_json"]
            else:
                new_def = _as_def(live_tool)
                new_json = json.dumps(new_def, sort_keys=True, separators=(",", ":"))
                new_hash = _sha(new_json)

            cur.execute("SELECT hash, first_seen FROM pins WHERE server=%s AND tool=%s", (server, tool))
            old = cur.fetchone()
            first_seen = old["first_seen"] if old else time.time()
            cur.execute(
                "INSERT INTO pins (server, tool, hash, def_json, first_seen, approved) "
                "VALUES (%s, %s, %s, %s, %s, 1) ON CONFLICT (server, tool) DO UPDATE SET "
                "hash=EXCLUDED.hash, def_json=EXCLUDED.def_json, approved=1",
                (server, tool, new_hash, new_json, first_seen),
            )
            cur.execute("DELETE FROM quarantine WHERE server=%s AND tool=%s", (server, tool))

        old_hash = old["hash"] if old else None
        log.warning("RE-PINNED by human %s/%s: sha256:%s → sha256:%s",
                    server, tool, (old_hash or "none")[:12], new_hash[:12])
        return Decision(Verdict.ALLOWED,
                        reason=f"human re-approved {server}/{tool}; re-pinned to sha256:{new_hash[:12]}",
                        layer="integrity", server=server, tool=tool,
                        details={"new_hash": new_hash, "old_hash": old_hash, "reapproved": True})

    def pins(self, server: str | None = None) -> list[dict[str, Any]]:
        return self._select("SELECT server, tool, hash, def_json, first_seen, approved FROM pins", server)

    def quarantined(self, server: str | None = None) -> list[dict[str, Any]]:
        return self._select("SELECT server, tool, hash, def_json, seen FROM quarantine", server)

    def _select(self, sql: str, server: str | None) -> list[dict[str, Any]]:
        from psycopg.rows import dict_row

        args: tuple = ()
        if server:
            sql += " WHERE server=%s"
            args = (server,)
        with self._lock, self._conn.transaction(), self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql + " ORDER BY server, tool", args)
            return [dict(r) for r in cur.fetchall()]

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


# ---- rate limiter over Redis ------------------------------------------------


class RedisRateLimiter:
    """Sliding-window rate limiter in Redis, shared across the fleet.

    One sorted set per (agent, server, tool, window): members are call
    timestamps, scored by time. Check = trim the window and count; record = add
    this call. Because the counter lives in Redis, the limit is a fleet-wide
    ceiling, not a per-instance one — 30/min means 30/min no matter how many
    Warden instances the calls are spread across.
    """

    def __init__(self, url: str) -> None:
        import redis  # lazy

        self._r = redis.Redis.from_url(url)

    def check_and_record(self, agent: str, server: str, tool: str, rate_limit: dict[str, int]) -> str | None:
        now = time.time()
        windows = [(name, secs) for name, secs in (("per_minute", 60.0), ("per_hour", 3600.0))
                   if rate_limit.get(name)]
        # Check every configured window first; only record if all pass, so a call
        # that trips the limit does not itself consume a slot.
        for name, secs in windows:
            key = self._key(agent, server, tool, name)
            self._r.zremrangebyscore(key, 0, now - secs)
            count = self._r.zcard(key)
            if count >= rate_limit[name]:
                return (f"rate limit exceeded: {count} call(s) to {tool} by {agent} "
                        f"in the last {name.replace('per_', '')} (limit {rate_limit[name]})")
        member = f"{now:.6f}:{uuid.uuid4().hex}"
        for name, secs in windows:
            key = self._key(agent, server, tool, name)
            self._r.zadd(key, {member: now})
            self._r.expire(key, int(secs) + 1)
        return None

    @staticmethod
    def _key(agent: str, server: str, tool: str, window: str) -> str:
        return f"warden:rl:{agent}:{server}:{tool}:{window}"

    def close(self) -> None:
        try:
            self._r.close()
        except Exception:
            pass
