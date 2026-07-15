"""Ledger — the append-only, hash-chained audit log (defeats the blind spot).

THE PROBLEM — the audit blind spot. When something goes wrong, the first question is "what
happened, exactly?" A flat log answers that only until someone with write access
edits it. Compliance — and honest post-incident analysis — needs a record that
is *tamper-evident*: you may not be able to stop someone deleting a row, but you
must be able to PROVE a row was deleted.

THE MECHANISM. Each entry carries the hash of the one before it:

    entry_hash = SHA256(prev_hash + canonical_json(payload))

where `payload` is the entry's own fields (seq, ts, agent, server, tool, verdict,
reason, args_hash, result_hash) and `prev_hash` is the previous entry's
`entry_hash` (genesis = 64 zeros). Binding `seq` into the payload ties each entry
to its position, and chaining `prev_hash` ties each entry to its history. So:

  * edit any field of any row       → its entry_hash no longer recomputes → caught
  * delete a row                    → the next row's prev_hash no longer links → caught
  * reorder / insert a row          → seq and linkage disagree → caught

`verify_chain()` re-walks the whole thing and returns the FIRST seq that breaks,
so a tamper is localized, not just detected.

WHAT WE STORE. Hashes of the arguments and result, never the payloads
themselves. The audit log records *that* `read_file` was called and *what
verdict* it got, with a hash that proves the arguments — without becoming a
second copy of every secret that ever flowed through the gateway.

INVARIANTS. Append-only: this module contains no UPDATE and no DELETE of audit
rows, by design. Appends are serialized so the chain stays strictly ordered, and
each append reads prev_hash and writes the new row with no yield point in
between, so two concurrent calls can never fork the chain.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from warden.verdicts import Decision, Verdict

log = logging.getLogger("warden.ledger")

GENESIS_PREV = "0" * 64  # the prev_hash of the very first entry


def _canonical(obj: Any) -> str:
    """Stable JSON: same content → same bytes, so a hash is reproducible."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def hash_payload(payload: dict[str, Any]) -> str:
    return _sha(_canonical(payload))


# The fields that make up the hashed payload, in a fixed set. entry_hash and
# prev_hash are deliberately NOT in here: prev_hash is prepended separately (so
# it appears exactly once in the preimage), and entry_hash is the output.
PAYLOAD_FIELDS = ("seq", "ts", "agent", "server", "tool", "verdict", "reason", "args_hash", "result_hash")


def _entry_hash(row: dict[str, Any]) -> str:
    payload = {k: row[k] for k in PAYLOAD_FIELDS}
    return _sha(row["prev_hash"] + _canonical(payload))


class Ledger:
    """Append-only hash-chained audit store over SQLite."""

    def __init__(self, db_path: str | Path = "warden.db") -> None:
        self.db_path = str(db_path)
        # A plain threading.Lock, and a SYNC append with no await inside it, is
        # what keeps the chain strictly ordered. Because there is no yield point
        # between reading prev_hash and inserting the new row, two calls on the
        # event loop can never interleave and fork the chain — which an async
        # lock around async DB I/O could not guarantee as cheaply.
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    seq         INTEGER PRIMARY KEY,
                    ts          REAL NOT NULL,
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

    # ---- append (the only writer) -------------------------------------------

    def append(
        self,
        decision: Decision,
        *,
        args: Any = None,
        result_text: str | None = None,
    ) -> dict[str, Any]:
        """Record one decision as the next link in the chain. Returns the row.

        Runs for EVERY verdict — allow, every kind of block, every flag — so the
        ledger is a complete account of what the gateway decided, not just what
        it refused.
        """
        args_hash = _sha(_canonical(args if args is not None else {}))
        result_hash = _sha(result_text or "")

        with self._lock:
            with self._connect() as conn:
                last = conn.execute(
                    "SELECT seq, entry_hash FROM audit ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = 1 if last is None else last["seq"] + 1
                prev_hash = GENESIS_PREV if last is None else last["entry_hash"]

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

                conn.execute(
                    "INSERT INTO audit (seq, ts, agent, server, tool, verdict, reason, "
                    "args_hash, result_hash, prev_hash, entry_hash) "
                    "VALUES (:seq, :ts, :agent, :server, :tool, :verdict, :reason, "
                    ":args_hash, :result_hash, :prev_hash, :entry_hash)",
                    row,
                )
        log.info("audit #%d %s %s/%s → %s", seq, row["agent"], row["server"], row["tool"], row["verdict"])
        return row

    # ---- verify --------------------------------------------------------------

    def verify_chain(self) -> dict[str, Any]:
        """Re-walk from genesis, recomputing every hash and checking every link.

        Returns {ok, broken_seq, count, detail}. `broken_seq` is the FIRST seq
        whose stored hash or linkage disagrees with a fresh recomputation — i.e.
        exactly where the record was tampered with (or a row went missing right
        before it).
        """
        with self._connect() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM audit ORDER BY seq ASC")]

        prev = GENESIS_PREV
        expected_seq = 1
        for row in rows:
            # A gap or reordering in seq is itself evidence of a deleted/moved row.
            if row["seq"] != expected_seq:
                return {"ok": False, "broken_seq": row["seq"], "count": len(rows),
                        "detail": f"seq gap: expected {expected_seq}, found {row['seq']} "
                                  f"(a row was deleted or reordered)"}
            # Linkage: this row must point at the previous row's hash.
            if row["prev_hash"] != prev:
                return {"ok": False, "broken_seq": row["seq"], "count": len(rows),
                        "detail": f"broken link at seq {row['seq']}: prev_hash does not match "
                                  f"the previous entry's hash"}
            # Integrity: recompute this row's own hash from its contents.
            if _entry_hash(row) != row["entry_hash"]:
                return {"ok": False, "broken_seq": row["seq"], "count": len(rows),
                        "detail": f"tampered content at seq {row['seq']}: a field was changed "
                                  f"after it was written"}
            prev = row["entry_hash"]
            expected_seq += 1

        return {"ok": True, "broken_seq": None, "count": len(rows), "detail": "chain intact"}

    # ---- reads (for the dashboard/API) ---------------------

    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"]

    def all(self, limit: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit ORDER BY seq ASC"
        if limit:
            sql = f"SELECT * FROM (SELECT * FROM audit ORDER BY seq DESC LIMIT {int(limit)}) ORDER BY seq ASC"
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(sql)]

    # ---- export --------------------------------------------------------------

    def export_verifiable(self) -> str:
        """JSONL, one entry per line, carrying prev_hash + entry_hash so a third
        party can re-walk and re-verify the chain OFFLINE — no trust in us
        required, just the same hash function."""
        lines = [_canonical(row) for row in self.all()]
        return "\n".join(lines) + ("\n" if lines else "")

    def export_csv(self) -> str:
        """CSV convenience export. Clearly labelled UNVERIFIED: a spreadsheet
        drops the hash-chain semantics, so this is for eyeballing, not proof."""
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

    @staticmethod
    def verify_export(jsonl: str) -> dict[str, Any]:
        """Re-verify a JSONL export offline (no database needed). The same walk
        as verify_chain(), but over exported text — this is what makes the export
        'verifiable' rather than just 'a dump'."""
        rows = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
        prev = GENESIS_PREV
        expected_seq = 1
        for row in rows:
            if row["seq"] != expected_seq or row["prev_hash"] != prev or _entry_hash(row) != row["entry_hash"]:
                return {"ok": False, "broken_seq": row["seq"], "count": len(rows)}
            prev = row["entry_hash"]
            expected_seq += 1
        return {"ok": True, "broken_seq": None, "count": len(rows)}
