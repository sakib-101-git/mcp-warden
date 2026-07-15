"""API — read-only HTTP + SSE for the dashboard.

The dashboard is a spectator, not a participant. This module exposes Warden's
live state over plain HTTP on localhost so a browser can render it, and it does
so under three hard constraints:

  * **It never touches the MCP wire.** Warden speaks JSON-RPC over stdout; this
    server runs in its own daemon thread on its own TCP port and logs only to
    stderr. One stray write to stdout would corrupt the protocol.
  * **It is read-only, with two exceptions** — approve/deny of a *pending*
    call, which resolve a real paused elicitation (not relabel a row). Every
    other endpoint only reads the ledger, the pin store, and the live queues.
  * **It is additive.** If the API fails to start or a request raises, the
    gateway keeps enforcing policy exactly as before. The dashboard going dark
    must never weaken the proxy.

Stdlib only (`http.server` + `threading` + `queue`) so the security core stays
dependency-light — the architecture doc explicitly allows "FastAPI or stdlib".

The seam feeds this module through an `EventHub`: every completed call, and
every pending/resolved transition, is published to a ring buffer (for
`/api/traffic`) and fanned out to SSE subscribers (for `/api/stream`). Because
the seam runs on the asyncio loop and HTTP handlers run on worker threads, the
hand-off uses thread-safe primitives only, and resolving a pending call is
marshalled back onto the loop by the caller-supplied `resolve_pending`.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from warden.verdicts import FLAG_VERDICTS, TERMINAL_BLOCK, Verdict

log = logging.getLogger("warden.api")

# Verdicts grouped under each Live-Traffic filter chip. Kept here (not in the
# handler) so it reads next to the enum it mirrors.
_BLOCKED = {v.value for v in TERMINAL_BLOCK}
_FLAGGED = {v.value for v in FLAG_VERDICTS}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


class EventHub:
    """Thread-safe fan-out of live events + a bounded ring buffer of traffic.

    The seam (asyncio loop thread) publishes; HTTP handlers (worker threads)
    read the ring buffer and drain per-subscriber queues. `queue.Queue` and a
    `Lock` are all this needs — no asyncio, so it works identically whichever
    thread calls in.
    """

    def __init__(self, buffer: int = 500) -> None:
        self._recent: deque[dict[str, Any]] = deque(maxlen=buffer)
        self._subs: set[queue.Queue] = set()
        self._lock = threading.Lock()

    # ---- producer side (called from the seam) --------------------------------

    def record_call(self, rec: dict[str, Any]) -> None:
        """A completed tool call (any verdict). Buffered for /api/traffic."""
        with self._lock:
            self._recent.append(rec)
        self._publish({"type": "call", **rec})

    def record_pending(self, rec: dict[str, Any]) -> None:
        """A call parked awaiting a human. Not buffered — it isn't traffic yet."""
        self._publish({"type": "pending", **rec})

    def record_resolved(self, rec: dict[str, Any]) -> None:
        """A pending call was answered (approved/denied/timed out)."""
        self._publish({"type": "resolved", **rec})

    def _publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:  # a stuck client must not back-pressure the seam
                pass

    # ---- consumer side (called from SSE handlers) ----------------------------

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(q)

    def recent(self, limit: int, filt: str = "all") -> list[dict[str, Any]]:
        """Most-recent-first traffic, optionally filtered by verdict group."""
        with self._lock:
            rows = list(self._recent)
        rows.reverse()

        def keep(r: dict[str, Any]) -> bool:
            v = r.get("verdict", "")
            if filt in ("all", ""):
                return True
            if filt == "allowed":
                return v == Verdict.ALLOWED.value
            if filt == "blocked":
                return v in _BLOCKED
            if filt == "pending":
                return v == Verdict.PENDING.value
            if filt == "flagged":
                return v in _FLAGGED
            return True

        return [r for r in rows if keep(r)][:limit]


class WardenAPI:
    """The dashboard's read model + the two approve/deny bridges.

    Holds references to the live layers so every response reflects real state.
    `resolve_pending(pending_id, approved)` is supplied by the seam and is the
    ONLY write path — it marshals `ElicitationGate.resolve` back onto the
    asyncio loop (a gate's `asyncio.Event` may only be set from the loop thread).
    """

    def __init__(
        self,
        *,
        ledger: Any,
        integrity: Any,
        gate: Any,
        pool: Any,
        config: Any,
        hub: EventHub,
        resolve_pending: Callable[[str, bool], bool],
    ) -> None:
        self.ledger = ledger
        self.integrity = integrity
        self.gate = gate
        self.pool = pool
        self.config = config
        self.hub = hub
        self.resolve_pending = resolve_pending
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ---- lifecycle -----------------------------------------------------------

    def start(self, host: str = "127.0.0.1", port: int = 8787) -> None:
        httpd = ThreadingHTTPServer((host, port), _Handler)
        httpd.daemon_threads = True  # SSE threads must not block process exit
        httpd.api = self  # type: ignore[attr-defined]  # handlers read this
        self._httpd = httpd
        self._thread = threading.Thread(
            target=httpd.serve_forever, name="warden-api", daemon=True
        )
        self._thread.start()
        log.info("dashboard API listening on http://%s:%d", host, port)

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    # ---- read models (built fresh per request; all reads are cheap) ----------

    def servers(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for d in self.config.downstreams:
            name = d.name
            quarantined = _safe(lambda: self.integrity.quarantined(name), [])
            pins = _safe(lambda: self.integrity.pins(name), [])
            connected = _safe(
                lambda: getattr(self.pool.egresses.get(name), "session", None) is not None,
                False,
            )
            if quarantined:
                status, risk = "quarantined", "high"
            elif not connected:
                status, risk = "degraded", "medium"
            else:
                status, risk = "healthy", "low"
            out.append({
                "name": name,
                "endpoint": f"stdio: {d.command} {' '.join(d.args)}".strip(),
                "status": status,
                "risk": risk,
                "tools": len(pins),
                "last_seen": _iso(time.time()),
            })
        return out

    def analytics(self) -> dict[str, Any]:
        rows = _safe(lambda: self.ledger.all(), [])
        now = time.time()
        midnight = now - (now % 86400)

        blocked = sum(1 for r in rows if r["verdict"] in _BLOCKED)
        flagged = sum(1 for r in rows if r["verdict"] in _FLAGGED)
        today = sum(1 for r in rows if r["ts"] >= midnight)
        pending = len(_safe(lambda: self.gate.pending_list(), []))

        # Calls per day for the last 7 days, oldest → newest (chart order).
        last7 = [0] * 7
        for r in rows:
            days_ago = int((midnight - (r["ts"] - (r["ts"] % 86400))) // 86400)
            if 0 <= days_ago < 7:
                last7[6 - days_ago] += 1

        counts: dict[str, int] = {}
        for r in rows:
            key = f"{r['server']}/{r['tool']}" if r["server"] else r["tool"]
            counts[key] = counts.get(key, 0) + 1
        top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:6]

        return {
            "kpis": {
                "total": len(rows),
                "today": today,
                "blocked": blocked,
                "flagged": flagged,
                "pending": pending,
                "servers": len(self.config.downstreams),
            },
            "last7days": last7,
            "top_tools": [{"name": n, "count": c} for n, c in top],
        }

    def pending(self) -> list[dict[str, Any]]:
        items = _safe(lambda: self.gate.pending_list(), [])
        return [
            {
                "id": p["id"],
                "server": p["server"],
                "tool": p["tool"],
                "agent": p["agent"],
                "created": p.get("created"),
                "reason": p.get("what_will_happen", ""),
                "what_will_happen": p.get("what_will_happen", ""),
            }
            for p in items
        ]


def _safe(fn: Callable[[], Any], default: Any) -> Any:
    """Any read failure degrades to a default — the dashboard must never take
    the gateway down, so a locked DB or a torn-down pool just shows stale/empty
    rather than raising into the HTTP thread."""
    try:
        return fn()
    except Exception:
        log.debug("api read failed — serving default", exc_info=True)
        return default


class _Handler(BaseHTTPRequestHandler):
    """Routes one request. `self.server.api` is the WardenAPI instance."""

    protocol_version = "HTTP/1.1"

    @property
    def api(self) -> WardenAPI:
        return self.server.api  # type: ignore[attr-defined]

    # Quiet by default; BaseHTTPRequestHandler logs to stderr (never stdout),
    # but per-request lines are noise next to the MCP logs.
    def log_message(self, fmt: str, *args: Any) -> None:
        log.debug("api %s - " + fmt, self.address_string(), *args)

    # ---- helpers -------------------------------------------------------------

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text: str, content_type: str, filename: str | None = None) -> None:
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    # ---- verbs ---------------------------------------------------------------

    def do_OPTIONS(self) -> None:  # noqa: N802 (stdlib naming)
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        try:
            if path == "/api/servers":
                return self._json(self.api.servers())
            if path == "/api/traffic":
                limit = _int(qs.get("limit"), 100)
                filt = (qs.get("filter") or ["all"])[0]
                return self._json(self.api.hub.recent(limit, filt))
            if path == "/api/stream":
                return self._stream()
            if path == "/api/audit":
                limit = _int(qs.get("limit"), 200)
                return self._json(_safe(lambda: self.api.ledger.all(limit), []))
            if path == "/api/audit/export":
                fmt = (qs.get("format") or ["jsonl"])[0]
                if fmt == "csv":
                    return self._text(self.api.ledger.export_csv(), "text/csv",
                                      "warden-audit-unverified.csv")
                return self._text(self.api.ledger.export_verifiable(),
                                  "application/x-ndjson", "warden-audit.jsonl")
            if path == "/api/analytics":
                return self._json(self.api.analytics())
            if path == "/api/pending":
                return self._json(self.api.pending())
            return self._json({"error": "not found", "path": path}, 404)
        except Exception as exc:  # a handler bug must not kill the API thread
            log.exception("api GET %s failed", path)
            return self._json({"error": str(exc)}, 500)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/api/audit/verify":
                return self._json(_safe(lambda: self.api.ledger.verify_chain(),
                                        {"ok": False, "broken_seq": None, "count": 0}))
            parts = path.strip("/").split("/")
            # /api/pending/{id}/approve|deny
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "pending":
                pending_id, action = parts[2], parts[3]
                if action in ("approve", "deny"):
                    ok = self.api.resolve_pending(pending_id, action == "approve")
                    return self._json({"ok": bool(ok), "id": pending_id, "action": action})
            return self._json({"error": "not found", "path": path}, 404)
        except Exception as exc:
            log.exception("api POST %s failed", path)
            return self._json({"error": str(exc)}, 500)

    # ---- SSE -----------------------------------------------------------------

    def _stream(self) -> None:
        """Server-Sent Events: one JSON event per new call / pending / resolved.

        Runs on this connection's own thread (ThreadingHTTPServer). Blocks on a
        per-subscriber queue with a timeout so it can send keepalive comments
        and notice a dropped client, and always unsubscribes on exit."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._cors()
        self.end_headers()

        q = self.api.hub.subscribe()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = q.get(timeout=15.0)
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")  # keepalive + disconnect probe
                    self.wfile.flush()
                    continue
                payload = json.dumps(event).encode("utf-8")
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # client went away — normal
        finally:
            self.api.hub.unsubscribe(q)


def _int(values: list[str] | None, default: int) -> int:
    try:
        return int(values[0]) if values else default
    except (ValueError, TypeError):
        return default
