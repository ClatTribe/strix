"""Local HTTP listener backend for OOB callbacks.

Spawns a low-overhead HTTP server in a daemon thread bound to
`STRIX_OOB_LOCAL_HOST` (default `127.0.0.1:8443` for unit tests;
production deployments should bind a public IP). When a callback
hits the listener, the request is recorded keyed by the token
embedded in the URL path or Host header.

URL format: `http://<host>:<port>/<token>` — the token segment is
checked against any pending registrations.

This backend is designed for hermetic testability + deployments
where external infra (interactsh.sh) isn't reachable. For real
DNS-based blind XXE / SSRF detection you typically need a backend
with a wildcard DNS record (interactsh / dnslog / Burp
Collaborator).
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


logger = logging.getLogger(__name__)


class LocalListenerBackend:
    """In-process HTTP listener for OOB callbacks.

    Methods (matched by service.py's backend protocol):
      * `name`: str — `"local"`
      * `callback_url_for(token)` → URL the specialist embeds
      * `poll(token, timeout_seconds)` → block until a hit lands
      * `shutdown()` — graceful teardown
    """

    name = "local"

    def __init__(self) -> None:
        host_spec = os.environ.get("STRIX_OOB_LOCAL_HOST", "127.0.0.1:8443")
        if ":" in host_spec:
            host, port_str = host_spec.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_spec
            port = 8443

        # Allow port=0 in tests (auto-assign).
        self._hits: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._hits_lock = threading.Lock()
        self._hits_event: dict[str, threading.Event] = defaultdict(threading.Event)

        handler_cls = _make_handler_class(self._hits, self._hits_lock, self._hits_event)
        self._server = ThreadingHTTPServer((host, port), handler_cls)
        actual_port = self._server.server_address[1]
        self._public_host = host if host != "0.0.0.0" else (
            os.environ.get("STRIX_OOB_PUBLIC_HOST") or socket.gethostname()
        )
        self._public_port = actual_port
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
            name="strix-oob-listener",
        )
        self._thread.start()
        logger.info(
            "OOB local listener bound to %s:%d (public %s:%d)",
            host, actual_port, self._public_host, self._public_port,
        )

    def callback_url_for(self, token: str) -> str:
        return f"http://{self._public_host}:{self._public_port}/{token}"

    def poll(self, token: str, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        """Block until a hit lands matching `token` OR timeout."""
        evt = self._hits_event[token]
        if evt.wait(timeout=timeout_seconds):
            with self._hits_lock:
                hits = list(self._hits.get(token, []))
            if hits:
                first = hits[0]
                return {
                    "hit": True,
                    "source_ip": first.get("source_ip"),
                    "raw_request": first,
                }
        return {"hit": False, "source_ip": None, "raw_request": None}

    def shutdown(self) -> None:
        try:
            self._server.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._server.server_close()
        except Exception:  # noqa: BLE001
            pass


def _make_handler_class(
    hits_dict: dict[str, list[dict[str, Any]]],
    lock: threading.Lock,
    events: dict[str, threading.Event],
):
    """Build a closure-capturing handler class that records hits."""

    class _Handler(BaseHTTPRequestHandler):
        def _record(self) -> str | None:
            # Token is the first path segment.
            path = self.path.lstrip("/")
            token = path.split("/", 1)[0].split("?", 1)[0]
            if not token.startswith("strix"):
                return None
            entry = {
                "ts": time.time(),
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "source_ip": (self.client_address or ("?", 0))[0],
            }
            with lock:
                hits_dict[token].append(entry)
                events[token].set()
            return token

        def do_GET(self) -> None:  # noqa: N802
            self._record()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            try:
                self.wfile.write(b"strix-oob-ok")
            except Exception:  # noqa: BLE001
                pass

        def do_POST(self) -> None:  # noqa: N802
            self._record()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            # Suppress default access-log spam.
            pass

    return _Handler
