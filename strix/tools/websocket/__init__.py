"""WebSocket / SSE first-class testing (roadmap §7.2).

Probes a WebSocket endpoint for the four classes that single-
target HTTP scanners always miss:

  * Auth-on-upgrade (CWE-306)
  * Origin reflection / bypass (CWE-942)
  * Cross-scheme allowance (`http://` Origin accepted on a TLS WS)
  * Subprotocol echo (Sec-WebSocket-Protocol reflected verbatim)

Everything is checked at the handshake level — `Connection:
Upgrade` + `Upgrade: websocket` + the magic key — without
needing a full WebSocket client library. Zero-FP-by-construction:
each finding is grounded in a binary 101 / non-101 outcome.
"""

from .websocket_audit import websocket_audit


__all__ = ["websocket_audit"]
