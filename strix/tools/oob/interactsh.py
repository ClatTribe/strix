"""Interactsh backend for OOB callbacks.

Wraps `interactsh-client` (already in the strix sandbox image) as a
subprocess. The CLI streams JSON events to stdout for every
DNS / HTTP hit on the registered domain — we tail that stream and
keyed-store the results by token (extracted from the subdomain
prefix).

`interactsh-client -json` output shape per hit (one JSON object per
line):

    {
      "protocol": "dns",
      "unique-id": "<unique-prefix>.interact.sh",
      "full-id": "...",
      "raw-request": "...",
      "remote-address": "x.x.x.x",
      "timestamp": "..."
    }

We reserve a 5-character random prefix per token that gets prepended
to the interactsh-issued domain, so the token segment is recoverable
from the inbound hit's `unique-id` field.

This backend is the production-grade default when interactsh-client
is on PATH. The tests use the local listener instead because
interactsh hits external infra.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import time
from collections import defaultdict
from typing import Any


logger = logging.getLogger(__name__)


class InteractshBackend:
    """Wraps `interactsh-client -json`. Initializes lazily on first
    `callback_url_for` call so we don't spawn the process if no
    specialist actually needs OOB."""

    name = "interactsh"

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._domain: str | None = None  # the unique interactsh domain assigned to us
        self._reader_thread: threading.Thread | None = None
        self._hits: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._hits_lock = threading.Lock()
        self._hits_event: dict[str, threading.Event] = defaultdict(threading.Event)
        self._init_lock = threading.Lock()

    def _ensure_started(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            return
        with self._init_lock:
            if self._proc is not None and self._proc.poll() is None:
                return
            cmd = ["interactsh-client", "-json"]
            server = os.environ.get("STRIX_OOB_INTERACTSH_SERVER")
            if server:
                cmd += ["-server", server]
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except FileNotFoundError as e:
                logger.warning("interactsh-client not found: %s", e)
                raise
            # Block briefly on stderr to capture the assigned domain.
            assigned = _capture_assigned_domain(self._proc, timeout=10.0)
            if not assigned:
                raise RuntimeError(
                    "interactsh-client did not announce an assigned domain "
                    "within 10s; backend unusable"
                )
            self._domain = assigned
            self._reader_thread = threading.Thread(
                target=self._reader_loop, daemon=True,
                name="strix-oob-interactsh-reader",
            )
            self._reader_thread.start()
            logger.info(
                "interactsh-client started; domain=%s pid=%d",
                self._domain, self._proc.pid,
            )

    def callback_url_for(self, token: str) -> str:
        self._ensure_started()
        # interactsh issues us a random subdomain. We embed the token
        # as a sub-subdomain so we can route inbound hits.
        return f"http://{token}.{self._domain}/"

    def poll(self, token: str, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
        evt = self._hits_event[token]
        if evt.wait(timeout=timeout_seconds):
            with self._hits_lock:
                hits = list(self._hits.get(token, []))
            if hits:
                first = hits[0]
                return {
                    "hit": True,
                    "source_ip": first.get("remote-address"),
                    "raw_request": first,
                }
        return {"hit": False, "source_ip": None, "raw_request": None}

    def shutdown(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2.0)
            except Exception:  # noqa: BLE001
                try:
                    self._proc.kill()
                except Exception:  # noqa: BLE001
                    pass

    # ------------------------------------------------------------------
    # Internal — JSON line reader
    # ------------------------------------------------------------------

    def _reader_loop(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            uid = event.get("unique-id") or event.get("full-id") or ""
            # Token is the lowest sub-subdomain segment.
            m = re.match(r"^(strix[a-f0-9]+)\.", uid.lower())
            if not m:
                continue
            token = m.group(1)
            with self._hits_lock:
                self._hits[token].append(event)
                self._hits_event[token].set()


def _capture_assigned_domain(
    proc: subprocess.Popen, *, timeout: float = 10.0,
) -> str | None:
    """interactsh-client announces its assigned subdomain on stderr
    at startup. Read until we see one or timeout."""
    if proc.stderr is None:
        return None
    deadline = time.time() + timeout
    pattern = re.compile(r"\b([a-z0-9]+\.(?:interact\.sh|oast\.[a-z]+))\b")
    while time.time() < deadline:
        line = proc.stderr.readline()
        if not line:
            time.sleep(0.05)
            continue
        m = pattern.search(line)
        if m:
            return m.group(1)
    return None
