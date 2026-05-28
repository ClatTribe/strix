"""Tests for iter-Q7.4 — scan_path_traversal form / param discovery.

Pre-Q7.4 the scanner only inferred params from the URL's query string,
so a bare-path endpoint (no query) whose injectable parameter is
rendered in an on-page `<form>` produced ZERO probes and bailed with
status="partial". That is the dominant L1-DAST recall gap (path
traversal is 73% of the WAVSEP corpus, scored 0%).

Q7.4 adds, for a bare URL:
  1. form discovery — fetch the page, parse <form> (action + method +
     input field names) and same-origin <a href> query keys, inject
     into the discovered fields (GET query OR POST body);
  2. a blind common-param GET fallback when the page yields no form.

These tests pin that contract with a payload-aware proxy mock.
"""

from __future__ import annotations

import importlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest


_mod = importlib.import_module("strix.tools.specialist.scan_path_traversal")
scan_path_traversal = _mod.scan_path_traversal

# A /etc/passwd body that matches the scanner's uid-0 fingerprint regex.
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-pt-q74"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


def _patch_proxy(monkeypatch, side_effect):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=side_effect)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager", lambda: fake,
    )
    return fake


def _passwd_when_traversal(landing_html: str):
    """Proxy side-effect: return /etc/passwd when the request carries a
    traversal payload (in the GET URL or POST body), else the landing
    page. Mimics a vulnerable file-read endpoint."""

    def _resp(method, url, headers=None, body=None, timeout=None):  # noqa: ARG001
        blob = f"{url} {body or ''}".lower()
        if "etc/passwd" in blob or "etc%2fpasswd" in blob or "etc%252fpasswd" in blob:
            return {"status_code": 200, "body": _PASSWD}
        return {"status_code": 200, "body": landing_html}

    return _resp


# ----------------------------------------------------------------------
# _discover_injection_points (unit)
# ----------------------------------------------------------------------

class TestDiscoverInjectionPoints:
    def test_get_form_field_discovered(self):
        html = (
            '<html><body><form method="GET" action="/files/view.jsp">'
            '<input type="text" name="target"></form></body></html>'
        )
        pts = _mod._discover_injection_points("http://x.test/page.jsp", html)
        assert ("http://x.test/files/view.jsp", "GET", "target", {}) in pts

    def test_post_form_field_discovered_with_baseline(self):
        html = (
            '<form method="post" action="/load">'
            '<input name="doc"><input name="csrf" value="abc"></form>'
        )
        pts = _mod._discover_injection_points("http://x.test/p", html)
        # `doc` is injected; `csrf` rides along as a baseline field.
        doc_pts = [p for p in pts if p[2] == "doc"]
        assert doc_pts and doc_pts[0][1] == "POST"
        assert doc_pts[0][3] == {"csrf": "abc"}

    def test_href_query_param_discovered(self):
        html = '<a href="/dl.jsp?file=readme.txt">download</a>'
        pts = _mod._discover_injection_points("http://x.test/", html)
        assert any(p[2] == "file" and p[1] == "GET" for p in pts)

    def test_path_shaped_params_ranked_first(self):
        html = (
            '<form action="/a"><input name="zzz_other">'
            '<input name="file"></form>'
        )
        pts = _mod._discover_injection_points("http://x.test/", html)
        names = [p[2] for p in pts]
        assert names.index("file") < names.index("zzz_other")

    def test_cross_origin_href_skipped(self):
        html = '<a href="http://evil.test/x.jsp?file=y">x</a>'
        pts = _mod._discover_injection_points("http://x.test/", html)
        assert pts == []

    def test_no_html_returns_empty(self):
        assert _mod._discover_injection_points("http://x.test/", "") == []


# ----------------------------------------------------------------------
# end-to-end: form discovery closes the bare-URL gap
# ----------------------------------------------------------------------

class TestFormDiscoveryDetection:
    def test_get_form_discovery_finds_traversal(self, monkeypatch):
        """The WAVSEP shape: bare .jsp, no query, injectable param in a
        GET form. Discovery finds `target` and the traversal fires."""
        html = (
            '<html><body><form method="GET" action="">'
            '<input type="text" name="target"></form></body></html>'
        )
        _patch_proxy(monkeypatch, _passwd_when_traversal(html))
        out = scan_path_traversal(url="http://app.test/active/lfi/Case01.jsp")
        assert out["status"] == "ok"
        assert out["tool_metadata"]["discovery_mode"] == "form_discovery"
        assert out["tool_metadata"]["findings_emitted_to_tracer"] >= 1
        assert any("target" in e for e in out["evidence"])

    def test_post_form_discovery_finds_traversal(self, monkeypatch):
        html = (
            '<form method="POST" action="/read">'
            '<input name="path"></form>'
        )
        _patch_proxy(monkeypatch, _passwd_when_traversal(html))
        out = scan_path_traversal(url="http://app.test/lfi/post.jsp")
        assert out["status"] == "ok"
        assert out["tool_metadata"]["discovery_mode"] == "form_discovery"
        assert out["tool_metadata"]["findings_emitted_to_tracer"] >= 1
        # The winning probe was a POST.
        assert any("POST" in e for e in out["evidence"])


class TestBlindFallbackDetection:
    def test_blind_fallback_finds_traversal(self, monkeypatch):
        """No form on the page, but a common-named param IS vulnerable —
        the blind fallback sweep catches it."""
        _patch_proxy(monkeypatch, _passwd_when_traversal("<html>no form here</html>"))
        out = scan_path_traversal(url="http://app.test/lfi/bare.jsp")
        assert out["status"] == "ok"
        assert out["tool_metadata"]["discovery_mode"] == "blind_fallback"
        assert out["tool_metadata"]["findings_emitted_to_tracer"] >= 1


# ----------------------------------------------------------------------
# anti-overfit guard (CLAUDE.md §6.4)
# ----------------------------------------------------------------------

class TestNoOverfit:
    def test_source_has_no_sut_identifiers(self):
        src = Path(_mod.__file__).read_text(encoding="utf-8").lower()
        for ident in ("wavsep", "juice", "bkimminich", "vampi", "crapi", "erev0s"):
            assert ident not in src, f"SUT identifier {ident!r} leaked into detector source"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
