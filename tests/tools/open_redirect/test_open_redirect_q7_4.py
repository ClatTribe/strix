"""Tests for iter-Q7.4 — open_redirect_check page param-name discovery.

Pre-Q7.4, a bare URL (no query string) fell back to a 6-name default
set (`next, redirect, url, return, goto, dest`), missing redirect
params rendered in an on-page <form> or example links. Q7.4 fetches
the page and discovers candidate param names from <form> input fields
+ same-origin <a href> query keys (redirect-shaped names first) before
resorting to the blind defaults.
"""

from __future__ import annotations

import importlib

import pytest


_mod = importlib.import_module("strix.tools.open_redirect.open_redirect_check")


def _patch_get(monkeypatch, responder):
    def fake(url, *, timeout=10.0):  # noqa: ARG001
        return responder(url)

    monkeypatch.setattr(_mod, "_http_get", fake)


def _resp(body: str = ""):
    return {"status": 200, "headers": {}, "body": body}


class TestDiscoverRedirectParamNames:
    def test_form_field_name_discovered(self, monkeypatch):
        _patch_get(monkeypatch, lambda url: _resp(
            '<form action="/go"><input name="returnUrl"></form>'
        ))
        names = _mod._discover_redirect_param_names("http://x.test/login.jsp", 10.0)
        assert "returnUrl" in names

    def test_href_query_key_discovered(self, monkeypatch):
        _patch_get(monkeypatch, lambda url: _resp(
            '<a href="/redir.jsp?dest=/home">home</a>'
        ))
        names = _mod._discover_redirect_param_names("http://x.test/", 10.0)
        assert "dest" in names

    def test_redirect_shaped_names_ranked_first(self, monkeypatch):
        _patch_get(monkeypatch, lambda url: _resp(
            '<form><input name="zeta"><input name="redirect"></form>'
        ))
        names = _mod._discover_redirect_param_names("http://x.test/", 10.0)
        assert names.index("redirect") < names.index("zeta")

    def test_cross_origin_href_skipped(self, monkeypatch):
        _patch_get(monkeypatch, lambda url: _resp(
            '<a href="http://evil.test/x?next=y">x</a>'
        ))
        names = _mod._discover_redirect_param_names("http://x.test/", 10.0)
        assert "next" not in names

    def test_empty_body_returns_empty(self, monkeypatch):
        _patch_get(monkeypatch, lambda url: _resp(""))
        assert _mod._discover_redirect_param_names("http://x.test/", 10.0) == []


class TestBareUrlProbesDiscoveredParam:
    def test_discovered_param_is_probed(self, monkeypatch):
        """End-to-end: a bare URL whose redirect param `returnUrl` is
        only in the page form gets that param probed (it wouldn't be in
        the 6-name default set)."""
        log: list[str] = []

        def fake(url, *, timeout=10.0):  # noqa: ARG001
            log.append(url)
            return _resp('<form action=""><input name="returnUrl"></form>')

        monkeypatch.setattr(_mod, "_http_get", fake)
        out = _mod.open_redirect_check("http://app.test/login.jsp")
        assert out["success"] is True
        assert "returnUrl" in out["probed_params"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
