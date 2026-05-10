"""Tests for the template interpreter (single-template execution)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from strix.tools.nuclei_runner.interpreter import (
    _base_url,
    _substitute,
    run_template,
)
from strix.tools.nuclei_runner.parser import parse_template_file


_FIXTURES = Path(__file__).parent / "fixtures" / "templates"


@pytest.fixture
def patch_proxy(monkeypatch):
    """Yields a setter; tests provide a callable
    `(method, url, headers, body, timeout) -> dict`."""
    state = {"fn": lambda *a, **kw: {"status_code": 200, "body": "", "headers": {}}}

    def setter(fn):
        state["fn"] = fn

    fake = MagicMock()

    def _send(method, url, headers, body, timeout):
        return state["fn"](method, url, headers, body, timeout)

    fake.send_simple_request = MagicMock(side_effect=_send)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager", lambda: fake,
    )
    return setter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_base_url_strips_path() -> None:
    assert _base_url("http://example.com/api/x") == "http://example.com"
    assert _base_url("https://example.com:8443/foo") == "https://example.com:8443"
    # Already a base URL.
    assert _base_url("http://example.com") == "http://example.com"


def test_substitute_baseurl() -> None:
    out = _substitute("{{BaseURL}}/jobmanager/logs",
                      base_url="http://target.test:3000")
    assert out == "http://target.test:3000/jobmanager/logs"


def test_substitute_other_vars() -> None:
    out = _substitute("https://{{Hostname}}/x",
                      base_url="http://target.test:3000")
    assert "target.test:3000" in out


# ---------------------------------------------------------------------------
# run_template happy path
# ---------------------------------------------------------------------------


def test_run_apache_flink_match(patch_proxy) -> None:
    tpl = parse_template_file(_FIXTURES / "apache-flink-unauth.yaml")

    def fake(method, url, headers, body, timeout):
        if "/jobmanager/logs" in url:
            return {
                "status_code": 200,
                "body": "Apache Flink Dashboard\nLog viewer\n",
                "headers": {},
            }
        return {"status_code": 404, "body": "", "headers": {}}

    patch_proxy(fake)
    result = run_template(tpl, target_url="http://target.test:3000")
    assert result.matched is True
    assert result.template_id == "apache-flink-unauth-fixture"
    assert result.matched_request_index == 0
    assert "/jobmanager/logs" in result.matched_path
    assert "word" in result.matched_matchers
    assert "status" in result.matched_matchers


def test_run_template_does_not_match_on_wrong_response(patch_proxy) -> None:
    tpl = parse_template_file(_FIXTURES / "apache-flink-unauth.yaml")
    patch_proxy(lambda *a, **kw: {
        "status_code": 200,
        "body": "this is not flink — it's nginx",
        "headers": {},
    })
    result = run_template(tpl, target_url="http://target.test/")
    assert result.matched is False


def test_run_template_status_only_mismatch(patch_proxy) -> None:
    """Both matchers required (AND); status mismatch fails the AND."""
    tpl = parse_template_file(_FIXTURES / "apache-flink-unauth.yaml")
    patch_proxy(lambda *a, **kw: {
        "status_code": 500,
        "body": "Apache Flink Dashboard",
        "headers": {},
    })
    result = run_template(tpl, target_url="http://target.test/")
    assert result.matched is False


def test_run_unsupported_template_returns_error(patch_proxy) -> None:
    tpl = parse_template_file(_FIXTURES / "unsupported-workflow.yaml")
    result = run_template(tpl, target_url="http://target.test/")
    assert result.matched is False
    assert result.error is not None
    assert "unsupported" in result.error


def test_run_with_empty_url_errors(patch_proxy) -> None:
    tpl = parse_template_file(_FIXTURES / "apache-flink-unauth.yaml")
    result = run_template(tpl, target_url="")
    assert result.matched is False
    assert result.error == "empty target_url"


def test_run_with_proxy_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: (_ for _ in ()).throw(ImportError("no proxy")),
    )
    tpl = parse_template_file(_FIXTURES / "apache-flink-unauth.yaml")
    result = run_template(tpl, target_url="http://target.test/")
    assert result.matched is False
    assert "proxy_manager unavailable" in result.error


def test_run_template_transport_error_continues(patch_proxy) -> None:
    """A single-path transport error doesn't crash the run; matcher
    just doesn't fire."""
    tpl = parse_template_file(_FIXTURES / "apache-flink-unauth.yaml")
    def fake(method, url, headers, body, timeout):
        raise OSError("connection reset")
    patch_proxy(fake)
    result = run_template(tpl, target_url="http://target.test/")
    assert result.matched is False


def test_run_template_forwards_extra_headers(patch_proxy) -> None:
    """The lead's auth headers should propagate to the request."""
    tpl = parse_template_file(_FIXTURES / "apache-flink-unauth.yaml")
    captured = []
    def fake(method, url, headers, body, timeout):
        captured.append(dict(headers or {}))
        return {"status_code": 200, "body": "Apache Flink", "headers": {}}
    patch_proxy(fake)
    run_template(
        tpl, target_url="http://target.test/",
        extra_headers={"Authorization": "Bearer xyz"},
    )
    assert captured
    assert captured[0].get("Authorization") == "Bearer xyz"


def test_run_template_substitutes_baseurl_in_headers() -> None:
    """{{BaseURL}} in a header value gets replaced (e.g. ssrf
    callback templates)."""
    from strix.tools.nuclei_runner.parser import parse_template
    tpl = parse_template({
        "id": "header-sub-fixture",
        "info": {"name": "x", "severity": "low"},
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/x"],
            "headers": {"X-Origin": "{{BaseURL}}"},
            "matchers": [{"type": "status", "status": [200]}],
        }],
    })
    captured = []
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=lambda *a, **kw: (
        captured.append(kw.get("headers") or a[2]),
        {"status_code": 200, "body": "", "headers": {}},
    )[1])
    import strix.tools.proxy.proxy_manager as pm_mod
    orig = pm_mod.get_proxy_manager
    pm_mod.get_proxy_manager = lambda: fake
    try:
        run_template(tpl, target_url="http://target.test:3000/foo")
    finally:
        pm_mod.get_proxy_manager = orig
    assert captured[0].get("X-Origin") == "http://target.test:3000"
