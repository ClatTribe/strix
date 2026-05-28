"""Tests for iter-Q5.46 — `enumerate_subdomains_crtsh` wrapper.

Covers:
  * Empty domain → error
  * STRIX_CRTSH_DISABLED=1 → partial (recall-safe)
  * URL construction — encodes the wildcard query, honours
    include_expired toggle
  * Response parsing — common_name + name_value (multi-line SANs)
  * Wildcard prefix strip (`*.foo` → `foo`)
  * Apex-relative filter — drops fuzzy-match noise from outside
    the apex
  * Lower-case + trailing-dot strip
  * Malformed JSON → partial (not crash)
  * Non-list response → partial
  * HTTPError 502 → retried; persistent failure → partial
  * Timeout → partial
  * max_results cap honoured
"""

from __future__ import annotations

import importlib
import json
from io import BytesIO
from unittest.mock import MagicMock

import pytest

# Module-import via importlib so we get the MODULE, not the function
# (the package `__init__` re-exports the callable under the same name).
sci = importlib.import_module(
    "strix.tools.crtsh_runner.enumerate_subdomains_crtsh",
)
enumerate_subdomains_crtsh = sci.enumerate_subdomains_crtsh


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_CRTSH_DISABLED", raising=False)


# ----------------------------------------------------------------------
# Recall-safe degrade paths
# ----------------------------------------------------------------------

class TestRecallSafeDegrades:
    def test_error_when_empty(self):
        out = enumerate_subdomains_crtsh("")
        assert out["status"] == "error"
        assert out["subdomains"] == []

    def test_partial_when_disabled(self, monkeypatch):
        monkeypatch.setenv("STRIX_CRTSH_DISABLED", "1")
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "partial"
        assert out["success"] is True
        assert "STRIX_CRTSH_DISABLED" in out["reason"]

    @pytest.mark.parametrize("v", ["true", "yes", "on", "1"])
    def test_partial_when_disabled_alternative_truthy(self, monkeypatch, v):
        monkeypatch.setenv("STRIX_CRTSH_DISABLED", v)
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "partial"


# ----------------------------------------------------------------------
# URL construction
# ----------------------------------------------------------------------

def _mock_urlopen(monkeypatch, body: str | bytes):
    """Stub urllib.request.urlopen so the test can return any body."""
    captured: list[object] = []

    class _Resp:
        def __init__(self, data: bytes):
            self._data = data

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def read(self):
            return self._data

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        captured.append(req)
        if isinstance(body, str):
            return _Resp(body.encode("utf-8"))
        return _Resp(body)

    monkeypatch.setattr(sci.urllib.request, "urlopen", _fake_urlopen)
    return captured


class TestUrlConstruction:
    def test_wildcard_query_url_encoded(self, monkeypatch):
        captured = _mock_urlopen(monkeypatch, "[]")
        enumerate_subdomains_crtsh("example.com")
        # The captured Request has the URL we want.
        url = captured[0].full_url  # type: ignore[attr-defined]
        # Wildcard `%` is encoded as %25 by urlencode (literal `%`).
        assert "q=%25.example.com" in url or "q=%2525.example.com" in url
        assert "output=json" in url

    def test_include_expired_default_no_exclude(self, monkeypatch):
        captured = _mock_urlopen(monkeypatch, "[]")
        enumerate_subdomains_crtsh("example.com")
        url = captured[0].full_url  # type: ignore[attr-defined]
        assert "exclude=expired" not in url

    def test_exclude_expired_flag(self, monkeypatch):
        captured = _mock_urlopen(monkeypatch, "[]")
        enumerate_subdomains_crtsh("example.com", include_expired=False)
        url = captured[0].full_url  # type: ignore[attr-defined]
        assert "exclude=expired" in url

    def test_apex_lowercased_in_query(self, monkeypatch):
        captured = _mock_urlopen(monkeypatch, "[]")
        enumerate_subdomains_crtsh("Example.COM")
        url = captured[0].full_url  # type: ignore[attr-defined]
        assert "example.com" in url
        assert "EXAMPLE" not in url

    def test_user_agent_set(self, monkeypatch):
        captured = _mock_urlopen(monkeypatch, "[]")
        enumerate_subdomains_crtsh("example.com")
        req = captured[0]
        ua = req.headers.get("User-agent")  # type: ignore[attr-defined]
        assert ua and "strix-crtsh" in ua


# ----------------------------------------------------------------------
# Response parsing
# ----------------------------------------------------------------------

class TestResponseParsing:
    def test_common_name_extracted(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": "api.example.com"},
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert out["subdomains"] == ["api.example.com"]
        assert out["status"] == "ok"

    def test_name_value_multiline_SANs(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {"name_value": "api.example.com\nadmin.example.com"},
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert sorted(out["subdomains"]) == [
            "admin.example.com", "api.example.com",
        ]

    def test_both_common_name_and_name_value(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {
                "common_name": "api.example.com",
                "name_value": "admin.example.com\napi.example.com",
            },
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        # Dedup — api appears twice, surfaces once.
        assert sorted(out["subdomains"]) == [
            "admin.example.com", "api.example.com",
        ]

    def test_wildcard_prefix_stripped(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": "*.api.example.com"},
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert out["subdomains"] == ["api.example.com"]

    def test_off_apex_dropped(self, monkeypatch):
        """crt.sh fuzzy LIKE returns unrelated certs sometimes."""
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": "api.example.com"},
            {"common_name": "evil.attacker.com"},  # off-apex
            {"common_name": "myexample.com"},      # off-apex (prefix match)
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert out["subdomains"] == ["api.example.com"]

    def test_apex_itself_kept(self, monkeypatch):
        """The apex `example.com` is a valid CT entry — keep it.
        (The Q5.44 extractor drops it from the child sidecar separately.)"""
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": "example.com"},
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert out["subdomains"] == ["example.com"]

    def test_trailing_dot_stripped(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": "api.example.com."},
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert out["subdomains"] == ["api.example.com"]

    def test_case_dedup(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": "api.example.com"},
            {"common_name": "API.EXAMPLE.COM"},
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert out["subdomains"] == ["api.example.com"]

    def test_non_dict_records_skipped(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            "garbage",
            42,
            {"common_name": "api.example.com"},
            None,
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert out["subdomains"] == ["api.example.com"]


# ----------------------------------------------------------------------
# Malformed responses
# ----------------------------------------------------------------------

class TestMalformedResponses:
    def test_invalid_json_returns_partial(self, monkeypatch):
        _mock_urlopen(monkeypatch, "not json")
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "partial"
        assert out["success"] is True
        assert "not JSON" in out["reason"]

    def test_non_list_response_returns_partial(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps({"error": "rate limited"}))
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "partial"
        assert "not a list" in out["reason"]

    def test_empty_list_ok_with_zero_subdomains(self, monkeypatch):
        _mock_urlopen(monkeypatch, "[]")
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "ok"
        assert out["subdomains"] == []
        assert out["total_found"] == 0


# ----------------------------------------------------------------------
# Network failures
# ----------------------------------------------------------------------

class TestNetworkFailures:
    def test_httperror_502_retried(self, monkeypatch):
        """502 / 503 / 504 are retried (crt.sh is intermittent)."""
        import urllib.error
        calls = {"n": 0}

        def _fake_urlopen(req, timeout=None):  # noqa: ARG001
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.HTTPError(
                    req.full_url, 502, "Bad Gateway", {}, None,  # type: ignore[arg-type]
                )

            class _Resp:
                def __enter__(self): return self
                def __exit__(self, *_): return None
                def read(self): return json.dumps([
                    {"common_name": "api.example.com"},
                ]).encode("utf-8")

            return _Resp()

        monkeypatch.setattr(sci.urllib.request, "urlopen", _fake_urlopen)
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "ok"
        assert out["subdomains"] == ["api.example.com"]
        assert calls["n"] == 2  # first 502, second success

    def test_httperror_400_not_retried(self, monkeypatch):
        """Client errors (4xx other than 408/429) bail immediately."""
        import urllib.error
        calls = {"n": 0}

        def _fake_urlopen(req, timeout=None):  # noqa: ARG001
            calls["n"] += 1
            raise urllib.error.HTTPError(
                req.full_url, 400, "Bad Request", {}, None,  # type: ignore[arg-type]
            )

        monkeypatch.setattr(sci.urllib.request, "urlopen", _fake_urlopen)
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "partial"
        assert calls["n"] == 1  # bailed without retry

    def test_persistent_502_returns_partial(self, monkeypatch):
        """Both attempts return 502 → partial."""
        import urllib.error

        def _fake_urlopen(req, timeout=None):  # noqa: ARG001
            raise urllib.error.HTTPError(
                req.full_url, 502, "Bad Gateway", {}, None,  # type: ignore[arg-type]
            )

        monkeypatch.setattr(sci.urllib.request, "urlopen", _fake_urlopen)
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "partial"
        assert "502" in out["reason"]

    def test_socket_timeout_returns_partial(self, monkeypatch):
        import socket

        def _fake_urlopen(req, timeout=None):  # noqa: ARG001
            raise socket.timeout("read timeout")

        monkeypatch.setattr(sci.urllib.request, "urlopen", _fake_urlopen)
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "partial"
        assert "timeout" in out["reason"].lower()

    def test_oserror_returns_partial(self, monkeypatch):
        def _fake_urlopen(req, timeout=None):  # noqa: ARG001
            raise OSError("network down")

        monkeypatch.setattr(sci.urllib.request, "urlopen", _fake_urlopen)
        out = enumerate_subdomains_crtsh("example.com")
        assert out["status"] == "partial"
        assert "network down" in out["reason"]


# ----------------------------------------------------------------------
# max_results
# ----------------------------------------------------------------------

class TestMaxResults:
    def test_cap_honoured(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": f"s{i}.example.com"} for i in range(20)
        ]))
        out = enumerate_subdomains_crtsh("example.com", max_results=5)
        assert len(out["subdomains"]) == 5

    def test_default_500(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": f"s{i}.example.com"} for i in range(600)
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        assert len(out["subdomains"]) == 500


# ----------------------------------------------------------------------
# Return shape
# ----------------------------------------------------------------------

class TestReturnShape:
    def test_required_keys_present(self, monkeypatch):
        _mock_urlopen(monkeypatch, json.dumps([
            {"common_name": "api.example.com"},
        ]))
        out = enumerate_subdomains_crtsh("example.com")
        # Q5.44 extractor reads `subdomains`.
        assert "subdomains" in out
        assert isinstance(out["subdomains"], list)
        for k in ("success", "status", "domain", "total_found"):
            assert k in out


# ----------------------------------------------------------------------
# Anti-overfit
# ----------------------------------------------------------------------

def test_no_fixture_identifiers_in_impl():
    import inspect
    src = inspect.getsource(sci)
    banned = {
        "juice-shop", "bkimminich", "vampi", "crapi", "wavsep",
        "getedunext",
    }
    for ident in banned:
        assert ident not in src.lower(), (
            f"crt.sh wrapper references SUT identifier {ident!r}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
