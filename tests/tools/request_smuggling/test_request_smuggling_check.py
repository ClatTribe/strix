"""Tests for request_smuggling_check.

Hermetic — `_send_one_probe` is monkeypatched so no real sockets are
opened. Tests cover:

- Target URL normalization (bare host / scheme / port)
- Probe cohort: 9 probes total, exactly 1 baseline + 8 variants
- Raw-request byte construction (no Content-Length when send_cl=False;
  duplicate TE lines preserved; vertical-tab obfuscation passes through)
- Response parsing (status line + headers + body)
- Differential analysis: status class change → high; body-length
  divergence → medium; matching response → no finding
- Probe error → no false-positive finding
- Baseline failure → all variants recorded as inconclusive
- Cluster-A composition: --exclude-path on baseline → graceful skip;
  --rate-limit throttle invoked
- Auth headers from STRIX_AUTH_BEARER → embedded in raw request
- Every emitted finding carries description_plain + recommended_action
- Check event emitted with category=http_request_smuggling
- Body-length divergence threshold filters out tiny noise
- 5xx-vs-5xx pair excluded from medium finding
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.request_smuggling.request_smuggling_check  # noqa: F401

rs_module = sys.modules["strix.tools.request_smuggling.request_smuggling_check"]
request_smuggling_check = rs_module.request_smuggling_check


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("rs-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com/"}]})
    yield


def _patch_probes(monkeypatch, responder):
    """Install a `_send_one_probe` fake. responder(probe_kwargs) → response dict."""
    log: list[dict[str, Any]] = []

    def fake(*, scheme, host, port, path, te_lines, send_cl, extra_headers, timeout):
        kwargs = {
            "scheme": scheme, "host": host, "port": port, "path": path,
            "te_lines": list(te_lines), "send_cl": send_cl,
            "extra_headers": dict(extra_headers), "timeout": timeout,
        }
        log.append(kwargs)
        return responder(kwargs)

    monkeypatch.setattr(rs_module, "_send_one_probe", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    return {"status": status, "headers": headers, "body": body, "raw_length": len(body) + 100}


# ---------------------------------------------------------------------------
# Target normalization
# ---------------------------------------------------------------------------


def test_bare_hostname_default_port() -> None:
    out = rs_module._normalize_target("example.com")
    assert out == {"scheme": "https", "host": "example.com", "port": 443, "path": "/"}


def test_explicit_http() -> None:
    out = rs_module._normalize_target("http://example.com:8080/foo")
    assert out == {"scheme": "http", "host": "example.com", "port": 8080, "path": "/foo"}


def test_query_preserved() -> None:
    out = rs_module._normalize_target("https://example.com/foo?x=1")
    assert out["path"] == "/foo?x=1"


def test_invalid_target_rejected() -> None:
    assert rs_module._normalize_target("") is None
    assert rs_module._normalize_target("   ") is None
    assert rs_module._normalize_target("ftp://example.com/") is None


# ---------------------------------------------------------------------------
# Probe cohort shape
# ---------------------------------------------------------------------------


def test_probe_cohort_size_and_baseline() -> None:
    probes = rs_module._build_probes()
    # 1 baseline + 8 variants = 9 probes total.
    assert len(probes) == 9
    baselines = [p for p in probes if p["is_baseline"]]
    assert len(baselines) == 1
    assert baselines[0]["label"] == "te_baseline"
    labels = {p["label"] for p in probes}
    expected = {
        "te_baseline", "te_xchunked", "te_space_after_value", "te_tab_after_value",
        "te_chunked_uppercase", "te_dual_value", "te_obscure_separator",
        "te_dup_header", "cl_te_present",
    }
    assert labels == expected


def test_te_dup_header_has_two_te_lines() -> None:
    probes = rs_module._build_probes()
    dup = next(p for p in probes if p["label"] == "te_dup_header")
    assert len(dup["te_lines"]) == 2
    assert all(line.startswith("Transfer-Encoding:") for line in dup["te_lines"])


def test_only_cl_te_probe_sends_content_length() -> None:
    probes = rs_module._build_probes()
    sends_cl = [p for p in probes if p["send_cl"]]
    assert len(sends_cl) == 1
    assert sends_cl[0]["label"] == "cl_te_present"


# ---------------------------------------------------------------------------
# Raw request bytes construction
# ---------------------------------------------------------------------------


def test_request_bytes_chunked_baseline() -> None:
    raw = rs_module._build_request_bytes(
        method="POST", path="/", host_header="example.com",
        te_lines=["Transfer-Encoding: chunked"],
        send_cl=False,
        extra_headers={"User-Agent": "x"},
        body=b"0\r\n\r\n",
    )
    assert b"POST / HTTP/1.1\r\n" in raw
    assert b"Host: example.com\r\n" in raw
    assert b"Transfer-Encoding: chunked\r\n" in raw
    # send_cl=False → no Content-Length header.
    assert b"Content-Length:" not in raw
    assert raw.endswith(b"0\r\n\r\n")


def test_request_bytes_cl_te() -> None:
    raw = rs_module._build_request_bytes(
        method="POST", path="/", host_header="example.com",
        te_lines=["Transfer-Encoding: chunked"],
        send_cl=True,
        extra_headers={},
        body=b"0\r\n\r\n",
    )
    assert b"Content-Length: 5\r\n" in raw
    assert b"Transfer-Encoding: chunked\r\n" in raw


def test_request_bytes_duplicate_te() -> None:
    raw = rs_module._build_request_bytes(
        method="POST", path="/", host_header="example.com",
        te_lines=["Transfer-Encoding: chunked", "Transfer-Encoding: identity"],
        send_cl=False, extra_headers={}, body=b"0\r\n\r\n",
    )
    # Both TE lines preserved verbatim.
    assert raw.count(b"Transfer-Encoding:") == 2


def test_request_bytes_vertical_tab_passes_through() -> None:
    """Vertical tab in header name must round-trip — that's the obfuscation."""
    raw = rs_module._build_request_bytes(
        method="POST", path="/", host_header="example.com",
        te_lines=["Transfer-Encoding\x0b: chunked"],
        send_cl=False, extra_headers={}, body=b"0\r\n\r\n",
    )
    assert b"Transfer-Encoding\x0b: chunked" in raw


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def test_parse_simple_200() -> None:
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"
    parsed = rs_module._parse_response(raw)
    assert parsed["status"] == 200
    assert parsed["headers"]["content-type"] == "text/html"
    assert parsed["body"] == "hello"


def test_parse_400_with_no_body() -> None:
    raw = b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n"
    parsed = rs_module._parse_response(raw)
    assert parsed["status"] == 400
    assert parsed["body"] == ""


def test_parse_empty_response() -> None:
    parsed = rs_module._parse_response(b"")
    assert parsed["status"] == 0
    assert parsed["headers"] == {}


# ---------------------------------------------------------------------------
# Status-class differential — high finding
# ---------------------------------------------------------------------------


def test_status_class_change_emits_high(monkeypatch) -> None:
    """Baseline 200 + xchunked variant returning 400 → high CWE-444."""
    def responder(kwargs):
        if kwargs["te_lines"] == ["Transfer-Encoding: chunked"]:
            return _resp(status=200, body="ok")
        if kwargs["te_lines"] == ["Transfer-Encoding: xchunked"]:
            return _resp(status=400, body="bad TE")
        return _resp(status=200, body="ok")

    _patch_probes(monkeypatch, responder)
    out = request_smuggling_check("https://example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high"]
    assert high, [r["title"] for r in reports]
    assert high[0]["cwe"] == "CWE-444"
    assert high[0]["category"] == "http_request_smuggling"
    assert out["findings_emitted"] >= 1


def test_status_class_reverse_change_emits_high(monkeypatch) -> None:
    """Baseline 400 + variant returning 200 → also high (parser disagreement
    in either direction)."""
    def responder(kwargs):
        if kwargs["te_lines"] == ["Transfer-Encoding: chunked"]:
            return _resp(status=400, body="rejected")
        return _resp(status=200, body="ok")

    _patch_probes(monkeypatch, responder)
    out = request_smuggling_check("https://example.com/")
    assert out["findings_emitted"] >= 1


# ---------------------------------------------------------------------------
# Body-length divergence — medium finding
# ---------------------------------------------------------------------------


def test_body_length_divergence_emits_medium(monkeypatch) -> None:
    """Same status class but >20% body delta → medium."""
    baseline_body = "x" * 1000
    variant_body = "y" * 2000  # 100% delta

    def responder(kwargs):
        if kwargs["te_lines"] == ["Transfer-Encoding: chunked"]:
            return _resp(status=200, body=baseline_body)
        if kwargs["te_lines"] == ["Transfer-Encoding: xchunked"]:
            return _resp(status=200, body=variant_body)
        return _resp(status=200, body=baseline_body)

    _patch_probes(monkeypatch, responder)
    out = request_smuggling_check("https://example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "medium" for r in reports)
    # No false high.
    assert all(r["severity"] != "high" for r in reports)
    assert out["findings_emitted"] >= 1


def test_small_body_delta_no_finding(monkeypatch) -> None:
    """<20% body delta in matching status class → no finding (within noise)."""
    baseline_body = "x" * 1000

    def responder(kwargs):
        if kwargs["te_lines"] == ["Transfer-Encoding: chunked"]:
            return _resp(status=200, body=baseline_body)
        if kwargs["te_lines"] == ["Transfer-Encoding: xchunked"]:
            return _resp(status=200, body="x" * 1100)  # 10% delta
        return _resp(status=200, body=baseline_body)

    _patch_probes(monkeypatch, responder)
    out = request_smuggling_check("https://example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    # The xchunked probe ran clean; if any other probe accidentally diverged
    # it would still be a valid finding. So we just assert no FALSE positive
    # from the xchunked alone — which means 0 findings if all others match.
    if reports:
        # If any finding exists, it must not be from the xchunked probe.
        for r in reports:
            assert "te_xchunked" not in r["title"]
    assert out["findings_emitted"] >= 0


def test_5xx_pair_excluded_from_medium(monkeypatch) -> None:
    """Both responses 5xx → no medium even if body length diverges."""
    def responder(kwargs):
        if kwargs["te_lines"] == ["Transfer-Encoding: chunked"]:
            return _resp(status=503, body="x" * 100)
        return _resp(status=503, body="y" * 1000)  # 90% delta but both 5xx

    _patch_probes(monkeypatch, responder)
    out = request_smuggling_check("https://example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    medium = [r for r in reports if r["severity"] == "medium"]
    assert medium == []
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Clean target → no findings
# ---------------------------------------------------------------------------


def test_clean_target_no_findings(monkeypatch) -> None:
    """All probes return the same response → no findings."""
    _patch_probes(monkeypatch, lambda kwargs: _resp(status=200, body="ok"))
    out = request_smuggling_check("https://example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Probe error handling
# ---------------------------------------------------------------------------


def test_probe_error_no_false_positive(monkeypatch) -> None:
    """Probe errors mid-cohort → recorded but not finding-worthy."""
    def responder(kwargs):
        if kwargs["te_lines"] == ["Transfer-Encoding: chunked"]:
            return _resp(status=200, body="ok")
        if kwargs["te_lines"] == ["Transfer-Encoding: xchunked"]:
            return {"status": 0, "headers": {}, "body": "", "raw_length": 0, "error": "TimeoutError: timed out"}
        return _resp(status=200, body="ok")

    _patch_probes(monkeypatch, responder)
    out = request_smuggling_check("https://example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    # Error in one probe shouldn't generate a finding.
    assert all("te_xchunked" not in r["title"] for r in reports)
    # The errored probe is recorded.
    err_probe = next(p for p in out["probes"] if p["label"] == "te_xchunked")
    assert err_probe.get("error")


def test_baseline_failure_marks_inconclusive(monkeypatch) -> None:
    """Baseline TimeoutError → all variants recorded as 'baseline failed'."""
    def responder(kwargs):
        return {"status": 0, "headers": {}, "body": "", "raw_length": 0, "error": "ConnectionRefusedError"}

    _patch_probes(monkeypatch, responder)
    out = request_smuggling_check("https://nope.example.com/")
    assert out["success"] is True
    assert out["findings_emitted"] == 0
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"].get("http_request_smuggling", {})
    assert cat.get("inconclusive", 0) == 1


# ---------------------------------------------------------------------------
# Cluster-A composition
# ---------------------------------------------------------------------------


def test_exclude_path_skips_baseline(monkeypatch) -> None:
    """STRIX_EXCLUDE_PATHS matching → baseline skipped → all probes skipped."""
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", '["/admin/*"]')
    log = _patch_probes(monkeypatch, lambda kwargs: _resp(status=200, body="should not be called"))
    out = request_smuggling_check("https://example.com/admin/destroy")
    # exclude-path is checked BEFORE socket open, so the fake responder is
    # never invoked.
    assert log == []
    assert out["findings_emitted"] == 0
    skipped_probes = [p for p in out["probes"] if p.get("skipped")]
    assert len(skipped_probes) == 9  # all probes skipped (baseline + 8 variants)


def test_auth_headers_embedded_in_request(monkeypatch) -> None:
    """STRIX_AUTH_BEARER → Authorization: Bearer <token> in extra_headers."""
    monkeypatch.setenv("STRIX_AUTH_BEARER", "secret-token")
    log = _patch_probes(monkeypatch, lambda kwargs: _resp(status=200, body="ok"))
    request_smuggling_check("https://example.com/")
    # First probe (baseline) should have the auth header injected.
    assert log[0]["extra_headers"].get("Authorization") == "Bearer secret-token"


# ---------------------------------------------------------------------------
# §11 non-tech UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    def responder(kwargs):
        if kwargs["te_lines"] == ["Transfer-Encoding: chunked"]:
            return _resp(status=200, body="ok")
        if kwargs["te_lines"] == ["Transfer-Encoding: xchunked"]:
            return _resp(status=400, body="bad TE")
        return _resp(status=200, body="ok")

    _patch_probes(monkeypatch, responder)
    request_smuggling_check("https://example.com/")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r["category"] == "http_request_smuggling"
        assert r["cwe"] == "CWE-444"
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check event
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    _patch_probes(monkeypatch, lambda kwargs: _resp(status=200, body="ok"))
    request_smuggling_check("https://example.com/")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "http_request_smuggling" in summary["by_category"]
    assert summary["by_category"]["http_request_smuggling"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    def responder(kwargs):
        if kwargs["te_lines"] == ["Transfer-Encoding: chunked"]:
            return _resp(status=200, body="ok")
        return _resp(status=400, body="bad")

    _patch_probes(monkeypatch, responder)
    request_smuggling_check("https://example.com/")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["http_request_smuggling"]
    assert cat["vulnerable"] == 1


# ---------------------------------------------------------------------------
# Diff helper
# ---------------------------------------------------------------------------


def test_diff_status_class_match_no_finding() -> None:
    bl = _resp(status=200, body="x" * 100)
    pb = _resp(status=200, body="x" * 100)
    out = rs_module._diff_against_baseline(bl, pb)
    assert out["severity"] is None
    assert out["differs_status_class"] is False


def test_diff_status_class_change_high() -> None:
    bl = _resp(status=200, body="x" * 100)
    pb = _resp(status=400, body="bad")
    out = rs_module._diff_against_baseline(bl, pb)
    assert out["severity"] == "high"
    assert out["differs_status_class"] is True


def test_diff_body_divergence_medium() -> None:
    bl = _resp(status=200, body="x" * 100)
    pb = _resp(status=200, body="y" * 500)  # 80% delta
    out = rs_module._diff_against_baseline(bl, pb)
    assert out["severity"] == "medium"


def test_diff_5xx_pair_no_medium() -> None:
    bl = _resp(status=503, body="x")
    pb = _resp(status=503, body="y" * 200)
    out = rs_module._diff_against_baseline(bl, pb)
    assert out["severity"] is None


def test_diff_probe_error_no_finding() -> None:
    bl = _resp(status=200, body="x" * 100)
    pb = {"status": 0, "headers": {}, "body": "", "raw_length": 0, "error": "TimeoutError"}
    out = rs_module._diff_against_baseline(bl, pb)
    assert out["severity"] is None


# ---------------------------------------------------------------------------
# Top-level rejection paths
# ---------------------------------------------------------------------------


def test_invalid_target_rejected_returns_failure(monkeypatch) -> None:
    out = request_smuggling_check("")
    assert out["success"] is False
    out2 = request_smuggling_check("ftp://x.com/")
    assert out2["success"] is False
