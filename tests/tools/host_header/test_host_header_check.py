"""Tests for host_header_check.

Hermetic — `_http_get` is monkeypatched. Tests cover:

- URL normalization (bare hostname / scheme-prefixed / path-preserving)
- All 8 probe variants are dispatched per scan
- Reflection in body → medium finding (CWE-20)
- Reflection in `Location` header → high finding (CWE-20)
- Reflection in `Set-Cookie` `Domain=` → high finding (CWE-20)
- Cache-poison heuristic (cached response + body-length variance) → low finding (CWE-444)
- Clean target (no reflection, fixed body length) → zero findings
- Baseline excluded by --exclude-path → graceful no-op
- Baseline unreachable → no crash, marked inconclusive
- All findings carry description_plain + recommended_action (§11 UX baseline)
- Check event emitted with category=host_header_injection
- Probe attacker host is per-run unique (random nonce)
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


# Pull the actual submodule (the package re-exports the function under
# the same name, shadowing the submodule in the package namespace).
import strix.tools.host_header.host_header_check  # noqa: F401

hh_module = sys.modules["strix.tools.host_header.host_header_check"]
host_header_check = hh_module.host_header_check


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
    tracer = Tracer("hh-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com/"}]})
    yield


def _patch_http(monkeypatch, responder):
    """Install a custom responder. `responder(url, headers)` → response dict."""
    log: list[dict[str, Any]] = []

    def fake(url, *, headers=None, timeout=12.0):
        headers = dict(headers or {})
        log.append({"url": url, "headers": headers})
        return responder(url, headers)

    monkeypatch.setattr(hh_module, "_http_get", fake)
    return log


def _resp(*, status=200, body="", headers=None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


def test_bare_hostname_gets_https_prefix(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda url, h: _resp(body="hi"))
    out = host_header_check("example.com")
    assert out["success"] is True
    assert out["target_url"] == "https://example.com"
    assert out["target_host"] == "example.com"
    assert all(entry["url"] == "https://example.com" for entry in log)


def test_full_url_preserved(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda url, h: _resp(body=""))
    out = host_header_check("https://app.example.com/login?x=1")
    assert out["target_url"] == "https://app.example.com/login?x=1"
    assert out["target_host"] == "app.example.com"


def test_invalid_target_rejected(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda url, h: _resp())
    out = host_header_check("")
    assert out["success"] is False


def test_unsupported_scheme_rejected(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda url, h: _resp())
    out = host_header_check("ftp://example.com/")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Probe cohort dispatch
# ---------------------------------------------------------------------------


def test_all_probes_dispatched(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda url, h: _resp(body="ok"))
    out = host_header_check("https://example.com")
    # 1 baseline + 8 probe variants
    assert len(log) == 9
    labels = {p["label"] for p in out["probes"]}
    assert labels == {
        "host_replace", "host_suffix", "xfh", "xfs",
        "x_host", "forwarded", "xforig", "dual_xfh",
    }


def test_probe_attacker_host_is_per_run_unique(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda url, h: _resp(body=""))
    out_a = host_header_check("https://example.com")
    out_b = host_header_check("https://example.com")
    # Both end with the configured base host but the random nonce differs.
    assert out_a["attacker_host"] != out_b["attacker_host"]
    assert out_a["attacker_host"].endswith(".attacker.example.com")
    assert out_b["attacker_host"].endswith(".attacker.example.com")


def test_attacker_host_override(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda url, h: _resp(body=""))
    out = host_header_check("https://example.com", attacker_host="burpcollab.test")
    assert out["attacker_host"].endswith(".burpcollab.test")


# ---------------------------------------------------------------------------
# Reflection in Location header → high finding
# ---------------------------------------------------------------------------


def test_location_reflection_emits_high(monkeypatch) -> None:
    """When `Host:` is reflected into a 302 Location → high (password-reset
    link poisoning class)."""
    def responder(url, headers):
        host = headers.get("Host")
        if host and host.startswith("strix-"):
            return _resp(
                status=302,
                headers={"Location": f"https://{host}/welcome"},
                body="",
            )
        return _resp(body="baseline")

    _patch_http(monkeypatch, responder)
    out = host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high" and "Location" in r["title"]]
    assert high, f"expected high Location-reflection finding; got {[r['title'] for r in reports]}"
    assert high[0]["cwe"] == "CWE-20"
    assert high[0]["category"] == "host_header_injection"
    assert out["findings_emitted"] >= 1


def test_xfh_location_reflection_emits_high(monkeypatch) -> None:
    """X-Forwarded-Host reflected in Location is just as bad."""
    def responder(url, headers):
        xfh = headers.get("X-Forwarded-Host")
        if xfh and xfh.startswith("strix-"):
            return _resp(
                status=302,
                headers={"Location": f"https://{xfh}/dashboard"},
                body="",
            )
        return _resp(body="baseline")

    _patch_http(monkeypatch, responder)
    out = host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" for r in reports)
    assert out["findings_emitted"] >= 1


# ---------------------------------------------------------------------------
# Reflection in Set-Cookie Domain → high finding
# ---------------------------------------------------------------------------


def test_cookie_domain_reflection_emits_high(monkeypatch) -> None:
    def responder(url, headers):
        host = headers.get("Host")
        if host and host.startswith("strix-"):
            return _resp(
                status=200,
                headers={"Set-Cookie": f"sid=abc123; Domain={host}; Path=/"},
                body="hi",
            )
        return _resp(body="baseline")

    _patch_http(monkeypatch, responder)
    out = host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high_cookie = [r for r in reports if r["severity"] == "high" and "Set-Cookie" in r["title"]]
    assert high_cookie
    assert high_cookie[0]["cwe"] == "CWE-20"
    assert out["findings_emitted"] >= 1


def test_cookie_value_substring_does_not_trigger(monkeypatch) -> None:
    """A cookie value that happens to contain the attacker host substring
    (but Domain= is hardcoded) should NOT trigger cookie_domain_reflection."""
    def responder(url, headers):
        host = headers.get("Host")
        # Embed the attacker host inside the cookie VALUE but Domain= is
        # the legit host. Should NOT fire cookie_domain_reflection.
        if host and host.startswith("strix-"):
            return _resp(
                status=200,
                headers={"Set-Cookie": f"sid=token-with-{host}-inside; Domain=app.example.com; Path=/"},
                body="ok",
            )
        return _resp(body="baseline")

    _patch_http(monkeypatch, responder)
    host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    cookie_findings = [r for r in reports if "Set-Cookie" in r["title"]]
    assert cookie_findings == []


# ---------------------------------------------------------------------------
# Reflection in body → medium finding
# ---------------------------------------------------------------------------


def test_body_reflection_emits_medium(monkeypatch) -> None:
    def responder(url, headers):
        host = headers.get("Host")
        if host and host.startswith("strix-"):
            return _resp(body=f"<a href='https://{host}/reset'>Reset password</a>")
        return _resp(body="<a href='https://app.example.com/reset'>Reset password</a>")

    _patch_http(monkeypatch, responder)
    out = host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    body = [r for r in reports if r["severity"] == "medium" and "body" in r["title"].lower()]
    assert body
    assert body[0]["cwe"] == "CWE-20"
    assert out["findings_emitted"] >= 1


# ---------------------------------------------------------------------------
# Cache-poison heuristic → low finding
# ---------------------------------------------------------------------------


def test_cache_poison_heuristic_emits_low(monkeypatch) -> None:
    """Cached response + body-length variance under XFH mutation, no
    explicit reflection → low cache-poisoning candidate."""
    baseline_body = "x" * 1000

    def responder(url, headers):
        cache_headers = {"Cache-Control": "public, max-age=3600", "X-Cache": "HIT"}
        xfh = headers.get("X-Forwarded-Host")
        if xfh and xfh.startswith("strix-"):
            # Different body, no attacker host in body — pure cache-key
            # obliviousness signal.
            return _resp(body="y" * 2000, headers=cache_headers)
        return _resp(body=baseline_body, headers=cache_headers)

    _patch_http(monkeypatch, responder)
    out = host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    low_cache = [r for r in reports if r["severity"] == "low" and r["category"] == "cache_poisoning"]
    assert low_cache
    assert low_cache[0]["cwe"] == "CWE-444"
    assert out["findings_emitted"] >= 1


def test_no_cache_poison_when_response_uncacheable(monkeypatch) -> None:
    """Body-length variance on a `Cache-Control: no-store` response is NOT
    a cache-poison signal — uncacheable responses can't be poisoned."""
    baseline_body = "x" * 1000

    def responder(url, headers):
        xfh = headers.get("X-Forwarded-Host")
        cc = {"Cache-Control": "no-store, private"}
        if xfh and xfh.startswith("strix-"):
            return _resp(body="y" * 2000, headers=cc)
        return _resp(body=baseline_body, headers=cc)

    _patch_http(monkeypatch, responder)
    host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    cache_findings = [r for r in reports if r["category"] == "cache_poisoning"]
    assert cache_findings == []


# ---------------------------------------------------------------------------
# Clean target (no reflection)
# ---------------------------------------------------------------------------


def test_clean_target_no_findings(monkeypatch) -> None:
    """Server ignores attacker-controlled host headers entirely → no findings."""
    _patch_http(monkeypatch, lambda url, h: _resp(body="<html>welcome</html>"))
    out = host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Cluster-A composition
# ---------------------------------------------------------------------------


def test_baseline_excluded_short_circuits(monkeypatch) -> None:
    """When --exclude-path filters the baseline, the tool returns gracefully
    with no probe traffic and no findings."""
    log = _patch_http(monkeypatch, lambda url, h: {"status": 0, "headers": {}, "body": "", "skipped": True})
    out = host_header_check("https://app.example.com/admin/destroy")
    assert out["skipped"] is True
    # Only the baseline was attempted; no probes dispatched.
    assert len(log) == 1
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_baseline_unreachable_marks_inconclusive(monkeypatch) -> None:
    """Network error on baseline → no probes, no findings, no crash."""
    _patch_http(monkeypatch, lambda url, h: {"status": 0, "headers": {}, "body": "", "error": "conn refused"})
    out = host_header_check("https://nope.example.com")
    assert out["success"] is True
    assert out["findings_emitted"] == 0
    assert out["probes"] == []


def test_individual_probe_skipped_does_not_crash(monkeypatch) -> None:
    """If one probe is short-circuited (e.g. by --exclude-path because the
    Host: header changed the resolved URL), the rest still run."""
    call_count = [0]

    def responder(url, headers):
        call_count[0] += 1
        if call_count[0] == 3:  # skip the second probe
            return {"status": 0, "headers": {}, "body": "", "skipped": True}
        return _resp(body="ok")

    _patch_http(monkeypatch, responder)
    out = host_header_check("https://app.example.com")
    assert out["success"] is True
    # 8 probes attempted, one skipped.
    skipped = [p for p in out["probes"] if "skipped" in (p.get("evidence") or "")]
    assert len(skipped) == 1


# ---------------------------------------------------------------------------
# §11 non-tech UX baseline
# ---------------------------------------------------------------------------


def test_every_finding_has_plain_and_action(monkeypatch) -> None:
    def responder(url, headers):
        host = headers.get("Host")
        xfh = headers.get("X-Forwarded-Host")
        if host and host.startswith("strix-"):
            return _resp(
                status=302,
                headers={
                    "Location": f"https://{host}/welcome",
                    "Set-Cookie": f"sid=abc; Domain={host}; Path=/",
                },
                body=f"<p>welcome to {host}</p>",
            )
        if xfh and xfh.startswith("strix-"):
            return _resp(body=f"<p>{xfh}</p>")
        return _resp(body="<p>baseline</p>")

    _patch_http(monkeypatch, responder)
    host_header_check("https://app.example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) >= 1
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r["category"] in ("host_header_injection", "cache_poisoning")
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check event
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    _patch_http(monkeypatch, lambda url, h: _resp(body="<html>welcome</html>"))
    host_header_check("https://app.example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "host_header_injection" in summary["by_category"]


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    def responder(url, headers):
        host = headers.get("Host")
        if host and host.startswith("strix-"):
            return _resp(status=302, headers={"Location": f"https://{host}/x"}, body="")
        return _resp(body="ok")

    _patch_http(monkeypatch, responder)
    host_header_check("https://app.example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["host_header_injection"]
    assert cat["vulnerable"] == 1


# ---------------------------------------------------------------------------
# Probe dispatch sanity — request actually carries the mutation header
# ---------------------------------------------------------------------------


def test_probe_headers_actually_sent(monkeypatch) -> None:
    log = _patch_http(monkeypatch, lambda url, h: _resp(body=""))
    host_header_check("https://app.example.com")
    # Skip baseline (index 0) — every other call should carry exactly one
    # probe variant header set.
    sent_header_names = [tuple(sorted(entry["headers"].keys())) for entry in log[1:]]
    assert ("Host",) in sent_header_names
    assert ("X-Forwarded-Host",) in sent_header_names
    assert ("X-Forwarded-Server",) in sent_header_names
    assert ("X-Host",) in sent_header_names
    assert ("Forwarded",) in sent_header_names
    assert ("X-Forwarded-For",) in sent_header_names
    # dual_xfh sends both
    assert ("Host", "X-Forwarded-Host") in sent_header_names or \
           ("X-Forwarded-Host", "Host") in sent_header_names
