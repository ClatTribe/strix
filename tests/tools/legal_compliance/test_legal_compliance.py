"""Tests for legal_compliance_probe (roadmap §16 / PR #126)."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.legal_compliance.legal_compliance_probe  # noqa: F401

lc_module = sys.modules["strix.tools.legal_compliance.legal_compliance_probe"]
legal_compliance_probe = lc_module.legal_compliance_probe


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
    tracer = Tracer("legal-test")
    set_global_tracer(tracer)
    yield


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


def _patch_get(monkeypatch, responder: callable) -> None:
    def fake(url, *, timeout=8.0):
        return responder(url)

    monkeypatch.setattr(lc_module, "_http_get", fake)


def _good_resp(body_extra: str = "") -> dict[str, Any]:
    return {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "body": "<html><body>" + ("Privacy policy content. " * 20) + body_extra + "</body></html>",
        "final_url": "https://app.example.com/x",
    }


def _404_resp() -> dict[str, Any]:
    return {"status": 404, "headers": {}, "body": "Not Found"}


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert legal_compliance_probe("")["success"] is False
    assert legal_compliance_probe("ftp://x.com")["success"] is False


def test_bare_host_auto_prefixed(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _404_resp())
    out = legal_compliance_probe("app.example.com")
    assert out["success"] is True


# ---------------------------------------------------------------------------
# Document presence (canonical paths)
# ---------------------------------------------------------------------------


def test_privacy_policy_at_canonical_path_emits_info(monkeypatch) -> None:
    """`/privacy` returns a real document → info finding (present)."""
    def responder(url):
        if url.endswith("/privacy"):
            return _good_resp()
        return _404_resp()

    _patch_get(monkeypatch, responder)

    out = legal_compliance_probe("https://app.example.com")
    privacy_doc = next(d for d in out["documents"] if d["doc_class"] == "privacy_policy")
    assert privacy_doc["present"] is True
    assert privacy_doc["source"] == "canonical_path"

    findings = _findings()
    info = [f for f in findings if "Privacy policy" in f["title"] and f["severity"] == "info"]
    assert len(info) == 1
    assert info[0]["cwe"] == "CWE-1390"


def test_short_body_treated_as_absent(monkeypatch) -> None:
    """200 OK but body < 200 chars → soft 404, treated as absent."""
    def responder(url):
        if url.endswith("/privacy"):
            return {"status": 200, "headers": {}, "body": "too short", "final_url": url}
        return _404_resp()

    _patch_get(monkeypatch, responder)

    out = legal_compliance_probe("https://app.example.com")
    privacy_doc = next(d for d in out["documents"] if d["doc_class"] == "privacy_policy")
    assert privacy_doc["present"] is False


# ---------------------------------------------------------------------------
# Document absence — severity ladder
# ---------------------------------------------------------------------------


def test_privacy_policy_absent_emits_low(monkeypatch) -> None:
    """GDPR-class doc absent → low (privacy_policy / cookie / dpa)."""
    _patch_get(monkeypatch, lambda url: _404_resp())

    legal_compliance_probe("https://app.example.com")

    findings = _findings()
    privacy = [f for f in findings if "Privacy policy not found" in f["title"]]
    assert len(privacy) == 1
    assert privacy[0]["severity"] == "low"


def test_cookie_policy_absent_emits_low(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _404_resp())
    legal_compliance_probe("https://app.example.com")
    findings = _findings()
    cookie = [f for f in findings if "Cookie policy not found" in f["title"]]
    assert len(cookie) == 1
    assert cookie[0]["severity"] == "low"


def test_dpa_absent_emits_low(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _404_resp())
    legal_compliance_probe("https://app.example.com")
    findings = _findings()
    dpa = [f for f in findings if "DPA" in f["title"] and "not found" in f["title"]]
    assert len(dpa) == 1
    assert dpa[0]["severity"] == "low"


def test_terms_absent_emits_info(monkeypatch) -> None:
    """Non-GDPR-class doc absent → info (terms / imprint / accessibility)."""
    _patch_get(monkeypatch, lambda url: _404_resp())
    legal_compliance_probe("https://app.example.com")
    findings = _findings()
    terms = [f for f in findings if "Terms of service not found" in f["title"]]
    assert len(terms) == 1
    assert terms[0]["severity"] == "info"


def test_imprint_absent_emits_info(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _404_resp())
    legal_compliance_probe("https://app.example.com")
    findings = _findings()
    imprint = [f for f in findings if "Imprint" in f["title"] and "not found" in f["title"]]
    assert len(imprint) == 1
    assert imprint[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# link rel="..." extraction
# ---------------------------------------------------------------------------


def test_link_rel_privacy_policy_used(monkeypatch) -> None:
    """`<link rel="privacy-policy" href="/legal/p">` in homepage →
    that URL is checked first, source=link_rel."""
    homepage_html = (
        '<!DOCTYPE html><html><head>'
        '<link rel="privacy-policy" href="/legal/p">'
        '</head><body>'
        + ("Home content. " * 50)
        + '</body></html>'
    )

    def responder(url):
        if url == "https://app.example.com":
            return {"status": 200, "headers": {}, "body": homepage_html, "final_url": url}
        if url.endswith("/legal/p"):
            return _good_resp()
        return _404_resp()

    _patch_get(monkeypatch, responder)

    out = legal_compliance_probe("https://app.example.com")
    privacy_doc = next(d for d in out["documents"] if d["doc_class"] == "privacy_policy")
    assert privacy_doc["present"] is True
    assert privacy_doc["source"] == "link_rel"


def test_link_rel_relative_url_resolved(monkeypatch) -> None:
    """`<link rel="privacy-policy" href="legal/p">` (relative) →
    resolved against the homepage origin."""
    homepage_html = (
        '<!DOCTYPE html><html><head>'
        '<link rel="privacy-policy" href="legal/p">'
        '</head><body>'
        + ("Home content. " * 50)
        + '</body></html>'
    )
    visited: list[str] = []

    def responder(url):
        visited.append(url)
        if url == "https://app.example.com":
            return {"status": 200, "headers": {}, "body": homepage_html, "final_url": url}
        if url.endswith("legal/p"):
            return _good_resp()
        return _404_resp()

    _patch_get(monkeypatch, responder)

    out = legal_compliance_probe("https://app.example.com")
    privacy_doc = next(d for d in out["documents"] if d["doc_class"] == "privacy_policy")
    assert privacy_doc["present"] is True


# ---------------------------------------------------------------------------
# All present (clean target)
# ---------------------------------------------------------------------------


def test_all_documents_present_emits_only_info(monkeypatch) -> None:
    """Every canonical doc returns 200+real-body → all info findings,
    no low findings."""
    _patch_get(monkeypatch, lambda url: _good_resp() if "/" in url else _404_resp())

    out = legal_compliance_probe("https://app.example.com")

    findings = _findings()
    severities = {f["severity"] for f in findings}
    # All findings are info ("present" cards); no low.
    assert severities == {"info"}


# ---------------------------------------------------------------------------
# Per-class dedup
# ---------------------------------------------------------------------------


def test_per_class_dedup_first_path_wins(monkeypatch) -> None:
    """Multiple paths for `privacy_policy` could all return 200 — we
    take the first hit and don't double-emit."""
    def responder(url):
        # ALL paths return 200+real-body. The first one in the
        # _PROBE_PATHS order should win.
        return _good_resp()

    _patch_get(monkeypatch, responder)

    legal_compliance_probe("https://app.example.com")
    findings = _findings()
    privacy_present = [f for f in findings if "Privacy policy present" in f["title"]]
    assert len(privacy_present) == 1


# ---------------------------------------------------------------------------
# Schema + MITRE
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: _404_resp())
    out = legal_compliance_probe("https://app.example.com")
    assert set(out.keys()) >= {
        "success", "target", "documents", "findings_emitted",
    }
    assert isinstance(out["documents"], list)
    for d in out["documents"]:
        assert "doc_class" in d
        assert "present" in d
        assert "source" in d


def test_mitre_techniques_registered() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    assert "T1592" in get_tool_mitre_techniques("legal_compliance_probe")


def test_six_doc_classes_probed(monkeypatch) -> None:
    """Privacy / cookie / terms / DPA / imprint / accessibility = 6."""
    _patch_get(monkeypatch, lambda url: _404_resp())
    out = legal_compliance_probe("https://app.example.com")
    classes = {d["doc_class"] for d in out["documents"]}
    assert classes == {
        "privacy_policy", "cookie_policy", "terms_of_service",
        "dpa", "imprint", "accessibility",
    }


# ---------------------------------------------------------------------------
# Failure resilience
# ---------------------------------------------------------------------------


def test_skipped_response_does_not_crash(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: {"status": 0, "body": "", "skipped": True})
    out = legal_compliance_probe("https://app.example.com")
    # All probes skip → all docs marked absent.
    assert out["success"] is True
    assert all(not d["present"] for d in out["documents"])


def test_error_response_recorded(monkeypatch) -> None:
    _patch_get(monkeypatch, lambda url: {"status": 0, "body": "", "error": "DNS fail"})
    out = legal_compliance_probe("https://app.example.com")
    assert out["success"] is True
    # The home-page fetch failed → recorded in errors.
    assert "errors" in out
