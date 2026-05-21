"""Integration tests for iter-21.2 — the `campaigns` block lands
on every finding via `tracer.add_vulnerability_report`, AND
severity nudges fire when at least one matched campaign is
severity ≥ high.

Mirrors `test_tracer_kev_integration.py` for the campaign-feed
layer. Verifies:
  * Block always lands.
  * `not_in_campaigns` / `cache_unavailable` / `no_cve` /
    `enrichment_disabled` reasons surface correctly.
  * Severity nudges fire (medium → high) for high/critical campaign
    matches; finding still lands.
  * Recall safety on resolver failure: defensive fallback block.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from strix.llm import campaign_enrichment as ce
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.delenv("STRIX_CAMPAIGN_ENRICHMENT_DISABLED", raising=False)
    monkeypatch.chdir(tmp_path)
    yield


def _new_tracer(name: str = "campaign-int") -> Tracer:
    t = Tracer(name)
    set_global_tracer(t)
    return t


def _emit_finding(tracer: Tracer, **overrides) -> str:
    defaults = {
        "title": "SCA vuln test",
        "severity": "medium",
        "endpoint": "/api",
        "target": "https://x.com/api",
        "category": "sca",
        "description": "x",
        "impact": "x",
        "technical_analysis": "x",
        "poc_description": "x",
        "poc_script_code": "curl x",
        "remediation_steps": "Upgrade.",
    }
    defaults.update(overrides)
    return tracer.add_vulnerability_report(**defaults)


def _campaign(**ov):
    base = {
        "campaign_id": "otx:abc",
        "source": "otx",
        "name": "Spring Boot RCE — APT-X",
        "author": "AlienVault",
        "first_seen": "2026-05-01T00:00:00Z",
        "last_seen": "2026-05-19T14:21:00Z",
        "severity": "high",
        "references": [],
    }
    base.update(ov)
    return base


def test_campaign_block_present_on_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", lambda: fresh)
    monkeypatch.setattr(ce, "_lookup_campaigns", lambda _c: [_campaign()])
    tracer = _new_tracer("camp-int-1")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert "campaigns" in report
    assert report["campaigns"]["matched_pulse_count"] == 1
    assert report["campaigns"]["reason"] == "ok"


def test_campaign_block_present_without_cve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracer = _new_tracer("camp-int-2")
    fid = _emit_finding(tracer)
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["campaigns"]["reason"] == "no_cve"
    assert report["campaigns"]["matched_pulse_count"] == 0


def test_campaign_block_when_cache_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", lambda: None)
    tracer = _new_tracer("camp-int-3")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["campaigns"]["reason"] == "cache_unavailable"


def test_high_campaign_nudges_medium_to_high(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", lambda: fresh)
    monkeypatch.setattr(
        ce, "_lookup_campaigns",
        lambda _c: [_campaign(severity="high")],
    )
    tracer = _new_tracer("camp-int-4")
    fid = _emit_finding(tracer, cve="CVE-2024-1234", severity="medium")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["severity"] == "high"
    trace = report.get("reasoning_trace") or []
    assert any(
        isinstance(line, str) and "campaign" in line.lower()
        for line in trace
    )


def test_low_campaign_does_not_nudge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", lambda: fresh)
    monkeypatch.setattr(
        ce, "_lookup_campaigns",
        lambda _c: [_campaign(severity="medium")],
    )
    tracer = _new_tracer("camp-int-5")
    fid = _emit_finding(tracer, cve="CVE-2024-1234", severity="medium")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["severity"] == "medium"


def test_campaign_nudge_kept_below_critical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even with a critical-severity campaign match, the nudge tops
    out at high (KEV remains the only path that pushes to critical
    — campaigns are a softer signal)."""
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", lambda: fresh)
    monkeypatch.setattr(
        ce, "_lookup_campaigns",
        lambda _c: [_campaign(severity="critical")],
    )
    tracer = _new_tracer("camp-int-6")
    fid = _emit_finding(tracer, cve="CVE-2024-1234", severity="medium")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    # Medium → high (one step), NOT critical.
    assert report["severity"] == "high"


def test_kill_switch_skips_block_and_nudge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_CAMPAIGN_ENRICHMENT_DISABLED", "1")
    tracer = _new_tracer("camp-int-7")
    fid = _emit_finding(tracer, cve="CVE-2024-1234", severity="medium")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["campaigns"]["reason"] == "enrichment_disabled"
    # Severity untouched.
    assert report["severity"] == "medium"


def test_finding_lands_when_resolver_breaks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the resolver raises, the tracer's defensive fallback must
    supply a default block and the finding must still land."""
    def _boom(**kw):
        raise RuntimeError("simulated catastrophic failure")

    monkeypatch.setattr(ce, "resolve_campaign_block", _boom)
    tracer = _new_tracer("camp-int-8")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert fid
    assert "campaigns" in report
    assert report["campaigns"]["reason"] == "cache_unavailable"
