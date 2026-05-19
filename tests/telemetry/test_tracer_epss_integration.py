"""Integration tests for MA-S2 P0-CVS-A — the EPSS enrichment
block lands on every finding emitted via
`tracer.add_vulnerability_report`.

Recall-safety contract pinned by tests:
  * The `epss` block is ALWAYS present on the persisted finding.
  * The block is present even when the threat-intel cache is
    unavailable / EPSS feed never polled (the block just carries
    a reason explaining why).
  * Kill switch surfaces a consistent "disabled" block — the
    finding still lands.
  * Findings without a CVE id get a `no_cve` reason; the finding
    still lands.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from strix.llm import epss_enrichment as ee
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.delenv("STRIX_EPSS_ENRICHMENT_DISABLED", raising=False)
    monkeypatch.chdir(tmp_path)
    yield


def _new_tracer(name: str = "epss-int") -> Tracer:
    t = Tracer(name)
    set_global_tracer(t)
    return t


def _emit_finding(tracer: Tracer, **overrides) -> str:
    defaults = {
        "title": "Test SQLi finding",
        "severity": "high",
        "endpoint": "/api/users",
        "target": "https://x.com/api/users",
        "category": "sqli",
        "description": "x",
        "impact": "x",
        "technical_analysis": "x",
        "poc_description": "x",
        "poc_script_code": "curl x",
        "remediation_steps": "Parameterize.",
    }
    defaults.update(overrides)
    return tracer.add_vulnerability_report(**defaults)


# ---------------------------------------------------------------------------
# Block ALWAYS lands on finding (MA-S2 attestation discipline)
# ---------------------------------------------------------------------------


def test_epss_block_present_on_finding_with_cve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fresh cache + score present → block has score + last_updated."""
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(ee, "_lookup_epss_score", lambda c: 0.85)

    tracer = _new_tracer("epss-int-1")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert "epss" in report
    assert report["epss"]["score"] == 0.85
    assert report["epss"]["reason"] == "ok"
    assert report["epss"]["last_updated"] == fresh


def test_epss_block_present_on_finding_without_cve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No CVE → block still present, score null, reason='no_cve'."""
    tracer = _new_tracer("epss-int-2")
    fid = _emit_finding(tracer)  # no cve kwarg
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert "epss" in report
    assert report["epss"]["score"] is None
    assert report["epss"]["reason"] == "no_cve"


def test_epss_block_present_when_cache_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Feed_meta returns None → reason=cache_unavailable, finding
    still lands with a block."""
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: None)

    tracer = _new_tracer("epss-int-3")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["epss"]["reason"] == "cache_unavailable"
    assert report["epss"]["score"] is None


def test_epss_block_marks_stale_when_feed_old(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Old feed + score present → reason=cache_stale, score surfaces
    so wrapper can discount it."""
    old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: old)
    monkeypatch.setattr(ee, "_lookup_epss_score", lambda c: 0.7)

    tracer = _new_tracer("epss-int-4")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["epss"]["score"] == 0.7
    assert report["epss"]["reason"] == "cache_stale"


def test_epss_block_when_kill_switch_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kill switch on → block has reason='enrichment_disabled',
    finding still lands."""
    monkeypatch.setenv("STRIX_EPSS_ENRICHMENT_DISABLED", "1")
    tracer = _new_tracer("epss-int-5")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["epss"]["reason"] == "enrichment_disabled"


# ---------------------------------------------------------------------------
# Recall safety — finding lands regardless of EPSS resolver state
# ---------------------------------------------------------------------------


def test_finding_lands_even_if_resolver_breaks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence-in-depth canary — if the resolver module itself
    blows up at import / call time, the tracer's own try/except
    must catch it and the finding MUST still land."""
    def boom(**kw):
        raise RuntimeError("simulated catastrophic failure")

    monkeypatch.setattr(ee, "resolve_epss_block", boom)
    tracer = _new_tracer("epss-int-6")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    # Finding still lands
    assert fid
    assert report["title"] == "Test SQLi finding"
    # And the tracer's defensive fallback supplied a default block
    assert "epss" in report
    assert report["epss"]["reason"] == "cache_unavailable"


# ---------------------------------------------------------------------------
# Schema invariant — every block carries all 4 canonical keys
# ---------------------------------------------------------------------------


def test_every_epss_block_has_canonical_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MA-S2 attestation invariant: regardless of resolution path,
    every emitted block has the same 4 keys so downstream
    consumers (wrapper, auditor bundle compiler) don't have to
    handle shape variations."""
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ee, "_epss_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(ee, "_lookup_epss_score", lambda c: 0.5)

    tracer = _new_tracer("epss-int-7")
    for cve in [None, "", "CVE-2024-1234", "CVE-2099-9999"]:
        fid = _emit_finding(tracer, cve=cve)
        report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
        assert set(report["epss"].keys()) == {
            "score", "percentile", "last_updated", "reason",
        }
