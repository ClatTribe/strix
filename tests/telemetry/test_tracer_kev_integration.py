"""Integration tests for iter-21.1 — CISA KEV enrichment block
lands on every finding emitted via
`tracer.add_vulnerability_report`, AND severity auto-promotion
fires when the listed-in-KEV bit is True.

Recall-safety contract pinned by tests:
  * The `kev_block` is ALWAYS present on the persisted finding
    (mirrors MA-S2 EPSS attestation discipline).
  * The block is present even when the cache is unavailable / KEV
    feed never polled.
  * Findings without a CVE id get a `no_cve` reason; finding lands.
  * Severity auto-promotes high → critical when `listed=True`,
    finding lands, reasoning_trace gains the promotion line.
  * `kev=True` + `actively_exploited_in_wild=True` legacy mirror
    fields land alongside the structured block.
  * Kill switch disables both the block (`enrichment_disabled`)
    AND the severity promotion.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from strix.llm import kev_enrichment as ke
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.delenv("STRIX_KEV_ENRICHMENT_DISABLED", raising=False)
    monkeypatch.chdir(tmp_path)
    yield


def _new_tracer(name: str = "kev-int") -> Tracer:
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
# Block ALWAYS lands
# ---------------------------------------------------------------------------


def test_kev_block_present_on_finding_with_cve_listed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fresh cache + CVE listed in KEV → block reason=ok, listed=True."""
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ke, "_kev_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(
        ke, "_lookup_kev_record",
        lambda _c: (True, {
            "vulnerability_name": "Apache Tomcat RCE",
            "date_added": "2024-03-15",
        }),
    )
    tracer = _new_tracer("kev-int-1")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert "kev_block" in report
    assert report["kev_block"]["listed"] is True
    assert report["kev_block"]["reason"] == "ok"
    assert report["kev_block"]["vulnerability_name"] == "Apache Tomcat RCE"


def test_kev_block_present_without_cve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No CVE → block present, listed=None, reason=no_cve."""
    tracer = _new_tracer("kev-int-2")
    fid = _emit_finding(tracer)  # no cve kwarg
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert "kev_block" in report
    assert report["kev_block"]["listed"] is None
    assert report["kev_block"]["reason"] == "no_cve"


def test_kev_block_present_when_cache_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Feed_meta returns None → reason=cache_unavailable, finding lands."""
    monkeypatch.setattr(ke, "_kev_feed_last_polled", lambda: None)
    tracer = _new_tracer("kev-int-3")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["kev_block"]["reason"] == "cache_unavailable"
    assert report["kev_block"]["listed"] is None


def test_kev_block_when_kill_switch_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kill switch on → block reason=enrichment_disabled,
    finding still lands."""
    monkeypatch.setenv("STRIX_KEV_ENRICHMENT_DISABLED", "1")
    tracer = _new_tracer("kev-int-4")
    fid = _emit_finding(tracer, cve="CVE-2024-1234", severity="high")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["kev_block"]["reason"] == "enrichment_disabled"
    # Severity untouched (promotion also disabled).
    assert report["severity"] == "high"


# ---------------------------------------------------------------------------
# Severity auto-promotion
# ---------------------------------------------------------------------------


def test_kev_listed_bumps_high_to_critical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ke, "_kev_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(
        ke, "_lookup_kev_record",
        lambda _c: (True, {
            "vulnerability_name": "Apache Tomcat RCE",
            "date_added": "2024-03-15",
            "known_ransomware_use": "Known",
        }),
    )
    tracer = _new_tracer("kev-int-5")
    fid = _emit_finding(tracer, cve="CVE-2024-1234", severity="high")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["severity"] == "critical"
    # Reasoning trace gained the promotion line
    trace = report.get("reasoning_trace") or []
    assert any(
        isinstance(line, str) and "actively exploited" in line
        for line in trace
    )


def test_kev_listed_doesnt_demote_already_critical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ke, "_kev_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(
        ke, "_lookup_kev_record",
        lambda _c: (True, {"vulnerability_name": "X"}),
    )
    tracer = _new_tracer("kev-int-6")
    fid = _emit_finding(tracer, cve="CVE-2024-1234", severity="critical")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report["severity"] == "critical"


def test_not_listed_doesnt_promote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ke, "_kev_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(ke, "_lookup_kev_record", lambda _c: (False, {}))
    tracer = _new_tracer("kev-int-7")
    fid = _emit_finding(tracer, cve="CVE-2024-1234", severity="medium")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    # Severity unchanged
    assert report["severity"] == "medium"
    # Block still present
    assert report["kev_block"]["listed"] is False


# ---------------------------------------------------------------------------
# Legacy field mirror
# ---------------------------------------------------------------------------


def test_kev_listed_mirrors_to_legacy_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tools that read `report["kev"]` or
    `report["actively_exploited_in_wild"]` (priority-label
    derivation, KG, compliance) see the canonical answer."""
    fresh = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(ke, "_kev_feed_last_polled", lambda: fresh)
    monkeypatch.setattr(
        ke, "_lookup_kev_record",
        lambda _c: (True, {"vulnerability_name": "X"}),
    )
    tracer = _new_tracer("kev-int-8")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    assert report.get("kev") is True
    assert report.get("actively_exploited_in_wild") is True


# ---------------------------------------------------------------------------
# Recall safety — finding lands regardless of resolver state
# ---------------------------------------------------------------------------


def test_finding_lands_even_if_resolver_breaks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence-in-depth canary — if the KEV resolver module itself
    blows up at call time, the tracer's own try/except must catch
    it and the finding MUST still land with a fallback block."""
    def _boom(**kw):
        raise RuntimeError("simulated catastrophic failure")

    monkeypatch.setattr(ke, "resolve_kev_block", _boom)
    tracer = _new_tracer("kev-int-9")
    fid = _emit_finding(tracer, cve="CVE-2024-1234")
    report = next(r for r in tracer.vulnerability_reports if r["id"] == fid)
    # Finding still lands
    assert fid
    assert report["title"] == "Test SQLi finding"
    # And the tracer's defensive fallback supplied a default block
    assert "kev_block" in report
    assert report["kev_block"]["reason"] == "cache_unavailable"
