"""Tests for kev_diff_check.

Hermetic — KEV catalog `_load_remote` and snapshot file are
controlled. Tests cover:

- First run with no prior snapshot → silent baseline (no findings)
- First run with include_first_run_findings=True → emits findings
  for all current entries (capped at 50)
- Subsequent run with new entries → emits info findings per new
  entry, snapshot updated
- Subsequent run with no new entries → no findings, snapshot
  unchanged
- Subsequent run with removed entries → recorded but no finding
- Catalog refresh failure → graceful error
- Snapshot persistence across runs
- Hard cap of 50 findings on first-run-with-findings
- Findings carry CVE attached + plain text + recommended action
- check.completed events
- Result schema integrity
- Ransomware-flagged entries surface ransomware text in finding
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import threat_intel as threat_intel_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.kev_diff.kev_diff_check  # noqa: F401

kd_module = sys.modules["strix.tools.kev_diff.kev_diff_check"]
kev_diff_check = kd_module.kev_diff_check


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_KEV_DISABLED", raising=False)  # we want KEV enabled here
    monkeypatch.setenv("STRIX_KEV_DIFF_SNAPSHOT", str(tmp_path / "kev_snap.json"))
    monkeypatch.setenv("STRIX_KEV_CACHE_PATH", str(tmp_path / "kev_cache.json"))
    # Reset the threat_intel global catalog so each test gets a fresh one.
    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("kd-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_kev(monkeypatch, vulnerabilities: list[dict[str, Any]]) -> None:
    """Patch the KEV catalog's `_fetch_json` to return a fake payload."""
    payload = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "vulnerabilities": vulnerabilities,
    }
    monkeypatch.setattr(threat_intel_module, "_fetch_json", lambda url, timeout=15: payload)


def _vuln(cve: str, *, vendor: str = "VendorCo", product: str = "ProductX",
          vuln_name: str = "RCE in foo",
          date_added: str = "2024-12-01", due_date: str = "2024-12-22",
          required_action: str = "Apply vendor patch.",
          ransomware: str = "Unknown") -> dict[str, Any]:
    return {
        "cveID": cve,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": vuln_name,
        "dateAdded": date_added,
        "dueDate": due_date,
        "requiredAction": required_action,
        "knownRansomwareCampaignUse": ransomware,
    }


# ---------------------------------------------------------------------------
# First-run behaviour
# ---------------------------------------------------------------------------


def test_first_run_silent_baseline(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")])
    out = kev_diff_check()
    assert out["success"] is True
    assert out["first_run"] is True
    assert out["findings_emitted"] == 0
    assert out["new_entries"] == []
    assert out["total_kev_entries"] == 2
    # No findings emitted to the tracer.
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_first_run_with_baseline_findings_enabled(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")])
    out = kev_diff_check(include_first_run_findings=True)
    assert out["first_run"] is True
    assert out["findings_emitted"] == 2
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 2
    cves = {r["cve"] for r in reports}
    assert cves == {"CVE-2024-0001", "CVE-2024-0002"}


def test_first_run_with_findings_capped_at_50(monkeypatch) -> None:
    vulns = [_vuln(f"CVE-2024-{i:05d}") for i in range(100)]
    _patch_kev(monkeypatch, vulns)
    out = kev_diff_check(include_first_run_findings=True)
    assert out["findings_emitted"] == 50
    assert out["total_kev_entries"] == 100


def test_first_run_writes_snapshot(monkeypatch, tmp_path) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    kev_diff_check()
    snap = json.loads((tmp_path / "kev_snap.json").read_text())
    assert "CVE-2024-0001" in snap["cve_ids"]
    assert snap["cve_count"] == 1


# ---------------------------------------------------------------------------
# Subsequent-run behaviour
# ---------------------------------------------------------------------------


def test_subsequent_run_with_new_entries_emits_findings(monkeypatch) -> None:
    # First run: baseline.
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")])
    kev_diff_check()
    # Reset the catalog so the next refresh re-fetches.
    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)

    # Second run: 2 new entries appear.
    _patch_kev(monkeypatch, [
        _vuln("CVE-2024-0001"), _vuln("CVE-2024-0002"),
        _vuln("CVE-2024-0003", vendor="NewVendor", ransomware="Known"),
        _vuln("CVE-2024-0004"),
    ])
    out = kev_diff_check()
    assert out["first_run"] is False
    assert out["findings_emitted"] == 2
    new_cves = {e["cve_id"] for e in out["new_entries"]}
    assert new_cves == {"CVE-2024-0003", "CVE-2024-0004"}

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 2
    cves = {r["cve"] for r in reports}
    assert cves == {"CVE-2024-0003", "CVE-2024-0004"}


def test_subsequent_run_no_changes_no_findings(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    kev_diff_check()
    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)

    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    out = kev_diff_check()
    assert out["first_run"] is False
    assert out["findings_emitted"] == 0
    assert out["new_entries"] == []


def test_subsequent_run_with_removed_entries(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")])
    kev_diff_check()
    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)

    # Second run: CVE-2024-0001 removed by CISA, CVE-2024-0003 added.
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0002"), _vuln("CVE-2024-0003")])
    out = kev_diff_check()
    assert out["new_entries"][0]["cve_id"] == "CVE-2024-0003"
    assert "CVE-2024-0001" in out["removed_entries"]
    # Removed entries don't generate findings.
    assert out["findings_emitted"] == 1


def test_ransomware_flagged_finding_text(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    kev_diff_check()
    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)

    _patch_kev(monkeypatch, [
        _vuln("CVE-2024-0001"),
        _vuln("CVE-2024-0002", ransomware="Known"),
    ])
    kev_diff_check()
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    rw = next(r for r in reports if r["cve"] == "CVE-2024-0002")
    assert "ransomware" in rw["description"].lower()


# ---------------------------------------------------------------------------
# Snapshot persistence
# ---------------------------------------------------------------------------


def test_snapshot_updated_each_run(monkeypatch, tmp_path) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    kev_diff_check()
    snap1 = json.loads((tmp_path / "kev_snap.json").read_text())
    assert snap1["cve_count"] == 1

    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")])
    kev_diff_check()
    snap2 = json.loads((tmp_path / "kev_snap.json").read_text())
    assert snap2["cve_count"] == 2
    assert "CVE-2024-0002" in snap2["cve_ids"]


# ---------------------------------------------------------------------------
# Catalog failure handling
# ---------------------------------------------------------------------------


def test_catalog_refresh_failure_returns_error(monkeypatch) -> None:
    def boom(url, timeout=15):
        raise RuntimeError("network unreachable")

    monkeypatch.setattr(threat_intel_module, "_fetch_json", boom)
    out = kev_diff_check()
    assert out["success"] is False
    assert "error" in out
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


# ---------------------------------------------------------------------------
# Findings UX
# ---------------------------------------------------------------------------


def test_findings_carry_cve_plain_action(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    kev_diff_check()
    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)

    _patch_kev(monkeypatch, [
        _vuln("CVE-2024-0001"),
        _vuln("CVE-2024-9999",
              vendor="TestVendor",
              product="TestProduct",
              due_date="2025-01-15"),
    ])
    kev_diff_check()
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    target = next(r for r in reports if r["cve"] == "CVE-2024-9999")
    assert target.get("description_plain")
    assert target.get("recommended_action")
    assert target["category"] == "vulnerable_software"
    assert target["cwe"] == "CWE-1395"
    assert target.get("verification_status") == "verified"
    # Recommendation references vendor / product / due date.
    assert "TestVendor" in target["recommended_action"]
    assert "TestProduct" in target["recommended_action"]
    assert "2025-01-15" in target["recommended_action"]


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_first_run_clean(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    kev_diff_check()
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["kev_diff"]["not_vulnerable"] == 1


def test_check_event_emitted_vulnerable_on_new_entries(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    kev_diff_check()
    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")])
    kev_diff_check()
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["kev_diff"]
    assert cat["vulnerable"] >= 1


def test_check_event_inconclusive_on_failure(monkeypatch) -> None:
    def boom(url, timeout=15):
        raise RuntimeError("net down")

    monkeypatch.setattr(threat_intel_module, "_fetch_json", boom)
    kev_diff_check()
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["kev_diff"]["inconclusive"] == 1


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    out = kev_diff_check()
    for k in ("success", "total_kev_entries", "snapshotted_cve_count",
              "prior_snapshot_at", "snapshot_updated", "first_run",
              "new_entries", "removed_entries", "findings_emitted"):
        assert k in out


def test_new_entries_record_full_metadata(monkeypatch) -> None:
    _patch_kev(monkeypatch, [_vuln("CVE-2024-0001")])
    kev_diff_check()
    monkeypatch.setattr(threat_intel_module, "_default_catalog", None)
    _patch_kev(monkeypatch, [
        _vuln("CVE-2024-0001"),
        _vuln("CVE-2024-0002", vendor="V", product="P", vuln_name="VN",
              date_added="2024-12-15", due_date="2025-01-05",
              required_action="Action", ransomware="Known"),
    ])
    out = kev_diff_check()
    rec = next(e for e in out["new_entries"] if e["cve_id"] == "CVE-2024-0002")
    assert rec["vendor"] == "V"
    assert rec["product"] == "P"
    assert rec["vuln_name"] == "VN"
    assert rec["added_at"] == "2024-12-15"
    assert rec["due_date"] == "2025-01-05"
    assert rec["required_action"] == "Action"
    assert rec["ransomware_use"] == "Known"
