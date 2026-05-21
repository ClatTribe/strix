"""Tests for iter-21.1 — CISA KEV enrichment on findings.

Recall-safety contract pinned by tests:
  * The `kev` block is ALWAYS present (mirrors the EPSS
    "we tried" attestation discipline).
  * Missing CVE → `reason: "no_cve"`, never raises.
  * Cache unavailable / errors → `reason: "cache_unavailable"`,
    never raises.
  * CVE in cache but not KEV-listed → `reason: "not_in_kev"`,
    `listed=False`.
  * Stale cache (>7d) → `reason: "cache_stale"`.
  * Kill switch (`STRIX_KEV_ENRICHMENT_DISABLED=1`) returns a
    consistent block with `reason: "enrichment_disabled"` AND
    disables the severity-promotion path.
  * `maybe_promote_severity` only fires when `listed=True` AND
    current severity is below critical. Never raises.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from strix.llm import kev_enrichment as ke


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_KEV_ENRICHMENT_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# CVE normalization (mirrors EPSS regex; tests only the canonical surface)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("CVE-2024-1234", "CVE-2024-1234"),
    ("cve-2024-1234", "CVE-2024-1234"),
    ("CVE 2024 1234", "CVE-2024-1234"),
    ("see CVE-2024-1234 for details", "CVE-2024-1234"),
    ("not a cve", None),
    ("", None),
    (None, None),
])
def test_normalize_cve_id(raw, expected) -> None:
    assert ke._normalize_cve_id(raw) == expected


# ---------------------------------------------------------------------------
# resolve_kev_block — no-cve / disabled / unavailable
# ---------------------------------------------------------------------------


def test_resolve_with_no_cve_returns_no_cve_reason() -> None:
    block = ke.resolve_kev_block(cve=None)
    assert block["listed"] is None
    assert block["last_updated"] is None
    assert block["reason"] == "no_cve"


def test_resolve_with_unparseable_cve_returns_no_cve_reason() -> None:
    block = ke.resolve_kev_block(cve="not a cve")
    assert block["reason"] == "no_cve"


def test_kill_switch_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_KEV_ENRICHMENT_DISABLED", "1")
    block = ke.resolve_kev_block(cve="CVE-2024-1234")
    assert block["listed"] is None
    assert block["reason"] == "enrichment_disabled"


def test_cache_unavailable_when_feed_meta_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ke, "_kev_feed_last_polled", lambda: None)
    block = ke.resolve_kev_block(cve="CVE-2024-1234")
    assert block["reason"] == "cache_unavailable"
    assert block["listed"] is None


# ---------------------------------------------------------------------------
# resolve_kev_block — happy paths
# ---------------------------------------------------------------------------


def _fresh_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()


def _stale_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()


def test_listed_cve_returns_full_block(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ke, "_kev_feed_last_polled", _fresh_iso)
    monkeypatch.setattr(
        ke, "_lookup_kev_record",
        lambda _cid: (True, {
            "date_added": "2024-03-15",
            "due_date": "2024-04-05",
            "vendor_project": "Apache",
            "product": "Tomcat",
            "vulnerability_name": "Apache Tomcat RCE",
            "short_description": "...",
            "required_action": "Apply updates.",
            "known_ransomware_use": "Known",
        }),
    )
    block = ke.resolve_kev_block(cve="CVE-2024-1234")
    assert block["listed"] is True
    assert block["reason"] == "ok"
    assert block["date_added"] == "2024-03-15"
    assert block["known_ransomware_use"] == "Known"
    assert block["vendor_project"] == "Apache"


def test_not_listed_cve_returns_not_in_kev_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ke, "_kev_feed_last_polled", _fresh_iso)
    monkeypatch.setattr(ke, "_lookup_kev_record", lambda _c: (False, {}))
    block = ke.resolve_kev_block(cve="CVE-2024-1234")
    assert block["listed"] is False
    assert block["reason"] == "not_in_kev"


def test_stale_cache_with_listed_cve_returns_cache_stale_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ke, "_kev_feed_last_polled", _stale_iso)
    monkeypatch.setattr(
        ke, "_lookup_kev_record",
        lambda _c: (True, {"vulnerability_name": "stale finding"}),
    )
    block = ke.resolve_kev_block(cve="CVE-2024-1234")
    # Stale wins over `ok` so the operator sees the freshness issue.
    assert block["reason"] == "cache_stale"
    # But the listed bit is still surfaced.
    assert block["listed"] is True


def test_camelcase_kev_meta_keys_normalized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Some KEV feed parsers emit camelCase keys (`dateAdded` /
    `vendorProject`). Block builder accepts both."""
    monkeypatch.setattr(ke, "_kev_feed_last_polled", _fresh_iso)
    monkeypatch.setattr(
        ke, "_lookup_kev_record",
        lambda _c: (True, {
            "dateAdded": "2024-03-15",
            "vendorProject": "Apache",
            "vulnerabilityName": "Apache Tomcat RCE",
            "knownRansomwareCampaignUse": "Unknown",
        }),
    )
    block = ke.resolve_kev_block(cve="CVE-2024-1234")
    assert block["date_added"] == "2024-03-15"
    assert block["vendor_project"] == "Apache"
    assert block["vulnerability_name"] == "Apache Tomcat RCE"
    assert block["known_ransomware_use"] == "Unknown"


# ---------------------------------------------------------------------------
# Resolver never raises
# ---------------------------------------------------------------------------


def test_lookup_exception_falls_through_to_not_listed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_lookup_kev_record` raising must not crash the resolver —
    we MUST always return a block."""
    monkeypatch.setattr(ke, "_kev_feed_last_polled", _fresh_iso)

    def _boom(_c: str) -> tuple[bool, dict[str, Any]]:
        raise RuntimeError("lookup broken")

    monkeypatch.setattr(ke, "_lookup_kev_record", _boom)
    block = ke.resolve_kev_block(cve="CVE-2024-1234")
    # Lookup failure surfaces as not-in-kev (no exception escapes).
    assert block["reason"] == "not_in_kev"
    assert block["listed"] is False


# ---------------------------------------------------------------------------
# maybe_promote_severity
# ---------------------------------------------------------------------------


def test_promote_skips_when_not_listed() -> None:
    new_sev, line = ke.maybe_promote_severity(
        current_severity="high",
        kev_block={"listed": False, "reason": "not_in_kev"},
    )
    assert new_sev is None
    assert line is None


def test_promote_skips_when_already_critical() -> None:
    new_sev, line = ke.maybe_promote_severity(
        current_severity="critical",
        kev_block={"listed": True, "vulnerability_name": "X"},
    )
    assert new_sev is None
    assert line is None


def test_promote_bumps_high_to_critical_with_trace_line() -> None:
    new_sev, line = ke.maybe_promote_severity(
        current_severity="high",
        kev_block={
            "listed": True,
            "vulnerability_name": "Apache Tomcat RCE",
            "date_added": "2024-03-15",
            "known_ransomware_use": "Known",
        },
    )
    assert new_sev == "critical"
    assert line is not None
    assert "actively exploited" in line
    assert "Apache Tomcat RCE" in line
    assert "ransomware" in line.lower()


def test_promote_bumps_medium_to_critical() -> None:
    new_sev, _ = ke.maybe_promote_severity(
        current_severity="medium",
        kev_block={"listed": True, "vulnerability_name": "X"},
    )
    assert new_sev == "critical"


def test_promote_handles_missing_or_garbage_block() -> None:
    """Defensive: malformed block must not raise."""
    new_sev, _ = ke.maybe_promote_severity(
        current_severity="high",
        kev_block={},  # type: ignore[arg-type]
    )
    assert new_sev is None


def test_promote_respects_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_KEV_ENRICHMENT_DISABLED", "1")
    new_sev, _ = ke.maybe_promote_severity(
        current_severity="high",
        kev_block={"listed": True, "vulnerability_name": "X"},
    )
    assert new_sev is None
