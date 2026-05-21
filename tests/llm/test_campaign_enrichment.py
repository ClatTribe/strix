"""Tests for iter-21.2 — active campaign threat-intel enrichment.

Recall-safety contract pinned by tests:
  * The `campaigns` block is ALWAYS present.
  * No CVE → `reason: "no_cve"`, never raises.
  * Cache unavailable → `reason: "cache_unavailable"`, never raises.
  * No matched campaigns → `reason: "not_in_campaigns"`,
    `matched_pulse_count=0`.
  * Stale cache → `reason: "cache_stale"`.
  * Kill switch → consistent `enrichment_disabled` block AND
    severity-nudge path disabled.
  * `maybe_nudge_severity_for_campaign` only fires when at least
    one matched campaign is severity ≥ high AND current severity
    is below high. Never pushes to critical.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from strix.llm import campaign_enrichment as ce


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_CAMPAIGN_ENRICHMENT_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# CVE normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("CVE-2024-1234", "CVE-2024-1234"),
    ("cve-2024-1234", "CVE-2024-1234"),
    ("see CVE-2024-1234", "CVE-2024-1234"),
    ("not a cve", None),
    ("", None),
    (None, None),
])
def test_normalize_cve(raw, expected) -> None:
    assert ce._normalize_cve_id(raw) == expected


# ---------------------------------------------------------------------------
# resolve_campaign_block — no-cve / disabled / unavailable
# ---------------------------------------------------------------------------


def test_no_cve_reason_no_cve() -> None:
    block = ce.resolve_campaign_block(cve=None)
    assert block["matched_pulse_count"] == 0
    assert block["matched_pulses"] == []
    assert block["highest_campaign_severity"] is None
    assert block["reason"] == "no_cve"


def test_kill_switch_short_circuits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_CAMPAIGN_ENRICHMENT_DISABLED", "1")
    block = ce.resolve_campaign_block(cve="CVE-2024-1234")
    assert block["reason"] == "enrichment_disabled"


def test_cache_unavailable_when_no_feed_meta(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", lambda: None)
    block = ce.resolve_campaign_block(cve="CVE-2024-1234")
    assert block["reason"] == "cache_unavailable"


# ---------------------------------------------------------------------------
# resolve_campaign_block — happy paths
# ---------------------------------------------------------------------------


def _fresh_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()


def _stale_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()


def _campaign(**overrides: Any) -> dict[str, Any]:
    base = {
        "campaign_id": "otx:pulse-1",
        "source": "otx",
        "name": "Spring Boot RCE — APT-X",
        "author": "AlienVault",
        "first_seen": "2026-05-01T00:00:00Z",
        "last_seen": "2026-05-19T14:21:00Z",
        "severity": "high",
        "references": ["https://otx.alienvault.com/pulse/abc"],
        "tags": ["apt-x", "rce", "spring-boot"],
    }
    base.update(overrides)
    return base


def test_listed_campaigns_return_full_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", _fresh_iso)
    monkeypatch.setattr(
        ce, "_lookup_campaigns",
        lambda _cid: [_campaign(), _campaign(source="misp", campaign_id="misp:5", severity="medium")],
    )
    block = ce.resolve_campaign_block(cve="CVE-2024-1234")
    assert block["matched_pulse_count"] == 2
    assert block["reason"] == "ok"
    assert block["highest_campaign_severity"] == "high"
    assert set(block["sources_seen"]) == {"otx", "misp"}


def test_no_match_returns_not_in_campaigns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", _fresh_iso)
    monkeypatch.setattr(ce, "_lookup_campaigns", lambda _c: [])
    block = ce.resolve_campaign_block(cve="CVE-2024-1234")
    assert block["matched_pulse_count"] == 0
    assert block["reason"] == "not_in_campaigns"


def test_stale_cache_marks_block_stale_when_match_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", _stale_iso)
    monkeypatch.setattr(ce, "_lookup_campaigns", lambda _c: [_campaign()])
    block = ce.resolve_campaign_block(cve="CVE-2024-1234")
    assert block["reason"] == "cache_stale"
    assert block["matched_pulse_count"] == 1


def test_highest_severity_picks_most_severe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", _fresh_iso)
    monkeypatch.setattr(
        ce, "_lookup_campaigns",
        lambda _c: [
            _campaign(severity="medium", campaign_id="a"),
            _campaign(severity="critical", campaign_id="b"),
            _campaign(severity="low", campaign_id="c"),
            _campaign(severity=None, campaign_id="d"),
        ],
    )
    block = ce.resolve_campaign_block(cve="CVE-2024-1234")
    assert block["highest_campaign_severity"] == "critical"


def test_garbage_campaigns_filtered_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Malformed campaign rows must not crash the resolver."""
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", _fresh_iso)
    monkeypatch.setattr(
        ce, "_lookup_campaigns",
        lambda _c: [None, "string", 42, _campaign()],
    )
    block = ce.resolve_campaign_block(cve="CVE-2024-1234")
    # Only the well-formed dict gets through.
    assert block["matched_pulse_count"] == 1


def test_resolver_never_raises_on_lookup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ce, "_campaign_feeds_last_polled", _fresh_iso)

    def _boom(_c: str) -> list[dict[str, Any]]:
        raise RuntimeError("lookup broken")

    monkeypatch.setattr(ce, "_lookup_campaigns", _boom)
    block = ce.resolve_campaign_block(cve="CVE-2024-1234")
    # Falls through; finding still gets a block.
    assert block["reason"] == "not_in_campaigns"
    assert block["matched_pulse_count"] == 0


# ---------------------------------------------------------------------------
# maybe_nudge_severity_for_campaign
# ---------------------------------------------------------------------------


def _ok_block(highest: str = "high") -> dict[str, Any]:
    return {
        "matched_pulse_count": 1,
        "matched_pulses": [_campaign(severity=highest)],
        "highest_campaign_severity": highest,
        "sources_seen": ["otx"],
        "last_updated": _fresh_iso(),
        "reason": "ok",
    }


def test_nudge_medium_to_high() -> None:
    new_sev, line = ce.maybe_nudge_severity_for_campaign(
        current_severity="medium",
        campaign_block=_ok_block(highest="high"),
    )
    assert new_sev == "high"
    assert line is not None
    assert "campaign" in line.lower()


def test_nudge_low_to_medium() -> None:
    new_sev, _ = ce.maybe_nudge_severity_for_campaign(
        current_severity="low",
        campaign_block=_ok_block(highest="high"),
    )
    assert new_sev == "medium"


def test_nudge_info_to_medium() -> None:
    new_sev, _ = ce.maybe_nudge_severity_for_campaign(
        current_severity="info",
        campaign_block=_ok_block(highest="critical"),
    )
    assert new_sev == "medium"


def test_nudge_skips_already_high() -> None:
    new_sev, _ = ce.maybe_nudge_severity_for_campaign(
        current_severity="high",
        campaign_block=_ok_block(highest="critical"),
    )
    assert new_sev is None


def test_nudge_skips_already_critical() -> None:
    new_sev, _ = ce.maybe_nudge_severity_for_campaign(
        current_severity="critical",
        campaign_block=_ok_block(highest="critical"),
    )
    assert new_sev is None


def test_nudge_skips_when_campaigns_are_medium_or_lower() -> None:
    """Only campaigns >= high cause severity nudges."""
    new_sev, _ = ce.maybe_nudge_severity_for_campaign(
        current_severity="medium",
        campaign_block=_ok_block(highest="medium"),
    )
    assert new_sev is None


def test_nudge_skips_stale_block() -> None:
    stale = _ok_block()
    stale["reason"] = "cache_stale"
    new_sev, _ = ce.maybe_nudge_severity_for_campaign(
        current_severity="medium",
        campaign_block=stale,
    )
    assert new_sev is None


def test_nudge_respects_kill_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_CAMPAIGN_ENRICHMENT_DISABLED", "1")
    new_sev, _ = ce.maybe_nudge_severity_for_campaign(
        current_severity="medium",
        campaign_block=_ok_block(highest="high"),
    )
    assert new_sev is None


def test_nudge_handles_garbage_block() -> None:
    """Defensive: malformed block must not raise."""
    new_sev, _ = ce.maybe_nudge_severity_for_campaign(
        current_severity="medium",
        campaign_block={},  # type: ignore[arg-type]
    )
    assert new_sev is None
