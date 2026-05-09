"""Tests for §workitem.md Phase 5.1 — hypothesis-experiment-result loop.

Pins:
  * score_hypothesis combines category severity + age + probe density + surface
  * pick_next_hypothesis returns highest-EV record
  * find_stuck_hypotheses surfaces dead-end records
  * probes_for_hypothesis walks decision_log
  * record_probe_for_hypothesis auto-links the probe to the hypothesis
  * loop_health_summary returns the lead's self-audit shape
  * Best-effort: empty stores → safe defaults (no exceptions)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from strix.agents.active_hypotheses import (
    open_hypothesis,
    reset_for_testing as reset_hypotheses,
)
from strix.agents.decision_log import (
    record_decision,
    reset_decision_log,
)
from strix.agents.hypothesis_loop import (
    StuckHypothesis,
    _count_probes,
    _surface_specificity,
    find_stuck_hypotheses,
    loop_health_summary,
    pick_next_hypothesis,
    probes_for_hypothesis,
    rank_hypotheses,
    record_probe_for_hypothesis,
    score_hypothesis,
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path) -> None:
    """Each test gets a fresh hypothesis store + decision log."""
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    set_global_tracer(Tracer("test-hyp-loop"))
    reset_hypotheses()
    reset_decision_log()
    yield
    reset_hypotheses()
    reset_decision_log()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_surface_specificity_url_with_param() -> None:
    score = _surface_specificity(
        "GET http://example.com/api/items?id=1 (param=id)"
    )
    assert score == 1.0


def test_surface_specificity_url_only() -> None:
    assert _surface_specificity("http://example.com/api/items") == 0.7


def test_surface_specificity_path_only() -> None:
    assert _surface_specificity("/admin/login") == 0.5


def test_surface_specificity_handwave() -> None:
    assert _surface_specificity("admin endpoints") == 0.2


def test_surface_specificity_empty() -> None:
    assert _surface_specificity("") == 0.0
    assert _surface_specificity(None) == 0.0  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Score components
# ---------------------------------------------------------------------------


def test_score_critical_category_higher_than_low_category() -> None:
    rec = open_hypothesis(
        hypothesis="SQLi in id",
        surface="http://example.com/api/items?id=1",
        category="sqli",
    )
    rec_low = open_hypothesis(
        hypothesis="weak CSP",
        surface="http://example.com/",
        category="csp",
    )
    s_high = score_hypothesis(rec)
    s_low = score_hypothesis(rec_low)
    assert s_high > s_low


def test_score_resolved_hypothesis_returns_zero() -> None:
    """confirmed/dismissed don't compete for next-pick attention."""
    rec = open_hypothesis(
        hypothesis="x", surface="/x", category="sqli",
    )
    rec_confirmed = dict(rec)
    rec_confirmed["status"] = "confirmed"
    assert score_hypothesis(rec_confirmed) == 0.0
    rec_dismissed = dict(rec)
    rec_dismissed["status"] = "dismissed"
    assert score_hypothesis(rec_dismissed) == 0.0


def test_score_age_decay() -> None:
    """Old hypothesis scores lower than fresh."""
    rec = open_hypothesis(
        hypothesis="old", surface="/x", category="sqli",
    )
    now = datetime.now(timezone.utc)
    fresh_score = score_hypothesis(rec, now=now)
    old_score = score_hypothesis(rec, now=now + timedelta(hours=2))
    assert fresh_score > old_score


def test_score_probe_density_boost() -> None:
    """Hypothesis with probes recorded scores higher than one without."""
    rec_a = open_hypothesis(
        hypothesis="a", surface="/x", category="sqli",
    )
    rec_b = open_hypothesis(
        hypothesis="b", surface="/x", category="sqli",
    )
    # Add probes for rec_b only.
    for i in range(3):
        record_decision(
            kind="probe", target="/x",
            links={"hypothesis_id": rec_b["hypothesis_id"]},
        )
    assert score_hypothesis(rec_b) > score_hypothesis(rec_a)


# ---------------------------------------------------------------------------
# pick_next_hypothesis
# ---------------------------------------------------------------------------


def test_pick_next_returns_highest_ev() -> None:
    open_hypothesis(
        hypothesis="weak CSP", surface="/", category="csp",
    )
    sqli = open_hypothesis(
        hypothesis="SQLi in id",
        surface="http://example.com/api/items?id=1",
        category="sqli",
    )
    pick = pick_next_hypothesis()
    assert pick is not None
    assert pick["hypothesis_id"] == sqli["hypothesis_id"]


def test_pick_next_filtered_by_category() -> None:
    open_hypothesis(
        hypothesis="SQLi", surface="/api", category="sqli",
    )
    xss = open_hypothesis(
        hypothesis="XSS", surface="/search", category="xss",
    )
    pick = pick_next_hypothesis(only_category="xss")
    assert pick is not None
    assert pick["hypothesis_id"] == xss["hypothesis_id"]


def test_pick_next_no_open_hypotheses() -> None:
    assert pick_next_hypothesis() is None


# ---------------------------------------------------------------------------
# rank_hypotheses
# ---------------------------------------------------------------------------


def test_rank_hypotheses_orders_by_score() -> None:
    open_hypothesis(
        hypothesis="weak CSP", surface="/", category="csp",
    )
    open_hypothesis(
        hypothesis="SQLi in id",
        surface="http://example.com/api/items?id=1",
        category="sqli",
    )
    open_hypothesis(
        hypothesis="open redirect",
        surface="http://example.com/redir",
        category="open_redirect",
    )
    ranked = rank_hypotheses(top_n=10)
    assert len(ranked) == 3
    # First entry has highest score.
    assert ranked[0][0] >= ranked[1][0] >= ranked[2][0]
    # Topmost is sqli.
    assert "SQLi" in ranked[0][1]["hypothesis"]


# ---------------------------------------------------------------------------
# find_stuck_hypotheses
# ---------------------------------------------------------------------------


def test_find_stuck_with_old_no_probes() -> None:
    """Open a hypothesis, manually back-date its opened_at into the
    past, expect it to surface as stuck."""
    rec = open_hypothesis(
        hypothesis="ancient", surface="/x", category="sqli",
    )
    # Back-date by 20 minutes.
    from strix.agents.active_hypotheses import _append_record
    rec_back = dict(rec)
    rec_back["opened_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=20)
    ).isoformat()
    _append_record(rec_back)

    stuck = find_stuck_hypotheses()
    assert any(s.hypothesis == "ancient" for s in stuck)
    target = next(s for s in stuck if s.hypothesis == "ancient")
    assert target.probes_recorded == 0
    assert target.suggested_action == "dismiss"


def test_find_stuck_with_old_one_probe_returns_deepen_action() -> None:
    rec = open_hypothesis(
        hypothesis="weakly probed", surface="/x", category="sqli",
    )
    from strix.agents.active_hypotheses import _append_record
    rec_back = dict(rec)
    rec_back["opened_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=20)
    ).isoformat()
    _append_record(rec_back)
    record_decision(
        kind="probe", target="/x",
        links={"hypothesis_id": rec["hypothesis_id"]},
    )
    stuck = find_stuck_hypotheses()
    target = next(s for s in stuck if s.hypothesis == "weakly probed")
    assert target.probes_recorded == 1
    assert target.suggested_action == "deepen_or_dismiss"


def test_find_stuck_excludes_fresh_hypotheses() -> None:
    open_hypothesis(
        hypothesis="brand new", surface="/x", category="sqli",
    )
    stuck = find_stuck_hypotheses()
    assert not any(s.hypothesis == "brand new" for s in stuck)


def test_find_stuck_excludes_well_probed_hypotheses() -> None:
    rec = open_hypothesis(
        hypothesis="actively chased", surface="/x", category="sqli",
    )
    from strix.agents.active_hypotheses import _append_record
    rec_back = dict(rec)
    rec_back["opened_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=30)
    ).isoformat()
    _append_record(rec_back)
    for _ in range(5):
        record_decision(
            kind="probe", target="/x",
            links={"hypothesis_id": rec["hypothesis_id"]},
        )
    stuck = find_stuck_hypotheses()
    assert not any(s.hypothesis == "actively chased" for s in stuck)


# ---------------------------------------------------------------------------
# probes_for_hypothesis + record_probe_for_hypothesis
# ---------------------------------------------------------------------------


def test_record_probe_links_to_hypothesis() -> None:
    rec = open_hypothesis(
        hypothesis="x", surface="/x", category="sqli",
    )
    did = record_probe_for_hypothesis(
        hypothesis_id=rec["hypothesis_id"],
        target="http://example.com/api?id=1",
        payload_label="boolean_blind",
        payload="' OR 1=1--",
        output={"status": 200},
    )
    assert did.startswith("d_")
    probes = probes_for_hypothesis(rec["hypothesis_id"])
    assert len(probes) == 1
    assert probes[0].input["payload_label"] == "boolean_blind"


def test_probes_for_hypothesis_excludes_unrelated() -> None:
    rec_a = open_hypothesis(
        hypothesis="a", surface="/x", category="sqli",
    )
    rec_b = open_hypothesis(
        hypothesis="b", surface="/y", category="xss",
    )
    record_probe_for_hypothesis(
        hypothesis_id=rec_a["hypothesis_id"],
        target="http://x/", payload_label="p1",
    )
    record_probe_for_hypothesis(
        hypothesis_id=rec_b["hypothesis_id"],
        target="http://y/", payload_label="p2",
    )
    a_probes = probes_for_hypothesis(rec_a["hypothesis_id"])
    assert len(a_probes) == 1
    assert a_probes[0].target == "http://x/"


def test_record_probe_with_invalid_id_returns_empty() -> None:
    assert record_probe_for_hypothesis(
        hypothesis_id="", target="x",
    ) == ""


# ---------------------------------------------------------------------------
# loop_health_summary
# ---------------------------------------------------------------------------


def test_loop_health_summary_empty_state() -> None:
    summary = loop_health_summary()
    assert summary["open_count"] == 0
    assert summary["stuck_count"] == 0
    assert summary["next_pick"] is None
    assert summary["stuck"] == []


def test_loop_health_summary_populated() -> None:
    open_hypothesis(
        hypothesis="SQLi", surface="http://x/?id=1", category="sqli",
    )
    open_hypothesis(
        hypothesis="weak CSP", surface="/", category="csp",
    )
    summary = loop_health_summary()
    assert summary["open_count"] == 2
    assert summary["next_pick"] is not None
    assert "SQLi" in summary["next_pick"]["hypothesis"]
    assert summary["next_pick"]["score"] > 0


# ---------------------------------------------------------------------------
# Best-effort robustness
# ---------------------------------------------------------------------------


def test_score_handles_malformed_record() -> None:
    """Non-dict / missing fields → 0.0, no exception."""
    assert score_hypothesis(None) == 0.0  # type: ignore[arg-type]
    assert score_hypothesis({}) == 0.0
    assert score_hypothesis({"status": "investigating"}) > 0.0


def test_count_probes_with_empty_decision_log() -> None:
    assert _count_probes("hyp_doesnotexist") == 0
    assert _count_probes(None) == 0  # type: ignore[arg-type]
    assert _count_probes("") == 0
