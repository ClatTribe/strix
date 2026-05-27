"""Tests for iter-Q2.2 — compaction transcript artifact.

Per docs/proposals/2026-05-27-token-reduction-v2-stratified-compaction.md.

The transcript is the deterministic markdown summary that replaces
COLD-stratum conversation turns dropped by the iter-Q2.1 stratified
compactor.

Pins:
  * Section structure: 4 sections, all present
  * Determinism: same inputs → identical output (no LLM, no clock)
  * Detection guarantee: every finding (up to cap) renders into the
    findings table — the compactor never silently drops a CV-report
  * L1.5 enrichment fields surface (surface_priority, exploitability,
    corroborated_by) so the LLM still reads what L1.5 wrote
  * Persistence: writes to `<run_dir>/compaction_transcript.md` when
    `STRIX_RUN_DIR` is set
  * Opt-out flag: `STRIX_COMPACTION_TRANSCRIPT_DISABLED=1` short-circuits
  * Anti-overfit guard: no fixture identifiers in source
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from strix.llm.compaction_transcript import (
    DEFAULT_MAX_FINDINGS_IN_TRANSCRIPT,
    CompactionTranscript,
    TranscriptSection,
    _build_findings_section,
    _build_open_questions_section,
    _build_what_we_know_section,
    _build_what_weve_tried_section,
    build_and_persist_transcript,
    is_transcript_disabled,
    render_transcript,
    render_transcript_from_singletons,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Default to ON for tests (matches production default)."""
    monkeypatch.delenv("STRIX_COMPACTION_TRANSCRIPT_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)


# ---------------------------------------------------------------------------
# Opt-out flag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("v,expected", [
    ("1", True), ("true", True), ("yes", True), ("on", True),
    ("True", True), ("YES", True),
    ("0", False), ("false", False), ("", False), ("garbage", False),
])
def test_opt_out_flag_canonical_values(monkeypatch, v, expected):
    monkeypatch.setenv("STRIX_COMPACTION_TRANSCRIPT_DISABLED", v)
    assert is_transcript_disabled() is expected


def test_opt_out_default_false():
    """Default ON — transcript renders by default."""
    assert is_transcript_disabled() is False


def test_opt_out_short_circuits_persistence(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIX_COMPACTION_TRANSCRIPT_DISABLED", "1")
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    out = build_and_persist_transcript(
        vulnerability_reports=[{"title": "x", "severity": "high"}],
    )
    assert out is None
    assert not (tmp_path / "compaction_transcript.md").exists()


def test_opt_out_short_circuits_singleton_entry(monkeypatch):
    monkeypatch.setenv("STRIX_COMPACTION_TRANSCRIPT_DISABLED", "1")
    assert render_transcript_from_singletons() is None


# ---------------------------------------------------------------------------
# Section builders — "What we know"
# ---------------------------------------------------------------------------


def test_what_we_know_handles_empty_inputs():
    sect = _build_what_we_know_section(None, None)
    assert isinstance(sect, TranscriptSection)
    assert sect.heading == "What we know so far"
    assert "no state recorded" in sect.body.lower()


def test_what_we_know_surfaces_workflow_phase():
    snap = {
        "current_phase": "auth_attempt",
        "endpoints_discovered_count": 7,
        "login_forms_found": ["/login"],
        "findings_emitted": 3,
        "chains_emitted": 1,
    }
    sect = _build_what_we_know_section(snap, None)
    assert "auth_attempt" in sect.body
    assert "7" in sect.body
    assert "Login forms found" in sect.body
    assert "Chains promoted" in sect.body


def test_what_we_know_surfaces_tech_stack():
    sc = {"tech_stack": {"server": "nginx", "framework": "express", "database": "postgres"}}
    sect = _build_what_we_know_section(None, sc)
    assert "nginx" in sect.body
    assert "express" in sect.body
    assert "postgres" in sect.body


def test_what_we_know_surfaces_auth_states():
    sc = {"auth_states": {"admin": {"label": "admin"}, "user": {"label": "user"}}}
    sect = _build_what_we_know_section(None, sc)
    assert "admin" in sect.body
    assert "user" in sect.body


def test_what_we_know_skips_empty_tech_fields():
    sc = {"tech_stack": {"server": "", "framework": None, "database": "mysql"}}
    sect = _build_what_we_know_section(None, sc)
    assert "mysql" in sect.body
    # Empty/None values should be filtered.
    assert "server=" not in sect.body
    assert "framework=" not in sect.body


# ---------------------------------------------------------------------------
# Section builders — "What we've tried"
# ---------------------------------------------------------------------------


def test_what_weve_tried_empty():
    sect = _build_what_weve_tried_section(None)
    assert sect.heading == "What we've tried"
    assert "no tool calls" in sect.body.lower()


def test_what_weve_tried_renders_tool_counts():
    snap = {
        "tools_run": ["scan_sqli", "scan_sqli", "scan_xss", "scan_idor"],
        "tools_succeeded": ["scan_sqli", "scan_xss"],
        "tools_failed": ["scan_idor"],
    }
    sect = _build_what_weve_tried_section(snap)
    # scan_sqli runs 2× and succeeded → should render with success marker.
    assert "scan_sqli" in sect.body
    assert "2×" in sect.body or "(2×" in sect.body
    # scan_idor failed.
    assert "scan_idor" in sect.body
    assert "✗" in sect.body
    # scan_xss succeeded.
    assert "✓" in sect.body


def test_what_weve_tried_sorts_by_count_descending():
    snap = {
        "tools_run": ["a", "b", "b", "b", "c", "c"],
        "tools_succeeded": ["a", "b", "c"],
        "tools_failed": [],
    }
    sect = _build_what_weve_tried_section(snap)
    pos_b = sect.body.find("`b`")
    pos_c = sect.body.find("`c`")
    pos_a = sect.body.find("`a`")
    assert 0 < pos_b < pos_c < pos_a, sect.body


# ---------------------------------------------------------------------------
# Section builders — Findings (THE DETECTION-GUARANTEE SECTION)
# ---------------------------------------------------------------------------


def test_findings_empty():
    sect = _build_findings_section(None)
    assert sect.heading == "Findings emitted so far"
    assert "no findings" in sect.body.lower()


def test_findings_renders_every_field_per_finding():
    reports = [
        {
            "title": "SQL injection at /api/users",
            "severity": "critical",
            "cwe": "CWE-89",
            "endpoint": "/api/users",
            "surface_priority": "critical",
            "exploitability": {"score": 0.9, "level": "high"},
            "corroborated_by": ["scan_sqli", "scan_nuclei_templates"],
            "confidence": 0.95,
        },
    ]
    sect = _build_findings_section(reports)
    assert "SQL injection" in sect.body
    assert "CWE-89" in sect.body
    assert "/api/users" in sect.body
    assert "critical" in sect.body
    # exploitability dict → render score or level
    assert "0.9" in sect.body or "high" in sect.body
    # corroborated_by → renders count.
    assert "2" in sect.body


def test_findings_render_includes_every_emitted_finding_up_to_cap():
    """The detection-guarantee invariant: every CV-report row appears
    in the findings table (up to the cap). The compactor never silently
    drops findings."""
    reports = [
        {"title": f"finding-{i}", "severity": "high", "cwe": "CWE-1"}
        for i in range(10)
    ]
    sect = _build_findings_section(reports, max_findings=50)
    for i in range(10):
        assert f"finding-{i}" in sect.body


def test_findings_caps_at_max_findings():
    reports = [
        {"title": f"f-{i}", "severity": "high", "surface_priority": "critical"}
        for i in range(80)
    ]
    sect = _build_findings_section(reports, max_findings=20)
    # Header announces the cap.
    assert "Total" in sect.body
    assert "80" in sect.body
    assert "top 20" in sect.body.lower()


def test_findings_sorted_by_priority_then_confidence():
    reports = [
        {"title": "low-conf", "surface_priority": "high", "confidence": 0.3},
        {"title": "high-conf", "surface_priority": "high", "confidence": 0.9},
        {"title": "critical-find", "surface_priority": "critical", "confidence": 0.5},
        {"title": "low-find", "surface_priority": "low", "confidence": 0.99},
    ]
    sect = _build_findings_section(reports)
    pos_critical = sect.body.find("critical-find")
    pos_high_conf = sect.body.find("high-conf")
    pos_low_conf = sect.body.find("low-conf")
    pos_low_find = sect.body.find("low-find")
    # critical surface ranks above high (regardless of confidence).
    assert pos_critical < pos_high_conf
    assert pos_critical < pos_low_find
    # within "high", higher confidence ranks higher.
    assert pos_high_conf < pos_low_conf


def test_findings_handles_scalar_exploitability():
    reports = [{"title": "x", "exploitability": "high", "severity": "low"}]
    sect = _build_findings_section(reports)
    assert "high" in sect.body


def test_findings_handles_missing_fields_gracefully():
    """A bare-minimum finding shouldn't crash the renderer."""
    reports = [{"title": "x"}, {}, {"severity": None, "cwe": None}]
    sect = _build_findings_section(reports)
    # Should render 3 rows.
    rows = [l for l in sect.body.splitlines() if l.startswith("| ") and "—" not in l]
    # Header + separator + 3 data rows.
    assert len(rows) >= 3


def test_findings_handles_long_endpoint_titles_via_truncation():
    """Long endpoints/titles must be truncated so markdown table stays
    readable."""
    reports = [{"title": "T" * 200, "endpoint": "E" * 200}]
    sect = _build_findings_section(reports)
    # Truncated to 60 chars (max).
    assert "T" * 200 not in sect.body
    assert "E" * 200 not in sect.body


# ---------------------------------------------------------------------------
# Section builders — Open questions
# ---------------------------------------------------------------------------


def test_open_questions_empty():
    sect = _build_open_questions_section(None, None)
    assert sect.heading == "Open questions"
    assert "no open questions" in sect.body.lower()


def test_open_questions_surfaces_partial_signals():
    sc = {
        "partial_signals": [
            {
                "surface": "/api/login",
                "signal": "responded 200 to invalid creds",
                "next_probe": "try registration endpoint",
            },
        ],
    }
    sect = _build_open_questions_section(None, sc)
    assert "/api/login" in sect.body
    assert "invalid creds" in sect.body
    assert "next:" in sect.body or "registration" in sect.body


def test_open_questions_surfaces_auth_retry_candidate():
    snap = {
        "login_forms_found": ["/login"],
        "auth_state_captured": False,
    }
    sect = _build_open_questions_section(snap, None)
    assert "Auth retry candidate" in sect.body
    assert "scan_auth_flow" in sect.body


def test_open_questions_silent_when_auth_already_captured():
    snap = {
        "login_forms_found": ["/login"],
        "auth_state_captured": True,
    }
    sect = _build_open_questions_section(snap, None)
    assert "Auth retry candidate" not in sect.body


def test_open_questions_caps_partial_signals_to_10():
    """Don't blow up the transcript with 100 partial signals."""
    sc = {
        "partial_signals": [
            {"surface": f"/path-{i}", "signal": "x", "next_probe": "y"}
            for i in range(50)
        ],
    }
    sect = _build_open_questions_section(None, sc)
    # Only first 10 are rendered.
    assert "/path-0" in sect.body
    assert "/path-9" in sect.body
    assert "/path-49" not in sect.body


# ---------------------------------------------------------------------------
# Top-level render — structure + determinism
# ---------------------------------------------------------------------------


def test_render_transcript_returns_dataclass():
    tr = render_transcript()
    assert isinstance(tr, CompactionTranscript)
    assert tr.section_count == 4
    assert tr.finding_count == 0
    assert tr.char_count > 0
    assert isinstance(tr.markdown, str)


def test_render_transcript_includes_all_sections():
    tr = render_transcript(
        vulnerability_reports=[{"title": "f", "severity": "high"}],
        workflow_snapshot={"current_phase": "probe"},
        security_context={"tech_stack": {"server": "nginx"}},
    )
    assert "What we know so far" in tr.markdown
    assert "What we've tried" in tr.markdown
    assert "Findings emitted so far" in tr.markdown
    assert "Open questions" in tr.markdown


def test_render_transcript_includes_header():
    tr = render_transcript()
    assert tr.markdown.startswith("# Scan compaction transcript")
    # Mentions where the LLM can drill down.
    assert "list_pending_findings" in tr.markdown


def test_render_transcript_deterministic_no_clock():
    """Same inputs → same output. The transcript must be deterministic
    so test sweeps don't flake."""
    payload = {
        "vulnerability_reports": [
            {"title": "x", "severity": "high", "endpoint": "/a"},
        ],
        "workflow_snapshot": {"current_phase": "probe"},
        "security_context": {"tech_stack": {"server": "nginx"}},
    }
    a = render_transcript(**payload).markdown
    b = render_transcript(**payload).markdown
    assert a == b


def test_render_transcript_finding_count_matches_input():
    reports = [{"title": f"f-{i}"} for i in range(7)]
    tr = render_transcript(vulnerability_reports=reports)
    assert tr.finding_count == 7


def test_render_transcript_estimated_tokens_is_chars_over_4():
    tr = render_transcript()
    assert tr.estimated_tokens == tr.char_count // 4


def test_render_transcript_to_dict_returns_metadata():
    tr = render_transcript(
        vulnerability_reports=[{"title": "x"}],
    )
    d = tr.to_dict()
    assert set(d.keys()) >= {
        "section_count", "finding_count", "char_count", "estimated_tokens",
    }
    assert d["finding_count"] == 1


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_build_and_persist_writes_to_run_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    tr = build_and_persist_transcript(
        vulnerability_reports=[{"title": "persisted-finding", "severity": "high"}],
    )
    assert tr is not None
    target = tmp_path / "compaction_transcript.md"
    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "persisted-finding" in content
    assert content == tr.markdown


def test_build_and_persist_skips_when_no_run_dir(monkeypatch):
    """When STRIX_RUN_DIR is unset, persistence is skipped but the
    transcript is still returned."""
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    tr = build_and_persist_transcript()
    assert tr is not None
    assert isinstance(tr, CompactionTranscript)


def test_build_and_persist_overwrites_previous(tmp_path, monkeypatch):
    """Re-running compaction should overwrite the prior transcript."""
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    build_and_persist_transcript(
        vulnerability_reports=[{"title": "first"}],
    )
    build_and_persist_transcript(
        vulnerability_reports=[{"title": "second"}],
    )
    content = (tmp_path / "compaction_transcript.md").read_text(encoding="utf-8")
    assert "second" in content
    assert "first" not in content


def test_build_and_persist_recovers_from_persistence_failure(
    tmp_path, monkeypatch,
):
    """Best-effort: a write failure must not crash the compactor."""
    # Point at a path that can't be written (file masquerading as a dir).
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    monkeypatch.setenv("STRIX_RUN_DIR", str(blocker))
    # Should NOT raise.
    tr = build_and_persist_transcript()
    # Transcript object still returned even if persist failed.
    assert tr is None or isinstance(tr, CompactionTranscript)


# ---------------------------------------------------------------------------
# Singleton entry point
# ---------------------------------------------------------------------------


def test_render_from_singletons_returns_something(tmp_path, monkeypatch):
    """The singleton entry must not crash even with no scan in flight."""
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    out = render_transcript_from_singletons()
    # On a fresh interpreter the singletons may not exist; defensive
    # return of None is fine. When they do exist, we get a transcript.
    assert out is None or isinstance(out, CompactionTranscript)


def test_render_from_singletons_disabled_via_flag(monkeypatch):
    monkeypatch.setenv("STRIX_COMPACTION_TRANSCRIPT_DISABLED", "1")
    assert render_transcript_from_singletons() is None


# ---------------------------------------------------------------------------
# Detection-guarantee invariants (the load-bearing tests)
# ---------------------------------------------------------------------------


def test_detection_guarantee_findings_never_dropped_below_cap():
    """A scan with 30 emitted findings must surface all 30 when cap=50."""
    reports = [
        {"title": f"finding-{i}", "severity": "medium", "endpoint": f"/api/{i}"}
        for i in range(30)
    ]
    tr = render_transcript(
        vulnerability_reports=reports, max_findings=50,
    )
    for i in range(30):
        assert f"finding-{i}" in tr.markdown


def test_detection_guarantee_severity_field_preserved():
    """A high-severity finding must render with its severity tier
    intact — operators / downstream graders need it."""
    reports = [
        {"title": "x", "severity": "critical"},
        {"title": "y", "severity": "high"},
        {"title": "z", "severity": "low"},
    ]
    tr = render_transcript(vulnerability_reports=reports)
    assert "critical" in tr.markdown
    assert "high" in tr.markdown
    assert "low" in tr.markdown


def test_detection_guarantee_l15_corroboration_count_renders():
    """L1.5 enrichment surfaces in the transcript so the LLM can
    cite the corroboration count when reasoning about chains."""
    reports = [
        {
            "title": "x",
            "severity": "high",
            "corroborated_by": ["a", "b", "c"],
        },
    ]
    tr = render_transcript(vulnerability_reports=reports)
    # The corroboration count "3" must appear in the row.
    assert "3" in tr.markdown


# ---------------------------------------------------------------------------
# Anti-overfit guard
# ---------------------------------------------------------------------------


def test_compaction_transcript_module_has_no_fixture_identifiers():
    """The transcript renderer is generic — it must not contain
    bench-fixture names (juiceshop / vampi / etc.)."""
    src = (
        Path(__file__).parent.parent.parent
        / "strix" / "llm" / "compaction_transcript.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "juice-shop", "juiceshop", "bkimminich", "vampi",
        "crapi", "erev0s", "webgoat", "owasp-benchmark",
    ):
        assert forbidden not in src.lower(), (
            f"compaction_transcript.py contains {forbidden!r}"
        )


def test_compaction_transcript_module_has_no_hardcoded_credentials():
    """Standard guard — the module must not embed API keys / tokens."""
    src = (
        Path(__file__).parent.parent.parent
        / "strix" / "llm" / "compaction_transcript.py"
    ).read_text(encoding="utf-8")
    for prefix in ("sk-", "AIza", "ghp_", "xoxb-"):
        assert prefix not in src, (
            f"compaction_transcript.py contains credential-shaped string {prefix!r}"
        )
