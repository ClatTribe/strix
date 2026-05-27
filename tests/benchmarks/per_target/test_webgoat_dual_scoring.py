"""Tests for iter-Q1.2 — WebGoat dual-mode scoring.

Pins the detection_rate / completion_rate / chain_gap math against
regressions. The chain_gap headline metric is the iter-Q1 proposal's
explicit L2-value separator — getting it wrong silently misattributes
"L2 chain failure" as "L1 detection failure" or vice-versa.
"""

from __future__ import annotations

import pytest

from benchmarks.per_target.webgoat_dual_scoring import (
    DualScorecard,
    LessonExpectation,
    WEBGOAT_BENCH_LESSONS,
    _finding_covers_lesson,
    render_report,
    score_completion,
    score_detection,
    score_dual,
)


# ---------------------------------------------------------------------------
# Detection scoring
# ---------------------------------------------------------------------------


def _lesson(lesson_id: str = "SqlInjection.lesson",
            cwe: str = "CWE-89",
            endpoint: str = "/WebGoat/SqlInjection/attack5a") -> LessonExpectation:
    return LessonExpectation(
        lesson_id=lesson_id, cwe=cwe, exploit_endpoint=endpoint,
    )


def test_finding_covers_lesson_matching_cwe_and_endpoint():
    """A finding with the lesson's CWE + an endpoint hitting the
    lesson's exploit URL covers the lesson."""
    f = {
        "cwe": "CWE-89",
        "endpoint": "http://localhost:8082/WebGoat/SqlInjection/attack5a?q=1",
    }
    assert _finding_covers_lesson(f, _lesson()) is True


def test_finding_does_not_cover_wrong_cwe():
    """A finding with the wrong CWE doesn't cover the lesson even
    if the endpoint matches."""
    f = {"cwe": "CWE-79", "endpoint": "/WebGoat/SqlInjection/attack5a"}
    assert _finding_covers_lesson(f, _lesson()) is False


def test_finding_does_not_cover_wrong_endpoint():
    """A finding with the right CWE but wrong endpoint doesn't cover.
    Conservative — we don't want generic SQLi findings to claim
    coverage of lesson-specific surfaces."""
    f = {"cwe": "CWE-89", "endpoint": "/WebGoat/IDOR/profile"}
    assert _finding_covers_lesson(f, _lesson()) is False


def test_finding_covers_lesson_with_path_relative_endpoint():
    """Coverage works for both `http://...` and bare path."""
    f = {"cwe": "CWE-89", "endpoint": "/WebGoat/SqlInjection/attack5a"}
    assert _finding_covers_lesson(f, _lesson()) is True


def test_score_detection_no_findings():
    detected_count, detected_ids = score_detection([], [_lesson()])
    assert detected_count == 0
    assert detected_ids == set()


def test_score_detection_multi_lesson():
    """Strix found SQLi + XSS lessons; missed JWT."""
    lessons = [
        _lesson("SqlInjection.lesson", "CWE-89", "/WebGoat/SqlInjection/attack5a"),
        _lesson("CrossSiteScripting.lesson", "CWE-79", "/WebGoat/CrossSiteScripting/attack5a"),
        _lesson("JWT.lesson", "CWE-347", "/WebGoat/JWT/decode"),
    ]
    findings = [
        {"cwe": "CWE-89", "endpoint": "/WebGoat/SqlInjection/attack5a"},
        {"cwe": "CWE-79", "endpoint": "/WebGoat/CrossSiteScripting/attack5a"},
        # JWT lesson missed — no finding.
    ]
    count, ids = score_detection(findings, lessons)
    assert count == 2
    assert ids == {"SqlInjection.lesson", "CrossSiteScripting.lesson"}


def test_score_detection_dedupes_multiple_findings_for_one_lesson():
    """Two findings against the same lesson count as one detection."""
    lessons = [_lesson()]
    findings = [
        {"cwe": "CWE-89", "endpoint": "/WebGoat/SqlInjection/attack5a?id=1"},
        {"cwe": "CWE-89", "endpoint": "/WebGoat/SqlInjection/attack5a?id=2"},
    ]
    count, ids = score_detection(findings, lessons)
    assert count == 1


# ---------------------------------------------------------------------------
# Completion scoring
# ---------------------------------------------------------------------------


def test_score_completion_dict_shape():
    """WebGoat returns {lesson_id: {solved, lessonName, ...}}."""
    progress = {
        "SqlInjection.lesson": {"lessonName": "SqlInjection.lesson", "solved": True},
        "JWT.lesson": {"lessonName": "JWT.lesson", "solved": False},
    }
    lessons = [
        _lesson("SqlInjection.lesson", "CWE-89", "/WebGoat/SqlInjection/attack5a"),
        _lesson("JWT.lesson", "CWE-347", "/WebGoat/JWT/decode"),
    ]
    count, ids = score_completion(progress, lessons)
    assert count == 1
    assert ids == {"SqlInjection.lesson"}


def test_score_completion_list_shape():
    """Alternate WebGoat version shape: [{lessonName, solved}, ...]."""
    progress = [
        {"lessonName": "SqlInjection.lesson", "solved": True},
        {"lessonName": "JWT.lesson", "solved": True},
    ]
    lessons = [
        _lesson("SqlInjection.lesson", "CWE-89", "/WebGoat/SqlInjection/attack5a"),
        _lesson("JWT.lesson", "CWE-347", "/WebGoat/JWT/decode"),
    ]
    count, ids = score_completion(progress, lessons)
    assert count == 2


def test_score_completion_empty_progress():
    """No lesson-progress data (e.g. registration failed) → 0
    completions, no exceptions."""
    count, ids = score_completion({}, [_lesson()])
    assert count == 0
    assert ids == set()


def test_score_completion_ignores_unknown_lessons():
    """Lessons NOT in our bench universe are ignored even if WebGoat
    marks them solved."""
    progress = {
        "RandomOtherLesson.lesson": {"lessonName": "RandomOtherLesson.lesson", "solved": True},
    }
    count, ids = score_completion(progress, [_lesson()])
    assert count == 0


# ---------------------------------------------------------------------------
# Headline integration: score_dual
# ---------------------------------------------------------------------------


def test_score_dual_perfect_chain():
    """Strix detected AND completed every lesson. Chain gap = 0."""
    lessons = [
        _lesson("SqlInjection.lesson", "CWE-89", "/WebGoat/SqlInjection/attack5a"),
        _lesson("CrossSiteScripting.lesson", "CWE-79", "/WebGoat/CrossSiteScripting/attack5a"),
    ]
    findings = [
        {"cwe": "CWE-89", "endpoint": "/WebGoat/SqlInjection/attack5a"},
        {"cwe": "CWE-79", "endpoint": "/WebGoat/CrossSiteScripting/attack5a"},
    ]
    progress = {
        "SqlInjection.lesson": {"solved": True, "lessonName": "SqlInjection.lesson"},
        "CrossSiteScripting.lesson": {"solved": True, "lessonName": "CrossSiteScripting.lesson"},
    }
    sc = score_dual(findings, progress, lessons)
    assert sc.detection_rate == 1.0
    assert sc.completion_rate == 1.0
    assert sc.chain_gap == 0.0
    assert sc.lessons_both == 2


def test_score_dual_chain_gap_when_found_but_not_chained():
    """The headline scenario: strix's L1 finds the bug but L2 doesn't
    execute the specific exploit that flips WebGoat's checker."""
    lessons = [
        _lesson("SqlInjection.lesson", "CWE-89", "/WebGoat/SqlInjection/attack5a"),
    ]
    findings = [
        {"cwe": "CWE-89", "endpoint": "/WebGoat/SqlInjection/attack5a"},
    ]
    progress = {  # WebGoat checker did NOT fire
        "SqlInjection.lesson": {"solved": False, "lessonName": "SqlInjection.lesson"},
    }
    sc = score_dual(findings, progress, lessons)
    assert sc.detection_rate == 1.0
    assert sc.completion_rate == 0.0
    assert sc.chain_gap == 1.0
    assert sc.lessons_detected_not_completed == 1
    assert sc.chain_gap_lesson_ids == ["SqlInjection.lesson"]


def test_score_dual_uses_default_lessons_when_not_passed():
    """`score_dual(findings, progress)` falls back to WEBGOAT_BENCH_
    LESSONS — the canonical universe."""
    sc = score_dual([], {}, lessons=None)
    assert sc.lessons_total == len(WEBGOAT_BENCH_LESSONS)


def test_score_dual_zero_division_safety():
    """Empty lessons universe → all rates 0, no ZeroDivision."""
    sc = score_dual([], {}, [])
    assert sc.detection_rate == 0.0
    assert sc.completion_rate == 0.0
    assert sc.chain_gap == 0.0


# ---------------------------------------------------------------------------
# Bench universe sanity
# ---------------------------------------------------------------------------


def test_webgoat_bench_lessons_have_all_required_fields():
    """Curated lesson universe must have stable schema."""
    for lesson in WEBGOAT_BENCH_LESSONS:
        assert "lesson_id" in lesson
        assert "cwe" in lesson
        assert "exploit_endpoint" in lesson
        assert lesson["cwe"].startswith("CWE-")
        assert lesson["exploit_endpoint"].startswith("/WebGoat/")


def test_webgoat_bench_lessons_have_unique_ids():
    """No duplicate lesson_ids."""
    ids = [l["lesson_id"] for l in WEBGOAT_BENCH_LESSONS]
    assert len(ids) == len(set(ids))


def test_webgoat_bench_covers_major_vuln_classes():
    """Sanity: the bench covers the major OWASP Top 10 classes."""
    cwes = {l["cwe"] for l in WEBGOAT_BENCH_LESSONS}
    expected_subset = {
        "CWE-89",   # SQLi
        "CWE-79",   # XSS
        "CWE-22",   # Path traversal
        "CWE-352",  # CSRF
        "CWE-918",  # SSRF
        "CWE-611",  # XXE
        "CWE-347",  # JWT
    }
    missing = expected_subset - cwes
    assert not missing, f"bench lesson universe missing: {missing}"


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def test_render_report_includes_headline_metrics():
    sc = DualScorecard(
        lessons_total=10,
        lessons_detected=5,
        lessons_completed=2,
        lessons_both=2,
        lessons_detected_not_completed=3,
        detected_lesson_ids=["A", "B", "C", "D", "E"],
        completed_lesson_ids=["A", "B"],
        chain_gap_lesson_ids=["C", "D", "E"],
    )
    md = render_report(sc, run_id="test")
    assert "Detection rate" in md
    assert "Completion rate" in md
    assert "L2 chain gap" in md
    assert "50.00%" in md  # 5/10 detection
    assert "20.00%" in md  # 2/10 completion
    assert "30.00%" in md  # 50% - 20% = 30% chain gap


def test_render_report_explains_chain_gap():
    """The report must explain what chain_gap means — operators
    reading the bench output should know the metric's meaning."""
    sc = DualScorecard()
    md = render_report(sc)
    assert "L2 chain-execution" in md or "chain reasoning" in md


# ---------------------------------------------------------------------------
# Anti-overfit guard
# ---------------------------------------------------------------------------


def test_scoring_module_has_no_juiceshop_identifiers():
    """The WebGoat scoring module must be WebGoat-specific but not
    leak Juice-Shop / VAmPI / etc."""
    from pathlib import Path
    src = (
        Path(__file__).parent.parent.parent.parent
        / "benchmarks" / "per_target" / "webgoat_dual_scoring.py"
    ).read_text(encoding="utf-8")
    for forbidden in ("juice-shop", "juiceshop", "bkimminich", "vampi", "crapi", "erev0s"):
        assert forbidden not in src.lower(), (
            f"webgoat_dual_scoring.py contains {forbidden!r} — must "
            f"stay fixture-specific to WebGoat only."
        )
