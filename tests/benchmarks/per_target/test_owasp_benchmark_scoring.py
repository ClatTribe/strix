"""Tests for iter-Q1.1 — OWASP Benchmark Project v1.2 scoring math.

These tests pin the canonical scoring methodology (per-CWE TP/FP/TN/FN
→ precision/recall/F1/Youden) so regressions in the math can't slip
past review. The math comes straight from the OWASP Benchmark Project
documentation; getting it wrong silently misreports our number vs
the competitor leaderboard.

Per `docs/proposals/2026-05-27-benchmark-suite-strategy.md` —
this is the **L1 headline benchmark** going forward.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from benchmarks.per_target.owasp_benchmark_scoring import (
    BenchmarkExpectation,
    BenchmarkScorecard,
    CategoryScore,
    OWASP_BENCHMARK_CATEGORIES,
    PUBLISHED_COMPETITOR_SCORES_YOUDEN,
    StrixFlag,
    cwe_to_category,
    findings_to_flags,
    load_expected_results,
    render_report,
    score,
)


# ---------------------------------------------------------------------------
# CategoryScore — TP/FP/TN/FN → derived metrics
# ---------------------------------------------------------------------------


def test_category_score_perfect_recall():
    """All vulns flagged, no false positives → TPR=1, FPR=0,
    Youden=1.0 (the theoretical perfect)."""
    cs = CategoryScore(category="sqli", tp=10, fp=0, tn=10, fn=0)
    assert cs.tpr == 1.0
    assert cs.fpr == 0.0
    assert cs.precision == 1.0
    assert cs.f1 == 1.0
    assert cs.youden == 1.0


def test_category_score_always_flag():
    """Flag every test case → TPR=1, FPR=1, Youden=0 (no better
    than random)."""
    cs = CategoryScore(category="sqli", tp=10, fp=10, tn=0, fn=0)
    assert cs.tpr == 1.0
    assert cs.fpr == 1.0
    assert cs.youden == 0.0  # always-flag is worth nothing


def test_category_score_never_flag():
    """Flag nothing → TPR=0, FPR=0, Youden=0."""
    cs = CategoryScore(category="sqli", tp=0, fp=0, tn=10, fn=10)
    assert cs.tpr == 0.0
    assert cs.fpr == 0.0
    assert cs.youden == 0.0
    # F1 is undefined when precision + recall = 0; we return 0.
    assert cs.f1 == 0.0


def test_category_score_half_recall_no_fp():
    """Caught half the vulns, no FPs → Youden = 0.5."""
    cs = CategoryScore(category="sqli", tp=5, fp=0, tn=10, fn=5)
    assert cs.tpr == 0.5
    assert cs.fpr == 0.0
    assert cs.youden == 0.5
    assert cs.precision == 1.0


def test_category_score_zero_division_safety():
    """Empty category (no test cases at all) → all metrics 0,
    no ZeroDivisionError."""
    cs = CategoryScore(category="empty")
    assert cs.tpr == 0.0
    assert cs.fpr == 0.0
    assert cs.precision == 0.0
    assert cs.f1 == 0.0
    assert cs.youden == 0.0


# ---------------------------------------------------------------------------
# score() — full TP/FP/TN/FN bucketing
# ---------------------------------------------------------------------------


def test_score_perfect_run():
    """Strix flags exactly the real vulns, nothing more."""
    expectations = [
        BenchmarkExpectation("T1", "sqli", 89, is_real_vulnerability=True),
        BenchmarkExpectation("T2", "sqli", 89, is_real_vulnerability=False),
        BenchmarkExpectation("T3", "xss", 79, is_real_vulnerability=True),
        BenchmarkExpectation("T4", "xss", 79, is_real_vulnerability=False),
    ]
    flags = [
        StrixFlag("T1", "sqli"),
        StrixFlag("T3", "xss"),
    ]
    sc = score(expectations, flags)
    assert sc.overall.tp == 2
    assert sc.overall.fp == 0
    assert sc.overall.tn == 2
    assert sc.overall.fn == 0
    assert sc.overall.youden == 1.0


def test_score_false_positive():
    """Strix flagged a safe variant — FP bucket."""
    expectations = [
        BenchmarkExpectation("T1", "sqli", 89, is_real_vulnerability=False),
    ]
    flags = [StrixFlag("T1", "sqli")]
    sc = score(expectations, flags)
    assert sc.overall.fp == 1
    assert sc.overall.tp == 0


def test_score_false_negative():
    """Strix missed a real vuln — FN bucket."""
    expectations = [
        BenchmarkExpectation("T1", "sqli", 89, is_real_vulnerability=True),
    ]
    flags: list[StrixFlag] = []
    sc = score(expectations, flags)
    assert sc.overall.fn == 1
    assert sc.overall.tp == 0


def test_score_cross_category_flags_dont_count_against_recall():
    """A real SQLi flagged as XSS is NOT a TP for SQLi (it's a
    false-positive in XSS, AND a false-negative in SQLi). Per
    OWASP Benchmark Project methodology, each test case is scored
    in its NATIVE category only."""
    expectations = [
        BenchmarkExpectation("T1", "sqli", 89, is_real_vulnerability=True),
    ]
    flags = [
        # Wrong category for this test case
        StrixFlag("T1", "xss"),
    ]
    sc = score(expectations, flags)
    # SQLi: real but not flagged → FN
    assert sc.per_category["sqli"].fn == 1
    assert sc.per_category["sqli"].tp == 0
    # XSS: T1 is NOT in xss expectations, so the rogue flag is
    # silently ignored — there's no "xss" category in the scorecard.
    assert "xss" not in sc.per_category


def test_score_aggregates_overall_correctly():
    """Per-category scores sum to overall."""
    expectations = [
        BenchmarkExpectation(f"S{i}", "sqli", 89, is_real_vulnerability=(i % 2 == 0))
        for i in range(10)
    ]
    expectations.extend([
        BenchmarkExpectation(f"X{i}", "xss", 79, is_real_vulnerability=(i % 2 == 0))
        for i in range(10)
    ])
    # Flag every "real" SQLi correctly, miss all XSS.
    flags = [
        StrixFlag(f"S{i}", "sqli") for i in range(10) if i % 2 == 0
    ]
    sc = score(expectations, flags)
    assert sc.per_category["sqli"].tp == 5  # 5 real sqli, all caught
    assert sc.per_category["sqli"].tn == 5  # 5 safe sqli, none flagged
    assert sc.per_category["xss"].fn == 5   # 5 real xss, all missed
    assert sc.per_category["xss"].tn == 5   # 5 safe xss, none flagged
    # Overall aggregates.
    assert sc.overall.tp == 5
    assert sc.overall.fn == 5
    assert sc.overall.tn == 10
    assert sc.overall.fp == 0
    # Mixed run: 50% recall, 0% FPR → Youden = 0.5
    assert sc.overall.youden == 0.5


# ---------------------------------------------------------------------------
# CWE → category mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cwe_in,expected_category",
    [
        ("CWE-89", "sqli"),
        ("cwe-89", "sqli"),
        ("89", "sqli"),
        (89, "sqli"),
        ("CWE-79", "xss"),
        ("CWE-78", "cmdi"),
        ("CWE-22", "pathtraver"),
        ("CWE-643", "xpathi"),
        ("CWE-90", "ldapi"),
        ("CWE-327", "crypto"),
        ("CWE-328", "hash"),
        ("CWE-330", "weakrand"),
        ("CWE-501", "trustbound"),
        ("CWE-614", "securecookie"),
        # Unknown / not covered
        ("CWE-9999", None),
        ("not-a-cwe", None),
        ("", None),
        (None, None),
    ],
)
def test_cwe_to_category_canonical_mapping(cwe_in, expected_category):
    assert cwe_to_category(cwe_in) == expected_category


def test_owasp_benchmark_categories_complete():
    """All 11 canonical OWASP Benchmark v1.2 categories present."""
    assert OWASP_BENCHMARK_CATEGORIES.keys() == {
        "cmdi", "crypto", "hash", "ldapi", "pathtraver",
        "securecookie", "sqli", "trustbound", "weakrand",
        "xpathi", "xss",
    }


# ---------------------------------------------------------------------------
# findings_to_flags — strix → BenchmarkJava flag mapping
# ---------------------------------------------------------------------------


def test_findings_to_flags_extracts_test_name_from_endpoint():
    findings = [
        {
            "endpoint": "http://target:8080/benchmark/BenchmarkTest00010/sqli",
            "cwe": "CWE-89",
            "title": "SQL Injection",
        },
    ]
    flags = findings_to_flags(findings)
    assert len(flags) == 1
    assert flags[0].test_name == "BenchmarkTest00010"
    assert flags[0].category == "sqli"


def test_findings_to_flags_drops_findings_without_test_name():
    """A finding on a non-BenchmarkJava endpoint (e.g. Tomcat manager)
    has no matching test case → drop it."""
    findings = [
        {"endpoint": "http://target:8080/manager/", "cwe": "CWE-200"},
        {"endpoint": "http://target:8080/", "cwe": "CWE-89"},
    ]
    assert findings_to_flags(findings) == []


def test_findings_to_flags_drops_findings_with_unmapped_cwe():
    """A finding with a CWE outside OWASP Benchmark v1.2's 11
    categories is dropped — it doesn't fit the bench's scoring."""
    findings = [
        {
            "endpoint": "http://target/benchmark/BenchmarkTest00001/anything",
            "cwe": "CWE-9999",  # not in our category map
        },
    ]
    assert findings_to_flags(findings) == []


def test_findings_to_flags_deduplicates():
    """Multiple emissions for the same (test, category) collapse
    to one flag — the bench counts presence, not multiplicity."""
    findings = [
        {
            "endpoint": "http://target/benchmark/BenchmarkTest00010/sqli",
            "cwe": "CWE-89",
        },
        {
            "endpoint": "/benchmark/BenchmarkTest00010/sqli",
            "cwe": "CWE-89",
        },
    ]
    flags = findings_to_flags(findings)
    assert len(flags) == 1


def test_findings_to_flags_handles_target_field_fallback():
    """Some strix tools emit `target=` instead of `endpoint=`. The
    flag extractor should fall back gracefully."""
    findings = [
        {"target": "http://x/benchmark/BenchmarkTest00007/crypto", "cwe": "CWE-327"},
    ]
    flags = findings_to_flags(findings)
    assert len(flags) == 1
    assert flags[0].test_name == "BenchmarkTest00007"
    assert flags[0].category == "crypto"


# ---------------------------------------------------------------------------
# CSV loader
# ---------------------------------------------------------------------------


def test_load_expected_results_parses_canonical_format():
    """Test the canonical
    `# test name, category, real vulnerability, cwe, source`
    header + value rows."""
    csv_text = (
        "# test name, category, real vulnerability, cwe, source\n"
        "BenchmarkTest00001,sqli,true,89,test\n"
        "BenchmarkTest00002,xss,false,79,test\n"
        "BenchmarkTest00003,cmdi,1,78,test\n"  # truthy variants
        "BenchmarkTest00004,sqli,no,89,test\n"   # falsy variants
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False,
    ) as f:
        f.write(csv_text)
        path = f.name
    expectations = load_expected_results(path)
    Path(path).unlink()
    assert len(expectations) == 4
    assert expectations[0].test_name == "BenchmarkTest00001"
    assert expectations[0].category == "sqli"
    assert expectations[0].is_real_vulnerability is True
    assert expectations[1].is_real_vulnerability is False
    assert expectations[2].is_real_vulnerability is True
    assert expectations[3].is_real_vulnerability is False


def test_load_expected_results_skips_unknown_categories():
    """Defensive against future BenchmarkJava versions that add
    a new CWE class. Skip unknown categories rather than error."""
    csv_text = (
        "BenchmarkTest00001,sqli,true,89,test\n"
        "BenchmarkTest00002,never_heard_of_it,true,9999,test\n"
        "BenchmarkTest00003,xss,true,79,test\n"
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False,
    ) as f:
        f.write(csv_text)
        path = f.name
    expectations = load_expected_results(path)
    Path(path).unlink()
    assert len(expectations) == 2
    assert {e.category for e in expectations} == {"sqli", "xss"}


def test_load_expected_results_handles_fixture_subset():
    """The bundled fixture (20-row CSV) must parse cleanly."""
    fixture_csv = (
        Path(__file__).parent.parent.parent.parent
        / "benchmarks" / "per_target" / "fixtures" / "web"
        / "owasp-benchmark" / "expectedresults-1.2.csv"
    )
    assert fixture_csv.is_file(), f"missing: {fixture_csv}"
    expectations = load_expected_results(str(fixture_csv))
    # Subset has 20 test cases.
    assert len(expectations) == 20
    # All categories from our subset.
    categories = {e.category for e in expectations}
    assert categories.issubset(set(OWASP_BENCHMARK_CATEGORIES))


# ---------------------------------------------------------------------------
# Markdown report rendering — anti-overfit guard (must cite competitors)
# ---------------------------------------------------------------------------


def test_render_report_includes_overall_youden():
    sc = BenchmarkScorecard()
    sc.per_category["sqli"] = CategoryScore(
        category="sqli", tp=5, fp=1, tn=9, fn=5,
    )
    md = render_report(sc, run_id="test_run")
    assert "Overall Youden index" in md
    assert "test_run" in md


def test_render_report_includes_published_competitor_scores():
    """Per iter-Q1 anti-overfit guards: every bench report must
    cite published competitor scores. Without this, the bench
    number is unmoored — operators can't tell if 'recall went up
    3pp' is good or terrible vs the field."""
    sc = BenchmarkScorecard()
    md = render_report(sc)
    for tool in (
        "Veracode", "Checkmarx", "Fortify", "ZAP", "SonarQube",
    ):
        assert tool in md, (
            f"report must cite {tool}'s published score per the "
            f"iter-Q1 anti-overfit guard"
        )


def test_render_report_per_category_table():
    sc = BenchmarkScorecard()
    sc.per_category["sqli"] = CategoryScore(
        category="sqli", tp=5, fp=1, tn=9, fn=5,
    )
    sc.per_category["xss"] = CategoryScore(
        category="xss", tp=8, fp=0, tn=12, fn=0,
    )
    md = render_report(sc)
    # Each category appears as a row.
    assert "| sqli |" in md
    assert "| xss |" in md
    # Headers present.
    assert "TP" in md and "FP" in md and "Youden" in md


def test_competitor_scores_are_documented_constants():
    """The published-competitor table must contain at least the
    4 commercial SAST tools the OWASP Benchmark Project ranks."""
    assert "Veracode" in PUBLISHED_COMPETITOR_SCORES_YOUDEN
    assert "Checkmarx" in PUBLISHED_COMPETITOR_SCORES_YOUDEN
    assert "Fortify" in PUBLISHED_COMPETITOR_SCORES_YOUDEN
    assert "SonarQube" in PUBLISHED_COMPETITOR_SCORES_YOUDEN
    # All scores between 0 and 1.
    for tool, score in PUBLISHED_COMPETITOR_SCORES_YOUDEN.items():
        assert 0.0 <= score <= 1.0, (
            f"{tool}: invalid Youden index {score}"
        )


# ---------------------------------------------------------------------------
# Anti-overfit guard — no fixture-specific identifiers in core scoring
# ---------------------------------------------------------------------------


def test_scoring_module_has_no_juiceshop_or_vampi_identifiers():
    """The scoring math module must be fixture-agnostic. Catches the
    case where someone tunes a heuristic for one specific bench."""
    src = (
        Path(__file__).parent.parent.parent.parent
        / "benchmarks" / "per_target" / "owasp_benchmark_scoring.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "juice-shop", "juiceshop", "bkimminich",
        "vampi", "erev0s", "crapi",
    ):
        assert forbidden not in src.lower(), (
            f"benchmarks/per_target/owasp_benchmark_scoring.py "
            f"contains fixture-specific identifier {forbidden!r} — "
            f"the scoring module must be fixture-agnostic."
        )
