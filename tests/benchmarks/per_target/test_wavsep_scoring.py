"""iter-Q5.34 — tests for the pure-Python WAVSEP scoring module.

Mirrors `test_owasp_benchmark_scoring.py` so the two L1 benches share
testing conventions. No I/O, no subprocess, no docker.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.per_target.wavsep_scoring import (
    PUBLISHED_COMPETITOR_SCORES_YOUDEN,
    WAVSEP_CATEGORIES,
    CategoryScore,
    WavsepExpectation,
    WavsepFlag,
    WavsepScorecard,
    cwe_to_category,
    findings_to_flags,
    load_expected_cases,
    render_report,
    score,
)


# ---------------------------------------------------------------------------
# CategoryScore math
# ---------------------------------------------------------------------------


def test_category_score_perfect_recall():
    cs = CategoryScore("sqli", tp=10, fp=0, tn=10, fn=0)
    assert cs.tpr == 1.0
    assert cs.fpr == 0.0
    assert cs.precision == 1.0
    assert cs.f1 == 1.0
    assert cs.youden == 1.0


def test_category_score_always_flag():
    """Tool that flags everything: TPR=1 FPR=1 → Youden 0."""
    cs = CategoryScore("xss", tp=10, fp=10, tn=0, fn=0)
    assert cs.tpr == 1.0
    assert cs.fpr == 1.0
    assert cs.youden == 0.0


def test_category_score_never_flag():
    cs = CategoryScore("redirect", tp=0, fp=0, tn=10, fn=10)
    assert cs.tpr == 0.0
    assert cs.fpr == 0.0
    assert cs.youden == 0.0


def test_category_score_zero_division_safety():
    cs = CategoryScore("sqli")
    assert cs.tpr == 0.0
    assert cs.fpr == 0.0
    assert cs.precision == 0.0
    assert cs.f1 == 0.0
    assert cs.youden == 0.0


# ---------------------------------------------------------------------------
# score()
# ---------------------------------------------------------------------------


def _exp(path: str, cat: str, real: bool, cwe: int = 89) -> WavsepExpectation:
    return WavsepExpectation(
        url_path=path, category=cat, cwe=cwe, is_real_vulnerability=real,
    )


def test_score_perfect_run():
    exps = [
        _exp("/wavsep/active/sqli/Case01.jsp", "sqli", True),
        _exp("/wavsep/active/sqli/Case02.jsp", "sqli", True),
        _exp("/wavsep/passive/sqli/Case01.jsp", "sqli", False),
    ]
    flags = [
        WavsepFlag("/wavsep/active/sqli/Case01.jsp", "sqli"),
        WavsepFlag("/wavsep/active/sqli/Case02.jsp", "sqli"),
    ]
    sc = score(exps, flags)
    cs = sc.per_category["sqli"]
    assert cs.tp == 2
    assert cs.fp == 0
    assert cs.tn == 1
    assert cs.fn == 0
    assert cs.tpr == 1.0
    assert cs.fpr == 0.0
    assert cs.youden == 1.0


def test_score_false_positive():
    exps = [
        _exp("/wavsep/passive/sqli/CaseFP.jsp", "sqli", False),
    ]
    flags = [WavsepFlag("/wavsep/passive/sqli/CaseFP.jsp", "sqli")]
    sc = score(exps, flags)
    cs = sc.per_category["sqli"]
    assert cs.fp == 1
    assert cs.tn == 0
    assert cs.tpr == 0.0
    assert cs.fpr == 1.0


def test_score_cross_category_flags_dont_count_against_recall():
    """A flag for sqli on a test case whose ground-truth is xss
    doesn't count as detection of the xss vuln."""
    exps = [
        _exp("/wavsep/active/xss/Case01.jsp", "xss", True),
    ]
    flags = [
        WavsepFlag("/wavsep/active/xss/Case01.jsp", "sqli"),
    ]
    sc = score(exps, flags)
    cs = sc.per_category["xss"]
    assert cs.tp == 0
    assert cs.fn == 1


def test_score_aggregates_overall_correctly():
    exps = [
        _exp("/a/sqli/Case01.jsp", "sqli", True),
        _exp("/a/xss/Case01.jsp", "xss", True),
        _exp("/p/sqli/CaseFP.jsp", "sqli", False),
    ]
    flags = [
        WavsepFlag("/a/sqli/Case01.jsp", "sqli"),
        WavsepFlag("/a/xss/Case01.jsp", "xss"),
    ]
    sc = score(exps, flags)
    ov = sc.overall
    assert ov.tp == 2
    assert ov.tn == 1
    assert ov.fp == 0
    assert ov.fn == 0
    assert ov.youden == 1.0


# ---------------------------------------------------------------------------
# CWE → category mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cwe_in,expected_category", [
    ("CWE-89", "sqli"),
    ("89", "sqli"),
    (89, "sqli"),
    ("cwe-79", "xss"),
    ("CWE-22", "pathtraver"),
    ("CWE-98", "pathtraver"),   # LFI also maps to pathtraver
    ("CWE-601", "redirect"),
    ("CWE-999", None),           # Not in the WAVSEP coverage
    (None, None),
    ("invalid", None),
    ("CWE-", None),
])
def test_cwe_to_category_canonical_mapping(cwe_in, expected_category):
    assert cwe_to_category(cwe_in) == expected_category


def test_wavsep_categories_match_owasp_canonical_cwes():
    """sqli/xss/pathtraver must use the same CWE constants as the
    OWASP Benchmark scorer so per-CWE Youden indices are directly
    comparable between the two harnesses."""
    from benchmarks.per_target.owasp_benchmark_scoring import (
        OWASP_BENCHMARK_CATEGORIES,
    )
    for shared in ("sqli", "xss", "pathtraver"):
        assert (
            OWASP_BENCHMARK_CATEGORIES[shared]
            <= WAVSEP_CATEGORIES[shared]
        ), (
            f"WAVSEP scorer's {shared!r} CWE set must be a superset of "
            f"the OWASP Benchmark scorer's — otherwise the two benches "
            f"score the same CWE under different category names."
        )


# ---------------------------------------------------------------------------
# findings_to_flags — substring path matching
# ---------------------------------------------------------------------------


def test_findings_to_flags_matches_substring_in_endpoint():
    expected = [
        "/wavsep/active/sqli/Case01.jsp",
    ]
    findings = [
        {
            "endpoint":
                "http://host.docker.internal:8098/wavsep/active/sqli/Case01.jsp?id=1",
            "cwe": "CWE-89",
        },
    ]
    flags = findings_to_flags(findings, expected)
    assert len(flags) == 1
    assert flags[0].url_path == "/wavsep/active/sqli/Case01.jsp"
    assert flags[0].category == "sqli"


def test_findings_to_flags_drops_findings_without_path_match():
    expected = ["/wavsep/active/sqli/Case01.jsp"]
    findings = [
        {
            "endpoint": "http://host.docker.internal:8098/unrelated/page.html",
            "cwe": "CWE-89",
        },
    ]
    assert findings_to_flags(findings, expected) == []


def test_findings_to_flags_drops_findings_with_unmapped_cwe():
    expected = ["/wavsep/active/sqli/Case01.jsp"]
    findings = [
        {
            "endpoint": "http://x/wavsep/active/sqli/Case01.jsp",
            "cwe": "CWE-999",   # Not covered by WAVSEP categories
        },
    ]
    assert findings_to_flags(findings, expected) == []


def test_findings_to_flags_falls_back_to_description():
    expected = ["/wavsep/active/redirect/Case03.jsp"]
    findings = [
        {
            "endpoint": "",
            "description": (
                "Open redirect in /wavsep/active/redirect/Case03.jsp "
                "via the target query parameter"
            ),
            "cwe": "CWE-601",
        },
    ]
    flags = findings_to_flags(findings, expected)
    assert len(flags) == 1
    assert flags[0].category == "redirect"


def test_findings_to_flags_deduplicates():
    expected = ["/wavsep/active/sqli/Case01.jsp"]
    findings = [
        {
            "endpoint": "/wavsep/active/sqli/Case01.jsp",
            "cwe": "CWE-89",
        },
        {
            "endpoint": "/wavsep/active/sqli/Case01.jsp?other",
            "cwe": "CWE-89",
        },
    ]
    flags = findings_to_flags(findings, expected)
    assert len(flags) == 1


# ---------------------------------------------------------------------------
# load_expected_cases — CSV parser
# ---------------------------------------------------------------------------


def test_load_expected_cases_parses_canonical_format(tmp_path):
    csv = tmp_path / "expected.csv"
    csv.write_text(
        "# comment\n"
        "url_path,category,is_real_vulnerability,cwe\n"
        "/wavsep/a/sqli/Case01.jsp,sqli,true,89\n"
        "/wavsep/p/sqli/CaseFP.jsp,sqli,false,89\n"
        "/wavsep/a/xss/Case01.jsp,xss,True,79\n",
        encoding="utf-8",
    )
    expectations = load_expected_cases(str(csv))
    assert len(expectations) == 3
    sqli_real = next(e for e in expectations if e.is_real_vulnerability and e.category == "sqli")
    assert sqli_real.url_path == "/wavsep/a/sqli/Case01.jsp"


def test_load_expected_cases_skips_unknown_categories(tmp_path):
    csv = tmp_path / "expected.csv"
    csv.write_text(
        "url_path,category,is_real_vulnerability,cwe\n"
        "/wavsep/a/sqli/Case01.jsp,sqli,true,89\n"
        "/wavsep/a/unknown/Case01.jsp,unknown_category,true,999\n",
        encoding="utf-8",
    )
    expectations = load_expected_cases(str(csv))
    assert len(expectations) == 1
    assert expectations[0].category == "sqli"


def test_load_expected_cases_loads_shipped_fixture():
    """Smoke-test the shipped starter CSV at the canonical fixture
    path. Catches CSV-format breakage at PR time."""
    fixture = (
        Path(__file__).resolve().parents[3]
        / "benchmarks" / "per_target" / "fixtures" / "web" / "wavsep"
        / "expected-cases.csv"
    )
    assert fixture.is_file(), f"missing shipped fixture: {fixture}"
    expectations = load_expected_cases(str(fixture))
    assert len(expectations) >= 40, (
        f"shipped fixture should have a meaningful starter set "
        f"(got only {len(expectations)} rows)"
    )
    # Coverage check — starter set must touch all 4 WAVSEP categories.
    categories = {e.category for e in expectations}
    assert categories == set(WAVSEP_CATEGORIES.keys()), (
        f"shipped fixture must cover every WAVSEP category; "
        f"got {categories!r}"
    )
    # Mix of real + non-real (so the scorer exercises both TP/FP buckets).
    assert any(e.is_real_vulnerability for e in expectations)
    assert any(not e.is_real_vulnerability for e in expectations)


# ---------------------------------------------------------------------------
# render_report
# ---------------------------------------------------------------------------


def test_render_report_includes_overall_youden():
    sc = WavsepScorecard()
    sc.per_category["sqli"] = CategoryScore("sqli", tp=8, fp=1, tn=4, fn=2)
    md = render_report(sc, run_id="test")
    assert "Overall Youden index" in md
    assert "sqli" in md


def test_render_report_includes_published_competitor_scores():
    """Per iter-Q1 anti-overfit guard: every L1 bench report must cite
    published competitor numbers so reviewers can sanity-check the
    delta."""
    sc = WavsepScorecard()
    sc.per_category["sqli"] = CategoryScore("sqli", tp=1, fp=0, tn=0, fn=0)
    md = render_report(sc, run_id="x")
    for competitor in PUBLISHED_COMPETITOR_SCORES_YOUDEN:
        assert competitor in md, (
            f"render_report must cite {competitor!r} for comparison"
        )


# ---------------------------------------------------------------------------
# Anti-overfit guard — no fixture-specific identifiers
# ---------------------------------------------------------------------------


def test_scoring_module_has_no_fixture_identifiers():
    """The WAVSEP scoring module must be fixture-agnostic — no juice-
    shop / vampi / WebGoat identifiers, since those would point at
    cross-bench leakage."""
    src = (
        Path(__file__).resolve().parents[3]
        / "benchmarks" / "per_target" / "wavsep_scoring.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "juice-shop", "juiceshop", "bkimminich",
        "vampi", "erev0s", "crapi",
        "webgoat",
    ):
        assert forbidden not in src.lower(), (
            f"wavsep_scoring.py contains fixture-specific identifier "
            f"{forbidden!r} — the scoring module must be fixture-agnostic."
        )
