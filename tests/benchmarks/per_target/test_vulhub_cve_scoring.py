"""Tests for iter-Q1.3 — Vulhub CVE corpus scoring math.

Pins the corpus-freshness scoring logic. Critical because the bench's
non-zero exit (cron pager) depends on `kev_hit_rate < 0.90`; off-by-one
in that math silently silences production alerts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.per_target.vulhub_cve_scoring import (
    CuratedCve,
    CveCorpusScorecard,
    CveDetectionResult,
    load_curated_cves,
    nuclei_flagged_template,
    render_report,
    score,
)


# ---------------------------------------------------------------------------
# Fixture loader
# ---------------------------------------------------------------------------


def _cve(
    cve_id: str = "CVE-2021-44228",
    category: str = "rce",
    vintage: int = 2021,
    kev: bool = True,
    epss: float = 0.95,
    expected_template: str = "cves/2021/CVE-2021-44228.yaml",
) -> CuratedCve:
    return CuratedCve(
        cve_id=cve_id, name=cve_id, category=category, vintage=vintage,
        kev=kev, epss=epss,
        vulhub_path=f"foo/{cve_id}", target_path="/", target_port=8080,
        expected_template=expected_template,
    )


def test_load_curated_cves_parses_fixture():
    """The shipped curated_cves.yaml must load cleanly + have the
    expected number of entries."""
    yaml_path = (
        Path(__file__).parent.parent.parent.parent
        / "benchmarks" / "per_target" / "fixtures" / "web"
        / "vulhub-cve-corpus" / "curated_cves.yaml"
    )
    assert yaml_path.is_file(), f"missing fixture: {yaml_path}"
    cves = load_curated_cves(yaml_path)
    # Per the proposal: ~25 curated CVEs.
    assert 20 <= len(cves) <= 30, (
        f"expected ~25 curated CVEs; got {len(cves)}. Update either "
        f"the count or the proposal's stated target."
    )
    # Every entry has all required fields populated.
    for cve in cves:
        assert cve.cve_id.startswith("CVE-")
        assert cve.expected_template.startswith("cves/")
        assert 0.0 <= cve.epss <= 1.0
        assert 2014 <= cve.vintage <= 2030


def test_load_curated_cves_majority_kev():
    """The corpus should be majority-KEV — those are the
    operationally-critical CVEs."""
    yaml_path = (
        Path(__file__).parent.parent.parent.parent
        / "benchmarks" / "per_target" / "fixtures" / "web"
        / "vulhub-cve-corpus" / "curated_cves.yaml"
    )
    cves = load_curated_cves(yaml_path)
    kev_count = sum(1 for c in cves if c.kev)
    assert kev_count >= len(cves) * 0.7, (
        f"only {kev_count}/{len(cves)} entries are KEV-catalog. The "
        f"corpus should be majority-KEV to focus the bench on "
        f"actively-exploited CVEs."
    )


# ---------------------------------------------------------------------------
# Nuclei output parsing
# ---------------------------------------------------------------------------


def test_nuclei_flagged_template_jsonl_format():
    """nuclei -jsonl emits one JSON line per finding with
    `template-id` field."""
    stdout = (
        '{"template-id":"CVE-2021-44228","matcher-name":"jndi",'
        '"info":{"severity":"critical"}}\n'
    )
    assert nuclei_flagged_template(
        stdout, "cves/2021/CVE-2021-44228.yaml",
    ) is True


def test_nuclei_flagged_template_human_format():
    """nuclei (default mode) prints `[template-id]` per finding."""
    stdout = "[CVE-2021-44228] [critical] http://target:8983/solr/admin/cores\n"
    assert nuclei_flagged_template(
        stdout, "cves/2021/CVE-2021-44228.yaml",
    ) is True


def test_nuclei_flagged_template_no_match():
    """Stdout that doesn't reference the template is a miss."""
    stdout = "[generic-cve-detection] http://target/\n"
    assert nuclei_flagged_template(
        stdout, "cves/2021/CVE-2021-44228.yaml",
    ) is False


def test_nuclei_flagged_template_empty_inputs():
    """Empty stdout or empty template name → False, no crashes."""
    assert nuclei_flagged_template("", "cves/2021/CVE-2021-44228.yaml") is False
    assert nuclei_flagged_template("some output", "") is False


# ---------------------------------------------------------------------------
# Scoring math
# ---------------------------------------------------------------------------


def test_score_all_detected():
    cves = [
        _cve("CVE-2021-44228", kev=True, epss=0.97),
        _cve("CVE-2017-5638", kev=True, epss=0.95),
    ]
    results = [
        CveDetectionResult(cve_id="CVE-2021-44228", detected=True),
        CveDetectionResult(cve_id="CVE-2017-5638", detected=True),
    ]
    sc = score(cves, results)
    assert sc.detected == 2
    assert sc.missed == 0
    assert sc.errored == 0
    assert sc.hit_rate == 1.0
    assert sc.kev_hit_rate == 1.0
    assert sc.kev_total == 2
    assert sc.epss_weighted_score == 1.0


def test_score_partial_with_kev_miss():
    """The headline regression scenario: a KEV CVE missed.
    kev_hit_rate < 0.9 triggers the cron pager (exit code 1)."""
    cves = [
        _cve("CVE-A", kev=True, epss=0.95),
        _cve("CVE-B", kev=True, epss=0.95),
        _cve("CVE-C", kev=False, epss=0.5),
    ]
    results = [
        CveDetectionResult(cve_id="CVE-A", detected=True),
        CveDetectionResult(cve_id="CVE-B", detected=False),    # KEV miss
        CveDetectionResult(cve_id="CVE-C", detected=True),
    ]
    sc = score(cves, results)
    assert sc.hit_rate == 2 / 3
    assert sc.kev_hit_rate == 0.5
    assert "CVE-B" in sc.missed_ids


def test_score_errored_excluded_from_hit_rate():
    """Errored labs (compose-up failed) don't count toward hit rate
    — those are infrastructure issues, not coverage gaps."""
    cves = [
        _cve("CVE-A", kev=True),
        _cve("CVE-B", kev=True),
    ]
    results = [
        CveDetectionResult(cve_id="CVE-A", detected=True),
        CveDetectionResult(cve_id="CVE-B", detected=False, error="lab down"),
    ]
    sc = score(cves, results)
    assert sc.errored == 1
    assert sc.detected == 1
    # Hit rate denominator excludes errors.
    assert sc.hit_rate == 1.0
    # But KEV hit rate is over the full KEV set, errored or not?
    # We chose to count errors against KEV hit rate (a lab that
    # won't come up means we can't detect anyway).
    assert sc.kev_hit_rate == 0.5


def test_score_missing_result_treated_as_error():
    """A CVE in the list with no corresponding result → errored
    (defensive — better than silent omission)."""
    cves = [_cve("CVE-A"), _cve("CVE-B")]
    results = [CveDetectionResult(cve_id="CVE-A", detected=True)]
    sc = score(cves, results)
    assert sc.errored == 1
    assert "CVE-B" in sc.errored_ids


def test_score_epss_weighted():
    """High-EPSS CVEs contribute more to the weighted score."""
    cves = [
        _cve("CVE-A", epss=0.99),    # high
        _cve("CVE-B", epss=0.01),    # low
    ]
    # Detected only the high-EPSS one.
    results = [
        CveDetectionResult(cve_id="CVE-A", detected=True),
        CveDetectionResult(cve_id="CVE-B", detected=False),
    ]
    sc = score(cves, results)
    # Unweighted: 1/2 = 50%.
    assert sc.hit_rate == 0.5
    # Weighted: 0.99 / 1.0 = 99%.
    assert sc.epss_weighted_score == pytest.approx(0.99, abs=1e-3)


def test_score_by_category_breakdown():
    cves = [
        _cve("CVE-A", category="rce"),
        _cve("CVE-B", category="rce"),
        _cve("CVE-C", category="auth_bypass"),
    ]
    results = [
        CveDetectionResult(cve_id="CVE-A", detected=True),
        CveDetectionResult(cve_id="CVE-B", detected=False),
        CveDetectionResult(cve_id="CVE-C", detected=True),
    ]
    sc = score(cves, results)
    assert sc.by_category["rce"]["detected"] == 1
    assert sc.by_category["rce"]["missed"] == 1
    assert sc.by_category["auth_bypass"]["detected"] == 1


def test_score_by_vintage_breakdown():
    """Year breakdown catches 'great on old CVEs, terrible on new ones'."""
    cves = [
        _cve("CVE-A", vintage=2017),
        _cve("CVE-B", vintage=2024),
    ]
    results = [
        CveDetectionResult(cve_id="CVE-A", detected=True),
        CveDetectionResult(cve_id="CVE-B", detected=False),
    ]
    sc = score(cves, results)
    assert sc.by_vintage[2017]["detected"] == 1
    assert sc.by_vintage[2024]["missed"] == 1


def test_score_zero_division_safety():
    """Empty inputs → all rates 0, no crashes."""
    sc = score([], [])
    assert sc.hit_rate == 0.0
    assert sc.kev_hit_rate == 0.0
    assert sc.epss_weighted_score == 0.0


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def test_render_report_headline_includes_kev_hit_rate():
    cves = [_cve("CVE-A", kev=True)]
    results = [CveDetectionResult(cve_id="CVE-A", detected=True)]
    sc = score(cves, results)
    md = render_report(sc, run_id="test")
    assert "KEV hit rate" in md
    assert "EPSS-weighted" in md
    assert "100.00%" in md


def test_render_report_lists_missed_cves_as_alert():
    """Missed CVEs section must be present + tagged as a corpus
    freshness gap (the cron-pageable signal)."""
    cves = [_cve("CVE-A", kev=True)]
    results = [CveDetectionResult(cve_id="CVE-A", detected=False)]
    sc = score(cves, results)
    md = render_report(sc)
    assert "Missed CVEs" in md or "missed_ids" in md.lower()
    assert "CVE-A" in md
    # Frame as a gap — operators reading the report must know this
    # is actionable, not informational.
    assert (
        "gap" in md.lower()
        or "freshness" in md.lower()
        or "update" in md.lower()
    )


# ---------------------------------------------------------------------------
# Anti-overfit guard
# ---------------------------------------------------------------------------


def test_scoring_module_has_no_juiceshop_identifiers():
    src = (
        Path(__file__).parent.parent.parent.parent
        / "benchmarks" / "per_target" / "vulhub_cve_scoring.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "juice-shop", "juiceshop", "bkimminich", "webgoat",
        "vampi", "crapi", "erev0s",
    ):
        assert forbidden not in src.lower(), (
            f"vulhub_cve_scoring.py contains {forbidden!r} — must "
            f"stay fixture-agnostic at the scoring layer."
        )
