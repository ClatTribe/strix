"""iter-Q1.1 — OWASP Benchmark Project v1.2 scoring math.

Implements the canonical scoring methodology from
https://owasp.org/www-project-benchmark/ — pure functions over
(expected, found) sets. No I/O, no subprocess, no docker. The
side-effecting bench harness (`bench_owasp_benchmark.py`) composes
this module.

Scoring per the OWASP Benchmark Project methodology:

  For each (test_case, vulnerability_category) pair, compare:
    * `is_real_vulnerability` — from expectedresults-1.2.csv
    * `is_tool_flagged`       — did strix emit a finding for this test

  Then per CWE / overall:
    TP  = real ∧ flagged
    FP  = NOT real ∧ flagged
    TN  = NOT real ∧ NOT flagged
    FN  = real ∧ NOT flagged

    TPR (recall) = TP / (TP + FN)
    FPR          = FP / (FP + TN)
    Precision    = TP / (TP + FP)
    F1           = 2 * (P * R) / (P + R)
    Youden index = TPR − FPR    # bench's headline metric

Published competitor scores on OWASP Benchmark v1.2 (Youden index,
overall, from the OWASP Benchmark Project scorecard as of 2024):

    Veracode:    51%
    Checkmarx:   47%
    Fortify:     35%
    SonarQube:    6%
    ZAP:         13% (DAST mode)
    PMD:          0% (intentionally — pure lint, not security)

These are the comparison points strix's bench result should cite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# OWASP Benchmark Project canonical category names (v1.2)
# ---------------------------------------------------------------------------
# These are the CWE categories the BenchmarkJava test suite covers.
# Each test case is tagged with exactly one. Strix's detectors emit
# findings tagged with CWE-XX; we map CWE → category here.
OWASP_BENCHMARK_CATEGORIES: dict[str, set[str]] = {
    # cmdi — command injection (CWE-78)
    "cmdi": {"CWE-78"},
    # crypto — weak crypto algorithm (CWE-327)
    "crypto": {"CWE-327"},
    # hash — broken/risky hash function (CWE-328)
    "hash": {"CWE-328"},
    # ldapi — LDAP injection (CWE-90)
    "ldapi": {"CWE-90"},
    # pathtraver — path traversal (CWE-22)
    "pathtraver": {"CWE-22"},
    # securecookie — missing/insecure cookie attribute (CWE-614)
    "securecookie": {"CWE-614"},
    # sqli — SQL injection (CWE-89)
    "sqli": {"CWE-89"},
    # trustbound — trust boundary violation (CWE-501)
    "trustbound": {"CWE-501"},
    # weakrand — insufficiently random values (CWE-330)
    "weakrand": {"CWE-330"},
    # xpathi — XPath injection (CWE-643)
    "xpathi": {"CWE-643"},
    # xss — cross-site scripting (CWE-79)
    "xss": {"CWE-79"},
}


# Published competitor scores (Youden index, overall, OWASP Benchmark
# Project scorecard, 2024). Cited in the bench report.
PUBLISHED_COMPETITOR_SCORES_YOUDEN: dict[str, float] = {
    "Veracode": 0.51,
    "Checkmarx": 0.47,
    "Fortify": 0.35,
    "ZAP (DAST)": 0.13,
    "SonarQube": 0.06,
    "PMD (lint, not security)": 0.0,
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BenchmarkExpectation:
    """One row of expectedresults-1.2.csv — ground truth per test case."""
    test_name: str           # e.g. "BenchmarkTest00001"
    category: str            # e.g. "sqli" (one of OWASP_BENCHMARK_CATEGORIES)
    cwe: int                 # e.g. 89
    is_real_vulnerability: bool   # the test is intentionally vulnerable


@dataclass(frozen=True)
class StrixFlag:
    """One strix finding mapped to a BenchmarkJava test case.

    The harness matches strix's emitted findings to BenchmarkTestXXXXX
    test cases by URL path. Each finding becomes a flag (tool said
    this test is vulnerable in category X)."""
    test_name: str
    category: str            # mapped via CWE → OWASP_BENCHMARK_CATEGORIES


@dataclass
class CategoryScore:
    """Per-CWE-category scorecard."""
    category: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def tpr(self) -> float:
        """Recall / true positive rate."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.tpr
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def youden(self) -> float:
        """Youden index — the OWASP Benchmark Project headline metric.
        Equals TPR − FPR. Perfect = 1.0, random guess = 0.0,
        always-flag = 0.0, never-flag = 0.0."""
        return self.tpr - self.fpr

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "tp": self.tp, "fp": self.fp,
            "tn": self.tn, "fn": self.fn,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
            "youden": round(self.youden, 4),
        }


@dataclass
class BenchmarkScorecard:
    """Full per-CWE + overall scorecard."""
    per_category: dict[str, CategoryScore] = field(default_factory=dict)

    @property
    def overall(self) -> CategoryScore:
        """Aggregate TP/FP/TN/FN across all categories."""
        agg = CategoryScore(category="OVERALL")
        for cs in self.per_category.values():
            agg.tp += cs.tp
            agg.fp += cs.fp
            agg.tn += cs.tn
            agg.fn += cs.fn
        return agg

    def to_dict(self) -> dict:
        ov = self.overall
        return {
            "overall": ov.to_dict(),
            "per_category": {
                cat: cs.to_dict()
                for cat, cs in sorted(self.per_category.items())
            },
        }


# ---------------------------------------------------------------------------
# Pure scoring functions
# ---------------------------------------------------------------------------


def score(
    expectations: Iterable[BenchmarkExpectation],
    flags: Iterable[StrixFlag],
) -> BenchmarkScorecard:
    """Score strix flags against the BenchmarkJava expectedresults.

    For each (test_name, category) in expectations:
      * Was the test case real_vulnerability=True?
      * Did strix flag it for this category?
    → bucket into TP/FP/TN/FN.

    Note: a strix flag for category X on a test case whose ground-
    truth category is Y is a *false positive in category X*, not a
    miss on Y. Per OWASP Benchmark Project methodology, each test
    case is scored in its NATIVE category only — cross-category
    flags don't count against recall.

    Returns a per-category + overall scorecard.
    """
    # Index flags by (test_name, category) for O(1) lookup.
    flag_set: set[tuple[str, str]] = {
        (f.test_name, f.category) for f in flags
    }

    scorecard = BenchmarkScorecard()

    for exp in expectations:
        cs = scorecard.per_category.setdefault(
            exp.category, CategoryScore(category=exp.category),
        )
        is_flagged = (exp.test_name, exp.category) in flag_set
        if exp.is_real_vulnerability and is_flagged:
            cs.tp += 1
        elif exp.is_real_vulnerability and not is_flagged:
            cs.fn += 1
        elif not exp.is_real_vulnerability and is_flagged:
            cs.fp += 1
        else:  # not real ∧ not flagged
            cs.tn += 1

    return scorecard


def cwe_to_category(cwe: str | int | None) -> str | None:
    """Map a CWE id (e.g. 'CWE-89' / 89 / 'cwe-89') to its OWASP
    Benchmark category name (e.g. 'sqli'). Returns None for CWEs
    not covered by the benchmark."""
    if cwe is None:
        return None
    s = str(cwe).strip().upper()
    if not s.startswith("CWE-"):
        # Accept bare int or 'cwe-N'.
        digits = "".join(c for c in s if c.isdigit())
        if not digits:
            return None
        s = f"CWE-{digits}"
    for cat, cwe_set in OWASP_BENCHMARK_CATEGORIES.items():
        if s in cwe_set:
            return cat
    return None


# ---------------------------------------------------------------------------
# CSV loader for expectedresults-1.2.csv
# ---------------------------------------------------------------------------


def load_expected_results(csv_path: str) -> list[BenchmarkExpectation]:
    """Parse expectedresults-1.2.csv from the BenchmarkJava repo.

    File format (the leading `#` line is a header comment):
        # test name, category, real vulnerability, cwe, source
        BenchmarkTest00001, sqli, true, 89, test
        BenchmarkTest00002, xss, false, 79, test
        ...

    Returns a list of BenchmarkExpectation. Skips rows with unknown
    categories (defensive against benchmark version drift)."""
    import csv

    out: list[BenchmarkExpectation] = []
    with open(csv_path, encoding="utf-8") as fh:
        # Skip the leading `#` comment line if present.
        first = fh.readline()
        if not first.startswith("#"):
            fh.seek(0)
        reader = csv.reader(fh)
        for row in reader:
            if len(row) < 4:
                continue
            test_name = row[0].strip()
            category = row[1].strip().lower()
            is_real = row[2].strip().lower() in ("true", "1", "yes")
            try:
                cwe = int(row[3].strip())
            except (ValueError, IndexError):
                continue
            if category not in OWASP_BENCHMARK_CATEGORIES:
                continue
            out.append(BenchmarkExpectation(
                test_name=test_name,
                category=category,
                cwe=cwe,
                is_real_vulnerability=is_real,
            ))
    return out


# ---------------------------------------------------------------------------
# Strix findings → BenchmarkJava flags
# ---------------------------------------------------------------------------


def findings_to_flags(
    findings: Iterable[dict],
) -> list[StrixFlag]:
    """Map a list of strix findings (vulnerability_reports entries)
    to BenchmarkJava flags. Each finding's `endpoint` is parsed for
    a `BenchmarkTestNNNNN` segment; the `cwe` is mapped to a category.

    Findings without a matching test_name OR an unmapped CWE are
    DROPPED (they're findings strix made that don't correspond to a
    BenchmarkJava test case — e.g. it found a CORS misconfig on
    Tomcat itself, not on a BenchmarkTestXXXXX endpoint)."""
    import re

    test_name_re = re.compile(r"\bBenchmarkTest\d{5}\b")
    flags: list[StrixFlag] = []
    for f in findings:
        endpoint = f.get("endpoint") or f.get("target") or ""
        m = test_name_re.search(str(endpoint))
        if not m:
            continue
        test_name = m.group(0)
        category = cwe_to_category(f.get("cwe"))
        if category is None:
            continue
        flags.append(StrixFlag(test_name=test_name, category=category))
    # Deduplicate (same finding may emit twice with slight variants).
    return list({(f.test_name, f.category): f for f in flags}.values())


# ---------------------------------------------------------------------------
# Markdown report rendering
# ---------------------------------------------------------------------------


def render_report(
    scorecard: BenchmarkScorecard, *,
    run_id: str = "",
    wall_seconds: float | None = None,
    extra_metadata: dict | None = None,
) -> str:
    """Render the scorecard as a markdown report citing published
    competitor scores per the iter-Q1 anti-overfit guard."""
    ov = scorecard.overall
    lines: list[str] = []
    lines.append(
        f"# OWASP Benchmark v1.2 — strix scorecard"
        + (f" ({run_id})" if run_id else "")
    )
    lines.append("")
    lines.append(f"- **Overall Youden index**: {ov.youden:.2%}")
    lines.append(f"- **Overall TPR (recall)**: {ov.tpr:.2%}")
    lines.append(f"- **Overall FPR**: {ov.fpr:.2%}")
    lines.append(f"- **Overall F1**: {ov.f1:.2%}")
    if wall_seconds is not None:
        lines.append(f"- **Wall time**: {wall_seconds:.1f}s")
    lines.append("")

    # Per-category table.
    lines.append("## Per-category scorecard")
    lines.append("")
    lines.append(
        "| Category | TP | FP | TN | FN | Precision | Recall | F1 | Youden |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for cat, cs in sorted(scorecard.per_category.items()):
        lines.append(
            f"| {cat} | {cs.tp} | {cs.fp} | {cs.tn} | {cs.fn} | "
            f"{cs.precision:.2%} | {cs.tpr:.2%} | "
            f"{cs.f1:.2%} | **{cs.youden:.2%}** |"
        )
    lines.append("")

    # Competitor comparison (mandatory per iter-Q1 anti-overfit guards).
    lines.append("## Published competitor scores (Youden index)")
    lines.append("")
    lines.append("Source: OWASP Benchmark Project scorecard, 2024.")
    lines.append("")
    lines.append("| Tool | Youden index |")
    lines.append("|---|---:|")
    lines.append(f"| **strix (this run)** | **{ov.youden:.2%}** |")
    for tool, score in PUBLISHED_COMPETITOR_SCORES_YOUDEN.items():
        lines.append(f"| {tool} | {score:.2%} |")
    lines.append("")

    if extra_metadata:
        lines.append("## Metadata")
        lines.append("")
        for k, v in sorted(extra_metadata.items()):
            lines.append(f"- **{k}**: {v}")
        lines.append("")

    return "\n".join(lines)
