"""iter-Q5.34 — WAVSEP scoring math (pure functions).

WAVSEP (Web Application Vulnerability Scanner Evaluation Project) is
the canonical neutral DAST corpus. Each test case is a JSP page with a
deterministic URL path; the fixture's `expected-cases.csv` carries the
ground truth (real vuln vs. false-positive shape).

Scoring follows the OWASP Benchmark Project convention so the two
DAST/SAST benches produce directly comparable Youden indices:

  For each (test_case, category) pair in expectations:
    TP  = real ∧ flagged
    FP  = NOT real ∧ flagged
    TN  = NOT real ∧ NOT flagged
    FN  = real ∧ NOT flagged

  TPR (recall) = TP / (TP + FN)
  FPR          = FP / (FP + TN)
  Precision    = TP / (TP + FP)
  F1           = 2 P R / (P + R)
  Youden index = TPR − FPR    # headline metric

Published competitor Youden indices on WAVSEP v1.5 (Shay Chen's
neutral DAST comparison, latest publicly-archived run):

    Acunetix:        87%
    Netsparker:      87%
    Burp Active Scan: 78%
    HP WebInspect:   76%
    IBM AppScan:     69%
    ZAP:             56%

These figures are SQL-injection + reflected XSS aggregates from
http://sectoolmarket.com — the most widely-cited DAST comparison
since 2014.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Category mapping — kept aligned with owasp_benchmark_scoring so the two
# DAST/SAST benches share CWE → category math.
# ---------------------------------------------------------------------------
WAVSEP_CATEGORIES: dict[str, set[str]] = {
    "sqli": {"CWE-89"},
    "xss": {"CWE-79"},
    "pathtraver": {"CWE-22", "CWE-98"},   # LFI maps to pathtraver
    "redirect": {"CWE-601"},
}


# Published competitor scores (Youden index, overall, from Shay Chen's
# WAVSEP comparison). Cited in the bench report per the iter-Q1
# anti-overfit guard (every L1 bench must cite competitor numbers).
PUBLISHED_COMPETITOR_SCORES_YOUDEN: dict[str, float] = {
    "Acunetix": 0.87,
    "Netsparker": 0.87,
    "Burp Active Scan": 0.78,
    "HP WebInspect": 0.76,
    "IBM AppScan": 0.69,
    "ZAP": 0.56,
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WavsepExpectation:
    """One row of expected-cases.csv — ground truth per test case."""
    url_path: str               # e.g. "/wavsep/active/SQL-Injection/.../Case01-...jsp"
    category: str               # e.g. "sqli"
    cwe: int                    # e.g. 89
    is_real_vulnerability: bool


@dataclass(frozen=True)
class WavsepFlag:
    """One strix finding mapped to a WAVSEP test case."""
    url_path: str
    category: str


@dataclass
class CategoryScore:
    """Per-category scorecard."""
    category: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def tpr(self) -> float:
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
class WavsepScorecard:
    per_category: dict[str, CategoryScore] = field(default_factory=dict)

    @property
    def overall(self) -> CategoryScore:
        agg = CategoryScore(category="OVERALL")
        for cs in self.per_category.values():
            agg.tp += cs.tp
            agg.fp += cs.fp
            agg.tn += cs.tn
            agg.fn += cs.fn
        return agg

    def to_dict(self) -> dict:
        return {
            "overall": self.overall.to_dict(),
            "per_category": {
                cat: cs.to_dict()
                for cat, cs in sorted(self.per_category.items())
            },
        }


# ---------------------------------------------------------------------------
# Pure scoring functions
# ---------------------------------------------------------------------------


def score(
    expectations: Iterable[WavsepExpectation],
    flags: Iterable[WavsepFlag],
) -> WavsepScorecard:
    """Score strix flags against WAVSEP expected-cases.

    Cross-category flags do NOT count against recall — each test case
    is scored only in its native category (mirrors OWASP Benchmark
    Project methodology).
    """
    flag_set: set[tuple[str, str]] = {
        (f.url_path, f.category) for f in flags
    }
    scorecard = WavsepScorecard()
    for exp in expectations:
        cs = scorecard.per_category.setdefault(
            exp.category, CategoryScore(category=exp.category),
        )
        is_flagged = (exp.url_path, exp.category) in flag_set
        if exp.is_real_vulnerability and is_flagged:
            cs.tp += 1
        elif exp.is_real_vulnerability and not is_flagged:
            cs.fn += 1
        elif not exp.is_real_vulnerability and is_flagged:
            cs.fp += 1
        else:
            cs.tn += 1
    return scorecard


def cwe_to_category(cwe: str | int | None) -> str | None:
    """Map a CWE id (e.g. 'CWE-89' / 89 / 'cwe-89') to its WAVSEP
    category. Returns None for CWEs outside the WAVSEP coverage."""
    if cwe is None:
        return None
    s = str(cwe).strip().upper()
    if not s.startswith("CWE-"):
        digits = "".join(c for c in s if c.isdigit())
        if not digits:
            return None
        s = f"CWE-{digits}"
    for cat, cwe_set in WAVSEP_CATEGORIES.items():
        if s in cwe_set:
            return cat
    return None


# ---------------------------------------------------------------------------
# CSV loader for expected-cases.csv
# ---------------------------------------------------------------------------


def load_expected_cases(csv_path: str) -> list[WavsepExpectation]:
    """Parse expected-cases.csv. Skips blank lines + comment lines
    (anything starting with `#` or `url_path` header)."""
    import csv

    out: list[WavsepExpectation] = []
    with open(csv_path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("url_path"):
                continue
            parts = next(csv.reader([line]))
            if len(parts) < 4:
                continue
            url_path = parts[0].strip()
            category = parts[1].strip().lower()
            is_real = parts[2].strip().lower() in ("true", "1", "yes")
            try:
                cwe = int(parts[3].strip())
            except (ValueError, IndexError):
                continue
            if category not in WAVSEP_CATEGORIES:
                continue
            out.append(WavsepExpectation(
                url_path=url_path,
                category=category,
                cwe=cwe,
                is_real_vulnerability=is_real,
            ))
    return out


# ---------------------------------------------------------------------------
# Strix findings → WAVSEP flags
# ---------------------------------------------------------------------------


def findings_to_flags(
    findings: Iterable[dict],
    expected_paths: Iterable[str],
) -> list[WavsepFlag]:
    """Map strix findings (vulnerability_reports entries) to
    WavsepFlag(url_path, category) by matching each finding's
    endpoint URL against the known `expected_paths` substrings.

    A finding matches a test case when the test case's `url_path` is a
    substring of any URL-like field in the finding (endpoint, target,
    description). The CWE is then mapped to a WAVSEP category. Findings
    that don't match any path OR have an unmapped CWE are dropped.

    Matching is intentionally substring-based (not equality) because
    strix may emit the path with or without query string, scheme, host,
    or trailing parameter info.
    """
    expected_list = [p for p in expected_paths if p]
    flags: list[WavsepFlag] = []
    for f in findings:
        candidates: list[str] = [
            str(f.get("endpoint") or ""),
            str(f.get("target") or ""),
            str(f.get("url") or ""),
            str(f.get("description") or "")[:1000],
            str(f.get("title") or ""),
        ]
        joined = " ".join(candidates)
        matched_path: str | None = None
        for path in expected_list:
            if path in joined:
                matched_path = path
                break
        if matched_path is None:
            continue
        category = cwe_to_category(f.get("cwe"))
        if category is None:
            continue
        flags.append(WavsepFlag(url_path=matched_path, category=category))
    # Deduplicate.
    return list({(f.url_path, f.category): f for f in flags}.values())


# ---------------------------------------------------------------------------
# Markdown report rendering
# ---------------------------------------------------------------------------


def render_report(
    scorecard: WavsepScorecard, *,
    run_id: str = "",
    wall_seconds: float | None = None,
    extra_metadata: dict | None = None,
) -> str:
    ov = scorecard.overall
    lines: list[str] = []
    lines.append(
        f"# WAVSEP — strix scorecard"
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

    lines.append("## Published competitor scores (Youden index)")
    lines.append("")
    lines.append("Source: Shay Chen WAVSEP comparison, sectoolmarket.com.")
    lines.append("")
    lines.append("| Tool | Youden index |")
    lines.append("|---|---:|")
    lines.append(f"| **strix (this run)** | **{ov.youden:.2%}** |")
    for tool, score_value in PUBLISHED_COMPETITOR_SCORES_YOUDEN.items():
        lines.append(f"| {tool} | {score_value:.2%} |")
    lines.append("")

    if extra_metadata:
        lines.append("## Metadata")
        lines.append("")
        for k, v in sorted(extra_metadata.items()):
            lines.append(f"- **{k}**: {v}")
        lines.append("")

    return "\n".join(lines)
