"""iter-Q1.3 — Vulhub CVE corpus scoring.

Pure math + report rendering for the L0/L1 CVE-corpus-freshness
bench. Loads the curated CVE list from `curated_cves.yaml`, accepts
per-CVE detection results (nuclei hit / miss), scores corpus
coverage with KEV + EPSS weights.

Why corpus freshness matters: nuclei templates drift behind upstream
CVE disclosures. A template missing for a high-EPSS CVE means strix's
L0/L1 layer can't detect it even if the bug is present. This bench
catches that gap before it shows up as a missed finding in
production.

Per `docs/proposals/2026-05-27-benchmark-suite-strategy.md`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CuratedCve:
    """One row from curated_cves.yaml."""
    cve_id: str
    name: str
    category: str             # rce / auth_bypass / sqli / etc.
    vintage: int              # year
    kev: bool                 # CISA Known Exploited Vulnerabilities catalog
    epss: float               # 0.0–1.0
    vulhub_path: str          # e.g. "log4j/CVE-2021-44228"
    target_path: str          # URL path to probe
    target_port: int          # exposed port from the lab
    expected_template: str    # nuclei template path


@dataclass(frozen=True)
class CveDetectionResult:
    """Per-CVE outcome from one bench run."""
    cve_id: str
    detected: bool            # nuclei flagged the expected_template
    nuclei_stdout: str = ""   # raw nuclei output for audit
    error: str | None = None  # set when the lab/scan failed (≠ a miss)


@dataclass
class CveCorpusScorecard:
    """Aggregate scorecard across the curated CVE set."""
    total: int = 0
    detected: int = 0
    missed: int = 0
    errored: int = 0          # lab failed to come up / scan timed out

    kev_total: int = 0
    kev_detected: int = 0

    by_category: dict[str, dict[str, int]] = field(default_factory=dict)
    by_vintage: dict[int, dict[str, int]] = field(default_factory=dict)

    detected_ids: list[str] = field(default_factory=list)
    missed_ids: list[str] = field(default_factory=list)
    errored_ids: list[str] = field(default_factory=list)

    # EPSS-weighted score — gives more weight to high-EPSS CVEs
    # (the ones most likely to be exploited in the wild).
    epss_weight_total: float = 0.0
    epss_weight_detected: float = 0.0

    @property
    def hit_rate(self) -> float:
        """Unweighted: detected / total (excluding errors)."""
        denom = self.total - self.errored
        return self.detected / denom if denom else 0.0

    @property
    def kev_hit_rate(self) -> float:
        """KEV-catalog-only hit rate. The most-critical subset —
        every miss here means we can't detect an actively-exploited
        vulnerability."""
        return self.kev_detected / self.kev_total if self.kev_total else 0.0

    @property
    def epss_weighted_score(self) -> float:
        """Each CVE contributes its EPSS as the weight of a hit.
        Same value as `hit_rate` when all EPSS are equal."""
        return (
            self.epss_weight_detected / self.epss_weight_total
            if self.epss_weight_total else 0.0
        )

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "detected": self.detected,
            "missed": self.missed,
            "errored": self.errored,
            "kev_total": self.kev_total,
            "kev_detected": self.kev_detected,
            "hit_rate": round(self.hit_rate, 4),
            "kev_hit_rate": round(self.kev_hit_rate, 4),
            "epss_weighted_score": round(self.epss_weighted_score, 4),
            "detected_ids": sorted(self.detected_ids),
            "missed_ids": sorted(self.missed_ids),
            "errored_ids": sorted(self.errored_ids),
            "by_category": self.by_category,
            "by_vintage": self.by_vintage,
        }


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


def load_curated_cves(yaml_path: str | Path) -> list[CuratedCve]:
    """Parse curated_cves.yaml into CuratedCve list. Defensive
    against missing fields — skip rows lacking required keys."""
    import yaml  # noqa: PLC0415

    with open(yaml_path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    rows = data.get("cves") or []
    out: list[CuratedCve] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            out.append(CuratedCve(
                cve_id=str(row["cve_id"]),
                name=str(row["name"]),
                category=str(row.get("category", "unknown")),
                vintage=int(row.get("vintage", 0)),
                kev=bool(row.get("kev", False)),
                epss=float(row.get("epss", 0.0)),
                vulhub_path=str(row.get("vulhub_path", "")),
                target_path=str(row.get("target_path", "/")),
                target_port=int(row.get("target_port", 80)),
                expected_template=str(row.get("expected_template", "")),
            ))
        except (KeyError, TypeError, ValueError):
            continue
    return out


# ---------------------------------------------------------------------------
# Detection-result inference from raw nuclei output
# ---------------------------------------------------------------------------


def nuclei_flagged_template(
    nuclei_stdout: str, expected_template: str,
) -> bool:
    """Return True when nuclei's stdout/json output references the
    expected template ID. Nuclei's JSON-line output includes a
    `template-id` field; the human-readable mode prefixes each
    finding with `[<template-id>]`. We accept either."""
    if not nuclei_stdout or not expected_template:
        return False
    # Extract bare template ID — strip `cves/2021/` prefix +
    # `.yaml` suffix.
    template_id = (
        Path(expected_template).stem
        if expected_template.endswith(".yaml")
        else expected_template
    )
    # Match either `[CVE-2021-44228]` (human-readable) or
    # `"template-id":"CVE-2021-44228"` (JSON-line).
    return (
        f"[{template_id}]" in nuclei_stdout
        or f'"template-id":"{template_id}"' in nuclei_stdout
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score(
    cves: Iterable[CuratedCve],
    results: Iterable[CveDetectionResult],
) -> CveCorpusScorecard:
    """Aggregate per-CVE results into the corpus scorecard.

    Detection result lookup is by cve_id — extra results (not in the
    cve list) are ignored; missing results are counted as errored
    (lab never ran).
    """
    cves_list = list(cves)
    by_id = {r.cve_id: r for r in results}

    sc = CveCorpusScorecard()
    sc.total = len(cves_list)

    for cve in cves_list:
        result = by_id.get(cve.cve_id)
        sc.epss_weight_total += cve.epss

        if cve.kev:
            sc.kev_total += 1

        # Bucket by category + vintage.
        cat = sc.by_category.setdefault(cve.category, {
            "total": 0, "detected": 0, "missed": 0, "errored": 0,
        })
        vin = sc.by_vintage.setdefault(cve.vintage, {
            "total": 0, "detected": 0, "missed": 0, "errored": 0,
        })
        cat["total"] += 1
        vin["total"] += 1

        if result is None or result.error:
            sc.errored += 1
            sc.errored_ids.append(cve.cve_id)
            cat["errored"] += 1
            vin["errored"] += 1
            continue

        if result.detected:
            sc.detected += 1
            sc.detected_ids.append(cve.cve_id)
            sc.epss_weight_detected += cve.epss
            cat["detected"] += 1
            vin["detected"] += 1
            if cve.kev:
                sc.kev_detected += 1
        else:
            sc.missed += 1
            sc.missed_ids.append(cve.cve_id)
            cat["missed"] += 1
            vin["missed"] += 1

    return sc


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def render_report(
    scorecard: CveCorpusScorecard, *,
    run_id: str = "",
    wall_seconds: float | None = None,
    extra_metadata: dict | None = None,
) -> str:
    """Render the corpus scorecard, emphasising the KEV miss list
    (the operationally-critical gap)."""
    lines: list[str] = []
    lines.append(
        f"# Vulhub CVE corpus — strix corpus-freshness scorecard"
        + (f" ({run_id})" if run_id else "")
    )
    lines.append("")
    lines.append(
        f"- **Hit rate**: {scorecard.hit_rate:.2%} "
        f"({scorecard.detected}/{scorecard.total - scorecard.errored})"
    )
    lines.append(
        f"- **KEV hit rate**: {scorecard.kev_hit_rate:.2%} "
        f"({scorecard.kev_detected}/{scorecard.kev_total})"
    )
    lines.append(
        f"- **EPSS-weighted score**: "
        f"{scorecard.epss_weighted_score:.2%}"
    )
    lines.append(f"- **Errored labs**: {scorecard.errored}")
    if wall_seconds is not None:
        lines.append(f"- **Wall time**: {wall_seconds:.1f}s")
    lines.append("")

    if scorecard.missed_ids:
        lines.append("## ⚠️ Missed CVEs (corpus freshness gap)")
        lines.append("")
        lines.append(
            "These CVEs have a public Vulhub lab + nuclei template "
            "but strix's L1 didn't detect them. **Each miss is a "
            "potential production gap** — update nuclei templates "
            "via `nuclei -ut` or investigate the wrapper."
        )
        lines.append("")
        for cve_id in scorecard.missed_ids:
            lines.append(f"- `{cve_id}`")
        lines.append("")

    if scorecard.errored_ids:
        lines.append("## Errored labs")
        lines.append("")
        lines.append(
            "Labs that failed to come up / scan timed out. Often "
            "transient (image pull / port conflict); rerun the bench."
        )
        lines.append("")
        for cve_id in scorecard.errored_ids:
            lines.append(f"- `{cve_id}`")
        lines.append("")

    # By-category breakdown.
    if scorecard.by_category:
        lines.append("## By category")
        lines.append("")
        lines.append("| Category | Total | Detected | Missed | Errored | Hit rate |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for cat, stats in sorted(scorecard.by_category.items()):
            denom = stats["total"] - stats["errored"]
            hr = (stats["detected"] / denom) if denom else 0.0
            lines.append(
                f"| {cat} | {stats['total']} | {stats['detected']} | "
                f"{stats['missed']} | {stats['errored']} | {hr:.2%} |"
            )
        lines.append("")

    # By-vintage breakdown — catches "great on 2017 CVEs, terrible
    # on 2024 CVEs" pattern.
    if scorecard.by_vintage:
        lines.append("## By vintage")
        lines.append("")
        lines.append("| Year | Total | Detected | Missed | Errored | Hit rate |")
        lines.append("|---:|---:|---:|---:|---:|---:|")
        for year, stats in sorted(scorecard.by_vintage.items()):
            denom = stats["total"] - stats["errored"]
            hr = (stats["detected"] / denom) if denom else 0.0
            lines.append(
                f"| {year} | {stats['total']} | {stats['detected']} | "
                f"{stats['missed']} | {stats['errored']} | {hr:.2%} |"
            )
        lines.append("")

    if extra_metadata:
        lines.append("## Metadata")
        lines.append("")
        for k, v in sorted(extra_metadata.items()):
            lines.append(f"- **{k}**: {v}")
        lines.append("")

    return "\n".join(lines)
