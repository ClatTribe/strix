"""IaC scanner — Phase 11.

Walk a repo, find IaC files, parse + run rules per file, return
an aggregate report. Mirrors `strix/sca/scanner.py`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from strix.iac.parsers.base import (
    IacFile,
    find_iac_files,
    parse_iac_file,
)
from strix.iac.rules import IacFinding, run_rules


logger = logging.getLogger(__name__)


@dataclass
class IacReport:
    """Aggregate IaC scan report."""
    repo_path: str
    files_scanned: list[str] = field(default_factory=list)
    files_by_platform: dict[str, int] = field(default_factory=dict)
    findings: list[IacFinding] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings
                   if (f.severity or "").lower() == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings
                   if (f.severity or "").lower() == "high")

    @property
    def findings_by_platform(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            p = f.platform or "unknown"
            out[p] = out.get(p, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "repo_path": self.repo_path,
            "files_scanned": list(self.files_scanned),
            "files_by_platform": dict(self.files_by_platform),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "findings_by_platform": self.findings_by_platform,
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }


def scan_iac_repo(
    repo_path: str | Path,
    *,
    max_files: int = 200,
) -> IacReport:
    """Walk `repo_path`, parse every recognised IaC file, run
    rules, return a report.

    No external CLI dependency in v1 — pure Python parsing +
    rules. Phase 11.2 (Checkov shell-out) plugs into this same
    pipeline as a separate rule source.
    """
    p = Path(repo_path)
    if not p.exists() or not p.is_dir():
        return IacReport(
            repo_path=str(p),
            errors=[{"type": "not_a_directory", "path": str(p)}],
        )

    files = find_iac_files(p, max_files=max_files)
    parsed: list[IacFile] = []
    by_platform: dict[str, int] = {}
    errors: list[dict] = []

    for fp in files:
        try:
            iac = parse_iac_file(fp)
        except Exception as e:  # noqa: BLE001
            errors.append({"file": str(fp), "error": str(e)})
            continue
        if iac is None:
            continue
        if iac.parse_error:
            errors.append({"file": str(fp), "error": iac.parse_error})
            # Still keep the file so rules see what we managed
            # to parse — partial structure may catch the error case.
        parsed.append(iac)
        by_platform[iac.platform] = by_platform.get(iac.platform, 0) + 1

    findings: list[IacFinding] = []
    for iac in parsed:
        try:
            findings.extend(run_rules(iac))
        except Exception as e:  # noqa: BLE001
            errors.append({"file": iac.path, "error": f"rule failure: {e}"})

    # Severity-descending sort so highest-priority findings surface first.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda f: -sev_rank.get((f.severity or "").lower(), 0))

    return IacReport(
        repo_path=str(p),
        files_scanned=[str(fp) for fp in files],
        files_by_platform=by_platform,
        findings=findings,
        errors=errors,
    )
