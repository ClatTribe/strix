"""iter-25.2 — root-cause collapse (Gap 5 in docs/L2-optimization.md).

Engineer sees 30 SAST findings of the same `strix-hardcoded-credential-
literal-python` rule across one repo and files **one** finding with
`occurrences: [30 locations]`. Not 30 separate findings. This module
makes the scanner behave the same way.

Collapse key = (rule_id, file_path, function_name).

Subsequent findings whose key matches a previously-emitted finding are
returned as ``CollapseDecision(action="skip_with_merge", target_id=...)``;
the caller (tracer hook) appends an ``occurrence`` block to the original
finding's ``occurrences[]`` instead of writing a new vulnerability row.

After ``N`` (default 8) collapses within the same `(rule_id, repo)`
the next collapse upgrades the parent finding to a "systemic-issue"
meta-finding with one tier of severity bump and a note in the
reasoning trace.

This is process-local state. The ledger lives for one scan run and is
keyed by ``(scan_id, rule_id, file, function)``. Tests reset the
ledger between cases via ``root_cause_ledger.clear()``.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any, Literal


logger = logging.getLogger(__name__)


_SYSTEMIC_THRESHOLD = 8


CollapseAction = Literal["emit", "skip_with_merge", "promote_systemic"]


@dataclass(frozen=True)
class CollapseDecision:
    """Outcome of the root-cause collapse check.

    * ``emit`` — first time we've seen this (rule, file, function) tuple
      this run; tracer writes the finding as-is and records the new
      parent id.
    * ``skip_with_merge`` — duplicate within the same tuple; tracer
      should NOT add a new row but should append an ``occurrence`` to
      the parent finding identified by ``target_id``.
    * ``promote_systemic`` — Nth duplicate within the same
      ``(rule_id, repo)`` family; tracer should bump the parent
      finding's severity one tier and append a "systemic issue"
      reasoning_trace line.
    """
    action: CollapseAction
    target_id: str | None = None
    occurrence: dict[str, Any] | None = None
    new_severity: str | None = None
    trace_line: str | None = None


@dataclass
class _ParentRecord:
    """Mutable state we keep about a coalesced finding."""
    finding_id: str
    rule_id: str
    repo_key: str
    occurrence_count: int = 1
    promoted_to_systemic: bool = False


_PROMOTE_TIER = {
    "info": "low",
    "informational": "low",
    "low": "medium",
    "medium": "high",
    "high": "critical",
    "critical": "critical",
}


def _repo_key(path: str | None) -> str:
    """First two path segments — close-enough proxy for repo root.

    The collapse threshold cares about "many hits in one codebase," not
    "many hits in one folder." Empty / no-path findings get ``""`` so
    they bucket together (unlikely to ever cross the threshold).
    """
    if not path:
        return ""
    p = path.replace("\\", "/").strip("/")
    parts = p.split("/")
    if len(parts) <= 2:
        return p
    return "/".join(parts[:2])


class RootCauseLedger:
    """Process-local ledger of `(rule_id, file, function)` → parent id.

    Thread-safe (single-process). Tracer calls ``check(finding)`` from
    inside ``add_vulnerability_report`` to decide what to do.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Tuple key → ParentRecord
        self._parents: dict[tuple[str, str, str], _ParentRecord] = {}
        # (rule_id, repo_key) → count
        self._repo_counts: dict[tuple[str, str], int] = {}

    def clear(self) -> None:
        with self._lock:
            self._parents.clear()
            self._repo_counts.clear()

    def check(
        self,
        finding: dict[str, Any],
        *,
        proposed_finding_id: str,
    ) -> CollapseDecision:
        """Decide whether this finding collapses into an existing one.

        Args:
            finding: the about-to-be-emitted vuln report dict.
            proposed_finding_id: the id the tracer would assign if it
                emits (used so the caller can persist the mapping).
        """
        try:
            rule_id = self._extract_rule_id(finding)
            if not rule_id:
                return CollapseDecision(action="emit")

            file_path = self._extract_file(finding)
            func_name = self._extract_function(finding)
            line_no = self._extract_line(finding)

            key = (rule_id, file_path or "", func_name or "")
            repo_k = (rule_id, _repo_key(file_path))

            with self._lock:
                parent = self._parents.get(key)
                if parent is None:
                    # First time we've seen this tuple — emit as parent.
                    self._parents[key] = _ParentRecord(
                        finding_id=proposed_finding_id,
                        rule_id=rule_id,
                        repo_key=_repo_key(file_path),
                    )
                    self._repo_counts[repo_k] = (
                        self._repo_counts.get(repo_k, 0) + 1
                    )
                    return CollapseDecision(action="emit")

                # Duplicate — coalesce.
                parent.occurrence_count += 1
                occurrence = {
                    "file": file_path,
                    "line": line_no,
                    "function": func_name,
                }
                # Strip Nones so the persisted JSON stays tidy.
                occurrence = {k: v for k, v in occurrence.items() if v}

                # Systemic promotion check on the FAMILY count.
                self._repo_counts[repo_k] = (
                    self._repo_counts.get(repo_k, 0) + 1
                )
                family_count = self._repo_counts[repo_k]
                if (
                    not parent.promoted_to_systemic
                    and family_count >= _SYSTEMIC_THRESHOLD
                ):
                    parent.promoted_to_systemic = True
                    sev = (finding.get("severity") or "").lower().strip()
                    new_sev = _PROMOTE_TIER.get(sev, sev)
                    return CollapseDecision(
                        action="promote_systemic",
                        target_id=parent.finding_id,
                        occurrence=occurrence,
                        new_severity=new_sev,
                        trace_line=(
                            f"l1.5: rule `{rule_id}` matched "
                            f"{family_count} locations in this repo "
                            f"family — promoted to systemic-issue, "
                            f"severity bumped to {new_sev}"
                        ),
                    )

                return CollapseDecision(
                    action="skip_with_merge",
                    target_id=parent.finding_id,
                    occurrence=occurrence,
                )
        except Exception as e:  # noqa: BLE001
            logger.debug("root_cause_ledger check failed: %s — emit", e)
            return CollapseDecision(action="emit")

    # ---------------- field extractors ----------------

    @staticmethod
    def _extract_rule_id(finding: dict[str, Any]) -> str | None:
        for key in ("rule_id", "rule", "check_id"):
            v = finding.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None

    @staticmethod
    def _extract_file(finding: dict[str, Any]) -> str | None:
        code_locs = finding.get("code_locations") or []
        if isinstance(code_locs, list) and code_locs:
            first = code_locs[0]
            if isinstance(first, dict):
                p = first.get("file") or first.get("path")
                if isinstance(p, str) and p.strip():
                    return p.strip()
        v = finding.get("file") or finding.get("path") or finding.get("target")
        return v.strip() if isinstance(v, str) and v.strip() else None

    @staticmethod
    def _extract_function(finding: dict[str, Any]) -> str | None:
        code_locs = finding.get("code_locations") or []
        if isinstance(code_locs, list) and code_locs:
            first = code_locs[0]
            if isinstance(first, dict):
                v = first.get("function") or first.get("symbol")
                if isinstance(v, str) and v.strip():
                    return v.strip()
        v = finding.get("function")
        return v.strip() if isinstance(v, str) and v.strip() else None

    @staticmethod
    def _extract_line(finding: dict[str, Any]) -> int | None:
        code_locs = finding.get("code_locations") or []
        if isinstance(code_locs, list) and code_locs:
            first = code_locs[0]
            if isinstance(first, dict):
                ln = first.get("line") or first.get("start_line")
                if isinstance(ln, int):
                    return ln
                if isinstance(ln, str) and ln.isdigit():
                    return int(ln)
        return None


# Module-level singleton — one ledger per scan process. Tests should
# call ``root_cause_ledger.clear()`` in a fixture.
root_cause_ledger = RootCauseLedger()
