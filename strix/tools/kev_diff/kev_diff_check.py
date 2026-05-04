"""CISA KEV proactive refresh + diff finding.

Today the KEV enrichment in #9 is reactive — it decorates existing
CVE findings if the CVE happens to be on the KEV catalog. This tool
makes it proactive: it forces a refresh of the local KEV cache,
compares the current catalog against a per-run snapshot, and emits
info findings for each NEW KEV entry that landed since the last
snapshot.

Useful for daily-running scans where each run highlights newly-
actively-exploited CVEs the customer should drop other priorities to
patch. CISA publishes new KEV entries roughly weekly; in any given
24-hour window there are usually 0-3 new entries.

Mechanism:

1. Force a KEV refresh via the existing
   `strix.telemetry.threat_intel.KevCatalog.refresh(force=True)`.
2. Read the prior snapshot from
   `~/.strix/kev_diff_snapshot.json` (the snapshot stores the set
   of CVE IDs from the catalog at the time of the last successful
   diff run — small file, ~200 KiB).
3. Compute the set diff:
   - **Added**: CVEs in the current catalog but not in the snapshot.
     Each emits an info finding with the full KEV metadata.
   - **Removed**: CVEs in the snapshot but not in the current
     catalog. Recorded in the result for the agent but doesn't emit
     a finding (CISA occasionally retires KEV entries; not
     immediately actionable).
4. Update the snapshot to the current catalog.

First run (no prior snapshot) is treated specially: emits zero
findings (we don't want to flag every existing KEV entry on first
use); just creates the snapshot for future runs. Use
`include_first_run_findings=True` to override (e.g. for one-shot
scans where the operator wants a baseline KEV report).

Findings:

- **Info** (CWE-1395, vulnerable_software) — per new KEV entry.
  Severity is info because the tool is informational about the
  catalog itself; downstream `cve_lookup` (#61) / `nvd_lookup`
  (#73) will surface the actual severity of each CVE.
  `verification_status=verified` (CISA KEV is authoritative).

The tracer's existing KEV enrichment (#9) auto-decorates each
finding with the full KEV record (added_at / due_date /
ransomware_use) since each finding carries a CVE ID.

Composes with cluster-A safety. The KEV fetch goes through
`strix.telemetry.threat_intel._fetch_json` (stdlib urllib), not
through the proxy chain, so `--exclude-path` doesn't apply (the URL
is CISA's, not the customer's).
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "kev_diff_check"
_DEFAULT_TIMEOUT = 30.0
_MAX_NEW_FINDINGS = 50  # Hard cap to avoid flooding on first-baseline runs.


# ---------------------------------------------------------------------------
# Snapshot persistence
# ---------------------------------------------------------------------------


def _snapshot_path() -> Path:
    """Path to the prior-run snapshot. Override-able via
    `STRIX_KEV_DIFF_SNAPSHOT` so tests / CI can use a different
    location."""
    override = os.environ.get("STRIX_KEV_DIFF_SNAPSHOT")
    if override:
        return Path(override)
    return Path.home() / ".strix" / "kev_diff_snapshot.json"


def _read_snapshot() -> dict[str, Any] | None:
    path = _snapshot_path()
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError, TypeError) as e:
        logger.debug("kev_diff snapshot read failed: %s", e)
    return None


def _write_snapshot(catalog_index: dict[str, dict[str, Any]]) -> None:
    """Write a compact snapshot — just the CVE-ID set + timestamp."""
    payload = {
        "snapshotted_at": int(time.time()),
        "cve_count": len(catalog_index),
        "cve_ids": sorted(catalog_index.keys()),
    }
    try:
        path = _snapshot_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
    except OSError as e:
        logger.debug("kev_diff snapshot write failed: %s", e)


# ---------------------------------------------------------------------------
# Catalog refresh
# ---------------------------------------------------------------------------


def _load_kev_catalog(force_refresh: bool):  # type: ignore[no-untyped-def]
    """Return (catalog, error_text). On error, catalog is None.

    Imports lazily so the tool registers cleanly even when the
    threat_intel module changes shape underneath us.
    """
    try:
        from strix.telemetry import threat_intel
    except Exception as e:  # noqa: BLE001
        return None, f"threat_intel import failed: {e}"
    try:
        catalog = threat_intel.get_default_catalog()
    except Exception as e:  # noqa: BLE001
        return None, f"KEV catalog accessor failed: {e}"
    try:
        ok = catalog.refresh(force=force_refresh)
    except Exception as e:  # noqa: BLE001
        return None, f"KEV refresh failed: {e}"
    if not ok or not catalog.loaded():
        return None, "KEV catalog refresh returned unsuccessful"
    return catalog, None


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    cve: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=title,
        severity="info",
        category="vulnerable_software",
        cwe="CWE-1395",
        cve=cve,
        target=cve,
        endpoint=f"cve://{cve}",
        description=description,
        impact=(
            "CISA KEV (Known Exploited Vulnerabilities) is the US "
            "government's authoritative list of CVEs being actively "
            "exploited in the wild. New KEV entries are the single "
            "highest-priority signal in vulnerability management — "
            "they carry CISA-mandated patch deadlines for federal "
            "agencies and represent confirmed exploitation activity. "
            "When a CVE that affects software in the customer's stack "
            "lands on KEV, every other vulnerability-management "
            "priority moves down the list."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="verified",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592.002", "T1588.006"],  # Software fingerprint + Obtain Vulns
)
def kev_diff_check(
    timeout: float = _DEFAULT_TIMEOUT,
    force_refresh: bool = True,
    include_first_run_findings: bool = False,
) -> dict[str, Any]:
    """Refresh the CISA KEV catalog and emit findings for new entries.

    Args:
        timeout: Underlying HTTP timeout (currently advisory — the
            KEV fetcher uses stdlib urllib with its own timeout).
        force_refresh: When True (default), forces a fresh KEV
            download regardless of the existing 24h cache. Set False
            to defer to whatever the cache has.
        include_first_run_findings: When True, the first run (no
            prior snapshot) will emit findings for ALL existing KEV
            entries (capped at 50 to avoid flooding). Default False
            — first run silently establishes the baseline.

    Returns:
        {
          success, total_kev_entries, snapshotted_cve_count,
          prior_snapshot_at, snapshot_updated,
          first_run: bool,
          new_entries: [{cve_id, vendor, product, vuln_name,
                         added_at, due_date, required_action,
                         ransomware_use}, ...],
          removed_entries: [cve_id, ...],
          findings_emitted, error?,
        }

    Findings:
        Per new KEV entry → info finding, CWE-1395, with the CVE
        attached so the tracer's existing KEV enrichment auto-
        decorates with the full record. `verification_status=
        verified`.

    Notes:
        - Snapshot stored at `~/.strix/kev_diff_snapshot.json`
          (override via `STRIX_KEV_DIFF_SNAPSHOT` env var). Just
          the sorted CVE-ID list + timestamp; small file.
        - First-run behaviour: silently baseline the snapshot, emit
          zero findings. Use `include_first_run_findings=True` to
          override (capped at 50 findings).
        - The tool reuses the existing KEV catalog from #9
          (`strix.telemetry.threat_intel`). Compose with the
          tracer's existing CVE → KEV auto-enrichment.
    """
    cev = _start_check("kev_diff", "cisa-kev")

    catalog, err = _load_kev_catalog(force_refresh=force_refresh)
    if err is not None or catalog is None:
        _complete_check(cev, "inconclusive", err or "KEV unavailable")
        return {
            "success": False,
            "error": err or "KEV catalog unavailable",
            "first_run": False,
            "new_entries": [],
            "removed_entries": [],
            "findings_emitted": 0,
        }

    # The catalog stores its index under `_index`. We treat it as
    # read-only here.
    index: dict[str, dict[str, Any]] = getattr(catalog, "_index", None) or {}
    current_cves: set[str] = set(index.keys())

    snapshot = _read_snapshot()
    first_run = snapshot is None
    prior_cves: set[str] = set(snapshot.get("cve_ids") or []) if snapshot else set()
    prior_snapshot_at: int | None = (
        int(snapshot.get("snapshotted_at"))
        if snapshot and isinstance(snapshot.get("snapshotted_at"), (int, float))
        else None
    )

    if first_run and not include_first_run_findings:
        # Silent baseline — write the snapshot, emit nothing.
        _write_snapshot(index)
        _complete_check(
            cev,
            result="not_vulnerable",
            evidence=f"first run; KEV baseline ({len(current_cves)} entries) snapshotted",
        )
        return {
            "success": True,
            "total_kev_entries": len(current_cves),
            "snapshotted_cve_count": len(current_cves),
            "prior_snapshot_at": None,
            "snapshot_updated": True,
            "first_run": True,
            "new_entries": [],
            "removed_entries": [],
            "findings_emitted": 0,
        }

    # Diff. On first run with include_first_run_findings=True, every
    # current CVE is "new".
    if first_run and include_first_run_findings:
        added = sorted(current_cves)
        removed: list[str] = []
    else:
        added = sorted(current_cves - prior_cves)
        removed = sorted(prior_cves - current_cves)

    # Emit findings for added entries (capped).
    findings_emitted = 0
    new_entries_records: list[dict[str, Any]] = []
    for cve in added[:_MAX_NEW_FINDINGS]:
        record = index.get(cve) or {}
        new_entries_records.append({
            "cve_id": cve,
            "vendor": record.get("vendor"),
            "product": record.get("product"),
            "vuln_name": record.get("vuln_name"),
            "added_at": record.get("added_at"),
            "due_date": record.get("due_date"),
            "required_action": record.get("required_action"),
            "ransomware_use": record.get("ransomware_use"),
        })
        title = (
            f"New CISA KEV entry: {cve} — "
            f"{record.get('vendor') or 'unknown vendor'} "
            f"{record.get('product') or ''}"
        ).strip()
        ransomware_text = (
            "Yes — observed in active ransomware campaigns."
            if str(record.get("ransomware_use") or "").lower() == "known"
            else "Not currently flagged for ransomware use."
        )
        description = (
            f"CISA added {cve} to the Known Exploited Vulnerabilities "
            f"catalog on {record.get('added_at')}. Required action by "
            f"{record.get('due_date')}: {record.get('required_action')}. "
            f"Affected: {record.get('vendor')}/{record.get('product')}. "
            f"Vulnerability: {record.get('vuln_name')}. "
            f"Ransomware use: {ransomware_text}"
        )
        description_plain = (
            "CISA — the US government cyber agency — added this CVE to "
            "their Known Exploited Vulnerabilities catalog since the "
            "last scan. KEV entries are the highest-priority "
            "vulnerability signal: they represent confirmed "
            "exploitation in the wild and carry CISA-mandated patch "
            f"deadlines for federal agencies. {ransomware_text}"
        )
        recommended_action = (
            f"Audit your stack for {record.get('vendor') or '(vendor)'}"
            f" {record.get('product') or '(product)'} — patch by "
            f"{record.get('due_date') or '(no deadline given)'} per "
            f"CISA's binding operational directive. Use `cve_lookup` "
            f"(#61) to confirm whether your detected versions are "
            f"vulnerable; use `exploit_refs` (#62) to find PoCs for "
            f"verification testing."
        )
        _emit_finding(
            title=title,
            cve=cve,
            description=description,
            description_plain=description_plain,
            recommended_action=recommended_action,
        )
        findings_emitted += 1

    # Always update the snapshot to the current catalog so the next
    # run picks up where this one left off.
    _write_snapshot(index)

    result_kind = "vulnerable" if findings_emitted else "not_vulnerable"
    _complete_check(
        cev,
        result=result_kind,
        evidence=(
            f"KEV diff: {len(added)} added, {len(removed)} removed; "
            f"{findings_emitted} finding(s) emitted"
        ),
    )
    return {
        "success": True,
        "total_kev_entries": len(current_cves),
        "snapshotted_cve_count": len(current_cves),
        "prior_snapshot_at": prior_snapshot_at,
        "snapshot_updated": True,
        "first_run": first_run,
        "new_entries": new_entries_records,
        "removed_entries": removed,
        "findings_emitted": findings_emitted,
    }
