"""iter-25.12 — `generate_remediation_plan`.

Closes the gap called out in `docs/l2-architecture-evaluation.md §4`:
the patcher specialist generates code patches, but there's no
human-readable remediation narrative for findings that can't be
auto-patched (infra/config issues, third-party-dep upgrades,
process-level fixes).

This tool reads `vulnerabilities.json` (the canonical finding set
after L1.5 has done its enrichment / collapse / join work) and emits
a markdown narrative grouped by:

  1. **Critical / Confirmed** — exploitability ≥ 0.8 OR
     verification_status=exploited OR corroborated_by ≥ 2 sources.
     Each gets a full "What / Why-it-matters / Fix / Verification"
     paragraph.

  2. **Systemic Issues** — root-cause-collapsed findings with
     ``promoted_to_systemic`` (one finding × N occurrences). Shows
     the count + sample occurrences + the one-fix-many-locations
     recommendation.

  3. **Hygiene** — missing-header / dev-banner / hygiene-prior
     contributors. Aggregated as a checklist, not per-finding.

  4. **Watch / Low confidence** — exploitability < 0.10 OR
     ``noise=True``. Listed as one-liners so the engineer can see
     they were considered + dismissed.

Three audiences are addressed by separate report variants
(`audience=` arg):
  * `developer` — code-level fix instructions, includes file:line
    + git-blame author for ownership routing
  * `ciso`     — risk roll-up with severity counts + business impact
  * `auditor`  — compliance-control mapping (CWE → SOC 2 / ISO 27001
    / PCI DSS / OWASP ASVS) — pulls from existing
    `emit_compliance_evidence` output if present

Output path defaults to `<run_dir>/remediation_plan.md`. Returns
the path on success.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


Audience = Literal["developer", "ciso", "auditor"]


# CWE → control mapping (audit variant). Same source as
# emit_compliance_evidence; kept minimal here to avoid coupling.
_CWE_TO_CONTROLS: dict[str, list[str]] = {
    "CWE-89": [
        "OWASP ASVS V5.3 (Sanitization)", "PCI DSS Req 6.2 (Secure Coding)",
    ],
    "CWE-79": [
        "OWASP ASVS V5.3.3 (XSS prevention)", "PCI DSS Req 6.2",
    ],
    "CWE-22": [
        "OWASP ASVS V12 (Files)", "PCI DSS Req 6.2",
    ],
    "CWE-78": ["OWASP ASVS V5.3", "PCI DSS Req 6.2"],
    "CWE-798": [
        "SOC 2 CC6.1 (Access Control)",
        "ISO 27001 A.8.20 (Key Management)",
        "OWASP ASVS V2 (Authentication)",
    ],
    "CWE-200": [
        "SOC 2 CC6.7 (Restricted Data Transmission)",
        "OWASP ASVS V8 (Data Protection)",
    ],
    "CWE-352": [
        "OWASP ASVS V4.2.2 (CSRF)", "PCI DSS Req 6.2",
    ],
    "CWE-639": [
        "OWASP ASVS V4 (Access Control)",
    ],
    "CWE-918": ["OWASP ASVS V12 (SSRF prevention)"],
    "CWE-502": [
        "OWASP ASVS V12 (Deserialization)", "ISO 27001 A.8.28",
    ],
    "CWE-319": [
        "ISO 27001 A.8.24 (Crypto)",
        "PCI DSS Req 4 (Encryption in Transit)",
    ],
}


# ----------------------- Finding classification -----------------------------

@dataclass
class Buckets:
    """Bucketed findings going into the report."""
    critical: list[dict] = field(default_factory=list)
    systemic: list[dict] = field(default_factory=list)
    hygiene: list[dict] = field(default_factory=list)
    watch: list[dict] = field(default_factory=list)


def _is_critical(f: dict) -> bool:
    if (f.get("verification_status") or "").lower() == "exploited":
        return True
    sev = (f.get("severity") or "").lower()
    if sev == "critical":
        return True
    expl = f.get("exploitability") or {}
    if isinstance(expl, dict):
        if (expl.get("composite") or 0.0) >= 0.80:
            return True
    cb = f.get("corroborated_by")
    if isinstance(cb, list) and len(cb) >= 2:
        return True
    return False


def _is_systemic(f: dict) -> bool:
    occs = f.get("occurrences") or []
    if isinstance(occs, list) and len(occs) >= 5:
        return True
    rt = f.get("reasoning_trace") or []
    if isinstance(rt, list):
        return any("systemic" in str(line).lower() for line in rt)
    return False


def _is_hygiene(f: dict) -> bool:
    sev = (f.get("severity") or "").lower()
    if sev in {"info", "informational"}:
        return True
    if f.get("role") == "corroborator":
        return True
    title = (f.get("title") or "").lower()
    if "missing" in title and ("header" in title or "csp" in title or "hsts" in title):
        return True
    return False


def _is_watch(f: dict) -> bool:
    if f.get("noise") is True:
        return True
    expl = f.get("exploitability") or {}
    if isinstance(expl, dict):
        comp = expl.get("composite")
        if isinstance(comp, (int, float)) and comp < 0.10:
            return True
    return False


def _bucket(findings: list[dict]) -> Buckets:
    b = Buckets()
    for f in findings:
        # Order matters: critical first, then watch (so noise demoted
        # findings don't end up in critical), then systemic, then hygiene
        if _is_critical(f):
            b.critical.append(f)
            continue
        if _is_watch(f):
            b.watch.append(f)
            continue
        if _is_systemic(f):
            b.systemic.append(f)
            continue
        if _is_hygiene(f):
            b.hygiene.append(f)
            continue
        # Default: critical bucket (anything we couldn't otherwise
        # classify gets the engineer's attention)
        b.critical.append(f)
    return b


# ----------------------- Rendering ------------------------------------------

def _fmt_critical(f: dict, audience: Audience) -> list[str]:
    out: list[str] = []
    title = f.get("title") or "(untitled)"
    sev = (f.get("severity") or "").upper()
    cwe = f.get("cwe") or ""
    target = f.get("endpoint") or f.get("target") or ""
    out.append(f"### {sev}: {title}")
    if cwe:
        out.append(f"- **CWE**: {cwe}")
    if target:
        out.append(f"- **Target**: `{target}`")

    if audience == "developer":
        code_locs = f.get("code_locations") or []
        if isinstance(code_locs, list) and code_locs:
            loc = code_locs[0]
            if isinstance(loc, dict):
                file = loc.get("file") or ""
                line = loc.get("line") or ""
                out.append(f"- **Location**: `{file}:{line}`")
        blame = f.get("git_blame")
        if isinstance(blame, dict):
            out.append(
                f"- **Authored**: {blame.get('author')} on "
                f"{blame.get('commit_date')} "
                f"({blame.get('days_since_change')} days ago) — "
                f"\"{blame.get('commit_subject')}\""
            )
        rem = f.get("recommended_action") or f.get("remediation_steps")
        if rem:
            out.append("- **Fix**:")
            out.append(f"  > {rem}")
        poc = f.get("poc_script_code")
        if poc:
            out.append("- **PoC** (for repro):")
            out.append("  ```")
            out.append("  " + poc.strip().replace("\n", "\n  "))
            out.append("  ```")

    elif audience == "ciso":
        impact = f.get("impact") or f.get("business_impact_plain")
        if impact:
            out.append(f"- **Business impact**: {impact}")
        kev = f.get("kev") or {}
        if isinstance(kev, dict) and kev.get("is_kev"):
            out.append("- ⚠️ **CISA KEV** — actively exploited in the wild")
        camp = f.get("campaigns") or {}
        if isinstance(camp, dict) and camp.get("matched_pulse_count", 0) > 0:
            out.append(
                f"- 🔥 **Active campaign**: "
                f"{camp.get('matched_pulse_count')} pulses across "
                f"{', '.join(camp.get('sources_seen') or [])}",
            )

    elif audience == "auditor":
        controls = _CWE_TO_CONTROLS.get(cwe.upper(), [])
        if controls:
            out.append("- **Controls**:")
            for c in controls:
                out.append(f"  - {c}")
        vstat = f.get("verification_status") or "inconclusive"
        out.append(f"- **Verification**: {vstat}")
    out.append("")
    return out


def _fmt_systemic(f: dict) -> list[str]:
    title = f.get("title") or "(systemic issue)"
    occs = f.get("occurrences") or []
    rule = f.get("rule_id") or ""
    locs = [
        f"`{o.get('file')}:{o.get('line', '')}`"
        for o in occs[:5] if isinstance(o, dict)
    ]
    extra = "" if len(occs) <= 5 else f" (and {len(occs) - 5} more)"
    return [
        f"### Systemic: {title}",
        f"- **Rule**: `{rule}`" if rule else "",
        f"- **Occurrences**: {len(occs) + 1} — {', '.join(locs)}{extra}",
        "- **Fix**: one root-cause change covers all locations.",
        "",
    ]


def _fmt_hygiene_checklist(findings: list[dict]) -> list[str]:
    if not findings:
        return []
    titles = sorted({(f.get("title") or "").strip() for f in findings})
    return [
        f"- [ ] {t}" for t in titles if t
    ]


def _fmt_watch_table(findings: list[dict]) -> list[str]:
    if not findings:
        return []
    rows = ["| Title | CWE | Reason |", "|---|---|---|"]
    for f in findings:
        title = (f.get("title") or "")[:60]
        cwe = f.get("cwe") or ""
        expl = f.get("exploitability") or {}
        reason = (
            expl.get("reason") if isinstance(expl, dict) else ""
        ) or "demoted by L1.5"
        rows.append(f"| {title} | {cwe} | {reason} |")
    return rows


def _render(buckets: Buckets, audience: Audience) -> str:
    out: list[str] = []
    out.append("# Strix Remediation Plan")
    out.append("")
    out.append(f"_Audience: **{audience}**_")
    out.append("")
    out.append(
        f"Summary: {len(buckets.critical)} critical, "
        f"{len(buckets.systemic)} systemic, "
        f"{len(buckets.hygiene)} hygiene, "
        f"{len(buckets.watch)} watch."
    )
    out.append("")

    if buckets.critical:
        out.append("## 1. Critical / Confirmed")
        out.append("")
        for f in buckets.critical:
            out.extend(_fmt_critical(f, audience))

    if buckets.systemic:
        out.append("## 2. Systemic Issues")
        out.append("")
        for f in buckets.systemic:
            out.extend(_fmt_systemic(f))

    if buckets.hygiene:
        out.append("## 3. Hygiene Checklist")
        out.append("")
        out.extend(_fmt_hygiene_checklist(buckets.hygiene))
        out.append("")

    if buckets.watch:
        out.append("## 4. Watch / Low Confidence")
        out.append("")
        out.append("These findings were demoted by L1.5 enrichment:")
        out.append("")
        out.extend(_fmt_watch_table(buckets.watch))
        out.append("")

    return "\n".join(line for line in out if line is not None)


def _default_findings_path() -> Path:
    run_dir = os.environ.get("STRIX_RUN_DIR")
    if run_dir:
        return Path(run_dir).expanduser() / "vulnerabilities.json"
    return Path.cwd() / "vulnerabilities.json"


def _default_output_path() -> Path:
    run_dir = os.environ.get("STRIX_RUN_DIR")
    if run_dir:
        return Path(run_dir).expanduser() / "remediation_plan.md"
    return Path.cwd() / "remediation_plan.md"


@register_tool(sandbox_execution=False)
def generate_remediation_plan(
    findings_path: str | None = None,
    output_path: str | None = None,
    audience: str = "developer",
) -> dict[str, Any]:
    """Generate a human-readable remediation narrative.

    Args:
        findings_path: path to `vulnerabilities.json`. Default:
            ``$STRIX_RUN_DIR/vulnerabilities.json`` or
            ``./vulnerabilities.json``.
        output_path: where to write the markdown. Default:
            sibling of findings_path named ``remediation_plan.md``.
        audience: one of ``developer`` (default), ``ciso``, ``auditor``.

    Returns:
        ``{success, status, path, total_findings, critical, systemic,
           hygiene, watch}``
    """
    in_path = (
        Path(findings_path).expanduser() if findings_path
        else _default_findings_path()
    )
    out_path = (
        Path(output_path).expanduser() if output_path
        else _default_output_path()
    )

    if audience not in ("developer", "ciso", "auditor"):
        return {
            "success": False, "status": "error",
            "reason": (
                f"audience must be one of developer/ciso/auditor, "
                f"got {audience!r}"
            ),
        }

    try:
        text = in_path.read_text(encoding="utf-8")
    except OSError as e:
        return {
            "success": False, "status": "error",
            "reason": f"could not read findings: {e}",
        }
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return {
            "success": False, "status": "error",
            "reason": f"invalid JSON: {e}",
        }

    findings: list[dict] = []
    if isinstance(data, list):
        findings = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        for key in ("vulnerability_reports", "findings", "reports"):
            v = data.get(key)
            if isinstance(v, list):
                findings = [d for d in v if isinstance(d, dict)]
                break

    if not findings:
        return {
            "success": True, "status": "partial",
            "reason": "no findings to render",
            "path": str(out_path), "total_findings": 0,
            "critical": 0, "systemic": 0, "hygiene": 0, "watch": 0,
        }

    buckets = _bucket(findings)
    rendered = _render(buckets, audience)  # type: ignore[arg-type]
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
    except OSError as e:
        return {
            "success": False, "status": "error",
            "reason": f"could not write output: {e}",
        }

    return {
        "success": True, "status": "ok",
        "path": str(out_path),
        "audience": audience,
        "total_findings": len(findings),
        "critical": len(buckets.critical),
        "systemic": len(buckets.systemic),
        "hygiene": len(buckets.hygiene),
        "watch": len(buckets.watch),
    }
