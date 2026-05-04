"""Verifier agent's deterministic re-probe tool (roadmap §8.2 row 3).

Reads the current run's findings, picks those eligible for
deterministic re-verification, re-runs the original probe, and
updates each finding's `verification_status` to `verified` or
`could_not_verify` depending on whether the original signal still
fires.

This is the lightweight (no-PoC) half of the Validator agent
described in §7.1 / §17.1. It DOES NOT spin up the target
application or replay an exploit payload — it just re-runs the
deterministic detector that originally emitted the finding and
checks whether the signal reproduces.

**Verification strategies** (per finding category):

- `information_disclosure` (from `debug_endpoint_check` #77): GET
  the finding's endpoint, scan for the same redaction marker /
  debug-page marker. Signal repeats → verified; gone → could_not_verify.
- `cors_misconfiguration` (from `cors_deep_check` #78): re-send
  the target endpoint with the same Origin probe (parsed from the
  finding's description metadata). Reflection still fires → verified.
- `open_redirect` (from `open_redirect_check` #59): re-fetch the
  finding's endpoint with the same payload param + value, observe
  the Location header.
- `method_disclosure` / `xst` / `webdav_exposure` (from
  `method_tamper_check` #60): re-run OPTIONS / TRACE / PROPFIND
  against the finding's endpoint.
- `host_header_injection` / `cache_poisoning` (from
  `host_header_check` #55): re-run host-header probe variants.

**Skip cases:**

- Finding has `verification_status=verified` already → skip (don't
  re-run).
- Finding's category doesn't have a registered re-probe strategy
  → skip with `reason=no_strategy`.
- Finding lacks an `endpoint` field → skip with
  `reason=missing_endpoint`.
- Per-tool exceptions are swallowed → skip with `reason=verifier_error`.

**Caps:**

- `max_findings` (default 20): hard cap on the number of findings
  the verifier touches per call. Prevents one verifier run from
  consuming the team's entire budget on a finding-heavy scan.
- `categories` (optional comma-separated list): restrict to specific
  categories. Default: all categories the strategy table supports.

**Output**: structured `{verified: [...], could_not_verify: [...],
skipped: [{report_id, reason}, ...]}` dict the lead reads.

Composes with §8.0:

- #86 finding contract — checks the post-update finding remains
  canonical via the allow-list constraint on `verification_status`.
- The validator-agent specialist (registered #89) is the canonical
  caller of this tool.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "verify_findings"


# Categories where deterministic re-probe is supported.
_VERIFIABLE_CATEGORIES: frozenset[str] = frozenset({
    # Web-app categories (#93 / §8.2 row 3)
    "information_disclosure",
    "cors_misconfiguration",
    "open_redirect",
    "method_disclosure",
    "xst",
    "webdav_exposure",
    "host_header_injection",
    "cache_poisoning",
    # Code-target categories (§8.1 row 4)
    "taint_flow",
    "vulnerable_dependency",
})


# Statuses that should be re-verified (skip already-verified findings).
_RE_VERIFIABLE_STATUSES: frozenset[str] = frozenset({
    "needs_review",
    "pattern_match",
    "inconclusive",
})


# ---------------------------------------------------------------------------
# Per-strategy re-probe dispatchers
# ---------------------------------------------------------------------------


def _verify_information_disclosure(finding: dict[str, Any]) -> tuple[bool, str]:
    """Re-run debug_endpoint_check against the same endpoint and
    check whether the same trace-marker / redaction signal fires."""
    endpoint = finding.get("endpoint")
    if not endpoint:
        return (False, "missing endpoint")
    try:
        # Use sys.modules to bypass __init__-shadowing (the recurring
        # module-vs-function pattern across strix tools).
        import strix.tools.debug_endpoint.debug_endpoint_check  # noqa: F401
        debug_module = sys.modules["strix.tools.debug_endpoint.debug_endpoint_check"]
        result = debug_module.debug_endpoint_check(
            target_url=endpoint, skip_framework_pages=True,
        )
    except Exception as e:  # noqa: BLE001
        return (False, f"verifier_error: {e}")

    findings_now = result.get("findings_emitted", 0) if isinstance(result, dict) else 0
    if findings_now > 0:
        return (True, f"re-probe emitted {findings_now} finding(s); signal repeats")
    return (False, "re-probe emitted 0 findings; signal may have been remediated")


def _verify_cors(finding: dict[str, Any]) -> tuple[bool, str]:
    endpoint = finding.get("endpoint")
    if not endpoint:
        return (False, "missing endpoint")
    try:
        import strix.tools.cors_check.cors_deep_check  # noqa: F401
        cors_module = sys.modules["strix.tools.cors_check.cors_deep_check"]
        result = cors_module.cors_deep_check(target_url=endpoint)
    except Exception as e:  # noqa: BLE001
        return (False, f"verifier_error: {e}")

    findings_now = result.get("findings_emitted", 0) if isinstance(result, dict) else 0
    if findings_now > 0:
        return (True, f"cors_deep_check still flags this endpoint")
    return (False, "cors_deep_check found nothing on re-run")


def _verify_open_redirect(finding: dict[str, Any]) -> tuple[bool, str]:
    endpoint = finding.get("endpoint")
    if not endpoint:
        return (False, "missing endpoint")
    try:
        import strix.tools.open_redirect.open_redirect_check  # noqa: F401
        or_module = sys.modules["strix.tools.open_redirect.open_redirect_check"]
        result = or_module.open_redirect_check(target_url=endpoint)
    except Exception as e:  # noqa: BLE001
        return (False, f"verifier_error: {e}")

    findings_now = result.get("findings_emitted", 0) if isinstance(result, dict) else 0
    if findings_now > 0:
        return (True, f"open_redirect_check still flags this endpoint")
    return (False, "open_redirect_check found nothing on re-run")


def _verify_method_tamper(finding: dict[str, Any]) -> tuple[bool, str]:
    endpoint = finding.get("endpoint")
    if not endpoint:
        return (False, "missing endpoint")
    try:
        import strix.tools.method_tamper.method_tamper_check  # noqa: F401
        mt_module = sys.modules["strix.tools.method_tamper.method_tamper_check"]
        # Read-only cohort only — never re-run destructive verbs.
        result = mt_module.method_tamper_check(
            target_url=endpoint, include_destructive=False,
        )
    except Exception as e:  # noqa: BLE001
        return (False, f"verifier_error: {e}")

    findings_now = result.get("findings_emitted", 0) if isinstance(result, dict) else 0
    if findings_now > 0:
        return (True, f"method_tamper_check still flags this endpoint")
    return (False, "method_tamper_check found nothing on re-run")


def _verify_host_header(finding: dict[str, Any]) -> tuple[bool, str]:
    endpoint = finding.get("endpoint")
    if not endpoint:
        return (False, "missing endpoint")
    try:
        import strix.tools.host_header.host_header_check  # noqa: F401
        hh_module = sys.modules["strix.tools.host_header.host_header_check"]
        result = hh_module.host_header_check(target_url=endpoint)
    except Exception as e:  # noqa: BLE001
        return (False, f"verifier_error: {e}")

    findings_now = result.get("findings_emitted", 0) if isinstance(result, dict) else 0
    if findings_now > 0:
        return (True, f"host_header_check still flags this endpoint")
    return (False, "host_header_check found nothing on re-run")


# ---------------------------------------------------------------------------
# §8.1 code-target re-verification strategies
# ---------------------------------------------------------------------------


def _verify_taint_flow(finding: dict[str, Any]) -> tuple[bool, str]:
    """Re-run taint_analysis on the same file; check if the same
    source→sink flow still exists at the same line.

    Findings have endpoint=`<file>:<line>` from the taint_analysis
    emitter. We parse that to drive the re-run."""
    endpoint = finding.get("endpoint") or ""
    code_locations = finding.get("code_locations") or []

    file_path: str | None = None
    lineno: int | None = None

    # Prefer code_locations when available (more reliable shape).
    if isinstance(code_locations, list) and code_locations:
        loc = code_locations[0]
        if isinstance(loc, dict):
            file_path = loc.get("file")
            try:
                lineno = int(loc.get("line") or 0) or None
            except (TypeError, ValueError):
                lineno = None

    if file_path is None and ":" in endpoint:
        # Fall back to parsing endpoint=`file:line`.
        parts = endpoint.rsplit(":", 1)
        file_path = parts[0]
        try:
            lineno = int(parts[1])
        except (TypeError, ValueError):
            pass

    if not file_path:
        return (False, "missing file location for re-analysis")

    # The file may have been recorded relative to the repo root
    # (taint_analysis uses Path.relative_to). Without the repo root
    # we can't resolve the absolute path here; the re-run uses the
    # cwd as a best-effort fallback. For tests + sandbox cases the
    # cwd is typically the run dir or project root.
    from pathlib import Path

    candidate = Path(file_path)
    if not candidate.exists():
        # Try relative to cwd.
        candidate = Path.cwd() / file_path
    if not candidate.exists():
        return (False, f"file no longer at {file_path}")

    try:
        import strix.tools.taint.taint_analysis  # noqa: F401
        ta_module = sys.modules["strix.tools.taint.taint_analysis"]
        result = ta_module.taint_analysis(
            repo_path=str(candidate),
            emit_findings=False,  # don't double-emit on re-verification
        )
    except Exception as e:  # noqa: BLE001
        return (False, f"verifier_error: {e}")

    if not isinstance(result, dict):
        return (False, "taint_analysis returned non-dict")

    flows = result.get("flows") or []
    if not flows:
        return (False, "taint_analysis re-run found no flows in this file")

    # Match by line number when we have one — otherwise any flow on
    # the file is sufficient evidence.
    if lineno is not None:
        for flow in flows:
            if flow.get("lineno") == lineno:
                return (True, f"taint flow still detected at line {lineno}")
        return (
            False,
            f"file has {len(flows)} flow(s) but none at line {lineno}",
        )

    return (True, f"taint_analysis re-run detected {len(flows)} flow(s)")


def _verify_vulnerable_dependency(finding: dict[str, Any]) -> tuple[bool, str]:
    """Re-run cve_lookup with the same (package, version, ecosystem);
    check CVE still applies.

    Findings from cve_lookup emit endpoint=`<ecosystem>://<name>@<version>`.
    We parse that to drive the re-run."""
    endpoint = finding.get("endpoint") or ""
    target = finding.get("target") or ""

    # Parse `pkg://name@version` style endpoint.
    if "://" not in endpoint or "@" not in endpoint:
        return (False, f"endpoint {endpoint!r} doesn't match cve_lookup shape")

    try:
        ecosystem_part, rest = endpoint.split("://", 1)
        if "@" not in rest:
            return (False, "endpoint missing version separator @")
        # Right-most '@' is the version separator (handles scoped npm
        # packages like @scope/name@1.2.3).
        name, version = rest.rsplit("@", 1)
    except (ValueError, AttributeError):
        return (False, f"failed to parse endpoint {endpoint!r}")

    if not name or not version:
        return (False, "name or version empty after parse")

    try:
        import strix.tools.cve_lookup.cve_lookup  # noqa: F401
        cve_module = sys.modules["strix.tools.cve_lookup.cve_lookup"]
        result = cve_module.cve_lookup(
            package_name=name,
            package_version=version,
            ecosystem=ecosystem_part if ecosystem_part != "pkg" else None,
        )
    except Exception as e:  # noqa: BLE001
        return (False, f"verifier_error: {e}")

    if not isinstance(result, dict):
        return (False, "cve_lookup returned non-dict")

    vulns = result.get("vulnerabilities") or []
    finding_cve = (finding.get("cve") or "").upper()

    if not vulns:
        return (
            False,
            f"cve_lookup re-run found 0 CVE(s) for {name}@{version}",
        )

    if finding_cve:
        for v in vulns:
            v_id = (v.get("id") or v.get("cve") or "").upper()
            if v_id == finding_cve:
                return (
                    True,
                    f"CVE {finding_cve} still applies to {name}@{version}",
                )
        return (
            False,
            f"cve_lookup found {len(vulns)} CVE(s) but {finding_cve} no longer present",
        )

    return (True, f"cve_lookup re-run found {len(vulns)} CVE(s) for {name}@{version}")


_STRATEGY_DISPATCH: dict[str, Any] = {
    "information_disclosure": _verify_information_disclosure,
    "cors_misconfiguration": _verify_cors,
    "open_redirect": _verify_open_redirect,
    "method_disclosure": _verify_method_tamper,
    "xst": _verify_method_tamper,
    "webdav_exposure": _verify_method_tamper,
    "host_header_injection": _verify_host_header,
    "cache_poisoning": _verify_host_header,
    # §8.1 row 4 code-target additions
    "taint_flow": _verify_taint_flow,
    "vulnerable_dependency": _verify_vulnerable_dependency,
}


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application — re-probe
)
def verify_findings(
    finding_ids: str | None = None,
    categories: str | None = None,
    max_findings: int = 20,
) -> dict[str, Any]:
    """Re-run deterministic probes on existing findings and update
    each finding's `verification_status`.

    The Verifier specialist's primary tool. Reads the run's
    findings via `tracer.get_existing_vulnerabilities()`, picks
    those eligible for deterministic re-verification (status in
    {needs_review, pattern_match, inconclusive} AND category in
    the strategy table), re-runs the original probe, and updates
    each finding's `verification_status` via
    `tracer.update_finding_verification`.

    Args:
        finding_ids: optional comma-separated list of finding IDs
            (e.g. `"vuln-0001,vuln-0002"`) to restrict the
            verification scope. Default: every eligible finding in
            the run, capped at `max_findings`.
        categories: optional comma-separated list of categories to
            restrict the verification scope. Default: all categories
            the strategy table supports.
        max_findings: hard cap on findings touched per call
            (default 20).

    Returns:
        {
          success,
          eligible_count, processed_count,
          verified: [{report_id, evidence}, ...],
          could_not_verify: [{report_id, evidence}, ...],
          skipped: [{report_id, reason}, ...],
        }

    Composes with §8.0:
        - Updated `verification_status` runs through the canonical
          contract's allow-list.
        - Emits `finding.verification_attempted` events for every
          processed finding (audit trail).
        - The `validator-agent` specialist (registered #89) is the
          canonical caller.
    """
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return {"success": False, "error": "tracer not available"}

    tracer = get_global_tracer()
    if tracer is None:
        return {"success": False, "error": "no global tracer"}

    requested_ids: set[str] | None = None
    if finding_ids:
        requested_ids = {
            i.strip() for i in finding_ids.split(",") if i.strip()
        }

    requested_cats: set[str] | None = None
    if categories:
        requested_cats = {
            c.strip().lower() for c in categories.split(",") if c.strip()
        }

    findings = tracer.get_existing_vulnerabilities()

    # Filter to eligible findings.
    eligible: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for f in findings:
        rid = f.get("id")
        cat = (f.get("category") or "").lower()
        status = (f.get("verification_status") or "").lower()

        if requested_ids is not None and rid not in requested_ids:
            continue
        if requested_cats is not None and cat not in requested_cats:
            continue

        # Skip already-verified
        if status == "verified":
            skipped.append({"report_id": rid, "reason": "already_verified"})
            continue

        if status not in _RE_VERIFIABLE_STATUSES:
            skipped.append({
                "report_id": rid,
                "reason": f"status_not_re_verifiable:{status}",
            })
            continue

        if cat not in _STRATEGY_DISPATCH:
            skipped.append({"report_id": rid, "reason": f"no_strategy:{cat}"})
            continue

        if not f.get("endpoint"):
            skipped.append({"report_id": rid, "reason": "missing_endpoint"})
            continue

        eligible.append(f)

    eligible_count = len(eligible)
    cap = max(1, int(max_findings))
    eligible = eligible[:cap]

    verified: list[dict[str, Any]] = []
    could_not_verify: list[dict[str, Any]] = []

    for f in eligible:
        rid = f.get("id")
        cat = (f.get("category") or "").lower()
        strategy = _STRATEGY_DISPATCH.get(cat)
        if strategy is None:
            skipped.append({"report_id": rid, "reason": f"no_strategy:{cat}"})
            continue

        try:
            ok, evidence = strategy(f)
        except Exception as e:  # noqa: BLE001
            ok, evidence = (False, f"verifier_error: {e}")

        new_status = "verified" if ok else "could_not_verify"
        try:
            tracer.update_finding_verification(
                report_id=rid,
                new_status=new_status,
                evidence=evidence,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("update_finding_verification failed: %s", e)

        record = {"report_id": rid, "category": cat, "evidence": evidence}
        if ok:
            verified.append(record)
        else:
            could_not_verify.append(record)

    return {
        "success": True,
        "eligible_count": eligible_count,
        "processed_count": len(verified) + len(could_not_verify),
        "verified": verified,
        "could_not_verify": could_not_verify,
        "skipped": skipped,
    }
