"""Deterministic false-positive pre-filter.

Step 1 of the recall-safe per-workflow-phase plan
(docs/proposals/2026-05-19-scan-mode-cost-optimization.md, v2). Sits
in the verification phase, BEFORE the LLM dedupe / verifier call.
Catches the structurally-noisy 50-70% of false positives with zero
LLM cost.

## Design discipline — recall-safe by construction

Every rule below was hand-checked against the must_find findings in
`benchmarks/per_target/fixtures/**/expected.yaml`. The discipline:

  * When in doubt, the rule ALLOWS. The LLM verifier is the
    authoritative judge; the pre-filter only short-circuits the
    *obviously* structural noise.
  * DROP verdicts fire only when the finding's own payload
    contradicts itself (e.g. empty PoC, out-of-scope target,
    duplicate request signature) — not on heuristic similarity.
  * DOWNGRADE verdicts fire when severity is clearly mis-claimed
    (e.g. banner-grab tagged CRITICAL). The finding still flows to
    the report, just at the corrected severity floor.

## Rule inventory (the eight that ship in v1)

  R1 — empty / placeholder PoC
       title or PoC contains no testable artifact → DROP
  R2 — speculation language without concrete PoC
       title contains "potential", "may", "possibly", etc. AND
       PoC < 20 chars → DROP
  R3 — out-of-scope target
       target host is not in scan_config["targets"] AND not a
       sub-resource of one → DROP
  R4 — vague target (no endpoint, just a bare domain)
       endpoint=None AND poc_script_code lacks an HTTP request →
       DROP
  R5 — duplicate request signature
       (method, endpoint, payload-hash) already emitted →
       DROP (exact dedupe, no LLM needed)
  R6 — severity / CWE-200 mismatch
       severity ∈ {critical, high} AND CWE-200 (info disclosure)
       AND poc text matches a banner-grab pattern → DOWNGRADE to
       `low`
  R7 — banner-grab tagged high-tier
       severity ∈ {critical, high} AND poc references only static
       headers (Server, X-Powered-By, X-AspNet-Version, etc.) →
       DOWNGRADE to `low`
  R8 — directory-listing-only without traversal
       title mentions directory listing AND no path-traversal
       payload in the PoC AND severity > medium → DOWNGRADE to
       `low`

## Kill switch

`STRIX_FP_FILTER_DISABLED=1` bypasses the entire filter. The
filter is opt-OUT (default-on) because every rule has been
validated against the must_find fixtures.

## Telemetry

Every fired rule (DROP or DOWNGRADE) emits an event keyed by rule
name into the tracer when one is available. Operators can see
which rules are doing the work via the run's events.jsonl.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


_HIGH_TIER = frozenset({"critical", "high"})

# Speculation tokens — when these appear in the title and the PoC
# is empty / trivial, the finding is a hunch, not a verified bug.
_SPECULATION_TOKENS = (
    "potential ", "potentially ", "may be ", "might be ",
    "possibly ", "could be ", "appears to ", "seems to ",
    "consider ", "investigate ", "review whether ",
)

# Patterns that suggest the PoC body is just a banner / header grab,
# not a real exploit. Matched case-insensitively.
_BANNER_HEADER_PATTERNS = (
    r"\bServer\s*:\s*",
    r"\bX-Powered-By\s*:\s*",
    r"\bX-AspNet-Version\s*:\s*",
    r"\bX-AspNetMvc-Version\s*:\s*",
    r"\bX-Generator\s*:\s*",
    r"\bX-Runtime\s*:\s*",
    r"\bVia\s*:\s*",
)

# CWE-200 family — generic info disclosure. When attached to a
# high/critical, the severity is almost always inflated.
_INFO_DISCLOSURE_CWE = frozenset({
    "CWE-200", "CWE-209", "CWE-538", "CWE-540", "CWE-548",
})

# Path-traversal-shaped tokens (R8 uses these to confirm the PoC
# actually demonstrates traversal vs just listing).
_TRAVERSAL_TOKENS = (
    "../", "..\\", "..%2f", "..%5c", "/etc/passwd",
    "%2e%2e", "%252e%252e",
)


@dataclass
class FPRuleResult:
    """One rule's verdict.

    Verdicts:
      ALLOW — the rule did not fire; finding flows downstream.
      DROP — the rule is confident this is noise; finding is
        suppressed. Caller should return a `success=False`
        rejection so the agent knows why.
      DOWNGRADE — the rule wants to lower severity but keep the
        finding. `new_severity` is the floor. The finding still
        ships to the report.
    """
    verdict: str  # ALLOW | DROP | DOWNGRADE
    rule: str
    reason: str
    new_severity: str | None = None


def _is_disabled() -> bool:
    return os.environ.get(
        "STRIX_FP_FILTER_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _norm(s: Any) -> str:
    """Lowercase + collapse whitespace for substring matching."""
    if not isinstance(s, str):
        return ""
    return re.sub(r"\s+", " ", s.strip().lower())


def _request_signature(finding: dict[str, Any]) -> str:
    """Stable hash of (method, endpoint, payload-shape). Used by R5
    to dedupe identical-request emissions without an LLM call.

    The payload-shape is a hash of the PoC body trimmed of
    whitespace + URL-prefix variance. Two findings with the same
    sig are *structurally* identical at the HTTP-request level —
    that's a true duplicate, not a similarity judgement.
    """
    method = _norm(finding.get("method") or "")
    endpoint = _norm(finding.get("endpoint") or "")
    poc = _norm(finding.get("poc_script_code") or "")
    poc_hash = hashlib.sha256(poc.encode("utf-8", errors="ignore")).hexdigest()[:16]
    base = f"{method}|{endpoint}|{poc_hash}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:24]


def _extract_host(value: str) -> str:
    """Best-effort host extraction from a URL / hostname / target
    string. Tolerant to bare hosts, schemes, ports, and trailing
    paths.

    Returns empty string for inputs that don't look URL-shaped
    (e.g. `src/app/auth.py:142` is a code-location target on a
    repository scan — not a host). The discipline: when we can't
    confidently extract a hostname, downstream rules should fall
    back to ALLOW rather than risk a false DROP.
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    raw = value.strip()
    has_scheme = "://" in raw
    if not has_scheme:
        # Look like a host only if the first path segment has a dot
        # (foo.example.com) or is a literal IP. Reject bare words
        # that look like local paths.
        head = raw.split("/", 1)[0]
        head_no_port = head.split(":", 1)[0]
        looks_like_host = (
            "." in head_no_port
            or head_no_port.replace(".", "").isdigit()  # IPv4-ish
        )
        if not looks_like_host:
            return ""
        raw = "http://" + raw
    try:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
        return host
    except Exception:  # noqa: BLE001
        return ""


def _scope_hosts(scope_targets: list[Any] | None) -> set[str]:
    """Normalize scan_config["targets"] entries to a set of
    hostnames. Targets come in mixed shapes:
      - {"original": "https://x.example.com:8443/api"}
      - {"value": "...", "type": "web_application"}
      - bare strings
    """
    hosts: set[str] = set()
    for t in scope_targets or []:
        if isinstance(t, dict):
            for k in ("original", "value", "details", "target", "url"):
                v = t.get(k)
                if isinstance(v, str):
                    h = _extract_host(v)
                    if h:
                        hosts.add(h)
                        break
        elif isinstance(t, str):
            h = _extract_host(t)
            if h:
                hosts.add(h)
    return hosts


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def rule_empty_poc(finding: dict[str, Any]) -> FPRuleResult:
    """R1 — drop findings with no usable PoC body."""
    poc = finding.get("poc_script_code") or ""
    if not isinstance(poc, str) or len(poc.strip()) < 5:
        return FPRuleResult(
            verdict="DROP", rule="R1_empty_poc",
            reason="poc_script_code missing or trivial (<5 chars)",
        )
    return FPRuleResult(verdict="ALLOW", rule="R1_empty_poc", reason="")


def rule_speculation_title(finding: dict[str, Any]) -> FPRuleResult:
    """R2 — drop hedging-titled findings without a substantial PoC.

    Real findings have concrete PoCs. "Potential SQLi on /login" +
    a 10-character PoC is a hunch, not a finding.
    """
    title = _norm(finding.get("title"))
    poc = finding.get("poc_script_code") or ""
    if any(tok in title for tok in _SPECULATION_TOKENS):
        if not isinstance(poc, str) or len(poc.strip()) < 20:
            return FPRuleResult(
                verdict="DROP", rule="R2_speculation_no_poc",
                reason="hedging title + PoC < 20 chars; this is a hunch, not a finding",
            )
    return FPRuleResult(verdict="ALLOW", rule="R2_speculation_no_poc", reason="")


def rule_out_of_scope(
    finding: dict[str, Any],
    *,
    scope_hosts: set[str],
) -> FPRuleResult:
    """R3 — drop findings whose target host is not in scope.

    Conservative: if scope_hosts is empty (no scan_config yet),
    we ALLOW — we can't know what's in scope so we don't gate.
    """
    if not scope_hosts:
        return FPRuleResult(verdict="ALLOW", rule="R3_out_of_scope", reason="")
    target = finding.get("target") or ""
    endpoint = finding.get("endpoint") or ""
    finding_hosts = {
        h for h in (_extract_host(target), _extract_host(endpoint))
        if h
    }
    if not finding_hosts:
        # Can't determine host — treat as in-scope rather than risk
        # dropping a legitimate finding whose target field is
        # non-URL (e.g. local code paths).
        return FPRuleResult(verdict="ALLOW", rule="R3_out_of_scope", reason="")
    # In-scope if any finding host equals a scope host OR is a
    # subdomain of one.
    for fh in finding_hosts:
        for sh in scope_hosts:
            if fh == sh or fh.endswith("." + sh):
                return FPRuleResult(
                    verdict="ALLOW", rule="R3_out_of_scope", reason="",
                )
    return FPRuleResult(
        verdict="DROP", rule="R3_out_of_scope",
        reason=(
            f"target host(s) {sorted(finding_hosts)} not in scope "
            f"{sorted(scope_hosts)}"
        ),
    )


def rule_vague_target(finding: dict[str, Any]) -> FPRuleResult:
    """R4 — drop findings with no endpoint AND no HTTP-shaped PoC.

    Findings need a concrete target — either an `endpoint` field
    or an HTTP request embedded in the PoC. A bare-domain
    `target` with neither is too vague to act on.
    """
    endpoint = (finding.get("endpoint") or "").strip()
    if endpoint:
        return FPRuleResult(verdict="ALLOW", rule="R4_vague_target", reason="")
    poc = finding.get("poc_script_code") or ""
    poc_norm = _norm(poc)
    has_http_shape = (
        " /" in poc_norm                 # path-only request line
        or "http://" in poc_norm
        or "https://" in poc_norm
        or "curl " in poc_norm
        or "requests." in poc_norm       # python requests lib
        or "fetch(" in poc_norm
    )
    if not has_http_shape:
        return FPRuleResult(
            verdict="DROP", rule="R4_vague_target",
            reason="no endpoint field and PoC has no HTTP request shape",
        )
    return FPRuleResult(verdict="ALLOW", rule="R4_vague_target", reason="")


def rule_duplicate_request_signature(
    finding: dict[str, Any],
    *,
    existing_signatures: set[str],
) -> FPRuleResult:
    """R5 — exact-request dedupe. No LLM call needed when the
    (method, endpoint, payload-hash) tuple is identical."""
    sig = _request_signature(finding)
    if sig in existing_signatures:
        return FPRuleResult(
            verdict="DROP", rule="R5_duplicate_request_signature",
            reason=(
                f"finding with same (method, endpoint, payload-hash) "
                f"signature already emitted (sig={sig[:12]})"
            ),
        )
    return FPRuleResult(
        verdict="ALLOW", rule="R5_duplicate_request_signature", reason="",
    )


def _looks_like_banner_grab(text: str) -> bool:
    if not text:
        return False
    for pat in _BANNER_HEADER_PATTERNS:
        if re.search(pat, text, flags=re.IGNORECASE):
            return True
    return False


def rule_severity_cwe_mismatch(
    finding: dict[str, Any],
    *,
    severity: str,
) -> FPRuleResult:
    """R6 — downgrade high/critical findings tagged with a CWE-200
    family code AND a banner-grab-shaped PoC.

    Critical means RCE / dataloss / privesc. Banner disclosure is
    `low`. This rule corrects the inflation without dropping.
    """
    if severity.lower() not in _HIGH_TIER:
        return FPRuleResult(verdict="ALLOW", rule="R6_severity_cwe_mismatch", reason="")
    cwe = (finding.get("cwe") or "").strip().upper()
    if not any(code in cwe for code in _INFO_DISCLOSURE_CWE):
        return FPRuleResult(verdict="ALLOW", rule="R6_severity_cwe_mismatch", reason="")
    body = " ".join([
        finding.get("technical_analysis") or "",
        finding.get("poc_description") or "",
        finding.get("poc_script_code") or "",
    ])
    if _looks_like_banner_grab(body):
        return FPRuleResult(
            verdict="DOWNGRADE", rule="R6_severity_cwe_mismatch",
            reason=(
                f"severity={severity} + CWE-200-family + banner-grab PoC; "
                "info disclosure of static headers is low severity"
            ),
            new_severity="low",
        )
    return FPRuleResult(verdict="ALLOW", rule="R6_severity_cwe_mismatch", reason="")


def rule_banner_grab_high_tier(
    finding: dict[str, Any],
    *,
    severity: str,
) -> FPRuleResult:
    """R7 — downgrade high/critical findings whose entire PoC
    body is a static-header reveal. Distinct from R6 because R7
    fires regardless of CWE — covers the cases where the agent
    skipped the CWE tag entirely."""
    if severity.lower() not in _HIGH_TIER:
        return FPRuleResult(verdict="ALLOW", rule="R7_banner_grab_high_tier", reason="")
    body = " ".join([
        finding.get("technical_analysis") or "",
        finding.get("poc_description") or "",
        finding.get("poc_script_code") or "",
    ])
    if not _looks_like_banner_grab(body):
        return FPRuleResult(verdict="ALLOW", rule="R7_banner_grab_high_tier", reason="")
    # Sanity check: if the PoC mentions a payload that *isn't* a
    # static header (e.g. an actual injection string), don't fire
    # because the banner-grab might be incidental.
    body_norm = _norm(body)
    exploit_signals = (
        "' or '", "select ", "<script", "$(", "${", "../",
        "0x", "%00", "<?xml", "<!doctype", "$ne", "$where",
    )
    if any(sig in body_norm for sig in exploit_signals):
        return FPRuleResult(verdict="ALLOW", rule="R7_banner_grab_high_tier", reason="")
    return FPRuleResult(
        verdict="DOWNGRADE", rule="R7_banner_grab_high_tier",
        reason=(
            f"severity={severity} + PoC body matches banner-grab pattern "
            "without exploit signals; static header disclosure is low severity"
        ),
        new_severity="low",
    )


def rule_directory_listing_only(
    finding: dict[str, Any],
    *,
    severity: str,
) -> FPRuleResult:
    """R8 — downgrade directory-listing findings that don't
    demonstrate path traversal. Open directory listing is
    `low`/`info` unless paired with traversal."""
    if severity.lower() not in (_HIGH_TIER | {"medium"}):
        return FPRuleResult(verdict="ALLOW", rule="R8_directory_listing_only", reason="")
    title = _norm(finding.get("title"))
    if "directory listing" not in title and "directory index" not in title:
        return FPRuleResult(verdict="ALLOW", rule="R8_directory_listing_only", reason="")
    body = " ".join([
        finding.get("poc_description") or "",
        finding.get("poc_script_code") or "",
        finding.get("technical_analysis") or "",
    ]).lower()
    if any(tok in body for tok in _TRAVERSAL_TOKENS):
        # Listing + traversal in PoC → real path-traversal severity
        # is justified; don't downgrade.
        return FPRuleResult(verdict="ALLOW", rule="R8_directory_listing_only", reason="")
    return FPRuleResult(
        verdict="DOWNGRADE", rule="R8_directory_listing_only",
        reason=(
            "directory-listing title without traversal in PoC; "
            "open listing alone is low severity"
        ),
        new_severity="low",
    )


# ---------------------------------------------------------------------------
# Aggregate entry point
# ---------------------------------------------------------------------------


def evaluate(
    finding: dict[str, Any],
    *,
    severity: str,
    scope_targets: list[Any] | None = None,
    existing_findings: list[dict[str, Any]] | None = None,
) -> FPRuleResult:
    """Run every rule against the finding. Return the strongest
    verdict (DROP > DOWNGRADE > ALLOW); the first DROP wins;
    multiple DOWNGRADEs collapse to the lowest severity.

    Args:
      finding: the candidate finding dict (the same shape passed
        to `create_vulnerability_report`).
      severity: post-CVSS severity string (e.g. "high"). The agent
        emits CVSS; the caller has already computed severity from
        it before calling the filter.
      scope_targets: scan_config["targets"] entries. Used by R3.
      existing_findings: the tracer's prior `vulnerability_reports`
        list. Used by R5 (request-signature dedupe).

    Returns:
      A single FPRuleResult. Always returns ALLOW when the filter
      is disabled via `STRIX_FP_FILTER_DISABLED`.
    """
    if _is_disabled():
        return FPRuleResult(verdict="ALLOW", rule="filter_disabled", reason="")

    scope_hosts = _scope_hosts(scope_targets)
    existing_sigs = {
        _request_signature(f) for f in (existing_findings or [])
        if isinstance(f, dict)
    }

    rules: list[Callable[[], FPRuleResult]] = [
        lambda: rule_empty_poc(finding),
        lambda: rule_speculation_title(finding),
        lambda: rule_out_of_scope(finding, scope_hosts=scope_hosts),
        lambda: rule_vague_target(finding),
        lambda: rule_duplicate_request_signature(
            finding, existing_signatures=existing_sigs,
        ),
        lambda: rule_severity_cwe_mismatch(finding, severity=severity),
        lambda: rule_banner_grab_high_tier(finding, severity=severity),
        lambda: rule_directory_listing_only(finding, severity=severity),
    ]

    drop: FPRuleResult | None = None
    downgrades: list[FPRuleResult] = []
    for r in rules:
        try:
            result = r()
        except Exception as e:  # noqa: BLE001
            # A buggy rule must never block a finding — log + skip.
            logger.warning("fp_filter rule raised: %s", e)
            continue
        if result.verdict == "DROP":
            drop = result
            break
        if result.verdict == "DOWNGRADE":
            downgrades.append(result)

    if drop is not None:
        _emit_telemetry(drop, finding)
        return drop

    if downgrades:
        # Pick the lowest severity floor across all firing
        # downgrades. Today every downgrade rule sets `low`, so
        # this is effectively `downgrades[0]`, but the structure
        # supports future rules that downgrade to `medium`/`info`.
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        picked = min(
            downgrades,
            key=lambda d: severity_order.get(
                (d.new_severity or "low").lower(), 1,
            ),
        )
        _emit_telemetry(picked, finding)
        return picked

    return FPRuleResult(verdict="ALLOW", rule="all_clear", reason="")


def _emit_telemetry(result: FPRuleResult, finding: dict[str, Any]) -> None:
    """Best-effort telemetry — surface which rules are doing the
    work in events.jsonl. Failures are logged + swallowed; the
    filter must work even when the tracer is unavailable."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return
        evt = {
            "event": "fp_filter.rule_fired",
            "rule": result.rule,
            "verdict": result.verdict,
            "reason": result.reason,
            "new_severity": result.new_severity,
            "finding_title": (finding.get("title") or "")[:120],
            "finding_target": (finding.get("target") or "")[:160],
        }
        if hasattr(tracer, "emit_event"):
            tracer.emit_event(**evt)
        elif hasattr(tracer, "add_event"):
            tracer.add_event(evt)
    except Exception as e:  # noqa: BLE001
        logger.debug("fp_filter telemetry suppressed: %s", e)
