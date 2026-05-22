"""iter-25.9 — SAST-sink → DAST-confirm auto-promotion (Gap 8).

When SAST flags a sink with high confidence and the route touching
that file is live, the engineer's next move is "fire one payload and
check." Currently this requires the LLM-driven conversational
specialist. With iter-23.2 (`scan_sqli_sqlmap`) and iter-22.8
(`scan_xss_dalfox`) we have deterministic active checkers — auto-chain
them.

This module owns the **decision logic**: given a SAST finding, decide
whether to fire a confirmation probe, which probe, and what target.
The actual firing is delegated to the corresponding tool (via the
tracer's amplify queue — wired in Wave 4 / iter-25.10) so the L2 layer
doesn't have to plumb subprocess invocation directly.

For Wave 2 we ship the **decision** and the **handoff record**. The
record carries:

    {
        "tool": "scan_sqli_sqlmap" | "scan_xss_dalfox" | ...,
        "target_url": "...",
        "param": "...",          # extracted from sink expression
        "confidence_after_confirm": 0.95 if confirmed,
        "src_finding_id": "vuln-0001",
    }

Wave 4's amplify orchestrator reads these records and fires the
probes. For Wave 2 the integration test just checks the record is
attached to the finding under ``pending_confirmations``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any


logger = logging.getLogger(__name__)


# CWE → deterministic confirmation tool mapping. Only CWEs where we
# have a deterministic active checker land here; the rest fall through.
_CWE_TO_CONFIRMER = {
    "CWE-89": "scan_sqli_sqlmap",    # SQLi
    "CWE-79": "scan_xss_dalfox",      # XSS
    "CWE-22": "scan_path_traversal",  # path traversal
    "CWE-78": "scan_cmd_injection",   # command injection
    "CWE-918": "scan_ssrf",           # SSRF
    "CWE-1336": "scan_ssti",          # SSTI
}


# Param-name extraction patterns. SAST tools surface the sink line
# in technical_analysis / description; we pull the variable name on
# the right side of common sink shapes.
_PARAM_EXTRACTION_PATTERNS = (
    # Flask:  request.args.get("foo") / request.form["bar"]
    re.compile(r"""request\.args\.get\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""request\.args\[\s*['"]([^'"]+)['"]\s*\]"""),
    re.compile(r"""request\.form\.get\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""request\.form\[\s*['"]([^'"]+)['"]\s*\]"""),
    re.compile(r"""request\.json\[\s*['"]([^'"]+)['"]\s*\]"""),
    # Express:  req.query.foo / req.body.bar / req.params.id
    re.compile(r"""req\.(?:query|body|params)\.(\w+)"""),
    re.compile(r"""req\.(?:query|body|params)\[\s*['"]([^'"]+)['"]\s*\]"""),
    # FastAPI / Django:  param: str = Form(...) — name on the left
    re.compile(r"""^\s*(\w+)\s*=\s*Form\(""", re.MULTILINE),
    re.compile(r"""^\s*(\w+)\s*=\s*Query\(""", re.MULTILINE),
)


@dataclass(frozen=True)
class ConfirmationRequest:
    """A planned auto-confirmation probe; attached to the SAST finding
    as ``pending_confirmations[]`` for Wave 4 to fire."""
    tool: str
    target_url: str | None
    param: str | None
    src_finding_id: str
    cwe: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "target_url": self.target_url,
            "param": self.param,
            "src_finding_id": self.src_finding_id,
            "cwe": self.cwe,
        }


def _is_sast_finding(finding: dict[str, Any]) -> bool:
    """Is this a SAST sink we can confirm?

    Three signals:
      1. has a `rule_id` from a SAST tool (semgrep/strix-sast/etc.)
      2. has at least one `code_locations[]` entry
      3. has a CWE we know how to confirm

    Returns False for findings that already have `verification_status
    == "exploited"` — those don't need confirmation.
    """
    vstat = (finding.get("verification_status") or "").lower().strip()
    if vstat == "exploited":
        return False
    cwe = (finding.get("cwe") or "").upper()
    if cwe not in _CWE_TO_CONFIRMER:
        return False
    rule_id = finding.get("rule_id") or finding.get("check_id")
    code_locs = finding.get("code_locations") or []
    if not (isinstance(code_locs, list) and code_locs):
        return False
    return bool(rule_id)


def _extract_param_name(finding: dict[str, Any]) -> str | None:
    """Pull the parameter name out of the sink expression."""
    blobs: list[str] = []
    for key in ("description", "technical_analysis", "evidence"):
        v = finding.get(key)
        if isinstance(v, str):
            blobs.append(v)
    code_locs = finding.get("code_locations") or []
    if isinstance(code_locs, list):
        for loc in code_locs:
            if isinstance(loc, dict):
                snip = loc.get("snippet") or loc.get("code")
                if isinstance(snip, str):
                    blobs.append(snip)
    combined = "\n".join(blobs)
    for rx in _PARAM_EXTRACTION_PATTERNS:
        m = rx.search(combined)
        if m:
            return m.group(1)
    return None


def _derive_target_url(finding: dict[str, Any]) -> str | None:
    """Best-effort live-route URL for the confirmer.

    Order of preference:
      1. existing `endpoint` field on the finding
      2. `url` field
      3. None — Wave 4's amplify orchestrator will need to consult
         the crawl output to join file → route.
    """
    for key in ("endpoint", "url"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def plan_dast_confirmation(
    finding: dict[str, Any],
) -> ConfirmationRequest | None:
    """Return a ConfirmationRequest if this finding warrants auto-DAST.

    Pure function — no side effects, does not mutate ``finding``.
    Returns ``None`` when the finding doesn't qualify (wrong CWE,
    not SAST-shaped, already confirmed).
    """
    try:
        if not _is_sast_finding(finding):
            return None
        cwe = finding["cwe"].upper()
        tool = _CWE_TO_CONFIRMER.get(cwe)
        if not tool:
            return None
        param = _extract_param_name(finding)
        target = _derive_target_url(finding)
        # We need EITHER a target URL OR a way to derive one. For
        # Wave 2 we accept None-target requests; Wave 4 will fill it
        # in from crawl data.
        return ConfirmationRequest(
            tool=tool,
            target_url=target,
            param=param,
            src_finding_id=finding.get("id") or "",
            cwe=cwe,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("plan_dast_confirmation failed: %s", e)
        return None
