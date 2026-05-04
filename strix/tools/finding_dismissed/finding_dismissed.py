"""`dismiss_finding` agent-callable tool.

The agent calls this when it investigated a candidate vuln and
ruled it out. The tool emits a `finding.dismissed` event with the
investigation context so:

  * Wrappers can render "investigated and dismissed" cards
    alongside confirmed findings.
  * RL training pipelines can use the dismissals as the "negative
    class" — surfaces that looked suspicious but turned out OK.
  * Cost dashboards can attribute spend to dismissals (legitimate
    investigation work) vs. wandering.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "dismiss_finding"

# Allowed dismissal reasons — closed enum so consumers can group /
# filter without LLM-string parsing. The canonical set covers the
# real-world ways an agent rules out a candidate.
_VALID_REASONS: frozenset[str] = frozenset({
    "input_properly_encoded",       # XSS payload was HTML/URL-encoded
    "framework_default_blocked",    # framework's built-in protection caught it
    "csrf_token_validated",         # POST has working anti-CSRF
    "auth_enforced",                # endpoint actually requires auth
    "not_reflected",                # source not reachable to sink
    "different_origin",             # cookie / token isn't from in-scope origin
    "out_of_scope",                 # surface belongs to a different target
    "false_positive_signature",     # tool's signature was a known FP pattern
    "compensating_control",         # WAF / CSP / etc. blocks practical exploit
    "intended_behavior",            # the "vuln" is documented/intended
    "test_fixture",                 # finding was in a test fixture file
    "deprecated_path",              # endpoint exists but is unreachable in prod
    "other",                        # explanation in `evidence` field
})


def _emit_event(
    *,
    surface: str,
    hypothesis: str,
    evidence: str,
    dismissal_reason: str,
    candidate_severity: str | None,
    cwe: str | None,
    agent_id: str | None,
) -> bool:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return False
    tracer = get_global_tracer()
    if tracer is None:
        return False

    try:
        tracer._emit_event(  # noqa: SLF001
            "finding.dismissed",
            actor={"agent_id": agent_id, "tool_name": _TOOL_NAME},
            payload={
                "surface": surface,
                "hypothesis": hypothesis,
                "evidence": evidence,
                "dismissal_reason": dismissal_reason,
                "candidate_severity": candidate_severity,
                "cwe": cwe,
            },
            status="dismissed",
            source="strix.findings",
        )
    except Exception:  # noqa: BLE001
        logger.debug("finding.dismissed emission failed", exc_info=True)
        return False
    return True


@register_tool(
    sandbox_execution=False,
    mitre_techniques=[],  # Reasoning operation, not an attack technique.
)
def dismiss_finding(
    surface: str,
    hypothesis: str,
    evidence: str,
    dismissal_reason: str,
    *,
    candidate_severity: str | None = None,
    cwe: str | None = None,
) -> dict[str, Any]:
    """Record that you investigated a candidate vulnerability and
    confirmed it ISN'T a finding.

    Use this when you SPECIFICALLY tested a hypothesis (input
    reflection, framework protection, auth boundary) and the
    result said "not vulnerable". Don't use it as a generic
    "I looked at this and moved on" — those are part of normal
    iteration. This event is for the cases where you formed an
    explicit hypothesis and ran an explicit test.

    Args:
        surface: The thing you investigated (URL / endpoint /
            file:line / parameter / cookie name). E.g.
            "/api/users/123 ?name= parameter" or
            "src/auth.py:42 password-reset flow".
        hypothesis: The vuln class you suspected. E.g. "reflected
            XSS via name parameter" or "missing CSRF on
            password-reset POST".
        evidence: What you saw that proves the hypothesis is
            wrong. E.g. "Response HTML-encodes < as &lt; and "
            "as &quot;" or "POST /password-reset returns 403 "
            "without an X-CSRF-Token header".
        dismissal_reason: Closed-enum tag for grouping. Must be
            one of: `input_properly_encoded`,
            `framework_default_blocked`, `csrf_token_validated`,
            `auth_enforced`, `not_reflected`, `different_origin`,
            `out_of_scope`, `false_positive_signature`,
            `compensating_control`, `intended_behavior`,
            `test_fixture`, `deprecated_path`, or `other`.
            When `other`, put the rationale in `evidence`.
        candidate_severity: optional — what severity the candidate
            WOULD have been if real (e.g. "high" for a candidate
            SQLi). Helps wrappers prioritise dismissals: a
            dismissed-critical is more interesting than a
            dismissed-info.
        cwe: optional CWE ID (e.g. "CWE-79"). Useful for grouping
            dismissals by class.

    Returns:
        ```
        {
          success: bool,
          dismissal_reason: str,        # echoed
          surface: str,                 # echoed
          message: str,                 # confirmation / error
        }
        ```

    Schema (`finding.dismissed` event payload):
        ```
        {
          surface, hypothesis, evidence,
          dismissal_reason, candidate_severity, cwe,
        }
        ```
    """
    # Validation — non-empty + length caps to keep events small.
    if not isinstance(surface, str) or not surface.strip():
        return {
            "success": False,
            "message": "surface is required (the thing you investigated)",
        }
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        return {
            "success": False,
            "message": "hypothesis is required (the vuln class you suspected)",
        }
    if not isinstance(evidence, str) or not evidence.strip():
        return {
            "success": False,
            "message": "evidence is required (what proves the hypothesis is wrong)",
        }
    if dismissal_reason not in _VALID_REASONS:
        return {
            "success": False,
            "message": (
                f"dismissal_reason {dismissal_reason!r} is not in the allowed "
                f"set. Valid values: {sorted(_VALID_REASONS)}"
            ),
        }

    # Severity validation — optional but if supplied, must be canonical.
    if candidate_severity is not None:
        cs = candidate_severity.strip().lower()
        if cs not in {"info", "low", "medium", "high", "critical"}:
            return {
                "success": False,
                "message": (
                    f"candidate_severity {candidate_severity!r} is not in "
                    f"the canonical set (info/low/medium/high/critical)"
                ),
            }
        candidate_severity = cs

    # Cap field lengths so events stay reasonable.
    surface_str = surface.strip()[:512]
    hypothesis_str = hypothesis.strip()[:512]
    evidence_str = evidence.strip()[:2048]

    # The tool.execution.started event carries the agent_id already
    # (via #107's actor.agent_id), so consumers can correlate this
    # finding.dismissed back to its caller via execution_id when
    # needed. We still pass None here; the tracer's per-event correlation
    # IDs (trace_id / span_id) tie events together.
    agent_id: str | None = None

    emitted = _emit_event(
        surface=surface_str,
        hypothesis=hypothesis_str,
        evidence=evidence_str,
        dismissal_reason=dismissal_reason,
        candidate_severity=candidate_severity,
        cwe=cwe,
        agent_id=agent_id,
    )

    return {
        "success": True,
        "dismissal_reason": dismissal_reason,
        "surface": surface_str,
        "message": (
            "finding.dismissed event emitted"
            if emitted
            else "tracer unavailable — dismissal recorded locally only"
        ),
    }
