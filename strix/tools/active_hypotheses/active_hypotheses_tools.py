"""Agent-callable wrappers around `strix.agents.active_hypotheses`."""

from __future__ import annotations

from typing import Any

from strix.tools.registry import register_tool


# NOTE: the `strix.agents.active_hypotheses` module is imported
# lazily inside each tool body (NOT at module-load time). Reason:
# `strix.agents.__init__` pulls in `BaseAgent` which transitively
# imports `strix.tools` — at module-load that's a circular re-entry
# while `strix.tools.__init__` is still resolving us.
def _module():
    import strix.agents.active_hypotheses as m  # noqa: PLC0415

    return m


@register_tool(sandbox_execution=False, mitre_techniques=[])
def open_hypothesis(
    hypothesis: str,
    surface: str,
    category: str | None = None,
) -> dict[str, Any]:
    """Register a new in-flight hypothesis BEFORE you start
    investigating. Returns `{success, hypothesis_id, ...}` — retain
    the `hypothesis_id` for the eventual confirm/dismiss call.

    BEFORE opening, call `list_hypotheses(surface=...)` to check
    whether a sister specialist is already investigating this
    surface — if so, defer rather than duplicating work.

    Args:
        hypothesis: Plain-English description of the vuln class
            you suspect ("POST /password-reset is vulnerable to
            host-header poisoning").
        surface: The thing you'll investigate ("POST /password-reset",
            "src/auth.py:42 password-reset flow").
        category: Optional vuln class tag (mirrors finding categories:
            host_header_injection / sql_injection / xss / etc.).

    Returns:
        {success: bool, hypothesis_id: str, ...} — id is needed for
        confirm/dismiss.
    """
    return _module().open_hypothesis(
        hypothesis=hypothesis,
        surface=surface,
        category=category,
    )


@register_tool(sandbox_execution=False, mitre_techniques=[])
def confirm_hypothesis(
    hypothesis_id: str,
    resolution: str = "",
    linked_finding_id: str | None = None,
) -> dict[str, Any]:
    """Mark a hypothesis as CONFIRMED — the vuln was found.

    When you emitted a vulnerability report, pass `linked_finding_id`
    so the wrapper can join the hypothesis timeline to the finding.
    """
    return _module().confirm_hypothesis(
        hypothesis_id=hypothesis_id,
        resolution=resolution,
        linked_finding_id=linked_finding_id,
    )


@register_tool(sandbox_execution=False, mitre_techniques=[])
def dismiss_hypothesis(
    hypothesis_id: str,
    dismissal_reason: str,
    resolution: str = "",
) -> dict[str, Any]:
    """Mark a hypothesis as DISMISSED — investigated, ruled out.

    Use the same closed-enum `dismissal_reason` as `dismiss_finding`
    (#118): `input_properly_encoded`, `framework_default_blocked`,
    `csrf_token_validated`, `auth_enforced`, `not_reflected`,
    `different_origin`, `out_of_scope`, `false_positive_signature`,
    `compensating_control`, `intended_behavior`, `test_fixture`,
    `deprecated_path`, `other`.
    """
    return _module().dismiss_hypothesis(
        hypothesis_id=hypothesis_id,
        dismissal_reason=dismissal_reason,
        resolution=resolution,
    )


@register_tool(sandbox_execution=False, mitre_techniques=[])
def list_hypotheses(
    only_status: str | None = None,
    surface: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """Read in-flight hypotheses. Sister-specialist guard before
    opening your own.

    Args:
        only_status: 'investigating' / 'confirmed' / 'dismissed' / None
            (all). Most common: 'investigating' to find work-in-flight.
        surface: substring filter (case-insensitive).
        category: exact-match filter on the vuln-class tag.

    Returns:
        {success: True, count: int, hypotheses: [...]} — list ordered
        by opened_at (oldest first).
    """
    out = _module().list_active_hypotheses(
        only_status=only_status,
        surface=surface,
        category=category,
    )
    return {"success": True, "count": len(out), "hypotheses": out}
