"""Tests for the OSS-first anchor pre-pass (2026-05-20 proposal).

Hermetic — `execute_tool` is monkeypatched to return synthetic
SpecialistResult-shaped dicts. We verify:

  * Per-target-type anchor sequences are invoked in the documented order.
  * Per-tool failures are isolated (one tool erroring doesn't block
    the rest of the sequence).
  * Timeouts surface as `status="timeout"` with the right reason.
  * `STRIX_OSS_PREPASS_DISABLED` kill switch short-circuits everything.
  * `STRIX_OSS_PREPASS_TIMEOUT` overrides the per-tool wall-clock cap.
  * Skipped target types (domain, ip_address) return a stub summary
    without invoking any tools.
  * `format_summary_for_lead_context` produces a useful task-description
    prefix when findings landed, empty string when prepass was skipped.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest import mock

import pytest

from strix.agents.lead_agent.anchor_prepass import (
    PrepassSummary,
    ToolResult,
    _ANCHORS_BY_TARGET_TYPE,
    _read_timeout,
    format_summary_for_lead_context,
    is_disabled,
    run_oss_anchor_prepass,
)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_OSS_PREPASS_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_OSS_PREPASS_TIMEOUT", raising=False)
    yield


# ---------------------------------------------------------------------------
# Anchor sequences — pinned so we catch accidental order/removal changes
# ---------------------------------------------------------------------------


def test_local_code_anchors_lead_with_sca_then_sast() -> None:
    """For code targets, scan_sca_lockfiles MUST run first
    (highest-EPSS finding class, drives chain construction), then
    scan_sast, then scan_iac, then secrets_scan."""
    anchors = _ANCHORS_BY_TARGET_TYPE["local_code"]
    names = [t[0] for t in anchors]
    assert names == [
        "scan_sca_lockfiles", "scan_sast", "scan_iac", "secrets_scan",
    ]


def test_repository_anchors_match_local_code() -> None:
    """`repository` and `local_code` are equivalent for L1 purposes."""
    assert _ANCHORS_BY_TARGET_TYPE["repository"] == _ANCHORS_BY_TARGET_TYPE["local_code"]


def test_api_anchors_include_full_owasp_api_top10() -> None:
    """OWASP API Top 10 specialists MUST all be present — pinning
    this catches regressions where someone trims the API anchor
    sequence without thinking it through."""
    names = {t[0] for t in _ANCHORS_BY_TARGET_TYPE["api"]}
    required = {
        "jwt_audit", "scan_api_bola", "scan_api_bfla",
        "scan_api_mass_assignment", "scan_api_rate_limit",
        "scan_nuclei_templates", "fingerprint_tech_stack",
    }
    missing = required - names
    assert not missing, f"API anchor sequence missing: {missing}"


def test_web_application_extends_api_with_dom_specialists() -> None:
    api_names = {t[0] for t in _ANCHORS_BY_TARGET_TYPE["api"]}
    web_names = {t[0] for t in _ANCHORS_BY_TARGET_TYPE["web_application"]}
    # Web must be a STRICT superset of api anchors.
    assert api_names.issubset(web_names)
    # And must include DOM-aware probes.
    assert "scan_xss" in web_names
    assert "dom_xss_static_probe" in web_names


def test_domain_and_ip_address_have_empty_anchor_lists() -> None:
    """No L1 signature corpus applies directly to a domain root or
    bare IP — we fall through to the lead loop for recon-driven
    surface mapping."""
    assert _ANCHORS_BY_TARGET_TYPE["domain"] == []
    assert _ANCHORS_BY_TARGET_TYPE["ip_address"] == []


# ---------------------------------------------------------------------------
# Kill switch / timeout env vars
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_is_disabled_honours_truthy_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_OSS_PREPASS_DISABLED", val)
    assert is_disabled() is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off"])
def test_is_disabled_default_falsy(monkeypatch, val) -> None:
    if val:
        monkeypatch.setenv("STRIX_OSS_PREPASS_DISABLED", val)
    else:
        monkeypatch.delenv("STRIX_OSS_PREPASS_DISABLED", raising=False)
    assert is_disabled() is False


def test_timeout_env_override(monkeypatch) -> None:
    assert _read_timeout() == 600  # default
    monkeypatch.setenv("STRIX_OSS_PREPASS_TIMEOUT", "120")
    assert _read_timeout() == 120
    # Bad values fall back to default.
    monkeypatch.setenv("STRIX_OSS_PREPASS_TIMEOUT", "not-a-number")
    assert _read_timeout() == 600
    # Floor at 30s (prevents trivial values from breaking tools).
    monkeypatch.setenv("STRIX_OSS_PREPASS_TIMEOUT", "5")
    assert _read_timeout() == 30


# ---------------------------------------------------------------------------
# run_oss_anchor_prepass — orchestration
# ---------------------------------------------------------------------------


def test_kill_switch_short_circuits_prepass(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OSS_PREPASS_DISABLED", "1")
    with mock.patch(
        "strix.tools.executor.execute_tool",
    ) as mock_exec:
        summary = asyncio.run(run_oss_anchor_prepass(
            target_type="local_code",
            target_value="/tmp/foo",
            workspace_path="/workspace/foo",
            agent_state=mock.Mock(),
        ))
    assert summary.skipped_reason == "STRIX_OSS_PREPASS_DISABLED set"
    assert summary.tools_run == []
    mock_exec.assert_not_called()


def test_unknown_target_type_skipped_cleanly() -> None:
    summary = asyncio.run(run_oss_anchor_prepass(
        target_type="some_future_target",
        target_value="x",
        workspace_path="",
        agent_state=mock.Mock(),
    ))
    assert summary.skipped_reason is not None
    assert "some_future_target" in summary.skipped_reason
    assert summary.tools_run == []


def test_domain_target_skipped_with_documented_reason() -> None:
    """domain targets have no L1 signature corpus — must skip with
    a clear reason so the lead loop runs unaffected."""
    summary = asyncio.run(run_oss_anchor_prepass(
        target_type="domain",
        target_value="example.com",
        workspace_path="",
        agent_state=mock.Mock(),
    ))
    assert summary.skipped_reason is not None
    assert "no L1 signature corpus" in summary.skipped_reason
    assert summary.tools_run == []


def test_local_code_prepass_invokes_all_anchors_in_order() -> None:
    """The full local_code anchor sequence (scan_sca_lockfiles ->
    scan_sast -> scan_iac -> secrets_scan) must fire on a
    successful prepass."""
    called: list[str] = []

    async def fake_execute_tool(tool_name: str, agent_state: Any = None, **kwargs: Any) -> dict:
        called.append(tool_name)
        return {"status": "ok", "findings": [{"id": f"{tool_name}-f1"}]}

    with mock.patch(
        "strix.tools.executor.execute_tool", new=fake_execute_tool,
    ):
        summary = asyncio.run(run_oss_anchor_prepass(
            target_type="local_code",
            target_value="/tmp/repo",
            workspace_path="/workspace/repo",
            agent_state=mock.Mock(),
        ))

    assert called == [
        "scan_sca_lockfiles", "scan_sast", "scan_iac", "secrets_scan",
    ]
    assert summary.tools_succeeded == [
        "scan_sca_lockfiles", "scan_sast", "scan_iac", "secrets_scan",
    ]
    assert summary.tools_failed == []
    assert summary.total_findings == 4  # 1 per tool


def test_per_tool_failures_are_isolated() -> None:
    """One tool failing must NOT block the rest of the sequence.
    Tool's failure surfaces as status="error" with the exception
    in the reason field; other tools still run."""
    call_count = {"n": 0}

    async def fake_execute_tool(tool_name: str, agent_state: Any = None, **kwargs: Any) -> Any:
        call_count["n"] += 1
        if tool_name == "scan_sast":
            raise RuntimeError("semgrep binary not on PATH")
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool", new=fake_execute_tool,
    ):
        summary = asyncio.run(run_oss_anchor_prepass(
            target_type="local_code",
            target_value="/tmp/repo",
            workspace_path="/workspace/repo",
            agent_state=mock.Mock(),
        ))

    # All 4 anchor tools attempted, scan_sast failed, others succeeded.
    assert summary.tools_run == [
        "scan_sca_lockfiles", "scan_sast", "scan_iac", "secrets_scan",
    ]
    assert summary.tools_failed == ["scan_sast"]
    assert sorted(summary.tools_succeeded) == sorted([
        "scan_sca_lockfiles", "scan_iac", "secrets_scan",
    ])
    # The failed tool's reason carries the exception info.
    failed_result = next(
        r for r in summary.tool_results if r.tool_name == "scan_sast"
    )
    assert failed_result.status == "error"
    assert "RuntimeError" in (failed_result.error_reason or "")


def test_tool_timeout_surfaces_as_timeout_status() -> None:
    """A tool exceeding STRIX_OSS_PREPASS_TIMEOUT must be cancelled
    and surface as ToolResult.status='timeout'. The rest of the
    sequence must still run."""

    async def slow_tool(tool_name: str, agent_state: Any = None, **kwargs: Any) -> Any:
        if tool_name == "scan_sast":
            await asyncio.sleep(10)
        return {"status": "ok", "findings": []}

    with mock.patch.dict("os.environ", {"STRIX_OSS_PREPASS_TIMEOUT": "30"}), \
         mock.patch("strix.tools.executor.execute_tool", new=slow_tool):
        # Patch asyncio.wait_for to time out the slow tool immediately.
        # This avoids actually sleeping 10s in the test.
        original_wait_for = asyncio.wait_for

        async def fast_wait(coro, timeout):
            if timeout > 0:
                # Force the slow_tool to fail-by-timeout.
                return await original_wait_for(coro, timeout=0.05)
            return await original_wait_for(coro, timeout=timeout)

        with mock.patch("strix.agents.lead_agent.anchor_prepass.asyncio.wait_for",
                        new=fast_wait):
            summary = asyncio.run(run_oss_anchor_prepass(
                target_type="local_code",
                target_value="/tmp/repo",
                workspace_path="/workspace/repo",
                agent_state=mock.Mock(),
            ))

    # The timeout class of failure surfaces with status="timeout".
    timed_out = [r for r in summary.tool_results if r.status == "timeout"]
    assert timed_out, (
        f"expected at least one timeout result; got "
        f"{[(r.tool_name, r.status) for r in summary.tool_results]}"
    )


def test_findings_count_uses_findings_or_vulnerabilities_key() -> None:
    """The strix SpecialistResult shape uses either `findings` or
    `vulnerabilities` for the finding list. Both should count."""

    async def fake_execute(tool_name: str, agent_state: Any = None, **kwargs: Any) -> Any:
        if tool_name == "scan_sca_lockfiles":
            return {"status": "ok", "vulnerabilities": [1, 2, 3]}
        return {"status": "ok", "findings": [1, 2]}

    with mock.patch("strix.tools.executor.execute_tool", new=fake_execute):
        summary = asyncio.run(run_oss_anchor_prepass(
            target_type="local_code",
            target_value="/tmp/repo",
            workspace_path="/workspace/repo",
            agent_state=mock.Mock(),
        ))
    # 3 (sca) + 2 (sast) + 2 (iac) + 2 (secrets_scan) = 9
    assert summary.total_findings == 9


# ---------------------------------------------------------------------------
# format_summary_for_lead_context
# ---------------------------------------------------------------------------


def test_format_summary_returns_empty_when_skipped() -> None:
    """If the prepass was skipped, there's no block to inject."""
    s = PrepassSummary(
        target_type="domain",
        target_value="example.com",
        skipped_reason="no L1 corpus",
    )
    assert format_summary_for_lead_context(s) == ""


def test_format_summary_renders_lead_directive() -> None:
    """The lead's first LLM call must see a clear directive: don't
    re-invoke L1 tools, focus on L2 ranking/dedup."""
    s = PrepassSummary(
        target_type="local_code",
        target_value="/tmp/repo",
        tools_run=["scan_sca_lockfiles", "scan_sast"],
        tools_succeeded=["scan_sca_lockfiles", "scan_sast"],
        tools_failed=[],
        total_findings=8,
        wall_time_s=12.3,
    )
    block = format_summary_for_lead_context(s)
    assert "OSS Anchor Pre-pass Results" in block
    assert "L1" in block and "L2" in block
    assert "scan_sca_lockfiles" not in block.split("Tools run:")[0]
    # Directive against re-invocation must be present.
    assert "Do NOT re-invoke" in block
    # Stats are surfaced.
    assert "8" in block
    assert "12.3" in block


def test_format_summary_includes_failed_tool_breadcrumbs() -> None:
    s = PrepassSummary(
        target_type="local_code",
        target_value="/tmp/repo",
        tools_run=["scan_sca_lockfiles", "scan_sast"],
        tools_succeeded=["scan_sca_lockfiles"],
        tools_failed=["scan_sast"],
        tool_results=[
            ToolResult(tool_name="scan_sca_lockfiles", status="ok",
                       findings_count=3),
            ToolResult(tool_name="scan_sast", status="error",
                       error_reason="semgrep binary missing"),
        ],
        total_findings=3,
        wall_time_s=4.2,
    )
    block = format_summary_for_lead_context(s)
    assert "scan_sast" in block
    assert "semgrep binary missing" in block
