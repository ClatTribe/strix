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
    scan_sast, then scan_iac, then secrets_scan.

    iter-37.14 appended scan_mobile_mobsfscan as a no-op-on-non-
    mobile-repos final step (broad mobile SAST coverage)."""
    anchors = _ANCHORS_BY_TARGET_TYPE["local_code"]
    names = [t[0] for t in anchors]
    assert names == [
        "scan_sca_lockfiles", "scan_sast", "scan_iac",
        "secrets_scan", "scan_mobile_mobsfscan",
    ]


def test_repository_anchors_match_local_code() -> None:
    """`repository` and `local_code` are equivalent for L1 purposes."""
    assert _ANCHORS_BY_TARGET_TYPE["repository"] == _ANCHORS_BY_TARGET_TYPE["local_code"]


def test_api_anchors_include_v1_set() -> None:
    """API anchor sequence v1 (2026-05-20 — post path-routing fix +
    kwarg correction):
      * Recon: fingerprint_tech_stack, openapi_spec_ingest
      * Signature: scan_nuclei_templates
      * Rate-limit: scan_api_rate_limit
      * Injection class (URL-based, no prereqs): scan_sqli, scan_xxe,
        scan_ssrf, scan_ssti, scan_path_traversal, scan_nosql_injection,
        scan_cmd_injection
      * Passive: scan_secrets_in_response, http_security_headers_audit,
        tls_audit, cors_deep_check, csrf_check, open_redirect_check

    NOT in v1 (require prereqs the prepass doesn't yet wire):
      * jwt_audit — needs a JWT token (the lead's L2 layer extracts
        tokens from response captures and invokes per-token)
      * scan_api_bola / scan_api_bfla / scan_api_mass_assignment —
        need `endpoints=list[dict]` from openapi_spec_ingest's KG
        emission. The lead picks these up after the spec is ingested.
    """
    names = {t[0] for t in _ANCHORS_BY_TARGET_TYPE["api"]}
    required_v1 = {
        "fingerprint_tech_stack",
        "openapi_spec_ingest",
        "scan_nuclei_templates",
        "scan_api_rate_limit",
        "scan_sqli", "scan_xxe", "scan_ssrf",
    }
    missing = required_v1 - names
    assert not missing, f"API anchor v1 sequence missing: {missing}"
    # Tools that need prereqs MUST NOT be in v1 — they would crash.
    deferred_to_v2 = {
        "jwt_audit",
        "scan_api_bola", "scan_api_bfla", "scan_api_mass_assignment",
    }
    invalid = deferred_to_v2 & names
    assert not invalid, (
        f"API anchor v1 sequence MUST NOT include tools that need "
        f"prereqs (would TypeError on missing kwargs): {invalid}"
    )


def test_web_application_extends_api_with_dom_specialists() -> None:
    api_names = {t[0] for t in _ANCHORS_BY_TARGET_TYPE["api"]}
    web_names = {t[0] for t in _ANCHORS_BY_TARGET_TYPE["web_application"]}
    # Web must be a STRICT superset of api anchors.
    assert api_names.issubset(web_names)
    # And must include DOM-aware probes.
    assert "scan_xss" in web_names
    assert "dom_xss_static_probe" in web_names


def test_domain_and_ip_address_have_anchor_coverage() -> None:
    """iter-Q5.4/Q5.5 inverted the prior behaviour. Pre-Q5: domain +
    IP fell through to the lead loop with no prepass coverage and the
    LLM drove recon via catalog tools. Post-Q5: the OSS recon tools
    (nmap / httpx / nuclei / tls_audit for IP; subfinder / checkdmarc /
    dnstwist / nuclei / domain_recon_pipeline for domain) fire
    deterministically per CLAUDE.md §1.5 — they're L1 detection, not
    LLM-choice work."""
    assert len(_ANCHORS_BY_TARGET_TYPE["ip_address"]) > 0
    ip_anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["ip_address"]}
    for name in (
        "fingerprint_services_nmap",
        "probe_hosts_httpx",
        "scan_nuclei_templates",
        "tls_audit",
    ):
        assert name in ip_anchors, f"{name} missing from _ANCHORS_IP"

    assert len(_ANCHORS_BY_TARGET_TYPE["domain"]) > 0
    domain_anchors = {t for t, _ in _ANCHORS_BY_TARGET_TYPE["domain"]}
    for name in (
        "domain_recon_pipeline",
        "enumerate_subdomains_subfinder",
        "scan_dns_hygiene_checkdmarc",
        "scan_typosquats_dnstwist",
        "scan_nuclei_templates",
    ):
        assert name in domain_anchors, f"{name} missing from _ANCHORS_DOMAIN"


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


def test_domain_target_runs_recon_prepass() -> None:
    """iter-Q5.5: domain assets now have L1 anchor coverage
    (subfinder / checkdmarc / dnstwist / nuclei / domain_recon_pipeline).
    Pre-Q5.5 this test asserted the prepass skipped with a "no L1
    signature corpus" reason. The prepass now invokes the OSS recon
    tools; we mock the executor to avoid hitting the network."""
    with mock.patch("strix.tools.executor.execute_tool") as mock_exec:
        mock_exec.return_value = {"success": True, "status": "ok"}
        summary = asyncio.run(run_oss_anchor_prepass(
            target_type="domain",
            target_value="example.com",
            workspace_path="",
            agent_state=mock.Mock(),
        ))
    # No skipped_reason — the prepass actually ran.
    assert summary.skipped_reason is None
    # At least one tool fired (mock returns success for all).
    assert len(summary.tools_run) > 0
    # The first tool fired should be the domain pipeline orchestrator.
    assert "domain_recon_pipeline" in summary.tools_run


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
        "scan_sca_lockfiles", "scan_sast", "scan_iac",
        "secrets_scan", "scan_mobile_mobsfscan",
    ]
    assert summary.tools_succeeded == [
        "scan_sca_lockfiles", "scan_sast", "scan_iac",
        "secrets_scan", "scan_mobile_mobsfscan",
    ]
    assert summary.tools_failed == []
    assert summary.total_findings == 5  # 1 per tool (iter-37.14: + mobsfscan)


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

    # iter-37.14 — anchor sequence is sca/sast/iac/secrets_scan +
    # scan_mobile_mobsfscan. scan_sast failed; the rest succeed.
    assert summary.tools_run == [
        "scan_sca_lockfiles", "scan_sast", "scan_iac",
        "secrets_scan", "scan_mobile_mobsfscan",
    ]
    assert summary.tools_failed == ["scan_sast"]
    assert sorted(summary.tools_succeeded) == sorted([
        "scan_sca_lockfiles", "scan_iac",
        "secrets_scan", "scan_mobile_mobsfscan",
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


def test_code_kwargs_uses_workspace_path_for_all_code_anchors() -> None:
    """All code-shape anchor tools (scan_sast, scan_sca_lockfiles,
    scan_iac, secrets_scan) execute inside the sandbox container, so
    they all receive the in-sandbox workspace path (`/workspace/<subdir>`)
    rather than the host path.

    The prior architecture shelled scan_sast/scan_sca_lockfiles/scan_iac
    out to host subprocesses and required the HOST path; that branch
    was removed when those tools moved into the sandbox alongside
    secrets_scan. Pinning the unified behaviour here so a regression
    can't reintroduce the split.
    """
    from strix.agents.lead_agent.anchor_prepass import _code_kwargs

    host_path = "/Users/ashish/repo/src"
    workspace_path = "/workspace/src"

    for tool_name in (
        "scan_sast", "scan_sca_lockfiles", "scan_iac", "secrets_scan",
    ):
        kw = _code_kwargs(host_path, workspace_path, tool_name)
        assert kw == {"repo_path": workspace_path}, (
            f"{tool_name} must get workspace path; got {kw}"
        )


def test_code_kwargs_falls_back_to_host_path_when_no_workspace() -> None:
    """When workspace_path is empty (native-execution runs without
    a sandbox), every tool gets the host path — there's nothing
    else to fall back to."""
    from strix.agents.lead_agent.anchor_prepass import _code_kwargs

    host_path = "/Users/ashish/repo/src"

    # Both host-tool and sandbox-tool fall back to host_path.
    kw = _code_kwargs(host_path, "", "scan_sast")
    assert kw == {"repo_path": host_path}

    kw = _code_kwargs(host_path, "", "secrets_scan")
    assert kw == {"repo_path": host_path}


def test_phase_2_iterates_rate_limit_per_endpoint() -> None:
    """Phase 2 of the API prepass: when openapi_spec_ingest succeeds
    and emits an endpoints list, scan_api_rate_limit is invoked
    PER-ENDPOINT (not just on the base URL).

    Without per-endpoint iteration we'd miss endpoint-specific
    rate-limit must_finds (e.g. vampi's `/users/v1/login` rate-limit).
    """

    async def fake_execute(tool_name: str, agent_state: Any = None, **kwargs: Any) -> Any:
        if tool_name == "openapi_spec_ingest":
            return {
                "status": "ok",
                "success": True,
                "endpoints": [
                    {"path": "/login", "method": "POST",
                     "url": "http://example/login"},
                    {"path": "/api/users", "method": "GET",
                     "url": "http://example/api/users"},
                    {"path": "/api/orders", "method": "POST",
                     "url": "http://example/api/orders"},
                ],
                "endpoint_count": 3,
            }
        if tool_name == "scan_api_rate_limit":
            # Synthesize finding for /login only (mimics vampi's shape).
            url = kwargs.get("url", "")
            findings = [{"id": "rate-limit"}] if "/login" in url else []
            return {"status": "ok", "findings": findings}
        # Default: no-op success.
        return {"status": "ok", "findings": []}

    with mock.patch("strix.tools.executor.execute_tool", new=fake_execute):
        summary = asyncio.run(run_oss_anchor_prepass(
            target_type="api",
            target_value="http://example",
            workspace_path="",
            agent_state=mock.Mock(),
        ))

    # Phase-2 entries are labeled with `scan_api_rate_limit[METHOD PATH]`.
    p2_entries = [
        r for r in summary.tool_results
        if r.tool_name.startswith("scan_api_rate_limit[")
    ]
    assert len(p2_entries) == 3, (
        f"phase-2 must iterate per endpoint (3 endpoints expected); "
        f"got {len(p2_entries)} entries: {[r.tool_name for r in p2_entries]}"
    )
    # The /login endpoint should produce a finding (per the fake).
    login_entries = [r for r in p2_entries if "/login" in r.tool_name]
    assert login_entries and login_entries[0].findings_count == 1, (
        "phase-2 /login rate-limit hit must surface as a finding"
    )
    # The other 2 endpoints produced 0 findings — still tracked.
    other_entries = [r for r in p2_entries if "/login" not in r.tool_name]
    assert all(r.findings_count == 0 for r in other_entries)


def test_phase_2_skipped_when_openapi_ingest_fails() -> None:
    """If openapi_spec_ingest didn't emit endpoints (target has no
    spec, or the tool errored), phase-2 must skip gracefully without
    invoking per-endpoint scanners."""

    async def fake_execute(tool_name: str, agent_state: Any = None, **kwargs: Any) -> Any:
        if tool_name == "openapi_spec_ingest":
            # Failure shape — no `endpoints` key.
            return {"status": "error", "error": "no spec found"}
        return {"status": "ok", "findings": []}

    with mock.patch("strix.tools.executor.execute_tool", new=fake_execute):
        summary = asyncio.run(run_oss_anchor_prepass(
            target_type="api",
            target_value="http://example",
            workspace_path="",
            agent_state=mock.Mock(),
        ))

    # NO phase-2 per-endpoint entries.
    p2_entries = [
        r for r in summary.tool_results
        if r.tool_name.startswith("scan_api_rate_limit[")
    ]
    assert p2_entries == [], (
        f"phase-2 must not run when openapi_spec_ingest fails; "
        f"got {[r.tool_name for r in p2_entries]}"
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
    # iter-37.14 — _ANCHORS_LOCAL_CODE now has 5 entries:
    # 3 (sca, "vulnerabilities" key) + 2 (sast) + 2 (iac)
    # + 2 (secrets_scan) + 2 (scan_mobile_mobsfscan) = 11
    assert summary.total_findings == 11


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
