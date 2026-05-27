"""Tests for iter-Q5.9 — `rescan(tool_name, target, captured_state)`."""

from __future__ import annotations

from unittest import mock

import pytest

from strix.tools.rescan.rescan import (
    _ALLOW_LIST,
    _reset_counter_for_tests,
    rescan,
)


@pytest.fixture(autouse=True)
def _reset_budget(monkeypatch):
    """Reset the per-process budget counter between tests."""
    _reset_counter_for_tests()
    monkeypatch.delenv("STRIX_RESCAN_BUDGET", raising=False)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_rejects_empty_tool_name() -> None:
    out = rescan(tool_name="", target="https://x")
    assert out["success"] is False
    assert "tool_name is required" in out["reason"]


def test_rejects_unknown_tool_name() -> None:
    out = rescan(tool_name="not_a_real_tool", target="https://x")
    assert out["success"] is False
    assert "not in rescan allow-list" in out["reason"]


def test_rejects_empty_target() -> None:
    out = rescan(tool_name="scan_sqli_sqlmap", target="")
    assert out["success"] is False
    assert "target is required" in out["reason"]


# ---------------------------------------------------------------------------
# Allow-list — only L1 OSS-wrappers from prepass are allowed
# ---------------------------------------------------------------------------


def test_allow_list_includes_all_prepass_oss_wrappers() -> None:
    """Every tool in _ALLOW_LIST is something anchor_prepass already
    fires. The cap is meaningful only when this invariant holds."""
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    all_prepass_tools: set[str] = set()
    for anchors in _ANCHORS_BY_TARGET_TYPE.values():
        for tool_name, _ in anchors:
            all_prepass_tools.add(tool_name)

    # The allow-list intersection should be non-empty and contain
    # the canonical deep-exploit wrappers.
    intersect = _ALLOW_LIST & all_prepass_tools
    assert len(intersect) > 0
    # Specific canonical entries:
    for canonical in (
        "scan_sqli_sqlmap", "scan_xss_dalfox", "scan_smuggling_smuggler",
        "fingerprint_services_nmap", "scan_nuclei_templates",
    ):
        assert canonical in _ALLOW_LIST
        assert canonical in all_prepass_tools


def test_allow_list_excludes_l2_native_probes() -> None:
    """L2-native probes (scan_idor / scan_auth_flow /
    scan_business_logic) reach the lead via dispatch_l2_probe, not
    rescan. Keeping them out of rescan's allow-list prevents
    overlap."""
    for l2_native in (
        "scan_idor", "scan_auth_flow", "scan_business_logic",
    ):
        assert l2_native not in _ALLOW_LIST


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def test_dispatches_to_named_tool() -> None:
    """rescan forwards captured_state as kwargs to the named tool."""
    fake_fn = mock.MagicMock(return_value={"status": "ok", "findings": []})
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn,
    ):
        out = rescan(
            tool_name="scan_sqli_sqlmap",
            target="https://app.example.com/api/users",
            captured_state={"target_url": "https://app.example.com/api/users",
                            "auth_cookie": "session=abc"},
        )
    fake_fn.assert_called_once_with(
        target_url="https://app.example.com/api/users",
        auth_cookie="session=abc",
    )
    assert out["status"] == "ok"


def test_defaults_target_url_when_kwarg_missing() -> None:
    """If captured_state doesn't carry url/target_url/target, rescan
    defaults `target_url=<target>` (most common prepass kwarg)."""
    fake_fn = mock.MagicMock(return_value={"status": "ok"})
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn,
    ):
        rescan(tool_name="scan_nuclei_templates", target="https://x")
    fake_fn.assert_called_once_with(target_url="https://x")


def test_typeerror_from_underlying_tool_surfaced_cleanly() -> None:
    """If kwargs don't match the underlying tool's signature, the
    umbrella returns an error dict — never raises."""
    fake_fn = mock.MagicMock(
        side_effect=TypeError(
            "missing required argument 'image_ref'",
        ),
    )
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn,
    ):
        out = rescan(tool_name="scan_sqli_sqlmap", target="https://x")
    assert out["success"] is False
    assert "bad kwargs" in out["reason"]
    assert "image_ref" in out["reason"]


def test_general_exception_returns_error_dict() -> None:
    fake_fn = mock.MagicMock(side_effect=RuntimeError("network down"))
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn,
    ):
        out = rescan(tool_name="scan_sqli_sqlmap", target="https://x")
    assert out["success"] is False
    assert "RuntimeError" in out["reason"]


# ---------------------------------------------------------------------------
# Budget (iter-29.9 destructive-amplification guard)
# ---------------------------------------------------------------------------


def test_budget_caps_at_5_per_scan() -> None:
    """Per iter-29.9, runaway rescan loops are blocked. Default is 5;
    sixth call returns error."""
    fake_fn = mock.MagicMock(return_value={"status": "ok"})
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn,
    ):
        # First 5 succeed.
        for i in range(5):
            out = rescan(tool_name="scan_sqli_sqlmap", target=f"https://x/{i}")
            assert out["status"] == "ok"
        # 6th blocks.
        blocked = rescan(tool_name="scan_sqli_sqlmap", target="https://x/6")
    assert blocked["success"] is False
    assert "budget exhausted" in blocked["reason"]


def test_budget_decrements_per_call() -> None:
    fake_fn = mock.MagicMock(return_value={"status": "ok"})
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn,
    ):
        out1 = rescan(tool_name="scan_sqli_sqlmap", target="https://x/1")
        out2 = rescan(tool_name="scan_sqli_sqlmap", target="https://x/2")
    assert out1["rescan_budget_remaining"] == 4
    assert out2["rescan_budget_remaining"] == 3
    assert out1["rescan_blocked_after_this"] is False


def test_budget_overridable_via_env(monkeypatch) -> None:
    """Ops can raise the budget for legitimate deep-scan needs via
    STRIX_RESCAN_BUDGET."""
    monkeypatch.setenv("STRIX_RESCAN_BUDGET", "10")
    fake_fn = mock.MagicMock(return_value={"status": "ok"})
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn,
    ):
        # 10 should all succeed now.
        for i in range(10):
            out = rescan(tool_name="scan_sqli_sqlmap", target=f"https://x/{i}")
            assert out["status"] == "ok"
        # 11th blocks.
        out = rescan(tool_name="scan_sqli_sqlmap", target="https://x/11")
    assert out["success"] is False


def test_failed_calls_do_not_charge_budget() -> None:
    """Errors from the underlying tool shouldn't burn the budget —
    the lead may want to retry with corrected kwargs."""
    fake_fn = mock.MagicMock(side_effect=RuntimeError("fail"))
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn,
    ):
        for _ in range(8):
            rescan(tool_name="scan_sqli_sqlmap", target="https://x")
    # Despite 8 failed calls, the budget hasn't ticked.
    fake_fn_ok = mock.MagicMock(return_value={"status": "ok"})
    with mock.patch(
        "strix.tools.registry.get_tool_by_name",
        return_value=fake_fn_ok,
    ):
        out = rescan(tool_name="scan_sqli_sqlmap", target="https://x")
    assert out["rescan_budget_remaining"] == 4  # 5 - 1


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_rescan_is_registered() -> None:
    from strix.tools.registry import get_tool_by_name, get_tool_names
    assert "rescan" in get_tool_names()
    assert get_tool_by_name("rescan") is not None


def test_in_minimal_core() -> None:
    from strix.agents.lead_agent.tool_catalog import _MINIMAL_CORE_TOOLS
    assert "rescan" in _MINIMAL_CORE_TOOLS
