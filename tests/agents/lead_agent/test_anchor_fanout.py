"""Tests for the iter-Q5.34e anchor-prepass fan-out phase.

Hermetic — `execute_tool` is monkeypatched so each call returns a
synthetic SpecialistResult-shaped dict. We verify:

  * The fan-out helper is opt-in (STRIX_ANCHOR_FANOUT default OFF).
  * It picks URLs from `workflow_state.endpoints_discovered`, drops the
    seed URL, filters non-http schemes, sorts deterministically.
  * It dispatches each fan-out specialist once per URL with the right
    kwarg shape (sqlmap/dalfox/open_redirect_check → `target_url=`;
    scan_nuclei_templates → `url=`).
  * STRIX_ANCHOR_FANOUT_LIMIT caps per-tool invocations.
  * Non-web/api target types skip the phase entirely.
  * The rollup `anchor_fanout_summary` ToolResult is appended.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest import mock

import pytest

from strix.agents.lead_agent.anchor_prepass import (
    PrepassSummary,
    ToolResult,
    _FANOUT_DEEP_SPECIALISTS_WEB,
    _anchor_fanout_enabled,
    _anchor_fanout_limit,
    _fanout_deep_specialists_across_endpoints,
    _select_fanout_urls,
    _DEFAULT_FANOUT_LIMIT,
)
from strix.agents.workflow_state import (
    record_endpoint_discovered,
    reset_for_testing as _reset_workflow,
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_ANCHOR_FANOUT", raising=False)
    monkeypatch.delenv("STRIX_ANCHOR_FANOUT_LIMIT", raising=False)
    monkeypatch.delenv("STRIX_DISPATCH_CONCURRENCY", raising=False)
    _reset_workflow()
    yield
    _reset_workflow()


# ---------------------------------------------------------------------------
# Env-flag plumbing
# ---------------------------------------------------------------------------


def test_anchor_fanout_default_disabled() -> None:
    assert _anchor_fanout_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE"])
def test_anchor_fanout_truthy_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", val)
    assert _anchor_fanout_enabled() is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off"])
def test_anchor_fanout_falsy_values(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", val)
    assert _anchor_fanout_enabled() is False


def test_anchor_fanout_limit_default() -> None:
    assert _anchor_fanout_limit() == _DEFAULT_FANOUT_LIMIT


def test_anchor_fanout_limit_override(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_LIMIT", "7")
    assert _anchor_fanout_limit() == 7


def test_anchor_fanout_limit_clamps_to_1000(monkeypatch) -> None:
    """Pathological N=999_999 must not take a benchmark hostage."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_LIMIT", "999999")
    assert _anchor_fanout_limit() == 1000


def test_anchor_fanout_limit_invalid_returns_default(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_LIMIT", "garbage")
    assert _anchor_fanout_limit() == _DEFAULT_FANOUT_LIMIT


# ---------------------------------------------------------------------------
# URL selection
# ---------------------------------------------------------------------------


def test_select_fanout_urls_drops_seed_and_filters_non_http() -> None:
    record_endpoint_discovered("http://example.com/a")
    record_endpoint_discovered("http://example.com/b")
    record_endpoint_discovered("http://example.com/seed")
    record_endpoint_discovered("javascript:alert(1)")
    record_endpoint_discovered("ftp://example.com/file")
    urls = _select_fanout_urls("http://example.com/seed", 50)
    assert urls == ["http://example.com/a", "http://example.com/b"]


def test_select_fanout_urls_normalizes_trailing_slash_for_seed() -> None:
    """Seed comparison must be slash-tolerant — katana / web_crawler
    may register the same URL with or without trailing slash."""
    record_endpoint_discovered("http://x.test/")
    record_endpoint_discovered("http://x.test/page")
    urls = _select_fanout_urls("http://x.test", 10)
    assert urls == ["http://x.test/page"]


def test_select_fanout_urls_respects_limit() -> None:
    for i in range(20):
        record_endpoint_discovered(f"http://x.test/p{i:02d}")
    urls = _select_fanout_urls("http://x.test", 5)
    assert len(urls) == 5
    # Sorted determinism.
    assert urls == sorted(urls)


def test_select_fanout_urls_empty_workflow_returns_empty() -> None:
    assert _select_fanout_urls("http://x.test", 50) == []


# ---------------------------------------------------------------------------
# End-to-end fan-out — patch execute_tool, observe dispatched kwargs
# ---------------------------------------------------------------------------


def test_fanout_disabled_short_circuits() -> None:
    """With STRIX_ANCHOR_FANOUT unset, helper must not invoke any tool
    even when URLs are present."""
    record_endpoint_discovered("http://x.test/a")
    summary = PrepassSummary(target_type="web_application", target_value="http://x.test/")
    with mock.patch(
        "strix.tools.executor.execute_tool", new=mock.AsyncMock(),
    ) as mocked:
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application", target_value="http://x.test/",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))
    assert mocked.call_count == 0
    # No fanout summary either.
    names = [tr.tool_name for tr in summary.tool_results]
    assert "anchor_fanout_summary" not in names


def test_fanout_skipped_for_non_web_target(monkeypatch) -> None:
    """Only `web_application` and `api` target types are eligible —
    SAST / container / IP / domain run their own L1 stacks."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")
    record_endpoint_discovered("http://x.test/a")
    summary = PrepassSummary(target_type="local_code", target_value="/tmp/repo")
    with mock.patch(
        "strix.tools.executor.execute_tool", new=mock.AsyncMock(),
    ) as mocked:
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="local_code", target_value="/tmp/repo",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))
    assert mocked.call_count == 0


def test_fanout_dispatches_each_specialist_per_url(monkeypatch) -> None:
    """With 2 URLs and 4 fan-out specialists, expect 8 dispatches."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")
    record_endpoint_discovered("http://x.test/a")
    record_endpoint_discovered("http://x.test/b")
    summary = PrepassSummary(target_type="web_application", target_value="http://x.test/")

    async def _fake_execute_tool(tool_name: str, *, agent_state: Any, **kwargs: Any):
        return {"status": "ok", "findings": [{"category": tool_name}]}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake_execute_tool),
    ) as mocked:
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application", target_value="http://x.test/",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    # 4 specialists × 2 URLs = 8 dispatches.
    assert mocked.call_count == 4 * 2

    # Per-specialist kwarg shape check.
    target_url_tools = {"scan_sqli_sqlmap", "scan_xss_dalfox", "open_redirect_check"}
    url_tools = {"scan_nuclei_templates"}
    for call in mocked.call_args_list:
        tname = call.args[0]
        kwargs = call.kwargs
        assert "agent_state" in kwargs
        if tname in target_url_tools:
            assert "target_url" in kwargs
            assert kwargs["target_url"].startswith("http://x.test/")
        elif tname in url_tools:
            assert "url" in kwargs
            assert kwargs["url"].startswith("http://x.test/")
        else:
            pytest.fail(f"Unexpected fan-out tool dispatched: {tname!r}")

    # Each dispatch should land as a tagged ToolResult on the summary.
    fanout_results = [
        tr for tr in summary.tool_results if "[fanout " in tr.tool_name
    ]
    assert len(fanout_results) == 8
    # Each carried findings=1, so total_findings += 8.
    assert summary.total_findings == 8
    # Rollup summary appended.
    rollup = [
        tr for tr in summary.tool_results if tr.tool_name == "anchor_fanout_summary"
    ]
    assert len(rollup) == 1
    per_tool = rollup[0].raw_result["per_tool"]
    assert set(per_tool.keys()) == {t for t, _ in _FANOUT_DEEP_SPECIALISTS_WEB}
    for bucket in per_tool.values():
        assert bucket["attempted"] == 2
        assert bucket["succeeded"] == 2
        assert bucket["findings"] == 2


def test_fanout_respects_per_tool_limit(monkeypatch) -> None:
    """STRIX_ANCHOR_FANOUT_LIMIT caps URLs per tool — verify with 10
    URLs + limit=3."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_LIMIT", "3")
    for i in range(10):
        record_endpoint_discovered(f"http://x.test/p{i}")
    summary = PrepassSummary(target_type="web_application", target_value="http://x.test/")

    async def _fake(*args, **kwargs):
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake),
    ) as mocked:
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application", target_value="http://x.test/",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    # 4 specialists × 3 URLs = 12 dispatches.
    assert mocked.call_count == 4 * 3


def test_fanout_with_no_urls_logs_and_skips(monkeypatch) -> None:
    """Enabled flag + zero crawled URLs = no dispatches, no rollup."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")
    summary = PrepassSummary(target_type="web_application", target_value="http://x.test/")
    with mock.patch(
        "strix.tools.executor.execute_tool", new=mock.AsyncMock(),
    ) as mocked:
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application", target_value="http://x.test/",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))
    assert mocked.call_count == 0
    names = [tr.tool_name for tr in summary.tool_results]
    assert "anchor_fanout_summary" not in names


# ---------------------------------------------------------------------------
# Anti-overfit guard — the fan-out specialist list must stay minimal
# ---------------------------------------------------------------------------


def test_fanout_specialist_list_is_narrow() -> None:
    """Per the iter-Q5.34e design — fan-out fires O(N_urls) tool calls
    per scan, so the per-URL specialist set must stay ≤ 6 to keep
    sandbox load bounded. If the list grows past that, the cap default
    needs re-thinking."""
    assert len(_FANOUT_DEEP_SPECIALISTS_WEB) <= 6
