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


def test_select_fanout_urls_reads_endpoints_from_tool_results() -> None:
    """iter-Q5.34f — primary source is `summary.tool_results[i].
    raw_result.endpoints`. Sandbox-side katana writes URLs to its own
    sandbox-side workflow_state singleton; the host never sees that.
    The only data that crosses the sandbox→host boundary is the
    tool's return value, so the fan-out MUST read from there."""
    summary = PrepassSummary(target_type="web_application", target_value="http://x.test/")
    summary.tool_results.append(ToolResult(
        tool_name="crawl_with_katana",
        status="ok",
        findings_count=0,
        raw_result={
            "status": "ok",
            "endpoints": [
                {"url": "http://x.test/page-a", "method": "GET"},
                {"url": "http://x.test/page-b", "method": "GET"},
                {"url": "http://x.test/page-c", "method": "POST"},
            ],
        },
    ))
    urls = _select_fanout_urls("http://x.test/", 50, summary=summary)
    assert urls == [
        "http://x.test/page-a",
        "http://x.test/page-b",
        "http://x.test/page-c",
    ]


def test_select_fanout_urls_merges_tool_results_and_workflow_state() -> None:
    """Both sources contribute; the union is deduped + sorted."""
    record_endpoint_discovered("http://x.test/from-workflow")
    summary = PrepassSummary(target_type="web_application", target_value="http://x.test/")
    summary.tool_results.append(ToolResult(
        tool_name="crawl_with_katana",
        status="ok",
        raw_result={
            "endpoints": [
                {"url": "http://x.test/from-tool-result"},
                {"url": "http://x.test/from-workflow"},  # dupe — should collapse
            ],
        },
    ))
    urls = _select_fanout_urls("http://x.test/", 50, summary=summary)
    assert urls == [
        "http://x.test/from-tool-result",
        "http://x.test/from-workflow",
    ]


def test_select_fanout_urls_tolerates_string_endpoints() -> None:
    """Some recon tools emit `endpoints: list[str]` instead of
    `endpoints: list[dict]` — both forms should work."""
    summary = PrepassSummary(target_type="web_application", target_value="http://x.test/")
    summary.tool_results.append(ToolResult(
        tool_name="some_recon",
        status="ok",
        raw_result={"endpoints": ["http://x.test/a", "http://x.test/b"]},
    ))
    urls = _select_fanout_urls("http://x.test/", 50, summary=summary)
    assert urls == ["http://x.test/a", "http://x.test/b"]


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
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_ROUTING", "0")  # iter-Q5.34j ablation
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
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_ROUTING", "0")  # iter-Q5.34j ablation
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


# ---------------------------------------------------------------------------
# iter-Q5.34h — bridge list-shape findings to host tracer
# ---------------------------------------------------------------------------


def test_fanout_bridges_list_findings_to_tracer(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_ROUTING", "0")  # iter-Q5.34j ablation
    """Wrappers like dalfox emit findings as a list in their result
    dict instead of calling `tracer.add_vulnerability_report`. iter-
    Q5.34h: fan-out must bridge that list back to the tracer so the
    L1.5 hook chain + bench harness see those findings."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")

    # Plant a real workflow URL for the fan-out to dispatch against.
    record_endpoint_discovered("http://x.test/case1.jsp")

    summary = PrepassSummary(
        target_type="web_application", target_value="http://x.test/seed",
    )

    # Track tracer emissions.
    emissions: list[dict[str, Any]] = []

    class FakeTracer:
        def add_vulnerability_report(self, **kw: Any) -> str:
            emissions.append(kw)
            return "vuln-1"

    fake_tracer = FakeTracer()
    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: fake_tracer,
    )

    async def _fake_execute_tool(tool_name: str, *, agent_state, **kwargs):
        # Each dispatched tool returns a list-shape finding.
        return {
            "status": "ok",
            "findings": [{
                "rule_id": f"{tool_name}-rule",
                "title": f"{tool_name} finding",
                "severity": "high",
                "cwe": "CWE-79" if "xss" in tool_name else "CWE-89",
                "description": f"detected by {tool_name}",
            }],
        }

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake_execute_tool),
    ):
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application",
            target_value="http://x.test/seed",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    # 4 specialists × 1 URL = 4 dispatches → 4 bridged tracer emissions.
    assert len(emissions) == 4, f"expected 4 emissions, got {len(emissions)}"

    # Each tracer call must carry the expected core fields.
    for em in emissions:
        assert "title" in em
        assert "severity" in em
        assert em["endpoint"] == "http://x.test/case1.jsp"
        assert "cwe" in em
        # category should fall back to per-tool hint when not in finding.
        assert em.get("category") in (
            "sqli", "xss", "redirect", "vulnerability",
        )


def test_fanout_concurrency_defaults_to_1(monkeypatch) -> None:
    """Without explicit override, concurrency must be 1 to avoid the
    sandbox tool_server's same-agent_id cancellation race."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")
    monkeypatch.delenv("STRIX_ANCHOR_FANOUT_CONCURRENCY", raising=False)
    record_endpoint_discovered("http://x.test/a")
    record_endpoint_discovered("http://x.test/b")
    summary = PrepassSummary(
        target_type="web_application", target_value="http://x.test/",
    )

    # Capture dispatch ordering: if concurrency=1, gather still launches
    # all coroutines but Semaphore(1) serializes them. Verify by
    # observing that no two dispatches overlap.
    overlap_max = {"v": 0}
    running = {"v": 0}

    async def _fake_exec(*args, **kwargs):
        running["v"] += 1
        overlap_max["v"] = max(overlap_max["v"], running["v"])
        await asyncio.sleep(0)
        running["v"] -= 1
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake_exec),
    ):
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application", target_value="http://x.test/",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    assert overlap_max["v"] == 1, (
        f"concurrency must default to 1 to avoid sandbox cancel race; "
        f"observed max overlap {overlap_max['v']}"
    )


def test_fanout_concurrency_override_respected(monkeypatch) -> None:
    """STRIX_ANCHOR_FANOUT_CONCURRENCY explicitly overrides the
    serial-by-default behavior for operators who've worked around the
    cancel-by-agent_id issue (e.g. patched tool_server, multi-agent
    fan-out)."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_CONCURRENCY", "3")
    record_endpoint_discovered("http://x.test/a")
    record_endpoint_discovered("http://x.test/b")
    record_endpoint_discovered("http://x.test/c")
    record_endpoint_discovered("http://x.test/d")
    summary = PrepassSummary(
        target_type="web_application", target_value="http://x.test/",
    )

    overlap_max = {"v": 0}
    running = {"v": 0}

    async def _fake_exec(*args, **kwargs):
        running["v"] += 1
        overlap_max["v"] = max(overlap_max["v"], running["v"])
        await asyncio.sleep(0.01)
        running["v"] -= 1
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake_exec),
    ):
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application", target_value="http://x.test/",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    assert overlap_max["v"] >= 2, (
        f"override should allow concurrent dispatches; "
        f"observed max overlap {overlap_max['v']}"
    )


def test_fanout_bridge_swallows_emission_errors(monkeypatch) -> None:
    """A failing tracer.add_vulnerability_report must not abort the
    fan-out pass — log + continue."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")
    record_endpoint_discovered("http://x.test/case.jsp")
    summary = PrepassSummary(
        target_type="web_application", target_value="http://x.test/",
    )

    class BrokenTracer:
        def add_vulnerability_report(self, **kw: Any) -> str:
            raise RuntimeError("simulated tracer failure")

    monkeypatch.setattr(
        "strix.telemetry.tracer.get_global_tracer",
        lambda: BrokenTracer(),
    )

    async def _fake_exec(*args, **kwargs):
        return {
            "status": "ok",
            "findings": [{"title": "x", "severity": "low", "cwe": "CWE-79"}],
        }

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake_exec),
    ):
        # Must complete without raising.
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application", target_value="http://x.test/",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    # Rollup summary still appended.
    assert any(
        tr.tool_name == "anchor_fanout_summary" for tr in summary.tool_results
    )


# ---------------------------------------------------------------------------
# iter-Q5.34i — classifier-driven URL filter
# ---------------------------------------------------------------------------

from strix.agents.lead_agent.anchor_prepass import (
    _fanout_dedup_key,
    _should_skip_for_fanout,
)


@pytest.mark.parametrize("url,expected_skip,reason_contains", [
    ("http://x.test/main.css", True, "static"),
    ("http://x.test/logo.png", True, "static"),
    ("http://x.test/bundle.js", True, "static"),
    ("http://x.test/admin/delete-user", True, "destructive"),
    ("http://x.test/api/users/123/remove", True, "destructive"),
    ("http://x.test/products?id=1", False, ""),
    ("http://x.test/search?q=foo", False, ""),
    ("http://x.test/wavsep/active/SQL-Injection/Case01.jsp", False, ""),
])
def test_should_skip_classifier(url, expected_skip, reason_contains) -> None:
    skip, reason = _should_skip_for_fanout(url)
    assert skip is expected_skip
    if reason_contains:
        assert reason_contains in reason


def test_dedup_key_collapses_query_values() -> None:
    assert _fanout_dedup_key("http://x.test/p?id=1") == _fanout_dedup_key(
        "http://x.test/p?id=2",
    )


def test_dedup_key_keeps_distinct_param_names() -> None:
    assert _fanout_dedup_key("http://x.test/p?id=1") != _fanout_dedup_key(
        "http://x.test/p?name=foo",
    )


def test_dedup_key_normalizes_trailing_slash() -> None:
    assert _fanout_dedup_key("http://x.test/page/") == _fanout_dedup_key(
        "http://x.test/page",
    )


def test_select_fanout_urls_drops_static_and_dedups(monkeypatch) -> None:
    """End-to-end: a katana-style endpoint list with the typical mix
    of static assets, destructive endpoints, and value-only query
    variations gets filtered down to one row per shape."""
    summary = PrepassSummary(target_type="web_application", target_value="http://x.test/")
    summary.tool_results.append(ToolResult(
        tool_name="crawl_with_katana",
        status="ok",
        raw_result={
            "endpoints": [
                {"url": "http://x.test/products?id=1"},
                {"url": "http://x.test/products?id=2"},      # query-value dup
                {"url": "http://x.test/products?id=3"},      # query-value dup
                {"url": "http://x.test/main.css"},           # static
                {"url": "http://x.test/logo.png"},           # static
                {"url": "http://x.test/admin/delete-user"},  # destructive
                {"url": "http://x.test/search?q=foo"},       # distinct shape
                {"url": "http://x.test/about"},              # distinct shape
            ],
        },
    ))
    urls = _select_fanout_urls("http://x.test/", 50, summary=summary)
    # /products?id (1 shape), /search?q (1 shape), /about (1 shape) = 3 URLs
    assert len(urls) == 3
    # Either /products?id=1 OR ?id=2 OR ?id=3 — depends on sort — but
    # one of the three.
    assert any("products" in u for u in urls)
    assert any("search" in u for u in urls)
    assert any("about" in u for u in urls)
    assert not any(".css" in u for u in urls)
    assert not any(".png" in u for u in urls)
    assert not any("delete-user" in u for u in urls)


# ---------------------------------------------------------------------------
# iter-Q5.34j — per-URL tool routing
# ---------------------------------------------------------------------------

from strix.agents.lead_agent.anchor_prepass import _select_tools_for_url


def _tool_names_for(url: str) -> set[str]:
    return {t for t, _ in _select_tools_for_url(url)}


def test_routing_no_param_no_path_hint_only_nuclei() -> None:
    """URLs with neither params nor SQL/XSS/redirect path hints fall through
    to nuclei only — the broad-template detector that can find CVEs / CSP
    issues / misconfigs without a specific signal."""
    assert _tool_names_for("http://x.test/about") == {"scan_nuclei_templates"}
    assert _tool_names_for("http://x.test/landing.html") == {"scan_nuclei_templates"}


def test_routing_sqli_signal_via_path_and_param() -> None:
    """sqlmap fires when path looks SQLi-ish OR a param name matches the
    typical SQLi-target set (id, username, q, search, msg, ...)."""
    assert "scan_sqli_sqlmap" in _tool_names_for("http://x.test/login")
    assert "scan_sqli_sqlmap" in _tool_names_for("http://x.test/sqli/Case01.jsp?id=1")
    assert "scan_sqli_sqlmap" in _tool_names_for("http://x.test/products?id=1")
    assert "scan_sqli_sqlmap" in _tool_names_for("http://x.test/search?q=foo")


def test_routing_xss_signal_excludes_id_only_urls() -> None:
    """dalfox skips URLs whose only param is a numeric ID — those won't
    reflect text. It does fire on any text-shaped param."""
    assert "scan_xss_dalfox" not in _tool_names_for("http://x.test/p?id=1")
    assert "scan_xss_dalfox" in _tool_names_for("http://x.test/p?q=hello")
    assert "scan_xss_dalfox" in _tool_names_for("http://x.test/p?msg=foo")


def test_routing_redirect_signal_via_url_shaped_param() -> None:
    """open-redirect runs when a redirect-shaped param appears, OR when
    the path hints redirect (/redirect/, /sso/, /oauth/)."""
    assert "open_redirect_check" in _tool_names_for("http://x.test/r?url=foo")
    assert "open_redirect_check" in _tool_names_for("http://x.test/r?next=/dash")
    assert "open_redirect_check" in _tool_names_for("http://x.test/oauth/callback")
    assert "open_redirect_check" not in _tool_names_for("http://x.test/products?id=1")


def test_routing_lfi_url_only_gets_nuclei() -> None:
    """An LFI-shaped URL (?file=...) carries no SQLi/XSS/redirect signal —
    only nuclei (which has LFI templates) runs. Verifies we don't waste
    sqlmap/dalfox cycles."""
    tools = _tool_names_for("http://x.test/view?file=safe.html")
    assert tools == {"scan_nuclei_templates"}


def test_routing_static_url_still_only_nuclei() -> None:
    """A URL that survived the Q5.34i classifier filter but has no signal
    falls through to nuclei alone — safer than dropping it entirely."""
    tools = _tool_names_for("http://x.test/landing")
    assert tools == {"scan_nuclei_templates"}


def test_routing_ablation_via_env(monkeypatch) -> None:
    """STRIX_ANCHOR_FANOUT_ROUTING=0 disables routing — every tool fires
    against every URL, restoring the iter-Q5.34e contract. Used by
    benchmark ablation runs that want to measure the routing's effect."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT_ROUTING", "0")
    tools = _tool_names_for("http://x.test/about")  # nothing routes to this normally
    # All 4 specialists are returned.
    assert tools == {
        "scan_sqli_sqlmap", "scan_xss_dalfox",
        "open_redirect_check", "scan_nuclei_templates",
    }


def test_routing_savings_surfaced_in_rollup(monkeypatch) -> None:
    """The anchor_fanout_summary tool_result must surface
    `routing_enabled`, `baseline_dispatches`, `actual_dispatches`, and
    `savings_pct` so the bench markdown can show 'we saved X% of
    sandbox calls' rather than just the raw run."""
    monkeypatch.setenv("STRIX_ANCHOR_FANOUT", "1")
    record_endpoint_discovered("http://x.test/about")        # 1 tool: nuclei
    record_endpoint_discovered("http://x.test/login")        # 2 tools: sqlmap + nuclei
    record_endpoint_discovered("http://x.test/search?q=foo") # 3 tools
    summary = PrepassSummary(
        target_type="web_application", target_value="http://x.test/seed",
    )

    async def _fake(*args, **kwargs):
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake),
    ):
        asyncio.run(_fanout_deep_specialists_across_endpoints(
            summary, target_type="web_application",
            target_value="http://x.test/seed",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    rollup = [
        tr for tr in summary.tool_results
        if tr.tool_name == "anchor_fanout_summary"
    ]
    assert len(rollup) == 1
    raw = rollup[0].raw_result
    assert raw["routing_enabled"] is True
    # 3 URLs × 4 tools = 12 baseline; routing trims it.
    assert raw["baseline_dispatches"] == 12
    assert raw["actual_dispatches"] < 12, (
        f"routing should drop dispatches; got actual={raw['actual_dispatches']}"
    )
    assert 0 < raw["savings_pct"] <= 100
