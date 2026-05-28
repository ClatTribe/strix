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
    """With 2 URLs and 5 fan-out specialists (post-Q6.3), expect 10
    dispatches."""
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

    # iter-Q6.3 — 5 specialists × 2 URLs = 10 dispatches.
    assert mocked.call_count == 5 * 2

    # Per-specialist kwarg shape check.
    target_url_tools = {"scan_sqli_sqlmap", "scan_xss_dalfox", "open_redirect_check"}
    url_tools = {"scan_nuclei_templates", "scan_path_traversal"}
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
    assert len(fanout_results) == 10
    # Each carried findings=1, so total_findings += 10.
    assert summary.total_findings == 10
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

    # iter-Q6.3 — 5 specialists × 3 URLs = 15 dispatches.
    assert mocked.call_count == 5 * 3


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

    # iter-Q6.3 — 5 specialists × 1 URL = 5 dispatches → 5 bridged
    # tracer emissions.
    assert len(emissions) == 5, f"expected 5 emissions, got {len(emissions)}"

    # Each tracer call must carry the expected core fields.
    for em in emissions:
        assert "title" in em
        assert "severity" in em
        assert em["endpoint"] == "http://x.test/case1.jsp"
        assert "cwe" in em
        # category should fall back to per-tool hint when not in finding.
        # iter-Q6.3 adds `path_traversal` to the allowed set.
        assert em.get("category") in (
            "sqli", "xss", "redirect", "path_traversal", "vulnerability",
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
    typical SQLi-target set (id, username, q, search, msg, ...).

    iter-Q5.34k carved /login etc. out of the SQLi path-hint list —
    sqlmap aggression on credential forms triggers account lockout. See
    test_routing_login_protection."""
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


def test_routing_lfi_url_gets_path_traversal_and_nuclei() -> None:
    """iter-Q6.3 — an LFI-shaped URL (?file=...) routes to BOTH
    scan_path_traversal (deep deterministic LFI specialist) AND nuclei
    (template-based corroboration). Pre-Q6.3 only nuclei fired and the
    WAVSEP LFI sub-corpus (824 cases — biggest single category) got 0
    recall. Verifies sqlmap/dalfox/open_redirect still don't waste
    cycles on a non-injection-shape URL."""
    tools = _tool_names_for("http://x.test/view?file=safe.html")
    assert tools == {"scan_path_traversal", "scan_nuclei_templates"}


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
    # iter-Q6.3 — all 5 specialists are returned (the 4-tool fallback
    # is now 5 with scan_path_traversal added).
    assert tools == {
        "scan_sqli_sqlmap", "scan_xss_dalfox",
        "open_redirect_check", "scan_path_traversal",
        "scan_nuclei_templates",
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
    # iter-Q6.3 — 3 URLs × 5 tools = 15 baseline; routing trims it.
    assert raw["baseline_dispatches"] == 15
    assert raw["actual_dispatches"] < 15, (
        f"routing should drop dispatches; got actual={raw['actual_dispatches']}"
    )
    assert 0 < raw["savings_pct"] <= 100


# ---------------------------------------------------------------------------
# iter-Q5.34k — scope, path-shape dedup, login protection
# ---------------------------------------------------------------------------

from strix.agents.lead_agent.anchor_prepass import (
    _fanout_dedup_key,
    _in_scope,
    _is_login_url,
    _normalize_host,
    _path_shape,
)


# ----- path shape -----

@pytest.mark.parametrize("path,expected", [
    ("/items/1", "/items/:int"),
    ("/items/42", "/items/:int"),
    ("/items/9999", "/items/:int"),
    ("/posts/2024-01-31/recap", "/posts/:date/recap"),
    ("/users/01234567-89ab-cdef-0123-456789abcdef/profile",
     "/users/:uuid/profile"),
    ("/cache/d41d8cd98f00b204e9800998ecf8427e", "/cache/:hash"),
    # Real path names (mixed letters / words) — kept as-is.
    ("/products/iphone-15", "/products/iphone-15"),
    ("/wavsep/active/SQL-Injection/Case01.jsp",
     "/wavsep/active/SQL-Injection/Case01.jsp"),
    ("/", "/"),
    ("", "/"),
])
def test_path_shape_normalization(path, expected) -> None:
    assert _path_shape(path) == expected


def test_dedup_key_collapses_numeric_id_paths() -> None:
    """`/items/1`, `/items/2`, ..., `/items/N` → one dedup bucket. The
    single biggest waste on catalog-style apps."""
    assert _fanout_dedup_key("http://x.test/items/1") == _fanout_dedup_key(
        "http://x.test/items/9999",
    )


def test_dedup_key_keeps_distinct_path_names() -> None:
    """Real path names (not placeholders) must stay distinct so
    `/products/iphone-15` and `/products/samsung-galaxy` don't get
    collapsed into one probe."""
    assert _fanout_dedup_key("http://x.test/products/iphone-15") != _fanout_dedup_key(
        "http://x.test/products/samsung-galaxy",
    )


def test_dedup_key_collapses_uuid_paths() -> None:
    """UUID-shaped path segments collapse to `:uuid`."""
    a = _fanout_dedup_key("http://x.test/users/01234567-89ab-cdef-0123-456789abcdef")
    b = _fanout_dedup_key("http://x.test/users/fedcba98-7654-3210-fedc-ba9876543210")
    assert a == b


# ----- scope -----

@pytest.mark.parametrize("seed,url,expected", [
    # Exact host.
    ("getedunext.com", "https://getedunext.com/about", True),
    # www-normalized.
    ("getedunext.com", "https://www.getedunext.com/", True),
    ("www.getedunext.com", "https://getedunext.com/", True),
    # Subdomains.
    ("getedunext.com", "https://app.getedunext.com/dash", True),
    ("getedunext.com", "https://api.getedunext.com/v1/u", True),
    # Out-of-scope.
    ("getedunext.com", "https://twitter.com/share", False),
    ("getedunext.com", "https://gettedunext.com/typo", False),
    ("getedunext.com", "https://cdn.fastly.net/img.jpg", False),
    # Bench-fixture conventions always in-scope.
    ("getedunext.com", "http://localhost:8080/x", True),
    ("getedunext.com", "http://127.0.0.1/y", True),
    ("getedunext.com", "http://host.docker.internal/z", True),
])
def test_in_scope_default_policy(seed, url, expected) -> None:
    assert _in_scope(url, _normalize_host(seed)) is expected


def test_in_scope_extra_hosts_env(monkeypatch) -> None:
    """`STRIX_ANCHOR_FANOUT_SCOPE_HOSTS` whitelists extra hostnames."""
    monkeypatch.setenv(
        "STRIX_ANCHOR_FANOUT_SCOPE_HOSTS", "edge.cloudfront.net, partner.io",
    )
    assert _in_scope("https://edge.cloudfront.net/asset", "getedunext.com") is True
    assert _in_scope("https://partner.io/api", "getedunext.com") is True
    assert _in_scope("https://other.cdn.net/x", "getedunext.com") is False


def test_in_scope_no_seed_lets_through() -> None:
    """Empty seed host (uncommon — fan-out called without target context)
    treats all URLs as in-scope to avoid silently dropping everything."""
    assert _in_scope("https://x.com/", "") is True


def test_select_fanout_urls_drops_out_of_scope() -> None:
    """End-to-end: katana-style endpoint list with off-host links is
    filtered to in-scope-only URLs."""
    summary = PrepassSummary(
        target_type="web_application",
        target_value="https://getedunext.com/landing",
    )
    summary.tool_results.append(ToolResult(
        tool_name="crawl_with_katana", status="ok",
        raw_result={
            "endpoints": [
                {"url": "https://getedunext.com/about"},
                {"url": "https://app.getedunext.com/dashboard"},
                {"url": "https://twitter.com/share"},
                {"url": "https://cdn.fastly.net/banner.jpg"},
                {"url": "https://getedunext.com/contact"},
            ],
        },
    ))
    urls = _select_fanout_urls("https://getedunext.com/landing", 50, summary=summary)
    # 3 in-scope (about, app.x, contact); twitter and cdn dropped.
    assert len(urls) == 3
    for u in urls:
        assert ("getedunext.com" in u) or ("localhost" in u)
    assert not any("twitter" in u for u in urls)
    assert not any("cdn.fastly" in u for u in urls)


# ----- login -----

@pytest.mark.parametrize("url,expected", [
    ("http://x.test/login", True),
    ("http://x.test/signin", True),
    ("http://x.test/sign-in", True),
    ("http://x.test/auth/login", True),
    ("http://x.test/account/login", True),
    ("http://x.test/users/sign_in", True),
    ("http://x.test/sessions/new", True),
    # Not login.
    ("http://x.test/products?id=1", False),
    ("http://x.test/sqli/case01.jsp", False),
    ("http://x.test/admin/dashboard", False),
])
def test_is_login_url(url, expected) -> None:
    assert _is_login_url(url) is expected


def test_routing_login_protection() -> None:
    """Login URLs route to nuclei ONLY. sqlmap aggression on credential
    forms triggers account lockout / CAPTCHA — real auth bypass goes
    through scan_auth_flow + probe_default_creds (separate anchor
    tools, not fan-out's per-URL probing)."""
    tools = _tool_names_for("http://x.test/login?username=foo&password=bar")
    assert tools == {"scan_nuclei_templates"}
    tools = _tool_names_for("http://x.test/account/login")
    assert tools == {"scan_nuclei_templates"}
    tools = _tool_names_for("http://x.test/users/sign_in")
    assert tools == {"scan_nuclei_templates"}


# ---------------------------------------------------------------------------
# iter-Q6.2 — per-category proportional quota in _select_fanout_urls
# ---------------------------------------------------------------------------
#
# The Q5.34l WAVSEP bench at limit=200 found 0 Unvalidated-Redirect URLs
# reached the fan-out because alphabetical sort placed them last and the
# limit truncated the slice. Per-category round-robin fixes this — every
# distinct URL family gets at least one slot before any single family
# fills the rest.

from strix.agents.lead_agent.anchor_prepass import (  # noqa: E402
    _fanout_category_key,
)


class TestFanoutCategoryKey:
    """`_fanout_category_key` — the bucket key for round-robin selection."""

    def test_strips_leaf_segment(self):
        assert _fanout_category_key(
            "http://x/a/b/c/leaf.jsp",
        ) == "/a/b/c"

    def test_single_segment_path_collapses_to_root(self):
        """`/login`, `/p00` — too shallow to have a parent."""
        assert _fanout_category_key("http://x/login") == "/"
        assert _fanout_category_key("http://x/p00") == "/"

    def test_root_path(self):
        assert _fanout_category_key("http://x/") == "/"
        assert _fanout_category_key("http://x") == "/"

    def test_lowercased(self):
        """Categories that differ only by case should bucket together."""
        a = _fanout_category_key("http://x/Wavsep/Active/SQL-Injection/Case01.jsp")
        b = _fanout_category_key("http://x/wavsep/active/sql-injection/Case02.jsp")
        assert a == b == "/wavsep/active/sql-injection"

    def test_query_ignored(self):
        a = _fanout_category_key("http://x/a/b/c.jsp")
        b = _fanout_category_key("http://x/a/b/c.jsp?x=1")
        assert a == b


class TestFanoutCategoryQuota:
    """`_select_fanout_urls` round-robin: every category surfaces at
    least one URL before any category monopolises slots."""

    def test_wavsep_shape_all_5_categories_represented(self):
        """The Q5.34l regression case: with limit=20 and a WAVSEP-like
        landing page (5 categories, hundreds of cases each), every
        category MUST have at least one URL in the fan-out output.

        Pre-Q6.2, alphabetical sort + cap-at-limit dropped late-alphabet
        categories entirely."""
        # Categories sorted alphabetically — late ones (Unvalidated-Redirect)
        # would be truncated under the old logic.
        categories = [
            "DOM-XSS", "LFI", "Reflected-XSS",
            "SQL-Injection", "Unvalidated-Redirect",
        ]
        for cat in categories:
            for i in range(50):
                record_endpoint_discovered(
                    f"http://x.test/wavsep/active/{cat}/Sub/Case{i:02d}.jsp",
                )
        urls = _select_fanout_urls("http://x.test", 20)
        assert len(urls) == 20
        # Every category must contribute at least 1 URL.
        cats_seen = {
            url.split("/wavsep/active/")[1].split("/")[0].lower()
            for url in urls
        }
        expected_cats = {c.lower() for c in categories}
        missing = expected_cats - cats_seen
        assert not missing, (
            f"Q6.2 quota failed — categories missing from fan-out: {missing}"
        )

    def test_round_robin_balanced_distribution(self):
        """With 5 categories × 50 URLs each and limit=15, every category
        should get exactly 3 URLs (perfect round-robin)."""
        categories = ["alpha", "beta", "gamma", "delta", "epsilon"]
        for cat in categories:
            for i in range(50):
                record_endpoint_discovered(
                    f"http://x.test/{cat}/sub/case{i:02d}.html",
                )
        urls = _select_fanout_urls("http://x.test", 15)
        # 15 / 5 = 3 per category exactly.
        per_cat: dict[str, int] = {}
        for url in urls:
            cat = url.split("/")[3]
            per_cat[cat] = per_cat.get(cat, 0) + 1
        assert sum(per_cat.values()) == 15
        for cat in categories:
            assert per_cat[cat] == 3, (
                f"{cat} got {per_cat[cat]} URLs, expected 3"
            )

    def test_uneven_buckets_proportional_fall_through(self):
        """When buckets are uneven, round-robin drains the small one
        first then keeps cycling the remaining ones to fill the limit."""
        # Small: 2 URLs; Big: 50 URLs; limit=10
        record_endpoint_discovered("http://x.test/small/a/1.html")
        record_endpoint_discovered("http://x.test/small/a/2.html")
        for i in range(50):
            record_endpoint_discovered(f"http://x.test/big/a/{i:02d}.html")
        urls = _select_fanout_urls("http://x.test", 10)
        assert len(urls) == 10
        small = sum(1 for u in urls if "/small/" in u)
        big = sum(1 for u in urls if "/big/" in u)
        assert small == 2   # exhausted
        assert big == 8     # filled the rest

    def test_single_category_falls_back_to_sequential(self):
        """When all URLs share one category, round-robin degenerates to
        sequential — matches pre-Q6.2 behaviour for flat sites."""
        for i in range(20):
            record_endpoint_discovered(f"http://x.test/p{i:02d}")
        urls = _select_fanout_urls("http://x.test", 5)
        assert len(urls) == 5
        # Stable order within a bucket (sorted).
        assert urls == sorted(urls)

    def test_limit_zero_returns_empty(self):
        for i in range(10):
            record_endpoint_discovered(
                f"http://x.test/cat{i}/sub/case.jsp",
            )
        assert _select_fanout_urls("http://x.test", 0) == []

    def test_limit_larger_than_total_returns_all(self):
        """When limit exceeds the total dedupe-clean URL count, we
        return everything without padding."""
        record_endpoint_discovered("http://x.test/a/b/page1.html")
        record_endpoint_discovered("http://x.test/c/d/page2.html")
        urls = _select_fanout_urls("http://x.test", 100)
        assert len(urls) == 2


# Anti-overfit: the Q6.2 category-key function must not reference any
# SUT-specific identifier — it's a generic per-asset quota mechanism.

def test_no_fixture_identifiers_in_q6_2_impl():
    import inspect
    from strix.agents.lead_agent.anchor_prepass import _fanout_category_key
    src = inspect.getsource(_fanout_category_key).lower()
    for ident in ("juice-shop", "vampi", "crapi", "wavsep", "getedunext"):
        assert ident not in src, (
            f"_fanout_category_key references SUT identifier {ident!r}"
        )


# ---------------------------------------------------------------------------
# iter-Q6.3 — path-traversal predicate + fan-out wiring
# ---------------------------------------------------------------------------

from strix.agents.lead_agent.anchor_prepass import (  # noqa: E402
    _has_lfi_signal,
    _PATH_HINTS_LFI,
    _LFI_PARAM_NAMES,
)


class TestLfiSignalPredicate:
    """`_has_lfi_signal` — gates `scan_path_traversal` per-URL routing."""

    def _parse(self, url):
        from urllib.parse import urlparse, parse_qs
        p = urlparse(url)
        return p, set(parse_qs(p.query).keys())

    @pytest.mark.parametrize("url", [
        "http://x/view?file=safe.html",
        "http://x/page?path=docs/intro.md",
        "http://x/include?template=footer.tpl",
        "http://x/get?doc=report.pdf",
        "http://x/render?view=user-profile",
    ])
    def test_lfi_param_matches(self, url):
        p, params = self._parse(url)
        assert _has_lfi_signal(p, params) is True

    @pytest.mark.parametrize("url", [
        "http://x/lfi/Case01-X.jsp",
        "http://x/path-traversal/sub/case.jsp",
        "http://x/files/list",
        "http://x/download/report.pdf",
        "http://x/file/get/123",
        "http://x/docs/api",
    ])
    def test_lfi_path_hint_matches(self, url):
        p, params = self._parse(url)
        assert _has_lfi_signal(p, params) is True

    @pytest.mark.parametrize("url", [
        "http://x/search?q=hello",
        "http://x/login?username=foo",
        "http://x/products?id=42",
        "http://x/about",
        "http://x/static/css/main.css",
    ])
    def test_non_lfi_urls_skipped(self, url):
        p, params = self._parse(url)
        assert _has_lfi_signal(p, params) is False


def test_lfi_routing_includes_path_traversal_and_nuclei():
    """LFI-shape URLs route to scan_path_traversal + scan_nuclei_templates.
    Pre-Q6.3 only nuclei fired on these. The deep specialist is what
    converts hint → finding."""
    tools = _tool_names_for("http://x.test/files/list")
    assert tools == {"scan_path_traversal", "scan_nuclei_templates"}


def test_xss_url_does_not_get_path_traversal():
    """Q6.3 must not over-fire — XSS-shape URLs shouldn't get the
    path-traversal specialist (would waste cycles on each XSS case)."""
    tools = _tool_names_for("http://x.test/search?q=foo")
    assert "scan_path_traversal" not in tools


def test_sqli_url_does_not_get_path_traversal():
    """Same — SQLi-shape URLs don't route to path-traversal."""
    tools = _tool_names_for("http://x.test/products?id=42")
    assert "scan_path_traversal" not in tools


def test_no_fixture_identifiers_in_q6_3_impl():
    """`_has_lfi_signal` + the LFI path hints must not name a single
    bench fixture — predicates are generic per-shape, not per-target."""
    import inspect
    src = inspect.getsource(_has_lfi_signal).lower()
    hints_src = str(_PATH_HINTS_LFI).lower()
    for ident in ("juice-shop", "vampi", "crapi", "wavsep", "getedunext"):
        assert ident not in src, f"_has_lfi_signal references {ident!r}"
        assert ident not in hints_src, f"_PATH_HINTS_LFI contains {ident!r}"
