"""iter-Q5.43 — tests for ip_address per-port routing helpers.

Hermetic — only the pure helpers (port → tags + port → URL). The
integration with `_run_dependent_ip_tools` is exercised by the broader
anchor_prepass tests."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest import mock

import pytest

from strix.agents.lead_agent.anchor_prepass import (
    PrepassSummary,
    ToolResult,
    _IP_HTTP_PORTS,
    _IP_PORT_TO_NUCLEI_TAGS,
    _ip_port_routing_enabled,
    _nuclei_tags_for_port,
    _nuclei_url_for_port,
    _run_dependent_ip_tools,
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_IP_PORT_ROUTING", raising=False)


# ---------------------------------------------------------------------------
# Port → tags
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("port,expected_tag", [
    (21,    "ftp"),
    (22,    "ssh"),
    (25,    "smtp"),
    (53,    "dns"),
    (80,    "http"),
    (443,   "https"),
    (3306,  "mysql"),
    (5432,  "postgres"),
    (6379,  "redis"),
    (9200,  "elastic"),
    (27017, "mongodb"),
    (8080,  "tomcat"),       # 8080 is the canonical Tomcat / Jenkins port
])
def test_nuclei_tags_carry_expected_service(port, expected_tag) -> None:
    tags = _nuclei_tags_for_port(port)
    assert expected_tag in tags, (
        f"port {port} should produce '{expected_tag}' tag; got {tags!r}"
    )


def test_nuclei_tags_unknown_port_returns_empty() -> None:
    """Ports not in the table return [] — the caller skips dispatch
    (no need to fire nuclei without a tag-filter)."""
    assert _nuclei_tags_for_port(12345) == []
    assert _nuclei_tags_for_port(0) == []
    assert _nuclei_tags_for_port(65535) == []


def test_nuclei_tags_for_443_includes_tls_family() -> None:
    """HTTPS ports get tls/ssl tags so cert + handshake templates fire."""
    tags = _nuclei_tags_for_port(443)
    assert "https" in tags
    assert "tls" in tags or "ssl" in tags


def test_port_to_tags_table_covers_common_ports() -> None:
    """Anti-regression: every port in _IP_COMMON_PORTS should have a
    nuclei tag entry. Catches additions to one list without the other."""
    from strix.agents.lead_agent.anchor_prepass import _IP_COMMON_PORTS
    missing = [p for p in _IP_COMMON_PORTS if p not in _IP_PORT_TO_NUCLEI_TAGS]
    assert missing == [], (
        f"_IP_COMMON_PORTS has ports without a Q5.43 tag mapping: "
        f"{missing}. Add an entry to _IP_PORT_TO_NUCLEI_TAGS."
    )


# ---------------------------------------------------------------------------
# Port → URL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("port,host,expected", [
    (80,    "10.0.0.1",      "http://10.0.0.1:80/"),
    (8080,  "10.0.0.1",      "http://10.0.0.1:8080/"),
    (8000,  "ex.com",         "http://ex.com:8000/"),
    (443,   "10.0.0.1",      "https://10.0.0.1:443/"),
    (8443,  "10.0.0.1",      "https://10.0.0.1:8443/"),
    # Non-HTTP ports: bare host:port (nuclei network templates)
    (22,    "10.0.0.1",      "10.0.0.1:22"),
    (6379,  "10.0.0.1",      "10.0.0.1:6379"),
    (3306,  "10.0.0.1",      "10.0.0.1:3306"),
])
def test_nuclei_url_construction(port, host, expected) -> None:
    assert _nuclei_url_for_port(host, port) == expected


def test_nuclei_url_lowercases_host() -> None:
    """nuclei expects lower-cased hostnames in URL form."""
    assert _nuclei_url_for_port("EXAMPLE.COM", 80) == "http://example.com:80/"


# ---------------------------------------------------------------------------
# Env knob
# ---------------------------------------------------------------------------


def test_port_routing_enabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_IP_PORT_ROUTING", raising=False)
    assert _ip_port_routing_enabled() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off"])
def test_port_routing_disabled_via_falsy_env(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_IP_PORT_ROUTING", val)
    assert _ip_port_routing_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "TRUE"])
def test_port_routing_explicit_truthy_env(monkeypatch, val) -> None:
    monkeypatch.setenv("STRIX_IP_PORT_ROUTING", val)
    assert _ip_port_routing_enabled() is True


# ---------------------------------------------------------------------------
# End-to-end: per-port nuclei dispatch
# ---------------------------------------------------------------------------


def test_run_dependent_ip_tools_dispatches_nuclei_per_port(monkeypatch) -> None:
    """When 3 distinct service ports are open, nuclei should fire 3
    times with the right tags + URL form per port."""
    summary = PrepassSummary(
        target_type="ip_address", target_value="10.0.0.1",
    )

    nuclei_calls: list[dict[str, Any]] = []

    async def _fake_execute_tool(tool_name: str, *, agent_state, **kwargs):
        if tool_name == "probe_open_tcp_ports":
            return {"status": "ok", "open_ports": [22, 80, 6379]}
        if tool_name == "scan_nuclei_templates":
            nuclei_calls.append(kwargs)
            return {"status": "ok", "findings": []}
        # Quiet stubs for the other per-port specialists.
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake_execute_tool),
    ):
        asyncio.run(_run_dependent_ip_tools(
            summary, target_value="10.0.0.1",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    # 3 nuclei dispatches (one per open service port we have tags for).
    assert len(nuclei_calls) == 3
    by_url = {c["url"]: c.get("tags", []) for c in nuclei_calls}

    # SSH: bare host:port + ssh tags
    assert "10.0.0.1:22" in by_url
    assert "ssh" in by_url["10.0.0.1:22"]
    # HTTP: full URL + http tags
    assert "http://10.0.0.1:80/" in by_url
    assert "http" in by_url["http://10.0.0.1:80/"]
    # Redis: bare host:port + redis tags
    assert "10.0.0.1:6379" in by_url
    assert "redis" in by_url["10.0.0.1:6379"]

    # Each tool_result was recorded with the per-port label.
    nuclei_results = [
        r for r in summary.tool_results
        if r.tool_name.startswith("scan_nuclei_templates[port-")
    ]
    assert {r.tool_name for r in nuclei_results} == {
        "scan_nuclei_templates[port-22]",
        "scan_nuclei_templates[port-80]",
        "scan_nuclei_templates[port-6379]",
    }


def test_run_dependent_ip_tools_ablation_disables_per_port_nuclei(monkeypatch) -> None:
    """STRIX_IP_PORT_ROUTING=0 → single nuclei call without tag filter."""
    monkeypatch.setenv("STRIX_IP_PORT_ROUTING", "0")
    summary = PrepassSummary(
        target_type="ip_address", target_value="10.0.0.1",
    )

    nuclei_calls: list[dict[str, Any]] = []

    async def _fake(tool_name: str, *, agent_state, **kwargs):
        if tool_name == "probe_open_tcp_ports":
            return {"status": "ok", "open_ports": [22, 80, 6379]}
        if tool_name == "scan_nuclei_templates":
            nuclei_calls.append(kwargs)
            return {"status": "ok", "findings": []}
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake),
    ):
        asyncio.run(_run_dependent_ip_tools(
            summary, target_value="10.0.0.1",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    # Ablation: ONE nuclei dispatch, no tag filter.
    assert len(nuclei_calls) == 1
    assert "tags" not in nuclei_calls[0]
    # Recorded as the ablation label.
    assert any(
        r.tool_name == "scan_nuclei_templates[ablation]"
        for r in summary.tool_results
    )


def test_run_dependent_ip_tools_skips_nuclei_when_no_open_ports(monkeypatch) -> None:
    """When no ports are open, no nuclei dispatches — early return."""
    summary = PrepassSummary(
        target_type="ip_address", target_value="10.0.0.1",
    )

    nuclei_calls: list[dict[str, Any]] = []

    async def _fake(tool_name: str, *, agent_state, **kwargs):
        if tool_name == "probe_open_tcp_ports":
            return {"status": "ok", "open_ports": []}
        if tool_name == "scan_nuclei_templates":
            nuclei_calls.append(kwargs)
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake),
    ):
        asyncio.run(_run_dependent_ip_tools(
            summary, target_value="10.0.0.1",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    assert nuclei_calls == []


def test_run_dependent_ip_tools_unrouted_port_not_dispatched(monkeypatch) -> None:
    """An open port without a tag mapping (e.g. some custom port 12345)
    doesn't trigger nuclei — the caller logs unrouted and moves on."""
    summary = PrepassSummary(
        target_type="ip_address", target_value="10.0.0.1",
    )

    nuclei_calls: list[dict[str, Any]] = []

    async def _fake(tool_name: str, *, agent_state, **kwargs):
        if tool_name == "probe_open_tcp_ports":
            return {"status": "ok", "open_ports": [12345]}
        if tool_name == "scan_nuclei_templates":
            nuclei_calls.append(kwargs)
        return {"status": "ok", "findings": []}

    with mock.patch(
        "strix.tools.executor.execute_tool",
        new=mock.AsyncMock(side_effect=_fake),
    ):
        asyncio.run(_run_dependent_ip_tools(
            summary, target_value="10.0.0.1",
            agent_state=mock.MagicMock(), timeout_s=10,
        ))

    assert nuclei_calls == [], (
        "Unrouted port should not trigger nuclei (no tag-filter to apply)"
    )
