"""Tests for preflight reachability checks.

Hermetic — DNS resolution and TCP probes are mocked at the
strix.interface.preflight namespace.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from strix.interface import preflight as pf


def _t(target: str, type_: str, **details: Any) -> dict[str, Any]:
    """Build a target_info dict matching what main.py builds."""
    return {"type": type_, "details": details, "original": target}


# ---------------------------------------------------------------------------
# _extract_host
# ---------------------------------------------------------------------------


def test_extract_host_from_web_application() -> None:
    assert pf._extract_host(_t("https://example.com/x", "web_application", target_url="https://example.com/x")) == "example.com"


def test_extract_host_from_bare_domain_target_url() -> None:
    """target_url already includes scheme by the time it reaches preflight."""
    assert pf._extract_host(_t("example.com", "web_application", target_url="https://example.com")) == "example.com"


def test_extract_host_from_ip_address() -> None:
    assert pf._extract_host(_t("192.0.2.1", "ip_address", target_ip="192.0.2.1")) == "192.0.2.1"


def test_extract_host_from_repository_returns_none() -> None:
    assert pf._extract_host(_t("https://github.com/x/y", "repository", target_repo="https://github.com/x/y")) is None


# ---------------------------------------------------------------------------
# _resolve_host
# ---------------------------------------------------------------------------


def test_resolve_host_returns_ip_for_ip_input() -> None:
    """An IP literal is its own resolution — no DNS call."""
    assert pf._resolve_host("8.8.8.8", timeout=3.0) == ["8.8.8.8"]


def test_resolve_host_dns_failure_returns_empty(monkeypatch) -> None:
    def fake_getaddrinfo(*a, **kw):
        raise socket.gaierror("not found")

    monkeypatch.setattr(pf.socket, "getaddrinfo", fake_getaddrinfo)
    assert pf._resolve_host("nx.example.com", timeout=3.0) == []


def test_resolve_host_dedupes_ips(monkeypatch) -> None:
    def fake_getaddrinfo(*a, **kw):
        return [
            (None, None, None, "", ("1.2.3.4", 0)),
            (None, None, None, "", ("1.2.3.4", 0)),
            (None, None, None, "", ("5.6.7.8", 0)),
        ]

    monkeypatch.setattr(pf.socket, "getaddrinfo", fake_getaddrinfo)
    assert pf._resolve_host("multi.example.com", timeout=3.0) == ["1.2.3.4", "5.6.7.8"]


# ---------------------------------------------------------------------------
# preflight_check_target — core paths
# ---------------------------------------------------------------------------


def test_skipped_for_repository(monkeypatch) -> None:
    monkeypatch.setattr(pf, "_resolve_host", lambda h, **kw: pytest.fail("should not resolve"))
    r = pf.preflight_check_target(_t("https://github.com/x/y", "repository", target_repo="..."))
    assert r.status == "skipped"
    assert r.ok is True


def test_skipped_for_local_code(monkeypatch) -> None:
    r = pf.preflight_check_target(_t("/tmp/code", "local_code", target_path="/tmp/code"))
    assert r.status == "skipped"


def test_dns_failed(monkeypatch) -> None:
    monkeypatch.setattr(pf, "_resolve_host", lambda h, **kw: [])
    monkeypatch.setattr(pf, "_tcp_probe", lambda *a, **kw: pytest.fail("should not probe"))
    r = pf.preflight_check_target(_t("https://nx.example.com", "web_application", target_url="https://nx.example.com"))
    assert r.status == "dns_failed"
    assert r.ok is False
    assert "DNS lookup failed" in (r.error or "")


def test_no_open_ports(monkeypatch) -> None:
    monkeypatch.setattr(pf, "_resolve_host", lambda h, **kw: ["1.2.3.4"])
    monkeypatch.setattr(pf, "_tcp_probe", lambda *a, **kw: False)
    r = pf.preflight_check_target(_t("https://example.com", "web_application", target_url="https://example.com"))
    assert r.status == "no_open_ports"
    assert r.resolved_ips == ["1.2.3.4"]
    assert r.ok is False


def test_reachable_first_port_open(monkeypatch) -> None:
    monkeypatch.setattr(pf, "_resolve_host", lambda h, **kw: ["1.2.3.4"])
    # First port (443) accepts.
    monkeypatch.setattr(pf, "_tcp_probe", lambda host, port, **kw: port == 443)
    r = pf.preflight_check_target(_t("https://example.com", "web_application", target_url="https://example.com"))
    assert r.status == "reachable"
    assert r.open_ports == [443]
    assert r.ok is True


def test_reachable_second_port_open(monkeypatch) -> None:
    """First port refuses; second port accepts."""
    monkeypatch.setattr(pf, "_resolve_host", lambda h, **kw: ["1.2.3.4"])
    monkeypatch.setattr(pf, "_tcp_probe", lambda host, port, **kw: port == 80)
    r = pf.preflight_check_target(_t("http://example.com", "web_application", target_url="http://example.com"))
    assert r.status == "reachable"
    assert r.open_ports == [80]


def test_ip_target_uses_ip_port_set(monkeypatch) -> None:
    """ip_address targets probe a wider port set (443, 80, 22, 25)."""
    seen_ports: list[int] = []

    def fake_probe(host: str, port: int, **kw) -> bool:
        seen_ports.append(port)
        return port == 22

    monkeypatch.setattr(pf, "_resolve_host", lambda h, **kw: ["1.2.3.4"])
    monkeypatch.setattr(pf, "_tcp_probe", fake_probe)
    r = pf.preflight_check_target(_t("1.2.3.4", "ip_address", target_ip="1.2.3.4"))
    assert r.status == "reachable"
    assert 22 in seen_ports
    assert r.open_ports == [22]


def test_first_success_wins_no_more_probes(monkeypatch) -> None:
    """When the first port answers, we stop probing — don't waste time."""
    seen_ports: list[int] = []

    def fake_probe(host: str, port: int, **kw) -> bool:
        seen_ports.append(port)
        return True

    monkeypatch.setattr(pf, "_resolve_host", lambda h, **kw: ["1.2.3.4"])
    monkeypatch.setattr(pf, "_tcp_probe", fake_probe)
    pf.preflight_check_target(_t("https://example.com", "web_application", target_url="https://example.com"))
    assert seen_ports == [443]  # only one probe issued


# ---------------------------------------------------------------------------
# preflight_check_targets aggregator
# ---------------------------------------------------------------------------


def test_check_targets_returns_one_result_per_input(monkeypatch) -> None:
    monkeypatch.setattr(pf, "_resolve_host", lambda h, **kw: ["1.2.3.4"])
    monkeypatch.setattr(pf, "_tcp_probe", lambda *a, **kw: True)
    targets = [
        _t("https://a.example.com", "web_application", target_url="https://a.example.com"),
        _t("https://b.example.com", "web_application", target_url="https://b.example.com"),
        _t("/tmp/x", "local_code", target_path="/tmp/x"),
    ]
    results = pf.preflight_check_targets(targets)
    assert len(results) == 3
    assert results[2].status == "skipped"


# ---------------------------------------------------------------------------
# all_network_targets_unreachable
# ---------------------------------------------------------------------------


def test_all_unreachable_with_only_failures() -> None:
    results = [
        pf.PreflightResult("a", "web_application", "dns_failed"),
        pf.PreflightResult("b", "ip_address", "no_open_ports"),
    ]
    assert pf.all_network_targets_unreachable(results) is True


def test_not_all_unreachable_with_one_success() -> None:
    results = [
        pf.PreflightResult("a", "web_application", "dns_failed"),
        pf.PreflightResult("b", "web_application", "reachable", resolved_ips=["1.2.3.4"], open_ports=[443]),
    ]
    assert pf.all_network_targets_unreachable(results) is False


def test_no_network_targets_returns_false() -> None:
    """All-skipped (only code targets) is not 'unreachable' — there's just nothing to probe."""
    results = [pf.PreflightResult("a", "repository", "skipped")]
    assert pf.all_network_targets_unreachable(results) is False


# ---------------------------------------------------------------------------
# render_preflight_panel
# ---------------------------------------------------------------------------


def test_render_panel_includes_each_status() -> None:
    results = [
        pf.PreflightResult("a", "web_application", "reachable", resolved_ips=["1.2.3.4"], open_ports=[443]),
        pf.PreflightResult("b", "web_application", "dns_failed", error="DNS lookup failed for b"),
        pf.PreflightResult("c", "ip_address", "no_open_ports", resolved_ips=["5.6.7.8"]),
        pf.PreflightResult("d", "repository", "skipped"),
    ]
    text = pf.render_preflight_panel(results)
    assert "✓ a" in text
    assert "✗ b" in text
    assert "DNS FAILED" in text
    assert "✗ c" in text
    assert "UNREACHABLE" in text
    assert "skipped" in text
