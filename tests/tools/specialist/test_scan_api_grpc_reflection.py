"""Tests for `scan_api_grpc_reflection`."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.specialist.scan_api_grpc_reflection import (
    _looks_grpc_response,
    scan_api_grpc_reflection,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_GRPC_REFLECTION_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_looks_grpc_response_via_content_type() -> None:
    assert _looks_grpc_response(
        status_code=200,
        headers={"content-type": "application/grpc"},
    ) is True


def test_looks_grpc_response_via_content_type_proto() -> None:
    assert _looks_grpc_response(
        status_code=200,
        headers={"Content-Type": "application/grpc+proto"},
    ) is True


def test_looks_grpc_response_via_grpc_status_header() -> None:
    """Some servers return 200 with empty body + grpc-status trailer."""
    assert _looks_grpc_response(
        status_code=200,
        headers={"grpc-status": "0"},
    ) is True


def test_looks_grpc_response_negative() -> None:
    assert _looks_grpc_response(
        status_code=200,
        headers={"content-type": "text/html"},
    ) is False
    assert _looks_grpc_response(
        status_code=404, headers={},
    ) is False


# ---------------------------------------------------------------------------
# Native-gRPC path
# ---------------------------------------------------------------------------


def test_native_reflection_enumerates_services() -> None:
    """When the native dispatcher returns a service list, emit
    a medium finding with the count."""
    def fake_dispatcher(*, host, port, use_tls, timeout):
        return [
            "grpc.reflection.v1.ServerReflection",
            "shop.OrderService",
            "shop.PaymentService",
        ]

    result = scan_api_grpc_reflection(
        url="https://grpc.example.com:443",
        _native_dispatcher=fake_dispatcher,
    )
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["severity"] == "medium"
    assert "3 services" in f["title"]
    assert result["tool_metadata"]["detection_path"] == "native_grpc"


def test_native_returns_none_falls_back_to_http_probe() -> None:
    """When grpc isn't installed (dispatcher returns None), the
    HTTP-shape probe runs as fallback."""
    def fake_http_probe(*, url, path, timeout, extra_headers):
        return 200, {"content-type": "application/grpc"}, ""

    result = scan_api_grpc_reflection(
        url="https://grpc.example.com:443",
        _native_dispatcher=lambda **k: None,
        _http_probe=fake_http_probe,
    )
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["severity"] == "info"
    assert result["tool_metadata"]["detection_path"] == "http_shape"


# ---------------------------------------------------------------------------
# HTTP-shape probe
# ---------------------------------------------------------------------------


def test_http_probe_detects_grpc_response() -> None:
    def fake_http_probe(*, url, path, timeout, extra_headers):
        return 200, {"content-type": "application/grpc+proto"}, ""

    result = scan_api_grpc_reflection(
        url="https://api.example.com:443",
        _native_dispatcher=lambda **k: None,
        _http_probe=fake_http_probe,
    )
    assert len(result["findings"]) == 1
    assert result["tool_metadata"]["detection_path"] == "http_shape"
    assert result["tool_metadata"]["reflection_path"].startswith(
        "/grpc.reflection",
    )


def test_http_probe_returns_no_finding_on_404() -> None:
    def fake_http_probe(*, url, path, timeout, extra_headers):
        return 404, {}, ""

    result = scan_api_grpc_reflection(
        url="https://api.example.com:443",
        _native_dispatcher=lambda **k: None,
        _http_probe=fake_http_probe,
    )
    assert result["findings"] == []
    assert result["tool_metadata"]["detection_path"] == "none"


def test_http_probe_tries_v1_then_v1alpha() -> None:
    """The v1 reflection path is tried first; v1alpha as fallback."""
    paths_seen: list[str] = []

    def fake_http_probe(*, url, path, timeout, extra_headers):
        paths_seen.append(path)
        # Only v1alpha responds gRPC-shaped — v1 returns 404.
        if "v1alpha" in path:
            return 200, {"content-type": "application/grpc"}, ""
        return 404, {}, ""

    scan_api_grpc_reflection(
        url="https://api.example.com:443",
        _native_dispatcher=lambda **k: None,
        _http_probe=fake_http_probe,
    )
    # Both paths probed, v1 first.
    assert paths_seen == [
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    ]


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


def test_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_GRPC_REFLECTION_DISABLED", "1")
    result = scan_api_grpc_reflection(
        url="https://api.example.com:443",
    )
    assert result["status"] == "error"
    assert "kill_switch" in result["error"]


def test_invalid_url_scheme() -> None:
    result = scan_api_grpc_reflection(url="ftp://example.com")
    assert result["status"] == "error"


def test_empty_url() -> None:
    result = scan_api_grpc_reflection(url="")
    assert result["status"] == "error"
