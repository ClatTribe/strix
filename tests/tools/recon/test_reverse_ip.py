"""Tests for reverse_ip_discovery.

Hermetic — every external call (dig, http_get_text) is mocked.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import reverse_ip as ri


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_VIEWDNS_KEY", raising=False)
    tracer = Tracer("reverse-ip-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_target_rejected() -> None:
    out = ri.reverse_ip_discovery("")
    assert out["success"] is False


def test_invalid_target_rejected() -> None:
    out = ri.reverse_ip_discovery("not a thing")
    assert out["success"] is False


def test_unknown_provider_rejected() -> None:
    out = ri.reverse_ip_discovery("5.5.5.1", providers="hackertarget,bogus")
    assert out["success"] is False
    assert "bogus" in str(out["error"])


# ---------------------------------------------------------------------------
# IP target — direct provider calls
# ---------------------------------------------------------------------------


def test_ip_target_hackertarget_success(monkeypatch) -> None:
    body = "alpha.com\nbeta.com\ngamma.org\n"
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (200, body))
    out = ri.reverse_ip_discovery("5.5.5.1", providers="hackertarget")
    assert out["success"] is True
    assert out["target_type"] == "ip"
    assert out["ips_queried"] == ["5.5.5.1"]
    assert "alpha.com" in out["merged_domains"]
    assert "beta.com" in out["merged_domains"]
    assert out["merged_count"] == 3


def test_hackertarget_rate_limit_returns_no_data(monkeypatch) -> None:
    monkeypatch.setattr(
        ri,
        "_http_get_text",
        lambda url, **kw: (200, "API count exceeded - this is a free service"),
    )
    out = ri.reverse_ip_discovery("5.5.5.2", providers="hackertarget")
    # Tool itself succeeds (it ran), but the provider entry is unsuccessful.
    assert out["success"] is True
    block = out["per_ip_results"][0]["providers"][0]
    assert block["success"] is False
    assert block["error"] == "rate_limited"
    assert out["merged_count"] == 0


def test_hackertarget_error_response(monkeypatch) -> None:
    monkeypatch.setattr(
        ri,
        "_http_get_text",
        lambda url, **kw: (200, "error check your search parameter"),
    )
    out = ri.reverse_ip_discovery("5.5.5.3", providers="hackertarget")
    block = out["per_ip_results"][0]["providers"][0]
    assert block["success"] is False
    assert block["error"] == "no_data"


def test_hackertarget_http_error(monkeypatch) -> None:
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (500, ""))
    out = ri.reverse_ip_discovery("5.5.5.4", providers="hackertarget")
    block = out["per_ip_results"][0]["providers"][0]
    assert block["success"] is False
    assert "http_500" in block["error"]


# ---------------------------------------------------------------------------
# Domain target — resolves first
# ---------------------------------------------------------------------------


def test_domain_target_resolves_then_queries(monkeypatch) -> None:
    monkeypatch.setattr(ri, "dig", lambda *a, **kw: "5.5.5.10\n5.5.5.11")
    monkeypatch.setattr(
        ri, "_http_get_text", lambda url, **kw: (200, "neighbour.com\nexample.com\n")
    )
    out = ri.reverse_ip_discovery("example.com", providers="hackertarget")
    assert out["success"] is True
    assert out["target_type"] == "domain"
    assert out["ips_queried"] == ["5.5.5.10", "5.5.5.11"]
    # The target itself should not appear in the merged neighbour list.
    assert "example.com" not in out["merged_domains"]
    assert "neighbour.com" in out["merged_domains"]


def test_domain_that_does_not_resolve(monkeypatch) -> None:
    monkeypatch.setattr(ri, "dig", lambda *a, **kw: "")
    out = ri.reverse_ip_discovery("nx.example.com", providers="hackertarget")
    assert out["success"] is False
    assert out["error"] == "domain_did_not_resolve"


def test_private_ips_filtered(monkeypatch) -> None:
    """A domain resolving to RFC1918 IPs should be treated as not-resolved
    because we filter private/loopback before querying any external API."""
    monkeypatch.setattr(ri, "dig", lambda *a, **kw: "10.0.0.1\n127.0.0.1")
    out = ri.reverse_ip_discovery("internal.example.com", providers="hackertarget")
    assert out["success"] is False
    assert out["error"] == "domain_did_not_resolve"


def test_max_ips_cap(monkeypatch) -> None:
    """When a domain resolves to many IPs, only the first _MAX_IPS are queried."""
    many = "\n".join(f"5.5.5.{i}" for i in range(1, 30))
    monkeypatch.setattr(ri, "dig", lambda *a, **kw: many)
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (200, ""))
    out = ri.reverse_ip_discovery("multi.example.com", providers="hackertarget")
    assert len(out["ips_queried"]) == ri._MAX_IPS


# ---------------------------------------------------------------------------
# ViewDNS provider (key-gated)
# ---------------------------------------------------------------------------


def test_viewdns_skipped_when_no_key(monkeypatch) -> None:
    """No STRIX_VIEWDNS_KEY → viewdns silently dropped from default-all."""
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (200, ""))
    out = ri.reverse_ip_discovery("5.5.5.5")
    assert out["success"] is True
    assert "viewdns" not in out["providers_queried"]
    assert "hackertarget" in out["providers_queried"]


def test_viewdns_explicit_request_without_key_errors(monkeypatch) -> None:
    """Asking for viewdns by name without the key returns a clear error
    instead of silently dropping it."""
    out = ri.reverse_ip_discovery("5.5.5.6", providers="viewdns")
    assert out["success"] is False
    assert "STRIX_VIEWDNS_KEY" in str(out["error_reason"])


def test_viewdns_with_key_parses_json(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VIEWDNS_KEY", "fake-key")
    payload = (
        '{"response": {"domains": ['
        '{"name": "alpha.com", "last_resolved": "2024-01-01"}, '
        '{"name": "beta.com", "last_resolved": "2024-02-01"}'
        "]}}"
    )
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (200, payload))
    out = ri.reverse_ip_discovery("5.5.5.7", providers="viewdns")
    assert out["success"] is True
    assert "alpha.com" in out["merged_domains"]
    assert "beta.com" in out["merged_domains"]


def test_viewdns_bad_json(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VIEWDNS_KEY", "fake-key")
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (200, "<html>"))
    out = ri.reverse_ip_discovery("5.5.5.8", providers="viewdns")
    block = out["per_ip_results"][0]["providers"][0]
    assert block["success"] is False
    assert block["error"] == "bad_json"


# ---------------------------------------------------------------------------
# Shared-hosting finding
# ---------------------------------------------------------------------------


def test_shared_hosting_threshold_emits_info_finding(monkeypatch) -> None:
    """When >= _SHARED_HOSTING_THRESHOLD co-tenants found, emit an info finding."""
    domains = "\n".join(f"co{i}.com" for i in range(10))
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (200, domains))
    out = ri.reverse_ip_discovery("5.5.5.20", providers="hackertarget")
    assert out["merged_count"] == 10
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "info"
    assert reports[0]["category"] == "info_disclosure"
    assert "Shared hosting" in reports[0]["title"]


def test_below_threshold_no_finding(monkeypatch) -> None:
    """A small co-tenant count (< threshold) should not emit a finding."""
    monkeypatch.setattr(
        ri, "_http_get_text", lambda url, **kw: (200, "one.com\ntwo.com\n")
    )
    out = ri.reverse_ip_discovery("5.5.5.21", providers="hackertarget")
    assert out["merged_count"] == 2
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_max_results_per_ip_cap(monkeypatch) -> None:
    """A flood of co-tenants gets capped at _MAX_RESULTS_PER_IP per IP."""
    huge = "\n".join(f"d{i}.com" for i in range(1000))
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (200, huge))
    out = ri.reverse_ip_discovery("5.5.5.22", providers="hackertarget")
    block = out["per_ip_results"][0]["providers"][0]
    assert len(block["domains"]) == ri._MAX_RESULTS_PER_IP


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_emits_one_check_per_ip_per_provider(monkeypatch) -> None:
    monkeypatch.setattr(ri, "_http_get_text", lambda url, **kw: (200, ""))
    ri.reverse_ip_discovery("5.5.5.30", providers="hackertarget")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "reverse_ip" in summary["by_category"]
