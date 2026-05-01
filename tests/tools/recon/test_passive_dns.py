"""Tests for passive_dns_history."""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import passive_dns


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
    monkeypatch.delenv("STRIX_KEV_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    monkeypatch.delenv("STRIX_SECURITYTRAILS_KEY", raising=False)
    monkeypatch.delenv("STRIX_VIRUSTOTAL_KEY", raising=False)
    tracer = Tracer("pdns-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def test_no_keys_fails_open() -> None:
    out = passive_dns.passive_dns_history("example.com")
    assert out["success"] is False
    assert "no api keys" in out["error_reason"].lower()


def test_invalid_domain_rejected(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SECURITYTRAILS_KEY", "fake-key")
    out = passive_dns.passive_dns_history("not a domain")
    assert out["success"] is False


def test_securitytrails_provider_path(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SECURITYTRAILS_KEY", "test-key")

    fake_history_response = {
        "records": [
            {
                "first_seen": "2020-01-01",
                "last_seen": "2020-12-31",
                "values": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}],
            }
        ]
    }
    fake_subs_response = {
        "subdomains": ["api", "blog", "old-internal"],
    }

    def fake_get(url: str, **_: Any) -> tuple[int, dict[str, Any] | None]:
        if "history/example.com/dns/a" in url:
            return 200, fake_history_response
        if "subdomains" in url:
            return 200, fake_subs_response
        return 404, None

    monkeypatch.setattr(passive_dns, "_http_get_json", fake_get)

    out = passive_dns.passive_dns_history("example.com")
    assert out["success"] is True
    assert out["providers_queried"] == ["securitytrails"]
    assert any(r["ip"] == "1.2.3.4" for r in out["merged_resolutions"])
    assert "api.example.com" in out["merged_subdomains"]
    assert "old-internal.example.com" in out["merged_subdomains"]
    assert out["merged_subdomain_count"] == 3


def test_virustotal_fallback_when_st_missing(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_VIRUSTOTAL_KEY", "test-vt")

    def fake_get(url: str, **_: Any) -> tuple[int, dict[str, Any] | None]:
        if "/resolutions" in url:
            return 200, {
                "data": [
                    {"attributes": {"ip_address": "1.1.1.1", "date": 1700000000}},
                ]
            }
        if "/subdomains" in url:
            return 200, {"data": [{"id": "vt-sub.example.com"}]}
        return 404, None

    monkeypatch.setattr(passive_dns, "_http_get_json", fake_get)

    out = passive_dns.passive_dns_history("example.com")
    assert out["success"] is True
    assert out["providers_queried"] == ["virustotal"]
    assert "vt-sub.example.com" in out["merged_subdomains"]


def test_both_keys_queries_both(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SECURITYTRAILS_KEY", "k1")
    monkeypatch.setenv("STRIX_VIRUSTOTAL_KEY", "k2")

    queried_urls: list[str] = []

    def fake_get(url: str, **_: Any) -> tuple[int, dict[str, Any] | None]:
        queried_urls.append(url)
        return 200, {}

    monkeypatch.setattr(passive_dns, "_http_get_json", fake_get)

    out = passive_dns.passive_dns_history("example.com")
    assert "securitytrails" in out["providers_queried"]
    assert "virustotal" in out["providers_queried"]
    assert any("securitytrails.com" in u for u in queried_urls)
    assert any("virustotal.com" in u for u in queried_urls)


def test_prefer_overrides_default(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SECURITYTRAILS_KEY", "k1")
    monkeypatch.setenv("STRIX_VIRUSTOTAL_KEY", "k2")

    queried_urls: list[str] = []

    def fake_get(url: str, **_: Any) -> tuple[int, dict[str, Any] | None]:
        queried_urls.append(url)
        return 200, {}

    monkeypatch.setattr(passive_dns, "_http_get_json", fake_get)

    out = passive_dns.passive_dns_history("example.com", prefer="virustotal")
    assert out["providers_queried"] == ["virustotal"]
    # Only VirusTotal URLs should have been hit.
    assert all("virustotal.com" in u for u in queried_urls)


def test_provider_failure_marks_inconclusive(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SECURITYTRAILS_KEY", "test-key")

    def fake_get(url: str, **_: Any) -> tuple[int, dict[str, Any] | None]:
        # Both endpoints return non-200.
        return 503, None

    monkeypatch.setattr(passive_dns, "_http_get_json", fake_get)

    out = passive_dns.passive_dns_history("example.com")
    # Tool itself succeeds (it ran the providers); but no providers reported success.
    assert out["success"] is False
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["passive_dns"]["inconclusive"] == 1


def test_emits_one_check_per_provider(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SECURITYTRAILS_KEY", "k1")
    monkeypatch.setenv("STRIX_VIRUSTOTAL_KEY", "k2")
    monkeypatch.setattr(passive_dns, "_http_get_json", lambda u, **_: (200, {}))

    passive_dns.passive_dns_history("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 2
    assert "passive_dns" in summary["by_category"]
