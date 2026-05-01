"""Tests for subdomain_takeover_check.

We mock both the `dig` (CNAME resolution) and `http_get_text` (fingerprint
fetch) helpers so the suite is hermetic.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.tools.recon import takeover


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
    tracer = Tracer("takeover-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["example.com"]})
    yield


def _patch(monkeypatch, *, cnames: dict[str, str], bodies: dict[str, tuple[int, str]]) -> None:
    def fake_dig(query: str, record_type: str = "A", **_: Any) -> str:
        if record_type == "CNAME":
            return cnames.get(query, "")
        return ""

    def fake_http_get_text(url: str, **_: Any) -> tuple[int, str]:
        return bodies.get(url, (0, ""))

    monkeypatch.setattr(takeover, "dig", fake_dig)
    monkeypatch.setattr(takeover, "http_get_text", fake_http_get_text)


def test_no_cname_no_candidate(monkeypatch) -> None:
    _patch(monkeypatch, cnames={}, bodies={})
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="api.example.com"
    )
    assert out["candidates"] == 0
    assert out["results"][0]["candidate"] is False
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_unknown_provider_no_finding(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"api.example.com": "internal-lb-12345.aws.local."},
        bodies={},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="api.example.com"
    )
    assert out["candidates"] == 0
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_heroku_unclaimed_emits_high_finding(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"app.example.com": "old-project-123.herokuapp.com."},
        bodies={
            "https://app.example.com/": (404, "<html><body>No such app</body></html>"),
        },
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="app.example.com"
    )
    assert out["candidates"] == 1
    candidate = out["results"][0]
    assert candidate["provider"] == "heroku"
    assert candidate["verification_status"] == "verified"
    assert candidate["severity"] == "high"

    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "subdomain_takeover"
    assert reports[0]["severity"] == "high"


def test_heroku_claimed_no_finding(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"app.example.com": "real-prod-app.herokuapp.com."},
        bodies={"https://app.example.com/": (200, "<html><body>Welcome to my app</body></html>")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="app.example.com"
    )
    # CNAME matched a known provider but fingerprint didn't match → not a verified candidate
    assert out["results"][0]["verification_status"] == "pattern_match"
    # severity downgraded to "info" because not unclaimed
    # No finding emitted (we only emit when unclaimed or fingerprint=None)
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 0


def test_azure_cloudapp_always_candidate(monkeypatch) -> None:
    """Azure CloudApp has fingerprint=None — always-candidate; emit at medium."""
    _patch(
        monkeypatch,
        cnames={"app.example.com": "myorg.cloudapp.net."},
        bodies={},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="app.example.com"
    )
    assert out["candidates"] == 1
    assert out["results"][0]["provider"] == "azure_cloudapp"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["category"] == "subdomain_takeover"
    assert reports[0]["severity"] == "medium"


def test_invalid_subdomain_rejected(monkeypatch) -> None:
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="not a domain,api.example.com"
    )
    assert out["success"] is False
    assert "invalid" in out["error"].lower()
