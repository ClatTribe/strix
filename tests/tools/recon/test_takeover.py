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


# ---------------------------------------------------------------------------
# Provider-expansion smoke tests (representative new providers)
# ---------------------------------------------------------------------------


def test_statuspage_unclaimed_high_severity(monkeypatch, tmp_path) -> None:
    _patch(
        monkeypatch,
        cnames={"status.example.com": "abc123.statuspage.io."},
        bodies={
            "https://status.example.com/": (404, "<html><body>There is no app configured at that hostname</body></html>"),
        },
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="status.example.com"
    )
    assert out["candidates"] == 1
    assert out["results"][0]["provider"] == "statuspage"
    assert out["results"][0]["severity"] == "high"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert reports[0]["severity"] == "high"


def test_surge_sh_unclaimed_high_severity(monkeypatch, tmp_path) -> None:
    _patch(
        monkeypatch,
        cnames={"app.example.com": "myproject.surge.sh."},
        bodies={"https://app.example.com/": (404, "project not found")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="app.example.com"
    )
    assert out["results"][0]["provider"] == "surge_sh"
    assert out["results"][0]["verification_status"] == "verified"


def test_pantheon_unclaimed(monkeypatch, tmp_path) -> None:
    _patch(
        monkeypatch,
        cnames={"site.example.com": "live-x.pantheonsite.io."},
        bodies={"https://site.example.com/": (404, "<h1>The gods are wise</h1>")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="site.example.com"
    )
    assert out["results"][0]["provider"] == "pantheon"
    assert out["results"][0]["severity"] == "high"


def test_aws_apigateway_unclaimed(monkeypatch, tmp_path) -> None:
    _patch(
        monkeypatch,
        cnames={"api.example.com": "abc123.execute-api.us-east-1.amazonaws.com."},
        bodies={
            "https://api.example.com/": (403, '{"message":"Forbidden"}'),
        },
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="api.example.com"
    )
    assert out["candidates"] == 1
    assert out["results"][0]["provider"] == "aws_apigateway"


def test_render_unclaimed(monkeypatch, tmp_path) -> None:
    _patch(
        monkeypatch,
        cnames={"web.example.com": "myservice-abc.onrender.com."},
        bodies={"https://web.example.com/": (404, "Not Found")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="web.example.com"
    )
    assert out["results"][0]["provider"] == "render"


def test_zendesk_unclaimed(monkeypatch, tmp_path) -> None:
    _patch(
        monkeypatch,
        cnames={"help.example.com": "support.zendesk.com."},
        bodies={"https://help.example.com/": (404, "Help Center Closed")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="help.example.com"
    )
    assert out["results"][0]["provider"] == "zendesk"


def test_canny_io_unclaimed(monkeypatch, tmp_path) -> None:
    _patch(
        monkeypatch,
        cnames={"feedback.example.com": "myorg.canny.io."},
        bodies={"https://feedback.example.com/": (404, "Company Not Found")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="feedback.example.com"
    )
    assert out["results"][0]["provider"] == "canny_io"


def test_unknown_provider_in_new_set_no_finding(monkeypatch, tmp_path) -> None:
    """A CNAME targeting a domain we don't fingerprint should not be flagged."""
    _patch(
        monkeypatch,
        cnames={"x.example.com": "internal-load-balancer-12345.aws.local."},
        bodies={},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="x.example.com"
    )
    assert out["candidates"] == 0


def test_provider_count_exceeds_legacy(monkeypatch, tmp_path) -> None:
    """Sanity check on the table — should be 60+ providers post-expansion."""
    from strix.tools.recon.takeover import _PROVIDERS
    assert len(_PROVIDERS) >= 60


# ---------------------------------------------------------------------------
# 38 → 60+ provider expansion smoke tests
# ---------------------------------------------------------------------------


def test_webflow_unclaimed(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"site.example.com": "myproject.webflow.io."},
        bodies={
            "https://site.example.com/": (
                404,
                "The page you are looking for doesn't exist or has been moved",
            )
        },
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="site.example.com"
    )
    assert out["results"][0]["provider"] == "webflow"
    assert out["results"][0]["verification_status"] == "verified"


def test_hubspot_unclaimed(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"info.example.com": "abc.hs-sites.com."},
        bodies={"https://info.example.com/": (404, "Domain not found")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="info.example.com"
    )
    assert out["results"][0]["provider"] == "hubspot"


def test_helpscout_unclaimed(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"docs.example.com": "abc.helpscoutdocs.com."},
        bodies={
            "https://docs.example.com/": (
                404,
                "No settings were found for this company",
            )
        },
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="docs.example.com"
    )
    assert out["results"][0]["provider"] == "helpscout"


def test_ngrok_unclaimed_is_high_severity(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"tunnel.example.com": "abc123.ngrok.io."},
        bodies={"https://tunnel.example.com/": (404, "Tunnel <tunnel> not found")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="tunnel.example.com"
    )
    assert out["results"][0]["provider"] == "ngrok"
    assert out["results"][0]["severity"] == "high"


def test_uservoice_unclaimed(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"feedback.example.com": "abc.uservoice.com."},
        bodies={
            "https://feedback.example.com/": (
                404,
                "This UserVoice subdomain is currently available!",
            )
        },
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="feedback.example.com"
    )
    assert out["results"][0]["provider"] == "uservoice"


def test_substack_unclaimed(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"newsletter.example.com": "myorg.substack.com."},
        bodies={"https://newsletter.example.com/": (404, "This page does not exist")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="newsletter.example.com"
    )
    assert out["results"][0]["provider"] == "substack"


def test_carrd_unclaimed(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"page.example.com": "abc.carrd.co."},
        bodies={"https://page.example.com/": (404, "This site is unavailable")},
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="page.example.com"
    )
    assert out["results"][0]["provider"] == "carrd"


def test_kajabi_unclaimed(monkeypatch) -> None:
    _patch(
        monkeypatch,
        cnames={"course.example.com": "abc.mykajabi.com."},
        bodies={
            "https://course.example.com/": (
                404,
                "The page you were looking for doesn't exist",
            )
        },
    )
    out = takeover.subdomain_takeover_check(
        "example.com", subdomains="course.example.com"
    )
    assert out["results"][0]["provider"] == "kajabi"


def test_provider_names_are_unique(monkeypatch) -> None:
    """No duplicate names across the expanded provider table."""
    from strix.tools.recon.takeover import _PROVIDERS
    names = [p["name"] for p in _PROVIDERS]
    assert len(names) == len(set(names)), f"duplicate provider names: {names}"


def test_each_provider_has_required_keys() -> None:
    """Every provider entry must have name / cname_pattern / fingerprint / severity."""
    from strix.tools.recon.takeover import _PROVIDERS

    for entry in _PROVIDERS:
        assert "name" in entry, f"missing name: {entry}"
        assert "cname_pattern" in entry, f"missing cname_pattern: {entry['name']}"
        assert "fingerprint" in entry, f"missing fingerprint: {entry['name']}"
        assert entry["severity"] in (
            "info", "low", "medium", "high", "critical"
        ), f"bad severity for {entry['name']}: {entry.get('severity')}"
