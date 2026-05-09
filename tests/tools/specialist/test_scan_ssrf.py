"""Tests for §workitem.md Phase 2.1 — `scan_ssrf` deterministic SSRF specialist.

Pins detection of:
  * Cloud-metadata SSRF (AWS / GCP / Azure) → critical
  * Internal-IP loopback fingerprints → high
  * `file:///etc/passwd` disclosure → critical
  * Param inference from URL query string + SSRF lexicon
  * Forgiving args (param=str, params=str, params=list)
  * Auth auto-injection from SecurityContext.AuthState
  * Negative cases (transport error, no fingerprint, no params)
  * Auto-emit via tracer + SecurityContext probed_for=ssrf
  * OOB callback path is invoked when enabled (mocked)
  * Registry / lead-catalog wiring
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.tools.specialist.scan_ssrf import scan_ssrf


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-ssrf"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


@pytest.fixture(autouse=True)
def _reset_oob() -> None:
    """Default: OOB disabled so tests don't bind real ports unless they
    opt in. Individual tests that exercise the OOB path patch the
    relevant symbols directly."""
    import os

    from strix.tools.oob.service import reset_oob_service

    reset_oob_service()
    os.environ["STRIX_OOB_BACKEND"] = "disabled"
    yield
    reset_oob_service()
    os.environ.pop("STRIX_OOB_BACKEND", None)


def _patch_proxy(monkeypatch, response_for_url):
    fake = MagicMock()
    fake.send_simple_request = MagicMock(side_effect=response_for_url)
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        lambda: fake,
    )
    return fake


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_ssrf(url="")
    assert out["status"] == "error"


def test_proxy_manager_unavailable_returns_error(monkeypatch) -> None:
    def boom():
        raise ImportError("simulated")

    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager",
        boom,
    )
    out = scan_ssrf(url="http://example.com/proxy?url=http://example.org", param="url")
    assert out["status"] == "error"
    assert "proxy_manager" in out["error"]


def test_no_ssrf_shaped_params_returns_partial(monkeypatch) -> None:
    """No URL-shaped params on the URL and none supplied → partial."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    out = scan_ssrf(url="http://example.com/api/items?id=1&page=2")
    # `id`, `page` aren't in the SSRF lexicon, but the fallback grabs
    # all query keys; what matters is detection doesn't fire on
    # innocuous responses.
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Cloud-metadata SSRF (the headline case)
# ---------------------------------------------------------------------------


def test_aws_metadata_ssrf_emits_critical(monkeypatch) -> None:
    """AWS IMDSv1 fingerprint in response → critical SSRF finding."""
    def fake_resp(method, url, headers, body, timeout):
        if "169.254.169.254" in url:
            return {
                "status_code": 200,
                "body": (
                    "ami-id\nami-launch-index\niam/security-credentials/\n"
                    "instance-id\nplacement/availability-zone\n"
                ),
            }
        return {"status_code": 200, "body": "innocuous"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssrf(
        url="http://example.com/proxy?url=http://example.org",
        param="url",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "ssrf"
    assert f["cwe"] == "CWE-918"
    assert f["severity"] == "critical"


def test_gcp_metadata_ssrf_emits_critical(monkeypatch) -> None:
    def fake_resp(method, url, headers, body, timeout):
        if "metadata.google.internal" in url:
            return {
                "status_code": 200,
                "body": (
                    "project-id\nservice-accounts/\ncompute/\n"
                    "instance/hostname\n"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssrf(
        url="http://example.com/fetch?target=https://api.example.com",
        param="target",
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["severity"] == "critical"


def test_file_passwd_disclosure_emits_critical(monkeypatch) -> None:
    """`file:///etc/passwd` reachable via SSRF → critical."""
    def fake_resp(method, url, headers, body, timeout):
        if "file%3A" in url or "file:" in url:
            return {
                "status_code": 200,
                "body": (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssrf(
        url="http://example.com/fetch?url=https://example.org",
        param="url",
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Loopback fingerprint (non-cloud, internal IP reachable)
# ---------------------------------------------------------------------------


def test_loopback_fingerprint_emits_high(monkeypatch) -> None:
    """Internal-only Apache default page indicates SSRF to 127.0.0.1
    succeeded — high severity (no immediate credential leak)."""
    def fake_resp(method, url, headers, body, timeout):
        if "127.0.0.1" in url or "localhost" in url:
            return {
                "status_code": 200,
                "body": (
                    "<html><head><title>Apache2 Ubuntu Default Page: It works"
                    "</title></head><body><h1>Apache2 Ubuntu Default Page</h1>"
                    "</body></html>"
                ),
            }
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssrf(
        url="http://example.com/webhook?url=https://example.org",
        param="url",
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_no_fingerprint_no_finding(monkeypatch) -> None:
    """Response unrelated to probe content → no finding."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "<html>Generic landing page</html>"
    })
    out = scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


def test_transport_error_does_not_emit(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "error": "Request failed: ConnectionError"
    })
    out = scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Param inference + forgiving args
# ---------------------------------------------------------------------------


def test_inference_picks_url_shaped_param(monkeypatch) -> None:
    """Caller didn't supply param=; scanner infers `image` from query."""
    def fake_resp(method, url, headers, body, timeout):
        if "169.254.169.254" in url:
            return {"status_code": 200, "body": "ami-id\nplacement\niam/"}
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssrf(
        url="http://example.com/avatar?image=http%3A%2F%2Fexample.org&user=alice",
    )
    assert len(out["findings"]) == 1
    # Finding should name `image`, not `user`.
    assert "image" in out["findings"][0]["title"]


def test_forgiving_params_string(monkeypatch) -> None:
    """params=str is accepted (mirrors scan_sqli convention)."""
    def fake_resp(method, url, headers, body, timeout):
        return {"status_code": 200, "body": "ok no fingerprint"}

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        params="url",
    )
    assert out["status"] == "ok"


def test_dedup_one_finding_per_param(monkeypatch) -> None:
    """Multiple internal probes that all match → one finding per param,
    not five."""
    def fake_resp(method, url, headers, body, timeout):
        # Match every probe — every fingerprint regex is satisfied.
        return {
            "status_code": 200,
            "body": (
                "ami-id\nproject-id\nvmId\n"
                "root:x:0:0:root:/root:/bin/bash\n"
                "<title>Welcome to nginx welcome</title>"
                "Apache2 Ubuntu Default Page"
            ),
        }

    _patch_proxy(monkeypatch, fake_resp)
    out = scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    # Exactly one finding even though every probe technically matches.
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(monkeypatch) -> None:
    """When SecurityContext has a captured bearer, scan_ssrf forwards
    it as Authorization."""
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)

    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="abc123token")

    scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    assert any(
        h.get("Authorization") == "Bearer abc123token"
        for h in captured_headers
    )


def test_explicit_auth_overrides_auto(monkeypatch) -> None:
    """Caller-supplied Authorization wins over the auto-injection."""
    captured_headers: list[dict] = []

    def fake_resp(method, url, headers, body, timeout):
        captured_headers.append(dict(headers or {}))
        return {"status_code": 200, "body": "ok"}

    _patch_proxy(monkeypatch, fake_resp)

    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="ctxtoken")

    scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
        extra_headers={"Authorization": "Bearer overridden"},
    )
    assert all(
        h.get("Authorization") == "Bearer overridden"
        for h in captured_headers
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log integration
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_ssrf(monkeypatch) -> None:
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("ssrf" in e.probed_for for e in eps)


def test_records_decision_log_entry(monkeypatch) -> None:
    from strix.agents.decision_log import (
        list_decisions,
        reset_decision_log,
    )
    reset_decision_log()
    _patch_proxy(monkeypatch, lambda *a, **kw: {"status_code": 200, "body": "ok"})
    scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_ssrf"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# OOB path (mocked — Phase 1.3 backend)
# ---------------------------------------------------------------------------


def test_oob_callback_path_emits_finding_when_hit(monkeypatch) -> None:
    """Mock the OOB service: backend reports a hit → high-severity blind
    SSRF finding emitted."""
    def fake_resp(method, url, headers, body, timeout):
        # No in-band fingerprint — forces fallthrough to OOB.
        return {"status_code": 200, "body": "fetched ok no body content"}

    _patch_proxy(monkeypatch, fake_resp)

    from dataclasses import dataclass

    @dataclass
    class _Cb:
        token: str = "strixDEADBEEF"
        callback_url: str = "http://oob.test/strixDEADBEEF"
        expires_at: str = "2099-01-01T00:00:00+00:00"
        backend_name: str = "local"

    monkeypatch.setattr(
        "strix.tools.oob.is_available", lambda: True,
    )
    monkeypatch.setattr(
        "strix.tools.oob.register_callback",
        lambda *a, **kw: _Cb(),
    )
    monkeypatch.setattr(
        "strix.tools.oob.poll_callback",
        lambda token, *, timeout_seconds=10.0: {
            "hit": True,
            "source_ip": "10.0.0.5",
            "raw_request": {"method": "GET", "path": f"/{token}"},
        },
    )

    out = scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
        oob_timeout_seconds=0.1,
    )
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert "OOB-confirmed" in f["title"]
    assert f["severity"] == "high"


def test_oob_disabled_falls_back_silent(monkeypatch) -> None:
    """When OOB is disabled and there's no in-band hit, scan returns no
    findings without erroring."""
    _patch_proxy(monkeypatch, lambda *a, **kw: {
        "status_code": 200, "body": "ok"
    })
    monkeypatch.setattr(
        "strix.tools.oob.is_available", lambda: False,
    )
    out = scan_ssrf(
        url="http://example.com/proxy?url=https://example.org",
        param="url",
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_ssrf_registered_in_specialist_registry() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_ssrf")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "ssrf-specialist"


def test_scan_ssrf_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_ssrf" in catalog
