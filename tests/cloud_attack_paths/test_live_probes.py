"""Tests for cloud-attack-path live probes.

Hermetic — never spawns real httpx / socket calls. Tests cover:

  * Probe registry: registered patterns vs unregistered.
  * Opt-in gate: explicit kwarg, env var, default-off.
  * S3 anonymous probe: verified / not-verified / non-S3 ARN
    skip / network error.
  * TCP reachability probe: verified / not-verified / no
    metadata host → skipped.
  * `upgrade_path_with_probe` semantics: verified bumps
    confidence, prepends narrative, stamps proof. Non-verified
    stamps without downgrading.
  * `analyze_cloud_attack_paths` runs probes only when opted in;
    verified paths land with `live_probe` in metadata.
  * `scan_cloud_attack_paths` specialist threads
    `enable_live_probes` through and surfaces `live_probes_summary`
    in `tool_metadata`.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.cloud_attack_paths import live_probes as lp_module
from strix.cloud_attack_paths import tools as tools_module
from strix.cloud_attack_paths.api import analyze_cloud_attack_paths
from strix.cloud_attack_paths.live_probes import (
    PROBE_ERROR,
    PROBE_NOT_VERIFIED,
    PROBE_SKIPPED,
    PROBE_VERIFIED,
    ProbeResult,
    is_live_probes_enabled,
    list_registered_probes,
    register_probe,
    run_probe,
    upgrade_path_with_probe,
)
from strix.cloud_attack_paths.patterns import AttackPath
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths
from strix.cspm.aws import CspmFinding


# ---------------------------------------------------------------------------
# Registry hygiene
# ---------------------------------------------------------------------------


def test_v1_ships_probes_for_two_patterns() -> None:
    registered = list_registered_probes()
    assert "cap_public_storage_credentials_risk" in registered
    assert "cap_internet_exposed_compute_with_iam" in registered


def test_run_probe_returns_none_for_unregistered_pattern() -> None:
    path = AttackPath(
        pattern_id="cap_unregistered_synthetic",
        title="x", severity="medium", narrative="",
        hops=["arn:aws:s3:::x"],
    )
    result = run_probe(path)
    assert result is None


def test_run_probe_wraps_exception_into_error_result(monkeypatch) -> None:
    """A probe that raises must not crash the scan — wraps into
    `status=error` so the surrounding pipeline keeps going."""
    @register_probe("cap_test_synthetic_raise")
    def _boom(path):
        raise RuntimeError("synthetic")

    path = AttackPath(
        pattern_id="cap_test_synthetic_raise",
        title="x", severity="medium", narrative="",
        hops=["arn:aws:s3:::x"],
    )
    try:
        result = run_probe(path)
        assert result is not None
        assert result.status == PROBE_ERROR
        assert "synthetic" in result.narrative
    finally:
        # Remove the synthetic registration so it doesn't leak.
        lp_module._REGISTRY.pop("cap_test_synthetic_raise", None)


# ---------------------------------------------------------------------------
# Opt-in gate
# ---------------------------------------------------------------------------


def test_default_off(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_CLOUD_LIVE_PROBES", raising=False)
    assert is_live_probes_enabled() is False


def test_explicit_true_overrides_env(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_CLOUD_LIVE_PROBES", raising=False)
    assert is_live_probes_enabled(explicit=True) is True


def test_explicit_false_overrides_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_CLOUD_LIVE_PROBES", "1")
    assert is_live_probes_enabled(explicit=False) is False


@pytest.mark.parametrize("env_val", ["1", "true", "yes", "TRUE", "Yes"])
def test_env_var_enables_when_explicit_none(monkeypatch, env_val) -> None:
    monkeypatch.setenv("STRIX_CLOUD_LIVE_PROBES", env_val)
    assert is_live_probes_enabled(explicit=None) is True


@pytest.mark.parametrize("env_val", ["0", "false", "no", "", "off"])
def test_env_var_falsy_does_not_enable(monkeypatch, env_val) -> None:
    monkeypatch.setenv("STRIX_CLOUD_LIVE_PROBES", env_val)
    assert is_live_probes_enabled() is False


# ---------------------------------------------------------------------------
# S3 anonymous-read probe
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.headers = headers or {}


class _FakeHttpxClient:
    def __init__(self, response_factory):
        self._factory = response_factory
        self.calls: list[dict[str, Any]] = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def head(self, url, *, headers=None):
        self.calls.append({"url": url, "headers": headers or {}})
        return self._factory(url)


def _patch_httpx(monkeypatch, response_factory):
    """Replace httpx.Client constructor with our fake. Captures
    request URLs + returns synthesised responses."""
    import httpx
    fake = _FakeHttpxClient(response_factory)

    def _client_ctor(**_kwargs):
        return fake

    monkeypatch.setattr(httpx, "Client", _client_ctor)
    return fake


def _s3_attack_path(bucket: str = "leaky-tfstate") -> AttackPath:
    return AttackPath(
        pattern_id="cap_public_storage_credentials_risk",
        title=f"Public bucket {bucket}",
        severity="critical",
        narrative=f"Bucket {bucket} is public",
        hops=[f"arn:aws:s3:::{bucket}"],
    )


def test_s3_probe_verified_on_200(monkeypatch) -> None:
    _patch_httpx(monkeypatch, lambda url: _FakeResponse(200, {"content-type": "application/xml"}))
    result = lp_module.probe_s3_anonymous_read(_s3_attack_path())
    assert result.status == PROBE_VERIFIED
    assert result.evidence["status_code"] == 200
    assert "publicly accessible" in result.narrative.lower()


def test_s3_probe_not_verified_on_403(monkeypatch) -> None:
    """403 = bucket exists but anonymous denied — CSPM may have
    flagged it but live state is locked down (recently fixed
    drift)."""
    _patch_httpx(monkeypatch, lambda url: _FakeResponse(403))
    result = lp_module.probe_s3_anonymous_read(_s3_attack_path())
    assert result.status == PROBE_NOT_VERIFIED
    assert "drift" in result.narrative.lower() or "locked down" in result.narrative.lower()


def test_s3_probe_skipped_for_non_s3_arn() -> None:
    """Pattern fires on Azure / GCP storage too — those aren't
    AWS S3 ARNs; probe must skip gracefully (no FP, no crash)."""
    azure_path = AttackPath(
        pattern_id="cap_public_storage_credentials_risk",
        title="Azure", severity="critical", narrative="",
        hops=["/subscriptions/sub/.../prodstorage"],
    )
    result = lp_module.probe_s3_anonymous_read(azure_path)
    assert result.status == PROBE_SKIPPED


def test_s3_probe_skipped_with_no_hops() -> None:
    path = AttackPath(
        pattern_id="cap_public_storage_credentials_risk",
        title="x", severity="critical", narrative="", hops=[],
    )
    result = lp_module.probe_s3_anonymous_read(path)
    assert result.status == PROBE_SKIPPED


def test_s3_probe_handles_network_error(monkeypatch) -> None:
    """When httpx raises (DNS / TLS / conn refused), probe must
    return not_verified — never crash the scan."""
    import httpx

    class _BrokenClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def head(self, *args, **kwargs):
            raise httpx.ConnectError("synthetic")

    monkeypatch.setattr(httpx, "Client", lambda **_: _BrokenClient())
    result = lp_module.probe_s3_anonymous_read(_s3_attack_path())
    assert result.status == PROBE_NOT_VERIFIED
    assert "could not externally verify" in result.narrative.lower()


def test_s3_probe_user_agent_includes_strix_marker(monkeypatch) -> None:
    fake = _patch_httpx(monkeypatch, lambda url: _FakeResponse(403))
    lp_module.probe_s3_anonymous_read(_s3_attack_path())
    assert any(
        "strix-cspm-probe" in (c["headers"] or {}).get("User-Agent", "")
        for c in fake.calls
    )


# ---------------------------------------------------------------------------
# TCP reachability probe
# ---------------------------------------------------------------------------


def _compute_attack_path(
    *, public_dns: str | None = None,
    function_url: str | None = None,
    compute_kind: str = "ec2_instance",
) -> AttackPath:
    md: dict[str, Any] = {"compute_kind": compute_kind}
    if public_dns:
        md["public_dns"] = public_dns
    if function_url:
        md["function_url"] = function_url
    return AttackPath(
        pattern_id="cap_internet_exposed_compute_with_iam",
        title="exposed compute",
        severity="high",
        narrative="public compute with IAM",
        hops=["arn:aws:ec2:us-east-1:1:instance/i-aaa", "arn:aws:iam::1:role/r"],
        metadata=md,
    )


def test_tcp_probe_skipped_without_host_metadata() -> None:
    """No public_dns / public_ip / function_url → no host to
    probe → skip cleanly."""
    result = lp_module.probe_tcp_reachability(_compute_attack_path())
    assert result.status == PROBE_SKIPPED
    assert "metadata" in result.narrative


def test_tcp_probe_verified_when_port_reachable(monkeypatch) -> None:
    import socket

    def fake_create_connection(addr, timeout=None):
        # Simulate connect success on port 443; refused otherwise.
        host, port = addr
        if port == 443:
            class _S:
                def close(self):
                    pass
            return _S()
        raise ConnectionRefusedError(f"refused on {port}")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    path = _compute_attack_path(public_dns="ec2-1-2-3-4.compute.amazonaws.com")
    result = lp_module.probe_tcp_reachability(path)
    assert result.status == PROBE_VERIFIED
    assert 443 in result.evidence["reachable_ports"]


def test_tcp_probe_not_verified_when_all_refused(monkeypatch) -> None:
    import socket

    def fake_create_connection(*a, **k):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    path = _compute_attack_path(public_dns="x.example")
    result = lp_module.probe_tcp_reachability(path)
    assert result.status == PROBE_NOT_VERIFIED
    assert "not tcp-reachable" in result.narrative.lower()


def test_tcp_probe_normalises_function_url(monkeypatch) -> None:
    """Lambda function URLs have the shape `https://.../...` —
    the probe must extract hostname + port from the URL."""
    import socket
    captured: list[tuple[str, int]] = []

    def fake_create_connection(addr, timeout=None):
        captured.append(addr)
        class _S:
            def close(self):
                pass
        return _S()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    path = _compute_attack_path(
        function_url="https://abc.lambda-url.us-east-1.on.aws/",
        compute_kind="lambda_function",
    )
    result = lp_module.probe_tcp_reachability(path)
    assert result.status == PROBE_VERIFIED
    # Captured connection attempts use the URL's hostname.
    assert any("lambda-url" in addr[0] for addr in captured)
    # ...and the URL's scheme defaults to 443.
    assert any(addr[1] == 443 for addr in captured)


# ---------------------------------------------------------------------------
# upgrade_path_with_probe
# ---------------------------------------------------------------------------


def test_upgrade_verified_bumps_confidence_and_narrative() -> None:
    path = _s3_attack_path()
    path.confidence = 0.85
    original_narrative = path.narrative
    result = ProbeResult(
        status=PROBE_VERIFIED,
        probe_id="s3_anonymous_head",
        pattern_id=path.pattern_id,
        narrative="bucket returned 200",
        evidence={"status_code": 200},
    )
    upgrade_path_with_probe(path, result)
    assert path.confidence >= 0.99
    assert "VERIFIED LIVE" in path.narrative
    assert original_narrative in path.narrative
    assert path.metadata["live_probe"]["status"] == PROBE_VERIFIED


def test_upgrade_not_verified_records_evidence_but_no_downgrade() -> None:
    """When the probe returns not_verified, the pattern-derived
    severity / confidence stays — the pattern saw a real misconfig,
    the probe just couldn't externally confirm exploitability."""
    path = _s3_attack_path()
    path.confidence = 0.85
    original_confidence = path.confidence
    original_narrative = path.narrative
    result = ProbeResult(
        status=PROBE_NOT_VERIFIED,
        probe_id="s3_anonymous_head",
        pattern_id=path.pattern_id,
        narrative="403 denied",
        evidence={"status_code": 403},
    )
    upgrade_path_with_probe(path, result)
    assert path.confidence == original_confidence
    assert "VERIFIED LIVE" not in path.narrative
    assert path.narrative == original_narrative
    # Evidence still recorded for transparency.
    assert path.metadata["live_probe"]["status"] == PROBE_NOT_VERIFIED


# ---------------------------------------------------------------------------
# analyze_cloud_attack_paths integration
# ---------------------------------------------------------------------------


def _cspm_findings_for_public_s3() -> list[CspmFinding]:
    return [CspmFinding(
        rule_id="AWS_S3_PUBLIC_ACL",
        severity="critical",
        message="public ACL on prod-tfstate",
        service="s3", region=None,
        resource_arn="arn:aws:s3:::prod-tfstate",
        account_id="1", cwe="CWE-732", category="misconfig",
    )]


def test_analyze_does_not_probe_by_default(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_CLOUD_LIVE_PROBES", raising=False)

    def _refuse_probe(path):
        raise AssertionError("probe should not run when opt-in is OFF")

    monkeypatch.setattr(lp_module, "run_probe", _refuse_probe)
    report = analyze_cloud_attack_paths(
        cspm_findings=_cspm_findings_for_public_s3(),
    )
    # No live_probe metadata on any path.
    assert all(
        not (p.metadata or {}).get("live_probe")
        for p in report.paths
    )


def test_analyze_probes_when_explicit_opt_in(monkeypatch) -> None:
    _patch_httpx(monkeypatch, lambda url: _FakeResponse(200))
    report = analyze_cloud_attack_paths(
        cspm_findings=_cspm_findings_for_public_s3(),
        enable_live_probes=True,
    )
    s3_paths = [
        p for p in report.paths
        if p.pattern_id == "cap_public_storage_credentials_risk"
    ]
    assert s3_paths
    live = (s3_paths[0].metadata or {}).get("live_probe")
    assert live is not None
    assert live["status"] == PROBE_VERIFIED


def test_analyze_probes_when_env_opt_in(monkeypatch) -> None:
    _patch_httpx(monkeypatch, lambda url: _FakeResponse(200))
    monkeypatch.setenv("STRIX_CLOUD_LIVE_PROBES", "1")
    report = analyze_cloud_attack_paths(
        cspm_findings=_cspm_findings_for_public_s3(),
    )
    s3_paths = [
        p for p in report.paths
        if p.pattern_id == "cap_public_storage_credentials_risk"
    ]
    assert s3_paths
    assert (s3_paths[0].metadata or {}).get("live_probe", {}).get("status") == PROBE_VERIFIED


def test_analyze_explicit_false_overrides_env_opt_in(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_CLOUD_LIVE_PROBES", "1")

    def _refuse_probe(path):
        raise AssertionError("probe must not run when explicit=False")

    monkeypatch.setattr(lp_module, "run_probe", _refuse_probe)
    report = analyze_cloud_attack_paths(
        cspm_findings=_cspm_findings_for_public_s3(),
        enable_live_probes=False,
    )
    assert all(
        not (p.metadata or {}).get("live_probe")
        for p in report.paths
    )


# ---------------------------------------------------------------------------
# scan_cloud_attack_paths specialist threading
# ---------------------------------------------------------------------------


class _StubAwsReport:
    def __init__(self, findings):
        self.findings = findings
        self.errors = []
        self.account_id = "1"
        self.regions_scanned = ["us-east-1"]


def test_specialist_threads_enable_live_probes(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport(_cspm_findings_for_public_s3()),
    )
    _patch_httpx(monkeypatch, lambda url: _FakeResponse(200))

    result = scan_cloud_attack_paths(
        provider="aws", enable_live_probes=True,
    )
    assert result["status"] == "ok"
    assert result["tool_metadata"]["live_probes_enabled"] is True
    summary = result["tool_metadata"]["live_probes_summary"]
    assert summary["verified"] >= 1


def test_specialist_default_no_live_probes_metadata(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_CLOUD_LIVE_PROBES", raising=False)
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport(_cspm_findings_for_public_s3()),
    )

    result = scan_cloud_attack_paths(provider="aws")
    assert result["status"] == "ok"
    # No live-probe key when probes didn't run.
    assert "live_probes_summary" not in result["tool_metadata"]
    assert "live_probes_enabled" not in result["tool_metadata"]


def test_specialist_verified_path_emits_exploited_status(monkeypatch) -> None:
    """A live-probe-verified path should land on the tracer
    report with `verification_status="exploited"` (vs the
    pattern-only `"verified"`). The auditor-grade signal lives
    on the tracer record — the FindingDraft schema constrains
    `verification_status` to a Literal that doesn't yet include
    `"exploited"`."""
    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer, set_global_tracer

    tracer_module._global_tracer = None
    tracer_module._OTEL_BOOTSTRAPPED = False
    tracer_module._OTEL_REMOTE_ENABLED = False
    telemetry_utils.reset_events_write_locks()
    tracer = Tracer("lp-test")
    set_global_tracer(tracer)

    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport(_cspm_findings_for_public_s3()),
    )
    _patch_httpx(monkeypatch, lambda url: _FakeResponse(200))

    scan_cloud_attack_paths(
        provider="aws", enable_live_probes=True,
    )
    s3_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "cloud_attack_path"
        and r.get("rule_id") == "cap_public_storage_credentials_risk"
    ]
    assert s3_reports
    assert s3_reports[0]["verification_status"] == "exploited"


def test_specialist_non_verified_path_emits_verified_not_exploited(monkeypatch) -> None:
    """Pattern-only paths (live probe not run OR not verified)
    keep the canonical `verified` status."""
    from strix.telemetry import tracer as tracer_module
    from strix.telemetry import utils as telemetry_utils
    from strix.telemetry.tracer import Tracer, set_global_tracer

    tracer_module._global_tracer = None
    tracer_module._OTEL_BOOTSTRAPPED = False
    tracer_module._OTEL_REMOTE_ENABLED = False
    telemetry_utils.reset_events_write_locks()
    tracer = Tracer("lp-test-2")
    set_global_tracer(tracer)

    monkeypatch.delenv("STRIX_CLOUD_LIVE_PROBES", raising=False)
    monkeypatch.setattr(tools_module, "is_prowler_available", lambda: False)
    monkeypatch.setattr(
        tools_module, "scan_aws_account",
        lambda **_: _StubAwsReport(_cspm_findings_for_public_s3()),
    )

    scan_cloud_attack_paths(provider="aws")
    s3_reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "cloud_attack_path"
        and r.get("rule_id") == "cap_public_storage_credentials_risk"
    ]
    assert s3_reports
    assert s3_reports[0]["verification_status"] == "verified"
