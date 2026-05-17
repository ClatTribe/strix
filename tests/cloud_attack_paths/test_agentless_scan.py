"""Tests for agentless VM CVE scanning (`strix.cloud_attack_paths.agentless_scan`).

Hermetic — `subprocess.run` is DI'd; no real `trivy` invocation."""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.cloud_attack_paths import agentless_scan as agentless_module
from strix.cloud_attack_paths import tools as tools_module
from strix.cloud_attack_paths.agentless_scan import (
    AgentlessScanResult,
    _build_trivy_argv,
    _parse_trivy_vm_output,
    _trivy_severity,
    scan_snapshot,
    scan_snapshots,
    summarise,
    union_findings,
)
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------


_TRIVY_FIXTURE = {
    "ArtifactName": "ebs:snap-0123abc",
    "ArtifactType": "vm",
    "Results": [{
        "Target": "Ubuntu 22.04 (linux)",
        "Vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2024-1234",
                "PkgName": "openssl",
                "InstalledVersion": "3.0.2-0ubuntu1.10",
                "FixedVersion": "3.0.2-0ubuntu1.15",
                "Severity": "HIGH",
                "Title": "OpenSSL X.509 GeneralName injection",
                "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
            },
            {
                "VulnerabilityID": "CVE-2023-9999",
                "PkgName": "libxml2",
                "InstalledVersion": "2.9.13",
                "Severity": "CRITICAL",
            },
        ],
    }],
}


def test_parser_extracts_vulnerabilities() -> None:
    findings = _parse_trivy_vm_output(_TRIVY_FIXTURE, snapshot_id="snap-0123abc")
    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {
        "agentless_vm:CVE-2024-1234",
        "agentless_vm:CVE-2023-9999",
    }


def test_parser_maps_severity_levels() -> None:
    findings = _parse_trivy_vm_output(
        _TRIVY_FIXTURE, snapshot_id="snap-0123abc",
    )
    by_cve = {f.metadata["cve_id"]: f for f in findings}
    assert by_cve["CVE-2024-1234"].severity == "high"
    assert by_cve["CVE-2023-9999"].severity == "critical"


def test_parser_attaches_package_metadata() -> None:
    findings = _parse_trivy_vm_output(
        _TRIVY_FIXTURE, snapshot_id="snap-0123abc",
    )
    finding = next(
        f for f in findings if f.metadata["cve_id"] == "CVE-2024-1234"
    )
    assert finding.metadata["package"] == "openssl"
    assert finding.metadata["installed_version"] == "3.0.2-0ubuntu1.10"
    assert finding.metadata["fixed_version"] == "3.0.2-0ubuntu1.15"
    assert finding.metadata["source"] == "trivy_vm"
    assert finding.cwe == "CWE-1395"
    assert finding.category == "agentless_vm_cve"


def test_parser_handles_empty_output() -> None:
    """Trivy returns `Results: null` when zero CVEs — must
    produce empty list, not crash."""
    assert _parse_trivy_vm_output({"Results": None},
                                    snapshot_id="snap-x") == []
    assert _parse_trivy_vm_output({}, snapshot_id="snap-x") == []
    assert _parse_trivy_vm_output("", snapshot_id="snap-x") == []


def test_parser_handles_invalid_json() -> None:
    assert _parse_trivy_vm_output("not json",
                                    snapshot_id="snap-x") == []


def test_parser_skips_missing_vulnerability_id() -> None:
    """Result entries with no VulnerabilityID get a fallback
    rule_id of `agentless_vm:unknown` — non-empty signal still
    captured."""
    data = {
        "Results": [{
            "Target": "alpine",
            "Vulnerabilities": [{
                "PkgName": "musl",
                "Severity": "MEDIUM",
                # No VulnerabilityID.
            }],
        }],
    }
    findings = _parse_trivy_vm_output(data, snapshot_id="snap-y")
    assert len(findings) == 1
    assert findings[0].rule_id == "agentless_vm:unknown"


def test_severity_unknown_defaults_to_low() -> None:
    assert _trivy_severity("UNKNOWN") == "low"


def test_severity_missing_defaults_to_medium() -> None:
    assert _trivy_severity(None) == "medium"


# ---------------------------------------------------------------------------
# argv builder
# ---------------------------------------------------------------------------


def test_argv_uses_ebs_prefix() -> None:
    argv = _build_trivy_argv(snapshot_id="snap-abc")
    assert argv[0] == "trivy"
    assert argv[1] == "vm"
    assert "ebs:snap-abc" in argv
    # Force JSON + quiet output for parseable + non-progress.
    assert "--format" in argv
    assert "json" in argv
    assert "--quiet" in argv
    assert "--no-progress" in argv


# ---------------------------------------------------------------------------
# scan_snapshot — subprocess wiring
# ---------------------------------------------------------------------------


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_scan_snapshot_emits_findings_on_clean_run(monkeypatch) -> None:
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    fake_run = lambda *a, **kw: _FakeCompletedProcess(
        stdout=json.dumps(_TRIVY_FIXTURE),
    )
    result = scan_snapshot(
        "snap-0123abc", _subprocess_run=fake_run,
    )
    assert len(result.findings) == 2
    assert result.errors == []
    assert result.metadata["returncode"] == 0


def test_scan_snapshot_trivy_missing_yields_error(monkeypatch) -> None:
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: False,
    )

    def _refused(*a, **kw):
        raise AssertionError("subprocess must not be called when trivy missing")

    result = scan_snapshot("snap-x", _subprocess_run=_refused)
    assert result.findings == []
    assert any(e["stage"] == "trivy_check" for e in result.errors)


def test_scan_snapshot_non_zero_exit_is_error(monkeypatch) -> None:
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    fake_run = lambda *a, **kw: _FakeCompletedProcess(
        returncode=1, stderr="AccessDenied: ec2:GetSnapshotBlock",
    )
    result = scan_snapshot("snap-x", _subprocess_run=fake_run)
    assert result.findings == []
    assert any(
        "AccessDenied" in e.get("error", "") for e in result.errors
    )


def test_scan_snapshot_timeout(monkeypatch) -> None:
    import subprocess as sp
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )

    def _timeout(*a, **kw):
        raise sp.TimeoutExpired(cmd="trivy", timeout=1)

    result = scan_snapshot(
        "snap-x", timeout_seconds=1, _subprocess_run=_timeout,
    )
    assert any("timed out" in e["error"] for e in result.errors)


def test_scan_snapshot_empty_stdout_treated_as_zero_cves(monkeypatch) -> None:
    """Trivy can emit empty stdout for a snapshot with zero CVEs.
    Should not produce findings, should not error."""
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    fake_run = lambda *a, **kw: _FakeCompletedProcess(stdout="")
    result = scan_snapshot("snap-clean", _subprocess_run=fake_run)
    assert result.findings == []
    assert result.errors == []


def test_scan_snapshot_env_overrides_propagate(monkeypatch) -> None:
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    captured: dict[str, Any] = {}

    def _capture(argv, **kwargs):
        captured["env"] = kwargs.get("env", {})
        return _FakeCompletedProcess(stdout="")

    scan_snapshot(
        "snap-x",
        env_overrides={"AWS_PROFILE": "ci-snap-reader"},
        _subprocess_run=_capture,
    )
    assert captured["env"].get("AWS_PROFILE") == "ci-snap-reader"


# ---------------------------------------------------------------------------
# scan_snapshots — fan-out + isolation
# ---------------------------------------------------------------------------


def test_scan_snapshots_returns_per_snapshot_result(monkeypatch) -> None:
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    fake_run = lambda *a, **kw: _FakeCompletedProcess(
        stdout=json.dumps(_TRIVY_FIXTURE),
    )
    results = scan_snapshots(
        ["snap-1", "snap-2", "snap-3"],
        _subprocess_run=fake_run,
    )
    assert len(results) == 3
    assert all(len(r.findings) == 2 for r in results)


def test_scan_snapshots_empty_input() -> None:
    assert scan_snapshots([]) == []


def test_scan_snapshots_max_snapshots_caps_run(monkeypatch) -> None:
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    fake_run = lambda *a, **kw: _FakeCompletedProcess(stdout="")
    results = scan_snapshots(
        [f"snap-{i}" for i in range(100)],
        max_snapshots=5,
        _subprocess_run=fake_run,
    )
    assert len(results) == 5


def test_scan_snapshots_per_snapshot_isolation(monkeypatch) -> None:
    """One snapshot fails, others still complete."""
    monkeypatch.setattr(
        agentless_module, "is_trivy_vm_available", lambda: True,
    )
    call_count = {"n": 0}

    def fake_run(*a, **kw):
        call_count["n"] += 1
        if call_count["n"] == 2:
            return _FakeCompletedProcess(
                returncode=1, stderr="AccessDenied",
            )
        return _FakeCompletedProcess(
            stdout=json.dumps(_TRIVY_FIXTURE),
        )

    results = scan_snapshots(
        ["snap-1", "snap-2", "snap-3"],
        _subprocess_run=fake_run,
    )
    assert len(results) == 3
    assert results[0].findings  # ok
    assert not results[1].findings  # errored
    assert results[1].errors
    assert results[2].findings  # ok


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------


def test_summarise_counts_severities() -> None:
    r = AgentlessScanResult(snapshot_id="s1")
    r.findings.extend(_parse_trivy_vm_output(
        _TRIVY_FIXTURE, snapshot_id="s1",
    ))
    s = summarise([r])
    assert s["snapshots_scanned"] == 1
    assert s["total_cve_findings"] == 2
    assert s["severity_breakdown"]["high"] == 1
    assert s["severity_breakdown"]["critical"] == 1


def test_union_findings_flat_list() -> None:
    r1 = AgentlessScanResult(snapshot_id="s1")
    r1.findings.extend(_parse_trivy_vm_output(
        _TRIVY_FIXTURE, snapshot_id="s1",
    ))
    r2 = AgentlessScanResult(snapshot_id="s2")
    r2.findings.extend(_parse_trivy_vm_output(
        _TRIVY_FIXTURE, snapshot_id="s2",
    ))
    out = union_findings([r1, r2])
    assert len(out) == 4


# ---------------------------------------------------------------------------
# Specialist integration
# ---------------------------------------------------------------------------


class _StubAwsReport:
    findings: list = []
    errors: list = []
    account_id = "1"
    regions_scanned = ["us-east-1"]
    findings_by_service = {}


def test_specialist_threads_agentless_snapshot_ids(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())
    # Stub the agentless scan to return canned results.
    fake_results = [
        AgentlessScanResult(snapshot_id="snap-1"),
    ]
    fake_results[0].findings.extend(_parse_trivy_vm_output(
        _TRIVY_FIXTURE, snapshot_id="snap-1",
    ))

    monkeypatch.setattr(agentless_module, "scan_snapshots",
                        lambda *a, **kw: fake_results)

    result = scan_cloud_attack_paths(
        provider="aws",
        agentless_snapshot_ids=["snap-1"],
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    assert "agentless_scan_summary" in result["tool_metadata"]
    summary = result["tool_metadata"]["agentless_scan_summary"]
    assert summary["snapshots_scanned"] == 1
    assert summary["total_cve_findings"] == 2


def test_specialist_no_snapshots_kwarg_keeps_legacy(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    result = scan_cloud_attack_paths(
        provider="aws", auto_discover_assets=False,
    )
    assert "agentless_scan_summary" not in result["tool_metadata"]


def test_specialist_agentless_only_runs_on_aws(monkeypatch) -> None:
    """`agentless_snapshot_ids` is ignored for non-AWS providers."""
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: True)
    from strix.cspm.prowler import ProwlerScanResult
    monkeypatch.setattr(
        tools_module, "run_prowler",
        lambda **_: ProwlerScanResult(provider="azure", findings=[]),
    )

    def _refuse(*a, **kw):
        raise AssertionError("agentless must not run on Azure")

    monkeypatch.setattr(agentless_module, "scan_snapshots", _refuse)

    result = scan_cloud_attack_paths(
        provider="azure",
        agentless_snapshot_ids=["snap-1"],
        auto_discover_assets=False,
    )
    assert "agentless_scan_summary" not in result["tool_metadata"]
