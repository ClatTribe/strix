"""Tests for `scan_container_image` (Trivy wrapper).

Trivy is invoked via subprocess. We mock the subprocess call to
return canonical Trivy JSON shapes so tests are hermetic and don't
require Trivy installed.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from strix.tools.container_image.scan_container_image import (
    _extract_packages_and_vulns,
    _normalise_ecosystem,
    scan_container_image,
)


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    """Run each test against a fresh in-memory tracer."""
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-trivy"))
    yield


# ---------------------------------------------------------------------------
# Canonical Trivy JSON output — captured from Trivy v0.50+ on `nginx:1.25`.
# Truncated to one OS-pkg result + one lang-pkg result for test brevity.
# ---------------------------------------------------------------------------


_TRIVY_REPORT_FIXTURE: dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "nginx:1.25",
    "ArtifactType": "container_image",
    "Metadata": {
        "OS": {"Family": "debian", "Name": "12.2"},
        "ImageID": "sha256:abc123",
        "RepoTags": ["nginx:1.25"],
    },
    "Results": [
        {
            "Target": "nginx:1.25 (debian 12.2)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-12345",
                    "PkgName": "libssl1.1",
                    "InstalledVersion": "1.1.1n-0+deb11u4",
                    "FixedVersion": "1.1.1n-0+deb11u5",
                    "Status": "fixed",
                    "Severity": "HIGH",
                    "Title": "OpenSSL: example RCE",
                    "Description": "An attacker can trigger RCE via crafted TLS.",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
                    "CweIDs": ["CWE-787"],
                    "CVSS": {
                        "nvd": {
                            "V3Vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "V3Score": 9.8,
                        },
                    },
                    "References": [
                        "https://www.openssl.org/news/secadv/...",
                        "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
                    ],
                },
                {
                    "VulnerabilityID": "CVE-2024-00001",
                    "PkgName": "libpng16-16",
                    "InstalledVersion": "1.6.39-2",
                    "FixedVersion": "",
                    "Status": "affected",
                    "Severity": "MEDIUM",
                    "Title": "libpng: integer overflow",
                    "Description": "Integer overflow in libpng decoder.",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-00001",
                    "CweIDs": ["CWE-190"],
                },
            ],
        },
        {
            "Target": "app/package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "GHSA-XXXX-YYYY-ZZZZ",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "FixedVersion": "4.17.21",
                    "Severity": "CRITICAL",
                    "Title": "lodash: prototype pollution",
                    "PrimaryURL": "https://github.com/advisories/...",
                },
            ],
        },
    ],
}


def _mock_trivy_run(
    monkeypatch, *, trivy_present: bool = True, report: dict[str, Any] | None = None,
    returncode: int = 0, stderr: str = "",
):
    """Patch `shutil.which` + `subprocess.run` to simulate Trivy.

    `shutil` and `subprocess` are imported as bare module names
    inside scan_container_image.py, so patching their global
    attributes (via the module objects, not dotted strings) is
    the cleanest hook. monkeypatch reverts the global mutation
    after the test.

    Returns the MagicMock used for subprocess.run so tests can
    inspect call args.
    """
    import shutil
    import subprocess

    monkeypatch.setattr(
        shutil, "which",
        lambda binary: (
            "/usr/local/bin/trivy"
            if trivy_present and binary == "trivy"
            else None
        ),
    )

    if not trivy_present:
        # Still patch subprocess.run so tests can't accidentally
        # invoke the real trivy if shutil.which leaks somehow.
        monkeypatch.setattr(
            subprocess, "run",
            MagicMock(side_effect=AssertionError(
                "subprocess.run called with trivy_present=False",
            )),
        )
        return None

    fake_result = MagicMock()
    fake_result.returncode = returncode
    fake_result.stdout = json.dumps(report or _TRIVY_REPORT_FIXTURE)
    fake_result.stderr = stderr
    run_mock = MagicMock(return_value=fake_result)
    monkeypatch.setattr(subprocess, "run", run_mock)
    return run_mock


def _get_emitted() -> list[dict[str, Any]]:
    from strix.telemetry.tracer import get_global_tracer

    return get_global_tracer().get_existing_vulnerabilities()


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_image_ref_returns_error() -> None:
    out = scan_container_image(image_ref="")
    assert out["status"] == "error"


def test_trivy_missing_returns_partial(monkeypatch) -> None:
    _mock_trivy_run(monkeypatch, trivy_present=False)
    out = scan_container_image(image_ref="nginx:1.25")
    assert out["status"] == "partial"
    assert out["tool_metadata"]["engine_available"] is False


def test_trivy_disabled_env_returns_partial(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TRIVY_DISABLED", "1")
    _mock_trivy_run(monkeypatch, trivy_present=True)
    out = scan_container_image(image_ref="nginx:1.25")
    assert out["status"] == "partial"
    assert out["tool_metadata"]["engine_available"] is False


def test_trivy_nonzero_exit_returns_error(monkeypatch) -> None:
    _mock_trivy_run(
        monkeypatch, trivy_present=True, returncode=2,
        stderr="trivy error: DB out of date",
    )
    out = scan_container_image(image_ref="nginx:1.25")
    assert out["status"] == "error"
    assert "DB out of date" in out["error"]


def test_trivy_invalid_json_returns_error(monkeypatch) -> None:
    import shutil
    import subprocess

    monkeypatch.setattr(
        shutil, "which",
        lambda binary: "/usr/local/bin/trivy",
    )
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = "not json"
    fake_result.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake_result))
    out = scan_container_image(image_ref="nginx:1.25")
    assert out["status"] == "error"
    assert "JSON" in out["error"]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_canonical_trivy_output_emits_findings(monkeypatch) -> None:
    _mock_trivy_run(monkeypatch)
    out = scan_container_image(image_ref="nginx:1.25")

    assert out["status"] == "ok"
    findings = _get_emitted()
    # Fixture has 3 distinct (CVE, pkg, version) tuples.
    assert len(findings) == 3
    # Per-finding properties.
    cves = sorted(f["cve"] for f in findings)
    assert cves == ["CVE-2023-12345", "CVE-2024-00001", "GHSA-XXXX-YYYY-ZZZZ"]


def test_finding_carries_severity_from_trivy(monkeypatch) -> None:
    _mock_trivy_run(monkeypatch)
    scan_container_image(image_ref="nginx:1.25")

    findings = {f["cve"]: f for f in _get_emitted()}
    assert findings["CVE-2023-12345"]["severity"] == "high"
    assert findings["CVE-2024-00001"]["severity"] == "medium"
    assert findings["GHSA-XXXX-YYYY-ZZZZ"]["severity"] == "critical"


def test_finding_carries_cwe_when_trivy_provides_one(monkeypatch) -> None:
    _mock_trivy_run(monkeypatch)
    scan_container_image(image_ref="nginx:1.25")

    findings = {f["cve"]: f for f in _get_emitted()}
    assert findings["CVE-2023-12345"]["cwe"] == "CWE-787"
    assert findings["CVE-2024-00001"]["cwe"] == "CWE-190"


def test_finding_target_is_image_ref(monkeypatch) -> None:
    _mock_trivy_run(monkeypatch)
    scan_container_image(image_ref="nginx:1.25")

    for f in _get_emitted():
        assert f["target"] == "nginx:1.25"


def test_finding_poc_includes_trivy_command(monkeypatch) -> None:
    _mock_trivy_run(monkeypatch)
    scan_container_image(image_ref="nginx:1.25")

    findings = _get_emitted()
    assert any("trivy image" in f["poc_script_code"] for f in findings)


def test_unpatched_vuln_remediation_mentions_no_fix(monkeypatch) -> None:
    """CVE-2024-00001 has no FixedVersion — remediation must signal
    this to the operator (don't recommend a non-existent upgrade)."""
    _mock_trivy_run(monkeypatch)
    scan_container_image(image_ref="nginx:1.25")

    findings = {f["cve"]: f for f in _get_emitted()}
    rem = findings["CVE-2024-00001"]["remediation_steps"].lower()
    assert "no fixed version" in rem or "unpatched" in rem


# ---------------------------------------------------------------------------
# Trivy invocation
# ---------------------------------------------------------------------------


def test_trivy_command_includes_image_ref(monkeypatch) -> None:
    run_mock = _mock_trivy_run(monkeypatch)
    scan_container_image(image_ref="registry.example.com/foo/bar:v1")

    cmd = run_mock.call_args[0][0]
    assert "trivy" in cmd[0]
    assert "image" in cmd
    assert "--format" in cmd
    assert "json" in cmd
    assert "registry.example.com/foo/bar:v1" in cmd


def test_trivy_command_does_not_set_skip_db_update(monkeypatch) -> None:
    """iter-20 (commit 9082b4a) dropped `--skip-db-update` after the
    nginx-vuln bench hit `FATAL ... DB error: --skip-db-update
    cannot be specified on the first run` inside the strix-sandbox.
    The entrypoint's lazy-init pre-fetches the DB on container
    start, but the tool server (invoked via sudo) bypasses the
    entrypoint, so the first tool-server-invoked trivy call always
    hit a missing DB and `--skip-db-update` blocked the recovery
    path. Without the flag, trivy is idempotent: uses existing DB
    if fresh, refreshes once otherwise. This test was previously
    asserting the flag IS present; iter-20 inverted it."""
    run_mock = _mock_trivy_run(monkeypatch)
    scan_container_image(image_ref="nginx:1.25")

    cmd = run_mock.call_args[0][0]
    assert "--skip-db-update" not in cmd


def test_docker_entrypoint_bypasses_oci_proxy(monkeypatch) -> None:
    """iter-27.6 — the nginx-vuln bench failed with
    `FATAL ... Unable to initialize the Java DB ... unexpected EOF`
    because trivy tried to fetch trivy-java-db from mirror.gcr.io
    through the sandbox's Caido proxy, which truncates OCI
    artifacts. trivy 0.70.0 doesn't have `--disable-analyzers`,
    and `--skip-java-db-update` fails on first run. The fix:
    sandbox-side NO_PROXY for OCI registries so trivy / grype /
    syft / dockle can bypass Caido entirely when pulling vuln
    DBs.

    Regression-guards the entrypoint, since the python-side
    trivy invocation has no knobs that fix this on its own.
    """
    from pathlib import Path
    src = (
        Path(__file__).resolve().parents[3]
        / "containers" / "docker-entrypoint.sh"
    )
    text = src.read_text()
    # NO_PROXY must include at least the OCI mirrors trivy and grype
    # pull from. Without these entries Caido MITMs the OCI artifacts
    # and truncates them (the original nginx-vuln 0/4 root cause).
    assert "NO_PROXY" in text, (
        "docker-entrypoint.sh must export NO_PROXY for OCI registries"
    )
    for host in ("mirror.gcr.io", "ghcr.io"):
        assert host in text, (
            f"NO_PROXY must include OCI mirror {host!r} so trivy/grype "
            f"DB fetches don't go through the Caido MITM proxy"
        )


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


def test_same_cve_pkg_dedup_within_image(monkeypatch) -> None:
    """If Trivy reports the same (CVE, pkg, version) twice (e.g.
    from two layers), only ONE finding should emit."""
    duplicated = json.loads(json.dumps(_TRIVY_REPORT_FIXTURE))
    # Duplicate the libssl finding.
    duplicated["Results"][0]["Vulnerabilities"].append(
        duplicated["Results"][0]["Vulnerabilities"][0],
    )
    _mock_trivy_run(monkeypatch, report=duplicated)
    scan_container_image(image_ref="nginx:1.25")

    cve_ids = [f["cve"] for f in _get_emitted()]
    assert cve_ids.count("CVE-2023-12345") == 1


def test_drafts_populate_when_tracer_unavailable(monkeypatch) -> None:
    """iter-27.8 — the drafts list (the SpecialistResult return-shape
    payload) must be populated regardless of whether the tracer-side
    emit succeeds.

    When this tool runs inside the sandbox tool-server,
    `get_global_tracer()` returns None (the tool-server doesn't
    init one), so `_emit_image_finding` returns None. The old
    code gated draft creation behind `if report_id:`, which meant
    the SpecialistResult shipped back with `findings=[]` despite
    trivy finding hundreds of CVEs. Caught 2026-05-24 during the
    iter-27.6/27.7 nginx-vuln re-bench: 0/4 recall despite 189
    raw trivy hits.

    scan_sast already follows the "draft always, tracer maybe"
    pattern — this regression-guards parity.
    """
    import strix.telemetry.tracer as tracer_mod
    monkeypatch.setattr(tracer_mod, "get_global_tracer", lambda: None)

    _mock_trivy_run(monkeypatch)
    result = scan_container_image(image_ref="nginx:1.25")

    # The registry-level wrapper coerces SpecialistResult to a dict
    # before returning. Access either way.
    status = result["status"] if isinstance(result, dict) else result.status
    findings = (
        result["findings"] if isinstance(result, dict) else result.findings
    )
    assert status == "ok"
    assert len(findings) > 0, (
        "drafts must populate even when tracer is unavailable "
        "(scan_sast already does this — see iter-27.8 fix)"
    )


# ---------------------------------------------------------------------------
# Pure-function tests — no subprocess
# ---------------------------------------------------------------------------


def test_extract_packages_and_vulns_counts() -> None:
    packages, vulns = _extract_packages_and_vulns(_TRIVY_REPORT_FIXTURE)
    # 3 vulnerable packages, all observed via Vulnerabilities (Packages
    # array isn't populated in the fixture — same shape Trivy emits
    # without --list-all-pkgs).
    assert len(packages) == 3
    assert len(vulns) == 3
    pkg_names = sorted(p.name for p in packages)
    assert pkg_names == ["libpng16-16", "libssl1.1", "lodash"]


def test_extract_packages_and_vulns_handles_empty_report() -> None:
    packages, vulns = _extract_packages_and_vulns({})
    assert packages == []
    assert vulns == []


def test_extract_packages_and_vulns_handles_missing_results() -> None:
    packages, vulns = _extract_packages_and_vulns({"SchemaVersion": 2})
    assert packages == []
    assert vulns == []


def test_normalise_ecosystem_os_collapses() -> None:
    assert _normalise_ecosystem("debian") == "os"
    assert _normalise_ecosystem("alpine") == "os"
    assert _normalise_ecosystem("rhel") == "os"


def test_normalise_ecosystem_lang_preserves() -> None:
    assert _normalise_ecosystem("npm") == "npm"
    assert _normalise_ecosystem("gomod") == "go"
    assert _normalise_ecosystem("gem") == "rubygems"
    assert _normalise_ecosystem("pip") == "pypi"


def test_normalise_ecosystem_unknown_passes_through() -> None:
    assert _normalise_ecosystem("nonsense") == "nonsense"


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------


def test_scan_container_image_registered_in_specialist_registry() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor

    desc = get_specialist_descriptor("scan_container_image")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "container-image-specialist"


def test_scan_container_image_in_lead_container_image_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog

    catalog = get_lead_tool_catalog(target_types=["container_image"])
    assert "scan_container_image" in catalog
    # The container_image catalog should NOT carry DAST tools — they
    # don't apply to a registry-resident artefact.
    assert "scan_xss" not in catalog
    assert "scan_sqli" not in catalog
    assert "browser_action" not in catalog


def test_lead_asset_routing_for_container_image() -> None:
    """The lead's per-asset guidance must reference scan_container_image
    explicitly. Without it the agent has no anchor."""
    from strix.agents.lead_agent.lead_agent import _PER_ASSET_GUIDANCE

    guidance = _PER_ASSET_GUIDANCE.get("container_image", "")
    assert "scan_container_image" in guidance
    assert "Trivy" in guidance or "trivy" in guidance


def test_test_plan_includes_container_image_categories() -> None:
    """`_CATEGORIES_BY_TARGET_TYPE` must list container_image so
    `run.test_plan` events surface a sensible plan."""
    from strix.telemetry.test_plan import _CATEGORIES_BY_TARGET_TYPE

    cats = _CATEGORIES_BY_TARGET_TYPE.get("container_image")
    assert cats is not None
    assert len(cats) >= 3
    names = {name for name, _ in cats}
    assert "os_package_cves" in names
    assert "lang_package_cves" in names
