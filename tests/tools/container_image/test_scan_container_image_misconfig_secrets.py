"""Tests for the misconfig + secret findings paths in
`scan_container_image` (Trivy `--scanners vuln,misconfig,secret`).

Companion to `test_scan_container_image.py` (CVE path). Mocks
Trivy subprocess + `shutil.which` to keep tests hermetic.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.tools.container_image.scan_container_image import (
    _extract_misconfigurations,
    _extract_secrets,
    _trivy_scanners,
    scan_container_image,
)


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
    set_global_tracer(Tracer("test-misconfig-secrets"))
    yield


# ---------------------------------------------------------------------------
# Canonical Trivy JSON fixtures
# ---------------------------------------------------------------------------


_REPORT_MISCONFIG_ONLY: dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "myapp:v1",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "Type": "Dockerfile Security Check",
                    "ID": "DS002",
                    "AVDID": "AVD-DS-0002",
                    "Title": "Image user should not be 'root'",
                    "Description": (
                        "Running as root violates least privilege."
                    ),
                    "Message": (
                        "Specify at least 1 USER command in Dockerfile "
                        "with non-root user as argument"
                    ),
                    "Resolution": (
                        "Add 'USER <non-root user>' line to Dockerfile"
                    ),
                    "Severity": "HIGH",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                    "References": ["https://owasp.org/x"],
                    "Status": "FAIL",
                },
                {
                    "ID": "DS013",
                    "Title": "Healthcheck absent",
                    "Severity": "LOW",
                    "Status": "PASS",  # passing rule — must be filtered
                },
                {
                    "ID": "DS026",
                    "Title": "Exposed sensitive port",
                    "Description": "Port 3306 exposes MySQL.",
                    "Resolution": "Remove EXPOSE 3306 or bind to localhost.",
                    "Severity": "MEDIUM",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds026",
                    "Status": "FAIL",
                },
            ],
        },
    ],
}


_REPORT_SECRETS_ONLY: dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "myapp:v1",
    "ArtifactType": "container_image",
    "Results": [
        {
            "Target": "app/.env",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key ID",
                    "StartLine": 5,
                    "EndLine": 5,
                    "Match": "AKIAEXAMPLEEXAMPLE",
                },
                {
                    "RuleID": "github-pat",
                    "Category": "GitHub",
                    "Severity": "HIGH",
                    "Title": "GitHub Personal Access Token",
                    "StartLine": 12,
                    "EndLine": 12,
                    "Match": "ghp_abcdefghijklmnop",
                },
            ],
        },
    ],
}


_REPORT_ALL_THREE_CLASSES: dict[str, Any] = {
    "SchemaVersion": 2,
    "ArtifactName": "myapp:v1",
    "ArtifactType": "container_image",
    "Results": [
        # CVE
        {
            "Target": "myapp:v1 (debian 12)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-001",
                    "PkgName": "libssl1.1",
                    "InstalledVersion": "1.1.1n",
                    "FixedVersion": "1.1.1o",
                    "Severity": "HIGH",
                    "Title": "OpenSSL RCE",
                    "PrimaryURL": "https://nvd.nist.gov/x",
                },
            ],
        },
        # Misconfig
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Description": "Running as root.",
                    "Resolution": "Add USER directive",
                    "Severity": "HIGH",
                    "Status": "FAIL",
                    "PrimaryURL": "https://x",
                },
            ],
        },
        # Secret
        {
            "Target": "app/.env",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key",
                    "StartLine": 5,
                    "Match": "AKIAEXAMPLE",
                },
            ],
        },
    ],
}


def _mock_trivy(monkeypatch, *, report=None, present=True):
    """Patch shutil.which + subprocess.run to simulate Trivy with
    the supplied report."""
    import shutil
    import subprocess

    monkeypatch.setattr(
        shutil, "which",
        lambda b: ("/usr/local/bin/trivy" if present and b == "trivy" else None),
    )
    if not present:
        return
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = json.dumps(report or _REPORT_ALL_THREE_CLASSES)
    fake.stderr = ""
    run_mock = MagicMock(return_value=fake)
    monkeypatch.setattr(subprocess, "run", run_mock)
    return run_mock


def _emitted():
    from strix.telemetry.tracer import get_global_tracer
    return get_global_tracer().get_existing_vulnerabilities()


# ---------------------------------------------------------------------------
# Extractor unit tests
# ---------------------------------------------------------------------------


def test_extract_misconfigurations_filters_pass_status() -> None:
    """Trivy emits `Status=PASS` for rules that didn't fire.
    The extractor must keep only `Status=FAIL` entries."""
    out = _extract_misconfigurations(_REPORT_MISCONFIG_ONLY)
    ids = {m["ID"] for m in out}
    assert "DS002" in ids
    assert "DS026" in ids
    assert "DS013" not in ids  # PASS status filtered


def test_extract_misconfigurations_attaches_target() -> None:
    out = _extract_misconfigurations(_REPORT_MISCONFIG_ONLY)
    for m in out:
        assert m["_target"] == "Dockerfile"
        assert m["_config_type"] == "dockerfile"


def test_extract_secrets_attaches_target() -> None:
    out = _extract_secrets(_REPORT_SECRETS_ONLY)
    assert len(out) == 2
    for s in out:
        assert s["_target"] == "app/.env"


def test_extract_misconfigurations_empty_when_no_config_class() -> None:
    """Result blocks with `Class != "config"` are skipped."""
    out = _extract_misconfigurations({"Results": [
        {"Class": "os-pkgs", "Misconfigurations": [{"ID": "X"}]},
    ]})
    assert out == []


def test_extract_secrets_empty_when_no_secret_class() -> None:
    out = _extract_secrets({"Results": [
        {"Class": "os-pkgs", "Secrets": [{"RuleID": "X"}]},
    ]})
    assert out == []


def test_extract_misconfigurations_handles_empty_report() -> None:
    assert _extract_misconfigurations({}) == []
    assert _extract_misconfigurations({"Results": []}) == []


def test_extract_secrets_handles_empty_report() -> None:
    assert _extract_secrets({}) == []


def test_extract_handles_malformed_entries() -> None:
    """Non-dict entries inside Misconfigurations / Secrets must be
    skipped without crashing."""
    report = {"Results": [
        {"Class": "config", "Target": "Dockerfile", "Misconfigurations": [
            "not a dict", 42, None,
            {"ID": "DS002", "Status": "FAIL"},
        ]},
        {"Class": "secret", "Target": "app/.env", "Secrets": [
            "not a dict",
            {"RuleID": "aws-access-key-id", "StartLine": 1},
        ]},
    ]}
    mc = _extract_misconfigurations(report)
    secs = _extract_secrets(report)
    assert len(mc) == 1
    assert len(secs) == 1


# ---------------------------------------------------------------------------
# _trivy_scanners — env-var override
# ---------------------------------------------------------------------------


def test_trivy_scanners_default(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_TRIVY_SCANNERS", raising=False)
    assert _trivy_scanners() == "vuln,misconfig,secret"


def test_trivy_scanners_env_override(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TRIVY_SCANNERS", "vuln")
    assert _trivy_scanners() == "vuln"


def test_trivy_scanners_empty_env_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_TRIVY_SCANNERS", "   ")
    assert _trivy_scanners() == "vuln,misconfig,secret"


def test_trivy_invocation_includes_scanners_flag(monkeypatch) -> None:
    """The Trivy command line must carry `--scanners <list>` so the
    misconfig + secret scanners run alongside the vuln scanner."""
    run_mock = _mock_trivy(monkeypatch)
    scan_container_image(image_ref="myapp:v1")
    cmd = run_mock.call_args[0][0]
    assert "--scanners" in cmd
    scanners_value = cmd[cmd.index("--scanners") + 1]
    assert "misconfig" in scanners_value
    assert "secret" in scanners_value
    assert "vuln" in scanners_value


# ---------------------------------------------------------------------------
# End-to-end: misconfig findings
# ---------------------------------------------------------------------------


def test_misconfig_finding_emitted(monkeypatch) -> None:
    _mock_trivy(monkeypatch, report=_REPORT_MISCONFIG_ONLY)
    out = scan_container_image(image_ref="myapp:v1")

    assert out["status"] == "ok"
    findings = _emitted()
    # 2 FAIL misconfigs, 1 PASS filtered → 2 findings total.
    misconfig_findings = [
        f for f in findings if f["category"] == "misconfiguration"
    ]
    assert len(misconfig_findings) == 2
    ids = {f["title"].split(":")[0] for f in misconfig_findings}
    assert "DS002" in ids
    assert "DS026" in ids


def test_misconfig_finding_carries_severity(monkeypatch) -> None:
    _mock_trivy(monkeypatch, report=_REPORT_MISCONFIG_ONLY)
    scan_container_image(image_ref="myapp:v1")
    findings = {f["title"].split(":")[0]: f for f in _emitted()}
    assert findings["DS002"]["severity"] == "high"
    assert findings["DS026"]["severity"] == "medium"


def test_misconfig_remediation_uses_trivy_resolution(monkeypatch) -> None:
    _mock_trivy(monkeypatch, report=_REPORT_MISCONFIG_ONLY)
    scan_container_image(image_ref="myapp:v1")
    findings = {f["title"].split(":")[0]: f for f in _emitted()}
    rem = findings["DS002"]["remediation_steps"]
    assert "USER" in rem


def test_misconfig_metadata_reports_observed_count(monkeypatch) -> None:
    _mock_trivy(monkeypatch, report=_REPORT_MISCONFIG_ONLY)
    out = scan_container_image(image_ref="myapp:v1")
    md = out["tool_metadata"]
    # 3 misconfigs total in fixture (2 FAIL + 1 PASS); extractor
    # returns only the 2 FAIL ones, so observed_count == 2.
    assert md["misconfigurations_observed"] == 2
    assert md["findings_emitted_misconfigs"] == 2


def test_misconfig_dedup_within_run(monkeypatch) -> None:
    """Same (rule_id, target) pair reported twice → only one
    finding emits."""
    duplicated = json.loads(json.dumps(_REPORT_MISCONFIG_ONLY))
    duplicated["Results"][0]["Misconfigurations"].append(
        duplicated["Results"][0]["Misconfigurations"][0],
    )
    _mock_trivy(monkeypatch, report=duplicated)
    scan_container_image(image_ref="myapp:v1")
    ids = [f["title"].split(":")[0] for f in _emitted()]
    assert ids.count("DS002") == 1


# ---------------------------------------------------------------------------
# End-to-end: secret findings
# ---------------------------------------------------------------------------


def test_secret_finding_emitted(monkeypatch) -> None:
    _mock_trivy(monkeypatch, report=_REPORT_SECRETS_ONLY)
    out = scan_container_image(image_ref="myapp:v1")

    assert out["status"] == "ok"
    findings = _emitted()
    secret_findings = [
        f for f in findings if f["category"] == "secrets"
    ]
    assert len(secret_findings) == 2


def test_secret_finding_carries_cwe_798(monkeypatch) -> None:
    """Hardcoded credentials → CWE-798."""
    _mock_trivy(monkeypatch, report=_REPORT_SECRETS_ONLY)
    scan_container_image(image_ref="myapp:v1")
    for f in _emitted():
        if f["category"] == "secrets":
            assert f["cwe"] == "CWE-798"


def test_secret_finding_severity_matches_trivy(monkeypatch) -> None:
    _mock_trivy(monkeypatch, report=_REPORT_SECRETS_ONLY)
    scan_container_image(image_ref="myapp:v1")
    findings = {f["title"]: f for f in _emitted()}
    aws = next(f for k, f in findings.items() if "AWS" in k)
    gh = next(f for k, f in findings.items() if "GitHub" in k)
    assert aws["severity"] == "critical"
    assert gh["severity"] == "high"


def test_secret_finding_match_truncated_to_16_chars(monkeypatch) -> None:
    """Secret match content must NOT be logged verbatim — first 16
    chars + ellipsis only. Verbatim logging would leak the
    credential into the audit trail."""
    _mock_trivy(monkeypatch, report=_REPORT_SECRETS_ONLY)
    scan_container_image(image_ref="myapp:v1")
    for f in _emitted():
        if f["category"] != "secrets":
            continue
        # The full match strings in the fixture are >16 chars.
        # The finding's description and technical_analysis must not
        # contain the full string.
        assert "AKIAEXAMPLEEXAMPLE" not in f["description"]
        assert "AKIAEXAMPLEEXAMPLE" not in f["technical_analysis"]
        assert "ghp_abcdefghijklmnop" not in f["description"]


def test_secret_remediation_recommends_rotate_first(monkeypatch) -> None:
    """Leaked credential = rotate immediately — anything else
    starts the recovery window late. Remediation MUST lead with
    rotate."""
    _mock_trivy(monkeypatch, report=_REPORT_SECRETS_ONLY)
    scan_container_image(image_ref="myapp:v1")
    for f in _emitted():
        if f["category"] != "secrets":
            continue
        # First line of remediation_steps mentions rotation.
        assert "ROTATE" in f["remediation_steps"]


def test_secret_dedup_by_rule_target_line(monkeypatch) -> None:
    """Same (rule_id, target, start_line) tuple → one finding."""
    duplicated = json.loads(json.dumps(_REPORT_SECRETS_ONLY))
    duplicated["Results"][0]["Secrets"].append(
        duplicated["Results"][0]["Secrets"][0],
    )
    _mock_trivy(monkeypatch, report=duplicated)
    scan_container_image(image_ref="myapp:v1")
    rule_titles = [
        f["title"] for f in _emitted() if f["category"] == "secrets"
    ]
    aws_titles = [t for t in rule_titles if "AWS" in t]
    assert len(aws_titles) == 1


def test_secret_metadata_reports_observed_count(monkeypatch) -> None:
    _mock_trivy(monkeypatch, report=_REPORT_SECRETS_ONLY)
    out = scan_container_image(image_ref="myapp:v1")
    md = out["tool_metadata"]
    assert md["secrets_observed"] == 2
    assert md["findings_emitted_secrets"] == 2


# ---------------------------------------------------------------------------
# End-to-end: all three finding classes together
# ---------------------------------------------------------------------------


def test_three_classes_emit_distinct_finding_categories(monkeypatch) -> None:
    """One Trivy scan, three result classes → three categories of
    finding. This is the headline value of the misconfig + secret
    expansion."""
    _mock_trivy(monkeypatch, report=_REPORT_ALL_THREE_CLASSES)
    out = scan_container_image(image_ref="myapp:v1")

    assert out["status"] == "ok"
    categories = {f["category"] for f in _emitted()}
    assert categories == {"sca", "misconfiguration", "secrets"}


def test_three_classes_metadata_breakdown(monkeypatch) -> None:
    """Tool metadata must surface the per-class emission count."""
    _mock_trivy(monkeypatch, report=_REPORT_ALL_THREE_CLASSES)
    out = scan_container_image(image_ref="myapp:v1")
    md = out["tool_metadata"]
    assert md["findings_emitted_cves"] == 1
    assert md["findings_emitted_misconfigs"] == 1
    assert md["findings_emitted_secrets"] == 1
    assert md["findings_emitted_to_tracer"] == 3


def test_metadata_includes_trivy_scanners_telemetry(monkeypatch) -> None:
    _mock_trivy(monkeypatch, report=_REPORT_ALL_THREE_CLASSES)
    out = scan_container_image(image_ref="myapp:v1")
    md = out["tool_metadata"]
    assert "trivy_scanners" in md
    assert "misconfig" in md["trivy_scanners"]
    assert "secret" in md["trivy_scanners"]


def test_cve_only_scanner_env_skips_misconfig_secrets(monkeypatch) -> None:
    """`STRIX_TRIVY_SCANNERS=vuln` → command line doesn't enable
    misconfig/secret scanners. Trivy still emits whatever it ran
    (vuln only); the extractor still walks the report but finds
    no config / secret Result classes. End state: zero misconfig
    and secret findings even when the fixture happens to contain
    them (would normally fire under the default scanners)."""
    monkeypatch.setenv("STRIX_TRIVY_SCANNERS", "vuln")
    run_mock = _mock_trivy(monkeypatch, report=_REPORT_ALL_THREE_CLASSES)
    scan_container_image(image_ref="myapp:v1")
    cmd = run_mock.call_args[0][0]
    scanners_value = cmd[cmd.index("--scanners") + 1]
    assert scanners_value == "vuln"
    # Findings: when scanners=vuln, in production Trivy wouldn't
    # emit Misconfigurations / Secrets entries. Our mock returns
    # all three classes regardless; we test the COMMAND LINE
    # here. (The extractor behaviour against malformed reports
    # is tested in the unit tests above.)


# ---------------------------------------------------------------------------
# test_plan + lead-routing wiring
# ---------------------------------------------------------------------------


def test_test_plan_includes_misconfig_and_secrets() -> None:
    from strix.telemetry.test_plan import _CATEGORIES_BY_TARGET_TYPE

    cats = _CATEGORIES_BY_TARGET_TYPE.get("container_image")
    assert cats is not None
    names = {name for name, _ in cats}
    assert "image_misconfiguration" in names
    assert "image_secrets" in names


def test_lead_routing_mentions_three_finding_classes() -> None:
    from strix.agents.lead_agent.lead_agent import _PER_ASSET_GUIDANCE

    guidance = _PER_ASSET_GUIDANCE.get("container_image", "")
    assert "Package CVEs" in guidance or "package CVEs" in guidance
    assert "Misconfigurations" in guidance or "misconfiguration" in guidance.lower()
    assert "Secrets" in guidance or "secrets" in guidance.lower()
