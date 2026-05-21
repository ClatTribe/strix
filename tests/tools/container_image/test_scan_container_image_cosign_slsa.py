"""Tests for cosign signature + SLSA provenance verification in
`scan_container_image`.

The pre-PR specialist wrapped Trivy only (CVE / misconfig / secret).
Supply-chain primitives — cosign signature verification + SLSA
provenance attestation — were absent. Closes that audit gap.

Tests mock `cosign` subprocess to keep hermetic. The Trivy
subprocess is also mocked (re-using the pattern from
`test_scan_container_image.py`).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.tools.container_image.scan_container_image import (
    _cosign_available,
    _cosign_expected_identity,
    _cosign_expected_issuer,
    _extract_signer_identity,
    _extract_slsa_builder,
    _run_cosign_verify,
    _run_cosign_verify_attestation,
    _signing_policy_strict,
    scan_container_image,
)


# ---------------------------------------------------------------------------
# Test scaffolding
# ---------------------------------------------------------------------------


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
    set_global_tracer(Tracer("test-cosign-slsa"))
    yield


_EMPTY_TRIVY_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "myapp:v1",
    "ArtifactType": "container_image",
    "Results": [],
}


def _mock_subprocess(
    monkeypatch, *,
    trivy_present: bool = True,
    cosign_present: bool = True,
    trivy_report: dict | None = None,
    cosign_verify: tuple[int, str, str] | None = None,
    cosign_attest: tuple[int, str, str] | None = None,
):
    """Patch subprocess.run + shutil.which to simulate Trivy +
    cosign with the supplied outcomes.

    Each cosign_* arg is `(returncode, stdout, stderr)`; None
    falls back to a default `(0, "[]", "")` success.

    Returns the subprocess.run mock for caller inspection.
    """
    import shutil
    import subprocess

    def _which(b):
        if b == "trivy":
            return "/usr/local/bin/trivy" if trivy_present else None
        if b == "cosign":
            return "/usr/local/bin/cosign" if cosign_present else None
        return None

    monkeypatch.setattr(shutil, "which", _which)

    cv = cosign_verify or (0, "[]", "")
    ca = cosign_attest or (0, "[]", "")
    tr_stdout = json.dumps(trivy_report or _EMPTY_TRIVY_REPORT)

    def _run(cmd, **kw):
        out = MagicMock()
        if cmd[0].endswith("trivy"):
            out.returncode = 0 if trivy_present else 1
            out.stdout = tr_stdout
            out.stderr = ""
        elif cmd[0].endswith("cosign"):
            if "verify-attestation" in cmd:
                rc, so, se = ca
            else:
                rc, so, se = cv
            out.returncode = rc
            out.stdout = so
            out.stderr = se
        else:
            out.returncode = 0
            out.stdout = ""
            out.stderr = ""
        return out

    run_mock = MagicMock(side_effect=_run)
    monkeypatch.setattr(subprocess, "run", run_mock)
    return run_mock


def _emitted():
    from strix.telemetry.tracer import get_global_tracer
    return get_global_tracer().get_existing_vulnerabilities()


# ---------------------------------------------------------------------------
# _cosign_available + env flags
# ---------------------------------------------------------------------------


def test_cosign_available_when_binary_on_path(monkeypatch) -> None:
    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/cosign" if b == "cosign" else None)
    monkeypatch.delenv("STRIX_COSIGN_DISABLED", raising=False)
    assert _cosign_available() is True


def test_cosign_unavailable_when_binary_missing(monkeypatch) -> None:
    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: None)
    assert _cosign_available() is False


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
def test_cosign_disabled_env_skips(monkeypatch, val: str) -> None:
    import shutil
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/cosign")
    monkeypatch.setenv("STRIX_COSIGN_DISABLED", val)
    assert _cosign_available() is False


def test_signing_policy_strict_default_off(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_COSIGN_REQUIRE_SIGNED", raising=False)
    assert _signing_policy_strict() is False


def test_signing_policy_strict_env_on(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_COSIGN_REQUIRE_SIGNED", "1")
    assert _signing_policy_strict() is True


def test_expected_identity_and_issuer_from_env(monkeypatch) -> None:
    monkeypatch.setenv(
        "STRIX_COSIGN_EXPECTED_IDENTITY",
        "https://github.com/myorg/.+/.github/workflows/build.yml@.+",
    )
    monkeypatch.setenv(
        "STRIX_COSIGN_EXPECTED_ISSUER",
        "https://token.actions.githubusercontent.com",
    )
    assert "myorg" in _cosign_expected_identity()
    assert "githubusercontent.com" in _cosign_expected_issuer()


def test_expected_identity_unset_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_COSIGN_EXPECTED_IDENTITY", raising=False)
    monkeypatch.delenv("STRIX_COSIGN_EXPECTED_ISSUER", raising=False)
    assert _cosign_expected_identity() is None
    assert _cosign_expected_issuer() is None


# ---------------------------------------------------------------------------
# Subprocess helpers — _run_cosign_verify / _run_cosign_verify_attestation
# ---------------------------------------------------------------------------


def test_run_cosign_verify_success(monkeypatch) -> None:
    payload = [{"optional": {"Subject": "build-bot@myorg"}}]
    _mock_subprocess(
        monkeypatch, cosign_verify=(0, json.dumps(payload), ""),
    )
    signed, parsed, err = _run_cosign_verify("myapp:v1")
    assert signed is True
    assert err is None
    assert parsed is not None
    assert parsed["optional"]["Subject"] == "build-bot@myorg"


def test_run_cosign_verify_failure(monkeypatch) -> None:
    _mock_subprocess(
        monkeypatch, cosign_verify=(1, "", "no signatures found"),
    )
    signed, parsed, err = _run_cosign_verify("myapp:v1")
    assert signed is False
    assert "no signatures" in err


def test_run_cosign_verify_attestation_success(monkeypatch) -> None:
    payload = [{
        "predicate": {
            "builder": {"id": "https://github.com/actions/runner"},
        },
    }]
    _mock_subprocess(
        monkeypatch,
        cosign_attest=(0, json.dumps(payload), ""),
    )
    present, parsed, err = _run_cosign_verify_attestation("myapp:v1")
    assert present is True
    assert err is None
    assert parsed["predicate"]["builder"]["id"].endswith("runner")


def test_run_cosign_verify_attestation_failure(monkeypatch) -> None:
    _mock_subprocess(
        monkeypatch,
        cosign_attest=(1, "", "no matching attestations"),
    )
    present, _, err = _run_cosign_verify_attestation("myapp:v1")
    assert present is False
    assert "no matching" in err


def test_run_cosign_verify_includes_identity_flag(monkeypatch) -> None:
    """When STRIX_COSIGN_EXPECTED_IDENTITY is set, the cosign
    command line must carry `--certificate-identity-regexp <value>`
    so the verification is pinned to the expected signer."""
    monkeypatch.setenv(
        "STRIX_COSIGN_EXPECTED_IDENTITY",
        "https://github.com/myorg/.+",
    )
    run_mock = _mock_subprocess(monkeypatch)
    _run_cosign_verify("myapp:v1")
    # Find the cosign verify call (it's the second one — first is shutil.which check via cosign_available).
    verify_calls = [
        c for c in run_mock.call_args_list
        if c.args and c.args[0] and c.args[0][0].endswith("cosign")
    ]
    assert verify_calls
    cmd = verify_calls[0].args[0]
    assert "--certificate-identity-regexp" in cmd
    idx = cmd.index("--certificate-identity-regexp")
    assert "myorg" in cmd[idx + 1]


# ---------------------------------------------------------------------------
# Identity / builder extractors
# ---------------------------------------------------------------------------


def test_extract_signer_identity_from_optional_subject() -> None:
    assert _extract_signer_identity(
        {"optional": {"Subject": "build@example.com"}}
    ) == "build@example.com"


def test_extract_signer_identity_from_cert_field() -> None:
    cert = "-----BEGIN CERT-----\nMIIEXAMPLE..."
    out = _extract_signer_identity({"Cert": cert})
    assert "BEGIN CERT" in out


def test_extract_signer_identity_empty_when_no_signal() -> None:
    assert _extract_signer_identity({}) == ""
    assert _extract_signer_identity(None) == ""


def test_extract_slsa_builder_from_predicate() -> None:
    payload = {
        "predicate": {
            "builder": {"id": "https://github.com/actions/runner"},
        },
    }
    assert _extract_slsa_builder(payload) == (
        "https://github.com/actions/runner"
    )


def test_extract_slsa_builder_empty_when_missing() -> None:
    assert _extract_slsa_builder({}) == ""
    assert _extract_slsa_builder({"predicate": {}}) == ""
    assert _extract_slsa_builder(None) == ""


# ---------------------------------------------------------------------------
# End-to-end — cosign findings via scan_container_image
# ---------------------------------------------------------------------------


def test_unsigned_image_emits_finding(monkeypatch) -> None:
    """Cosign verify fails → unsigned-image finding emits (medium
    severity when policy is best-effort).

    iter-21.7 expanded the attestation-type sweep to also cover
    `cyclonedx` (SBOM) and `vuln` (VEX) — so when the mock has
    all attestations failing, we get 4 image_signing findings:
    unsigned + missing-SLSA + missing-SBOM + missing-VEX. This
    test pins the UNSIGNED + SLSA findings without over-
    constraining the count (the SBOM/VEX paths are covered in
    `test_scan_container_image_cosign_sbom_vex.py`)."""
    monkeypatch.delenv("STRIX_COSIGN_REQUIRE_SIGNED", raising=False)
    _mock_subprocess(
        monkeypatch,
        cosign_verify=(1, "", "no matching signatures"),
        cosign_attest=(1, "", "no attestation"),  # all 3 attest types fail
    )
    out = scan_container_image(image_ref="myapp:v1")
    assert out["status"] == "ok"
    findings = _emitted()
    image_signing_findings = [
        f for f in findings if f["category"] == "image_signing"
    ]
    titles = {f["title"] for f in image_signing_findings}
    assert any("Unsigned" in t for t in titles)
    assert any("SLSA" in t for t in titles)


def test_unsigned_image_high_severity_under_strict_policy(monkeypatch) -> None:
    """`STRIX_COSIGN_REQUIRE_SIGNED=1` escalates unsigned to high."""
    monkeypatch.setenv("STRIX_COSIGN_REQUIRE_SIGNED", "1")
    _mock_subprocess(
        monkeypatch,
        cosign_verify=(1, "", "no sigs"),
        cosign_attest=(0, "[]", ""),  # SLSA OK
    )
    scan_container_image(image_ref="myapp:v1")
    findings = _emitted()
    unsigned = next(
        f for f in findings
        if f["category"] == "image_signing"
        and "Unsigned" in f["title"]
    )
    assert unsigned["severity"] == "high"


def test_signed_image_emits_no_signing_finding(monkeypatch) -> None:
    """Both cosign verify AND verify-attestation succeed → no
    image_signing findings emit. Successful verification is the
    expected state, not a vulnerability."""
    payload = [{"optional": {"Subject": "build@example.com"}}]
    slsa = [{"predicate": {"builder": {"id": "https://gh/actions"}}}]
    _mock_subprocess(
        monkeypatch,
        cosign_verify=(0, json.dumps(payload), ""),
        cosign_attest=(0, json.dumps(slsa), ""),
    )
    out = scan_container_image(image_ref="myapp:v1")
    findings = _emitted()
    assert not [
        f for f in findings if f["category"] == "image_signing"
    ]
    # Metadata records successful verification for audit trail.
    md = out["tool_metadata"]
    assert md["image_signed"] is True
    assert md["image_signer"] == "build@example.com"
    assert md["slsa_provenance_present"] is True
    assert md["slsa_builder"].endswith("actions")


def test_signed_but_no_slsa_emits_slsa_finding(monkeypatch) -> None:
    """Signature OK but no SLSA attestation → missing-SLSA finding
    (medium, CWE-345). iter-21.7 also emits info-severity SBOM
    and VEX findings under the same mock, so we assert the SLSA
    finding's specific shape rather than the total count."""
    payload = [{"optional": {"Subject": "build@example.com"}}]
    _mock_subprocess(
        monkeypatch,
        cosign_verify=(0, json.dumps(payload), ""),
        cosign_attest=(1, "", "no attestation"),
    )
    scan_container_image(image_ref="myapp:v1")
    findings = [
        f for f in _emitted() if f["category"] == "image_signing"
    ]
    slsa = [f for f in findings if "SLSA" in f["title"]]
    assert len(slsa) == 1
    assert slsa[0]["severity"] == "medium"
    assert slsa[0]["cwe"] == "CWE-345"


def test_cosign_unavailable_skips_signing_phase(monkeypatch) -> None:
    """When cosign binary is missing, the signing/SLSA phase
    silently skips — no findings, no metadata claiming verification."""
    _mock_subprocess(monkeypatch, cosign_present=False)
    out = scan_container_image(image_ref="myapp:v1")
    findings = [
        f for f in _emitted() if f["category"] == "image_signing"
    ]
    assert findings == []
    md = out["tool_metadata"]
    assert md["cosign_available"] is False
    assert md["image_signed"] is False  # default
    assert md["slsa_provenance_present"] is False


def test_cosign_disabled_env_skips_signing_phase(monkeypatch) -> None:
    """`STRIX_COSIGN_DISABLED=1` skips even when cosign binary is present."""
    monkeypatch.setenv("STRIX_COSIGN_DISABLED", "1")
    _mock_subprocess(monkeypatch, cosign_present=True)
    out = scan_container_image(image_ref="myapp:v1")
    md = out["tool_metadata"]
    assert md["cosign_available"] is False


# ---------------------------------------------------------------------------
# Remediation guidance — must reference cosign sign + admission control
# ---------------------------------------------------------------------------


def test_unsigned_finding_remediation_mentions_cosign_sign(monkeypatch) -> None:
    _mock_subprocess(
        monkeypatch,
        cosign_verify=(1, "", "no sigs"),
        cosign_attest=(1, "", "no attestation"),
    )
    scan_container_image(image_ref="myapp:v1")
    unsigned = next(
        f for f in _emitted()
        if "Unsigned" in f["title"]
    )
    rem = unsigned["remediation_steps"].lower()
    assert "cosign sign" in rem
    # Admission-controller recommendation present.
    assert any(t in rem for t in ("kyverno", "gatekeeper", "connaisseur"))


def test_missing_slsa_finding_remediation_mentions_attest(monkeypatch) -> None:
    _mock_subprocess(
        monkeypatch,
        cosign_verify=(0, "[]", ""),
        cosign_attest=(1, "", "no attestation"),
    )
    scan_container_image(image_ref="myapp:v1")
    slsa = next(
        f for f in _emitted()
        if "SLSA" in f["title"]
    )
    rem = slsa["remediation_steps"].lower()
    assert "cosign attest" in rem


# ---------------------------------------------------------------------------
# Lead routing + test_plan
# ---------------------------------------------------------------------------


def test_test_plan_includes_signing_categories() -> None:
    from strix.telemetry.test_plan import _CATEGORIES_BY_TARGET_TYPE

    cats = _CATEGORIES_BY_TARGET_TYPE.get("container_image") or []
    names = {name for name, _ in cats}
    assert "image_signing" in names
    assert "slsa_provenance" in names


def test_lead_routing_mentions_cosign_and_slsa() -> None:
    from strix.agents.lead_agent.lead_agent import _PER_ASSET_GUIDANCE

    guidance = _PER_ASSET_GUIDANCE.get("container_image", "")
    assert "cosign" in guidance.lower()
    assert "slsa" in guidance.lower()
    # Pin the env-var names the operator needs to know.
    assert "STRIX_COSIGN_EXPECTED_IDENTITY" in guidance
