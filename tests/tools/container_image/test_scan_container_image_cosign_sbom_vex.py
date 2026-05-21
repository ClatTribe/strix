"""iter-21.7 tests — cosign SBOM (cyclonedx) + VEX (vuln)
attestation paths in `scan_container_image`.

The base cosign + SLSA paths are covered by
`test_scan_container_image_cosign_slsa.py`; this file pins the
new attestation types that extend that integration.

Recall-safety contract:
  * SBOM-attestation absence emits ONE finding, severity `info`
    (default — operators can raise policy via env).
  * VEX-attestation absence emits ONE finding, severity `info`.
  * Both attestation paths share the same `_run_cosign_verify_
    attestation` helper with `attestation_type` kwarg routing.
  * Cosign-unavailable skip path covers SBOM/VEX too (no findings
    emit when the binary isn't on PATH).
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from strix.tools.container_image.scan_container_image import (
    _emit_missing_sbom_attestation_finding,
    _emit_missing_vex_attestation_finding,
    _run_cosign_verify_attestation,
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
    set_global_tracer(Tracer("test-cosign-sbom-vex"))
    yield


_EMPTY_TRIVY_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "myapp:v1",
    "ArtifactType": "container_image",
    "Results": [],
}


def _mock_subprocess(
    monkeypatch,
    *,
    cosign_present: bool = True,
    cosign_verify_rc: int = 0,
    sbom_attest_rc: int = 1,
    sbom_attest_stderr: str = "no attestation",
    vex_attest_rc: int = 1,
    vex_attest_stderr: str = "no attestation",
    slsa_attest_rc: int = 0,
):
    """Patch subprocess.run + shutil.which to give per-attestation-
    type outcomes. The mock examines the `--type X` flag in the
    cosign command line to route to the right return code.

    Defaults: cosign verify succeeds (image signed), SLSA succeeds,
    SBOM + VEX BOTH absent (the new findings should emit).
    """
    import shutil
    import subprocess

    def _which(b):
        if b == "trivy":
            return "/usr/local/bin/trivy"
        if b == "cosign":
            return "/usr/local/bin/cosign" if cosign_present else None
        return None

    monkeypatch.setattr(shutil, "which", _which)

    tr_stdout = json.dumps(_EMPTY_TRIVY_REPORT)

    def _run(cmd, **kw):
        out = MagicMock()
        if cmd[0].endswith("trivy"):
            out.returncode = 0
            out.stdout = tr_stdout
            out.stderr = ""
        elif cmd[0].endswith("cosign"):
            if "verify-attestation" in cmd:
                # Look at the --type argument to dispatch
                attestation_type = None
                if "--type" in cmd:
                    idx = cmd.index("--type")
                    if idx + 1 < len(cmd):
                        attestation_type = cmd[idx + 1]
                if attestation_type == "cyclonedx":
                    out.returncode = sbom_attest_rc
                    out.stderr = sbom_attest_stderr if sbom_attest_rc != 0 else ""
                    out.stdout = "[]" if sbom_attest_rc == 0 else ""
                elif attestation_type == "vuln":
                    out.returncode = vex_attest_rc
                    out.stderr = vex_attest_stderr if vex_attest_rc != 0 else ""
                    out.stdout = "[]" if vex_attest_rc == 0 else ""
                else:  # slsaprovenance
                    out.returncode = slsa_attest_rc
                    out.stderr = "" if slsa_attest_rc == 0 else "no attestation"
                    out.stdout = "[]" if slsa_attest_rc == 0 else ""
            else:
                # cosign verify (signature)
                out.returncode = cosign_verify_rc
                out.stdout = "[]" if cosign_verify_rc == 0 else ""
                out.stderr = "" if cosign_verify_rc == 0 else "no sig"
        else:
            out.returncode = 0
            out.stdout = ""
            out.stderr = ""
        return out

    return monkeypatch.setattr(subprocess, "run", MagicMock(side_effect=_run))


def _emitted():
    from strix.telemetry.tracer import get_global_tracer
    return get_global_tracer().get_existing_vulnerabilities()


# ---------------------------------------------------------------------------
# _run_cosign_verify_attestation routes the --type flag correctly
# ---------------------------------------------------------------------------


def test_run_cosign_verify_attestation_routes_cyclonedx_type(
    monkeypatch,
) -> None:
    """The helper takes `attestation_type` kwarg; verify the flag
    reaches the subprocess command."""
    import subprocess
    captured = {}

    def _run(cmd, **kw):
        captured["cmd"] = list(cmd)
        out = MagicMock()
        out.returncode = 0
        out.stdout = "[]"
        out.stderr = ""
        return out

    monkeypatch.setattr(subprocess, "run", MagicMock(side_effect=_run))
    _run_cosign_verify_attestation("img:v1", attestation_type="cyclonedx")
    # --type cyclonedx must appear in argv
    cmd = captured["cmd"]
    type_idx = cmd.index("--type")
    assert cmd[type_idx + 1] == "cyclonedx"


def test_run_cosign_verify_attestation_routes_vuln_type(
    monkeypatch,
) -> None:
    import subprocess
    captured = {}

    def _run(cmd, **kw):
        captured["cmd"] = list(cmd)
        out = MagicMock()
        out.returncode = 0
        out.stdout = "[]"
        out.stderr = ""
        return out

    monkeypatch.setattr(subprocess, "run", MagicMock(side_effect=_run))
    _run_cosign_verify_attestation("img:v1", attestation_type="vuln")
    cmd = captured["cmd"]
    type_idx = cmd.index("--type")
    assert cmd[type_idx + 1] == "vuln"


# ---------------------------------------------------------------------------
# _emit_* finding emitters
# ---------------------------------------------------------------------------


def test_emit_missing_sbom_attestation_emits_info_finding() -> None:
    rid = _emit_missing_sbom_attestation_finding(
        image_ref="myapp:v1", error="no attestation",
    )
    assert rid is not None
    findings = _emitted()
    assert len(findings) == 1
    f = findings[0]
    assert "cyclonedx" in f["title"].lower() or "sbom" in f["title"].lower()
    assert f["severity"] == "info"
    assert f["category"] == "image_signing"


def test_emit_missing_vex_attestation_emits_info_finding() -> None:
    rid = _emit_missing_vex_attestation_finding(
        image_ref="myapp:v1", error="no attestation",
    )
    assert rid is not None
    findings = _emitted()
    assert len(findings) == 1
    f = findings[0]
    assert "vex" in f["title"].lower()
    assert f["severity"] == "info"


# ---------------------------------------------------------------------------
# Main scan flow — new attestation findings emit alongside existing ones
# ---------------------------------------------------------------------------


def test_signed_image_no_sbom_no_vex_emits_two_info_findings(
    monkeypatch,
) -> None:
    """Image is signed (cosign verify passes) + SLSA passes BUT
    SBOM + VEX both absent → two info findings."""
    _mock_subprocess(
        monkeypatch,
        cosign_verify_rc=0,    # signed
        slsa_attest_rc=0,      # SLSA present
        sbom_attest_rc=1,      # SBOM absent
        vex_attest_rc=1,       # VEX absent
    )
    result = scan_container_image(image_ref="myapp:v1")
    findings = _emitted()
    titles = [f["title"] for f in findings]
    sbom_findings = [t for t in titles if "cyclonedx" in t.lower() or "sbom" in t.lower()]
    vex_findings = [t for t in titles if "vex" in t.lower()]
    assert len(sbom_findings) == 1
    assert len(vex_findings) == 1
    # No "unsigned image" or "missing slsa" findings because both succeeded.
    assert not any("Unsigned" in t for t in titles)
    assert not any("Missing SLSA" in t for t in titles)


def test_all_attestations_present_emits_no_image_signing_findings(
    monkeypatch,
) -> None:
    """When every cosign step succeeds, no image_signing findings.
    Pins the "verified state is silent" contract."""
    _mock_subprocess(
        monkeypatch,
        cosign_verify_rc=0,
        slsa_attest_rc=0,
        sbom_attest_rc=0,
        vex_attest_rc=0,
    )
    result = scan_container_image(image_ref="myapp:v1")
    findings = _emitted()
    assert not any(
        f["category"] == "image_signing" for f in findings
    )


def test_cosign_unavailable_skips_sbom_vex(monkeypatch) -> None:
    """Cosign binary missing → SBOM/VEX never probed, no findings."""
    _mock_subprocess(monkeypatch, cosign_present=False)
    result = scan_container_image(image_ref="myapp:v1")
    findings = _emitted()
    # No image_signing findings at all
    assert not any(
        f["category"] == "image_signing" for f in findings
    )


def test_cosign_disabled_env_skips_sbom_vex(monkeypatch) -> None:
    """STRIX_COSIGN_DISABLED=1 → SBOM/VEX skipped along with the
    rest of the cosign block."""
    _mock_subprocess(monkeypatch, cosign_present=True)
    monkeypatch.setenv("STRIX_COSIGN_DISABLED", "1")
    result = scan_container_image(image_ref="myapp:v1")
    findings = _emitted()
    assert not any(
        f["category"] == "image_signing" for f in findings
    )


def test_unsigned_image_still_probes_sbom_vex(monkeypatch) -> None:
    """Even if the image is unsigned, cosign continues to probe
    SBOM + VEX attestations (they don't require the image to be
    signed first — they're orthogonal supply-chain signals).
    Expected: unsigned + missing-SLSA + missing-SBOM + missing-VEX
    = 4 image_signing findings."""
    _mock_subprocess(
        monkeypatch,
        cosign_verify_rc=1,    # unsigned
        slsa_attest_rc=1,      # missing SLSA
        sbom_attest_rc=1,      # missing SBOM
        vex_attest_rc=1,       # missing VEX
    )
    result = scan_container_image(image_ref="myapp:v1")
    findings = _emitted()
    image_signing = [f for f in findings if f["category"] == "image_signing"]
    assert len(image_signing) == 4
    titles = " | ".join(f["title"] for f in image_signing)
    assert "Unsigned" in titles
    assert "Missing SLSA" in titles
    assert "cyclonedx" in titles.lower() or "sbom" in titles.lower()
    assert "vex" in titles.lower()
