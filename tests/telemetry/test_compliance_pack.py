"""Tests for compliance evidence-pack output (roadmap §16 / PR #129)."""

from __future__ import annotations

import csv
import hashlib
import json
from io import StringIO
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry.compliance_pack import write_compliance_pack


@pytest.fixture(autouse=True)
def _clean_signing_env(monkeypatch) -> None:
    """Default: no signing key; tests opt in per case."""
    monkeypatch.delenv("STRIX_SIGNING_KEY", raising=False)
    monkeypatch.delenv("STRIX_SIGNING_CMD", raising=False)


def _basic_run_metadata() -> dict[str, Any]:
    return {
        "run_id": "test-run-001",
        "run_name": "test-run-001",
        "start_time": "2026-05-04T00:00:00+00:00",
        "end_time": "2026-05-04T00:30:00+00:00",
        "targets": [{"type": "web_application", "value": "https://example.com"}],
        "scan_mode": "deep",
        "scope_mode": "full",
        "model_name": "openai/gpt-5",
        "user_instructions": "scan everything",
    }


def _basic_findings() -> list[dict[str, Any]]:
    return [
        {
            "id": "vuln-001",
            "title": "SQL injection in /api/users",
            "severity": "high",
            "category": "sql_injection",
            "cwe": "CWE-89",
            "verification_status": "verified",
            "is_kev": False,
            "owasp_top_10": "A03:2021",
            "target": "https://example.com",
            "endpoint": "/api/users",
            "description_plain": "SQLi found",
            "recommended_action": "Use parameterized queries.",
            "compliance_controls": {
                "soc2": ["CC6.1"],
                "pci_dss": ["6.5.1"],
                "owasp_top10": ["A03:2021"],
            },
        },
        {
            "id": "vuln-002",
            "title": "Reflected XSS",
            "severity": "medium",
            "category": "xss",
            "cwe": "CWE-79",
            "verification_status": "pattern_match",
            "is_kev": True,
            "target": "https://example.com",
            "endpoint": "/search",
            "description_plain": "XSS found",
            "recommended_action": "Encode output.",
            "compliance_controls": {
                "soc2": ["CC6.1"],
                "owasp_top10": ["A03:2021"],
            },
        },
    ]


def _make_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "strix_runs" / "test-run-001"
    run_dir.mkdir(parents=True, exist_ok=True)
    # Drop a token report.md that the pack should copy.
    (run_dir / "report.md").write_text("# Test Report\n\nFindings: 2.\n", encoding="utf-8")
    return run_dir


# ---------------------------------------------------------------------------
# Files written
# ---------------------------------------------------------------------------


def test_pack_writes_all_required_files(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    result = write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    pack_dir = Path(result["pack_dir"])
    assert pack_dir.exists()
    expected = {
        "report.md", "findings.csv", "findings.json", "scope.json",
        "scan_metadata.json", "control_attestation.md",
        "manifest.json", "signature.txt",
    }
    written = set(result["files"])
    assert expected <= written


def test_findings_csv_shape(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    csv_text = (out_dir / "test-run-001" / "findings.csv").read_text()
    rows = list(csv.DictReader(StringIO(csv_text)))
    assert len(rows) == 2
    assert rows[0]["title"] == "SQL injection in /api/users"
    # Severity is canonical lowercase per #106.
    assert rows[0]["severity"] == "high"
    assert rows[1]["severity"] == "medium"
    # is_kev → "true"/"false"
    assert rows[0]["is_kev"] == "false"
    assert rows[1]["is_kev"] == "true"


def test_findings_json_carries_full_schema(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    data = json.loads((out_dir / "test-run-001" / "findings.json").read_text())
    assert data["schema_version"] == 1
    assert data["count"] == 2
    assert len(data["findings"]) == 2
    assert data["findings"][0]["compliance_controls"]["soc2"] == ["CC6.1"]


def test_scope_json_extracts_correctly(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    scope = json.loads((out_dir / "test-run-001" / "scope.json").read_text())
    assert scope["run_id"] == "test-run-001"
    assert scope["scan_mode"] == "deep"
    assert scope["targets"][0]["value"] == "https://example.com"
    assert "user_instructions" in scope


def test_scan_metadata_json_round_trips(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    metadata = json.loads(
        (out_dir / "test-run-001" / "scan_metadata.json").read_text()
    )
    assert metadata["run_id"] == "test-run-001"
    assert metadata["scan_mode"] == "deep"


def test_report_md_copied_when_present(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    copied = (out_dir / "test-run-001" / "report.md").read_text()
    assert "# Test Report" in copied


def test_report_md_skipped_when_absent(tmp_path) -> None:
    """When run_dir doesn't have a report.md, the pack proceeds
    without it — no crash."""
    run_dir = tmp_path / "strix_runs" / "test-run-001"
    run_dir.mkdir(parents=True, exist_ok=True)
    # No report.md.
    out_dir = tmp_path / "compliance"

    result = write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    assert "report.md" not in result["files"]
    # Other files still written.
    assert "findings.json" in result["files"]


# ---------------------------------------------------------------------------
# Control attestation
# ---------------------------------------------------------------------------


def test_control_attestation_groups_by_framework(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    md = (out_dir / "test-run-001" / "control_attestation.md").read_text()
    assert "# Control attestation" in md
    assert "Total findings: 2" in md
    # Frameworks present in the findings.
    assert "SOC 2" in md
    # CC6.1 has 2 findings (high + medium).
    assert "CC6.1" in md
    assert "CWE-89" in md
    assert "CWE-79" in md


def test_control_attestation_handles_no_findings(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=[],
        run_dir=run_dir,
    )

    md = (out_dir / "test-run-001" / "control_attestation.md").read_text()
    assert "Total findings: 0" in md
    assert "No findings carry compliance-control mappings" in md


# ---------------------------------------------------------------------------
# Manifest + signature
# ---------------------------------------------------------------------------


def test_manifest_lists_every_file_with_sha256(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    manifest = json.loads(
        (out_dir / "test-run-001" / "manifest.json").read_text()
    )
    assert manifest["schema_version"] == 1
    assert manifest["run_id"] == "test-run-001"
    assert len(manifest["files"]) >= 6  # report.md, findings.csv, findings.json, scope.json, scan_metadata.json, control_attestation.md
    for entry in manifest["files"]:
        assert "path" in entry
        assert "sha256" in entry
        assert "size_bytes" in entry
        assert len(entry["sha256"]) == 64


def test_manifest_sha256_matches_file_bytes(tmp_path) -> None:
    """Sanity: recompute the SHA-256 of one file and compare to manifest."""
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    pack_dir = out_dir / "test-run-001"
    manifest = json.loads((pack_dir / "manifest.json").read_text())
    findings_entry = next(e for e in manifest["files"] if e["path"] == "findings.json")
    actual_bytes = (pack_dir / "findings.json").read_bytes()
    expected_sha = hashlib.sha256(actual_bytes).hexdigest()
    assert findings_entry["sha256"] == expected_sha


def test_signature_unsigned_when_no_key(tmp_path) -> None:
    """No STRIX_SIGNING_KEY → signature_algorithm='none'."""
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    sig = json.loads((out_dir / "test-run-001" / "signature.txt").read_text())
    assert sig["signature_algorithm"] == "none"
    assert sig["signature"] is None
    # Manifest hash still recorded.
    assert "manifest_hash" in sig
    assert len(sig["manifest_hash"]) == 64


def test_signature_signed_with_key(monkeypatch, tmp_path) -> None:
    """STRIX_SIGNING_KEY set → HMAC signature in signature.txt."""
    monkeypatch.setenv("STRIX_SIGNING_KEY", "audit-pack-key")
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    sig = json.loads((out_dir / "test-run-001" / "signature.txt").read_text())
    assert sig["signature_algorithm"] == "hmac-sha256"
    assert sig["signature"] is not None
    assert sig["key_fingerprint"] is not None
    assert sig["bundle_run_id"] == "test-run-001"


# ---------------------------------------------------------------------------
# Output structure + return values
# ---------------------------------------------------------------------------


def test_pack_dir_is_run_id_subdir(tmp_path) -> None:
    """`<output_dir>/<run_id>/` is the exact target."""
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    result = write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    assert result["pack_dir"] == str((out_dir / "test-run-001").resolve())


def test_result_carries_chain_terminal_hash(tmp_path) -> None:
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    result = write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    assert "chain_terminal_hash" in result
    assert isinstance(result["chain_terminal_hash"], str)


def test_idempotent_overwrite(tmp_path) -> None:
    """Running write_compliance_pack twice on the same output_dir
    overwrites cleanly — auditors regenerating the pack don't get
    a stale-file mix."""
    run_dir = _make_run_dir(tmp_path)
    out_dir = tmp_path / "compliance"

    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=_basic_findings(),
        run_dir=run_dir,
    )

    # Different findings the second time.
    write_compliance_pack(
        output_dir=out_dir,
        run_id="test-run-001",
        run_metadata=_basic_run_metadata(),
        findings=[],
        run_dir=run_dir,
    )

    data = json.loads((out_dir / "test-run-001" / "findings.json").read_text())
    assert data["count"] == 0
