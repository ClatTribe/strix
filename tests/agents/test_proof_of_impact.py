"""Tests for `strix.agents.proof_of_impact` — proof artifact capture
for the `exploited` verification tier (depth #1).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.agents import proof_of_impact
from strix.agents.proof_of_impact import (
    IMPACT_COOKIE_THEFT,
    IMPACT_DATA_DUMP,
    IMPACT_METADATA_EXFIL,
    IMPACT_RCE_OUTPUT,
    capture_proof_of_impact,
)


@pytest.fixture(autouse=True)
def _isolated_run_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> Path:
    """Drop a tracer-shaped fallback so the capture writes into tmp_path."""
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_PROOF_OF_IMPACT_DISABLED", raising=False)
    return tmp_path


# ---------------------------------------------------------------------------
# Happy path — captures land where expected
# ---------------------------------------------------------------------------


def test_capture_returns_path_relative_to_run_dir(_isolated_run_dir: Path) -> None:
    rel = capture_proof_of_impact(
        finding_fingerprint="finding-abc123",
        impact_type=IMPACT_COOKIE_THEFT,
        artifact_bytes="session=DEADBEEF; HttpOnly",
    )
    assert rel is not None
    assert rel.startswith("proof_of_impact/")
    full = _isolated_run_dir / rel
    assert full.exists()
    assert full.read_text() == "session=DEADBEEF; HttpOnly"


def test_capture_accepts_bytes_payload(_isolated_run_dir: Path) -> None:
    payload = b"\x89PNG\r\n\x1a\nrandom binary blob"
    rel = capture_proof_of_impact(
        finding_fingerprint="binary-fp",
        impact_type=IMPACT_RCE_OUTPUT,
        artifact_bytes=payload,
    )
    assert rel is not None
    assert (_isolated_run_dir / rel).read_bytes() == payload


def test_capture_writes_request_context_sibling(
    _isolated_run_dir: Path,
) -> None:
    rel = capture_proof_of_impact(
        finding_fingerprint="fp-with-ctx",
        impact_type=IMPACT_DATA_DUMP,
        artifact_bytes="version()=PostgreSQL 14.2",
        request_context={
            "method": "POST",
            "url": "https://app.test/api/products?id=1' UNION SELECT version()--",
            "response_status": 200,
        },
    )
    assert rel is not None
    full = _isolated_run_dir / rel
    ctx = full.parent / f"{full.stem}.context.json"
    assert ctx.exists()
    data = json.loads(ctx.read_text())
    assert data["method"] == "POST"
    assert data["response_status"] == 200


def test_filename_includes_fingerprint_and_impact_type(
    _isolated_run_dir: Path,
) -> None:
    rel = capture_proof_of_impact(
        finding_fingerprint="abc12345",
        impact_type=IMPACT_METADATA_EXFIL,
        artifact_bytes="iam-role/AdminRole",
    )
    assert rel is not None
    assert "abc12345" in rel
    assert IMPACT_METADATA_EXFIL in rel


def test_unique_fingerprints_keep_separate_files(
    _isolated_run_dir: Path,
) -> None:
    a = capture_proof_of_impact(
        finding_fingerprint="finding-A",
        impact_type=IMPACT_COOKIE_THEFT,
        artifact_bytes="A",
    )
    b = capture_proof_of_impact(
        finding_fingerprint="finding-B",
        impact_type=IMPACT_COOKIE_THEFT,
        artifact_bytes="B",
    )
    assert a != b
    assert (_isolated_run_dir / a).read_text() == "A"
    assert (_isolated_run_dir / b).read_text() == "B"


# ---------------------------------------------------------------------------
# Defensive / failure modes — should never raise, always return None
# ---------------------------------------------------------------------------


def test_unknown_impact_type_returns_none(_isolated_run_dir: Path) -> None:
    rel = capture_proof_of_impact(
        finding_fingerprint="fp",
        impact_type="not-a-real-impact-type",
        artifact_bytes="...",
    )
    assert rel is None


def test_kill_switch_returns_none(
    monkeypatch: pytest.MonkeyPatch, _isolated_run_dir: Path,
) -> None:
    monkeypatch.setenv("STRIX_PROOF_OF_IMPACT_DISABLED", "1")
    rel = capture_proof_of_impact(
        finding_fingerprint="fp",
        impact_type=IMPACT_COOKIE_THEFT,
        artifact_bytes="...",
    )
    assert rel is None


def test_no_run_dir_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    monkeypatch.delenv("STRIX_PROOF_OF_IMPACT_DISABLED", raising=False)
    # Also nuke any leftover global tracer so the fallback to env hits None.
    try:
        from strix.telemetry import tracer as tracer_module
        monkeypatch.setattr(tracer_module, "_global_tracer", None)
    except (AttributeError, ImportError):
        pass

    rel = capture_proof_of_impact(
        finding_fingerprint="fp",
        impact_type=IMPACT_COOKIE_THEFT,
        artifact_bytes="...",
    )
    assert rel is None


def test_fingerprint_sanitised_against_path_traversal(
    _isolated_run_dir: Path,
) -> None:
    """A malicious fingerprint must not escape the proof_of_impact
    directory. The sanitiser strips path separators."""
    rel = capture_proof_of_impact(
        finding_fingerprint="../../etc/passwd",
        impact_type=IMPACT_COOKIE_THEFT,
        artifact_bytes="probe",
    )
    assert rel is not None
    # The resulting path lives inside proof_of_impact/, not at /etc.
    full = (_isolated_run_dir / rel).resolve()
    assert full.is_relative_to(_isolated_run_dir.resolve())
    assert "proof_of_impact" in str(full)
