"""Tests for the KG-integration wiring that closes the post-#263
audit gaps. Covers:

  1. **Tracer auto-emit** — every `add_vulnerability_report` with
     an HTTP endpoint emits a `Vuln + Surface + AFFECTS` triple
     automatically (so nuclei / misconfig / domain-rep / greynoise /
     monitoring_posture / otx_lookup don't have to call
     `record_finding_in_kg` themselves; the threat-intel ones
     still wire `record_threat_intel_in_kg` for the Asset triple).
  2. **`record_code_finding_in_kg`** — the new code-location
     Surface variant for SAST + IaC.
  3. **Dedup** — auto-emit + explicit `record_finding_in_kg` calls
     don't double-count Surface nodes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents import knowledge_graph as kg
from strix.agents.kg_emit import (
    record_code_finding_in_kg,
    record_finding_in_kg,
    reset_code_surface_cache_for_testing,
    reset_surface_cache_for_testing,
)


@pytest.fixture(autouse=True)
def _isolated_kg(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Hard reset between tests: KG + surface caches + global tracer.
    Without the tracer reset, `set_global_tracer(t)` in tests below
    leaks into downstream test files that read the global tracer."""
    kg.reset_for_testing()
    reset_surface_cache_for_testing()
    reset_code_surface_cache_for_testing()
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    # Clear the global tracer before AND after each test so a test
    # that calls `_new_tracer()` doesn't bleed into the next.
    from strix.telemetry import tracer as _tracer_mod
    monkeypatch.setattr(_tracer_mod, "_global_tracer", None)
    yield
    monkeypatch.setattr(_tracer_mod, "_global_tracer", None)


# ---------------------------------------------------------------------------
# Tracer auto-emit — URL-shaped findings
# ---------------------------------------------------------------------------


def _new_tracer():
    from strix.telemetry.tracer import Tracer, set_global_tracer
    t = Tracer("kg-auto-emit-test")
    set_global_tracer(t)
    t.set_scan_config({
        "targets": [{"type": "web_application", "value": "https://app.test"}],
    })
    return t


def test_tracer_auto_emit_creates_kg_triple_for_http_finding() -> None:
    tracer = _new_tracer()
    tracer.add_vulnerability_report(
        title="Nuclei matched some-template at /api/v1/users",
        severity="high",
        category="nuclei",
        cwe="CWE-89",
        endpoint="https://app.test/api/v1/users",
        verification_status="verified",
    )
    g = kg.get_kg()
    stats = g.stats()
    assert stats["node_types"].get("Vuln", 0) == 1
    assert stats["node_types"].get("Surface", 0) == 1
    assert stats["edge_types"].get("AFFECTS", 0) == 1


def test_tracer_auto_emit_skips_non_http_endpoint() -> None:
    """SAST / IaC findings address `file:line` not URL — the
    auto-emit must skip them so the code-location adapter
    (`record_code_finding_in_kg`) is the single emitter for that
    Surface shape (no duplicate / wrong-shape Surfaces)."""
    tracer = _new_tracer()
    tracer.add_vulnerability_report(
        title="SAST semgrep rule matched",
        severity="medium",
        category="sast",
        cwe="CWE-89",
        endpoint="src/auth.py:42",
        target="repo://test",
        verification_status="pattern_match",
    )
    g = kg.get_kg()
    # No URL-shape Surface emitted.
    assert g.stats()["node_types"].get("Surface", 0) == 0


def test_tracer_auto_emit_skips_when_kg_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    tracer = _new_tracer()
    tracer.add_vulnerability_report(
        title="Finding",
        severity="high",
        category="nuclei",
        cwe="CWE-89",
        endpoint="https://app.test/x",
        verification_status="verified",
    )
    assert kg.get_kg().stats()["node_count"] == 0


def test_tracer_auto_emit_handles_missing_endpoint() -> None:
    """Findings without `endpoint` (e.g. compliance posture rows)
    must not crash the auto-emit path."""
    tracer = _new_tracer()
    tracer.add_vulnerability_report(
        title="Posture row",
        severity="info",
        category="compliance_attestation",
        cwe="CWE-1390",
        target="https://app.test",
        verification_status="verified",
    )
    g = kg.get_kg()
    # `target` IS a URL so auto-emit DOES fire (target falls back
    # to endpoint in the helper). One Surface, one Vuln.
    assert g.stats()["node_types"].get("Surface", 0) == 1


def test_tracer_auto_emit_dedups_against_explicit_record() -> None:
    """A scanner that calls BOTH the tracer auto-emit AND an
    explicit `record_finding_in_kg` (to set extra props like
    `db_engine`) should land on the SAME Surface node — the
    surface cache keys on `(canonical_url, param, method)`."""
    tracer = _new_tracer()
    report_id = tracer.add_vulnerability_report(
        title="SQLi at /api/search",
        severity="high",
        category="sqli",
        cwe="CWE-89",
        endpoint="https://app.test/api/search",
        verification_status="verified",
    )
    # Scanner adds db_engine via explicit call — same url+param+method.
    record_finding_in_kg(
        finding_id=report_id,
        url="https://app.test/api/search",
        param="",
        cwe="CWE-89",
        severity="high",
        category="sqli",
        method="GET",
        db_engine="postgres",
    )
    stats = kg.get_kg().stats()
    # One Surface (dedup). Two Vulns (auto-emit + explicit).
    assert stats["node_types"].get("Surface", 0) == 1
    assert stats["node_types"].get("Vuln", 0) == 2


# ---------------------------------------------------------------------------
# Code-location Surface (record_code_finding_in_kg)
# ---------------------------------------------------------------------------


def test_code_finding_emits_vuln_surface_affects() -> None:
    vuln_id, surface_id = record_code_finding_in_kg(
        finding_id="vuln-0001",
        file_path="src/auth.py",
        start_line=42,
        end_line=58,
        cwe="CWE-287",
        severity="high",
        category="auth_bypass",
        rule_id="strix.python.auth.missing-check",
    )
    assert vuln_id is not None
    assert surface_id is not None
    g = kg.get_kg()
    surface = g.get_node(surface_id)
    assert surface.props["file"] == "src/auth.py"
    assert surface.props["start_line"] == 42
    assert surface.props["end_line"] == 58
    assert surface.props["kind"] == "code_location"
    edges = g.query_edges(
        type="AFFECTS", source=vuln_id, target=surface_id,
    )
    assert len(edges) == 1
    assert edges[0].props["rule_id"] == "strix.python.auth.missing-check"


def test_code_finding_dedups_on_file_line() -> None:
    """Two SAST rules firing on the same line → one Surface,
    two Vulns. Same shape as URL+param dedup for DAST."""
    record_code_finding_in_kg(
        finding_id="vuln-A",
        file_path="src/auth.py", start_line=42,
        cwe="CWE-287", severity="high",
        category="auth_bypass", rule_id="rule-a",
    )
    record_code_finding_in_kg(
        finding_id="vuln-B",
        file_path="src/auth.py", start_line=42,
        cwe="CWE-862", severity="medium",
        category="auth", rule_id="rule-b",
    )
    stats = kg.get_kg().stats()
    assert stats["node_types"].get("Surface", 0) == 1
    assert stats["node_types"].get("Vuln", 0) == 2


def test_code_finding_distinguishes_url_surface_from_code_surface() -> None:
    """A Surface emitted by DAST and a Surface emitted by SAST for
    the same logical defect must NOT collide — they're keyed in
    separate caches and carry different `kind` props."""
    record_finding_in_kg(
        finding_id="dast-1",
        url="https://app.test/api/auth", param="token",
        cwe="CWE-287", severity="high", category="auth_bypass",
    )
    record_code_finding_in_kg(
        finding_id="sast-1",
        file_path="src/auth.py", start_line=42,
        cwe="CWE-287", severity="high", category="auth_bypass",
    )
    stats = kg.get_kg().stats()
    # Two Surfaces — one URL-shape, one code-shape.
    assert stats["node_types"].get("Surface", 0) == 2


def test_code_finding_rejects_empty_file_path() -> None:
    vuln_id, surface_id = record_code_finding_in_kg(
        finding_id="x", file_path="",
        start_line=1, cwe="CWE-89", severity="high",
        category="sast",
    )
    assert vuln_id is None
    assert surface_id is None


def test_code_finding_rejects_invalid_line_number() -> None:
    vuln_id, surface_id = record_code_finding_in_kg(
        finding_id="x", file_path="src/a.py",
        start_line=0, cwe="CWE-89", severity="high",
        category="sast",
    )
    assert vuln_id is None
    assert surface_id is None


def test_code_finding_skips_when_kg_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    vuln_id, surface_id = record_code_finding_in_kg(
        finding_id="x", file_path="src/a.py",
        start_line=1, cwe="CWE-89", severity="high",
        category="sast",
    )
    assert vuln_id is None
    assert surface_id is None


def test_code_finding_handles_missing_end_line() -> None:
    """IaC findings often have only a start line. The Surface
    should still be emitted; `end_line` is optional."""
    vuln_id, surface_id = record_code_finding_in_kg(
        finding_id="iac-1",
        file_path="Dockerfile",
        start_line=5,
        cwe="CWE-732",
        severity="medium",
        category="misconfig",
    )
    assert vuln_id is not None
    surface = kg.get_kg().get_node(surface_id)
    assert "end_line" not in surface.props
