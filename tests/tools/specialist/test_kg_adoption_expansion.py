"""Integration tests for KG-adoption expansion (PR after #242).

Pins that each of the four expanded scanners (scan_ssrf, scan_idor,
csrf_check, authz_matrix) correctly populates a Vuln + Surface +
AFFECTS triple in the §3 KG when its emit-path runs.

Strategy: each test fabricates a successful-emit scenario via a
fake tracer, then asserts the KG has the expected node/edge shape.
Counts only — we don't pin specific node IDs because the global
counter is shared and may have prior entries.

The kg_emit helper itself is exhaustively tested in
tests/agents/test_kg_emit.py — these tests just confirm the
wiring at the scanner side.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents import knowledge_graph as kg
from strix.agents import kg_emit


@pytest.fixture(autouse=True)
def _reset_kg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    kg.reset_for_testing()
    kg_emit.reset_surface_cache_for_testing()
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)


def _kg_has_finding(category: str, cwe: str) -> bool:
    """Helper — did any Vuln node land for this category+cwe?"""
    g = kg.get_kg()
    vulns = g.query_nodes(type="Vuln")
    return any(
        v.props.get("category") == category and v.props.get("cwe") == cwe
        for v in vulns
    )


# ---------------------------------------------------------------------------
# scan_ssrf
# ---------------------------------------------------------------------------


def test_ssrf_in_band_emit_populates_kg() -> None:
    """scan_ssrf._record_in_kg() is called after a successful in-band emit."""
    from strix.tools.specialist.scan_ssrf import _record_in_kg

    _record_in_kg(
        finding_id="F-001",
        url="https://app/api/fetch?url=...",
        param="url",
        severity="critical",
        via_oob=False,
    )

    assert _kg_has_finding(category="ssrf", cwe="CWE-918")
    vulns = kg.get_kg().query_nodes(type="Vuln", filters={"category": "ssrf"})
    assert vulns[0].props["detection_kind"] == "in_band_fingerprint"


def test_ssrf_oob_emit_carries_oob_marker() -> None:
    from strix.tools.specialist.scan_ssrf import _record_in_kg

    _record_in_kg(
        finding_id="F-002",
        url="https://app/proxy",
        param="target",
        severity="high",
        via_oob=True,
    )

    vulns = kg.get_kg().query_nodes(type="Vuln", filters={"category": "ssrf"})
    assert vulns[0].props["detection_kind"] == "oob"
    # OOB confirmation gets higher confidence than in-band fingerprint.
    assert vulns[0].props["confidence"] == 0.95


def test_ssrf_dedup_one_surface_per_endpoint_param() -> None:
    """Two probes against the same (url, param) → 1 Surface, 2 Vulns."""
    from strix.tools.specialist.scan_ssrf import _record_in_kg

    for i in range(2):
        _record_in_kg(
            finding_id=f"F-{i:03d}",
            url=f"https://app/proxy?attempt={i}",
            param="url",
            severity="high",
            via_oob=False,
        )

    g = kg.get_kg()
    assert g.stats()["node_types"]["Surface"] == 1
    assert g.stats()["node_types"]["Vuln"] == 2
    assert g.stats()["edge_types"]["AFFECTS"] == 2


# ---------------------------------------------------------------------------
# scan_idor
# ---------------------------------------------------------------------------


def test_idor_cross_session_emit_uses_cwe_639() -> None:
    from strix.tools.specialist.scan_idor import _record_in_kg

    _record_in_kg(
        finding_id="F-100",
        url="https://app/api/users/42",
        accessor_label="user_b",
        severity="high",
        cwe="CWE-639",
    )

    assert _kg_has_finding(category="idor", cwe="CWE-639")
    vulns = kg.get_kg().query_nodes(type="Vuln", filters={"cwe": "CWE-639"})
    assert vulns[0].props["detection_kind"] == "cross_session_read"


def test_idor_missing_auth_uses_cwe_862() -> None:
    from strix.tools.specialist.scan_idor import _record_in_kg

    _record_in_kg(
        finding_id="F-101",
        url="https://app/api/admin/users",
        accessor_label="anon",
        severity="critical",
        cwe="CWE-862",
    )

    assert _kg_has_finding(category="missing_auth", cwe="CWE-862")
    vulns = kg.get_kg().query_nodes(type="Vuln", filters={"cwe": "CWE-862"})
    assert vulns[0].props["detection_kind"] == "anon_read"


def test_idor_different_accessors_different_surfaces() -> None:
    """Same URL, different accessor labels → different Surfaces (because
    the surrogate `param` field carries the accessor)."""
    from strix.tools.specialist.scan_idor import _record_in_kg

    _record_in_kg(
        finding_id="F-200",
        url="https://app/api/users/42",
        accessor_label="user_b",
        severity="high",
        cwe="CWE-639",
    )
    _record_in_kg(
        finding_id="F-201",
        url="https://app/api/users/42",
        accessor_label="anon",
        severity="critical",
        cwe="CWE-862",
    )

    g = kg.get_kg()
    # Two surfaces — one per accessor.
    assert g.stats()["node_types"]["Surface"] == 2
    assert g.stats()["node_types"]["Vuln"] == 2


# ---------------------------------------------------------------------------
# csrf_check
# ---------------------------------------------------------------------------


def test_csrf_emit_populates_kg_with_post_method() -> None:
    """csrf_check._emit_finding records a Vuln + Surface{method=POST}
    + AFFECTS via the in-function side-effect."""
    from strix.tools.csrf_check.csrf_check import _emit_finding
    from unittest.mock import patch, MagicMock

    # MagicMock tracer that ALSO returns None from get_run_dir, so the
    # kg_emit helper falls through to STRIX_RUN_DIR (the tmp_path
    # set in the fixture). Without this, kg_emit would create a
    # literal "MagicMock/" directory in cwd.
    fake_tracer = MagicMock()
    fake_tracer.add_vulnerability_report.return_value = "F-300"
    fake_tracer.get_run_dir.return_value = None

    with patch(
        "strix.telemetry.tracer.get_global_tracer",
        return_value=fake_tracer,
    ):
        _emit_finding(
            title="CSRF on /api/email-update",
            severity="high",
            target="https://app",
            endpoint="https://app/api/email-update",
            description="missing csrf token",
            description_plain="missing csrf token",
            recommended_action="add a token",
        )

    assert _kg_has_finding(category="csrf", cwe="CWE-352")
    surface = kg.get_kg().query_nodes(type="Surface")[0]
    assert surface.props["method"] == "POST"


# ---------------------------------------------------------------------------
# authz_matrix
# ---------------------------------------------------------------------------


def test_authz_unauth_bypass_populates_kg() -> None:
    """authz_matrix unauth-bypass finding lands as a Vuln with the
    method that was probed (GET / POST etc.)."""
    from strix.tools.authz_matrix.authz_matrix import _emit_authz_finding
    from unittest.mock import patch, MagicMock

    fake_tracer = MagicMock()
    fake_tracer.add_vulnerability_report.return_value = "F-400"
    fake_tracer.get_run_dir.return_value = None  # use STRIX_RUN_DIR fallback

    with patch(
        "strix.telemetry.tracer.get_global_tracer",
        return_value=fake_tracer,
    ):
        _emit_authz_finding(
            finding_type="unauth_bypass",
            severity="critical",
            category="missing_auth",
            cwe="CWE-862",
            url="https://app/admin/users",
            method="GET",
            roles_involved=[],
            evidence="200 OK without auth header",
        )

    assert _kg_has_finding(category="missing_auth", cwe="CWE-862")
    vulns = kg.get_kg().query_nodes(type="Vuln")
    assert vulns[0].props["detection_kind"] == "unauth_bypass"
    surface = kg.get_kg().query_nodes(type="Surface")[0]
    assert surface.props["method"] == "GET"


def test_authz_privilege_escalation_records_roles_in_surface_param() -> None:
    from strix.tools.authz_matrix.authz_matrix import _emit_authz_finding
    from unittest.mock import patch, MagicMock

    fake_tracer = MagicMock()
    fake_tracer.add_vulnerability_report.return_value = "F-401"
    fake_tracer.get_run_dir.return_value = None  # use STRIX_RUN_DIR fallback

    with patch(
        "strix.telemetry.tracer.get_global_tracer",
        return_value=fake_tracer,
    ):
        _emit_authz_finding(
            finding_type="priv_esc",
            severity="high",
            category="broken_access_control",
            cwe="CWE-285",
            url="https://app/admin/billing",
            method="POST",
            roles_involved=["analyst", "admin"],
            evidence="analyst saw admin response",
        )

    surface = kg.get_kg().query_nodes(type="Surface")[0]
    # First two roles get joined into the param-surrogate field.
    assert "analyst" in surface.props["param"]


# ---------------------------------------------------------------------------
# Cross-scanner: chain query works across the new scanners
# ---------------------------------------------------------------------------


def test_kg_chain_query_finds_ssrf_to_idor_chain() -> None:
    """End-to-end: an SSRF finding on /api/fetch + an IDOR on
    /api/users/{id} on the same host both land in the KG, and a
    chain query rooted at the SSRF can reach the IDOR via a synthetic
    CHAINS_TO edge — proving the graph is rich enough for §3's
    forward-planning use case."""
    from strix.tools.specialist.scan_ssrf import _record_in_kg as ssrf_kg
    from strix.tools.specialist.scan_idor import _record_in_kg as idor_kg

    ssrf_kg(
        finding_id="F-500", url="https://app/api/fetch", param="url",
        severity="critical", via_oob=False,
    )
    idor_kg(
        finding_id="F-501", url="https://app/api/users/42",
        accessor_label="anon", severity="high", cwe="CWE-862",
    )

    g = kg.get_kg()
    vulns = g.query_nodes(type="Vuln")
    assert len(vulns) == 2
    ssrf_vuln = next(v for v in vulns if v.props.get("category") == "ssrf")
    idor_vuln = next(v for v in vulns if v.props.get("category") == "missing_auth")

    # Add the chain edge — what a chain-detection specialist would do.
    g.add_edge(
        type="CHAINS_TO",
        source=ssrf_vuln.id,
        target=idor_vuln.id,
        props={"rationale": "SSRF can pivot to internal IDOR-vulnerable endpoint"},
    )

    paths = g.query_paths(start_id=ssrf_vuln.id, end_id=idor_vuln.id)
    assert paths == [[ssrf_vuln.id, idor_vuln.id]]


# ---------------------------------------------------------------------------
# Kill switch — adopted scanners respect STRIX_KG_DISABLED
# ---------------------------------------------------------------------------


def test_ssrf_record_no_op_when_kg_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    from strix.tools.specialist.scan_ssrf import _record_in_kg

    _record_in_kg(
        finding_id="F-999", url="https://app/x", param="p",
        severity="high", via_oob=False,
    )
    # No nodes / edges added.
    assert kg.get_kg().stats()["node_count"] == 0
