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
# P2 batch — 5 more scanners adopted (jwt_audit, host_header,
# cookie_scoping, open_redirect, cors_check). Each test fires the
# scanner's _emit_finding with a fake tracer + asserts a Vuln + Surface
# triple lands.
# ---------------------------------------------------------------------------


def _patch_tracer(finding_id: str):
    """Helper — fake tracer that captures the finding_id + has a
    get_run_dir() returning None so kg_emit falls through to
    STRIX_RUN_DIR (set in the fixture)."""
    from unittest.mock import MagicMock, patch
    fake = MagicMock()
    fake.add_vulnerability_report.return_value = finding_id
    fake.get_run_dir.return_value = None
    return patch(
        "strix.telemetry.tracer.get_global_tracer",
        return_value=fake,
    )


def test_jwt_audit_emit_populates_kg() -> None:
    from strix.tools.jwt_audit.jwt_audit import _emit_finding

    with _patch_tracer("F-501"):
        _emit_finding(
            title="JWT alg:none accepted",
            severity="critical",
            cwe="CWE-327",
            target="https://app",
            endpoint="https://app/api/auth",
            description="d",
            description_plain="d",
            recommended_action="r",
        )

    assert _kg_has_finding(category="jwt_misconfiguration", cwe="CWE-327")
    surfaces = kg.get_kg().query_nodes(type="Surface")
    assert surfaces[0].props["param"] == "jwt"


def test_host_header_emit_populates_kg() -> None:
    from strix.tools.host_header.host_header_check import _emit_finding

    with _patch_tracer("F-502"):
        _emit_finding(
            title="Host header reflected in password-reset link",
            severity="high",
            category="host_header",
            cwe="CWE-79",
            target="https://app",
            endpoint="https://app/forgot",
            description="d",
            description_plain="d",
            recommended_action="r",
        )

    assert _kg_has_finding(category="host_header", cwe="CWE-79")
    surfaces = kg.get_kg().query_nodes(type="Surface")
    assert surfaces[0].props["param"] == "Host"


def test_cookie_scoping_emit_populates_kg() -> None:
    from strix.tools.cookie_scoping.cookie_scoping_check import _emit_finding

    with _patch_tracer("F-503"):
        _emit_finding(
            title="Session cookie missing Secure flag",
            severity="medium",
            cwe="CWE-1004",
            category="cookie_scoping",
            target="https://app",
            endpoint="https://app",
            description="d",
            description_plain="d",
            recommended_action="r",
        )

    assert _kg_has_finding(category="cookie_scoping", cwe="CWE-1004")


def test_open_redirect_emit_populates_kg() -> None:
    from strix.tools.open_redirect.open_redirect_check import _emit_finding

    with _patch_tracer("F-504"):
        _emit_finding(
            title="Open redirect via `next` param",
            severity="medium",
            target="https://app",
            endpoint="https://app/login",
            description="d",
            description_plain="d",
            recommended_action="r",
        )

    assert _kg_has_finding(category="open_redirect", cwe="CWE-601")
    surfaces = kg.get_kg().query_nodes(type="Surface")
    assert surfaces[0].props["param"] == "redirect_url"


def test_cors_check_emit_populates_kg() -> None:
    from strix.tools.cors_check.cors_deep_check import _emit_finding

    with _patch_tracer("F-505"):
        _emit_finding(
            title="CORS allows null Origin with credentials",
            severity="high",
            target="https://app",
            endpoint="https://app/api",
            description="d",
            description_plain="d",
            recommended_action="r",
        )

    assert _kg_has_finding(category="cors_misconfiguration", cwe="CWE-942")
    surfaces = kg.get_kg().query_nodes(type="Surface")
    assert surfaces[0].props["param"] == "Origin"


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


def test_jwt_audit_kg_no_op_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    from strix.tools.jwt_audit.jwt_audit import _emit_finding

    with _patch_tracer("F-998"):
        _emit_finding(
            title="x", severity="high", cwe="CWE-327",
            target="https://app", endpoint="https://app/x",
            description="d", description_plain="d", recommended_action="r",
        )
    assert kg.get_kg().stats()["node_count"] == 0


# ---------------------------------------------------------------------------
# P2-finish — 10 more specialist scanners adopted via direct
# `_emit_finding` -> `record_finding_in_kg` calls. Each test fires
# the scanner's emit via a mocked tracer + asserts a Vuln + Surface
# triple lands with the expected CWE / category / detection_kind.
# ---------------------------------------------------------------------------


def _assert_vuln(category: str, cwe: str) -> dict:
    """Helper — assert exactly one Vuln with this category+cwe; return its props."""
    g = kg.get_kg()
    vulns = [v for v in g.query_nodes(type="Vuln")
             if v.props.get("category") == category and v.props.get("cwe") == cwe]
    assert len(vulns) == 1, f"expected 1 Vuln for {category}/{cwe}, got {len(vulns)}"
    return vulns[0].props


def test_scan_xxe_populates_kg() -> None:
    from strix.tools.specialist.scan_xxe import _emit_xxe_finding

    with _patch_tracer("F-600"):
        _emit_xxe_finding(
            url="https://app/api/xml",
            payload_label="file_disclosure_passwd",
            target="file:///etc/passwd",
            response_excerpt="root:x:0:0:root:/root:/bin/bash",
            severity="critical",
            cwe="CWE-611",
        )

    props = _assert_vuln("xxe", "CWE-611")
    assert props["finding_id"] == "F-600"
    surface = kg.get_kg().query_nodes(type="Surface")[0]
    assert surface.props["method"] == "POST"
    assert surface.props["param"] == "xml_body"


def test_scan_deserialization_populates_kg() -> None:
    from strix.tools.specialist.scan_deserialization import _emit_finding

    with _patch_tracer("F-601"):
        _emit_finding(
            url="https://app/api/import",
            family="java",
            payload_label="ysoserial_cc5",
            detection_kind="time_delta",
            severity="critical",
            response_excerpt="...",
        )

    props = _assert_vuln("deserialization", "CWE-502")
    assert props["detection_kind"] == "time_delta"
    assert props["confidence"] == 0.97


def test_scan_cmd_injection_populates_kg() -> None:
    from strix.tools.specialist.scan_cmd_injection import _emit_finding

    with _patch_tracer("F-602"):
        _emit_finding(
            url="https://app/api/ping",
            param="host",
            payload_label="bash_command_substitution",
            payload="$(id)",
            response_excerpt="uid=33(www-data)",
            os_label="unix",
        )

    props = _assert_vuln("cmd_injection", "CWE-78")
    assert props["severity"] == "critical"


def test_scan_ssti_populates_kg() -> None:
    from strix.tools.specialist.scan_ssti import _emit_finding

    with _patch_tracer("F-603"):
        _emit_finding(
            url="https://app/api/render",
            param="template",
            engine_label="Jinja2",
            payload="{{7*7}}",
            expected_product=49,
            response_excerpt="...49...",
            severity="critical",
        )

    props = _assert_vuln("ssti", "CWE-1336")
    assert props["detection_kind"] == "Jinja2"


def test_scan_nosql_injection_populates_kg() -> None:
    from strix.tools.specialist.scan_nosql_injection import _emit_finding

    with _patch_tracer("F-604"):
        _emit_finding(
            url="https://app/api/search",
            param="filter",
            probe_label="ne_null_operator",
            probe_url="...",
            evidence_reason="result set expanded",
            response_excerpt="...",
            severity="high",
        )

    _assert_vuln("nosql_injection", "CWE-943")


def test_scan_path_traversal_populates_kg() -> None:
    from strix.tools.specialist.scan_path_traversal import _emit_finding

    with _patch_tracer("F-605"):
        _emit_finding(
            url="https://app/api/download",
            param="filename",
            payload_label="dot_dot_etc_passwd",
            payload="../../../../etc/passwd",
            response_excerpt="root:x:0:0:",
            severity="critical",
        )

    _assert_vuln("path_traversal", "CWE-22")


def test_scan_secrets_in_response_populates_kg() -> None:
    from strix.tools.specialist.scan_secrets_in_response import _emit_finding

    with _patch_tracer("F-606"):
        _emit_finding(
            url="https://app/.env",
            label="aws_access_key",
            description_label="AWS Access Key ID",
            excerpt="AKIA...",
            severity="critical",
            cwe="CWE-200",
        )

    props = _assert_vuln("secrets_in_response", "CWE-200")
    assert props["detection_kind"] == "aws_access_key"


def test_scan_oauth_populates_kg() -> None:
    from strix.tools.specialist.scan_oauth import _emit_finding

    with _patch_tracer("F-607"):
        _emit_finding(
            url="https://app/oauth/callback",
            issue_label="redirect_uri_open",
            title="OAuth redirect_uri allows open redirect",
            description="d", impact="i",
            technical_analysis="ta",
            poc_description="pd", poc_script_code="psc",
            remediation_steps="rs",
            severity="high",
            cwe="CWE-601",
        )

    _assert_vuln("oauth_misconfiguration", "CWE-601")


def test_scan_business_logic_populates_kg() -> None:
    from strix.tools.specialist.scan_business_logic import _emit_finding

    with _patch_tracer("F-608"):
        _emit_finding(
            url="https://app/api/apply-coupon",
            family="coupon_reapply",
            probe_label="apply_same_code_twice",
            severity="high",
            response_excerpt="balance: $100",
        )

    g = kg.get_kg()
    vulns = g.query_nodes(type="Vuln", filters={"category": "business_logic"})
    assert len(vulns) == 1


def test_scan_subdomain_takeover_populates_kg() -> None:
    from strix.tools.specialist.scan_subdomain_takeover_active import _emit_finding

    with _patch_tracer("F-609"):
        _emit_finding(
            url="https://dangling.example.com",
            service_label="aws_s3",
            fingerprint="NoSuchBucket",
            severity="high",
            takeover_instructions="Create an S3 bucket named ...",
            response_excerpt="...",
            status_code=404,
        )

    _assert_vuln("subdomain_takeover", "CWE-1390")
