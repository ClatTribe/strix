"""Tests for iter-21.6 `scan_cloud_imds_passthrough`."""

from __future__ import annotations

from typing import Any

import pytest

# Route through `sys.modules` to get the SUBMODULE object — the
# parent package's `__init__.py` re-exports a function with the
# same name as the submodule (`scan_cloud_imds_passthrough`), which
# shadows the module in the parent's namespace and breaks
# `import strix.tools.cloud_exposure_audit.scan_cloud_imds_passthrough as X`
# (X ends up bound to the function, not the module).
import sys
import strix.tools.cloud_exposure_audit.scan_cloud_imds_passthrough  # noqa: F401,E501  side-effect populates sys.modules
scip = sys.modules[
    "strix.tools.cloud_exposure_audit.scan_cloud_imds_passthrough"
]
scan_cloud_imds_passthrough = scip.scan_cloud_imds_passthrough


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


# ---------------------------------------------------------------------------
# _audit_response — fingerprint matching
# ---------------------------------------------------------------------------


def test_aws_credentials_body_emits_critical() -> None:
    body = (
        '{"Code":"Success","AccessKeyId":"AKIAIOSFODNN7EXAMPLE",'
        '"SecretAccessKey":"...","Token":"..."}'
    )
    resp = {"status": 200, "body": body}
    findings = scip._audit_response("https://x/imds", resp)
    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "imds-passthrough-aws"
    assert f["severity"] == "critical"


def test_aws_instance_id_emits_high() -> None:
    body = '{"instance-id": "i-0123456789abcdef0", "ami-id": "ami-12345"}'
    resp = {"status": 200, "body": body}
    findings = scip._audit_response("https://x/imds", resp)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_gcp_compute_instance_emits_high() -> None:
    body = '{"kind": "compute#instance", "name": "vm-1"}'
    resp = {"status": 200, "body": body}
    findings = scip._audit_response("https://x/metadata", resp)
    assert len(findings) == 1
    assert findings[0]["provider"] == "gcp"


def test_azure_subscription_id_emits_high() -> None:
    body = (
        '{"compute": {"subscriptionId": "12345678-1234-1234-1234-1234567890ab"}}'
    )
    resp = {"status": 200, "body": body}
    findings = scip._audit_response("https://x/metadata", resp)
    assert len(findings) == 1
    assert findings[0]["provider"] == "azure"


def test_no_match_no_finding() -> None:
    """Unrelated 200 OK responses don't trigger findings."""
    resp = {"status": 200, "body": "<html><body>welcome</body></html>"}
    assert scip._audit_response("https://x/imds", resp) == []


def test_non_200_no_finding() -> None:
    """Even with IMDS-shaped body in a 4xx/5xx body, we only fire
    on 200 OK (an error response with IMDS-looking text in it is
    likely a stub / debug response, not an actual passthrough)."""
    resp = {
        "status": 404,
        "body": '{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}',
    }
    assert scip._audit_response("https://x/imds", resp) == []


def test_critical_outranks_high_in_dedupe() -> None:
    """A response matching BOTH critical (creds) and high (instance-id)
    fingerprints emits one finding with the critical severity, not
    two findings."""
    body = (
        '{"AccessKeyId":"AKIAIOSFODNN7EXAMPLE",'
        '"instance-id":"i-0123456789abcdef0"}'
    )
    resp = {"status": 200, "body": body}
    findings = scip._audit_response("https://x/imds", resp)
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"


def test_empty_body_no_finding() -> None:
    assert scip._audit_response("https://x", {"status": 200, "body": ""}) == []


# ---------------------------------------------------------------------------
# scan_cloud_imds_passthrough — end-to-end with mocked HTTP
# ---------------------------------------------------------------------------


def test_scan_error_on_bad_url() -> None:
    # `_normalize_target` accepts hosts with spaces (urlparse is
    # permissive), so we use an unambiguously-bad scheme to exercise
    # the error branch.
    result = scan_cloud_imds_passthrough("ftp://x.com/")
    assert result["status"] == "error"
    assert result["total_findings"] == 0


def test_scan_no_passthrough_zero_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        scip, "_http_get",
        lambda _u, **_k: {"status": 404, "body": "", "headers": {}},
    )
    result = scan_cloud_imds_passthrough("https://x.com/")
    assert result["status"] == "ok"
    assert result["total_findings"] == 0
    assert result["paths_probed"] == len(scip._IMDS_PROBE_PATHS)


def test_scan_one_path_leaks_emits_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When exactly one probe path returns IMDS body, exactly one
    finding emits."""
    def _mock_get(url: str, **_k: Any) -> dict[str, Any]:
        if "/debug/imds" in url:
            return {
                "status": 200,
                "body": '{"instance-id":"i-0123456789abcdef0"}',
                "headers": {},
            }
        return {"status": 404, "body": "", "headers": {}}

    monkeypatch.setattr(scip, "_http_get", _mock_get)
    result = scan_cloud_imds_passthrough("https://x.com/")
    assert result["total_findings"] == 1
    assert "imds-passthrough-aws" in _rule_ids(result["findings"])


def test_scan_multiple_paths_leak_emit_multiple_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A target with multiple IMDS-shaped routes emits one finding
    per route (operator may want to close each separately)."""
    def _mock_get(url: str, **_k: Any) -> dict[str, Any]:
        if "/imds" in url or "/metadata" in url:
            return {
                "status": 200,
                "body": '{"instance-id":"i-0123456789abcdef0"}',
                "headers": {},
            }
        return {"status": 404, "body": "", "headers": {}}

    monkeypatch.setattr(scip, "_http_get", _mock_get)
    result = scan_cloud_imds_passthrough("https://x.com/")
    # Multiple paths in _IMDS_PROBE_PATHS contain '/imds' or '/metadata'
    assert result["total_findings"] >= 2


def test_scan_never_raises_on_http_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        scip, "_http_get",
        lambda _u, **_k: {"error": "boom", "status": 0, "body": "", "headers": {}},
    )
    result = scan_cloud_imds_passthrough("https://x.com/")
    assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_scan_cloud_imds_passthrough_registered() -> None:
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name, get_tool_names

    assert "scan_cloud_imds_passthrough" in get_tool_names()
    assert callable(get_tool_by_name("scan_cloud_imds_passthrough"))


def test_imds_passthrough_wired_into_api_anchors() -> None:
    """iter-21.6.2: only the IMDS-passthrough probe stays in the
    API anchor list. The bucket-discovery companion was reverted
    in PR #401 and returns via iter-21.6.1 as a bbot wrapper, not
    in this module."""
    from strix.agents.lead_agent.anchor_prepass import _ANCHORS_API

    tool_names = [name for name, _ in _ANCHORS_API]
    assert "scan_cloud_imds_passthrough" in tool_names
    # Pin that the reverted bucket tool stays OUT until iter-21.6.1
    # restores it as a bbot wrapper.
    assert "scan_public_bucket_exposure" not in tool_names
