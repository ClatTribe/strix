"""Tests for iter-21.6 `scan_public_bucket_exposure`.

Exercises the deterministic pieces (candidate-name generation,
provider classifiers) directly. The top-level HTTP-driving entry
point is covered with HTTP mocks via monkeypatch on `_http_get`.
"""

from __future__ import annotations

from typing import Any

import pytest

# Route through `sys.modules` — same shadowing issue as the
# imds-passthrough test (package re-exports `scan_public_bucket_
# exposure` as a function with the same name as the submodule).
import sys
import strix.tools.cloud_exposure_audit.scan_public_bucket_exposure  # noqa: F401,E501
spbe = sys.modules[
    "strix.tools.cloud_exposure_audit.scan_public_bucket_exposure"
]
scan_public_bucket_exposure = spbe.scan_public_bucket_exposure


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


# ---------------------------------------------------------------------------
# _normalize_target
# ---------------------------------------------------------------------------


def test_normalize_strips_path() -> None:
    assert spbe._normalize_target("https://app.example.com/api/v1") == "https://app.example.com/"


def test_normalize_adds_scheme() -> None:
    assert spbe._normalize_target("app.example.com") == "https://app.example.com/"


def test_normalize_rejects_empty() -> None:
    assert spbe._normalize_target("") is None
    assert spbe._normalize_target("   ") is None


def test_normalize_rejects_bad_scheme() -> None:
    assert spbe._normalize_target("ftp://x.com") is None


# ---------------------------------------------------------------------------
# _candidate_names
# ---------------------------------------------------------------------------


def test_candidate_names_simple_apex() -> None:
    candidates = spbe._candidate_names("example.com")
    # apex 'example' should be in candidates
    assert "example" in candidates
    # 'com' is technically valid as a label, but probably won't
    # match in practice — we don't filter it out
    assert all(spbe._S3_VALID_NAME_RE.match(c) for c in candidates)


def test_candidate_names_three_label_host() -> None:
    candidates = spbe._candidate_names("api.example.com")
    assert "example" in candidates
    assert "api-example" in candidates


def test_candidate_names_suffix_patterns() -> None:
    candidates = spbe._candidate_names("acme.com")
    # The apex + standard suffix patterns should be present
    assert "acme-backup" in candidates
    assert "acme-prod" in candidates


def test_candidate_names_no_ip() -> None:
    """Bare IPs produce no candidates (would generate noise)."""
    assert spbe._candidate_names("192.168.1.1") == []


def test_candidate_names_empty_host_no_candidates() -> None:
    assert spbe._candidate_names("") == []


def test_candidate_names_strips_port() -> None:
    candidates = spbe._candidate_names("example.com:8080")
    # Port should be stripped before label extraction
    assert "example" in candidates
    # No candidate should contain the port number directly
    assert all("8080" not in c for c in candidates)


def test_candidate_names_capped() -> None:
    """The candidate cap (24) protects against catastrophic blow-up
    on adversarial inputs."""
    candidates = spbe._candidate_names("a.b.c.d.e.f.g.h.example.com")
    assert len(candidates) <= spbe._MAX_CANDIDATES


def test_candidate_names_all_lowercase() -> None:
    candidates = spbe._candidate_names("Example.COM")
    assert all(c == c.lower() for c in candidates)


# ---------------------------------------------------------------------------
# Provider classifiers
# ---------------------------------------------------------------------------


def test_classify_s3_listable_emits_critical() -> None:
    resp = {
        "status": 200,
        "body": "<ListBucketResult>...</ListBucketResult>",
    }
    f = spbe._classify_s3("https://acme.s3.amazonaws.com/", resp)
    assert f is not None
    assert f["rule_id"] == "s3-bucket-publicly-listable"
    assert f["severity"] == "critical"


def test_classify_s3_private_emits_info() -> None:
    resp = {
        "status": 403,
        "body": "<Error><Code>AccessDenied</Code></Error>",
    }
    f = spbe._classify_s3("https://acme.s3.amazonaws.com/", resp)
    assert f is not None
    assert f["rule_id"] == "s3-bucket-exists-private"
    assert f["severity"] == "info"


def test_classify_s3_does_not_exist_no_finding() -> None:
    resp = {"status": 404, "body": "<Error><Code>NoSuchBucket</Code></Error>"}
    assert spbe._classify_s3("https://x.s3.amazonaws.com/", resp) is None


def test_classify_s3_unrelated_response_no_finding() -> None:
    resp = {"status": 200, "body": "<html><body>unrelated</body></html>"}
    assert spbe._classify_s3("https://x.s3.amazonaws.com/", resp) is None


def test_classify_gcs_listable_emits_critical() -> None:
    body = '{"kind": "storage#objects", "items": []}'
    resp = {"status": 200, "body": body}
    f = spbe._classify_gcs(
        "https://storage.googleapis.com/storage/v1/b/acme/o", resp,
    )
    assert f is not None
    assert f["rule_id"] == "gcs-bucket-publicly-listable"
    assert f["severity"] == "critical"


def test_classify_gcs_private_emits_info() -> None:
    resp = {"status": 403, "body": "{}"}
    f = spbe._classify_gcs("https://x", resp)
    assert f is not None
    assert f["rule_id"] == "gcs-bucket-exists-private"


def test_classify_azure_listable_emits_critical() -> None:
    body = '<?xml version="1.0"?><EnumerationResults>...</EnumerationResults>'
    resp = {"status": 200, "body": body}
    f = spbe._classify_azure(
        "https://acme.blob.core.windows.net/files?restype=container&comp=list",
        resp,
    )
    assert f is not None
    assert f["rule_id"] == "azure-blob-publicly-listable"
    assert f["severity"] == "critical"


def test_classify_azure_other_response_no_finding() -> None:
    resp = {"status": 404, "body": "<Error>...</Error>"}
    assert spbe._classify_azure("https://x", resp) is None


# ---------------------------------------------------------------------------
# scan_public_bucket_exposure — end-to-end with mocked HTTP
# ---------------------------------------------------------------------------


def test_scan_returns_partial_on_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # _candidate_names returns [] for IPs → status=partial
    result = scan_public_bucket_exposure("192.168.1.1")
    assert result["status"] == "partial"
    assert result["total_findings"] == 0


def test_scan_returns_error_on_bad_url() -> None:
    result = scan_public_bucket_exposure("ftp://x.com")
    assert result["status"] == "error"
    assert result["success"] is False


def test_scan_emits_finding_on_s3_listable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the mocked HTTP layer returns a listable S3 response,
    the scan emits a critical finding."""
    def _mock_get(url: str, *, timeout: float = 5.0) -> dict[str, Any]:
        if ".s3.amazonaws.com" in url and "acme" in url:
            return {
                "status": 200,
                "body": "<ListBucketResult><Name>acme</Name></ListBucketResult>",
                "headers": {},
            }
        return {"status": 404, "body": "", "headers": {}}

    monkeypatch.setattr(spbe, "_http_get", _mock_get)
    result = scan_public_bucket_exposure("https://acme.com/")
    assert result["status"] == "ok"
    assert result["total_findings"] >= 1
    rids = _rule_ids(result["findings"])
    assert "s3-bucket-publicly-listable" in rids


def test_scan_no_buckets_zero_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When every probe returns 404, no findings emit but status
    is still ok (the audit ran end-to-end)."""
    monkeypatch.setattr(
        spbe, "_http_get",
        lambda _u, **_k: {"status": 404, "body": "", "headers": {}},
    )
    result = scan_public_bucket_exposure("https://acme.com/")
    assert result["status"] == "ok"
    assert result["total_findings"] == 0


def test_scan_mixed_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify both S3 and GCS findings can land in the same audit."""
    def _mock_get(url: str, *, timeout: float = 5.0) -> dict[str, Any]:
        if ".s3.amazonaws.com" in url:
            return {
                "status": 200,
                "body": "<ListBucketResult/>",
                "headers": {},
            }
        if "storage.googleapis.com" in url:
            return {
                "status": 200,
                "body": '{"kind": "storage#objects"}',
                "headers": {},
            }
        return {"status": 404, "body": "", "headers": {}}

    monkeypatch.setattr(spbe, "_http_get", _mock_get)
    result = scan_public_bucket_exposure("https://acme.com/")
    rids = _rule_ids(result["findings"])
    assert "s3-bucket-publicly-listable" in rids
    assert "gcs-bucket-publicly-listable" in rids


def test_scan_never_raises_on_http_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defensive: HTTP failures must not crash the audit."""
    monkeypatch.setattr(
        spbe, "_http_get",
        lambda _u, **_k: {"error": "boom", "status": 0, "body": "", "headers": {}},
    )
    result = scan_public_bucket_exposure("https://acme.com/")
    assert result["status"] == "ok"  # audit completed; just no findings
    assert result["total_findings"] == 0


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_scan_public_bucket_exposure_registered() -> None:
    import strix.tools  # noqa: F401  side-effect
    from strix.tools.registry import get_tool_by_name, get_tool_names

    assert "scan_public_bucket_exposure" in get_tool_names()
    assert callable(get_tool_by_name("scan_public_bucket_exposure"))
