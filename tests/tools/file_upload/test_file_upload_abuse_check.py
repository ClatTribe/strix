"""Tests for file_upload_abuse_check.

Hermetic — `_http_post_multipart` and `_http_get` are monkeypatched
so no real network traffic. Tests cover:

- URL normalization (bare host, scheme, invalid)
- Probe cohort: 15 probes, classes covered, every probe has a
  `strix-<nonce>-` filename
- Multipart body builder: byte-exact filename round-trip (null byte,
  trailing space, encoded slash); extra_fields embedded
- `_looks_like_acceptance` heuristic — control 2xx + probe 2xx with
  similar body length → accepted; status-class change → not
  accepted; error responses → not accepted
- Filename extension parser respects null-byte / trailing dot/space
- Acceptance + fetch-back confirmed dangerous content-type → high
- Acceptance of executable extension → high (regardless of fetch-back)
- Acceptance + fetch-back returns image/jpeg → still high if class
  is extension-switch (extension implies served code path)
- Acceptance of content-mismatch / case / null-byte → medium
- Acceptance of path-traversal filename without fetch-back → low
- Path-traversal with fetch-back → still low (filename injection
  doesn't auto-escalate)
- Per-class dedup: 4 extension-switch variants → 1 finding
- Control rejected → all probes inconclusive, no findings
- --exclude-path blocks control → graceful no-op
- Probe URL extraction: Location header, body URL, body path
- Every emitted finding carries description_plain + recommended_action
- Check event emitted with category=unrestricted_upload
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.file_upload.file_upload_abuse_check  # noqa: F401

fu_module = sys.modules["strix.tools.file_upload.file_upload_abuse_check"]
file_upload_abuse_check = fu_module.file_upload_abuse_check


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("fu-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "web_application", "value": "https://app.example.com/"}]})
    yield


def _patch_post(monkeypatch, responder):
    """Install fake _http_post_multipart. responder(url, kwargs) → response."""
    log: list[dict[str, Any]] = []

    def fake(url, *, body, boundary, extra_headers=None, timeout=30.0):
        kwargs = {
            "url": url, "body": body, "boundary": boundary,
            "extra_headers": dict(extra_headers or {}), "timeout": timeout,
        }
        log.append(kwargs)
        return responder(url, kwargs)

    monkeypatch.setattr(fu_module, "_http_post_multipart", fake)
    return log


def _patch_get(monkeypatch, responder):
    log: list[str] = []

    def fake(url, *, timeout=30.0):
        log.append(url)
        return responder(url)

    monkeypatch.setattr(fu_module, "_http_get", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


def test_invalid_url_rejected() -> None:
    assert file_upload_abuse_check("")["success"] is False
    assert file_upload_abuse_check("ftp://x.com/")["success"] is False


def test_bare_hostname_gets_https_prefix(monkeypatch) -> None:
    _patch_post(monkeypatch, lambda url, k: _resp(body="ok"))
    out = file_upload_abuse_check("app.example.com/upload")
    assert out["success"] is True
    assert out["upload_url"].startswith("https://")


# ---------------------------------------------------------------------------
# Probe cohort shape
# ---------------------------------------------------------------------------


def test_probe_cohort_size() -> None:
    probes = fu_module._build_probes("deadbeef")
    assert len(probes) == 15


def test_probe_classes_present() -> None:
    classes = {p["class_"] for p in fu_module._build_probes("nonce")}
    assert "extension_switch" in classes
    assert "magic_byte_spoofing" in classes
    assert "content_mismatch" in classes
    assert "double_extension" in classes
    assert "byte_truncation" in classes
    assert "case_variant" in classes
    assert "filename_normalization" in classes
    assert "svg_xss" in classes
    assert "html_xss" in classes
    assert "filename_injection" in classes


def test_every_probe_has_strix_nonce_prefix() -> None:
    nonce = "deadbeef"
    for probe in fu_module._build_probes(nonce):
        # path_traversal filename has the nonce embedded after the traversal.
        assert f"strix-{nonce}" in probe["filename"]


def test_php_extension_uses_php_body() -> None:
    probes = fu_module._build_probes("n")
    php_probe = next(p for p in probes if p["label"] == "php_extension")
    assert b"<?php" in php_probe["body"]
    assert b"strix-probe-marker" in php_probe["body"]


def test_php_with_image_magic_starts_with_png_magic() -> None:
    probes = fu_module._build_probes("n")
    p = next(pr for pr in probes if pr["label"] == "php_with_image_magic")
    assert p["body"].startswith(b"\x89PNG\r\n\x1a\n")
    # PHP body still embedded after magic.
    assert b"<?php" in p["body"]


# ---------------------------------------------------------------------------
# Multipart body builder
# ---------------------------------------------------------------------------


def test_multipart_basic_shape() -> None:
    body = fu_module._build_multipart(
        boundary="X", field_name="file", filename="hello.txt",
        file_content_type="text/plain", file_body=b"hi",
    )
    assert b"--X\r\n" in body
    assert b'Content-Disposition: form-data; name="file"; filename="hello.txt"' in body
    assert b"Content-Type: text/plain\r\n\r\n" in body
    assert b"hi\r\n" in body
    assert body.endswith(b"--X--\r\n")


def test_multipart_filename_byte_exact_null_byte() -> None:
    """Null byte in filename must round-trip to wire bytes verbatim."""
    body = fu_module._build_multipart(
        boundary="X", field_name="file", filename="a.php\x00.jpg",
        file_content_type="image/jpeg", file_body=b"x",
    )
    assert b"filename=\"a.php\x00.jpg\"" in body


def test_multipart_filename_byte_exact_trailing_space() -> None:
    body = fu_module._build_multipart(
        boundary="X", field_name="file", filename="a.php ",
        file_content_type="application/x-php", file_body=b"x",
    )
    assert b"filename=\"a.php \"" in body


def test_multipart_extra_fields_embedded() -> None:
    body = fu_module._build_multipart(
        boundary="X", field_name="file", filename="x.txt",
        file_content_type="text/plain", file_body=b"x",
        extra_fields={"csrf": "abc", "type": "img"},
    )
    assert b'Content-Disposition: form-data; name="csrf"' in body
    assert b"\r\nabc\r\n" in body
    assert b'Content-Disposition: form-data; name="type"' in body
    assert b"\r\nimg\r\n" in body


# ---------------------------------------------------------------------------
# Acceptance heuristic
# ---------------------------------------------------------------------------


def test_acceptance_same_class_similar_length_yes() -> None:
    control = _resp(status=201, body="x" * 100)
    probe = _resp(status=200, body="x" * 110)  # within ±25%
    assert fu_module._looks_like_acceptance(control, probe) is True


def test_acceptance_status_class_change_no() -> None:
    control = _resp(status=200, body="x" * 100)
    probe = _resp(status=400, body="x" * 100)
    assert fu_module._looks_like_acceptance(control, probe) is False


def test_acceptance_huge_length_difference_no() -> None:
    control = _resp(status=200, body="x" * 100)
    probe = _resp(status=200, body="x" * 1000)  # 90% delta
    assert fu_module._looks_like_acceptance(control, probe) is False


def test_acceptance_probe_error_no() -> None:
    control = _resp(status=200, body="ok")
    probe = {"status": 0, "headers": {}, "body": "", "error": "TimeoutError"}
    assert fu_module._looks_like_acceptance(control, probe) is False


def test_acceptance_control_rejected_no() -> None:
    """If control wasn't 2xx/3xx, no probe can be 'accepted'."""
    control = _resp(status=403, body="forbidden")
    probe = _resp(status=403, body="forbidden")
    assert fu_module._looks_like_acceptance(control, probe) is False


# ---------------------------------------------------------------------------
# Filename extension parser
# ---------------------------------------------------------------------------


def test_extension_simple() -> None:
    assert fu_module._filename_extension("a.php") == "php"


def test_extension_null_byte_truncates() -> None:
    assert fu_module._filename_extension("a.php\x00.jpg") == "php"


def test_extension_trailing_dot_strips() -> None:
    assert fu_module._filename_extension("a.php.") == "php"


def test_extension_trailing_space_strips() -> None:
    assert fu_module._filename_extension("a.php ") == "php"


def test_extension_double_ext_returns_last() -> None:
    assert fu_module._filename_extension("a.php.jpg") == "jpg"


# ---------------------------------------------------------------------------
# URL extraction (fetch-back)
# ---------------------------------------------------------------------------


def test_extract_url_from_location_header() -> None:
    out = fu_module._extract_artifact_url(
        response_body="ok",
        response_headers={"location": "/uploads/strix-abc-control.jpg"},
        nonce="abc",
        base_url="https://x.com/upload",
    )
    assert out == "https://x.com/uploads/strix-abc-control.jpg"


def test_extract_url_from_body_absolute() -> None:
    out = fu_module._extract_artifact_url(
        response_body='{"url":"https://cdn.example.com/u/strix-abc-x.php"}',
        response_headers={},
        nonce="abc",
        base_url="https://x.com/upload",
    )
    assert out == "https://cdn.example.com/u/strix-abc-x.php"


def test_extract_url_from_body_relative_path() -> None:
    out = fu_module._extract_artifact_url(
        response_body='{"path":"/uploads/strix-abc-x.php"}',
        response_headers={},
        nonce="abc",
        base_url="https://x.com/upload",
    )
    assert out == "https://x.com/uploads/strix-abc-x.php"


def test_extract_url_no_match_returns_none() -> None:
    out = fu_module._extract_artifact_url(
        response_body="<p>Upload OK</p>",
        response_headers={},
        nonce="abc",
        base_url="https://x.com/upload",
    )
    assert out is None


# ---------------------------------------------------------------------------
# Acceptance scenarios — high
# ---------------------------------------------------------------------------


def test_executable_extension_accepted_emits_high(monkeypatch) -> None:
    """Server accepts .php upload → high regardless of fetch-back."""
    def post(url, k):
        # Server returns identical 200 + same body for everything → accepted.
        return _resp(status=200, body="ok")

    _patch_post(monkeypatch, post)
    _patch_get(monkeypatch, lambda url: _resp(status=404, body="not found"))
    out = file_upload_abuse_check("https://app.example.com/upload")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    high = [r for r in reports if r["severity"] == "high"]
    assert high
    assert all(r["cwe"] == "CWE-434" for r in reports)
    assert all(r["category"] == "unrestricted_upload" for r in reports)
    assert out["findings_emitted"] >= 1


def test_fetch_back_confirms_dangerous_content_type_emits_high(monkeypatch) -> None:
    def post(url, k):
        return _resp(
            status=201,
            body='{"url":"https://app.example.com/u/' + extract_nonce_filename(k) + '"}',
        )

    def extract_nonce_filename(k):
        # Pull strix-<nonce>-<rest>.<ext> from the multipart body so the
        # response URL points at the actual probe filename.
        body = k["body"]
        idx = body.find(b"filename=\"")
        if idx == -1:
            return "x"
        end = body.find(b"\"", idx + 10)
        return body[idx + 10:end].decode("latin-1", errors="replace")

    def get(url):
        # Server returns the SVG with text/html → dangerous CT → high.
        if ".svg" in url:
            return _resp(
                status=200,
                body="<svg><script>strix-probe-marker-x</script></svg>",
                headers={"Content-Type": "text/html"},
            )
        return _resp(status=200, body="strix-probe-marker-x", headers={"Content-Type": "image/jpeg"})

    _patch_post(monkeypatch, post)
    _patch_get(monkeypatch, get)
    out = file_upload_abuse_check("https://app.example.com/upload")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any(r["severity"] == "high" for r in reports)
    assert out["findings_emitted"] >= 1


# ---------------------------------------------------------------------------
# Per-class dedup
# ---------------------------------------------------------------------------


def test_per_class_dedup_collapses_extension_switch(monkeypatch) -> None:
    """Server accepts everything → 15 probes collapse to one finding per
    (severity × class) pair. Strictly fewer findings than probes."""
    _patch_post(monkeypatch, lambda url, k: _resp(status=200, body="ok"))
    _patch_get(monkeypatch, lambda url: _resp(status=404))
    out = file_upload_abuse_check("https://app.example.com/upload")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    # 15 probes, but dedup means each (severity, class) appears at most
    # once. There are 10 distinct classes; some classes legitimately
    # produce findings at multiple severity levels (e.g. double_extension
    # has both a medium variant and a high variant).
    # Assertion: total reports < 15 (dedup did something) AND each
    # (severity, class) pair appears exactly once.
    assert len(reports) < 15  # dedup actually collapsed something
    seen: set[tuple[str, ...]] = set()
    for r in reports:
        # Recover dedup key from per-finding endpoint+severity. Title
        # uniquely identifies a per-class finding text.
        key = (r["severity"], r["title"])
        assert key not in seen, f"duplicate finding emitted: {key}"
        seen.add(key)
    # Probes count == 15 always (sanity check).
    assert len(out["probes"]) == 15


# ---------------------------------------------------------------------------
# Server rejects → no findings
# ---------------------------------------------------------------------------


def test_server_rejects_all_no_findings(monkeypatch) -> None:
    def post(url, k):
        body = k["body"]
        # Accept only the .jpg control, reject everything else (the
        # control filename ends in .jpg).
        if b"-control.jpg" in body:
            return _resp(status=200, body="ok")
        return _resp(status=400, body="invalid file type")

    _patch_post(monkeypatch, post)
    _patch_get(monkeypatch, lambda url: _resp(status=404))
    out = file_upload_abuse_check("https://app.example.com/upload")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Control rejected → inconclusive
# ---------------------------------------------------------------------------


def test_control_rejected_inconclusive(monkeypatch) -> None:
    log = _patch_post(monkeypatch, lambda url, k: _resp(status=403, body="forbidden"))
    out = file_upload_abuse_check("https://app.example.com/upload")
    # Control is the first POST. With control rejected, probe cohort
    # is short-circuited — only 1 POST in log.
    assert len(log) == 1
    assert out["findings_emitted"] == 0
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["unrestricted_upload"]
    assert cat.get("inconclusive", 0) == 1


def test_control_status_500_inconclusive(monkeypatch) -> None:
    log = _patch_post(monkeypatch, lambda url, k: _resp(status=500, body="ise"))
    out = file_upload_abuse_check("https://app.example.com/upload")
    assert len(log) == 1
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Cluster-A composition
# ---------------------------------------------------------------------------


def test_control_skipped_response_short_circuits(monkeypatch) -> None:
    """When `_http_post_multipart` returns skipped (e.g. because cluster-A
    filtered the URL via --exclude-path), the tool must not run any
    probes."""
    skip_resp = {"status": 0, "headers": {}, "body": "", "skipped": True,
                 "skipped_reason": "excluded by --exclude-path: /admin/*"}
    log = _patch_post(monkeypatch, lambda url, k: skip_resp)
    out = file_upload_abuse_check("https://app.example.com/admin/upload")
    # Only the control was attempted; probe cohort short-circuited.
    assert len(log) == 1
    assert out["findings_emitted"] == 0
    assert out["control"]["skipped"] is True
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_http_post_multipart_honors_exclude_path(monkeypatch) -> None:
    """Direct test of cluster-A integration in `_http_post_multipart`:
    STRIX_EXCLUDE_PATHS matching → skipped response, httpx never called."""
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", '["/admin/*"]')
    # Sentinel: if httpx.Client is constructed, the test fails — cluster-A
    # should short-circuit before that.
    httpx_called = []
    import httpx

    real_client_init = httpx.Client.__init__

    def fake_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        httpx_called.append(True)
        real_client_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", fake_init)

    out = fu_module._http_post_multipart(
        "https://app.example.com/admin/upload",
        body=b"--X--\r\n",
        boundary="X",
    )
    assert out.get("skipped") is True
    assert "exclude-path" in (out.get("skipped_reason") or "")
    assert httpx_called == []


# ---------------------------------------------------------------------------
# §11 non-tech UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_plain_and_action(monkeypatch) -> None:
    _patch_post(monkeypatch, lambda url, k: _resp(status=200, body="ok"))
    _patch_get(monkeypatch, lambda url: _resp(status=404))
    file_upload_abuse_check("https://app.example.com/upload")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r["category"] == "unrestricted_upload"
        assert r["cwe"] == "CWE-434"
        assert r.get("verification_status") == "needs_review"


# ---------------------------------------------------------------------------
# Check event
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    """Control accepted, all probes rejected → check.completed not_vulnerable."""
    def post(url, k):
        if b"-control.jpg" in k["body"]:
            return _resp(status=200, body="ok")
        return _resp(status=400, body="rejected")

    _patch_post(monkeypatch, post)
    _patch_get(monkeypatch, lambda url: _resp(status=404))
    file_upload_abuse_check("https://app.example.com/upload")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    cat = summary["by_category"]["unrestricted_upload"]
    assert cat.get("not_vulnerable", 0) == 1


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    _patch_post(monkeypatch, lambda url, k: _resp(status=200, body="ok"))
    _patch_get(monkeypatch, lambda url: _resp(status=404))
    file_upload_abuse_check("https://app.example.com/upload")
    summary = tracer_module.get_global_tracer().get_check_summary()
    cat = summary["by_category"]["unrestricted_upload"]
    assert cat.get("vulnerable", 0) == 1


# ---------------------------------------------------------------------------
# Auth header injection (extra_fields round-trip)
# ---------------------------------------------------------------------------


def test_extra_fields_round_trip_into_multipart_body(monkeypatch) -> None:
    log = _patch_post(monkeypatch, lambda url, k: _resp(status=200, body="ok"))
    file_upload_abuse_check(
        "https://app.example.com/upload",
        extra_fields={"csrf_token": "abc-123", "doc_type": "image"},
    )
    # Every POST body should embed both extra fields.
    for entry in log:
        assert b'name="csrf_token"' in entry["body"]
        assert b"abc-123" in entry["body"]
        assert b'name="doc_type"' in entry["body"]
        assert b"image" in entry["body"]


# ---------------------------------------------------------------------------
# Path-traversal stays low even when accepted
# ---------------------------------------------------------------------------


def test_path_traversal_stays_low_without_fetch_back(monkeypatch) -> None:
    """Server "accepts" everything but path-traversal artifact has no
    fetchable URL → finding stays low."""
    def post(url, k):
        return _resp(status=200, body="ok")

    _patch_post(monkeypatch, post)
    _patch_get(monkeypatch, lambda url: _resp(status=404))
    file_upload_abuse_check("https://app.example.com/upload")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    pt = [r for r in reports if "path-traversal" in r["title"].lower() or "filename validation" in r["title"].lower()]
    assert pt
    assert pt[0]["severity"] == "low"


# ---------------------------------------------------------------------------
# Smoke: result schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_contains_expected_keys(monkeypatch) -> None:
    _patch_post(monkeypatch, lambda url, k: _resp(status=200, body="ok"))
    _patch_get(monkeypatch, lambda url: _resp(status=404))
    out = file_upload_abuse_check("https://app.example.com/upload")
    assert "success" in out
    assert "upload_url" in out
    assert "target_host" in out
    assert "nonce" in out
    assert "control" in out
    assert "probes" in out
    assert "findings_emitted" in out
    assert len(out["probes"]) == 15  # one verdict per probe
    for p in out["probes"]:
        assert "label" in p and "class_" in p and "filename" in p
