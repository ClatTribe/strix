"""Tests for csv_injection_check (roadmap §7.2 nice-to-have).

Hermetic — `_http_request` is monkeypatched. Tests cover:

- URL validation
- Setup endpoint failure → probe skipped
- Export endpoint failure → probe skipped
- Payload preserved + CSV content-type → medium finding
- Payload preserved + non-CSV content-type → low finding
- Payload NOT preserved → no finding
- Per-severity dedup across multiple payload classes
- All 5 payload prefix classes dispatched
- Cluster-A `--exclude-path` skip
- §11 UX fields
- verification_status="verified" (zero-FP detector)
- Result schema
- MITRE T1190
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.csv_injection.csv_injection_check  # noqa: F401

ci_module = sys.modules["strix.tools.csv_injection.csv_injection_check"]
csv_injection_check = ci_module.csv_injection_check


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
    tracer = Tracer("ci-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    yield


def _patch_request(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(method, url, *, headers=None, body="", timeout=10.0):
        kw = {
            "method": method, "url": url,
            "headers": dict(headers or {}), "body": body,
        }
        log.append(kw)
        return responder(method, url, kw)

    monkeypatch.setattr(ci_module, "_http_request", fake)
    return log


def _resp(*, status: int = 200, body: str = "", headers: dict[str, str] | None = None,
          skipped: bool = False) -> dict[str, Any]:
    if skipped:
        return {"status": 0, "headers": {}, "body": "", "skipped": True}
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _findings():
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------


def test_invalid_setup_url_rejected() -> None:
    out = csv_injection_check(
        setup_url="ftp://x.com/", export_url="https://x.com/csv",
    )
    assert out["success"] is False


def test_invalid_export_url_rejected() -> None:
    out = csv_injection_check(
        setup_url="https://x.com/setup", export_url="",
    )
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Skip cases
# ---------------------------------------------------------------------------


def test_setup_failure_probe_skipped(monkeypatch) -> None:
    """Setup endpoint returns 500 → probe skipped, no findings."""
    def responder(method, url, kw):
        return _resp(status=500)

    _patch_request(monkeypatch, responder)
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
    )
    # All probes skipped.
    assert all("skipped" in p for p in out["probes"])
    assert out["findings_emitted"] == 0


def test_export_failure_probe_skipped(monkeypatch) -> None:
    """Setup OK; export 500 → skipped."""
    def responder(method, url, kw):
        if "export" in url:
            return _resp(status=500)
        return _resp(status=201)  # setup ok

    _patch_request(monkeypatch, responder)
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/items/export.csv",
    )
    assert out["findings_emitted"] == 0


def test_excluded_path_setup(monkeypatch) -> None:
    def responder(method, url, kw):
        if "items" in url and "export" not in url:
            return _resp(skipped=True)
        return _resp(status=200, body="ok")

    _patch_request(monkeypatch, responder)
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/items/export.csv",
    )
    assert out["findings_emitted"] == 0


# ---------------------------------------------------------------------------
# Zero-FP detection: payload byte-exact in export
# ---------------------------------------------------------------------------


def test_payload_preserved_csv_content_type_medium(monkeypatch) -> None:
    """Setup accepts; export returns the EXACT payload bytes in
    text/csv → medium finding."""
    captured_payload = {"value": None}

    def responder(method, url, kw):
        if "export" in url:
            # Echo whatever the most-recent payload was as a CSV row.
            payload = captured_payload["value"] or ""
            csv = f"id,name\n1,{payload}\n"
            return _resp(
                status=200, body=csv,
                headers={"content-type": "text/csv; charset=utf-8"},
            )
        # Setup endpoint — capture the body so the export echoes it.
        body = kw.get("body", "")
        # Find name=<...> in URL-encoded body.
        for piece in body.split("&"):
            if piece.startswith("name="):
                from urllib.parse import unquote
                captured_payload["value"] = unquote(piece[5:])
                break
        return _resp(status=201, body="created")

    _patch_request(monkeypatch, responder)
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/items/export.csv",
    )
    findings = _findings()
    medium = [f for f in findings if f["severity"] == "medium"]
    assert len(medium) == 1
    assert medium[0]["category"] == "csv_formula_injection"
    assert medium[0]["cwe"] == "CWE-1236"
    # Per-severity dedup: only ONE medium even though 5 payloads ran.
    assert out["findings_emitted"] == 1


def test_payload_preserved_non_csv_content_type_low(monkeypatch) -> None:
    """Same setup-and-echo flow, but Content-Type is text/plain
    instead of text/csv → low finding."""
    captured_payload = {"value": None}

    def responder(method, url, kw):
        if "export" in url:
            payload = captured_payload["value"] or ""
            return _resp(
                status=200, body=f"name: {payload}",
                headers={"content-type": "text/plain"},
            )
        body = kw.get("body", "")
        for piece in body.split("&"):
            if piece.startswith("name="):
                from urllib.parse import unquote
                captured_payload["value"] = unquote(piece[5:])
                break
        return _resp(status=201, body="ok")

    _patch_request(monkeypatch, responder)
    csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/items/export.txt",
    )
    findings = _findings()
    low = [f for f in findings if f["severity"] == "low"]
    assert len(low) == 1


def test_payload_not_preserved_no_finding(monkeypatch) -> None:
    """Server sanitises the input → no payload bytes in export →
    NO finding (zero-FP)."""
    def responder(method, url, kw):
        if "export" in url:
            return _resp(
                status=200, body="id,name\n1,John\n",
                headers={"content-type": "text/csv"},
            )
        return _resp(status=201)

    _patch_request(monkeypatch, responder)
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
    )
    assert out["findings_emitted"] == 0
    findings = _findings()
    assert findings == []


def test_per_severity_dedup_one_finding_per_severity(monkeypatch) -> None:
    """5 payload classes all preserved + same Content-Type → ONE
    medium finding (per-severity dedup)."""
    captured = {"value": None}

    def responder(method, url, kw):
        if "export" in url:
            payload = captured["value"] or ""
            return _resp(
                status=200, body=f"id,name\n1,{payload}\n",
                headers={"content-type": "text/csv"},
            )
        body = kw.get("body", "")
        for piece in body.split("&"):
            if piece.startswith("name="):
                from urllib.parse import unquote
                captured["value"] = unquote(piece[5:])
                break
        return _resp(status=201)

    _patch_request(monkeypatch, responder)
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
    )
    # Per-severity dedup → at most 1 medium finding.
    assert out["findings_emitted"] == 1


# ---------------------------------------------------------------------------
# Probe matrix
# ---------------------------------------------------------------------------


def test_all_five_payload_classes_dispatched(monkeypatch) -> None:
    """The probe iterates all 5 payload prefixes (=cmd, @SUM, +arith,
    -arith, =HYPERLINK)."""
    payloads_seen: list[str] = []

    def responder(method, url, kw):
        if "export" in url:
            return _resp(status=200, body="empty", headers={"content-type": "text/csv"})
        # Capture the payload from the body.
        body = kw.get("body", "")
        for piece in body.split("&"):
            if piece.startswith("name="):
                from urllib.parse import unquote
                payloads_seen.append(unquote(piece[5:]))
                break
        return _resp(status=201)

    _patch_request(monkeypatch, responder)
    csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
    )
    # 5 distinct probe payloads dispatched.
    assert len(payloads_seen) == 5
    # Each payload starts with one of the prefix characters.
    prefixes_seen = {p[0] for p in payloads_seen}
    assert prefixes_seen == {"=", "@", "+", "-"}


def test_payloads_carry_strix_nonce(monkeypatch) -> None:
    """Each payload contains a strix-<nonce> marker for log
    auditability + cleanability."""
    payloads_seen: list[str] = []

    def responder(method, url, kw):
        if "export" in url:
            return _resp(status=200, body="empty", headers={"content-type": "text/csv"})
        body = kw.get("body", "")
        for piece in body.split("&"):
            if piece.startswith("name="):
                from urllib.parse import unquote
                payloads_seen.append(unquote(piece[5:]))
                break
        return _resp(status=201)

    _patch_request(monkeypatch, responder)
    csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
    )
    for p in payloads_seen:
        assert "strix-" in p


# ---------------------------------------------------------------------------
# JSON setup body
# ---------------------------------------------------------------------------


def test_json_setup_body_supported(monkeypatch) -> None:
    captured = {"value": None}

    def responder(method, url, kw):
        if "export" in url:
            payload = captured["value"] or ""
            return _resp(
                status=200, body=f"name,{payload}",
                headers={"content-type": "text/csv"},
            )
        # JSON body — parse it.
        import json as _json
        try:
            data = _json.loads(kw.get("body") or "{}")
            captured["value"] = data.get("name")
        except Exception:
            pass
        return _resp(status=201)

    _patch_request(monkeypatch, responder)
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
        setup_content_type="application/json",
    )
    findings = _findings()
    assert len(findings) >= 1


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_findings_carry_ux_fields(monkeypatch) -> None:
    captured = {"value": None}

    def responder(method, url, kw):
        if "export" in url:
            payload = captured["value"] or ""
            return _resp(
                status=200, body=f"id,name\n1,{payload}\n",
                headers={"content-type": "text/csv"},
            )
        body = kw.get("body", "")
        for piece in body.split("&"):
            if piece.startswith("name="):
                from urllib.parse import unquote
                captured["value"] = unquote(piece[5:])
                break
        return _resp(status=201)

    _patch_request(monkeypatch, responder)
    csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
    )
    findings = _findings()
    assert findings
    f = findings[0]
    assert f.get("description_plain")
    assert f.get("recommended_action")
    # Zero-FP: byte-exact match → verified.
    assert f.get("verification_status") == "verified"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_result_schema(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, k: _resp(status=201, body="ok"))
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
    )
    assert set(out.keys()) >= {
        "success", "setup_url", "export_url", "target_field",
        "export_content_type", "probes", "findings_emitted",
    }


def test_probe_record_shape(monkeypatch) -> None:
    captured = {"value": None}

    def responder(method, url, kw):
        if "export" in url:
            payload = captured["value"] or ""
            return _resp(
                status=200, body=f"id,n\n1,{payload}\n",
                headers={"content-type": "text/csv"},
            )
        body = kw.get("body", "")
        for piece in body.split("&"):
            if piece.startswith("name="):
                from urllib.parse import unquote
                captured["value"] = unquote(piece[5:])
                break
        return _resp(status=201)

    _patch_request(monkeypatch, responder)
    out = csv_injection_check(
        setup_url="https://app.example.com/items",
        export_url="https://app.example.com/export.csv",
    )
    assert out["probes"]
    p = out["probes"][0]
    assert set(p.keys()) >= {
        "label", "prefix", "payload", "nonce",
        "setup_status", "export_status", "payload_in_export",
        "severity",
    }


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("csv_injection_check")
    assert "T1190" in techniques
