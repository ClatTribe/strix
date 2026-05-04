"""Tests for HAR / Burp project ingestion (roadmap §7.0 / §18 row 3)."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


import strix.tools.traffic_ingest.traffic_ingest  # noqa: F401

ti_module = sys.modules["strix.tools.traffic_ingest.traffic_ingest"]
ingest_har_file = ti_module.ingest_har_file
ingest_burp_file = ti_module.ingest_burp_file


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
    tracer = Tracer("ingest-test")
    set_global_tracer(tracer)
    yield


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _make_har(tmp_path: Path, entries: list[dict[str, Any]]) -> Path:
    har = {"log": {"version": "1.2", "entries": entries}}
    p = tmp_path / "fixture.har"
    p.write_text(json.dumps(har), encoding="utf-8")
    return p


def _har_entry(
    *,
    url: str,
    method: str = "GET",
    headers: list[dict[str, str]] | None = None,
    query: list[dict[str, str]] | None = None,
    status: int = 200,
    content_type: str = "application/json",
    size: int = 100,
    body: bool = False,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "request": {
            "method": method,
            "url": url,
            "headers": headers or [],
            "queryString": query or [],
        },
        "response": {
            "status": status,
            "content": {"size": size, "mimeType": content_type},
        },
    }
    if body:
        entry["request"]["postData"] = {"text": "{}", "mimeType": "application/json"}
    return entry


def _make_burp(tmp_path: Path, items_xml: str) -> Path:
    p = tmp_path / "fixture.burp.xml"
    p.write_text(f"<?xml version='1.0'?>\n<items>{items_xml}</items>", encoding="utf-8")
    return p


def _burp_item(
    *,
    url: str,
    method: str = "GET",
    request_headers: dict[str, str] | None = None,
    status: int = 200,
    mimetype: str = "JSON",
    response_length: int = 100,
) -> str:
    """Build a Burp <item> with base64-encoded raw request."""
    headers = request_headers or {}
    p = "/" if "://" in url and "/" not in url.split("://", 1)[1] else "/" + url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else "/"
    raw = f"{method} {p} HTTP/1.1\r\nHost: {url.split('://')[1].split('/')[0]}\r\n"
    for k, v in headers.items():
        raw += f"{k}: {v}\r\n"
    raw += "\r\n"
    raw_b64 = base64.b64encode(raw.encode()).decode()

    return (
        "<item>"
        f"<url>{url}</url>"
        f"<method>{method}</method>"
        f"<request base64='true'>{raw_b64}</request>"
        f"<status>{status}</status>"
        f"<responselength>{response_length}</responselength>"
        f"<mimetype>{mimetype}</mimetype>"
        "</item>"
    )


# ---------------------------------------------------------------------------
# HAR — happy path
# ---------------------------------------------------------------------------


def test_har_basic_parse(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(url="https://api.example.com/login", method="POST"),
        _har_entry(url="https://api.example.com/users", method="GET"),
    ])
    out = ingest_har_file(str(p))
    assert out["success"] is True
    assert out["source"] == "har"
    assert out["requests_count"] == 2
    assert out["endpoints_count"] == 2
    assert "api.example.com" in out["hosts"]
    methods = {e["method"] for e in out["endpoints"]}
    assert methods == {"POST", "GET"}


def test_har_dedup_per_method_url(tmp_path) -> None:
    """Same (method, url) collapses to one endpoint."""
    p = _make_har(tmp_path, [
        _har_entry(url="https://api.example.com/login", method="POST"),
        _har_entry(url="https://api.example.com/login", method="POST"),
        _har_entry(url="https://api.example.com/login", method="POST"),
    ])
    out = ingest_har_file(str(p))
    assert out["requests_count"] == 3
    assert out["endpoints_count"] == 1
    assert out["endpoints"][0]["occurrences"] == 3


def test_har_param_union_across_calls(tmp_path) -> None:
    """Multiple calls with different params union the param names."""
    p = _make_har(tmp_path, [
        _har_entry(
            url="https://api.example.com/search",
            query=[{"name": "q", "value": "alpha"}],
        ),
        _har_entry(
            url="https://api.example.com/search",
            query=[{"name": "limit", "value": "10"}],
        ),
    ])
    out = ingest_har_file(str(p))
    endpoint = out["endpoints"][0]
    assert set(endpoint["params"]) == {"q", "limit"}


def test_har_query_extracted_from_url_when_querystring_absent(tmp_path) -> None:
    """HAR entries that omit `queryString` should still get param
    names parsed from the raw URL."""
    p = _make_har(tmp_path, [
        _har_entry(url="https://api.example.com/search?foo=1&bar=2"),
    ])
    out = ingest_har_file(str(p))
    endpoint = out["endpoints"][0]
    assert "foo" in endpoint["params"]
    assert "bar" in endpoint["params"]


# ---------------------------------------------------------------------------
# HAR — header redaction
# ---------------------------------------------------------------------------


def test_har_authorization_header_value_redacted(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(
            url="https://api.example.com/me",
            headers=[
                {"name": "Authorization", "value": "Bearer eyJsensitive"},
                {"name": "Accept", "value": "application/json"},
            ],
        ),
    ])
    out = ingest_har_file(str(p))
    endpoint = out["endpoints"][0]
    # Header NAME is preserved (so the agent knows auth was present).
    assert "Authorization" in endpoint["request_headers"]
    # VALUE is redacted (so the artifact doesn't leak the credential).
    assert endpoint["request_headers"]["Authorization"] == "[REDACTED]"
    # Non-sensitive headers pass through.
    assert endpoint["request_headers"]["Accept"] == "application/json"


def test_har_cookie_header_value_redacted(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(
            url="https://api.example.com/me",
            headers=[{"name": "Cookie", "value": "session=secret"}],
        ),
    ])
    out = ingest_har_file(str(p))
    assert out["endpoints"][0]["request_headers"]["Cookie"] == "[REDACTED]"


def test_har_xapikey_header_value_redacted(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(
            url="https://api.example.com/me",
            headers=[{"name": "X-API-Key", "value": "secret-api-key-42"}],
        ),
    ])
    out = ingest_har_file(str(p))
    assert out["endpoints"][0]["request_headers"]["X-API-Key"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# HAR — auth detection
# ---------------------------------------------------------------------------


def test_har_bearer_auth_detected(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(
            url="https://api.example.com/me",
            headers=[{"name": "Authorization", "value": "Bearer xyz"}],
        ),
    ])
    out = ingest_har_file(str(p))
    assert out["endpoints"][0]["auth_observed"] == "bearer"


def test_har_basic_auth_detected(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(
            url="https://api.example.com/me",
            headers=[{"name": "Authorization", "value": "Basic dXNlcjpwYXNz"}],
        ),
    ])
    out = ingest_har_file(str(p))
    assert out["endpoints"][0]["auth_observed"] == "basic"


def test_har_cookie_auth_detected(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(
            url="https://api.example.com/me",
            headers=[{"name": "Cookie", "value": "session=abc"}],
        ),
    ])
    out = ingest_har_file(str(p))
    assert out["endpoints"][0]["auth_observed"] == "cookie"


def test_har_no_auth_returns_none(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(url="https://api.example.com/public"),
    ])
    out = ingest_har_file(str(p))
    assert out["endpoints"][0]["auth_observed"] is None


# ---------------------------------------------------------------------------
# HAR — error handling
# ---------------------------------------------------------------------------


def test_har_missing_file_rejected(tmp_path) -> None:
    out = ingest_har_file(str(tmp_path / "does-not-exist.har"))
    assert out["success"] is False
    assert "not found" in out["error"]


def test_har_malformed_json_rejected(tmp_path) -> None:
    p = tmp_path / "bad.har"
    p.write_text("not json", encoding="utf-8")
    out = ingest_har_file(str(p))
    assert out["success"] is False


def test_har_empty_entries_returns_empty_inventory(tmp_path) -> None:
    p = _make_har(tmp_path, [])
    out = ingest_har_file(str(p))
    assert out["success"] is True
    assert out["endpoints_count"] == 0
    assert out["hosts"] == []


def test_har_max_requests_cap(tmp_path) -> None:
    entries = [_har_entry(url=f"https://api.example.com/p{i}") for i in range(20)]
    p = _make_har(tmp_path, entries)
    out = ingest_har_file(str(p), max_requests=5)
    assert out["requests_count"] == 5
    assert "errors" in out
    assert "capped at 5" in out["errors"][0]


def test_har_invalid_entries_silently_skipped(tmp_path) -> None:
    """Garbage entries dropped; valid ones kept."""
    p = _make_har(tmp_path, [
        {"not": "a valid entry"},
        _har_entry(url="https://api.example.com/login"),
    ])
    out = ingest_har_file(str(p))
    assert out["endpoints_count"] == 1


# ---------------------------------------------------------------------------
# HAR — body presence detection
# ---------------------------------------------------------------------------


def test_har_request_body_present_flag(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(url="https://api.example.com/login", method="POST", body=True),
        _har_entry(url="https://api.example.com/users", method="GET"),
    ])
    out = ingest_har_file(str(p))
    by_url = {e["url"]: e for e in out["endpoints"]}
    assert by_url["https://api.example.com/login"]["request_body_present"] is True
    assert by_url["https://api.example.com/users"]["request_body_present"] is False


# ---------------------------------------------------------------------------
# Burp — happy path
# ---------------------------------------------------------------------------


def test_burp_basic_parse(tmp_path) -> None:
    items = (
        _burp_item(url="https://api.example.com/login", method="POST")
        + _burp_item(url="https://api.example.com/users", method="GET")
    )
    p = _make_burp(tmp_path, items)
    out = ingest_burp_file(str(p))
    assert out["success"] is True
    assert out["source"] == "burp"
    assert out["requests_count"] == 2
    assert out["endpoints_count"] == 2


def test_burp_authorization_header_redacted(tmp_path) -> None:
    items = _burp_item(
        url="https://api.example.com/me",
        request_headers={
            "Authorization": "Bearer secret-token",
            "Accept": "application/json",
        },
    )
    p = _make_burp(tmp_path, items)
    out = ingest_burp_file(str(p))
    headers = out["endpoints"][0]["request_headers"]
    assert headers["Authorization"] == "[REDACTED]"
    assert headers["Accept"] == "application/json"
    # Auth detection still works on header NAMES.
    assert out["endpoints"][0]["auth_observed"] == "bearer"


def test_burp_dedup(tmp_path) -> None:
    items = "".join([
        _burp_item(url="https://api.example.com/login", method="POST")
        for _ in range(3)
    ])
    p = _make_burp(tmp_path, items)
    out = ingest_burp_file(str(p))
    assert out["requests_count"] == 3
    assert out["endpoints_count"] == 1


def test_burp_max_requests_cap(tmp_path) -> None:
    items = "".join([
        _burp_item(url=f"https://api.example.com/p{i}") for i in range(20)
    ])
    p = _make_burp(tmp_path, items)
    out = ingest_burp_file(str(p), max_requests=5)
    assert out["requests_count"] == 5


def test_burp_missing_file_rejected(tmp_path) -> None:
    out = ingest_burp_file(str(tmp_path / "does-not-exist.xml"))
    assert out["success"] is False
    assert "not found" in out["error"]


def test_burp_status_and_content_type_extracted(tmp_path) -> None:
    items = _burp_item(
        url="https://api.example.com/api/users",
        status=403,
        mimetype="JSON",
        response_length=512,
    )
    p = _make_burp(tmp_path, items)
    out = ingest_burp_file(str(p))
    e = out["endpoints"][0]
    assert e["response_status"] == 403
    assert e["response_size_bytes"] == 512
    assert "json" in e["response_content_type"]


# ---------------------------------------------------------------------------
# Tool registration / provenance
# ---------------------------------------------------------------------------


def test_tools_registered() -> None:
    from strix.tools.registry import get_tool_by_name
    assert get_tool_by_name("ingest_har_file") is not None
    assert get_tool_by_name("ingest_burp_file") is not None


def test_provenance_is_operator_input() -> None:
    """Both tools should declare provenance=operator_input — a HAR
    or Burp file is an operator-supplied artifact, not target output."""
    from strix.tools.registry import get_tool_provenance

    assert get_tool_provenance("ingest_har_file") == "operator_input"
    assert get_tool_provenance("ingest_burp_file") == "operator_input"


# ---------------------------------------------------------------------------
# Event emission
# ---------------------------------------------------------------------------


def test_traffic_ingested_event_emitted(tmp_path) -> None:
    p = _make_har(tmp_path, [
        _har_entry(url="https://api.example.com/login", method="POST"),
    ])
    ingest_har_file(str(p))

    events_path = tmp_path / "strix_runs" / "ingest-test" / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines() if line]
    ingested = [e for e in events if e.get("event_type") == "traffic.ingested"]
    assert len(ingested) == 1
    assert ingested[0]["payload"]["source"] == "har"
    assert ingested[0]["payload"]["endpoints_count"] == 1
