"""Tests for `scan_prototype_pollution`.

Hermetic — `_send` is monkeypatched. Tests cover:

  * Each canonical probe shape (JSON body direct / nested /
    constructor, query direct / nested / constructor).
  * Nonce-reflection detection (the strongest signal).
  * Status-shift detection (secondary signal).
  * Verification ladder: verified vs pattern_match.
  * Confidence assignment per evidence shape.
  * Probe allow-list / max_probes bounds.
  * Negative cases — non-vulnerable target, nonce not reflected.
  * Tracer round-trip.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.specialist.scan_prototype_pollution  # noqa: F401

pp_module = sys.modules["strix.tools.specialist.scan_prototype_pollution"]
scan_prototype_pollution = pp_module.scan_prototype_pollution


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
    tracer = Tracer("pp-test")
    set_global_tracer(tracer)
    yield


def _resp(*, status=200, body="", headers=None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _patch_send(monkeypatch, responder):
    """`responder(method, url, body, headers) -> response-dict`."""
    log: list[dict[str, Any]] = []

    def fake(method, url, *, body=None, headers=None, timeout=12.0):
        entry = {"method": method, "url": url, "body": body,
                 "headers": dict(headers or {})}
        log.append(entry)
        return responder(method, url, body, headers or {})

    monkeypatch.setattr(pp_module, "_send", fake)
    return log


# ---------------------------------------------------------------------------
# Vulnerable-target responder factories
# ---------------------------------------------------------------------------


def _vulnerable_responder(nonce_extractor=None):
    """A responder that simulates a vulnerable Node app: after any
    `__proto__` / `constructor.prototype` injection, subsequent
    GET responses leak the planted nonce in the response body."""
    state = {"polluted_value": None}

    def respond(method, url, body, headers):
        # Detect a polluting JSON body or query string.
        if body and ("__proto__" in body or
                     "constructor" in body and "prototype" in body):
            # Extract the nonce from the JSON body's polluted key.
            import re
            m = re.search(r'"x_strix_pollution_marker"\s*:\s*"([^"]+)"',
                          body)
            if m:
                state["polluted_value"] = m.group(1)
            return _resp(status=200, body="OK")
        if "__proto__" in url or (
            "constructor" in url and "prototype" in url
        ):
            # Query injection.
            import re
            m = re.search(r"\[x_strix_pollution_marker\]=([\w\-]+)", url)
            if m:
                state["polluted_value"] = m.group(1)
            return _resp(status=200, body="OK")
        # Observation GET — reflect the polluted nonce in the body.
        body_text = "<html>response</html>"
        if state["polluted_value"]:
            body_text += f"<!-- {state['polluted_value']} -->"
        return _resp(status=200, body=body_text)
    return respond


def _clean_responder(method, url, body, headers):
    """Non-vulnerable target — never reflects the nonce."""
    return _resp(status=200, body="<html>response</html>")


# ---------------------------------------------------------------------------
# Probe-shape positive tests
# ---------------------------------------------------------------------------


def test_json_proto_direct_detected(monkeypatch) -> None:
    _patch_send(monkeypatch, _vulnerable_responder())
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=False,
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    assert out["findings"][0]["category"] == "prototype_pollution"
    assert out["findings"][0]["severity"] == "high"
    assert out["findings"][0]["verification_status"] == "verified"


def test_json_proto_nested_detected(monkeypatch) -> None:
    _patch_send(monkeypatch, _vulnerable_responder())
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_nested"],
        detect_status_shift=False,
    )
    assert len(out["findings"]) == 1


def test_json_constructor_proto_detected(monkeypatch) -> None:
    _patch_send(monkeypatch, _vulnerable_responder())
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_constructor_proto"],
        detect_status_shift=False,
    )
    assert len(out["findings"]) == 1


def test_query_proto_direct_detected(monkeypatch) -> None:
    _patch_send(monkeypatch, _vulnerable_responder())
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["query_proto_direct"],
        detect_status_shift=False,
    )
    assert len(out["findings"]) == 1


def test_query_proto_nested_detected(monkeypatch) -> None:
    _patch_send(monkeypatch, _vulnerable_responder())
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["query_proto_nested"],
        detect_status_shift=False,
    )
    assert len(out["findings"]) == 1


def test_query_constructor_proto_detected(monkeypatch) -> None:
    _patch_send(monkeypatch, _vulnerable_responder())
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["query_constructor_proto"],
        detect_status_shift=False,
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_clean_target_emits_zero_findings(monkeypatch) -> None:
    _patch_send(monkeypatch, _clean_responder)
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        detect_status_shift=False,
    )
    assert out["findings"] == []
    assert out["tool_metadata"]["findings_emitted_to_tracer"] == 0


def test_nonce_only_in_pollute_response_does_not_fire(monkeypatch) -> None:
    """If the nonce ECHOES in the polluting request's response (a
    server might just reflect input) but NOT in the subsequent
    independent observation, that's not pollution — it's plain
    echo. Must not fire."""

    def respond(method, url, body, headers):
        # Pollution request: echo body back.
        if body and "__proto__" in body:
            return _resp(status=200, body=body)
        if "__proto__" in url:
            return _resp(status=200, body=url)
        # Observation: clean response.
        return _resp(status=200, body="clean")

    _patch_send(monkeypatch, respond)
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=False,
    )
    assert out["findings"] == []


# ---------------------------------------------------------------------------
# Status-shift detection
# ---------------------------------------------------------------------------


def test_status_shift_alone_yields_pattern_match(monkeypatch) -> None:
    """Status-code differential without nonce reflection should
    fire as pattern_match (lower confidence)."""
    state = {"polluted": False}

    def respond(method, url, body, headers):
        if (body and "__proto__" in body) or "__proto__" in url:
            state["polluted"] = True
            return _resp(status=200, body="ok")
        # Observation: changed status after pollution.
        return _resp(status=204 if state["polluted"] else 200, body="x")

    _patch_send(monkeypatch, respond)
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=True,
    )
    assert len(out["findings"]) == 1
    assert out["findings"][0]["verification_status"] == "pattern_match"
    assert out["findings"][0]["confidence"] < 0.9


def test_pollution_500_response_does_not_trigger_status_shift(
    monkeypatch,
) -> None:
    """If the polluting request ITSELF returns 5xx, don't treat a
    subsequent observation-status-shift as pollution evidence —
    the server just errored, not necessarily pollution."""

    def respond(method, url, body, headers):
        if (body and "__proto__" in body) or "__proto__" in url:
            return _resp(status=500, body="error")
        return _resp(status=204, body="changed")

    _patch_send(monkeypatch, respond)
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=True,
    )
    assert out["findings"] == []


def test_status_shift_disabled_by_kwarg(monkeypatch) -> None:
    """Explicit opt-out skips the status-shift probe entirely."""
    state = {"polluted": False}

    def respond(method, url, body, headers):
        if (body and "__proto__" in body) or "__proto__" in url:
            state["polluted"] = True
            return _resp(status=200, body="ok")
        return _resp(status=204 if state["polluted"] else 200, body="x")

    _patch_send(monkeypatch, respond)
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=False,
    )
    # No nonce reflection AND status-shift disabled → no finding.
    assert out["findings"] == []


# ---------------------------------------------------------------------------
# Combined evidence — strongest case
# ---------------------------------------------------------------------------


def test_nonce_and_status_shift_both_fire(monkeypatch) -> None:
    """When BOTH signals fire together, confidence maxes at 0.95
    and the finding still emits as verified (nonce is the
    authoritative signal)."""
    state = {"polluted_value": None}

    def respond(method, url, body, headers):
        if body and "__proto__" in body:
            import re
            m = re.search(r'"x_strix_pollution_marker"\s*:\s*"([^"]+)"',
                          body)
            if m:
                state["polluted_value"] = m.group(1)
            return _resp(status=200, body="ok")
        if "__proto__" in url:
            import re
            m = re.search(r"\[x_strix_pollution_marker\]=([\w\-]+)", url)
            if m:
                state["polluted_value"] = m.group(1)
            return _resp(status=200, body="ok")
        # Observation: nonce reflected AND status changed.
        body_text = "<html>x</html>"
        if state["polluted_value"]:
            body_text += f"<!-- {state['polluted_value']} -->"
            return _resp(status=204, body=body_text)
        return _resp(status=200, body=body_text)

    _patch_send(monkeypatch, respond)
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=True,
    )
    assert len(out["findings"]) == 1
    finding = out["findings"][0]
    assert finding["verification_status"] == "verified"
    assert finding["confidence"] == 0.95


# ---------------------------------------------------------------------------
# Probe allow-list + max_probes
# ---------------------------------------------------------------------------


def test_probe_allowlist_restricts_set(monkeypatch) -> None:
    """`probes=[...]` runs only the named probes, no others."""
    log = _patch_send(monkeypatch, _vulnerable_responder())
    scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=False,
    )
    pollute_calls = [e for e in log if e["body"] is not None]
    # Only one pollute call dispatched (single probe in allowlist).
    assert len(pollute_calls) == 1


def test_max_probes_caps_run(monkeypatch) -> None:
    _patch_send(monkeypatch, _clean_responder)
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        max_probes=2,
        detect_status_shift=False,
    )
    assert out["tool_metadata"]["probes_run"] <= 2


def test_unknown_probe_label_yields_no_probes_error() -> None:
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["nonexistent_probe"],
    )
    assert out["status"] == "error"
    assert "no probes" in out["error"]


# ---------------------------------------------------------------------------
# Separate observation URL
# ---------------------------------------------------------------------------


def test_observation_url_separate_from_pollution_url(monkeypatch) -> None:
    """Pollution hits `/api`; observation hits `/profile`. The
    cross-endpoint propagation IS the headline SSPP property."""
    state = {"polluted_value": None}

    def respond(method, url, body, headers):
        if body and "__proto__" in body:
            import re
            m = re.search(r'"x_strix_pollution_marker"\s*:\s*"([^"]+)"',
                          body)
            if m:
                state["polluted_value"] = m.group(1)
            return _resp(status=200, body="ok")
        # Observation URL must match `/profile`.
        if url.endswith("/profile"):
            body_text = "profile"
            if state["polluted_value"]:
                body_text += f"<!-- {state['polluted_value']} -->"
            return _resp(status=200, body=body_text)
        return _resp(status=404)

    _patch_send(monkeypatch, respond)
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        observation_url="https://app.example.com/profile",
        probes=["json_proto_direct"],
        detect_status_shift=False,
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_empty_url_rejected() -> None:
    out = scan_prototype_pollution(url="")
    assert out["status"] == "error"


def test_invalid_url_rejected() -> None:
    out = scan_prototype_pollution(url="not-a-url")
    assert out["status"] == "error"


def test_invalid_observation_url_rejected() -> None:
    out = scan_prototype_pollution(
        url="https://app.example.com/api",
        observation_url="not-a-url",
    )
    assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Nonce uniqueness — collision safety
# ---------------------------------------------------------------------------


def test_nonce_unique_per_run(monkeypatch) -> None:
    """Each scan invocation uses a fresh nonce; no possibility of
    two runs colliding on observation."""
    seen_bodies: list[str] = []

    def respond(method, url, body, headers):
        if body:
            seen_bodies.append(body)
        return _resp(status=200, body="ok")

    _patch_send(monkeypatch, respond)
    scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=False,
    )
    scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=False,
    )
    # Two pollution bodies; nonces inside differ.
    assert len(seen_bodies) == 2
    assert seen_bodies[0] != seen_bodies[1]


# ---------------------------------------------------------------------------
# Tracer round-trip
# ---------------------------------------------------------------------------


def test_tracer_emit_carries_prototype_pollution_category(monkeypatch) -> None:
    _patch_send(monkeypatch, _vulnerable_responder())
    tracer = tracer_module.get_global_tracer()
    scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        detect_status_shift=False,
    )
    reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "prototype_pollution"
    ]
    assert len(reports) >= 1
    r = reports[0]
    assert r.get("cwe") == "CWE-1321"
    assert r.get("severity") == "high"


# ---------------------------------------------------------------------------
# Custom marker key
# ---------------------------------------------------------------------------


def test_custom_marker_key_used_in_payload(monkeypatch) -> None:
    """`nonce_marker_key` is propagated into the pollute payload."""
    log = _patch_send(monkeypatch, _clean_responder)
    scan_prototype_pollution(
        url="https://app.example.com/api",
        probes=["json_proto_direct"],
        nonce_marker_key="custom_marker",
        detect_status_shift=False,
    )
    pollute = next(e for e in log if e["body"] is not None)
    assert "custom_marker" in pollute["body"]
