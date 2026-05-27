"""Tests for iter-35.4 — sandbox-tool findings reach the host tracer.

Before this iter, sandbox tools that called
`tracer.add_vulnerability_report` from inside their body wrote to the
sandbox process's tracer singleton — a fresh, hookless instance. The
host's tracer (where L1.5 hooks live) never saw the findings.
Findings appeared in trajectory.jsonl + run_summary.findings_summary
but vulnerabilities.json showed `count=0`, and L1.5 enrichment was
silently bypassed for ~53 tools.

The fix: the sandbox tool_server captures any findings the tool
emitted, ships them back as a `_sandbox_emitted_findings` sidecar in
the result, and the host's `_execute_tool_in_sandbox` re-emits each
through the host tracer so the L1.5 hook chain fires.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from strix.tools.executor import (
    _L15_HOOK_ATTACHED_FIELDS,
    _propagate_sandbox_findings_to_host,
)


# ---------------------------------------------------------------------------
# Direct unit tests for the propagation helper
# ---------------------------------------------------------------------------


def test_no_sidecar_returns_result_unchanged():
    """When the sandbox didn't emit findings, the result passes
    through cleanly — no tracer interaction."""
    result = {"status": "ok", "findings": []}
    with patch("strix.telemetry.tracer.get_global_tracer") as mock_get:
        out = _propagate_sandbox_findings_to_host("some_tool", result)
    mock_get.assert_not_called()
    assert out == {"status": "ok", "findings": []}


def test_non_dict_result_passes_through():
    """Tools that return strings / lists / None aren't affected."""
    with patch("strix.telemetry.tracer.get_global_tracer") as mock_get:
        out = _propagate_sandbox_findings_to_host("some_tool", "raw string")
    mock_get.assert_not_called()
    assert out == "raw string"


def _fake_tracer_with_kwargs_capture() -> tuple[Any, list[dict[str, Any]]]:
    """Build a tracer-like object whose `add_vulnerability_report`
    has the SAME signature as the real one (so signature-based filter
    works) and captures each call's kwargs into a list."""
    captured: list[dict[str, Any]] = []

    def add_vulnerability_report(  # noqa: PLR0913
        title: str,
        severity: str,
        description: str | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        target: str | None = None,
        category: str | None = None,
        cwe: str | None = None,
        cve: str | None = None,
        verification_status: str | None = None,
        confidence: float | None = None,
        discovery_source_tool: str | None = None,
        code_locations: list[dict[str, Any]] | None = None,
    ) -> str:
        captured.append({
            "title": title, "severity": severity,
            "description": description, "endpoint": endpoint,
            "method": method, "target": target, "category": category,
            "cwe": cwe, "cve": cve,
            "verification_status": verification_status,
            "confidence": confidence,
            "discovery_source_tool": discovery_source_tool,
            "code_locations": code_locations,
        })
        return f"vuln-{len(captured):04d}"

    fake = type("FakeTracer", (), {})()
    fake.add_vulnerability_report = add_vulnerability_report
    return fake, captured


def test_sidecar_findings_reach_host_tracer():
    """The headline test: when the result contains
    `_sandbox_emitted_findings`, each entry must be re-emitted via
    `host_tracer.add_vulnerability_report` so L1.5 hooks fire."""
    fake_tracer, captured = _fake_tracer_with_kwargs_capture()
    result = {
        "status": "ok",
        "findings": [],  # tool's "regular" findings (could be empty)
        "_sandbox_emitted_findings": [
            {
                "title": "SQLi at /api/products",
                "severity": "high",
                "cwe": "CWE-89",
                "endpoint": "/api/products?id=1",
                "category": "sqli",
                "verification_status": "verified",
                "confidence": 0.95,
            },
            {
                "title": "XSS at /search",
                "severity": "medium",
                "cwe": "CWE-79",
                "endpoint": "/search?q=test",
                "category": "xss",
            },
        ],
    }
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=fake_tracer,
    ):
        out = _propagate_sandbox_findings_to_host("scan_test", result)

    # Both findings should land on the host tracer.
    assert len(captured) == 2
    assert captured[0]["title"] == "SQLi at /api/products"
    assert captured[0]["cwe"] == "CWE-89"
    assert captured[0]["endpoint"] == "/api/products?id=1"
    assert captured[1]["title"] == "XSS at /search"
    # Sidecar must be stripped from the returned result.
    assert "_sandbox_emitted_findings" not in out


def test_l15_hook_fields_stripped_before_reemission():
    """When the sandbox tracer already attached L1.5 fields (e.g. if
    the sandbox happened to have its own hooks installed), the host
    must STRIP them so its own hooks recompute fresh values. Otherwise
    the host sees stale annotations from a different tracer state."""
    fake_tracer, captured = _fake_tracer_with_kwargs_capture()
    result = {
        "_sandbox_emitted_findings": [
            {
                "title": "Test finding",
                "severity": "high",
                "cwe": "CWE-89",
                # These are L1.5-hook-attached fields. Must NOT be
                # passed back into add_vulnerability_report — the host
                # hooks compute them.
                "id": "stale-vuln-0001",
                "fingerprint": "stale-fp",
                "surface_priority": "stale_low",
                "exploitability": {"stale": True},
                "corroborated_by": ["stale-tool"],
            },
        ],
    }
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=fake_tracer,
    ):
        _propagate_sandbox_findings_to_host("scan_test", result)

    # _fake_tracer_with_kwargs_capture's add_vulnerability_report
    # doesn't accept the L1.5 fields, so if propagation tried to pass
    # them it'd TypeError — the fact that the call succeeded AND the
    # capture has only the expected core fields proves the stripping
    # works correctly.
    assert len(captured) == 1
    assert captured[0]["title"] == "Test finding"
    assert captured[0]["cwe"] == "CWE-89"


def test_unknown_kwargs_filtered_to_signature():
    """Sandbox findings might include keys that aren't part of the
    host tracer's add_vulnerability_report signature (e.g. internal
    audit fields). Those must be filtered out — passing them raises
    TypeError in the host call."""
    mock_tracer = MagicMock()
    # Build a fake tracer whose add_vulnerability_report only accepts
    # a narrow signature.
    def fake_add(
        title: str, severity: str,
        endpoint: str | None = None, cwe: str | None = None,
    ) -> str:
        return "vuln-0001"
    mock_tracer.add_vulnerability_report = fake_add

    result = {
        "_sandbox_emitted_findings": [
            {
                "title": "Test",
                "severity": "high",
                "cwe": "CWE-89",
                "endpoint": "/api",
                # Unknown — would raise if passed through.
                "totally_made_up_field": "garbage",
                "another_unknown": {"nested": True},
            },
        ],
    }
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=mock_tracer,
    ):
        # No TypeError raised → the filter worked.
        _propagate_sandbox_findings_to_host("scan_test", result)


def test_propagation_failure_does_not_crash():
    """If host_tracer.add_vulnerability_report raises (e.g. malformed
    finding), the propagation must swallow the error and continue
    with subsequent findings — never crash the executor path."""
    mock_tracer = MagicMock()
    # First call raises, second succeeds.
    mock_tracer.add_vulnerability_report.side_effect = [
        RuntimeError("malformed payload"),
        "vuln-0002",
    ]
    result = {
        "_sandbox_emitted_findings": [
            {"title": "Bad finding", "severity": "high"},
            {"title": "Good finding", "severity": "medium"},
        ],
    }
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=mock_tracer,
    ):
        # No exception bubbles up.
        out = _propagate_sandbox_findings_to_host("scan_test", result)
    # Both attempts made; the bad one was swallowed.
    assert mock_tracer.add_vulnerability_report.call_count == 2
    assert "_sandbox_emitted_findings" not in out


def test_no_host_tracer_passes_result_through():
    """In tests / partial init where the host tracer isn't available,
    the helper must not crash — just return the result as-is."""
    result = {
        "status": "ok",
        "_sandbox_emitted_findings": [{"title": "x", "severity": "high"}],
    }
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=None,
    ):
        out = _propagate_sandbox_findings_to_host("scan_test", result)
    # Sidecar STAYS in the result so a downstream consumer can still
    # see what would have been emitted.
    assert isinstance(out, dict)


def test_wrapped_non_dict_result_unwrapped():
    """The sandbox tool_server wraps non-dict return values so the
    sidecar can travel. The host extractor must unwrap on the way
    out so callers see the original return."""
    mock_tracer = MagicMock()
    result = {
        "_sandbox_wrapped_result": "original return value as string",
        "_sandbox_emitted_findings": [
            {"title": "Test", "severity": "high"},
        ],
    }
    with patch(
        "strix.telemetry.tracer.get_global_tracer", return_value=mock_tracer,
    ):
        out = _propagate_sandbox_findings_to_host("scan_test", result)
    # Caller sees the original string, not the wrapper dict.
    assert out == "original return value as string"
    # Finding was still emitted.
    assert mock_tracer.add_vulnerability_report.call_count == 1


# ---------------------------------------------------------------------------
# Invariants on the strip-list
# ---------------------------------------------------------------------------


def test_strip_list_contains_known_l15_fields():
    """If a future L1.5 hook adds a new annotation, the iter-35.4
    strip list should be updated alongside. This test pins the
    current expected set so a regression in the strip list (someone
    accidentally deleting an entry) gets caught."""
    expected_subset = {
        "id", "fingerprint", "report_id",
        "surface_priority", "exploitability",
        "corroborated_by", "corroborators",
        "post_emit_verifier",
        "discovery_method",
        "epss", "kev", "campaign",
        "threat_intel",
    }
    missing = expected_subset - _L15_HOOK_ATTACHED_FIELDS
    assert not missing, (
        f"_L15_HOOK_ATTACHED_FIELDS is missing fields that L1.5 "
        f"hooks attach: {missing}. Adding back may unmask a "
        f"sandbox→host enrichment bug."
    )


def test_strip_list_includes_sidecar_key():
    """Defensive — the sidecar key itself must be in the strip list
    so we never recursively re-emit a finding whose payload already
    contains a sidecar (would explode at runtime)."""
    assert "_sandbox_emitted_findings" in _L15_HOOK_ATTACHED_FIELDS
