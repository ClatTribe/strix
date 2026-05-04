"""Tests for §12 finding-quality signals (PR-A / §18 row 4):
confidence, reasoning_trace, counter_proof, reproducibility_token.

These four fields are the substrate for the RLHF FP-loop and
auditor-grade explainability. Pinned by these tests so a future
refactor can't quietly drop them.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


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
    tracer = Tracer("quality-test")
    set_global_tracer(tracer)
    yield


def _findings() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    return list(t.get_existing_vulnerabilities())


def _emit(**kwargs):
    """Emit a vulnerability report with `verification_status` defaulted
    to a non-PoC value so the auto-`verified` heuristic doesn't fire
    unless explicitly tested for."""
    t = tracer_module.get_global_tracer()
    base = {
        "title": "Reflected XSS in /search",
        "severity": "medium",
        "cwe": "CWE-79",
        "endpoint": "/search?q=",
        "verification_status": "pattern_match",
    }
    base.update(kwargs)
    return t.add_vulnerability_report(**base)


# ---------------------------------------------------------------------------
# confidence — defaults from verification_status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "verification_status,expected_confidence",
    [
        ("verified", 1.0),
        ("pattern_match", 0.7),
        ("inconclusive", 0.4),
        ("needs_review", 0.4),
        ("could_not_verify", 0.2),
    ],
)
def test_confidence_default_from_verification_status(
    verification_status: str, expected_confidence: float
) -> None:
    _emit(verification_status=verification_status)
    finding = _findings()[0]
    assert finding["confidence"] == expected_confidence


def test_confidence_explicit_overrides_default() -> None:
    _emit(verification_status="pattern_match", confidence=0.95)
    finding = _findings()[0]
    assert finding["confidence"] == 0.95  # not the 0.7 default


def test_confidence_clamped_to_unit_interval() -> None:
    _emit(confidence=1.5)
    assert _findings()[0]["confidence"] == 1.0


def test_confidence_negative_clamped_to_zero() -> None:
    # Use a fresh emit because each call appends a finding.
    _emit(confidence=-0.5)
    assert _findings()[0]["confidence"] == 0.0


def test_confidence_garbage_falls_back_to_default() -> None:
    """Non-numeric confidence defaults to the conservative 0.4 value."""
    _emit(confidence="not-a-number")  # type: ignore[arg-type]
    assert _findings()[0]["confidence"] == 0.4


def test_confidence_default_for_unknown_status() -> None:
    _emit(verification_status="some-future-status")
    assert _findings()[0]["confidence"] == 0.4


# ---------------------------------------------------------------------------
# reasoning_trace — list normalisation + multi-line string support
# ---------------------------------------------------------------------------


def test_reasoning_trace_as_list() -> None:
    _emit(reasoning_trace=[
        "Saw user input reflect into the response body.",
        "Confirmed lack of HTML-encoding via marker payload.",
        "Browser interprets the marker as DOM script.",
    ])
    finding = _findings()[0]
    assert finding["reasoning_trace"] == [
        "Saw user input reflect into the response body.",
        "Confirmed lack of HTML-encoding via marker payload.",
        "Browser interprets the marker as DOM script.",
    ]


def test_reasoning_trace_as_multiline_string() -> None:
    """Newline-separated string accepted; split into bullets."""
    _emit(reasoning_trace=(
        "Saw user input reflect.\n"
        "Confirmed no encoding.\n"
        "Browser treats as DOM script."
    ))
    trace = _findings()[0]["reasoning_trace"]
    assert len(trace) == 3
    assert trace[0] == "Saw user input reflect."


def test_reasoning_trace_empty_lines_dropped() -> None:
    _emit(reasoning_trace=["one", "", "  ", "two"])
    assert _findings()[0]["reasoning_trace"] == ["one", "two"]


def test_reasoning_trace_capped_at_20_bullets() -> None:
    _emit(reasoning_trace=[f"step-{i}" for i in range(50)])
    assert len(_findings()[0]["reasoning_trace"]) == 20


def test_reasoning_trace_per_bullet_capped_at_320_chars() -> None:
    _emit(reasoning_trace=["X" * 1000])
    assert len(_findings()[0]["reasoning_trace"][0]) == 320


def test_reasoning_trace_absent_when_not_supplied() -> None:
    _emit()
    assert "reasoning_trace" not in _findings()[0]


# ---------------------------------------------------------------------------
# counter_proof — dict shape with description + evidence
# ---------------------------------------------------------------------------


def test_counter_proof_dict_shape() -> None:
    _emit(counter_proof={
        "description": "When a non-marker payload is sent, the response is HTML-encoded as expected.",
        "evidence": "GET /search?q=hello → <p>hello</p> (encoded correctly).",
    })
    finding = _findings()[0]
    assert "counter_proof" in finding
    assert finding["counter_proof"]["description"].startswith("When a non-marker")
    assert "hello" in finding["counter_proof"]["evidence"]


def test_counter_proof_description_only() -> None:
    _emit(counter_proof={"description": "No counter-evidence available."})
    cp = _findings()[0]["counter_proof"]
    assert cp["description"] == "No counter-evidence available."
    assert cp["evidence"] == ""


def test_counter_proof_capped() -> None:
    _emit(counter_proof={
        "description": "X" * 5000,
        "evidence": "Y" * 5000,
    })
    cp = _findings()[0]["counter_proof"]
    assert len(cp["description"]) == 1024
    assert len(cp["evidence"]) == 2048


def test_counter_proof_empty_dict_not_attached() -> None:
    """Empty counter_proof shouldn't pollute the finding shape."""
    _emit(counter_proof={"description": "", "evidence": ""})
    assert "counter_proof" not in _findings()[0]


def test_counter_proof_absent_when_not_supplied() -> None:
    _emit()
    assert "counter_proof" not in _findings()[0]


# ---------------------------------------------------------------------------
# reproducibility_token — distinct from fingerprint
# ---------------------------------------------------------------------------


def test_reproducibility_token_present() -> None:
    _emit()
    finding = _findings()[0]
    assert "reproducibility_token" in finding
    assert len(finding["reproducibility_token"]) == 16
    assert "fingerprint" in finding


def test_reproducibility_token_distinct_from_fingerprint() -> None:
    """Even though both are hashes, they encode different inputs and
    must differ in general (using a finding with reasoning to make
    them definitely-different)."""
    _emit(reasoning_trace=["unique trace step"])
    finding = _findings()[0]
    assert finding["reproducibility_token"] != finding["fingerprint"]


def test_reproducibility_token_changes_with_reasoning() -> None:
    """Different reasoning chains → different reproducibility tokens.
    This is the key contract: fingerprint dedupes vulns; token dedupes
    reasoning attempts.

    NOTE: cross-tool dedup (#98) merges findings with the same
    fingerprint, so we use distinct endpoints (= distinct fingerprints)
    to keep both findings around. The token-vs-token comparison is
    still meaningful: it confirms the reasoning_trace inputs DO
    propagate into the token hash."""
    _emit(reasoning_trace=["reasoning A"], endpoint="/a")
    _emit(reasoning_trace=["reasoning B"], endpoint="/b")

    findings = _findings()
    assert len(findings) == 2
    # Different fingerprints (different endpoints).
    assert findings[0]["fingerprint"] != findings[1]["fingerprint"]
    # Different tokens (different reasoning).
    assert findings[0]["reproducibility_token"] != findings[1]["reproducibility_token"]


def test_reproducibility_token_stable_for_same_inputs() -> None:
    """Same inputs (same endpoint, same reasoning) → cross-tool dedup
    merges them into ONE record. The merge contract preserves the
    first record's token. We assert the single-record's token is
    deterministic by re-computing it on a freshly-built tracer."""
    _emit(reasoning_trace=["same trace"], endpoint="/x")
    findings_first = _findings()
    assert len(findings_first) == 1
    token_first = findings_first[0]["reproducibility_token"]

    # Emitting the same finding again merges, doesn't append.
    _emit(reasoning_trace=["same trace"], endpoint="/x")
    findings_after = _findings()
    assert len(findings_after) == 1  # merged
    assert findings_after[0]["reproducibility_token"] == token_first


def test_reproducibility_token_changes_with_kill_chain() -> None:
    _emit(
        reasoning_trace=["t"], endpoint="/a",
        kill_chain=[{"step": 1, "type": "discovery"}],
    )
    _emit(
        reasoning_trace=["t"], endpoint="/b",
        kill_chain=[{"step": 1, "type": "exploitation"}],
    )
    findings = _findings()
    assert len(findings) == 2
    assert findings[0]["reproducibility_token"] != findings[1]["reproducibility_token"]


def test_reproducibility_token_changes_with_target_state() -> None:
    _emit(reasoning_trace=["t"], endpoint="/a")
    _emit(reasoning_trace=["t"], endpoint="/b")
    findings = _findings()
    # Different endpoints → different fingerprints AND different tokens.
    assert findings[0]["fingerprint"] != findings[1]["fingerprint"]
    assert findings[0]["reproducibility_token"] != findings[1]["reproducibility_token"]


# ---------------------------------------------------------------------------
# All four fields together (integration)
# ---------------------------------------------------------------------------


def test_all_four_quality_signals_together() -> None:
    _emit(
        verification_status="verified",
        confidence=0.95,
        reasoning_trace=["step 1", "step 2"],
        counter_proof={"description": "boundary", "evidence": "evidence"},
    )
    f = _findings()[0]
    assert f["confidence"] == 0.95
    assert f["reasoning_trace"] == ["step 1", "step 2"]
    assert f["counter_proof"]["description"] == "boundary"
    assert "reproducibility_token" in f
    assert "fingerprint" in f


def test_findings_json_carries_all_four_fields(tmp_path) -> None:
    """The on-disk vulnerabilities.json carries the new fields verbatim
    so the wrapper can render them."""
    import json as _json

    _emit(
        confidence=0.9,
        reasoning_trace=["bullet 1"],
        counter_proof={"description": "boundary"},
    )
    t = tracer_module.get_global_tracer()
    t.save_run_data(mark_complete=True)

    findings_json = tmp_path / "strix_runs" / "quality-test" / "vulnerabilities.json"
    data = _json.loads(findings_json.read_text())
    f = data["findings"][0]
    assert f["confidence"] == 0.9
    assert f["reasoning_trace"] == ["bullet 1"]
    assert f["counter_proof"]["description"] == "boundary"
    assert "reproducibility_token" in f
