"""Tests for cryptographically-signed audit trail (roadmap §16 / PR #127).

Coverage:
  * Chain links: prev_event_hash + event_hash on every event
  * Genesis: first event's prev_event_hash = "0"*64
  * Hash determinism: same record → same hash
  * Hash sensitivity: tampering with any field → different hash
  * Chain validation: walking the file recomputes correctly
  * Signing modes: no-key=none, HMAC-SHA256, external command
  * verify_signature happy + sad paths
  * No-op when STRIX_SIGNING_KEY/CMD absent
  * run.signature.json contents
  * mark_complete=False does NOT write a signature
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import audit_trail
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
    monkeypatch.delenv("STRIX_SIGNING_KEY", raising=False)
    monkeypatch.delenv("STRIX_SIGNING_CMD", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


def _events(tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / "audit-test" / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# Pure helper: compute_event_hash + stamp_event_record
# ---------------------------------------------------------------------------


def test_genesis_hash_constant() -> None:
    assert audit_trail.GENESIS_HASH == "0" * 64
    assert len(audit_trail.GENESIS_HASH) == 64


def test_compute_event_hash_deterministic() -> None:
    record = {"event_type": "x", "payload": {"a": 1, "b": 2}}
    h1 = audit_trail.compute_event_hash(record)
    h2 = audit_trail.compute_event_hash({"event_type": "x", "payload": {"b": 2, "a": 1}})
    # Same content, different key order → same hash (sort_keys=True).
    assert h1 == h2


def test_compute_event_hash_excludes_self() -> None:
    """The `event_hash` field on the record must NOT influence
    the computed hash — otherwise the chain would self-reference."""
    base = {"event_type": "x", "payload": {"a": 1}}
    h_no_field = audit_trail.compute_event_hash(base)
    base_with_hash = dict(base)
    base_with_hash["event_hash"] = "deadbeef" * 8
    h_with_field = audit_trail.compute_event_hash(base_with_hash)
    assert h_no_field == h_with_field


def test_compute_event_hash_sensitive_to_payload() -> None:
    """Tampering with any field changes the hash."""
    h1 = audit_trail.compute_event_hash({"event_type": "x", "payload": "v1"})
    h2 = audit_trail.compute_event_hash({"event_type": "x", "payload": "v2"})
    assert h1 != h2


def test_stamp_event_record_sets_both_fields() -> None:
    record = {"event_type": "x"}
    audit_trail.stamp_event_record(record, prev_event_hash="abc" * 21 + "x")
    assert record["prev_event_hash"] == "abc" * 21 + "x"
    assert "event_hash" in record
    assert len(record["event_hash"]) == 64


def test_stamp_event_record_chain_links() -> None:
    """Chain link: r2.prev_event_hash == r1.event_hash."""
    r1 = {"event_type": "first"}
    audit_trail.stamp_event_record(r1, prev_event_hash=audit_trail.GENESIS_HASH)
    r2 = {"event_type": "second"}
    audit_trail.stamp_event_record(r2, prev_event_hash=r1["event_hash"])
    assert r2["prev_event_hash"] == r1["event_hash"]
    assert r1["event_hash"] != r2["event_hash"]


# ---------------------------------------------------------------------------
# Tracer integration: every event gets stamped
# ---------------------------------------------------------------------------


def test_tracer_stamps_every_event(monkeypatch, tmp_path) -> None:
    tracer = Tracer("audit-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": ["https://example.com"]})
    tracer.log_agent_creation("agent-1", "Agent", "task")
    tracer.log_chat_message("hello", role="user", agent_id="agent-1")

    events = _events(tmp_path)
    assert len(events) >= 3  # run.started + run.configured + agent.created + chat.message
    for ev in events:
        assert "prev_event_hash" in ev
        assert "event_hash" in ev
        assert len(ev["event_hash"]) == 64


def test_tracer_chain_walk(monkeypatch, tmp_path) -> None:
    """Walk the chain: each event's prev_event_hash should equal
    the previous event's event_hash, starting from GENESIS_HASH."""
    tracer = Tracer("audit-test")
    set_global_tracer(tracer)
    tracer.log_agent_creation("agent-1", "A", "t")
    tracer.log_chat_message("m1", role="user", agent_id="agent-1")
    tracer.log_chat_message("m2", role="assistant", agent_id="agent-1")

    events = _events(tmp_path)
    expected_prev = audit_trail.GENESIS_HASH
    for ev in events:
        assert ev["prev_event_hash"] == expected_prev, (
            f"chain break at event_type={ev.get('event_type')!r}: "
            f"prev={ev['prev_event_hash']} expected={expected_prev}"
        )
        expected_prev = ev["event_hash"]


def test_tracer_chain_detects_tampering(monkeypatch, tmp_path) -> None:
    """A consumer that recomputes hashes detects mid-file tampering."""
    tracer = Tracer("audit-test")
    set_global_tracer(tracer)
    tracer.log_agent_creation("agent-1", "A", "t")
    tracer.log_chat_message("m1", role="user", agent_id="agent-1")

    # Tamper with the second event's payload.
    events = _events(tmp_path)
    events[1]["payload"] = {"injected": "tampered"}

    # Walk the chain — recomputed hash should NOT match the stored one.
    for i, ev in enumerate(events):
        recomputed = audit_trail.compute_event_hash(ev)
        if i == 1:
            # The tampered event's stored hash will differ from
            # the recomputed one.
            assert recomputed != ev["event_hash"]
            return
    pytest.fail("expected tampering detection at index 1")


# ---------------------------------------------------------------------------
# Signing — no key configured = no-op
# ---------------------------------------------------------------------------


def test_sign_chain_terminal_no_key_returns_none(monkeypatch) -> None:
    sig = audit_trail.sign_chain_terminal("abcdef" * 10 + "1234")
    assert sig["signature_algorithm"] == "none"
    assert sig["signature"] is None
    assert sig["key_fingerprint"] is None


def test_save_run_data_writes_signature_file_with_no_key(monkeypatch, tmp_path) -> None:
    """No key configured → signature file is still written, with
    algorithm='none'. Operators can still verify the chain hash."""
    tracer = Tracer("audit-test")
    set_global_tracer(tracer)
    tracer.log_agent_creation("agent-1", "A", "t")
    tracer.save_run_data(mark_complete=True)

    sig_file = tmp_path / "strix_runs" / "audit-test" / "run.signature.json"
    assert sig_file.exists()
    block = json.loads(sig_file.read_text())
    assert block["signature_algorithm"] == "none"
    assert block["signature"] is None
    assert isinstance(block["chain_terminal_hash"], str)
    assert len(block["chain_terminal_hash"]) == 64
    assert block["event_count"] >= 2


# ---------------------------------------------------------------------------
# Signing — HMAC mode
# ---------------------------------------------------------------------------


def test_sign_chain_terminal_hmac_mode(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SIGNING_KEY", "test-key-value")
    sig = audit_trail.sign_chain_terminal("a" * 64)
    assert sig["signature_algorithm"] == "hmac-sha256"
    assert isinstance(sig["signature"], str)
    assert len(sig["signature"]) == 64
    assert isinstance(sig["key_fingerprint"], str)
    assert len(sig["key_fingerprint"]) == 64


def test_save_run_data_signs_with_hmac_key(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_SIGNING_KEY", "operator-controlled-key")
    tracer = Tracer("audit-test")
    set_global_tracer(tracer)
    tracer.log_agent_creation("agent-1", "A", "t")
    tracer.save_run_data(mark_complete=True)

    sig_file = tmp_path / "strix_runs" / "audit-test" / "run.signature.json"
    block = json.loads(sig_file.read_text())
    assert block["signature_algorithm"] == "hmac-sha256"
    assert block["signature"] is not None
    assert block["key_fingerprint"] is not None


def test_verify_signature_hmac_round_trip(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SIGNING_KEY", "key-1")
    chain_hash = "f" * 64
    sig_block = audit_trail.sign_chain_terminal(chain_hash)

    # Right key verifies.
    valid, reason = audit_trail.verify_signature(
        chain_hash, sig_block, key="key-1"
    )
    assert valid is True
    assert reason is None

    # Wrong key fails.
    valid_wrong, reason_wrong = audit_trail.verify_signature(
        chain_hash, sig_block, key="key-2"
    )
    assert valid_wrong is False
    assert reason_wrong == "hmac mismatch"

    # Tampered chain hash fails.
    valid_tampered, _ = audit_trail.verify_signature(
        "0" * 64, sig_block, key="key-1"
    )
    assert valid_tampered is False


def test_verify_signature_hmac_without_key_fails() -> None:
    sig_block = {
        "signature_algorithm": "hmac-sha256",
        "signature": "abcd",
        "chain_terminal_hash": "ef",
    }
    valid, reason = audit_trail.verify_signature("ef", sig_block, key=None)
    assert valid is False
    assert reason is not None
    assert "no key" in reason.lower()


def test_verify_signature_unsigned() -> None:
    sig_block = {"signature_algorithm": "none"}
    valid, reason = audit_trail.verify_signature("xx", sig_block)
    assert valid is False
    assert reason == "unsigned"


def test_verify_signature_unknown_algorithm() -> None:
    sig_block = {"signature_algorithm": "rsa-pss-mystery"}
    valid, reason = audit_trail.verify_signature("xx", sig_block)
    assert valid is False
    assert "unknown algorithm" in (reason or "")


# ---------------------------------------------------------------------------
# Signing — external mode
# ---------------------------------------------------------------------------


def test_sign_chain_terminal_external_signer(monkeypatch) -> None:
    """STRIX_SIGNING_CMD takes priority over STRIX_SIGNING_KEY.
    The cmd reads chain_hash on stdin and emits b64 signature on stdout."""
    # Use a trivial command that just echoes a constant string.
    monkeypatch.setenv("STRIX_SIGNING_CMD", "/bin/echo signed-by-hsm")
    monkeypatch.setenv("STRIX_SIGNING_KEY", "would-be-used-by-hmac")

    sig = audit_trail.sign_chain_terminal("a" * 64)
    assert sig["signature_algorithm"] == "external"
    assert "signed-by-hsm" in sig["signature"]
    assert sig["external_signer"] == "/bin/echo signed-by-hsm"
    # HMAC path NOT used → key_fingerprint not set.
    assert sig["key_fingerprint"] is None


def test_external_signer_failure_recorded_not_raised(monkeypatch) -> None:
    """When the external signer crashes, we record the diagnostic
    rather than blowing up the run."""
    monkeypatch.setenv("STRIX_SIGNING_CMD", "/nonexistent-binary-xyz")
    sig = audit_trail.sign_chain_terminal("a" * 64)
    assert sig["signature_algorithm"] == "external"
    assert sig["signature"].startswith("ERROR")


def test_verify_signature_external_returns_true() -> None:
    """We can't generically verify HSM signatures — verify_signature
    returns True so callers know "it's the operator's job to verify
    out-of-band"."""
    sig_block = {"signature_algorithm": "external", "signature": "opaque-bytes"}
    valid, reason = audit_trail.verify_signature("xx", sig_block)
    assert valid is True
    assert reason is None


# ---------------------------------------------------------------------------
# mark_complete=False does NOT write signature
# ---------------------------------------------------------------------------


def test_partial_save_does_not_write_signature(monkeypatch, tmp_path) -> None:
    tracer = Tracer("audit-test")
    set_global_tracer(tracer)
    tracer.log_agent_creation("agent-1", "A", "t")
    tracer.save_run_data(mark_complete=False)

    sig_file = tmp_path / "strix_runs" / "audit-test" / "run.signature.json"
    assert not sig_file.exists()
