"""Tests for RLHF Phase 1 / A3 — feedback_loader.

Pins the verdict / fp_reason closed-enum sets, the discovery
order, the latest-label-wins resolution, and the auto-dismiss
policy gates.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import feedback_loader


# ---------------------------------------------------------------------------
# Closed-enum invariants — must match docs/rlhf-design.md and #118
# ---------------------------------------------------------------------------


def test_verdict_enum_pinned() -> None:
    assert feedback_loader._VALID_VERDICTS == frozenset({
        "tp", "fp", "partial_tp", "needs_review", "out_of_scope",
    })


def test_fp_reason_enum_pinned() -> None:
    """13-value closed-enum mirrors #118 dismiss_finding.
    Drift here breaks the wrapper's dismissal pipeline."""
    assert feedback_loader._VALID_FP_REASONS == frozenset({
        "input_properly_encoded",
        "framework_default_blocked",
        "csrf_token_validated",
        "auth_enforced",
        "not_reflected",
        "different_origin",
        "out_of_scope",
        "false_positive_signature",
        "compensating_control",
        "intended_behavior",
        "test_fixture",
        "deprecated_path",
        "other",
    })


# ---------------------------------------------------------------------------
# _validate_label
# ---------------------------------------------------------------------------


def _label(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": 1,
        "finding_fingerprint": "abc123",
        "verdict": "fp",
    }
    base.update(overrides)
    return base


def test_validate_label_minimal_record_ok() -> None:
    valid, _ = feedback_loader._validate_label(_label())
    assert valid is True


def test_validate_label_rejects_missing_fingerprint() -> None:
    valid, reason = feedback_loader._validate_label(_label(finding_fingerprint=""))
    assert valid is False
    assert "fingerprint" in (reason or "")


def test_validate_label_rejects_unknown_verdict() -> None:
    valid, reason = feedback_loader._validate_label(_label(verdict="dunno"))
    assert valid is False
    assert "verdict" in (reason or "")


def test_validate_label_rejects_unknown_fp_reason() -> None:
    valid, reason = feedback_loader._validate_label(
        _label(fp_reason="i_dont_like_it")
    )
    assert valid is False
    assert "fp_reason" in (reason or "")


def test_validate_label_accepts_null_fp_reason() -> None:
    valid, _ = feedback_loader._validate_label(_label(fp_reason=None))
    assert valid is True


def test_validate_label_rejects_non_dict() -> None:
    valid, _ = feedback_loader._validate_label("not a dict")  # type: ignore[arg-type]
    assert valid is False


# ---------------------------------------------------------------------------
# JSONL reader
# ---------------------------------------------------------------------------


def test_read_jsonl_skips_blank_and_malformed_lines(tmp_path: Path) -> None:
    p = tmp_path / "feedback.jsonl"
    p.write_text(
        '{"finding_fingerprint":"a","verdict":"fp"}\n'
        "\n"  # blank line
        "not json\n"  # malformed line
        '{"finding_fingerprint":"b","verdict":"tp"}\n'
    )
    out = feedback_loader._read_jsonl(p)
    assert len(out) == 2
    assert out[0]["finding_fingerprint"] == "a"
    assert out[1]["finding_fingerprint"] == "b"


def test_read_jsonl_returns_empty_when_file_missing(tmp_path: Path) -> None:
    assert feedback_loader._read_jsonl(tmp_path / "nope.jsonl") == []


# ---------------------------------------------------------------------------
# Discovery order
# ---------------------------------------------------------------------------


def test_candidate_paths_order(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("STRIX_FEEDBACK_FROM", raising=False)
    explicit = tmp_path / "explicit.jsonl"
    run = tmp_path / "run"
    run.mkdir()

    paths = feedback_loader._candidate_paths(
        explicit=str(explicit), run_dir=run,
    )

    assert paths[0] == explicit.resolve()
    assert paths[1] == run / "feedback.jsonl"
    # Last entry is always ~/.strix/feedback.jsonl.
    assert paths[-1].name == "feedback.jsonl"
    assert paths[-1].parent.name == ".strix"


def test_candidate_paths_env_var_inserted(tmp_path: Path, monkeypatch) -> None:
    env = tmp_path / "env.jsonl"
    monkeypatch.setenv("STRIX_FEEDBACK_FROM", str(env))
    run = tmp_path / "run"
    run.mkdir()

    paths = feedback_loader._candidate_paths(explicit=None, run_dir=run)
    assert env.resolve() in paths
    # Env path comes before run-dir.
    assert paths.index(env.resolve()) < paths.index(run / "feedback.jsonl")


def test_candidate_paths_dedupes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("STRIX_FEEDBACK_FROM", raising=False)
    p = tmp_path / "f.jsonl"
    paths = feedback_loader._candidate_paths(
        explicit=str(p), run_dir=p.parent,
    )
    # No duplicate path strings even if multiple sources resolve to the same.
    s = [str(x) for x in paths]
    assert len(s) == len(set(s))


# ---------------------------------------------------------------------------
# load_feedback — union across discovered paths, history preserved
# ---------------------------------------------------------------------------


def test_load_feedback_union_across_paths(tmp_path: Path, monkeypatch) -> None:
    """Both run-dir feedback and explicit-path feedback apply."""
    monkeypatch.delenv("STRIX_FEEDBACK_FROM", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))  # divert ~/.strix lookup
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "feedback.jsonl").write_text(
        json.dumps({"finding_fingerprint": "a", "verdict": "fp",
                    "labeled_at": "2026-01-01T00:00:00Z"}) + "\n"
    )
    explicit = tmp_path / "explicit.jsonl"
    explicit.write_text(
        json.dumps({"finding_fingerprint": "a", "verdict": "tp",
                    "labeled_at": "2026-01-02T00:00:00Z"}) + "\n"
        + json.dumps({"finding_fingerprint": "b", "verdict": "fp"}) + "\n"
    )

    out = feedback_loader.load_feedback(
        explicit_path=str(explicit), run_dir=run_dir,
    )
    assert "a" in out and "b" in out
    assert len(out["a"]) == 2  # both sources contributed
    assert len(out["b"]) == 1


def test_load_feedback_drops_invalid_silently(tmp_path: Path, monkeypatch) -> None:
    """Invalid records are skipped, not raised. Best-effort."""
    monkeypatch.delenv("STRIX_FEEDBACK_FROM", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    p = tmp_path / "feedback.jsonl"
    p.write_text(
        json.dumps({"finding_fingerprint": "a", "verdict": "fp"}) + "\n"
        + json.dumps({"finding_fingerprint": "", "verdict": "fp"}) + "\n"
        + json.dumps({"finding_fingerprint": "b", "verdict": "garbage"}) + "\n"
    )
    out = feedback_loader.load_feedback(explicit_path=str(p))
    assert list(out.keys()) == ["a"]


def test_load_feedback_empty_when_nothing_found(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("STRIX_FEEDBACK_FROM", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))  # no ~/.strix/feedback.jsonl
    out = feedback_loader.load_feedback(run_dir=tmp_path / "no-such-run")
    assert out == {}


# ---------------------------------------------------------------------------
# get_latest_verdict — labeled_at wins, falls back to file order
# ---------------------------------------------------------------------------


def test_get_latest_verdict_uses_labeled_at() -> None:
    history = [
        {"verdict": "tp", "labeled_at": "2026-01-01T00:00:00Z"},
        {"verdict": "fp", "labeled_at": "2026-01-02T00:00:00Z"},
        {"verdict": "tp", "labeled_at": "2026-01-01T12:00:00Z"},
    ]
    latest = feedback_loader.get_latest_verdict(history)
    assert latest is not None
    assert latest["verdict"] == "fp"


def test_get_latest_verdict_handles_missing_timestamps() -> None:
    history = [{"verdict": "fp"}, {"verdict": "tp"}]
    latest = feedback_loader.get_latest_verdict(history)
    assert latest is not None  # no crash on missing labeled_at


def test_get_latest_verdict_empty_history() -> None:
    assert feedback_loader.get_latest_verdict([]) is None


# ---------------------------------------------------------------------------
# is_auto_dismissable — the policy gates
# ---------------------------------------------------------------------------


def test_auto_dismiss_off_policy_never_dismisses() -> None:
    history = [{"verdict": "fp"}]
    should, attr = feedback_loader.is_auto_dismissable(history, policy="off")
    assert should is False
    assert attr is None


def test_auto_dismiss_conservative_one_fp_zero_tp_dismisses() -> None:
    history = [{"verdict": "fp", "labeled_at": "2026-01-01T00:00:00Z"}]
    should, attr = feedback_loader.is_auto_dismissable(
        history, policy="conservative",
    )
    assert should is True
    assert attr is not None
    assert attr["verdict"] == "fp"


def test_auto_dismiss_conservative_mixed_history_does_not_dismiss() -> None:
    """Mixed = ambiguous. Conservative policy refuses to dismiss."""
    history = [{"verdict": "fp"}, {"verdict": "tp"}]
    should, attr = feedback_loader.is_auto_dismissable(
        history, policy="conservative",
    )
    assert should is False
    assert attr is None


def test_auto_dismiss_aggressive_latest_fp_dismisses() -> None:
    """Aggressive ignores prior TPs — latest verdict wins."""
    history = [
        {"verdict": "tp", "labeled_at": "2026-01-01T00:00:00Z"},
        {"verdict": "fp", "labeled_at": "2026-01-02T00:00:00Z"},
    ]
    should, attr = feedback_loader.is_auto_dismissable(
        history, policy="aggressive",
    )
    assert should is True
    assert attr is not None
    assert attr["verdict"] == "fp"


def test_auto_dismiss_aggressive_latest_tp_does_not_dismiss() -> None:
    history = [
        {"verdict": "fp", "labeled_at": "2026-01-01T00:00:00Z"},
        {"verdict": "tp", "labeled_at": "2026-01-02T00:00:00Z"},
    ]
    should, _ = feedback_loader.is_auto_dismissable(
        history, policy="aggressive",
    )
    assert should is False


def test_auto_dismiss_empty_history_does_not_dismiss() -> None:
    should, attr = feedback_loader.is_auto_dismissable([], policy="conservative")
    assert should is False
    assert attr is None


# ---------------------------------------------------------------------------
# env_policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("conservative", "conservative"),
        ("aggressive", "aggressive"),
        ("off", "off"),
        ("CONSERVATIVE", "conservative"),  # case-insensitive
        ("  off  ", "off"),                # whitespace-tolerant
        ("garbage", "conservative"),       # falls back
        ("", "conservative"),
    ],
)
def test_env_policy(monkeypatch, raw: str, expected: str) -> None:
    monkeypatch.setenv("STRIX_FP_AUTO_DISMISS", raw)
    assert feedback_loader.env_policy() == expected


def test_env_policy_unset_defaults_conservative(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_FP_AUTO_DISMISS", raising=False)
    assert feedback_loader.env_policy() == "conservative"
