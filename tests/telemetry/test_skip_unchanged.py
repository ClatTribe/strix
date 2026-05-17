"""Tests for engine-wishlist §5 skip-if-unchanged orchestrator.

Hermetic — subprocess.run is DI'd via the `decide` kwargs;
filesystem ops use pytest's tmp_path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.telemetry.skip_unchanged import (
    SkipDecision,
    decide,
    emit_skipped_run,
)
from strix.telemetry.target_fingerprint import (
    TargetFingerprint,
    _FINGERPRINT_VERSION,
)


class _Proc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _write_prior_meta(
    runs_root: Path, run_name: str, target_value: str, digest: str,
) -> Path:
    run_dir = runs_root / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_meta.json").write_text(json.dumps({
        "run_id": run_name,
        "run_name": run_name,
        "status": "completed",
        "targets": [{"original": target_value}],
        "target_fingerprint": {
            "target_type": "repository",
            "target_value": target_value,
            "digest": digest,
            "sources": ["git:ls-remote"],
            "computed_at": "2026-05-18T00:00:00Z",
            "algo_version": _FINGERPRINT_VERSION,
        },
    }))
    return run_dir


# ---------------------------------------------------------------------------
# decide()
# ---------------------------------------------------------------------------


def test_decide_skips_when_fingerprints_match(tmp_path) -> None:
    """git ls-remote returns the same HEAD that the prior run
    stored → should_skip=True."""
    head_output = "abc123\trefs/heads/main\n"

    def _run(argv, **_):
        if argv[:3] == ["git", "ls-remote", "--symref"]:
            return _Proc(stdout=head_output)
        raise FileNotFoundError(argv)

    # Compute what the digest WILL be by calling decide first with
    # no prior run, capturing the digest, then writing a matching
    # prior run.
    first_decision = decide(
        target_type="repository",
        target_value="https://github.com/acme/x",
        runs_root=tmp_path,
        _subprocess_run=_run,
    )
    assert first_decision.should_skip is False
    assert first_decision.reason == "no_prior_run"
    assert first_decision.current_fingerprint is not None

    _write_prior_meta(
        tmp_path, "prior",
        "https://github.com/acme/x",
        first_decision.current_fingerprint.digest,
    )

    second_decision = decide(
        target_type="repository",
        target_value="https://github.com/acme/x",
        runs_root=tmp_path,
        _subprocess_run=_run,
    )
    assert second_decision.should_skip is True
    assert second_decision.reason == "fingerprint_matches_prior"
    assert second_decision.prior_run_dir is not None
    assert second_decision.prior_run_dir.name == "prior"


def test_decide_no_skip_when_fingerprint_changed(tmp_path) -> None:
    """Prior fingerprint exists but current differs → no skip."""
    _write_prior_meta(
        tmp_path, "prior", "https://github.com/acme/x", "OLD_DIGEST",
    )

    def _run(argv, **_):
        return _Proc(stdout="new-head\n")

    decision = decide(
        target_type="repository",
        target_value="https://github.com/acme/x",
        runs_root=tmp_path,
        _subprocess_run=_run,
    )
    assert decision.should_skip is False
    assert decision.reason == "fingerprint_changed"
    assert decision.prior_run_dir is not None  # prior was found


def test_decide_no_skip_when_no_prior_run(tmp_path) -> None:
    def _run(argv, **_):
        return _Proc(stdout="head\n")

    decision = decide(
        target_type="repository",
        target_value="https://github.com/acme/x",
        runs_root=tmp_path,
        _subprocess_run=_run,
    )
    assert decision.should_skip is False
    assert decision.reason == "no_prior_run"


def test_decide_no_skip_when_fingerprint_fails(tmp_path) -> None:
    """When fingerprinting fails (network down, git missing) we
    fall through to running the scan — false-negative-favoured."""
    def _run(*a, **k):
        raise FileNotFoundError("git not on PATH")

    decision = decide(
        target_type="repository",
        target_value="https://github.com/acme/x",
        runs_root=tmp_path,
        _subprocess_run=_run,
    )
    assert decision.should_skip is False
    assert decision.reason == "fingerprint_unavailable"
    assert decision.current_fingerprint is None


def test_decide_honours_explicit_prior_run_dir(tmp_path) -> None:
    """When explicit_prior_run_dir is set, only that dir is
    consulted — the wrapper owns the prior-run mapping."""
    _write_prior_meta(
        tmp_path, "other", "https://different/", "OTHER_DIGEST",
    )
    explicit = _write_prior_meta(
        tmp_path, "explicit", "https://different/", "EXPLICIT_DIGEST",
    )

    def _run(argv, **_):
        return _Proc(stdout="some-head\n")

    decision = decide(
        target_type="repository",
        target_value="https://target/",
        runs_root=tmp_path,
        explicit_prior_run_dir=explicit,
        _subprocess_run=_run,
    )
    # Explicit prior found regardless of target-value match.
    assert decision.prior_run_dir is not None
    assert decision.prior_run_dir.name == "explicit"
    # Different digest → no skip.
    assert decision.should_skip is False


# ---------------------------------------------------------------------------
# emit_skipped_run()
# ---------------------------------------------------------------------------


def test_emit_skipped_writes_run_meta_with_pointer(tmp_path) -> None:
    prior = _write_prior_meta(
        tmp_path, "prior-run", "https://x/", "DIGEST",
    )
    # Materialise some prior artefacts so the pointer block has
    # something to point at.
    (prior / "events.jsonl").write_text('{"event": "x"}\n')
    (prior / "vulnerabilities.json").write_text("{}")

    decision = SkipDecision(
        should_skip=True,
        current_fingerprint=TargetFingerprint(
            target_type="repository",
            target_value="https://x/",
            digest="DIGEST",
            sources=["git:ls-remote"],
            computed_at="2026-05-18T01:00:00Z",
        ),
        prior_run_dir=prior,
        prior_fingerprint=TargetFingerprint(
            target_type="repository",
            target_value="https://x/",
            digest="DIGEST",
        ),
        reason="fingerprint_matches_prior",
    )

    new_dir = tmp_path / "new-run"
    meta_path = emit_skipped_run(
        run_dir=new_dir,
        run_id="new-run",
        run_name="new-run",
        target_value="https://x/",
        target_type="repository",
        decision=decision,
        extra_metadata={"model_name": "gpt-test"},
    )
    assert meta_path.exists()
    body = json.loads(meta_path.read_text())
    assert body["status"] == "skipped_unchanged"
    assert body["prior_run_id"] == "prior-run"
    # Pointer entries for the artefacts that existed in the prior.
    assert "events.jsonl" in body["prior_artifacts"]
    assert "vulnerabilities.json" in body["prior_artifacts"]
    # Extra metadata propagated.
    assert body["model_name"] == "gpt-test"
    # Marker file exists.
    assert (new_dir / "SKIPPED_UNCHANGED").read_text() == "DIGEST"


def test_emit_skipped_pointers_only_reference_existing_files(tmp_path) -> None:
    """No `events.jsonl` in prior → no pointer entry for it."""
    prior = _write_prior_meta(
        tmp_path, "prior", "https://x/", "D",
    )
    # No artefacts present.

    decision = SkipDecision(
        should_skip=True,
        current_fingerprint=TargetFingerprint(
            target_type="repository",
            target_value="https://x/",
            digest="D",
        ),
        prior_run_dir=prior,
        prior_fingerprint=TargetFingerprint(
            target_type="repository",
            target_value="https://x/",
            digest="D",
        ),
        reason="fingerprint_matches_prior",
    )
    new_dir = tmp_path / "new"
    emit_skipped_run(
        run_dir=new_dir, run_id="new", run_name="new",
        target_value="https://x/", target_type="repository",
        decision=decision,
    )
    body = json.loads((new_dir / "run_meta.json").read_text())
    assert body["prior_artifacts"] == {}


def test_emit_skipped_idempotent(tmp_path) -> None:
    """Re-running emit_skipped_run overwrites cleanly."""
    prior = _write_prior_meta(tmp_path, "prior", "https://x/", "D")
    (prior / "events.jsonl").write_text("a\n")
    decision = SkipDecision(
        should_skip=True,
        current_fingerprint=TargetFingerprint(
            target_type="repository",
            target_value="https://x/", digest="D",
        ),
        prior_run_dir=prior,
        prior_fingerprint=TargetFingerprint(
            target_type="repository",
            target_value="https://x/", digest="D",
        ),
        reason="fingerprint_matches_prior",
    )
    new_dir = tmp_path / "new"
    emit_skipped_run(
        run_dir=new_dir, run_id="new", run_name="new",
        target_value="https://x/", target_type="repository",
        decision=decision,
    )
    # Second call shouldn't raise.
    emit_skipped_run(
        run_dir=new_dir, run_id="new", run_name="new",
        target_value="https://x/", target_type="repository",
        decision=decision,
    )
    # File still exists + parses.
    body = json.loads((new_dir / "run_meta.json").read_text())
    assert body["status"] == "skipped_unchanged"
