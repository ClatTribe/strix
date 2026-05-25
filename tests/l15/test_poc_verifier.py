"""Tests for iter-29.5 — PoC validator."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from strix.l15.baseline_diff import DiffSignal
from strix.l15.poc_verifier import (
    CONFIDENCE_DISMISSED,
    CONFIDENCE_LIKELY,
    CONFIDENCE_SUSPECTED,
    CONFIDENCE_VERIFIED,
    PocVerification,
    verify_finding,
)


def _sig(*, score, classes=None, status_changed=False, time_ratio=1.0, redirect_changed=False):
    return DiffSignal(
        score=score,
        new_error_classes=classes or [],
        status_class_changed=status_changed,
        time_ratio=time_ratio,
        redirect_target_changed=redirect_changed,
    )


def test_variant_reproduces_same_class_returns_verified():
    """Original tripped sqli; re-fire tripped sqli; variant tripped
    sqli → verified."""
    original = _sig(score=0.7, classes=["sqli"])
    rerun = _sig(score=0.7, classes=["sqli"])
    variant = _sig(score=0.6, classes=["sqli"])
    v = verify_finding(original, lambda: rerun, lambda: variant, wait_seconds=0)
    assert v.confidence == CONFIDENCE_VERIFIED
    assert v.reproduced is True
    assert v.variant_reproduced is True


def test_rerun_reproduces_but_no_variant_returns_likely():
    original = _sig(score=0.7, classes=["sqli"])
    rerun = _sig(score=0.7, classes=["sqli"])
    v = verify_finding(original, lambda: rerun, variant_fn=None, wait_seconds=0)
    assert v.confidence == CONFIDENCE_LIKELY
    assert v.reproduced is True
    assert "no variant function supplied" in " ".join(v.notes)


def test_rerun_fails_to_reproduce_returns_suspected():
    """Original signal, but re-fire shows nothing — likely flake."""
    original = _sig(score=0.7, classes=["sqli"])
    rerun = _sig(score=0.0)
    v = verify_finding(original, lambda: rerun, lambda: original, wait_seconds=0)
    assert v.confidence == CONFIDENCE_SUSPECTED
    assert v.reproduced is False


def test_variant_disagrees_with_zero_signal_returns_dismissed():
    """Original + rerun matched, but variant got zero → original
    is likely a payload-specific FP."""
    original = _sig(score=0.7, classes=["sqli"])
    rerun = _sig(score=0.7, classes=["sqli"])
    variant = _sig(score=0.0)
    v = verify_finding(original, lambda: rerun, lambda: variant, wait_seconds=0)
    assert v.confidence == CONFIDENCE_DISMISSED


def test_variant_scored_but_different_class_returns_likely():
    """Variant scored, but triggered different vuln-class →
    likely (original reproduced, variant noise)."""
    original = _sig(score=0.7, classes=["sqli"])
    rerun = _sig(score=0.7, classes=["sqli"])
    variant = _sig(score=0.6, classes=["xxe"])  # different class
    v = verify_finding(original, lambda: rerun, lambda: variant, wait_seconds=0)
    assert v.confidence == CONFIDENCE_LIKELY


def test_status_class_signal_matching():
    """Signals without error-class evidence match on status-class
    change direction."""
    original = _sig(score=0.5, status_changed=True)
    original.status_delta = 200  # 200→400 say
    rerun = _sig(score=0.5, status_changed=True)
    rerun.status_delta = 200
    variant = _sig(score=0.5, status_changed=True)
    variant.status_delta = 200
    v = verify_finding(original, lambda: rerun, lambda: variant, wait_seconds=0)
    assert v.confidence == CONFIDENCE_VERIFIED


def test_time_based_signal_matching():
    """Both signals high time_ratio → match."""
    original = _sig(score=0.5, time_ratio=10)
    rerun = _sig(score=0.5, time_ratio=12)
    variant = _sig(score=0.5, time_ratio=8)
    v = verify_finding(original, lambda: rerun, lambda: variant, wait_seconds=0)
    assert v.confidence == CONFIDENCE_VERIFIED


def test_too_low_original_score_returns_suspected():
    """If original score too weak, verifier doesn't even bother."""
    original = _sig(score=0.2)
    v = verify_finding(original, lambda: _sig(score=0.9), wait_seconds=0)
    assert v.confidence == CONFIDENCE_SUSPECTED
    assert "below threshold" in " ".join(v.notes)


def test_rerun_raises_returns_suspected():
    """Exception in rerun callable falls through to suspected."""
    original = _sig(score=0.7, classes=["sqli"])
    def _boom():
        raise RuntimeError("transient")
    v = verify_finding(original, _boom, wait_seconds=0)
    assert v.confidence == CONFIDENCE_SUSPECTED
    assert any("rerun raised" in n for n in v.notes)


def test_variant_raises_falls_back_to_likely():
    """Variant raising shouldn't downgrade — original already
    reproduced."""
    original = _sig(score=0.7, classes=["sqli"])
    rerun = _sig(score=0.7, classes=["sqli"])
    def _boom():
        raise RuntimeError("transient")
    v = verify_finding(original, lambda: rerun, _boom, wait_seconds=0)
    assert v.confidence == CONFIDENCE_LIKELY


def test_to_dict_json_serializable():
    import json
    v = verify_finding(
        _sig(score=0.7, classes=["sqli"]),
        lambda: _sig(score=0.7, classes=["sqli"]),
        wait_seconds=0,
    )
    json.dumps(v.to_dict())
