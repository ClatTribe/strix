"""iter-29.5 — PoC validator (suspicion → evidence promotion).

A real bug hunter never reports "the response had `SQL` in it once."
They re-fire the exploit + a variant. If both trigger, it's a real
finding. If only one trips, it's a flake (Set-Cookie randomness,
caching, transient state) — they discard.

This module gives specialists that same discipline:

  * After a payload triggers a `DiffSignal` worth reporting (score
    ≥ 0.5), the specialist calls `verify_finding(...)`
  * The verifier re-fires the original payload after a brief delay
  * Then fires a CLASS-EQUIVALENT variant (different payload, same
    vuln class)
  * Both must reproduce same signal class → `confidence=verified`
  * Only original re-fire matches → `confidence=likely`
  * Neither reproduces → `confidence=suspected` (or dismissed)

**Composes with iter-29.1 (EndpointProfile) + iter-29.2 (DiffSignal)
+ iter-29.3 (payload bins).** This is the verification layer that
sits between "specialist found a signal" and "L2 sees a finding."

Pure-python, no docker tools.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from strix.l15.baseline_diff import DiffSignal


logger = logging.getLogger(__name__)


# Confidence tiers (matches the L1.5 finding.confidence vocab)
CONFIDENCE_VERIFIED = "verified"      # original re-fired + variant fired
CONFIDENCE_LIKELY = "likely"          # original re-fired only
CONFIDENCE_SUSPECTED = "suspected"    # original did not reproduce (FP risk)
CONFIDENCE_DISMISSED = "dismissed"    # variant disagrees → likely false positive

_VERIFY_DEFAULT_WAIT_S = 2.0          # tame transient state between fires
_VERIFY_MIN_SCORE = 0.4               # variant must show this to count
_VERIFY_CLASS_MATCH_REQUIRED = True   # same new_error_classes intersection


@dataclass
class PocVerification:
    """Result of a PoC verification cycle."""
    confidence: str                              # verified / likely / suspected / dismissed
    original_score: float                        # score from the initial signal
    rerun_score: float = 0.0
    variant_score: float = 0.0
    reproduced: bool = False                     # original re-fire matched class
    variant_reproduced: bool = False             # variant fire matched class
    elapsed_s: float = 0.0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _signal_class_match(a: DiffSignal, b: DiffSignal) -> bool:
    """Two signals match when their new_error_classes intersect OR
    both are status-class-change with same direction. For diff
    signals that lack error-class evidence (time-based, body-size),
    we fall back to a score-similarity check."""
    if a.new_error_classes and b.new_error_classes:
        return bool(set(a.new_error_classes) & set(b.new_error_classes))
    if a.status_class_changed and b.status_class_changed:
        # Same direction: both went up or both went down
        return (a.status_delta > 0) == (b.status_delta > 0)
    # Time-based: both have high time_ratio
    if a.time_ratio >= 3 and b.time_ratio >= 3:
        return True
    # Redirect target change in both
    if a.redirect_target_changed and b.redirect_target_changed:
        return True
    return False


def verify_finding(
    original_signal: DiffSignal,
    rerun_fn: Callable[[], DiffSignal],
    variant_fn: Callable[[], DiffSignal] | None = None,
    *,
    wait_seconds: float = _VERIFY_DEFAULT_WAIT_S,
    min_variant_score: float = _VERIFY_MIN_SCORE,
) -> PocVerification:
    """Promote a `suspected` finding to `verified` / `likely` / `dismissed`.

    Args:
        original_signal: the initial DiffSignal that triggered the
            specialist to consider a finding.
        rerun_fn: zero-arg callable that re-fires the EXACT original
            payload after a brief wait, returns a fresh DiffSignal.
        variant_fn: optional zero-arg callable that fires a DIFFERENT
            payload of the same vuln-class. When omitted, max
            confidence reachable is `likely` (re-fire only).
        wait_seconds: delay between original-fire and re-fire (tames
            transient state).
        min_variant_score: variant_signal.score must reach this
            threshold to count as "variant reproduced."

    Returns:
        `PocVerification` with the verdict.
    """
    t0 = time.monotonic()
    notes: list[str] = []

    if original_signal.score < min_variant_score:
        # Too weak even to verify — caller shouldn't have called us
        return PocVerification(
            confidence=CONFIDENCE_SUSPECTED,
            original_score=original_signal.score,
            elapsed_s=0.0,
            notes=[f"original signal score {original_signal.score} below threshold"],
        )

    # Brief wait to let any transient state settle
    if wait_seconds > 0:
        time.sleep(wait_seconds)

    # ----- Re-fire original -----
    try:
        rerun_signal = rerun_fn()
    except Exception as e:  # noqa: BLE001
        notes.append(f"rerun raised: {type(e).__name__}: {e}")
        return PocVerification(
            confidence=CONFIDENCE_SUSPECTED,
            original_score=original_signal.score,
            elapsed_s=round(time.monotonic() - t0, 2),
            notes=notes,
        )

    reproduced = _signal_class_match(original_signal, rerun_signal)
    if not reproduced:
        # Original didn't reproduce → likely FP / flake
        notes.append("original payload re-fire did not reproduce")
        return PocVerification(
            confidence=CONFIDENCE_SUSPECTED,
            original_score=original_signal.score,
            rerun_score=rerun_signal.score,
            reproduced=False,
            elapsed_s=round(time.monotonic() - t0, 2),
            notes=notes,
        )

    # ----- Variant fire (optional) -----
    if variant_fn is None:
        # No variant supplied — best we can do is `likely`
        return PocVerification(
            confidence=CONFIDENCE_LIKELY,
            original_score=original_signal.score,
            rerun_score=rerun_signal.score,
            reproduced=True,
            elapsed_s=round(time.monotonic() - t0, 2),
            notes=notes + ["no variant function supplied — capped at `likely`"],
        )

    try:
        variant_signal = variant_fn()
    except Exception as e:  # noqa: BLE001
        notes.append(f"variant raised: {type(e).__name__}: {e}")
        return PocVerification(
            confidence=CONFIDENCE_LIKELY,
            original_score=original_signal.score,
            rerun_score=rerun_signal.score,
            reproduced=True,
            elapsed_s=round(time.monotonic() - t0, 2),
            notes=notes,
        )

    variant_reproduced = (
        variant_signal.score >= min_variant_score
        and _signal_class_match(original_signal, variant_signal)
    )

    if variant_reproduced:
        return PocVerification(
            confidence=CONFIDENCE_VERIFIED,
            original_score=original_signal.score,
            rerun_score=rerun_signal.score,
            variant_score=variant_signal.score,
            reproduced=True,
            variant_reproduced=True,
            elapsed_s=round(time.monotonic() - t0, 2),
            notes=notes,
        )

    # Variant disagreed — could be FP triggered by something
    # idiosyncratic to the original payload
    if variant_signal.score == 0.0:
        notes.append("variant produced no signal — original may be FP")
        return PocVerification(
            confidence=CONFIDENCE_DISMISSED,
            original_score=original_signal.score,
            rerun_score=rerun_signal.score,
            variant_score=variant_signal.score,
            reproduced=True,
            variant_reproduced=False,
            elapsed_s=round(time.monotonic() - t0, 2),
            notes=notes,
        )

    return PocVerification(
        confidence=CONFIDENCE_LIKELY,
        original_score=original_signal.score,
        rerun_score=rerun_signal.score,
        variant_score=variant_signal.score,
        reproduced=True,
        variant_reproduced=False,
        elapsed_s=round(time.monotonic() - t0, 2),
        notes=notes + ["variant scored but different signal class"],
    )


__all__ = [
    "PocVerification",
    "verify_finding",
    "CONFIDENCE_VERIFIED",
    "CONFIDENCE_LIKELY",
    "CONFIDENCE_SUSPECTED",
    "CONFIDENCE_DISMISSED",
]
