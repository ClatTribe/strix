"""iter-25.6 — hygiene prior (Gap 4 in docs/L2-optimization.md).

Engineers notice **absences** as much as presences:

  * `Server: Werkzeug/2.2.3` in production → dev server → assume
    everything else is also lax.
  * No CSP + no X-Frame-Options + no HSTS → vibe-coded or
    framework-defaulted; go look at auth harder.
  * Login endpoint exists + no rate-limit → password-reset OTP
    almost certainly also unlimited; probe it specifically.

Each absence is a separate low-severity finding today. This module
aggregates them into a single ``HygieneScore`` (0.0 = sloppy, 1.0 =
locked-down) that influences subsequent scan depth.

The score is a population statistic — not per-finding. It's computed
once per scan from the accumulated finding evidence and then read by
Wave 4's `dispatch_specialist` to scale per-specialist depth budgets:

  * `hygiene < 0.3` → `depth_multiplier = 2.0` (look harder)
  * `hygiene > 0.7` → `depth_multiplier = 0.6` (this place is tidy)
  * else            → `depth_multiplier = 1.0`

Inputs to the score (all signals already emitted by L1):

  * Security headers (CSP / HSTS / X-Frame / X-Content-Type) presence
  * Dev-server banners in `Server:` (Werkzeug / Express dev /
    webpack-dev-server / Flask dev)
  * Dependency staleness (mean age of vulnerable deps surfaced by SCA)
  * Secret hygiene (gitleaks finding density per 1000 lines of code)
  * Error-handling hygiene (stack traces visible in any 500 response)

A finding's `description` / `title` / `category` are scanned for the
above signals. We do NOT mutate findings; we just maintain a
process-local `HygieneLedger` that the orchestrator queries.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any


logger = logging.getLogger(__name__)


# ---- patterns ---------------------------------------------------------------

_DEV_BANNER_RE = re.compile(
    r"""(?ix)
    (?:^|[\s/=])
    (
        werkzeug
      | flask[-_]dev
      | webpack[-_]dev[-_]server
      | django[-_]?dev
      | nodemon
      | express[-_]?dev
      | rails[-_]?dev
      | gunicorn\s*\(dev\)
      | rack\s*\(dev\)
    )
    \b
    """,
)

_MISSING_HEADER_HINTS = (
    "missing content-security-policy",
    "missing csp",
    "missing strict-transport-security",
    "missing hsts",
    "missing x-frame-options",
    "missing x-content-type-options",
    "missing referrer-policy",
    "missing permissions-policy",
)

_STACK_TRACE_HINTS = (
    "traceback (most recent call last)",
    "internal server error.*at .+\\.java:",  # java stack
    "at object.<anonymous>",                  # node stack
    "valueerror:", "keyerror:", "typeerror:",
)


@dataclass(frozen=True)
class HygieneScore:
    """Composite hygiene snapshot."""
    score: float                  # 0.0 (sloppy) - 1.0 (locked-down)
    depth_multiplier: float       # 2.0 / 1.0 / 0.6
    missing_headers: int = 0
    dev_banners: int = 0
    stack_traces: int = 0
    vulnerable_deps: int = 0
    secret_density_per_kloc: float = 0.0
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "depth_multiplier": round(self.depth_multiplier, 3),
            "missing_headers": self.missing_headers,
            "dev_banners": self.dev_banners,
            "stack_traces": self.stack_traces,
            "vulnerable_deps": self.vulnerable_deps,
            "secret_density_per_kloc": round(self.secret_density_per_kloc, 3),
            "rationale": self.rationale,
        }


def _classify_finding(text: str) -> tuple[bool, bool, bool]:
    """Return (is_missing_header, is_dev_banner, is_stack_trace)."""
    t = (text or "").lower()
    is_header = any(h in t for h in _MISSING_HEADER_HINTS)
    is_banner = bool(_DEV_BANNER_RE.search(t))
    is_stack = any(h in t for h in _STACK_TRACE_HINTS)
    return is_header, is_banner, is_stack


def _looks_like_dep_finding(finding: dict[str, Any]) -> bool:
    cat = (finding.get("category") or "").lower()
    if "sca" in cat or "dependency" in cat:
        return True
    title = (finding.get("title") or "").lower()
    return "vulnerable dependency" in title or "outdated" in title


def _looks_like_secret_finding(finding: dict[str, Any]) -> bool:
    cwe = (finding.get("cwe") or "").upper()
    if cwe in {"CWE-798", "CWE-200"}:
        return True
    cat = (finding.get("category") or "").lower()
    return "secret" in cat or "credential" in cat


class HygieneLedger:
    """Process-local accumulator. Populated at finding emission;
    queried at dispatch time."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.missing_headers: int = 0
        self.dev_banners: int = 0
        self.stack_traces: int = 0
        self.vulnerable_deps: int = 0
        self.secret_findings: int = 0
        # Approximate "size" of the codebase, in thousand-LOC. Set by
        # the scan runner from prepass output; defaults to 1 so the
        # secret-density division is well-defined even before we know.
        self.kloc: float = 1.0

    def clear(self) -> None:
        with self._lock:
            self.__init__()

    def set_kloc(self, kloc: float) -> None:
        with self._lock:
            self.kloc = max(0.001, float(kloc))

    def observe(self, finding: dict[str, Any]) -> None:
        """Add this finding's signals to the running counters."""
        try:
            # Combine the most-likely-to-carry-the-signal fields
            text = " ".join(
                str(finding.get(k) or "")
                for k in ("title", "description", "category", "rule_id")
            )
            is_hdr, is_banner, is_stack = _classify_finding(text)
            with self._lock:
                if is_hdr:
                    self.missing_headers += 1
                if is_banner:
                    self.dev_banners += 1
                if is_stack:
                    self.stack_traces += 1
                if _looks_like_dep_finding(finding):
                    self.vulnerable_deps += 1
                if _looks_like_secret_finding(finding):
                    self.secret_findings += 1
        except Exception as e:  # noqa: BLE001
            logger.debug("hygiene observe failed: %s", e)

    def compute(self) -> HygieneScore:
        """Materialize a snapshot."""
        with self._lock:
            mh = self.missing_headers
            db = self.dev_banners
            st = self.stack_traces
            vd = self.vulnerable_deps
            sf = self.secret_findings
            kloc = self.kloc

        # Penalty model — each signal class subtracts from a 1.0
        # base. Caps prevent any single class from collapsing the
        # whole score on its own.
        penalty = 0.0
        penalty += min(0.3, mh * 0.05)       # 6 missing headers → max
        penalty += min(0.25, db * 0.15)       # ≥ 2 dev banners → max
        penalty += min(0.15, st * 0.05)       # 3 stack traces → max
        penalty += min(0.20, vd * 0.02)       # 10 vulnerable deps → max
        secret_density = sf / max(0.001, kloc)
        penalty += min(0.20, secret_density * 0.02)  # 10/kloc → max

        score = max(0.0, min(1.0, 1.0 - penalty))

        if score < 0.30:
            dm = 2.0
            rationale = (
                f"hygiene poor ({score:.2f}) — bump depth ×2: "
                f"{mh} missing headers, {db} dev banners, "
                f"{st} stack traces, {vd} vuln deps, "
                f"{secret_density:.2f}/kloc secrets"
            )
        elif score > 0.70:
            dm = 0.6
            rationale = f"hygiene strong ({score:.2f}) — trim depth ×0.6"
        else:
            dm = 1.0
            rationale = f"hygiene neutral ({score:.2f}) — depth ×1.0"

        return HygieneScore(
            score=score,
            depth_multiplier=dm,
            missing_headers=mh,
            dev_banners=db,
            stack_traces=st,
            vulnerable_deps=vd,
            secret_density_per_kloc=secret_density,
            rationale=rationale,
        )


# Singleton.
hygiene_ledger = HygieneLedger()
