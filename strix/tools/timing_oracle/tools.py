"""LLM-facing timing-oracle specialist (`scan_timing_oracle`).

For each (control, suspect) payload pair, collects N timing
samples per side, runs a statistical comparison, surfaces a
finding when the suspect distribution is statistically distinct
from the control.

Use cases:
  * **Blind SQLi**: control = `id=1`, suspect = `id=1' AND SLEEP(2) --`
    → suspect should add ~2s p50 if injectable
  * **Padding oracle**: control = valid ciphertext, suspect = malformed
    → BAD_PADDING path may be measurably slower
  * **TOCTOU**: control = light op, suspect = race-condition trigger

The caller supplies `payload_pairs` — list of dicts with `name`,
`control_send_fn`, `suspect_send_fn`. Each `_send_fn` is a
parameterless callable that issues the HTTP request and returns
a response dict.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)
from strix.tools.timing_oracle.statistics import (
    DEFAULT_SAMPLES_PER_PAYLOAD,
    TimingComparison,
    collect_timing_samples,
    compare_distributions,
)


logger = logging.getLogger(__name__)


def _emit_oracle_finding(
    *, name: str, comparison: TimingComparison, target: str,
) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        title = (
            f"Timing oracle: `{name}` "
            f"(median {comparison.median_a_ms:.0f}ms → "
            f"{comparison.median_b_ms:.0f}ms, "
            f"separation {comparison.median_separation:.2f}×)"
        )[:480]
        return tracer.add_vulnerability_report(
            title=title,
            severity="medium",     # timing alone is suggestive,
                                    # not confirmed exploitation
            cwe="CWE-208",          # Observable Timing Discrepancy
            endpoint=target,
            target=target,
            category="anomaly",
            cve=None,
            cvss=None,
            verification_status="pattern_match",
            confidence=0.75,
            description=(
                f"`scan_timing_oracle` ran a {comparison.n_a}+"
                f"{comparison.n_b}-sample comparison for the "
                f"`{name}` payload pair. The suspect payload's "
                f"latency distribution is statistically distinct "
                f"from the control:\n\n"
                f"{comparison.rationale}\n\n"
                f"This is a side-channel signal — the server "
                f"takes measurably longer on the suspect input. "
                f"For SQL: a SLEEP() injection. For crypto: a "
                f"padding-oracle decode-vs-validate split. For "
                f"auth: a username-known-vs-unknown timing leak."
            ),
            impact=(
                "A measurable timing oracle reveals state to an "
                "attacker who can issue many requests:\n"
                "  * Blind SQLi: extract DB content one bit at a "
                "time via SLEEP / pg_sleep / WAITFOR.\n"
                "  * Padding oracle: decrypt CBC-mode ciphertext "
                "one byte at a time.\n"
                "  * Auth-state leak: enumerate usernames / "
                "active sessions.\n"
                "  * TOCTOU: race-condition exploitation when the "
                "timing signal indicates a check-vs-use window.\n\n"
                "The timing signal is the oracle; the actual "
                "exploit primitive depends on the payload pair "
                "this finding wraps."
            ),
            technical_analysis=(
                f"Pair: {name}\n"
                f"Samples: {comparison.n_a} (control) vs "
                f"{comparison.n_b} (suspect)\n"
                f"Median A: {comparison.median_a_ms:.2f}ms\n"
                f"Median B: {comparison.median_b_ms:.2f}ms\n"
                f"Median separation (× pooled IQR): "
                f"{comparison.median_separation:.2f}\n"
                f"Rank-sum effect size: "
                f"{comparison.rank_sum_effect_size:.2f}\n"
                f"Distinct distributions: {comparison.distinct}\n"
            ),
            poc_description=(
                "1. Re-issue both payloads of the pair with the "
                "same auth context.\n"
                "2. Run the same 50+50 sample comparison "
                "manually to confirm the timing gap reproduces.\n"
                "3. If the gap is repeatable, the oracle is "
                "real — escalate to the matching exploit "
                "specialist (`scan_blind_cmd_injection` for SQL, "
                "etc.) for end-to-end exploitation."
            ),
            poc_script_code="",
            remediation_steps=(
                "1. For SQL/blind-injection oracles: parameterise "
                "queries (the static-payload version is what "
                "`scan_sqli` would suggest).\n"
                "2. For padding oracles: switch to AES-GCM or "
                "another AEAD that doesn't expose padding-failure "
                "timing.\n"
                "3. For auth-timing oracles: use constant-time "
                "comparison for credential checks; rate-limit "
                "the endpoint."
            ),
            cvss_breakdown=None,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("timing oracle emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="timing-oracle-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 600},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190"],
)
def scan_timing_oracle(
    *,
    target: str,
    payload_pairs: list[dict[str, Any]],
    n_samples: int = DEFAULT_SAMPLES_PER_PAYLOAD,
) -> SpecialistResult:
    """For each (control, suspect) payload pair, collect N timing
    samples each, run statistical comparison, emit findings on
    distinct distributions.

    Args:
        target: the URL / endpoint being probed (used for the
            finding's `target` + `endpoint` fields).
        payload_pairs: list of `{name, control_send_fn,
            suspect_send_fn}` dicts. Each `_send_fn` is a
            parameterless callable returning a response dict.
            The lead-agent typically constructs these from
            existing `send_request` invocations.
        n_samples: samples per payload (default 50). Tune up
            for noisy networks; tune down for cost-bounded runs.
    """
    if not isinstance(target, str) or not target.strip():
        return SpecialistResult(status="error", error="target required")
    target = target.strip()
    if not payload_pairs:
        return SpecialistResult(
            status="partial",
            error=(
                "no payload_pairs supplied — pass a list of "
                "`{name, control_send_fn, suspect_send_fn}` "
                "dicts. The lead-agent constructs these by "
                "wrapping existing `send_request` calls."
            ),
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0
    comparisons: list[TimingComparison] = []

    for pair in payload_pairs:
        if not isinstance(pair, dict):
            continue
        name = pair.get("name") or "(unnamed)"
        control_fn = pair.get("control_send_fn")
        suspect_fn = pair.get("suspect_send_fn")
        if not callable(control_fn) or not callable(suspect_fn):
            evidence.append(
                f"timing_oracle: skipped pair `{name}` — missing "
                f"control_send_fn or suspect_send_fn"
            )
            continue

        try:
            control_samples = collect_timing_samples(
                send_fn=control_fn, n_samples=n_samples,
            )
            suspect_samples = collect_timing_samples(
                send_fn=suspect_fn, n_samples=n_samples,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "timing_oracle: pair `%s` collection raised: %s",
                name, e,
            )
            continue

        comparison = compare_distributions(control_samples, suspect_samples)
        comparisons.append(comparison)

        if not comparison.distinct:
            evidence.append(
                f"timing_oracle: `{name}` — NOT distinct "
                f"({comparison.median_a_ms:.0f}ms vs "
                f"{comparison.median_b_ms:.0f}ms)"
            )
            continue

        rid = _emit_oracle_finding(
            name=name, comparison=comparison, target=target,
        )
        if rid:
            emitted_count += 1
        drafts.append(FindingDraft(
            title=(
                f"Timing oracle: `{name}` median "
                f"{comparison.median_a_ms:.0f}ms → "
                f"{comparison.median_b_ms:.0f}ms"
            )[:480],
            severity="medium",
            cwe="CWE-208",
            endpoint=target,
            category="anomaly",
            verification_status="pattern_match",
            confidence=0.75,
            description=comparison.rationale[:480],
        ))
        evidence.append(
            f"timing_oracle: `{name}` DISTINCT "
            f"({comparison.median_a_ms:.0f}ms vs "
            f"{comparison.median_b_ms:.0f}ms; "
            f"sep {comparison.median_separation:.2f}×)"
        )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "for `distinct` timing oracles, follow up with "
                "`scan_blind_cmd_injection` / `scan_sqli` (or "
                "the matching specialist for the payload class) "
                "to confirm end-to-end exploitation",
                "if the median separation was borderline, "
                "re-run with n_samples=100+ to tighten the "
                "statistical confidence",
            ]
            if drafts else
            [
                "no distinct timing oracles detected. If you "
                "expected one, network jitter may be drowning "
                "the signal — try running closer to the target "
                "(same AZ) or bump n_samples."
            ]
        ),
        tool_metadata={
            "target": target,
            "pairs_analysed": len(comparisons),
            "distinct_count": sum(1 for c in comparisons if c.distinct),
            "n_samples_per_payload": n_samples,
            "findings_emitted_to_tracer": emitted_count,
        },
    )
