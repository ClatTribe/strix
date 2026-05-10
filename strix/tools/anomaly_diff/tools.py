"""LLM-facing anomaly-diff specialist (`scan_response_anomaly`).

Two operating modes:

1. **Single-probe diff**: caller passes one probe response + the
   endpoint key; we read the baseline from the JSONL store and
   diff. Returns one finding per anomaly class triggered.

2. **Corpus shape clustering**: caller passes a list of probe
   responses; we fingerprint each and surface outliers (Phase 9.6).
   Useful for mutation fuzzers that send 100 variations and want
   to find the 1 that diverged.

Cross-asset chain (per §4a):
  * Anomaly-diff finding on a request handler → cross-reference
    with SCA / SAST findings on the same endpoint to confirm root
    cause.
  * `error_string_present` (SQL error detected) → pivot to
    `scan_sqli` for end-to-end exploit confirmation.
  * `latency_outlier_3sigma` → pivot to `scan_timing_oracle`
    for blind injection confirmation (the timing signal is the
    same; the oracle adds statistical fit).
"""

from __future__ import annotations

import logging
from typing import Any

from strix.baselines.capture import EndpointBaseline
from strix.baselines.store import BaselineStore
from strix.tools.anomaly_diff.diff import (
    AnomalyVerdict,
    diff_against_baseline,
)
from strix.tools.anomaly_diff.shape_cluster import (
    ShapeOutlier,
    find_shape_outliers,
)
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


# Class → CWE → category mapping. Categories align with the
# DAST scoring map so cross-asset routing dispatches correctly.
_CLASS_TO_CWE_CATEGORY: dict[str, tuple[str | None, str]] = {
    "status_flip": (None, "anomaly"),
    "length_outlier": (None, "anomaly"),
    "latency_outlier_3sigma": (None, "anomaly"),
    "new_keys_in_json": ("CWE-200", "info_disclosure"),
    "error_string_present": ("CWE-209", "info_disclosure"),
    "header_set_change": (None, "anomaly"),
    "shape_outlier": (None, "anomaly"),
}


def _emit_anomaly_finding(
    *,
    endpoint: str,
    verdict: AnomalyVerdict,
    target: str,
) -> str | None:
    """Emit one finding per AnomalyVerdict via tracer."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return None
        primary_class = verdict.classes[0] if verdict.classes else "anomaly"
        cwe, category = _CLASS_TO_CWE_CATEGORY.get(
            primary_class, (None, "anomaly"),
        )
        title = (
            f"Anomaly @ {endpoint}: "
            f"{', '.join(verdict.classes)} "
            f"(severity {verdict.severity})"
        )[:480]
        return tracer.add_vulnerability_report(
            title=title,
            severity=verdict.severity,
            cwe=cwe,
            endpoint=endpoint,
            target=target,
            category=category,
            cve=None,
            cvss=None,
            verification_status="pattern_match",
            confidence=0.7,
            description=(
                f"`scan_response_anomaly` diffed a probe response "
                f"against the captured baseline for `{endpoint}`. "
                f"Detected anomaly classes: "
                f"{', '.join(verdict.classes)}.\n\n"
                + "\n".join(f"  * {r}" for r in verdict.rationale)
            ),
            impact=(
                "Anomaly-diff findings are behavioural signals — "
                "the response diverged from baseline in a way that "
                "a static-payload scan wouldn't catch. Concrete "
                "impact depends on the class:\n"
                "  * status_flip + error_string_present → strong "
                "signal of an exploitable backend error path. "
                "Pivot to scan_sqli / scan_cmd_injection / "
                "scan_path_traversal depending on the payload that "
                "triggered it.\n"
                "  * latency_outlier_3sigma → blind injection / "
                "TOCTOU candidate. Pivot to scan_timing_oracle for "
                "statistical confirmation.\n"
                "  * new_keys_in_json → schema drift; could be a "
                "leak (the new key contains data the response "
                "shouldn't expose) or just a minor backwards-"
                "incompatible change. Inspect the new key's value.\n"
                "  * length_outlier (huge response) → potential "
                "data exfil or full-table dump."
            ),
            technical_analysis=(
                f"Endpoint: {endpoint}\n"
                f"Anomaly classes: {', '.join(verdict.classes)}\n"
                f"Severity: {verdict.severity}\n"
                f"Rationale:\n"
                + "\n".join(f"  - {r}" for r in verdict.rationale)
                + "\n\nMetadata:\n"
                + "\n".join(f"  {k}: {v}" for k, v in verdict.metadata.items())
            ),
            poc_description=(
                "1. Re-issue the probe that produced this anomaly "
                "(same payload, same auth context).\n"
                "2. Compare against the baseline samples for "
                f"`{endpoint}` (read from "
                "`behavioural_baselines.jsonl`).\n"
                "3. If the divergence reproduces, follow up with "
                "the matching DAST specialist per the impact list "
                "above."
            ),
            poc_script_code="",
            remediation_steps=(
                "1. Identify the divergence — what changed in the "
                "response shape that the diff classes flagged?\n"
                "2. If a backend error leaked (error_string_present), "
                "wrap the upstream code path in a generic 500 "
                "handler that logs but doesn't expose stack details "
                "to the client.\n"
                "3. If schema drifted (new_keys_in_json), verify "
                "the new key doesn't expose private data. If it "
                "does, filter at the API boundary."
            ),
            cvss_breakdown=None,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("anomaly emit failed: %s", e, exc_info=True)
        return None


@register_specialist_tool(
    category="anomaly-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 30},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1499"],   # Endpoint Denial of Service / behavioural
)
def scan_response_anomaly(
    *,
    endpoint: str,
    probe_response: dict[str, Any] | None = None,
    probe_responses: list[dict[str, Any]] | None = None,
    baseline_path: str | None = None,
) -> SpecialistResult:
    """Diff a probe response (or a corpus of responses) against
    the captured baseline for `endpoint`.

    Args:
        endpoint: canonical key — `<METHOD> <URL>` — matching the
            key used at baseline-capture time.
        probe_response: single response dict
            (`{status, headers, body, latency_ms?}`). When set,
            runs the per-baseline diff path.
        probe_responses: list of response dicts. When set, runs
            both the per-baseline diff (against each response)
            AND the corpus shape-clustering pass; outliers and
            per-response anomalies both emit.
        baseline_path: optional JSONL store path for tests.
            Production reads from the default location.

    At least one of `probe_response` / `probe_responses` must
    be supplied; otherwise the tool returns a partial result
    with a usage hint.
    """
    if not isinstance(endpoint, str) or not endpoint.strip():
        return SpecialistResult(status="error", error="endpoint required")
    endpoint = endpoint.strip()

    if probe_response is None and not probe_responses:
        return SpecialistResult(
            status="partial",
            error=(
                "either probe_response or probe_responses must be "
                "supplied. Pass `probe_response` for a single-probe "
                "diff or `probe_responses` for corpus shape-"
                "clustering."
            ),
        )

    store = BaselineStore(path=baseline_path)
    baseline = store.read(endpoint)
    if baseline is None or baseline.samples == 0:
        return SpecialistResult(
            status="partial",
            error=(
                f"no baseline found for `{endpoint}`. Capture one "
                f"first via `capture_baseline()` (Phase 9.2). "
                f"Without a baseline the diff layer would false-"
                f"positive every probe."
            ),
            tool_metadata={"endpoint": endpoint, "baseline_found": False},
        )

    drafts: list[FindingDraft] = []
    evidence: list[str] = []
    emitted_count = 0

    # Single-probe diff path.
    responses_for_diff: list[dict] = []
    if probe_response is not None:
        responses_for_diff.append(probe_response)
    if probe_responses:
        responses_for_diff.extend(probe_responses)

    for i, resp in enumerate(responses_for_diff):
        verdict = diff_against_baseline(resp, baseline)
        if not verdict:
            continue
        rid = _emit_anomaly_finding(
            endpoint=endpoint, verdict=verdict, target=endpoint,
        )
        if rid:
            emitted_count += 1
        title = (
            f"Anomaly @ {endpoint}#{i}: "
            f"{', '.join(verdict.classes)}"
        )[:480]
        drafts.append(FindingDraft(
            title=title,
            severity=verdict.severity,
            cwe=_CLASS_TO_CWE_CATEGORY.get(
                verdict.classes[0], (None, "anomaly"))[0],
            endpoint=endpoint,
            category=_CLASS_TO_CWE_CATEGORY.get(
                verdict.classes[0], (None, "anomaly"))[1],
            verification_status="pattern_match",
            confidence=0.7,
            description=" ; ".join(verdict.rationale)[:480],
        ))
        evidence.append(
            f"anomaly: {endpoint}#{i} → "
            f"{','.join(verdict.classes)} ({verdict.severity})"
        )

    # Corpus shape-clustering pass (Phase 9.6).
    outliers: list[ShapeOutlier] = []
    if probe_responses and len(probe_responses) >= 5:
        outliers = find_shape_outliers(probe_responses)
        for outlier in outliers:
            evidence.append(
                f"shape_outlier: {endpoint}#{outlier.response_index} "
                f"unique fingerprint `{outlier.fingerprint}` "
                f"in corpus of {len(probe_responses)}"
            )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "for `error_string_present` anomalies, follow up "
                "with `scan_sqli` / `scan_cmd_injection` / "
                "`scan_path_traversal` (depending on the payload "
                "that triggered the error)",
                "for `latency_outlier_3sigma`, pivot to "
                "`scan_timing_oracle` for statistical confirmation "
                "of blind injection",
                "for `new_keys_in_json`, inspect the new key's "
                "value to confirm it doesn't expose private data",
            ]
            if drafts else
            [
                "no anomalies detected — probe response matches "
                "baseline within tolerance. If you suspect a bug "
                "the baseline missed, capture more samples (current "
                f"baseline has {baseline.samples}) and try again."
            ]
        ),
        tool_metadata={
            "endpoint": endpoint,
            "baseline_samples": baseline.samples,
            "responses_analysed": len(responses_for_diff),
            "anomaly_findings": len(drafts),
            "shape_outliers": len(outliers),
            "outlier_indices": [o.response_index for o in outliers],
            "findings_emitted_to_tracer": emitted_count,
        },
    )
