"""iter-32.4 — post-emission verifier.

Closes the verification gap exposed by the v3 L2 Juice Shop standard
run where the L2 Lead emitted two `cache_deception` findings with
`verification_status=pattern_match` (LLM judgment alone, no
deterministic re-fire). Only the SQLi finding (which flowed through
the iter-29 dispatcher → fire_and_diff path) got tagged `verified`.

This module provides a generic post-emission hook: when a finding
lands with a low-confidence status, attempt to upgrade it by
re-firing a representative attack payload against its endpoint via
iter-29.2's `fire_and_diff` (now with iter-30.5's benign-shape
baseline). If the signal score crosses the verification threshold,
the finding's `verification_status` is upgraded to `verified`.

Strategy
--------
1. Look at finding's `category` + `endpoint` + `method` + `params`.
2. Classify the endpoint shape via iter-29.1 `EndpointClassifier`.
3. Look up a representative payload for (shape, category) via
   iter-29.3 `payload_bins.bin_for`.
4. Run `fire_and_diff` with the payload + iter-30.5 benign control.
5. If signal score >= threshold, upgrade
   `report["verification_status"] = "verified"` and append a
   reasoning_trace line so the upgrade is auditable.

Opt-in
------
Off by default. Enable via env `STRIX_L15_POST_EMIT_VERIFY=1`.
Reason: each invocation makes 2 HTTP probes (control + attack).
On agent-driven scans with many findings, this adds wall-clock
cost. Bench harnesses enable it explicitly; production scans
choose their own tradeoff.

Anti-overfit
------------
- Payload selection routes through payload_bins (iter-29.3) — no
  SUT-specific values
- Endpoint classifier (iter-29.1) determines shape — same generic
  taxonomy used by the dispatcher
- Source-grep guard test forbids SUT identifiers
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


# Verification threshold (same default as the dispatcher's _VERIFY_THRESHOLD)
_VERIFY_THRESHOLD = 0.4

# Statuses considered "low confidence" → eligible for upgrade.
_UPGRADEABLE_STATUSES = frozenset({
    "pattern_match", "inconclusive", "suspected", "likely",
})

# Categories the post-emit verifier knows how to probe. Maps a finding
# `category` (tracer's canonical underscore-snake names) to the
# payload_bins `vuln_class` key (which uses hyphens for the
# multi-word classes). Categories without a mapping are skipped
# (their findings stay at original status). Source-of-truth for the
# valid vuln_class values is `payload_bins.list_available_combinations`.
_CATEGORY_TO_VULN_CLASS = {
    "sqli": "sqli",
    "xss": "xss",
    "ssrf": "ssrf",
    "xxe": "xxe",
    "path_traversal": "path-traversal",
    "cmd_injection": "cmd-injection",
}


def is_enabled() -> bool:
    """True when `STRIX_L15_POST_EMIT_VERIFY=1` (or `true`/`yes`/`on`)."""
    return os.environ.get(
        "STRIX_L15_POST_EMIT_VERIFY", "",
    ).strip().lower() in ("1", "true", "yes", "on")


def _classify_endpoint_shape(endpoint: str, method: str) -> tuple[str | None, list[str]]:
    """Best-effort shape + params lookup via iter-29.1 EndpointClassifier.

    Returns (shape, params). When the classifier can't profile the
    endpoint (offline / network error), returns (None, []) — caller
    falls back to a no-shape diff (iter-29.2 default).
    """
    try:
        from strix.l15.endpoint_classifier import classify_endpoint
        profile = classify_endpoint(endpoint, methods=[method] if method else None)
        return profile.shape, list(profile.params or [])
    except Exception as e:  # noqa: BLE001
        logger.debug("post-emit verifier: classifier failed: %s", e)
        return None, []


def _pick_attack_payload(shape: str | None, vuln_class: str) -> str | None:
    """First payload from the (shape, vuln_class) bin. Returns None
    when no payload matches.
    """
    if not shape:
        return None
    try:
        from strix.l15.payload_bins import bin_for
        payloads = bin_for(shape, vuln_class)
        if payloads:
            return payloads[0]
    except Exception as e:  # noqa: BLE001
        logger.debug("post-emit verifier: payload_bins lookup failed: %s", e)
    return None


def _build_attack_kwargs(shape: str, method: str, params: list[str], payload: str) -> dict[str, Any]:
    """Same shape rules as the dispatcher uses (see
    `shape_aware_dispatcher._build_attack_kwargs_for_shape`).
    Duplicated here as a thin local copy so this module doesn't
    import from the dispatcher (which has heavier deps).
    """
    m = (method or "GET").upper()
    if shape == "json":
        if m in ("POST", "PUT", "PATCH"):
            return {"json": {p: payload for p in (params or ["q"])}}
        return {}
    if shape in ("form", "multipart"):
        if m in ("POST", "PUT", "PATCH"):
            return {"data": {p: payload for p in (params or ["q"])}}
        return {}
    if shape == "graphql":
        return {"json": {
            "query": "query Q($id: String) { node(id: $id) { id } }",
            "variables": {"id": payload},
        }}
    if shape == "xml":
        return {"data": payload}
    return {"data": {"q": payload}}


def _build_attack_url(base_url: str, method: str, params: list[str], payload: str) -> str:
    """For GET requests, append payload as a query string param so the
    server actually receives the attack."""
    m = (method or "GET").upper()
    if m != "GET":
        return base_url
    if not params:
        return base_url
    from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
    parts = urlparse(base_url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[params[0]] = payload
    new_qs = urlencode(qs)
    return urlunparse(parts._replace(query=new_qs))


def try_post_emit_verify(report: dict[str, Any]) -> bool:
    """Attempt to upgrade `report["verification_status"]` via fire_and_diff.

    Returns True when the report was upgraded; False otherwise. Mutates
    `report` in place when True. Never raises.
    """
    try:
        # Gate 1: only operate on low-confidence statuses.
        vs = (report.get("verification_status") or "").strip().lower()
        if vs not in _UPGRADEABLE_STATUSES:
            return False

        # Gate 2: must have an endpoint we can probe.
        endpoint = report.get("endpoint") or report.get("target") or ""
        if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
            return False

        # Gate 3: category must be in the verifiable set.
        category = (report.get("category") or "").strip().lower()
        vuln_class = _CATEGORY_TO_VULN_CLASS.get(category)
        if not vuln_class:
            return False

        # Classify endpoint + pick payload
        method = (report.get("method") or "GET").upper()
        shape, params = _classify_endpoint_shape(endpoint, method)
        payload = _pick_attack_payload(shape, vuln_class)
        if not payload:
            return False

        # Build attack kwargs + URL (matches dispatcher conventions)
        attack_kwargs = _build_attack_kwargs(shape, method, params, payload)
        attack_url = _build_attack_url(endpoint, method, params, payload)

        # Fire-and-diff with iter-30.5 benign control
        from strix.l15.baseline_diff import fire_and_diff, score_signal
        signal = fire_and_diff(
            url=attack_url, method=method,
            attack_payload=attack_kwargs,
            shape=shape, params=params,  # iter-30.5
        )
        # `signal` is a DiffSignal. Score it via score_signal helper
        # (consistent with how the dispatcher uses thresholds).
        try:
            score = score_signal(signal)
        except Exception:  # noqa: BLE001
            score = float(getattr(signal, "score", 0.0) or 0.0)

        if score < _VERIFY_THRESHOLD:
            return False

        # Upgrade
        report["verification_status"] = "verified"
        # Auditable trail: append a reasoning_trace line.
        trace = report.get("reasoning_trace") or []
        if isinstance(trace, str):
            trace = [trace]
        trace_line = (
            f"l1.5 (post-emit-verify iter-32.4): re-fired {category} payload "
            f"via fire_and_diff; signal_score={score:.2f} ≥ {_VERIFY_THRESHOLD} "
            f"→ promoted pattern_match → verified"
        )
        if isinstance(trace, list):
            report["reasoning_trace"] = list(trace) + [trace_line]
        return True
    except Exception as e:  # noqa: BLE001
        logger.debug("post-emit verifier failed: %s", e)
        return False


__all__ = [
    "is_enabled",
    "try_post_emit_verify",
]
