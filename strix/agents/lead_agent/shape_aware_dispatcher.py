"""iter-30 — Shape-aware dispatcher (phase 2.5 of anchor_prepass).

This is the missing wire-up that turns iter-29.1-9's library code
into actual recall on web/api targets.

**What it does, end-to-end per discovered URL or form:**

  1. Classify endpoint → `EndpointProfile` (iter-29.1) — get shape
     + class + waf + framework hints + auth_required + baseline metrics
  2. Skip if `endpoint_class == "static-asset"` (no payload value)
  3. Check destructive guard (iter-29.9) — refuse DELETE/PATCH/
     destructive-path unless `STRIX_DESTRUCTIVE_OK=1`
  4. Consult rate-limit governor (iter-29.9) — apply current cooldown
  5. For each plausible vuln class for the endpoint's class, pick
     the right payload bin (iter-29.3) honoring `waf_detected`
  6. For each payload, fire-and-diff against baseline (iter-29.2)
  7. If signal score ≥ 0.5, run PoC verifier (iter-29.5):
     re-fire + variant. Promote to `verified` or `likely`; demote
     suspected / dismissed
  8. Emit findings only at `verified` / `likely` confidence
  9. seed_auth's STRIX_AUTH_BEARER threads through automatically via
     iter-29.4's `list_auth_states()` synthesis (zero per-tool patching)

**Why this is generic:**

  * No SUT-specific paths, payloads, or expected responses
  * Class → vuln-class map is from OWASP testing guide vocabulary
  * Payload bins (29.3) carry their own provenance
  * Validation harness (28.2) gates merges across ≥3 fixtures

**Composition:** runs AFTER `_run_dependent_api_tools` in the prepass.
Idempotent — re-running on the same target is safe (rate-limit
governor smoothly throttles repeat probes).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.l15.baseline_diff import DiffSignal, fire_and_diff
from strix.l15.endpoint_classifier import EndpointProfile, classify_endpoint
from strix.l15.payload_bins import bin_for
from strix.l15.poc_verifier import (
    CONFIDENCE_LIKELY,
    CONFIDENCE_VERIFIED,
    PocVerification,
    verify_finding,
)
from strix.l15.safety_guards import check_destructive, get_governor


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Endpoint-class → plausible vuln-classes
# ---------------------------------------------------------------------------
#
# Generic mapping from OWASP testing guide / OWASP top-10 vocabulary.
# Each endpoint-class triggers exploration of attack-classes that are
# *plausible* for that endpoint pattern. NOT SUT-specific.

_CLASS_TO_VULN_CLASSES: dict[str, list[str]] = {
    "search":         ["sqli", "xss", "cmd-injection"],
    "upload":         ["path-traversal", "xxe", "ssrf"],
    "redirect":       ["ssrf"],   # open-redirect handled by existing scan_open_redirect
    "admin":          ["sqli", "xss", "cmd-injection"],
    "api-list":       ["sqli", "xss"],
    "api-detail":     ["sqli", "xss", "path-traversal"],
    "auth-login":     ["sqli"],
    "auth-register":  ["sqli", "xss"],
    "destructive":    [],          # never probed (refused by guard)
    "static-asset":   [],          # no value in payloading
    "generic":        ["sqli", "xss"],
}


# Per-endpoint payload cap — keeps total wall budget sane.
_PAYLOAD_CAP_PER_ENDPOINT = 6
# Per-endpoint vuln-class cap — at most N attack classes per endpoint.
_VULN_CLASS_CAP_PER_ENDPOINT = 3
# Score threshold to bother PoC-verifying
_VERIFY_THRESHOLD = 0.5
# Max endpoints processed per scan (avoid exploding wall time on huge SUTs)
_ENDPOINT_CAP_DEFAULT = 40


# Kill switch — operators / tests can opt out via env
def _disabled() -> bool:
    return os.environ.get("STRIX_SHAPE_DISPATCHER_DISABLED", "").lower() in (
        "1", "true", "yes",
    )


# ---------------------------------------------------------------------------
# DispatchResult — visible in bench output
# ---------------------------------------------------------------------------

@dataclass
class DispatchFinding:
    endpoint: str
    method: str
    vuln_class: str
    payload_excerpt: str
    confidence: str
    score: float
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DispatchSummary:
    endpoints_seen: int = 0
    endpoints_probed: int = 0
    endpoints_skipped_destructive: int = 0
    endpoints_skipped_static: int = 0
    payloads_fired: int = 0
    signals_above_threshold: int = 0
    findings: list[DispatchFinding] = field(default_factory=list)
    wall_time_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Variant payload selection (for PoC verifier)
# ---------------------------------------------------------------------------

def _pick_variant_payload(
    payloads: list[Any], original: Any,
) -> Any | None:
    """Pick a payload that is class-equivalent but textually different
    from `original`. Returns None if no alternative exists."""
    for p in payloads:
        if p != original and type(p) == type(original):
            return p
    # Fallback — any different payload
    for p in payloads:
        if p != original:
            return p
    return None


# ---------------------------------------------------------------------------
# Per-endpoint probe loop
# ---------------------------------------------------------------------------

def _build_attack_kwargs_for_shape(
    shape: str, method: str, params: list[str] | None,
    payload: Any,
) -> dict[str, Any]:
    """Build kwargs for requests.request() given the endpoint shape
    and a single payload. Returns kwargs suitable for passing to
    `fire_and_diff(..., attack_payload=...)`.
    """
    method = (method or "GET").upper()
    # JSON-shaped endpoints — payload goes into a JSON body if POST,
    # else query string.
    if shape == "json":
        if method in ("POST", "PUT", "PATCH"):
            if params and isinstance(payload, (str, int, float)):
                # Spread payload across all known param names
                return {"json": {p: payload for p in params}}
            if isinstance(payload, dict):
                # NoSQL-shape payload like {"$ne": None}
                return {"json": {(params or ["id"])[0]: payload}}
            return {"json": {(params or ["q"])[0]: payload}}
        # GET / HEAD — payload as query param
        return {}  # we'll URL-encode separately

    # Form-shaped — POST as form-encoded
    if shape in ("form", "multipart"):
        if method in ("POST", "PUT", "PATCH"):
            if params:
                return {"data": {p: payload for p in params}}
            return {"data": {"q": payload}}
        return {}

    # GraphQL — wrap in `variables`
    if shape == "graphql":
        return {"json": {
            "query": "query Q($id: String) { node(id: $id) { id } }",
            "variables": {"id": payload},
        }}

    # XML — payload IS the body
    if shape == "xml":
        return {"data": payload}

    # Unknown — best-effort form-encoded
    return {"data": {"q": payload}}


def _build_attack_url(
    base_url: str, shape: str, method: str, params: list[str] | None,
    payload: Any,
) -> str:
    """For GET-shaped requests on json/url-param/path endpoints, inject
    the payload into the URL. POSTs use _build_attack_kwargs_for_shape
    and return the URL unchanged."""
    if method.upper() not in ("GET", "HEAD"):
        return base_url
    # path-shaped — append payload to path. We use raw concat (not
    # urljoin) so `../../etc/passwd` style traversal payloads survive
    # urljoin's RFC-3986 normalization that would collapse the `../`s.
    if shape == "path":
        sep = "" if base_url.endswith("/") else "/"
        return base_url + sep + str(payload).lstrip("/")
    # URL-param shape — append/replace param
    if not isinstance(payload, str):
        # Non-string payloads can't ride in a query string cleanly
        return base_url
    if params:
        sep = "&" if "?" in base_url else "?"
        return base_url + sep + "&".join(
            f"{p}={payload}" for p in params
        )
    # Generic single-q param
    sep = "&" if "?" in base_url else "?"
    return base_url + sep + f"q={payload}"


def _summarize_payload(p: Any, n: int = 80) -> str:
    s = str(p) if not isinstance(p, str) else p
    return (s[:n] + "...") if len(s) > n else s


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def shape_aware_dispatch(
    base_url: str,
    *,
    forms: list[dict[str, Any]] | None = None,
    endpoints: list[dict[str, Any]] | None = None,
    timeout: int = 8,
    endpoint_cap: int = _ENDPOINT_CAP_DEFAULT,
) -> DispatchSummary:
    """Run the shape-aware probe loop against discovered surface.

    Args:
        base_url: the target's base URL.
        forms: list of forms surfaced by `crawl_with_katana` (iter-28.3).
            Each form: `{action, method, inputs: [{name, type}, ...]}`.
        endpoints: list of endpoints surfaced by `openapi_spec_ingest`
            or `crawl_with_katana`. Each: `{url, method, params}`.
        timeout: per-request timeout seconds.
        endpoint_cap: hard cap on # endpoints probed (wall budget).

    Returns:
        `DispatchSummary` with per-endpoint findings, score reasons,
        and aggregate stats.
    """
    summary = DispatchSummary()
    if _disabled():
        return summary
    if not base_url or not base_url.strip():
        return summary

    t_start = time.monotonic()

    # ----- Build candidate endpoint list -----
    candidates: list[dict[str, Any]] = []

    # From openapi / katana endpoints. Param normalization is critical:
    # openapi_spec_ingest emits `params=[{"name": "...", "in": "path",
    # "schema": {...}}, ...]` (OpenAPI parameter objects), while katana
    # emits `params=["id", "q"]` (bare name strings). The dispatcher
    # only needs the name strings — flatten the OpenAPI objects.
    for ep in endpoints or []:
        url = ep.get("url") or ep.get("endpoint") or ""
        if not url:
            continue
        if not url.startswith(("http://", "https://")):
            url = urljoin(base_url.rstrip("/") + "/", url.lstrip("/"))
        raw_params = ep.get("params") or []
        normalized_params: list[str] = []
        for p in raw_params:
            if isinstance(p, str):
                normalized_params.append(p)
            elif isinstance(p, dict):
                name = p.get("name")
                if isinstance(name, str) and name:
                    normalized_params.append(name)
        candidates.append({
            "url": url,
            "method": (ep.get("method") or "GET").upper(),
            "params": normalized_params,
            "_source": "endpoint",
        })

    # From discovered forms — derive a candidate per form action
    for f in forms or []:
        action = f.get("action") or "/"
        if not action.startswith(("http://", "https://")):
            action = urljoin(base_url.rstrip("/") + "/", action.lstrip("/"))
        params: list[str] = []
        for i in (f.get("inputs") or []):
            if not isinstance(i, dict):
                continue
            name = i.get("name")
            if not isinstance(name, str) or not name:
                continue
            if (i.get("type") or "").lower() == "hidden":
                continue
            params.append(name)
        candidates.append({
            "url": action,
            "method": (f.get("method") or "POST").upper(),
            "params": params,
            "_source": "form",
        })

    # Dedup by (url, method)
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for c in candidates:
        key = (c["url"], c["method"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)

    # Cap at endpoint_cap to bound wall time
    deduped = deduped[:endpoint_cap]
    summary.endpoints_seen = len(deduped)

    governor = get_governor()

    # ----- Per-endpoint probe loop -----
    for ep in deduped:
        url = ep["url"]
        method = ep["method"]
        params = ep["params"]

        # Classify (uses pre-cached response when re-running; here we
        # let the classifier probe fresh — it's a single HEAD-like GET)
        try:
            profile = classify_endpoint(
                url, methods=[method], probe_if_no_response=True,
                timeout=timeout,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("classify failed for %s: %s", url, e)
            continue

        # Skip static assets — no value in payloading
        if profile.endpoint_class == "static-asset":
            summary.endpoints_skipped_static += 1
            continue

        # Skip destructive endpoints unless explicit opt-in
        ok, why = check_destructive(url, method, profile.endpoint_class)
        if not ok:
            summary.endpoints_skipped_destructive += 1
            logger.info("skipping %s %s: %s", method, url, why)
            continue

        host = urlparse(url).netloc or ""
        # Honor rate-limit governor
        governor.before_request(host)

        # Pick vuln classes for this endpoint class
        vuln_classes = _CLASS_TO_VULN_CLASSES.get(
            profile.endpoint_class, _CLASS_TO_VULN_CLASSES["generic"],
        )[:_VULN_CLASS_CAP_PER_ENDPOINT]

        if not vuln_classes:
            continue

        summary.endpoints_probed += 1

        for vuln_class in vuln_classes:
            payloads = bin_for(
                profile.shape, vuln_class, waf=profile.waf_detected,
            )[:_PAYLOAD_CAP_PER_ENDPOINT]
            if not payloads:
                continue

            for payload in payloads:
                summary.payloads_fired += 1

                # Build attack url + kwargs
                attack_url = _build_attack_url(
                    url, profile.shape, method, params, payload,
                )
                attack_kwargs = _build_attack_kwargs_for_shape(
                    profile.shape, method, params, payload,
                )

                # Fire-and-diff (29.2)
                try:
                    signal = fire_and_diff(
                        url=attack_url, method=method,
                        attack_payload=attack_kwargs,
                        timeout=timeout,
                    )
                except Exception as e:  # noqa: BLE001
                    logger.debug("fire_and_diff failed: %s", e)
                    continue

                # Update rate-limit governor with the response status
                # we observed (fire_and_diff captures it internally;
                # we recover from the diff's status_delta)
                # Note: we approximate — governor needs status; we record
                # a 200 by default (no rate-limit info from diff alone)
                governor.record_response(host, status=200)

                if signal.score < _VERIFY_THRESHOLD:
                    continue

                summary.signals_above_threshold += 1

                # ----- PoC verification (29.5) -----
                # Re-fire original + variant (or just original if no
                # alternative payload).
                variant = _pick_variant_payload(payloads, payload)

                def _rerun(_u=attack_url, _m=method, _k=attack_kwargs) -> DiffSignal:
                    return fire_and_diff(
                        url=_u, method=_m, attack_payload=_k, timeout=timeout,
                    )

                variant_fn = None
                if variant is not None:
                    v_url = _build_attack_url(
                        url, profile.shape, method, params, variant,
                    )
                    v_kwargs = _build_attack_kwargs_for_shape(
                        profile.shape, method, params, variant,
                    )

                    def _variant_fn(_u=v_url, _m=method, _k=v_kwargs) -> DiffSignal:
                        return fire_and_diff(
                            url=_u, method=_m, attack_payload=_k,
                            timeout=timeout,
                        )

                    variant_fn = _variant_fn

                verification = verify_finding(
                    signal, _rerun, variant_fn=variant_fn,
                    wait_seconds=1.0,  # short wait in batch context
                )

                if verification.confidence not in (
                    CONFIDENCE_VERIFIED, CONFIDENCE_LIKELY,
                ):
                    continue

                # ----- Emit finding -----
                finding = DispatchFinding(
                    endpoint=url,
                    method=method,
                    vuln_class=vuln_class,
                    payload_excerpt=_summarize_payload(payload),
                    confidence=verification.confidence,
                    score=signal.score,
                    reasons=signal.reasons,
                )
                summary.findings.append(finding)
                # Emit to the tracer so downstream L2 + reporting picks it up
                _emit_to_tracer(finding, profile=profile)

                # Don't keep firing payloads of the same vuln class
                # once we have a verified finding — diminishing returns
                if verification.confidence == CONFIDENCE_VERIFIED:
                    break

    summary.wall_time_s = round(time.monotonic() - t_start, 2)
    return summary


def _emit_to_tracer(
    finding: DispatchFinding, *,
    profile: EndpointProfile,
) -> None:
    """Best-effort: emit the dispatch finding via the tracer so the
    rest of the strix machinery (L1.5 enrichment, L2 ranking, report)
    surfaces it. Falls through silently when tracer isn't initialized
    (tests / standalone)."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return
        # Map vuln_class to CWE coarsely — purely for downstream
        # categorization. Specialists with deeper context can override.
        cwe_map = {
            "sqli":           "CWE-89",
            "xss":            "CWE-79",
            "ssrf":           "CWE-918",
            "xxe":            "CWE-611",
            "path-traversal": "CWE-22",
            "cmd-injection":  "CWE-78",
            "code-exec":      "CWE-94",
        }
        cwe = cwe_map.get(finding.vuln_class)
        tracer.add_vulnerability_report(
            target=finding.endpoint,
            category=finding.vuln_class,
            cwe=cwe,
            severity="high" if finding.confidence == CONFIDENCE_VERIFIED else "medium",
            title=(
                f"shape-aware dispatcher: {finding.vuln_class} "
                f"on {finding.method} {finding.endpoint}"
            ),
            description=(
                f"Payload `{finding.payload_excerpt}` triggered a "
                f"`{finding.vuln_class}` signal (score={finding.score:.2f}, "
                f"confidence={finding.confidence}). Reasons: "
                + "; ".join(finding.reasons or ["unspecified"])
            ),
            evidence={
                "payload_excerpt": finding.payload_excerpt,
                "endpoint_shape": profile.shape,
                "endpoint_class": profile.endpoint_class,
                "waf_detected": profile.waf_detected,
                "framework_hints": profile.framework_hints,
                "diff_score": finding.score,
                "diff_reasons": finding.reasons,
            },
            verification_status=(
                "exploited" if finding.confidence == CONFIDENCE_VERIFIED else "pattern_match"
            ),
            confidence=(
                0.9 if finding.confidence == CONFIDENCE_VERIFIED else 0.7
            ),
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("emit_to_tracer failed: %s", e)


__all__ = [
    "DispatchFinding",
    "DispatchSummary",
    "shape_aware_dispatch",
]
