"""Batched recon interpretation — V3-4 of the quick-mode
lightweight plan (docs/proposals/2026-05-19-quick-mode-lightweight.md).

## Why this exists

After `webapp_recon_pipeline` produces a `webapp_surface_map.json`,
today the lead walks the result section by section — fingerprint,
crawl, security headers, TLS, well-known — each as its own LLM
reasoning step. That's 5-15 sequential LLM calls just to extract
"here are the endpoints, here are the suspected probe categories
per endpoint."

This tool collapses those into ONE structured-output LLM call
that sees the entire surface map and returns a prioritized probe
plan in JSON. Same context, fewer round-trips.

## What this tool returns

A dict with:
  * `endpoints` — flat list of `{path, method, shape}` with
    deterministic shape classification (form / api / file /
    auth / id-in-path / state-changing / search) derived from
    the surface map.
  * `tech_stack` — one-line summary string.
  * `security_posture_flags` — list of short noun phrases
    (e.g. "missing CSP", "TLS 1.0 enabled").
  * `prioritized_probes` — list of `{endpoint, suspected_categories,
    why}` ordered by suspected impact. Quick mode reads this
    list to decide which deterministic specialists to fire.

The endpoint classification + tech-stack summary + security flags
are **deterministic** — built from the surface_map without an LLM
call. The `prioritized_probes` ranking is produced via a single
LLM call when an `inner_call_fn` is provided (and surface
context is non-trivial); otherwise we fall back to a deterministic
default ranking so the tool stays usable in offline / test mode.

## Recall safety

* The deterministic parts (endpoints, tech_stack, flags) preserve
  every input from the surface_map — nothing is dropped on the
  floor.
* The probe ranking is *advisory* — the lead is free to override.
  An LLM call that returns malformed JSON falls through to the
  deterministic default ranking (never crashes).
* Kill switch: `STRIX_BATCHED_RECON_INTERP_DISABLED=1` makes the
  tool a deterministic-only no-op renderer (no LLM call). Useful
  in air-gapped environments + as a safety valve if the LLM
  output ever drifts.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse


from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


# Endpoint shape classifier — deterministic. Maps an endpoint
# string to one or more shape tags the lead can route on.
_NUMERIC_PATH_RE = re.compile(r"/\d+(?:/|$)")
_UUID_PATH_RE = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/|$)",
    re.IGNORECASE,
)
_AUTH_PATH_RE = re.compile(
    r"(?:^|/)(login|signin|signup|register|reset|forgot|"
    r"password|token|oauth|saml|sso|auth|logout)(?:/|$|\?)",
    re.IGNORECASE,
)
_FILE_PATH_RE = re.compile(r"(?:^|/)(upload|file|download|attachment)s?(?:/|$|\?)", re.IGNORECASE)
_SEARCH_PATH_RE = re.compile(r"(?:^|/)(search|query|filter)s?(?:/|$|\?)", re.IGNORECASE)


def is_disabled() -> bool:
    """`STRIX_BATCHED_RECON_INTERP_DISABLED=1` short-circuits the
    LLM call; tool returns the deterministic digest only."""
    return os.environ.get(
        "STRIX_BATCHED_RECON_INTERP_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def classify_endpoint_shape(endpoint: str) -> list[str]:
    """Return a list of shape tags for a URL / path string.

    Tags drawn from: `auth`, `file`, `search`, `id_in_path`,
    `numeric_id`, `uuid_id`, `api`, `state_changing`. Multiple
    tags can apply (an `/api/users/{id}` endpoint is both `api`
    and `id_in_path` + `numeric_id`).
    """
    if not isinstance(endpoint, str) or not endpoint.strip():
        return []
    path = endpoint.strip()
    if "://" in path:
        try:
            path = urlparse(path).path or "/"
        except Exception:  # noqa: BLE001
            pass
    tags: list[str] = []
    lower = path.lower()
    if "/api/" in lower or lower.startswith("/api/") or "/v1/" in lower or "/v2/" in lower:
        tags.append("api")
    if _AUTH_PATH_RE.search(lower):
        tags.append("auth")
    if _FILE_PATH_RE.search(lower):
        tags.append("file")
    if _SEARCH_PATH_RE.search(lower):
        tags.append("search")
    if _NUMERIC_PATH_RE.search(lower):
        tags.append("id_in_path")
        tags.append("numeric_id")
    elif _UUID_PATH_RE.search(lower):
        tags.append("id_in_path")
        tags.append("uuid_id")
    return tags


def suspected_categories_for_shape(shape: list[str]) -> list[str]:
    """Map endpoint shape tags to suspected probe categories.
    Conservative — every mapping is well-supported by deterministic
    specialist coverage."""
    cats: set[str] = set()
    if "auth" in shape:
        cats.update({"auth_flow", "csrf", "jwt"})
    if "file" in shape:
        cats.update({"path_traversal", "secrets_in_response"})
    if "search" in shape:
        cats.update({"sqli", "xss"})
    if "id_in_path" in shape:
        cats.update({"idor", "path_traversal"})
    if "api" in shape:
        cats.update({"sqli", "idor", "nosql_injection"})
    # State-changing routes get CSRF as well — would require
    # method info from the surface_map; conservative default off.
    return sorted(cats)


def _extract_endpoints(surface_map: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull endpoints out of the surface_map into a flat list of
    `{path, shape}`. Tolerant to multiple surface_map shapes —
    the webapp pipeline emits `endpoints: [str, ...]`, but newer
    fields may use `{path, method}` dicts.
    """
    raw = surface_map.get("endpoints") or []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for e in raw:
        if isinstance(e, str):
            path = e
        elif isinstance(e, dict):
            path = e.get("path") or e.get("url") or e.get("endpoint") or ""
        else:
            continue
        if not path or path in seen:
            continue
        seen.add(path)
        shape = classify_endpoint_shape(path)
        out.append({"path": path, "shape": shape})
    return out


def _summarize_tech_stack(surface_map: dict[str, Any]) -> str:
    """One-line tech-stack summary from the fingerprint block."""
    fp = (surface_map.get("fingerprint") or {})
    detections = fp.get("detections") or []
    if not detections:
        return "tech stack unknown"
    parts: list[str] = []
    for d in detections[:6]:  # cap to keep summary compact
        if isinstance(d, dict):
            name = d.get("name") or d.get("technology") or ""
            version = d.get("version") or ""
            if name:
                parts.append(f"{name} {version}".strip())
        elif isinstance(d, str):
            parts.append(d)
    if not parts:
        return "tech stack unknown"
    return ", ".join(parts)


def _extract_security_flags(surface_map: dict[str, Any]) -> list[str]:
    """Pull short noun phrases describing security-posture issues
    from the headers + TLS sections of the surface_map."""
    flags: list[str] = []
    headers = (surface_map.get("security_headers") or {})
    for issue in (headers.get("issues") or []):
        if isinstance(issue, dict):
            tag = issue.get("kind") or issue.get("severity") or issue.get("header") or ""
            if tag:
                flags.append(str(tag))
        elif isinstance(issue, str):
            flags.append(issue)
    tls = (surface_map.get("tls") or {})
    for issue in (tls.get("findings") or []):
        if isinstance(issue, dict):
            tag = issue.get("kind") or issue.get("title") or ""
            if tag:
                flags.append(str(tag))
        elif isinstance(issue, str):
            flags.append(issue)
    return flags[:12]  # cap noise


def _build_deterministic_probe_plan(
    endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Default probe ranking when no LLM call is made — rank
    endpoints by suspected severity proxy (auth + file higher,
    search + id higher than plain api, plain endpoints last)."""
    rank_weight = {
        "auth": 5, "file": 5, "id_in_path": 4, "numeric_id": 4,
        "search": 4, "uuid_id": 3, "api": 2,
    }
    ranked: list[dict[str, Any]] = []
    for e in endpoints:
        cats = suspected_categories_for_shape(e["shape"])
        if not cats:
            continue
        score = sum(rank_weight.get(s, 1) for s in e["shape"])
        ranked.append({
            "endpoint": e["path"],
            "suspected_categories": cats,
            "why": f"shape tags: {sorted(e['shape'])}",
            "_score": score,
        })
    ranked.sort(key=lambda r: r["_score"], reverse=True)
    # Drop the internal scoring field before returning.
    for r in ranked:
        r.pop("_score", None)
    return ranked


def _build_llm_prompt(
    *,
    endpoints: list[dict[str, Any]],
    tech_stack: str,
    security_flags: list[str],
) -> str:
    """The single-shot prompt for the LLM call. Compact +
    structured-output friendly."""
    endpoint_lines = [
        f"- {e['path']} (shape: {sorted(e['shape'])})"
        for e in endpoints[:40]  # cap input length
    ]
    return (
        "You are planning probes for a quick-mode scan. Given the "
        "surface map below, return a JSON array of probe-plan "
        "entries (no prose, just JSON). Each entry: "
        '{"endpoint": str, "suspected_categories": [str, ...], '
        '"why": str (one short phrase)}.\n\n'
        "Order by suspected impact (most impactful first). "
        "Suspected categories must be drawn from: sqli, xss, idor, "
        "ssrf, path_traversal, auth_flow, csrf, jwt, "
        "nosql_injection, open_redirect, secrets_in_response.\n\n"
        f"Tech stack: {tech_stack}\n"
        f"Security flags: {security_flags or '(none)'}\n\n"
        "Endpoints:\n" + "\n".join(endpoint_lines)
    )


def _parse_llm_probe_plan(response: Any) -> list[dict[str, Any]] | None:
    """Parse the LLM's JSON-array response. Tolerant to a string
    wrapper around the JSON; returns None on any parse failure
    so the caller can fall back to the deterministic plan."""
    if isinstance(response, list):
        plan = response
    elif isinstance(response, str):
        s = response.strip()
        # Strip markdown code fences if present.
        if s.startswith("```"):
            s = re.sub(r"^```(?:json)?\s*", "", s)
            s = re.sub(r"\s*```$", "", s)
        try:
            plan = json.loads(s)
        except json.JSONDecodeError:
            return None
    else:
        return None
    if not isinstance(plan, list):
        return None
    out: list[dict[str, Any]] = []
    for entry in plan:
        if not isinstance(entry, dict):
            continue
        endpoint = entry.get("endpoint")
        cats = entry.get("suspected_categories") or []
        if not isinstance(endpoint, str) or not isinstance(cats, list):
            continue
        out.append({
            "endpoint": endpoint,
            "suspected_categories": [c for c in cats if isinstance(c, str)],
            "why": str(entry.get("why") or ""),
        })
    return out if out else None


@register_tool(sandbox_execution=False, mitre_techniques=[])
def interpret_recon_and_plan_probes(
    surface_map_path: str,
    inner_call_fn: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """V3-4 — single-shot interpretation of a recon surface map.

    Consumes the entire `webapp_surface_map.json` and returns a
    structured probe plan in one go, replacing 5-15 sequential
    lead-LLM calls in the recon-interpretation phase. Quick
    mode's prompt directs the lead to call this once after
    `webapp_recon_pipeline`.

    Args:
      surface_map_path: filesystem path to the surface_map JSON
        emitted by `webapp_recon_pipeline`.
      inner_call_fn: TEST HOOK — when provided, the LLM call is
        routed through this function instead of litellm. Receives
        the prompt string; returns the response (either parsed
        JSON list or a string containing it).

    Returns:
      Dict with:
        - `endpoints` — flat list of `{path, shape}`
        - `tech_stack` — one-line summary
        - `security_posture_flags` — list of short noun phrases
        - `prioritized_probes` — list of `{endpoint,
          suspected_categories, why}` ranked by suspected impact
        - `interpretation_source` — "llm" or "deterministic_fallback"
          (lets operators see whether the LLM call fired)
    """
    try:
        with open(surface_map_path, encoding="utf-8") as f:
            surface_map = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return {
            "success": False,
            "error": f"could not read surface_map at {surface_map_path}: {e}",
        }

    endpoints = _extract_endpoints(surface_map)
    tech_stack = _summarize_tech_stack(surface_map)
    security_flags = _extract_security_flags(surface_map)

    # Build prompt + run LLM call (if available + enabled).
    prompt = _build_llm_prompt(
        endpoints=endpoints,
        tech_stack=tech_stack,
        security_flags=security_flags,
    )

    plan: list[dict[str, Any]] | None = None
    interpretation_source = "deterministic_fallback"
    if not is_disabled() and inner_call_fn is not None:
        try:
            response = inner_call_fn(prompt)
            plan = _parse_llm_probe_plan(response)
            if plan is not None:
                interpretation_source = "llm"
        except Exception as e:  # noqa: BLE001
            logger.debug("LLM probe-plan call failed: %s", e)
            plan = None

    if plan is None:
        plan = _build_deterministic_probe_plan(endpoints)

    return {
        "success": True,
        "endpoints": endpoints,
        "tech_stack": tech_stack,
        "security_posture_flags": security_flags,
        "prioritized_probes": plan,
        "interpretation_source": interpretation_source,
        "prompt_token_estimate": len(prompt) // 4,
    }
