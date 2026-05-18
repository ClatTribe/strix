"""Web-application recon pipeline (roadmap §8.2).

Composes the deterministic web-app recon specialists in a fixed
order, brackets them in a single `recon` phase, and emits one
`webapp_surface_map.json` the exploit phase reads from. Equivalent
to `domain_recon_pipeline` but for the web-application target type:

```
fingerprint_tech_stack  → tech stack + auto-load skills
bfs_crawl               → endpoint inventory + JS bundles + OpenAPI
http_security_headers   → headers posture + CORS reflection
tls_audit               → TLS protocol / cipher / cert posture
well_known_harvest      → /.well-known/* probes (RFC 8615)
                        (skipped when --dns-only / passive mode)
```

This is the §8.2 "recon group" — it runs to completion before any
specialist exploit agent is spawned, so the exploit specialists
read from the surface map instead of re-discovering the surface
themselves.

The pipeline:

1. Brackets the work in `phase.entered` / `phase.completed`
   (`recon`, focus=`webapp:<host>`).
2. Each underlying tool emits its own check events (so coverage
   attestation is honest).
3. Persists `webapp_surface_map.json` next to `vulnerabilities.json`.
4. Validates against the documented handoff schema (`§8.0` pattern):
   contract violations are emitted as `handoff.shape_violation` events
   on the events.jsonl stream, but never block the write.
5. Returns the structured surface map dict so the agent can consume
   it without re-reading from disk.

Skip / soft-fail:

- Each underlying tool's failure is recorded in the surface map's
  `errors` list — never aborts the pipeline.
- Optional steps (security_headers, tls, well_known) skip silently
  on internal exceptions. Critical steps (fingerprint, crawl) are
  still attempted.
- `--exclude-path` blocks bubble through cluster-A — each tool
  handles its own skip path.

Pairs with `spawn_webapp_specialist_team` (§8.2 row 2): the spawned
specialists each receive the surface map as starting context.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "webapp_recon_pipeline"


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------


def _normalize_target_url(target: str) -> str | None:
    if not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return target


# ---------------------------------------------------------------------------
# Surface-map persistence
# ---------------------------------------------------------------------------


def _write_webapp_surface_map(
    target_url: str, surface_map: dict[str, Any],
) -> Path | None:
    """Persist webapp_surface_map.json. Validates against the
    handoff schema (roadmap §8.0); violations emit
    `handoff.shape_violation` events but never block the write."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None

    try:
        from strix.agents.handoffs.webapp_surface_map import (
            has_canonical_errors,
            validate_webapp_surface_map,
            violations_to_dict_list,
        )

        violations = validate_webapp_surface_map(surface_map)
        if violations:
            violation_dicts = violations_to_dict_list(violations)
            is_canonical = not has_canonical_errors(violations)
            try:
                tracer._emit_event(
                    "handoff.shape_violation",
                    payload={
                        "artifact": "webapp_surface_map.json",
                        "target_url": target_url,
                        "violations": violation_dicts,
                        "is_canonical": is_canonical,
                    },
                    status="warning" if is_canonical else "error",
                    source="strix.handoffs",
                )
            except Exception:  # noqa: BLE001
                logger.debug("handoff event emit failed", exc_info=True)
            if not is_canonical:
                logger.warning(
                    "webapp_surface_map.json has canonical-contract errors: %s",
                    [v["code"] for v in violation_dicts if v["severity"] == "error"],
                )
    except Exception:  # noqa: BLE001
        logger.debug("webapp_surface_map validation failed", exc_info=True)

    try:
        run_dir = tracer.get_run_dir()
        path = run_dir / "webapp_surface_map.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(surface_map, f, indent=2, ensure_ascii=False, default=str)
        return path
    except Exception:  # noqa: BLE001
        logger.warning("failed to write webapp_surface_map.json", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Per-tool handoff trimming
# ---------------------------------------------------------------------------


def _strip_for_handoff(result: dict[str, Any] | None) -> dict[str, Any] | None:
    """Trim noisy fields from each tool's output before stashing in
    the surface map. Keeps structured data the exploit phase needs;
    drops verbose body excerpts / stack-trace text."""
    if not isinstance(result, dict):
        return None
    drop_keys = {
        "raw_response", "raw_body", "body_excerpt", "html_snippet",
        "raw_headers_text",
    }
    return {k: v for k, v in result.items() if k not in drop_keys}


# ---------------------------------------------------------------------------
# Phase events
# ---------------------------------------------------------------------------


def _open_phase(focus: str) -> tuple[Any, str | None]:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return (None, None)
        phase_id = tracer.enter_phase(phase="recon", focus=focus)
        return (tracer, phase_id)
    except Exception:  # noqa: BLE001
        logger.debug("phase open failed", exc_info=True)
        return (None, None)


def _close_phase(tracer: Any, phase_id: str | None, summary: dict[str, Any]) -> None:
    if tracer is None or phase_id is None:
        return
    try:
        tracer.complete_phase(phase_id, summary=summary)
    except Exception:  # noqa: BLE001
        logger.debug("phase close failed", exc_info=True)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1595", "T1592", "T1593"],  # Active scanning, info gathering
)
def webapp_recon_pipeline(  # noqa: PLR0912
    agent_state: Any,
    target_url: str,
    max_pages: int = 200,
    max_depth: int = 3,
    seed_urls: str | None = None,
    openapi_url: str | None = None,
    enable_well_known: bool = True,
    enable_tls: bool = True,
    enable_security_headers: bool = True,
) -> dict[str, Any]:
    """Run the deterministic web-application recon group.

    §8.2 recon-group orchestrator. Composes the building blocks in
    a fixed order so every specialist exploit agent reads from the
    same surface map instead of re-discovering the surface.

    Args:
        target_url: full URL (e.g. "https://app.example.com"). Bare
            hostnames auto-prefixed with `https://`.
        max_pages: cap for `bfs_crawl` (default 200).
        max_depth: BFS depth cap (default 3).
        seed_urls: optional comma-separated extra crawl seeds.
        openapi_url: optional OpenAPI spec URL.
        enable_well_known: toggle `/.well-known/*` probing.
        enable_tls: toggle TLS protocol / cipher / cert audit.
        enable_security_headers: toggle CORS / HSTS / CSP audit.

    Effects:
        - Brackets the pipeline in phase.entered/phase.completed
          (`recon`, focus=`webapp:<host>`).
        - Each underlying tool emits its own check events.
        - Persists `webapp_surface_map.json` to the run dir;
          validates against the §8.0 handoff schema.

    Returns the structured surface map dict (also returned in
    `surface_map`) for the exploit phase to consume directly.
    """
    target_norm = _normalize_target_url(target_url)
    if target_norm is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    target_host = (urlparse(target_norm).hostname or "").lower()
    if not target_host:
        return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}

    # v2 step 5 — recon cache lookup. Re-scans of the same target
    # within the TTL replay the cached surface_map without re-running
    # the inner recon steps. Key is parameter-aware so different
    # max_pages/max_depth/enable_* shapes get distinct entries.
    _cache_params = {
        "max_pages": max_pages,
        "max_depth": max_depth,
        "seed_urls": seed_urls,
        "openapi_url": openapi_url,
        "enable_well_known": enable_well_known,
        "enable_tls": enable_tls,
        "enable_security_headers": enable_security_headers,
    }
    try:
        from strix.agents.recon_cache import get as _recon_cache_get
        _cached = _recon_cache_get(
            pipeline="webapp_recon_pipeline",
            target_url=target_norm,
            params=_cache_params,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("recon_cache lookup failed: %s", e)
        _cached = None
    if _cached is not None:
        # Cache hit — replay verbatim. Skip the inner pipeline +
        # phase bracket (no work was done; no events to emit).
        return _cached

    tracer, phase_id = _open_phase(f"webapp:{target_host}")

    errors: list[dict[str, Any]] = []
    fingerprint_result: dict[str, Any] | None = None
    crawl_result: dict[str, Any] | None = None
    headers_result: dict[str, Any] | None = None
    tls_result: dict[str, Any] | None = None
    well_known_result: dict[str, Any] | None = None

    try:
        # 1. Fingerprint — tech stack + auto-load skills.
        try:
            from strix.tools.recon.fingerprint import fingerprint_tech_stack

            fingerprint_result = fingerprint_tech_stack(
                agent_state=agent_state, target=target_norm, deep=False,
            )
        except Exception as e:  # noqa: BLE001
            errors.append({"step": "fingerprint", "error": str(e)})
            logger.warning("fingerprint_tech_stack failed", exc_info=True)

        # 2. BFS crawl — endpoint inventory.
        try:
            from strix.tools.web_crawler.crawler import bfs_crawl

            crawl_result = bfs_crawl(
                target=target_norm,
                max_pages=max_pages,
                max_depth=max_depth,
                seed_urls=seed_urls,
                openapi_url=openapi_url,
            )
        except Exception as e:  # noqa: BLE001
            errors.append({"step": "bfs_crawl", "error": str(e)})
            logger.warning("bfs_crawl failed", exc_info=True)

        # 3. Security headers (HSTS / CSP / CORS reflection).
        if enable_security_headers:
            try:
                from strix.tools.http_headers.http_headers import (
                    http_security_headers_audit,
                )

                headers_result = http_security_headers_audit(target_url=target_norm)
            except Exception as e:  # noqa: BLE001
                errors.append({"step": "http_security_headers_audit", "error": str(e)})
                logger.warning("http_security_headers_audit failed", exc_info=True)

        # 4. TLS audit.
        if enable_tls:
            try:
                from strix.tools.tls_audit.tls_audit import tls_audit

                tls_result = tls_audit(target=target_norm)
            except Exception as e:  # noqa: BLE001
                errors.append({"step": "tls_audit", "error": str(e)})
                logger.warning("tls_audit failed", exc_info=True)

        # 5. Well-known harvest.
        if enable_well_known:
            try:
                from strix.tools.well_known.well_known import well_known_harvest

                well_known_result = well_known_harvest(target=target_norm)
            except Exception as e:  # noqa: BLE001
                errors.append({"step": "well_known_harvest", "error": str(e)})
                logger.warning("well_known_harvest failed", exc_info=True)

        # ---- Build surface map ----
        endpoints = (crawl_result or {}).get("endpoints") or []
        js_bundles = (crawl_result or {}).get("js_bundles") or []
        openapi_specs = (crawl_result or {}).get("openapi") or {}

        summary = {
            "endpoints_discovered": len(endpoints),
            "javascript_bundles": len(js_bundles) if isinstance(js_bundles, list) else 0,
            "openapi_specs_found": len(openapi_specs) if isinstance(openapi_specs, dict) else 0,
            "tech_stack_detections": len(
                ((fingerprint_result or {}).get("detections")) or []
            ),
            "skills_auto_loaded": len(
                ((fingerprint_result or {}).get("skills_loaded")) or []
            ),
            "tls_audit_findings": (tls_result or {}).get("findings_emitted") or 0,
            "security_header_issues": len(
                ((headers_result or {}).get("issues")) or []
            ),
            "well_known_hits": len(
                ((well_known_result or {}).get("hits")) or []
            ),
            "errors": len(errors),
        }

        surface_map: dict[str, Any] = {
            "schema_version": 1,
            "target_url": target_norm,
            "target_host": target_host,
            "generated_at": datetime.now(UTC).isoformat(),
            "phase_id": phase_id,
            "summary": summary,
            "fingerprint": _strip_for_handoff(fingerprint_result),
            "crawl": _strip_for_handoff(crawl_result),
            "security_headers": _strip_for_handoff(headers_result),
            "tls": _strip_for_handoff(tls_result),
            "well_known": _strip_for_handoff(well_known_result),
            "endpoints": [str(e) for e in endpoints if isinstance(e, str)],
            "errors": errors,
        }

        path = _write_webapp_surface_map(target_norm, surface_map)
        if path:
            surface_map["surface_map_path"] = str(path)

        result = {
            "success": True,
            "target_url": target_norm,
            "target_host": target_host,
            "phase_id": phase_id,
            "surface_map": surface_map,
            "next_steps": _format_next_steps(surface_map),
        }

        # v2 step 5 — store in the recon cache only when the run
        # succeeded cleanly. `put()` ignores results where
        # success=False, so this is conservative even if we drift.
        if not errors:
            try:
                from strix.agents.recon_cache import put as _recon_cache_put
                _recon_cache_put(
                    pipeline="webapp_recon_pipeline",
                    target_url=target_norm,
                    result=result,
                    params=_cache_params,
                )
            except Exception as e:  # noqa: BLE001
                logger.debug("recon_cache store failed: %s", e)

        return result
    finally:
        _close_phase(
            tracer, phase_id,
            summary={"tool": _TOOL_NAME, "target_url": target_norm},
        )


def _format_next_steps(surface_map: dict[str, Any]) -> list[str]:
    """Suggest what the lead agent should do next based on the
    discovered surface."""
    summary = surface_map.get("summary") or {}
    endpoints = summary.get("endpoints_discovered", 0)
    js_bundles = summary.get("javascript_bundles", 0)
    openapi = summary.get("openapi_specs_found", 0)
    tls_findings = summary.get("tls_audit_findings", 0)
    sec_header_issues = summary.get("security_header_issues", 0)
    skills_loaded = summary.get("skills_auto_loaded", 0)

    next_steps: list[str] = []
    if endpoints == 0:
        next_steps.append(
            "Crawl found 0 endpoints — verify target_url is reachable + "
            "auth flags are configured. Without endpoints, the exploit "
            "phase has no surface to probe."
        )
    if endpoints > 0:
        next_steps.append(
            f"Surface map has {endpoints} endpoint(s). Spawn the §8.2 "
            f"specialist exploit team via `spawn_webapp_specialist_team` "
            f"to dispatch authz / injection / SSRF / IDOR / GraphQL / "
            f"CSRF / auth-flaws specialists in parallel."
        )
    if openapi:
        next_steps.append(
            "OpenAPI spec discovered — pass it to the injection-specialist "
            "as authoritative endpoint metadata."
        )
    if js_bundles:
        next_steps.append(
            "JS bundles harvested — the §7.2 'DOM-XSS static probe on "
            "harvested JS bundles' (still ⬜) would consume these."
        )
    if tls_findings > 0:
        next_steps.append(
            f"TLS audit emitted {tls_findings} finding(s). Review the "
            f"`tls` block of surface_map for protocol / cipher / cert "
            f"issues — typically remediated outside the exploit phase."
        )
    if sec_header_issues > 0:
        next_steps.append(
            f"{sec_header_issues} security-header issue(s) detected. "
            f"For deeper CORS analysis run `cors_deep_check` (#78). "
            f"For debug-bleed run `debug_endpoint_check` (#77)."
        )
    if skills_loaded > 0:
        next_steps.append(
            f"{skills_loaded} skill(s) auto-loaded based on fingerprint "
            f"— the spawned specialists inherit them via "
            f"`inherit_context=True`."
        )
    return next_steps
