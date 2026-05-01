"""Domain recon orchestrator — composes the deterministic recon tools into a
structured pipeline with a single phase bracket and a `surface_map.json`
artifact handoff to the exploit phase.

Roadmap §8.3. A practical interpretation of "specialist sub-agent team for
domain": rather than literal multi-agent message-passing (which is heavy and
duplicates context), this orchestrator runs the existing single-purpose tools
in the right order, emits one consolidated `surface_map.json` the exploit phase
can read, and brackets everything in one `phase.entered` / `phase.completed`
pair so consumers see clean recon-vs-exploit progression.

Composes (in order):
  1. org_fingerprint      — WHOIS / ASN / GitHub org / typosquats
  2. dns_hygiene_check    — SPF / DMARC / DKIM / MTA-STS / CAA / DNSSEC / etc.
  3. passive_dns_history  — historical resolutions + known subdomains (when keys configured)
  4. subdomain enumeration — subfinder subprocess + passive-DNS result merge
  5. per-subdomain triage — HEAD-probe each live subdomain, classify deep/shallow/skip
  6. subdomain_takeover_check — across all discovered subdomains
  7. discover_cloud_assets — S3/GCS/Azure permutation

Each underlying tool already emits its own check events; this orchestrator
adds the phase bracket plus the surface map.

NOT in this orchestrator: `fingerprint_tech_stack`. That tool is host-side
(needs agent_state to load skills into the agent's prompt). The agent should
call it separately, ideally before invoking this orchestrator so the right
skills are loaded for the exploit phase that follows.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool

from . import cloud_assets, dns_hygiene, org_recon, passive_dns, takeover
from ._common import dig, http_head, looks_like_domain


logger = logging.getLogger(__name__)
_TOOL_NAME = "domain_recon_pipeline"

_SUBFINDER_TIMEOUT = 60
_TRIAGE_TIMEOUT = 6


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------


def _subfinder_enumerate(domain: str) -> list[str]:
    """Run `subfinder -d <domain> -silent`. Returns list of subdomains.
    Empty list on failure (subfinder absent / network failure / timeout)."""
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "5"],
            capture_output=True,
            text=True,
            timeout=_SUBFINDER_TIMEOUT,
            check=False,
        )
        out = (proc.stdout or "").strip().splitlines()
        return [line.strip().lower() for line in out if line.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning("subfinder failed for %s: %s", domain, e)
        return []


def _merge_subdomains(*sources: list[str]) -> list[str]:
    """Dedup + sort subdomains across multiple discovery sources."""
    seen: set[str] = set()
    for source in sources:
        for s in source:
            s = s.strip().lower().rstrip(".")
            if s:
                seen.add(s)
    return sorted(seen)


# ---------------------------------------------------------------------------
# Per-subdomain triage classifier
# ---------------------------------------------------------------------------


_DEEP_STATUS_CODES = {200, 301, 302, 401, 403}
_SHALLOW_STATUS_CODES = {204, 304, 405, 406}


def _resolve_subdomain(host: str) -> str | None:
    """Return first A record IP, or None if doesn't resolve."""
    out = dig(host, "A")
    for line in out.splitlines():
        line = line.strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
            return line
    return None


def _triage_subdomain(host: str) -> dict[str, Any]:
    """HEAD-probe the host, classify into deep / shallow / skip.

    deep    — likely a web app / authenticated surface worth deep testing
    shallow — live but probably not a primary target (static, redirect, etc.)
    skip    — doesn't resolve, or returns 5xx, or HEAD failed
    """
    ip = _resolve_subdomain(host)
    if not ip:
        return {
            "host": host,
            "ip": None,
            "live": False,
            "triage": "skip",
            "evidence": "no A record",
        }

    # Try HTTPS first, fall back to HTTP for legacy hosts.
    for scheme in ("https", "http"):
        status, headers = http_head(f"{scheme}://{host}/", follow_redirects=False)
        if status > 0:
            content_type = (
                headers.get("content-type") or headers.get("Content-Type") or ""
            ).lower()
            server = (headers.get("server") or headers.get("Server") or "")[:80]

            evidence = f"{scheme.upper()} {status}"
            if content_type:
                evidence += f" {content_type.split(';')[0]}"
            if server:
                evidence += f" / Server: {server}"

            triage: str
            if status >= 500:
                triage = "skip"
            elif status in _DEEP_STATUS_CODES and (
                "html" in content_type or status in (401, 403) or not content_type
            ):
                triage = "deep"
            elif status in _DEEP_STATUS_CODES and "json" in content_type:
                # JSON 200 → API surface — also valuable but a different focus.
                triage = "deep"
            elif status in _SHALLOW_STATUS_CODES:
                triage = "shallow"
            elif status in _DEEP_STATUS_CODES:
                triage = "shallow"  # served, but not html/json — likely static
            else:
                triage = "shallow"

            return {
                "host": host,
                "ip": ip,
                "live": True,
                "triage": triage,
                "status": status,
                "scheme": scheme,
                "content_type": content_type or None,
                "server": server or None,
                "evidence": evidence,
            }

    # Resolved but no HTTP/HTTPS response.
    return {
        "host": host,
        "ip": ip,
        "live": False,
        "triage": "skip",
        "evidence": "resolves but no HTTP/HTTPS response",
    }


# ---------------------------------------------------------------------------
# surface_map.json builder
# ---------------------------------------------------------------------------


def _write_surface_map(domain: str, surface_map: dict[str, Any]) -> Path | None:
    """Persist surface_map.json next to vulnerabilities.json. Returns the path
    or None if no tracer / no run_dir is available."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None
    try:
        run_dir = tracer.get_run_dir()
        path = run_dir / "surface_map.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(surface_map, f, indent=2, ensure_ascii=False, default=str)
        return path
    except Exception:  # noqa: BLE001
        logger.warning("failed to write surface_map.json", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(sandbox_execution=True)
def domain_recon_pipeline(  # noqa: PLR0913
    domain: str,
    enable_typosquats: bool = True,
    enable_passive_dns: bool = True,
    enable_cloud_assets: bool = True,
    subdomain_max: int = 50,
    triage_subdomains: bool = True,
) -> dict[str, Any]:
    """Orchestrate the full deterministic domain-target recon pipeline.

    Args:
        domain: apex domain.
        enable_typosquats: pass-through to org_fingerprint.
        enable_passive_dns: invoke passive_dns_history if API keys configured.
        enable_cloud_assets: invoke discover_cloud_assets.
        subdomain_max: cap on subdomains to triage + takeover-check (default 50,
                       to bound HTTP probe count).
        triage_subdomains: when True, HEAD-probe each live subdomain and
                           classify deep / shallow / skip.

    Effects:
        - Brackets the whole pipeline in a phase.entered/phase.completed
          ('recon', focus='domain:<host>') pair.
        - Each underlying tool emits its own check events.
        - Persists `surface_map.json` to the run directory.

    Returns the structured surface map dict; the agent's exploit phase
    reads from `surface_map.json` (or this return value) for endpoints
    and per-host triage classification.

    Note: does NOT call fingerprint_tech_stack — that's host-side and
    needs `agent_state` to auto-load skills. Call it separately, ideally
    before this orchestrator.
    """
    if not looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    # Open the recon phase. We always close it in `finally` so a partial
    # failure still emits phase.completed.
    phase_id: str | None = None
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is not None:
            phase_id = tracer.enter_phase("recon", focus=f"domain:{domain}")
    except Exception:  # noqa: BLE001
        tracer = None

    try:
        # 1. Org fingerprint.
        org_result = org_recon.org_fingerprint(
            domain, skip_typosquats=not enable_typosquats
        )

        # 2. DNS hygiene.
        dns_result = dns_hygiene.dns_hygiene_check(domain)

        # 3. Passive DNS (if keys configured — fails open with a clear message).
        passive_dns_result: dict[str, Any] | None = None
        if enable_passive_dns:
            passive_dns_result = passive_dns.passive_dns_history(domain)

        # 4. Subdomain enumeration.
        subfinder_subs = _subfinder_enumerate(domain)
        passive_dns_subs = (
            (passive_dns_result or {}).get("merged_subdomains", []) or []
            if isinstance(passive_dns_result, dict) and passive_dns_result.get("success")
            else []
        )
        # Always include the apex and www. Bound by subdomain_max.
        all_subs = _merge_subdomains(
            subfinder_subs,
            passive_dns_subs,
            [domain, f"www.{domain}"],
        )[:subdomain_max]

        # 5. Triage each subdomain.
        triage_results: list[dict[str, Any]] = []
        if triage_subdomains:
            for host in all_subs:
                triage_results.append(_triage_subdomain(host))

        deep_targets = [t["host"] for t in triage_results if t.get("triage") == "deep"]
        shallow_targets = [t["host"] for t in triage_results if t.get("triage") == "shallow"]
        live_targets = [t["host"] for t in triage_results if t.get("live")]

        # 6. Subdomain takeover across the discovered set (live or not — CNAME
        #    targets matter even when the subdomain itself doesn't HTTP-respond).
        takeover_subs_arg = ",".join(all_subs[:subdomain_max])
        takeover_result = takeover.subdomain_takeover_check(
            domain=domain, subdomains=takeover_subs_arg
        )

        # 7. Cloud assets.
        cloud_result: dict[str, Any] | None = None
        if enable_cloud_assets:
            cloud_result = cloud_assets.discover_cloud_assets(org_name=domain)

        # ----- Build the surface map -----
        surface_map = {
            "schema_version": 1,
            "domain": domain,
            "generated_at": datetime.now(UTC).isoformat(),
            "phase_id": phase_id,
            "summary": {
                "subdomains_discovered": len(all_subs),
                "subdomains_live": len(live_targets),
                "deep_targets": len(deep_targets),
                "shallow_targets": len(shallow_targets),
                "takeover_candidates": (takeover_result or {}).get("candidates", 0),
                "cloud_asset_hits": (cloud_result or {}).get("hit_count", 0),
                "passive_dns_subdomains": len(passive_dns_subs),
            },
            "org_fingerprint": _strip_for_handoff(org_result),
            "dns_hygiene": _strip_for_handoff(dns_result),
            "passive_dns": _strip_for_handoff(passive_dns_result) if passive_dns_result else None,
            "subdomain_enum": {
                "from_subfinder": len(subfinder_subs),
                "from_passive_dns": len(passive_dns_subs),
                "all_unique": len(all_subs),
                "subdomains": all_subs,
            },
            "subdomain_triage": triage_results,
            "deep_targets": deep_targets,
            "shallow_targets": shallow_targets,
            "takeover": _strip_for_handoff(takeover_result),
            "cloud_assets": _strip_for_handoff(cloud_result) if cloud_result else None,
        }

        path = _write_surface_map(domain, surface_map)
        if path:
            surface_map["surface_map_path"] = str(path)

        return {
            "success": True,
            "domain": domain,
            "phase_id": phase_id,
            "surface_map": surface_map,
            "next_steps": _format_next_steps(surface_map),
        }
    finally:
        if tracer is not None and phase_id is not None:
            try:
                tracer.complete_phase(
                    phase_id,
                    summary={"tool": _TOOL_NAME, "domain": domain},
                )
            except Exception:  # noqa: BLE001
                logger.warning("failed to complete recon phase", exc_info=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_for_handoff(result: dict[str, Any] | None) -> dict[str, Any] | None:
    """Trim noisy fields from the surface_map handoff. Keeps the structured
    summary; drops verbose per-record arrays the exploit phase doesn't need
    inline (consumers can cross-reference vulnerabilities.json or the
    individual tools' per-finding output)."""
    if not isinstance(result, dict):
        return result
    # Shallow copy so we don't mutate the caller's dict.
    trimmed = dict(result)
    # Drop full per-finding arrays the surface map doesn't need to embed.
    for noisy in ("typosquat_details", "merged_resolutions", "results"):
        trimmed.pop(noisy, None)
    return trimmed


def _format_next_steps(surface_map: dict[str, Any]) -> list[str]:
    """Build a compact list of suggested next actions for the agent."""
    summary = surface_map.get("summary") or {}
    out: list[str] = []
    if summary.get("deep_targets", 0) > 0:
        out.append(
            f"{summary['deep_targets']} deep target(s) — invoke web-app exploit "
            f"reasoning per host (consult `deep_targets`)."
        )
    if summary.get("takeover_candidates", 0) > 0:
        out.append(
            f"{summary['takeover_candidates']} subdomain takeover candidate(s) — "
            "review the existing findings; don't actively claim third-party projects."
        )
    if summary.get("cloud_asset_hits", 0) > 0:
        out.append(
            f"{summary['cloud_asset_hits']} cloud asset hit(s) — review "
            "`cloud_assets.hits` for public buckets."
        )
    if not out:
        out.append(
            "No deep targets / takeover candidates / cloud assets surfaced. "
            "Verify DNS-hygiene findings and consider expanding subdomain_max."
        )
    return out
