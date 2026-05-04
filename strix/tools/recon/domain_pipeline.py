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
    """Return first A record IP (IPv4), or None if doesn't resolve.
    Used by triage to decide whether to attempt HTTP. The IPv6 path
    runs separately (see `_resolve_subdomain_v6`) so we don't gate
    triage on AAAA presence."""
    out = dig(host, "A")
    for line in out.splitlines():
        line = line.strip()
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
            return line
    return None


def _resolve_subdomain_v6(host: str) -> str | None:
    """Return first AAAA (IPv6) record, or None. Roadmap §7.3 row
    "AAAA / IPv6 reachability" (PR #110): v6-only services often
    have different exposure (different firewalls, sometimes weaker
    hardening). Surfacing the AAAA presence in the triage output
    lets the agent + wrapper highlight v6-only paths."""
    out = dig(host, "AAAA")
    for line in out.splitlines():
        line = line.strip()
        # Lenient IPv6 match — `dig` returns canonical form, so a
        # quick presence check on `:` and hex chars is enough.
        if ":" in line and re.fullmatch(r"[0-9a-fA-F:]+", line):
            return line.lower()
    return None


def _triage_subdomain(host: str) -> dict[str, Any]:
    """HEAD-probe the host, classify into deep / shallow / skip.

    deep    — likely a web app / authenticated surface worth deep testing
    shallow — live but probably not a primary target (static, redirect, etc.)
    skip    — doesn't resolve, or returns 5xx, or HEAD failed

    Roadmap §7.3 row "HTTP / HTTPS asymmetry per subdomain" (PR #110):
    we probe BOTH schemes when either responds successfully — the
    asymmetry result lets us emit a low-severity finding when a
    subdomain serves only over plaintext HTTP. The original behaviour
    (HTTPS-first with HTTP fallback) is preserved for the chosen
    `scheme` field; the second probe is purely for asymmetry detection.
    """
    ip = _resolve_subdomain(host)
    ipv6 = _resolve_subdomain_v6(host)
    if not ip and not ipv6:
        return {
            "host": host,
            "ip": None,
            "ipv6": None,
            "live": False,
            "triage": "skip",
            "evidence": "no A or AAAA record",
        }
    # Edge case: IPv6-only subdomain — most environments still tolerate
    # HEAD via `http_head` since httpx supports v6, but the host won't
    # have an A record. Surface the AAAA so the agent picks up on it.
    if not ip:
        return {
            "host": host,
            "ip": None,
            "ipv6": ipv6,
            "live": True,
            "triage": "shallow",
            "scheme_asymmetry": "ipv6_only",
            "evidence": f"AAAA-only ({ipv6})",
        }

    https_status, https_headers = http_head(
        f"https://{host}/", follow_redirects=False
    )
    http_status, http_headers = http_head(
        f"http://{host}/", follow_redirects=False
    )

    # Determine the primary scheme — HTTPS preferred when it responds.
    primary_scheme: str | None = None
    primary_status = 0
    primary_headers: dict[str, str] = {}
    if https_status > 0:
        primary_scheme = "https"
        primary_status = https_status
        primary_headers = https_headers
    elif http_status > 0:
        primary_scheme = "http"
        primary_status = http_status
        primary_headers = http_headers

    # Asymmetry classification.
    # `https_only`: HTTPS responds, HTTP doesn't → standard well-configured.
    # `http_only`:  HTTP responds, HTTPS doesn't → INSECURE — emit low.
    # `both`:       both schemes respond — fine, but record for honesty.
    # `neither`:    neither responds — caller already handles via primary_scheme is None.
    asymmetry: str
    if https_status > 0 and http_status > 0:
        asymmetry = "both"
    elif https_status > 0:
        asymmetry = "https_only"
    elif http_status > 0:
        asymmetry = "http_only"
    else:
        asymmetry = "neither"

    # Emit asymmetry finding ONLY for the http_only case. The "both"
    # case is normal (HTTP→HTTPS redirect lives at HTTP); the
    # `https_only` case is the well-configured ideal.
    if asymmetry == "http_only":
        _emit_http_only_finding(host, http_status)

    if primary_scheme is None:
        return {
            "host": host,
            "ip": ip,
            "ipv6": ipv6,
            "live": False,
            "triage": "skip",
            "scheme_asymmetry": asymmetry,
            "evidence": "resolves but no HTTP/HTTPS response",
        }

    content_type = (
        primary_headers.get("content-type")
        or primary_headers.get("Content-Type")
        or ""
    ).lower()
    server = (
        primary_headers.get("server") or primary_headers.get("Server") or ""
    )[:80]

    evidence = f"{primary_scheme.upper()} {primary_status}"
    if content_type:
        evidence += f" {content_type.split(';')[0]}"
    if server:
        evidence += f" / Server: {server}"
    if asymmetry == "http_only":
        evidence += " [HTTP-ONLY: insecure]"

    triage: str
    if primary_status >= 500:
        triage = "skip"
    elif primary_status in _DEEP_STATUS_CODES and (
        "html" in content_type or primary_status in (401, 403) or not content_type
    ):
        triage = "deep"
    elif primary_status in _DEEP_STATUS_CODES and "json" in content_type:
        triage = "deep"
    elif primary_status in _SHALLOW_STATUS_CODES:
        triage = "shallow"
    elif primary_status in _DEEP_STATUS_CODES:
        triage = "shallow"
    else:
        triage = "shallow"

    return {
        "host": host,
        "ip": ip,
        "ipv6": ipv6,
        "live": True,
        "triage": triage,
        "status": primary_status,
        "scheme": primary_scheme,
        "scheme_asymmetry": asymmetry,
        "content_type": content_type or None,
        "server": server or None,
        "evidence": evidence,
    }


def _emit_http_only_finding(host: str, http_status: int) -> None:
    """Roadmap §7.3 — emit a low finding when a subdomain serves only
    plaintext HTTP. Zero-FP: probed both schemes, https returned no
    response, http returned a non-zero status. Binary fact."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=f"Subdomain {host} serves only over plaintext HTTP",
        severity="low",
        category="cleartext_transmission",
        cwe="CWE-319",
        target=host,
        endpoint=f"http://{host}/",
        description=(
            f"`{host}` responded to a HEAD probe over plaintext HTTP "
            f"(status {http_status}) but did NOT respond over HTTPS. "
            f"Any data transmitted to or from this subdomain — "
            f"credentials, tokens, session cookies, API payloads — "
            f"travels in plaintext over the network and is readable "
            f"by any observer on path."
        ),
        impact=(
            "Plaintext-HTTP subdomains in scope often share session "
            "cookies with their HTTPS sister apps (especially when "
            "cookies are scoped to the parent domain — see #109). "
            "An attacker on the network — coffee-shop wifi, "
            "compromised router, ISP-level adversary — can read "
            "the cookies and pivot to the HTTPS apps."
        ),
        remediation_steps=(
            "Either retire the subdomain (preferred) or front it with "
            "TLS via the org's existing certificate management. If "
            "the host is genuinely only an HTTP-redirect-to-HTTPS "
            "endpoint, configure HSTS at the apex with `includeSubDomains` "
            "so browsers refuse plaintext to any subdomain."
        ),
        description_plain=(
            f"`{host}` only works over insecure HTTP. Anyone on the "
            f"network can read what users send to or receive from it."
        ),
        recommended_action=(
            "Migrate the subdomain to HTTPS, or retire it. Set HSTS "
            "with `includeSubDomains` at the apex so browsers refuse "
            "plaintext connections."
        ),
        verification_status="verified",
    )


# ---------------------------------------------------------------------------
# surface_map.json builder
# ---------------------------------------------------------------------------


def _write_surface_map(domain: str, surface_map: dict[str, Any]) -> Path | None:
    """Persist surface_map.json next to vulnerabilities.json. Returns the path
    or None if no tracer / no run_dir is available.

    Roadmap §8.0: validates the surface_map against the documented
    handoff-schema contract BEFORE write. Violations are logged + emitted
    as a `handoff.shape_violation` event. Never blocks the write — data
    loss is worse than ugly data; the contract surfaces drift to the
    wrapper / GRC consumers."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None

    # Validate against the handoff-schema contract.
    try:
        from strix.agents.handoffs.surface_map import (
            has_canonical_errors,
            validate_surface_map,
            violations_to_dict_list,
        )

        violations = validate_surface_map(surface_map)
        if violations:
            violation_dicts = violations_to_dict_list(violations)
            is_canonical = not has_canonical_errors(violations)
            try:
                tracer._emit_event(
                    "handoff.shape_violation",
                    payload={
                        "artifact": "surface_map.json",
                        "domain": domain,
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
                    "surface_map.json has canonical-contract errors: %s",
                    [v["code"] for v in violation_dicts if v["severity"] == "error"],
                )
    except Exception:  # noqa: BLE001
        logger.debug("surface_map validation failed", exc_info=True)

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


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1590", "T1591", "T1593", "T1595"],  # Multi-source recon orchestrator
)
def domain_recon_pipeline(  # noqa: PLR0913
    domain: str,
    enable_typosquats: bool = True,
    enable_passive_dns: bool = True,
    enable_cloud_assets: bool = True,
    subdomain_max: int = 50,
    triage_subdomains: bool = True,
    dns_only: bool = False,
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
        dns_only: passive-recon mode. When True, every step that issues an
                  HTTP/TCP probe to the target's own hosts is skipped:
                  - subdomain triage (HEAD probes per host)
                  - subdomain takeover check (HEAD probes for fingerprints)
                  - cloud-asset discovery (HEAD probes against bucket URLs)
                  Steps that are pure DNS or hit third-party APIs run
                  normally: dns_hygiene, org_fingerprint, passive_dns,
                  subdomain_enum (passive sources + DNS bruteforce).
                  Implicitly forces `triage_subdomains=False` and
                  `enable_cloud_assets=False`. Setting `STRIX_DNS_ONLY=1`
                  in the environment also enables this.

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

    # Environment opt-in: STRIX_DNS_ONLY=1 forces dns_only mode regardless of
    # the explicit parameter, so the CLI flag in main.py can express intent
    # without the agent having to remember to pass dns_only=True every time.
    import os as _os

    if _os.environ.get("STRIX_DNS_ONLY") == "1":
        dns_only = True
    if dns_only:
        enable_cloud_assets = False
        triage_subdomains = False

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

        # 4. Subdomain enumeration — multi-source via subdomain_enum tool
        # (subfinder + amass + dns_bruteforce + wayback + permutations).
        # Per-source budget bounds total network volume.
        from . import subdomain_enum_tool as _subdomain_enum_mod

        enum_result = _subdomain_enum_mod.subdomain_enum(
            domain, max_per_source=max(subdomain_max, 100)
        )
        enum_subs = enum_result.get("subdomains", []) if enum_result.get("success") else []
        passive_dns_subs = (
            (passive_dns_result or {}).get("merged_subdomains", []) or []
            if isinstance(passive_dns_result, dict) and passive_dns_result.get("success")
            else []
        )
        # Always include the apex and www. Bound by subdomain_max.
        all_subs = _merge_subdomains(
            enum_subs,
            passive_dns_subs,
            [domain, f"www.{domain}"],
        )[:subdomain_max]
        # Track per-source counts for the surface map summary.
        enum_per_source = enum_result.get("per_source_counts", {}) if enum_result.get("success") else {}

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
        # In dns_only mode we skip — fingerprint matching needs HTTP body
        # fetches against the candidate hosts.
        takeover_result: dict[str, Any] | None = None
        if not dns_only:
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
            "dns_only": dns_only,
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
                "per_source": enum_per_source,
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
            f"{summary['deep_targets']} deep target(s) — call `spawn_webapp_subteam` "
            f"with the `deep_targets` list to hand off one focused web-app sub-agent "
            f"per host (default cap 5; tighten with `max_subteams` if needed)."
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
