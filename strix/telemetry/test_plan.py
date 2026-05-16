"""Build the deterministic `run.test_plan` payload from scan config.

Roadmap §1. Lets any consumer (TUI, CI log, dashboard) answer
"what is this scan doing?" *before* findings exist. The list of
planned categories per target is derived from target type, scan
mode, and a few flags (notably `dns_only`).

This is not the LLM's plan — it's the deterministic outer envelope of
"things this run could find" given how Strix is wired today. The agent
may pull additional skills inside the run; this is the floor, not the
ceiling.
"""

from __future__ import annotations

from typing import Any


# Per-target-type planned check categories. Each entry is (name, description).
# Order is intentional: roughly the order in which the recon→exploit→validate
# phases will exercise them. UIs can render the list verbatim.
_CATEGORIES_BY_TARGET_TYPE: dict[str, list[tuple[str, str]]] = {
    "domain": [
        ("org_fingerprint", "WHOIS / ASN / GitHub-org / typosquats"),
        ("dns_security", "DNSSEC / CAA / wildcard / AXFR / open resolver / dangling NS"),
        ("email_security", "SPF / DMARC / DKIM / MTA-STS / DANE / BIMI"),
        ("subdomain_enum", "subfinder + amass + DNS bruteforce + wayback + permutations"),
        ("subdomain_takeover", "63-provider takeover candidate detection"),
        ("info_disclosure", "S3/GCS/Azure + 6 PaaS provider leak discovery"),
        ("mx_recon", "MX banner fingerprint + sample-mail Authentication-Results"),
        ("passive_dns", "SecurityTrails / VirusTotal historical resolutions"),
        ("reverse_ip", "HackerTarget / ViewDNS co-tenant discovery"),
        ("code_search", "GitHub / GitLab references + secret-leak detection"),
        ("saas_leaks", "Trello / Notion / Google Docs / Pastebin / Confluence / Airtable"),
    ],
    "web_application": [
        ("tech_stack_fingerprint", "framework / WAF / CDN detection"),
        ("xss", "reflected / stored / DOM XSS"),
        ("sql_injection", "SQLi across all input points"),
        ("authentication", "auth bypass / JWT / session management"),
        ("authorization", "IDOR / BFLA / privilege escalation"),
        ("ssrf", "SSRF + cloud-metadata exposure"),
        ("xxe", "XXE in XML processing"),
        ("rce", "RCE in upload / template / deserialization paths"),
        ("csrf", "CSRF + SameSite policy"),
        ("path_traversal", "LFI / RFI / path traversal"),
        ("file_upload", "insecure file uploads"),
        ("open_redirect", "open redirect"),
        ("info_disclosure", "leaked env / source / debug endpoints"),
        ("business_logic", "business-logic abuse"),
    ],
    "ip_address": [
        ("port_scan", "nmap / naabu service discovery"),
        ("service_fingerprint", "per-service banner + version detection"),
        ("cve_correlation", "version-to-CVE matching via threat intel"),
        ("default_credentials", "default-credential / weak-cred testing per service"),
    ],
    "repository": [
        ("code_review", "static analysis for vulnerable patterns"),
        ("secret_scan", "leaked credentials in code + git history"),
        ("dependency_scan", "vulnerable / outdated dependencies"),
        ("auth_review", "auth & session management code paths"),
        ("crypto_review", "weak crypto / hard-coded keys"),
    ],
    "local_code": [
        ("code_review", "static analysis for vulnerable patterns"),
        ("secret_scan", "leaked credentials in code + git history"),
        ("dependency_scan", "vulnerable / outdated dependencies"),
        ("auth_review", "auth & session management code paths"),
        ("crypto_review", "weak crypto / hard-coded keys"),
    ],
    # `container_image` — registry-resident artefacts scanned via
    # Trivy. OS + language package CVEs are the headline category;
    # the misconfig + secrets categories surface here too because
    # Trivy detects them natively (Dockerfile USER root, hardcoded
    # secrets in image layers, etc.) — v1 wraps the CVE path only;
    # misconfig + secrets land as separate categories in follow-up
    # PRs.
    "container_image": [
        ("os_package_cves", "OS package CVEs (debian / ubuntu / alpine / rhel / etc.)"),
        ("lang_package_cves", "Language package CVEs (npm / pypi / cargo / maven / etc.)"),
        ("sbom_inventory", "full image SBOM — Dependency KG nodes for every package"),
        ("kev_decoration", "CISA KEV match → critical severity bump"),
        ("epss_decoration", "EPSS ≥ 0.5 → severity escalation"),
    ],
    # `api` shares most of the web_application probe surface but
    # skips DOM-rendering specialists (xss, dom_xss) and adds the
    # API-Top-10 categories — BOLA / BFLA / mass-assignment / rate-
    # limit specialists landed in PRs #267-#269.
    "api": [
        ("openapi_ingest", "OpenAPI / Swagger spec discovery + endpoint inventory"),
        ("tech_stack_fingerprint", "framework / WAF / CDN detection"),
        ("sql_injection", "SQLi across all input points"),
        ("authentication", "auth bypass / JWT / session management"),
        ("authorization", "BOLA / BFLA / IDOR / privilege escalation"),
        ("mass_assignment", "unexpected-property write via JSON body"),
        ("rate_limit", "per-endpoint rate-limit / quota enforcement"),
        ("ssrf", "SSRF + cloud-metadata exposure"),
        ("xxe", "XXE in XML processing"),
        ("rce", "RCE in upload / template / deserialization paths"),
        ("path_traversal", "LFI / RFI / path traversal"),
        ("file_upload", "insecure file uploads"),
        ("info_disclosure", "leaked env / source / debug endpoints"),
        ("business_logic", "business-logic abuse"),
    ],
}


# Categories pruned when --dns-only is active. Scoped to domain-target
# categories — dns_only is a domain-only mode, and web_application's
# tech_stack_fingerprint is a separate target type. The rest run
# normally because they're either pure DNS or third-party APIs.
_DNS_ONLY_PRUNED: set[str] = {
    "subdomain_takeover",  # HEAD probes against target subdomains
    "info_disclosure",  # cloud-asset HEAD probes against bucket URLs
    "mx_recon",  # SMTP banner grab against target MX
}


def _planned_for_target(
    target_type: str,
    *,
    dns_only: bool = False,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return (planned, skipped) category lists for a single target type.

    Each list entry is `{name, description}`. `skipped` is non-empty only
    when a flag (e.g. `dns_only`) prunes a category that would normally run.
    """
    base = _CATEGORIES_BY_TARGET_TYPE.get(target_type, [])
    planned: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for name, description in base:
        entry = {"name": name, "description": description}
        if dns_only and target_type == "domain" and name in _DNS_ONLY_PRUNED:
            entry_with_reason = {**entry, "reason": "dns-only mode active"}
            skipped.append(entry_with_reason)
        else:
            planned.append(entry)
    return planned, skipped


def _summarize_plan(targets: list[dict[str, Any]]) -> str:
    """One-paragraph headline of the plan. Plain text, no markdown."""
    if not targets:
        return "Plan: no targets — nothing to scan."
    type_counts: dict[str, int] = {}
    total_categories = 0
    for t in targets:
        type_counts[t.get("type") or "?"] = type_counts.get(t.get("type") or "?", 0) + 1
        total_categories += len(t.get("planned_categories") or [])
    type_summary = ", ".join(f"{n} {ttype}" for ttype, n in sorted(type_counts.items()))
    if len(targets) == 1:
        first = targets[0]
        label = first.get("value") or "(unknown target)"
        ttype = first.get("type") or "?"
        n_cats = len(first.get("planned_categories") or [])
        return f"Plan: 1 {ttype} target ({label}) with {n_cats} planned check categor{'y' if n_cats == 1 else 'ies'}."
    return (
        f"Plan: {len(targets)} target(s) ({type_summary}) with "
        f"{total_categories} planned check categor{'y' if total_categories == 1 else 'ies'} total."
    )


def build_test_plan(
    scan_config: dict[str, Any] | None,
    *,
    dns_only: bool = False,
) -> dict[str, Any]:
    """Compose the `run.test_plan` payload from a scan_config.

    The function tolerates the same target-shape variation as the rest of
    the telemetry layer (string entries, dict entries with `value+type` or
    CLI's `type+details+original`). Unrecognized target types are still
    emitted with empty planned/skipped lists so consumers see them.
    """
    config = scan_config or {}
    raw_targets = config.get("targets") or []

    # Local import to avoid a cycle at module load time.
    from strix.telemetry.tracer import _normalize_target_for_events

    targets_out: list[dict[str, Any]] = []
    for idx, raw in enumerate(raw_targets, start=1):
        normalized = _normalize_target_for_events(raw)
        if normalized is None:
            continue
        target_type = normalized.get("type") or ""
        planned, skipped = _planned_for_target(target_type, dns_only=dns_only)
        targets_out.append(
            {
                "target_id": f"target-{idx:04d}",
                "value": normalized["value"],
                "type": target_type or None,
                "planned_categories": planned,
                "skipped_categories": skipped,
            }
        )

    return {
        "schema_version": 1,
        "scan_mode": config.get("scan_mode"),
        "dns_only": dns_only,
        "targets": targets_out,
        "summary_text": _summarize_plan(targets_out),
    }
