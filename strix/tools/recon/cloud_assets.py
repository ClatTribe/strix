"""Cloud-asset discovery via predictable-name permutation.

Given an organization name (or the apex of a target domain), generate
candidate bucket / blob / store names by applying a permutation
wordlist, and probe S3 / GCS / Azure Blob endpoints to check whether
each candidate exists and how it responds.

This is the "external-recon treasure" check — public buckets named after
the org are a classic source of leaked data (backups, uploads, log
exports). The tool emits structured findings for each candidate that
responds with a public listing, public read access, or even just a
HEAD that suggests the bucket is owned (a 403 on a real bucket has
different security implications than a 404 on a non-existent one).

Bounded by design: a fixed (smallish) wordlist of suffixes/prefixes
that catches the canonical patterns. The agent can re-run with a
custom suffix list when the default doesn't fit the org's naming
convention.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool

from ._common import complete_check, emit_finding, http_head, start_check


_TOOL_NAME = "discover_cloud_assets"


logger = logging.getLogger(__name__)


# Suffix patterns applied to the org name to generate bucket candidates.
# Keep this list bounded; users wanting deeper coverage should pass `extra_suffixes`.
_DEFAULT_SUFFIXES: tuple[str, ...] = (
    "",
    "-prod",
    "-production",
    "-staging",
    "-stage",
    "-dev",
    "-development",
    "-test",
    "-testing",
    "-qa",
    "-uploads",
    "-upload",
    "-files",
    "-public",
    "-private",
    "-backup",
    "-backups",
    "-data",
    "-logs",
    "-static",
    "-assets",
    "-images",
    "-cdn",
    "-archive",
)

_DEFAULT_PREFIXES: tuple[str, ...] = (
    "",
    "prod-",
    "staging-",
    "dev-",
    "test-",
    "backup-",
)


def _candidate_names(org: str, extra_suffixes: list[str] | None = None,
                     extra_prefixes: list[str] | None = None) -> list[str]:
    """Compose unique bucket-name candidates from the org name."""
    suffixes = list(_DEFAULT_SUFFIXES) + list(extra_suffixes or [])
    prefixes = list(_DEFAULT_PREFIXES) + list(extra_prefixes or [])
    seen: set[str] = set()
    out: list[str] = []
    base = org.lower().split(".")[0]  # for "example.com" use "example"
    for prefix in prefixes:
        for suffix in suffixes:
            name = f"{prefix}{base}{suffix}"
            # Bucket-name validation: lowercase, 3-63 chars, no double dots.
            if 3 <= len(name) <= 63 and name not in seen:
                seen.add(name)
                out.append(name)
    return out


def _probe_s3(name: str) -> dict[str, Any] | None:
    """Probe an S3 bucket name. Returns finding-context if interesting."""
    url = f"https://{name}.s3.amazonaws.com/"
    status, headers = http_head(url)
    if status == 0:
        return None
    server = headers.get("server", "") or headers.get("Server", "")
    # 200 → bucket exists and listing is allowed
    # 403 → bucket exists but listing is denied (still owned by someone)
    # 404 → bucket doesn't exist
    if status == 200:
        return {
            "provider": "aws_s3",
            "name": name,
            "url": url,
            "status": status,
            "server": server,
            "severity": "medium",
            "reason": "Public bucket listing exposed",
            "category": "info_disclosure",
            "cwe": "CWE-548",
        }
    if status == 403:
        return {
            "provider": "aws_s3",
            "name": name,
            "url": url,
            "status": status,
            "server": server,
            "severity": "info",
            "reason": "Bucket exists (403 — owned, listing denied). Worth fingerprinting further.",
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


def _probe_gcs(name: str) -> dict[str, Any] | None:
    """Probe a GCS bucket name."""
    url = f"https://storage.googleapis.com/{name}/"
    status, _ = http_head(url)
    if status == 0:
        return None
    if status == 200:
        return {
            "provider": "gcs",
            "name": name,
            "url": url,
            "status": status,
            "severity": "medium",
            "reason": "Public GCS bucket exposed",
            "category": "info_disclosure",
            "cwe": "CWE-548",
        }
    if status == 403:
        return {
            "provider": "gcs",
            "name": name,
            "url": url,
            "status": status,
            "severity": "info",
            "reason": "GCS bucket exists (403 — listing denied).",
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


def _probe_azure_blob(name: str) -> dict[str, Any] | None:
    """Probe an Azure Blob storage account."""
    url = f"https://{name}.blob.core.windows.net/?comp=list"
    status, _ = http_head(url)
    if status == 0:
        return None
    # Azure: 200 with body = listing; 400 with InvalidAuthenticationInfo = exists; 404 = not exists.
    if status == 200:
        return {
            "provider": "azure_blob",
            "name": name,
            "url": f"https://{name}.blob.core.windows.net/",
            "status": status,
            "severity": "medium",
            "reason": "Public Azure Blob storage account exposed",
            "category": "info_disclosure",
            "cwe": "CWE-548",
        }
    if status in (400, 403):
        return {
            "provider": "azure_blob",
            "name": name,
            "url": f"https://{name}.blob.core.windows.net/",
            "status": status,
            "severity": "info",
            "reason": "Azure Blob storage account exists (anonymous listing denied).",
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


# ---------------------------------------------------------------------------
# PaaS-platform probes (Heroku / Vercel / Netlify / GitHub Pages /
# Firebase Hosting / Supabase).
#
# These platforms host org-named projects at predictable subdomains. Existence
# alone is informational (info-severity); a 200 OK confirms the namespace is
# owned. Pairs naturally with subdomain_takeover_check for follow-up — if
# the project's CNAME shape suggests it's been abandoned, that's a takeover
# candidate.
# ---------------------------------------------------------------------------


def _paas_candidate_names(
    org: str, extra_suffixes: list[str] | None = None
) -> list[str]:
    """PaaS app-names tend to be simple — just the org name plus a few
    common suffixes. Smaller candidate set than the storage-bucket generator."""
    suffixes = ["", "-prod", "-staging", "-dev", "-app", "-web", "-api", "-docs"]
    if extra_suffixes:
        suffixes.extend(extra_suffixes)
    base = org.lower().split(".")[0]
    seen: set[str] = set()
    out: list[str] = []
    for suffix in suffixes:
        name = f"{base}{suffix}"
        if 3 <= len(name) <= 63 and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _probe_heroku(name: str) -> dict[str, Any] | None:
    url = f"https://{name}.herokuapp.com/"
    status, _ = http_head(url, follow_redirects=False)
    if status == 0:
        return None
    if status == 200 or (300 <= status < 400):
        return {
            "provider": "heroku",
            "name": name,
            "url": url,
            "status": status,
            "severity": "info",
            "reason": "Heroku app exists at this name. Confirms org-namespace ownership.",
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


def _probe_vercel(name: str) -> dict[str, Any] | None:
    url = f"https://{name}.vercel.app/"
    status, _ = http_head(url, follow_redirects=False)
    if status == 0:
        return None
    # Vercel returns 200 for live deployments, 404 for unclaimed (which the
    # takeover tool handles separately). Anything 2xx/3xx → exists.
    if status == 200 or (300 <= status < 400):
        return {
            "provider": "vercel",
            "name": name,
            "url": url,
            "status": status,
            "severity": "info",
            "reason": "Vercel project deployed at this name. Confirms namespace ownership.",
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


def _probe_netlify(name: str) -> dict[str, Any] | None:
    url = f"https://{name}.netlify.app/"
    status, _ = http_head(url, follow_redirects=False)
    if status == 0:
        return None
    if status == 200 or (300 <= status < 400):
        return {
            "provider": "netlify",
            "name": name,
            "url": url,
            "status": status,
            "severity": "info",
            "reason": "Netlify site deployed at this name. Confirms namespace ownership.",
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


def _probe_github_pages(name: str) -> dict[str, Any] | None:
    """github.io subdomains follow `<org>.github.io` (org page) and
    `<org>.github.io/<repo>` (project page). HEAD on the org URL only."""
    url = f"https://{name}.github.io/"
    status, _ = http_head(url, follow_redirects=False)
    if status == 0:
        return None
    if status == 200 or (300 <= status < 400):
        return {
            "provider": "github_pages",
            "name": name,
            "url": url,
            "status": status,
            "severity": "info",
            "reason": (
                "GitHub Pages org-page exists. Source repo may be public — "
                "review for accidental commits of internal docs / config."
            ),
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


def _probe_firebase_hosting(name: str) -> dict[str, Any] | None:
    """Firebase Hosting projects are reachable at both <name>.web.app and
    <name>.firebaseapp.com. Probe the canonical .web.app first."""
    url = f"https://{name}.web.app/"
    status, _ = http_head(url, follow_redirects=False)
    if status == 0:
        return None
    if status == 200 or (300 <= status < 400):
        return {
            "provider": "firebase_hosting",
            "name": name,
            "url": url,
            "status": status,
            "severity": "info",
            "reason": (
                "Firebase Hosting project deployed. Check Firebase rules + "
                "Firestore/RTDB security rules for misconfigurations."
            ),
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


def _probe_supabase(name: str) -> dict[str, Any] | None:
    """Supabase projects are reachable at <name>.supabase.co. The unauthenticated
    REST endpoint typically returns 200 with `{"hint":"..."}` for live projects."""
    url = f"https://{name}.supabase.co/"
    status, _ = http_head(url, follow_redirects=False)
    if status == 0:
        return None
    if status == 200 or status == 401 or (300 <= status < 400):
        # 200/401 are both indicators of a live project.
        return {
            "provider": "supabase",
            "name": name,
            "url": url,
            "status": status,
            "severity": "info",
            "reason": (
                "Supabase project exists. Check anon-key exposure + Row-Level "
                "Security policies on the public schema."
            ),
            "category": "info_disclosure",
            "cwe": "CWE-200",
        }
    return None


# Map provider → (probe-fn, candidate-fn). Storage providers use the
# bucket-style permutation list; PaaS providers use the simpler app-name
# generator since their project namespace is usually less elaborate.
_PROVIDER_INFO: dict[str, dict[str, Any]] = {
    "s3": {"probe": _probe_s3, "candidates": _candidate_names},
    "gcs": {"probe": _probe_gcs, "candidates": _candidate_names},
    "azure": {"probe": _probe_azure_blob, "candidates": _candidate_names},
    "heroku": {"probe": _probe_heroku, "candidates": _paas_candidate_names},
    "vercel": {"probe": _probe_vercel, "candidates": _paas_candidate_names},
    "netlify": {"probe": _probe_netlify, "candidates": _paas_candidate_names},
    "github_pages": {"probe": _probe_github_pages, "candidates": _paas_candidate_names},
    "firebase": {"probe": _probe_firebase_hosting, "candidates": _paas_candidate_names},
    "supabase": {"probe": _probe_supabase, "candidates": _paas_candidate_names},
}

# Backward-compat alias for any direct callers.
_PROBES = {k: v["probe"] for k, v in _PROVIDER_INFO.items()}


_STORAGE_IMPACT = (
    "Public cloud storage buckets named after an organization "
    "are a classic source of leaked data (backups, customer "
    "uploads, log exports, build artifacts). Even a bucket "
    "that returns 403 to anonymous listing is significant — "
    "it confirms the namespace is owned and may be exposed "
    "via direct-object reads if object names can be guessed."
)
_STORAGE_REMEDIATION = (
    "Disable public access on the bucket, or — if public "
    "intentional — restrict to read-only of explicit prefixes "
    "and ensure no sensitive data is ever written there. Audit "
    "object ACLs across the bucket."
)
_PAAS_IMPACT = (
    "An org-named PaaS deployment confirms the namespace is owned and "
    "broadens the external attack surface. Pair with subdomain_takeover "
    "checks for follow-up — abandoned projects on Heroku/Vercel/Netlify "
    "are a common takeover vector. For Firebase / Supabase, the existence "
    "of the project is a prompt to audit security rules and anonymous "
    "API access."
)
_PAAS_REMEDIATION = (
    "Inventory all PaaS deployments under the org's name; decommission "
    "stale apps. For active projects, audit access control: Firebase "
    "Security Rules, Supabase Row-Level Security, Heroku/Vercel/Netlify "
    "environment-variable exposure, and any unauthenticated endpoints."
)
_STORAGE_PROVIDERS = {"s3", "gcs", "azure"}


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1593", "T1583.001"],  # Search Open Websites + Domain takeover
)
def discover_cloud_assets(
    org_name: str,
    providers: str | None = None,
    extra_suffixes: str | None = None,
) -> dict[str, Any]:
    """Discover public cloud assets by name permutation.

    Args:
        org_name: organization or domain name to derive bucket candidates from
                  (e.g. "example" or "example.com" — the leftmost label is used).
        providers: comma-separated subset of {s3, gcs, azure, heroku, vercel,
                   netlify, github_pages, firebase, supabase}. Default: all.
        extra_suffixes: comma-separated suffix list to append to the default
                        wordlist (e.g. ",-customer-data,-tenant-uploads").

    For each match, emits a structured finding. Returns a list of all hits
    so the agent can reason about which ones to investigate further.
    """
    if not org_name or not org_name.strip():
        return {"success": False, "error": "org_name required"}

    if providers is None or providers.strip().lower() == "all":
        active_providers = list(_PROVIDER_INFO.keys())
    else:
        active_providers = [p.strip().lower() for p in providers.split(",") if p.strip()]
        unknown = [p for p in active_providers if p not in _PROVIDER_INFO]
        if unknown:
            return {"success": False, "error": f"unknown providers: {unknown}"}

    extras_suffix_list: list[str] = []
    if extra_suffixes:
        extras_suffix_list = [s.strip() for s in extra_suffixes.split(",") if s.strip()]

    # Each provider has its own candidate generator — storage providers
    # use the wide bucket-name permutations, PaaS providers use a smaller
    # app-name list. Generate per-provider so we can report accurate
    # candidate counts and avoid hammering PaaS endpoints with
    # storage-style names that would never match.
    per_provider_candidates: dict[str, list[str]] = {
        p: _PROVIDER_INFO[p]["candidates"](org_name, extra_suffixes=extras_suffix_list)
        for p in active_providers
    }
    total_candidates = sum(len(c) for c in per_provider_candidates.values())

    # One check.started/completed per provider — emitting a check per
    # candidate-name probe would flood events.jsonl; the per-provider
    # summary is the right granularity.
    provider_checks: dict[str, str | None] = {
        p: start_check(category="info_disclosure", surface=org_name, tool=_TOOL_NAME)
        for p in active_providers
    }
    provider_hits: dict[str, int] = {p: 0 for p in active_providers}

    hits: list[dict[str, Any]] = []
    for provider in active_providers:
        probe = _PROVIDER_INFO[provider]["probe"]
        is_storage = provider in _STORAGE_PROVIDERS
        for name in per_provider_candidates[provider]:
            try:
                hit = probe(name)
            except Exception:  # noqa: BLE001
                logger.exception("cloud probe error for %s/%s", provider, name)
                hit = None
            if not hit:
                continue
            hits.append(hit)
            provider_hits[provider] += 1
            title_prefix = "Public" if is_storage else "Org-named"
            emit_finding(
                title=f"{title_prefix} {hit['provider']} asset: {name}",
                severity=hit["severity"],
                category=hit.get("category"),
                cwe=hit.get("cwe"),
                target=org_name,
                endpoint=hit["url"],
                description=hit["reason"],
                impact=_STORAGE_IMPACT if is_storage else _PAAS_IMPACT,
                remediation=_STORAGE_REMEDIATION if is_storage else _PAAS_REMEDIATION,
                verification_status="verified",
            )

    # Close out one check per provider with the aggregate verdict.
    for provider, cev_id in provider_checks.items():
        hit_count = provider_hits[provider]
        candidate_count = len(per_provider_candidates[provider])
        verdict = "vulnerable" if hit_count else "not_vulnerable"
        evidence = (
            f"{hit_count} hit(s) across {candidate_count} candidates"
            if hit_count
            else f"no public assets found across {candidate_count} candidates"
        )
        complete_check(cev_id, verdict, evidence=evidence)

    return {
        "success": True,
        "org_name": org_name,
        "providers_checked": active_providers,
        "candidates_probed": total_candidates,
        "hits": hits,
        "hit_count": len(hits),
    }
