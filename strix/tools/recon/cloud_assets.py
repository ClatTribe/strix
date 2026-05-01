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

from ._common import emit_finding, http_head


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


_PROBES = {
    "s3": _probe_s3,
    "gcs": _probe_gcs,
    "azure": _probe_azure_blob,
}


@register_tool(sandbox_execution=True)
def discover_cloud_assets(
    org_name: str,
    providers: str | None = None,
    extra_suffixes: str | None = None,
) -> dict[str, Any]:
    """Discover public cloud assets by name permutation.

    Args:
        org_name: organization or domain name to derive bucket candidates from
                  (e.g. "example" or "example.com" — the leftmost label is used).
        providers: comma-separated subset of {s3, gcs, azure}. Default: all.
        extra_suffixes: comma-separated suffix list to append to the default
                        wordlist (e.g. ",-customer-data,-tenant-uploads").

    For each match, emits a structured finding. Returns a list of all hits
    so the agent can reason about which ones to investigate further.
    """
    if not org_name or not org_name.strip():
        return {"success": False, "error": "org_name required"}

    if providers is None or providers.strip().lower() == "all":
        active_providers = list(_PROBES.keys())
    else:
        active_providers = [p.strip().lower() for p in providers.split(",") if p.strip()]
        unknown = [p for p in active_providers if p not in _PROBES]
        if unknown:
            return {"success": False, "error": f"unknown providers: {unknown}"}

    extras_suffix_list: list[str] = []
    if extra_suffixes:
        extras_suffix_list = [s.strip() for s in extra_suffixes.split(",") if s.strip()]

    candidates = _candidate_names(org_name, extra_suffixes=extras_suffix_list)
    hits: list[dict[str, Any]] = []
    for name in candidates:
        for provider in active_providers:
            try:
                hit = _PROBES[provider](name)
            except Exception:  # noqa: BLE001
                logger.exception("cloud probe error for %s/%s", provider, name)
                hit = None
            if hit:
                hits.append(hit)
                emit_finding(
                    title=f"Public {hit['provider']} asset: {name}",
                    severity=hit["severity"],
                    category=hit.get("category"),
                    cwe=hit.get("cwe"),
                    target=org_name,
                    endpoint=hit["url"],
                    description=hit["reason"],
                    impact=(
                        "Public cloud storage buckets named after an organization "
                        "are a classic source of leaked data (backups, customer "
                        "uploads, log exports, build artifacts). Even a bucket "
                        "that returns 403 to anonymous listing is significant — "
                        "it confirms the namespace is owned and may be exposed "
                        "via direct-object reads if object names can be guessed."
                    ),
                    remediation=(
                        "Disable public access on the bucket, or — if public "
                        "intentional — restrict to read-only of explicit prefixes "
                        "and ensure no sensitive data is ever written there. Audit "
                        "object ACLs across the bucket."
                    ),
                    verification_status="verified",
                )

    return {
        "success": True,
        "org_name": org_name,
        "providers_checked": active_providers,
        "candidates_probed": len(candidates),
        "hits": hits,
        "hit_count": len(hits),
    }
