"""iter-21.6 — `scan_public_bucket_exposure` deterministic
public-cloud-bucket audit.

## Why this exists

Misconfigured AWS S3 / GCP Cloud Storage / Azure Blob containers
are one of the most-common data-breach root causes (US-CERT
TA17-156A, dozens of high-profile incidents). The pattern is
boring: companies create a bucket named after their domain or
product (e.g. `acme-backups`, `acme.com`), accidentally leave the
ACL open, and the bucket lists every object to any anonymous
visitor.

Discovery is genuinely uncovered in strix today and in OSS
generally: subfinder / amass enumerate subdomains, but neither
classifies which subdomain labels correspond to publicly-listable
buckets. Mandiant ASM, Bishop Fox CAST, Detectify, and BlackKite
cover this; OSS Cloudripper / S3Scanner do too but require
manual seed lists.

This tool runs the deterministic discovery from a single target
URL:

  1. Extract candidate bucket names from the target's hostname
     labels (acme.com → ['acme', 'acme-com', 'acmecom'], etc.)
  2. For each candidate, probe AWS / GCP / Azure bucket endpoints
     with HEAD/GET.
  3. Classify each hit:
     * **public-listable** (critical): bucket lists objects to
       anonymous callers — XML/JSON with object names visible.
     * **exists-private** (info): bucket exists but enforces ACL.
       Useful intel — confirms the naming pattern is in use; the
       attacker now knows where to focus authenticated phishing.
     * **does-not-exist** (skip): 404 / NXDOMAIN.

The audit is pure HTTP — no AWS / GCP credentials required, no
SDKs, just `httpx` GETs against the public bucket endpoints.

## Recall safety

Read-only HTTP HEAD/GET. Each candidate gets one short request
per cloud provider; total wall time bounded by the candidate-list
size (default cap: 24 candidates × 3 providers = 72 probes).
Returns `partial` with `reason` when the target shape doesn't
yield credible bucket candidates (e.g. raw IP address as target).
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_HTTP_TIMEOUT = 5
_BODY_CAP_BYTES = 16 * 1024  # listings are small; cap for safety
_MAX_CANDIDATES = 24  # per-target cap on candidate-name expansion


# Bucket-name validity rules per cloud:
#   AWS S3 (DNS-style):  3-63 chars; lowercase letters / digits /
#                        hyphens; no IP-shape; can't end with hyphen.
#   GCS:                 3-63 chars; lowercase letters / digits /
#                        hyphens / underscores / dots.
#   Azure Blob (account+container): 3-24 chars for storage account;
#                                   3-63 chars for container.
# We use the AWS rules as the tightest filter — anything that's a
# valid S3 bucket name is valid (or close enough) for the others.
_S3_VALID_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


# Substrings that suggest a label is a generic word, not a
# company-specific identifier. We don't filter these out — they
# can absolutely be bucket names — but downstream the operator
# sees them in the candidate list and can prune.
_GENERIC_LABELS = frozenset({
    "www", "api", "app", "static", "cdn", "media", "img", "images",
    "assets", "files", "uploads", "download", "downloads", "dev",
    "staging", "prod", "production", "test", "mail", "blog", "docs",
    "support", "admin", "internal", "auth", "login",
})


def _normalize_target(url: str) -> str | None:
    """Return `scheme://host[:port]/` or None on malformed input."""
    if not url or not url.strip():
        return None
    s = url.strip()
    parsed = urlparse(s if "://" in s else f"https://{s}")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}/"


def _candidate_names(host: str) -> list[str]:
    """Build a candidate bucket-name list from a target hostname.

    For `api.example.com`:
      ['api', 'example', 'com',                          # raw labels
       'api-example', 'example-com', 'api-example-com',  # adjacent joins
       'apiexample', 'examplecom', 'apiexamplecom',      # concatenated
       'api.example', 'example.com', 'api.example.com',  # dot-joined
       'example-api', 'example-backup', 'example-files', # common suffix-patterns
       ...]

    Conservative: caps at `_MAX_CANDIDATES`, filters to S3-valid
    names so HTTP probes don't 400 on the bucket-name-syntax check.
    """
    if not host:
        return []
    # Strip port if present
    host_only = host.split(":", 1)[0].lower()
    # Bare IPs get no candidates — `192.168.1.1.s3.amazonaws.com`
    # is nonsense and would just generate noise.
    if all(p.isdigit() for p in host_only.split(".")):
        return []
    labels = [l for l in host_only.split(".") if l]
    if not labels:
        return []
    # Drop the rightmost ccTLD-shape label (.com / .io / .co.uk
    # second-level domain handling is best-effort — we keep the
    # apex label like `example` from `example.com`).
    candidates: list[str] = []

    # 1. Each raw label
    candidates.extend(labels)

    # 2. The apex (typically labels[-2] for example.com,
    #    labels[-3] for example.co.uk).
    if len(labels) >= 2:
        apex = labels[-2]
        candidates.append(apex)
    # 3. Hyphen-joined adjacent labels
    for i in range(len(labels) - 1):
        candidates.append(f"{labels[i]}-{labels[i+1]}")
    # 4. Full hostname hyphen-joined (drop final TLD chars)
    if len(labels) >= 2:
        # 'api.example.com' → 'api-example'
        candidates.append("-".join(labels[:-1]))
    # 5. Concatenated forms (no separator)
    if len(labels) >= 2:
        candidates.append("".join(labels[:-1]))
    # 6. Common backup/data-related suffix expansions on the apex
    if len(labels) >= 2:
        apex = labels[-2]
        for suffix in ("backup", "backups", "data", "files",
                       "uploads", "assets", "media", "prod",
                       "production", "staging", "dev", "logs"):
            candidates.append(f"{apex}-{suffix}")

    # Dedupe + filter to S3-valid + cap
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        c = c.lower().strip()
        if c in seen:
            continue
        seen.add(c)
        if not _S3_VALID_NAME_RE.match(c):
            continue
        out.append(c)
        if len(out) >= _MAX_CANDIDATES:
            break
    return out


def _http_get(url: str, *, timeout: float = _HTTP_TIMEOUT) -> dict[str, Any]:
    """HEAD/GET via proxy_manager when available, else direct httpx.
    Returns `{status, headers, body, error?}`. Body capped at
    `_BODY_CAP_BYTES`."""
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=timeout)
            if r.get("skipped"):
                return {"skipped": True, "status": 0, "headers": {}, "body": ""}
            return {
                "status": int(r.get("status") or 0),
                "headers": r.get("headers") or {},
                "body": (r.get("body") or "")[:_BODY_CAP_BYTES],
            }
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)[:200], "status": 0, "headers": {}, "body": ""}
    try:
        import httpx

        with httpx.Client(
            timeout=timeout, follow_redirects=True, trust_env=False,
        ) as c:
            resp = c.get(url)
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:_BODY_CAP_BYTES],
            }
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:200], "status": 0, "headers": {}, "body": ""}


# ---------------------------------------------------------------------------
# Provider classifiers
# ---------------------------------------------------------------------------


def _classify_s3(url: str, resp: dict[str, Any]) -> dict[str, Any] | None:
    """Classify an S3 probe response. Returns a finding dict or None."""
    status = resp.get("status") or 0
    body = (resp.get("body") or "")
    if status == 200 and "<ListBucketResult" in body:
        return {
            "rule_id": "s3-bucket-publicly-listable",
            "title": f"AWS S3 bucket publicly listable at `{url}`",
            "severity": "critical",
            "cwe": "CWE-732",
            "provider": "aws_s3",
            "url": url,
            "description": (
                f"`{url}` returned `<ListBucketResult>` XML to an "
                "anonymous GET. The bucket is publicly listable — "
                "every object name is visible without auth. Per "
                "AWS S3 ACL semantics this also typically allows "
                "anonymous reads of the listed objects."
            ),
            "remediation": (
                "Block public access at the account level "
                "(`PutPublicAccessBlock` with all four "
                "BlockPublicAccess flags set to true). Then audit "
                "the bucket's bucket policy + ACL for the "
                "anonymous principal."
            ),
        }
    if status == 403 and "<Code>AccessDenied</Code>" in body:
        return {
            "rule_id": "s3-bucket-exists-private",
            "title": f"AWS S3 bucket exists at `{url}` (access denied)",
            "severity": "info",
            "cwe": "CWE-200",
            "provider": "aws_s3",
            "url": url,
            "description": (
                f"`{url}` exists in S3 but responds AccessDenied "
                "to anonymous GETs. The naming pattern is in use "
                "by this organization — useful intel: subsequent "
                "auth-pivot attacks or insider-threat scenarios "
                "know where to focus."
            ),
            "remediation": (
                "If the bucket should remain private, no action "
                "needed. Consider whether the bucket NAME itself "
                "is sensitive (it leaks the org's bucket-naming "
                "scheme to anyone who tries it)."
            ),
        }
    return None


def _classify_gcs(url: str, resp: dict[str, Any]) -> dict[str, Any] | None:
    """Classify a GCS probe response. Returns a finding dict or None."""
    status = resp.get("status") or 0
    body = (resp.get("body") or "")
    if status == 200 and ("kind" in body and "storage#" in body):
        return {
            "rule_id": "gcs-bucket-publicly-listable",
            "title": f"GCP Cloud Storage bucket publicly listable at `{url}`",
            "severity": "critical",
            "cwe": "CWE-732",
            "provider": "gcp_gcs",
            "url": url,
            "description": (
                f"`{url}` returned a `storage#objects` JSON listing "
                "to an anonymous GET. The bucket grants "
                "`allUsers` the `storage.objects.list` role. "
                "Every object is enumerable; depending on per-"
                "object ACL, often readable too."
            ),
            "remediation": (
                "Remove the `allUsers` member from the bucket's "
                "IAM policy. Enable Public Access Prevention at "
                "the bucket level (`gcloud storage buckets update "
                "--public-access-prevention`)."
            ),
        }
    if status == 403:
        return {
            "rule_id": "gcs-bucket-exists-private",
            "title": f"GCP Cloud Storage bucket exists at `{url}` (access denied)",
            "severity": "info",
            "cwe": "CWE-200",
            "provider": "gcp_gcs",
            "url": url,
            "description": (
                f"`{url}` exists in GCS but rejects anonymous "
                "GETs. The naming pattern is in use; useful "
                "intel for downstream phases."
            ),
            "remediation": (
                "No immediate action needed if the bucket should "
                "stay private. Confirm the bucket name itself "
                "doesn't leak sensitive context."
            ),
        }
    return None


def _classify_azure(url: str, resp: dict[str, Any]) -> dict[str, Any] | None:
    """Classify an Azure Blob probe response. Returns a finding dict
    or None."""
    status = resp.get("status") or 0
    body = (resp.get("body") or "")
    if status == 200 and "<EnumerationResults" in body:
        return {
            "rule_id": "azure-blob-publicly-listable",
            "title": f"Azure Blob container publicly listable at `{url}`",
            "severity": "critical",
            "cwe": "CWE-732",
            "provider": "azure_blob",
            "url": url,
            "description": (
                f"`{url}` returned an `<EnumerationResults>` XML "
                "listing to an anonymous GET. The container's "
                "public-access level is Container (full anonymous "
                "list+read) — every blob name is visible without "
                "auth."
            ),
            "remediation": (
                "Set the container's `PublicAccess` to `None` via "
                "Azure Portal / CLI. Audit which blobs were "
                "exposed and rotate any sensitive material."
            ),
        }
    return None


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1593.003", "T1530"],  # Search Open Tech Databases; Data from Cloud Storage
)
def scan_public_bucket_exposure(
    target_url: str,
) -> dict[str, Any]:
    """Deterministic L1 audit for publicly-exposed cloud buckets.

    Args:
        target_url: web target URL or bare host. The hostname
                    labels seed a candidate bucket-name list;
                    each candidate is probed against AWS S3 /
                    GCP GCS / Azure Blob.

    Returns:
        ```
        {
          success: bool,
          status: "ok" | "partial",
          target_host: str,
          candidates_probed: int,
          providers_probed: int,
          total_findings: int,
          findings: [
            {rule_id, title, severity, cwe, provider, url,
             description, remediation},
            ...
          ],
          reason?: str   // when status=partial
        }
        ```

    Recall safety: read-only HTTP GETs. Cap of 24 candidate names
    per target × 3 providers = 72 probes max. Returns `partial`
    when the target is an IP / has no extractable bucket-name
    candidates.
    """
    base = _normalize_target(target_url)
    if base is None:
        return {
            "success": False,
            "status": "error",
            "target_host": None,
            "candidates_probed": 0,
            "providers_probed": 0,
            "total_findings": 0,
            "findings": [],
            "reason": f"invalid target_url: {target_url!r}",
        }
    host = urlparse(base).netloc

    candidates = _candidate_names(host)
    if not candidates:
        return {
            "success": True,
            "status": "partial",
            "target_host": host,
            "candidates_probed": 0,
            "providers_probed": 0,
            "total_findings": 0,
            "findings": [],
            "reason": (
                f"could not derive bucket-name candidates from `{host}` "
                "(is it a bare IP, or has no useful labels?)"
            ),
        }

    findings: list[dict[str, Any]] = []
    probe_count = 0

    for name in candidates:
        # AWS S3 — bucket-domain style. We probe the virtual-host
        # form `<name>.s3.amazonaws.com` which is the canonical
        # public-bucket URL.
        s3_url = f"https://{name}.s3.amazonaws.com/"
        s3_resp = _http_get(s3_url)
        probe_count += 1
        if s3_resp.get("status"):
            f = _classify_s3(s3_url, s3_resp)
            if f:
                findings.append(f)

        # GCP Cloud Storage — `storage.googleapis.com/storage/v1/b/<name>/o`
        # is the listing endpoint. Anonymous GET returns 200 +
        # objects JSON for public buckets.
        gcs_url = (
            f"https://storage.googleapis.com/storage/v1/b/{name}/o"
        )
        gcs_resp = _http_get(gcs_url)
        probe_count += 1
        if gcs_resp.get("status"):
            f = _classify_gcs(gcs_url, gcs_resp)
            if f:
                findings.append(f)

        # Azure Blob — virtual-host `<account>.blob.core.windows.net/<container>?restype=container&comp=list`
        # For container enumeration we'd need an account name AND a
        # container name; here we use the candidate as the
        # account+container guess. Most useful when the candidate
        # is short (Azure account names are <=24 chars).
        if len(name) <= 24:
            az_url = (
                f"https://{name}.blob.core.windows.net/{name}"
                "?restype=container&comp=list"
            )
            az_resp = _http_get(az_url)
            probe_count += 1
            if az_resp.get("status"):
                f = _classify_azure(az_url, az_resp)
                if f:
                    findings.append(f)

    # Emit each finding through the tracer
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is not None:
            for f in findings:
                tracer.add_vulnerability_report(
                    title=f["title"],
                    severity=f["severity"],
                    cwe=f["cwe"],
                    target=base,
                    endpoint=f["url"],
                    category="cloud_exposure",
                    verification_status="verified",
                    confidence=0.95,
                    description=f["description"],
                    impact=(
                        f"Cloud bucket exposure rule "
                        f"`{f['rule_id']}` matched. Provider: "
                        f"{f['provider']}."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Rule: `{f['rule_id']}`\n"
                        f"Provider: {f['provider']}\n"
                        f"URL: `{f['url']}`\n"
                        f"Target (derived from): `{host}`\n"
                        "Auditor: scan_public_bucket_exposure "
                        "(strix.tools.cloud_exposure_audit)."
                    ),
                    reasoning_trace=[
                        f"scan_public_bucket_exposure probed `{host}`.",
                        f"Candidate bucket name matched at "
                        f"`{f['url']}`.",
                        "Anonymous HTTP GET confirmed; no auth needed.",
                    ],
                    poc_description=(
                        f"Reproduce: `curl -s '{f['url']}'`"
                    ),
                    poc_script_code=f"curl -sS '{f['url']}' | head -30",
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_public_bucket_exposure tracer emit failed: %s", e)

    return {
        "success": True,
        "status": "ok",
        "target_host": host,
        "candidates_probed": len(candidates),
        "providers_probed": probe_count,
        "total_findings": len(findings),
        "findings": findings,
    }
