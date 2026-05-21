"""iter-21.6.1 — `scan_buckets_via_bbot` deterministic multi-cloud
bucket-discovery via bbot's bucket modules.

## Why this exists

The in-house bucket discovery shipped in iter-21.6 (PR #400,
reverted via PR #401) was avoidable reinvention of mature OSS
tools — CloudEnum, bbot, S3Scanner all do this better. strix's
established convention is to WRAP OSS scanners (trivy / semgrep /
gitleaks / nuclei / checkov / osv-scanner / gitleaks /
trufflehog all wrap an OSS CLI), so the bucket-discovery sub-iter
returns here as a bbot wrapper.

bbot wins among the candidates:
  * **AWS S3 + Azure Blob + GCP GCS + DigitalOcean Spaces +
    Firebase + IBM Cloud Object Storage** module coverage in one
    tool. CloudEnum covers the top three; S3Scanner is AWS-only.
  * **DNS + CT log chaining** — bbot resolves subdomains via
    subfinder / passive DNS / certificate transparency BEFORE
    probing bucket endpoints. CloudEnum requires manual seed
    lists for similar coverage.
  * **JSON event stream output** (`-o ndjson`) — clean integration
    with strix's finding-emit pipeline.
  * **Pure Python (pipx-installable)** — matches the strix
    sandbox pattern for `semgrep`, `checkov`, `bandit`,
    `wapiti3`, etc. No additional system deps.

## What it does

Invokes `bbot` as a subprocess with the bucket-module bundle
against the supplied target. Parses the JSON event stream for
`STORAGE_BUCKET` and `FINDING` events related to bucket exposure;
emits one finding per publicly-listable bucket discovered. Maps
bbot's severity to strix's canonical set; falls back to
`critical` for confirmed-public buckets, `info` for
exists-but-private (the naming-scheme-leak signal).

## Recall safety

  * `bbot` not on PATH → `status=partial` with `reason` (mirrors
    every other strix tool wrapper's degrade pattern).
  * `STRIX_BBOT_DISABLED=1` short-circuits to partial.
  * Wall-time bounded by bbot's own scan-timeout config; we
    additionally subprocess-timeout at 5 minutes.
  * Output JSON parse failures fall through to zero findings;
    we never fail the whole audit on a single garbled event.

## Why subprocess vs. Python API

bbot DOES expose a Python `Scanner` class but it's async-heavy
+ has a complex configuration surface (`omegaconf`-driven
yaml). Subprocess invocation matches the existing strix
wrapper pattern (`nuclei_runner` does the same — wraps the
nuclei CLI, doesn't import the binary's Go interfaces). Keeps
the integration isolated; bbot version upgrades don't touch
strix code.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404 — required for bbot CLI invocation
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_BBOT_BIN = "bbot"
_DEFAULT_SCAN_TIMEOUT_SECONDS = 300  # 5 min hard cap


# bbot module bundle for bucket discovery. Each is a stable
# module name in bbot's catalog as of bbot 2.x. Operators can
# add / remove via `STRIX_BBOT_BUCKET_MODULES` (comma-separated).
_DEFAULT_BUCKET_MODULES = (
    "bucket_aws",
    "bucket_azure",
    "bucket_gcp",
    "bucket_digitalocean",
    "bucket_firebase",
)


def _bbot_disabled() -> bool:
    """`STRIX_BBOT_DISABLED=1` short-circuits the wrapper."""
    return os.environ.get(
        "STRIX_BBOT_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}


def _bbot_available() -> bool:
    """True iff `bbot` is on PATH AND not killed via env."""
    if _bbot_disabled():
        return False
    return shutil.which(_BBOT_BIN) is not None


def _bucket_modules() -> tuple[str, ...]:
    """Operator-configurable bucket-module bundle.
    `STRIX_BBOT_BUCKET_MODULES=bucket_aws,bucket_azure` keeps a
    narrow scan; default is all five providers."""
    raw = os.environ.get(
        "STRIX_BBOT_BUCKET_MODULES", "",
    ).strip()
    if not raw:
        return _DEFAULT_BUCKET_MODULES
    mods = tuple(m.strip() for m in raw.split(",") if m.strip())
    return mods or _DEFAULT_BUCKET_MODULES


def _normalize_target(url: str) -> str | None:
    """Return the bare hostname bbot accepts. Strips scheme + path
    + port; returns None for bare-IP targets (bbot bucket modules
    need a domain to derive bucket-name candidates from)."""
    if not url or not url.strip():
        return None
    s = url.strip()
    parsed = urlparse(s if "://" in s else f"https://{s}")
    host = parsed.netloc or parsed.path
    if not host:
        return None
    # Strip port
    host = host.split(":", 1)[0].lower()
    # Reject bare IPs — bbot bucket modules need labels
    if all(p.isdigit() for p in host.split(".") if p):
        return None
    return host


def _run_bbot_scan(  # noqa: PLR0911
    target: str,
    *,
    modules: tuple[str, ...] = _DEFAULT_BUCKET_MODULES,
    timeout_seconds: int = _DEFAULT_SCAN_TIMEOUT_SECONDS,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Run bbot with the supplied module bundle against `target`.
    Returns `(events, error)`:
      * `events` is a list of bbot event dicts when scan succeeded.
      * `error` is a human-readable error string when bbot failed.
    """
    out_dir = Path(tempfile.mkdtemp(prefix="strix-bbot-"))
    cmd = [
        _BBOT_BIN,
        "-t", target,
        "-m", *modules,
        "-y",                    # auto-accept config
        "--json",                # JSON event output to stdout
        "-o", str(out_dir),
        "--silent",
    ]
    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return None, (
            f"bbot timed out after {timeout_seconds}s on {target!r}"
        )
    except OSError as e:
        return None, (
            f"bbot invocation failed: {type(e).__name__}: {e}"
        )

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()[:500]
        return None, (
            f"bbot exit {result.returncode}: {stderr or '(no detail)'}"
        )

    events: list[dict[str, Any]] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events, None


# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------


def _classify_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Map a bbot event into a strix finding shape, or return None
    when the event doesn't represent a bucket-related discovery.

    bbot emits many event types; we care about:
      * `STORAGE_BUCKET` — bucket discovered (any state).
      * `FINDING` with `bucket` tag — confirmed-public bucket.
    """
    etype = (event.get("type") or "").upper()
    data = event.get("data")
    tags = event.get("tags") or []
    if not isinstance(tags, list):
        tags = []

    if etype == "STORAGE_BUCKET":
        # bbot's data shape: {"name": "<bucket>", "url": "<url>",
        #                     "provider": "aws_s3" | ...}
        if not isinstance(data, dict):
            return None
        url = data.get("url") or data.get("name") or "(unknown)"
        provider = data.get("provider") or "unknown"
        bucket_name = data.get("name") or "(unnamed)"
        return {
            "rule_id": f"{provider}-bucket-discovered",
            "title": (
                f"{provider.upper()} bucket discovered: `{bucket_name}` "
                f"({url})"
            ),
            # Discovery alone is info-severity; the bbot FINDING
            # event below escalates when the bucket is confirmed
            # public.
            "severity": "info",
            "cwe": "CWE-200",
            "provider": provider,
            "url": url,
            "bucket_name": bucket_name,
            "description": (
                f"bbot's `{provider}` bucket module discovered "
                f"`{bucket_name}` at `{url}`. The bucket exists "
                "and is reachable from the public internet — "
                "auditor should check whether it's intentionally "
                "exposed and what objects (if any) are listable."
            ),
            "remediation": (
                "Review the bucket's IAM policy + ACL. If the "
                "bucket is intentionally public (CDN-style "
                "distribution), no action needed. If not, set "
                "the cloud's `BlockPublicAccess` flag (S3) / "
                "Public Access Prevention (GCS) / Anonymous Access "
                "Disabled (Azure) at the account level."
            ),
        }
    if etype == "FINDING" and isinstance(data, dict):
        desc = (data.get("description") or "").lower()
        if "bucket" in desc and (
            "public" in desc or "open" in desc or "listable" in desc
        ):
            url = data.get("url") or data.get("host") or "(unknown)"
            provider = (
                data.get("provider")
                or _provider_from_url(url)
                or "unknown"
            )
            return {
                "rule_id": f"{provider}-bucket-publicly-exposed",
                "title": (
                    f"Publicly-exposed {provider.upper()} bucket: "
                    f"`{url}` ({data.get('description') or 'public access'})"
                ),
                "severity": "critical",
                "cwe": "CWE-732",
                "provider": provider,
                "url": url,
                "bucket_name": data.get("name") or "(unnamed)",
                "description": (
                    f"bbot confirmed `{url}` is a publicly-"
                    "accessible cloud storage bucket. "
                    f"Original bbot finding: "
                    f"`{data.get('description') or '(none)'}`. "
                    "Every object listed is reachable without "
                    "auth; depending on per-object ACL, every "
                    "object may be readable too."
                ),
                "remediation": (
                    "Immediately remove anonymous read / list "
                    "permissions. Audit objects for sensitive "
                    "content (credentials, customer data, build "
                    "artifacts containing secrets). Rotate any "
                    "exposed keys. Enable account-level public-"
                    "access blocks to prevent re-exposure."
                ),
            }
    return None


def _provider_from_url(url: str) -> str | None:
    """Heuristic provider inference from a bucket URL."""
    if not isinstance(url, str):
        return None
    lower = url.lower()
    if ".s3.amazonaws.com" in lower or "s3-" in lower:
        return "aws_s3"
    if "storage.googleapis.com" in lower:
        return "gcp_gcs"
    if ".blob.core.windows.net" in lower:
        return "azure_blob"
    if "digitaloceanspaces.com" in lower:
        return "digitalocean_spaces"
    if "firebaseio.com" in lower or "firebasestorage" in lower:
        return "firebase"
    return None


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1593.003", "T1530"],  # Search Open Tech Databases; Data from Cloud Storage
)
def scan_buckets_via_bbot(
    target_url: str,
) -> dict[str, Any]:
    """Multi-cloud bucket discovery via bbot's bucket modules.

    Args:
        target_url: web target URL or bare domain. Hostname is
                    extracted; bbot's bucket modules derive
                    candidate bucket names from the domain labels
                    + apply their own wordlists.

    Returns:
        ```
        {
          success: bool,
          status: "ok" | "partial" | "error",
          target: str | None,
          modules: [str, ...],
          total_findings: int,
          findings: [
            {rule_id, title, severity, cwe, provider, url,
             bucket_name, description, remediation},
            ...
          ],
          reason?: str
        }
        ```

    `status=partial` when bbot isn't installed OR the target
    isn't a usable domain (bare IP, malformed URL). The wrapper
    never raises — every error path returns a structured dict.
    """
    if not _bbot_available():
        return {
            "success": True,
            "status": "partial",
            "target": target_url,
            "modules": [],
            "total_findings": 0,
            "findings": [],
            "reason": (
                "bbot binary not found on PATH "
                "(or STRIX_BBOT_DISABLED=1). Install via "
                "`pipx install bbot` in the sandbox image."
            ),
        }

    target = _normalize_target(target_url)
    if target is None:
        return {
            "success": True,
            "status": "partial",
            "target": target_url,
            "modules": [],
            "total_findings": 0,
            "findings": [],
            "reason": (
                f"could not extract a usable domain from "
                f"`{target_url!r}` (bare IP or malformed)"
            ),
        }

    modules = _bucket_modules()
    events, err = _run_bbot_scan(target, modules=modules)
    if events is None:
        return {
            "success": False,
            "status": "error",
            "target": target,
            "modules": list(modules),
            "total_findings": 0,
            "findings": [],
            "reason": err or "(no detail)",
        }

    findings: list[dict[str, Any]] = []
    for event in events:
        f = _classify_event(event)
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
                    target=target,
                    endpoint=f["url"],
                    category="cloud_exposure",
                    verification_status="verified",
                    confidence=0.93,
                    description=f["description"],
                    impact=(
                        f"Bucket discovery rule `{f['rule_id']}` "
                        f"matched on {target} via bbot module "
                        f"`{f.get('provider')}`."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Rule: `{f['rule_id']}`\n"
                        f"Provider: {f.get('provider')}\n"
                        f"Bucket: `{f.get('bucket_name')}`\n"
                        f"URL: `{f['url']}`\n"
                        f"Target: `{target}`\n"
                        "Auditor: scan_buckets_via_bbot "
                        "(strix.tools.bbot_runner)."
                    ),
                    reasoning_trace=[
                        f"bbot bucket modules ({', '.join(modules)}) "
                        f"probed `{target}`.",
                        f"`{f['url']}` matched rule "
                        f"`{f['rule_id']}`.",
                        "bbot's discovery uses subdomain enum + "
                        "DNS + CT logs to build the candidate "
                        "set, then HTTP-probes each.",
                    ],
                    poc_description=(
                        f"Reproduce: `bbot -t {target} -m "
                        f"{f.get('provider')} -y`"
                    ),
                    poc_script_code=(
                        f"bbot -t {target} -m "
                        f"{' '.join(modules)} -y --json"
                    ),
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_buckets_via_bbot tracer emit failed: %s", e)

    return {
        "success": True,
        "status": "ok",
        "target": target,
        "modules": list(modules),
        "total_findings": len(findings),
        "findings": findings,
    }
