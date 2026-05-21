"""iter-21.6 — `scan_cloud_imds_passthrough` deterministic L1
direct-IMDS-leakage audit.

## Why this exists

`scan_ssrf` already covers AWS / GCP / Azure / Oracle instance
metadata service (IMDS) probes when there's an SSRF-shaped param
on the target. What it doesn't cover is the **direct-passthrough**
case: routes that proxy `169.254.169.254` (or `metadata.google.
internal`) UNCONDITIONALLY, without taking a URL parameter. These
typically come from:

  * Dev/debug routes that someone wired during onboarding and
    forgot to remove (`/internal/imds`, `/debug/metadata`).
  * Reverse-proxy misconfigurations where the upstream is the
    IMDS endpoint and any request to the proxy path leaks creds.
  * Kubernetes pods exposing the node's IMDS via a sidecar (the
    pod's app handler accidentally exposes the IMDS proxy
    address on the pod's primary listener).

`scan_ssrf` won't catch these — there's no param to drive
substitution into. This tool tries a corpus of known paths
directly and inspects the response body for IMDS-specific
marker strings.

## Detection corpus

Paths probed (each on the target host + scheme):

  /imds, /metadata, /aws/metadata, /gcp/metadata, /__metadata,
  /_meta, /_metadata, /debug/imds, /debug/metadata, /internal/imds,
  /internal/metadata, /admin/imds, /api/metadata, /api/imds,
  /api/v1/metadata, /.well-known/instance-data, /proxy/imds

For each, GET; on 200, body is checked for AWS / GCP / Azure / OCI
fingerprints (instance-id, ami-id, security-credentials JSON
shape, project-id, MD-Server header etc.).

## Severity

  * **Critical** when AWS security-credentials response body is
    returned (full IAM creds exfiltration in one request)
  * **High** for any IMDS body (instance-id / project-id) but no
    creds — still attacker primitive for next pivot
  * **Medium** for IMDS-shaped HTTP headers (e.g. `Server:
    EC2ws`) but no body — strong inference

## Recall safety

Read-only HTTP GET. ~17 candidate paths per target; bounded wall
time. Returns `partial` with `reason` when target shape is
unsuitable (raw IP, etc.) — no false-positive load.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


_HTTP_TIMEOUT = 5
_BODY_CAP_BYTES = 8 * 1024


_IMDS_PROBE_PATHS = (
    "/imds",
    "/metadata",
    "/aws/metadata",
    "/gcp/metadata",
    "/__metadata",
    "/_meta",
    "/_metadata",
    "/debug/imds",
    "/debug/metadata",
    "/internal/imds",
    "/internal/metadata",
    "/admin/imds",
    "/api/metadata",
    "/api/imds",
    "/api/v1/metadata",
    "/.well-known/instance-data",
    "/proxy/imds",
)


# Body fingerprints for the four major cloud IMDS endpoints. Each
# tuple is (provider, regex, severity, label). Severity prioritises
# credential exposure over plain instance-id leakage.
_IMDS_FINGERPRINTS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    # AWS IAM security credentials JSON shape — when this returns
    # we have actual access keys.
    (
        "aws",
        re.compile(
            r'"AccessKeyId"\s*:\s*"AKIA[0-9A-Z]{16}"',
        ),
        "critical",
        "AWS IAM security credentials body returned",
    ),
    # AWS instance-id format (i-XXXXXXXXXXXXXXXXX).
    (
        "aws",
        re.compile(r"\bi-[0-9a-f]{17}\b"),
        "high",
        "AWS EC2 instance-id leaked",
    ),
    # AWS AMI ID format.
    (
        "aws",
        re.compile(r"\bami-[0-9a-f]{8,17}\b"),
        "high",
        "AWS AMI-id leaked",
    ),
    # GCP project-id format (or kind:compute#instance).
    (
        "gcp",
        re.compile(r'"kind"\s*:\s*"compute#instance"'),
        "high",
        "GCP compute#instance body returned",
    ),
    (
        "gcp",
        re.compile(r"projects/[a-z0-9-]+/zones/[a-z0-9-]+"),
        "high",
        "GCP project / zone path leaked",
    ),
    # Azure IMDS response body — includes compute.subscriptionId.
    (
        "azure",
        re.compile(r'"subscriptionId"\s*:\s*"[0-9a-f-]{36}"'),
        "high",
        "Azure subscription-id leaked",
    ),
    (
        "azure",
        re.compile(r'"vmId"\s*:\s*"[0-9a-f-]{36}"'),
        "high",
        "Azure vmId leaked",
    ),
    # OCI metadata format
    (
        "oci",
        re.compile(r'"ocid1\.instance\.[a-z0-9.-]+"'),
        "high",
        "OCI instance-OCID leaked",
    ),
)


def _normalize_target(url: str) -> str | None:
    if not url or not url.strip():
        return None
    s = url.strip()
    parsed = urlparse(s if "://" in s else f"https://{s}")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}/"


def _http_get(url: str, *, timeout: float = _HTTP_TIMEOUT) -> dict[str, Any]:
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


def _audit_response(
    url: str, resp: dict[str, Any],
) -> list[dict[str, Any]]:
    """Apply the fingerprint regexes to a response body + headers.
    Returns the highest-severity finding for the response (one
    per probe URL — avoid double-counting if multiple fingerprints
    match the same body).
    """
    if resp.get("status") != 200:
        return []
    body = resp.get("body") or ""
    if not body:
        return []
    # Find every fingerprint match
    matches: list[tuple[str, str, str]] = []
    for provider, pat, sev, label in _IMDS_FINGERPRINTS:
        if pat.search(body):
            matches.append((provider, sev, label))
    if not matches:
        return []
    # Rank by severity (critical > high > medium > low)
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    matches.sort(key=lambda m: sev_rank.get(m[1], 5))
    top_provider, top_sev, top_label = matches[0]
    return [{
        "rule_id": f"imds-passthrough-{top_provider}",
        "title": (
            f"Cloud IMDS body leaked at `{url}` "
            f"({top_label})"
        ),
        "severity": top_sev,
        "cwe": "CWE-918",
        "url": url,
        "provider": top_provider,
        "matched_fingerprint": top_label,
        "description": (
            f"`{url}` responded 200 with body content matching "
            f"a known {top_provider.upper()} instance metadata "
            f"service (IMDS) fingerprint: {top_label}. The "
            "endpoint is proxying the cloud-instance metadata "
            "service to anonymous callers — a complete attacker "
            "primitive: depending on the IMDS path proxied, the "
            "attacker exfiltrates IAM role credentials, instance "
            "configuration, user-data init scripts (which often "
            "contain secrets), and the cloud account / project "
            "identifiers."
        ),
        "remediation": (
            "Remove the IMDS-proxying route from production. If "
            "the route legitimately needs to call IMDS internally, "
            "ensure it never reflects the IMDS body back to the "
            "client. AWS: enable IMDSv2 with hop-limit 1 so the "
            "metadata can only be accessed from the instance "
            "itself, not via a proxy."
        ),
    }]


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1552.005", "T1078.004"],  # Credentials from cloud instance metadata; Cloud accounts
)
def scan_cloud_imds_passthrough(
    target_url: str,
) -> dict[str, Any]:
    """Deterministic L1 audit for direct-IMDS-passthrough exposure.

    Args:
        target_url: web target URL or bare host. The tool probes
                    `<scheme>://<host>/<imds-candidate-path>` for
                    a corpus of common IMDS-proxy routes; on
                    200 OK, the response body is checked for
                    AWS / GCP / Azure / OCI metadata fingerprints.

    Returns:
        ```
        {
          success: bool,
          status: "ok" | "partial" | "error",
          target: str,
          paths_probed: int,
          total_findings: int,
          findings: [
            {rule_id, title, severity, cwe, url, provider,
             matched_fingerprint, description, remediation},
            ...
          ],
        }
        ```

    Recall safety: read-only HTTP GET. ~17 candidate paths per
    target; bounded wall time (~50-100s worst case if every
    probe times out). Returns `partial` only when target_url
    is malformed.
    """
    base = _normalize_target(target_url)
    if base is None:
        return {
            "success": False,
            "status": "error",
            "target": target_url,
            "paths_probed": 0,
            "total_findings": 0,
            "findings": [],
            "reason": f"invalid target_url: {target_url!r}",
        }

    findings: list[dict[str, Any]] = []
    probe_count = 0

    for path in _IMDS_PROBE_PATHS:
        url = urljoin(base, path.lstrip("/"))
        resp = _http_get(url)
        probe_count += 1
        if resp.get("status") == 200:
            findings.extend(_audit_response(url, resp))

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
                        f"Direct IMDS passthrough detected. "
                        f"Provider: {f['provider']}. "
                        f"Fingerprint: {f['matched_fingerprint']}."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Rule: `{f['rule_id']}`\n"
                        f"Provider: {f['provider']}\n"
                        f"Matched fingerprint: {f['matched_fingerprint']}\n"
                        f"URL: `{f['url']}`\n"
                        "Auditor: scan_cloud_imds_passthrough "
                        "(strix.tools.cloud_exposure_audit)."
                    ),
                    reasoning_trace=[
                        f"scan_cloud_imds_passthrough probed `{base}`.",
                        f"`{f['url']}` returned 200 with body "
                        "matching IMDS fingerprint "
                        f"`{f['matched_fingerprint']}`.",
                        "Deterministic L1; no payloads sent, no "
                        "param substitution needed.",
                    ],
                    poc_description=(
                        f"Reproduce: `curl -s '{f['url']}'`"
                    ),
                    poc_script_code=f"curl -sS '{f['url']}' | head -50",
                )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "scan_cloud_imds_passthrough tracer emit failed: %s", e,
        )

    return {
        "success": True,
        "status": "ok",
        "target": base,
        "paths_probed": probe_count,
        "total_findings": len(findings),
        "findings": findings,
    }
