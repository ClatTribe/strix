"""Prowler wrapper — primary CSPM engine.

Prowler (Apache 2.0, multi-cloud, 500+ checks) is the most direct
"Nuclei for cloud" analog. We wrap it the same way strix wraps
`gitleaks` (secrets), `trivy` (containers), `cosign` (signatures):

  * Detect the binary via `shutil.which`.
  * Run with JSON-OCSF output to a temp directory.
  * Parse the OCSF schema into `CspmFinding`.
  * Fail open — if Prowler isn't installed, callers fall back to
    the built-in boto3 checks (`strix.cspm.aws.scanner`).

Why OCSF (not native JSON):
  * Prowler v4+ standardises on OCSF (Open Cybersecurity Schema
    Framework). The legacy `json` format is deprecated.
  * OCSF carries cloud provider / account / region in a stable
    schema that doesn't shift per release.
  * It includes the per-finding compliance dict
    (`unmapped.compliance`) — Prowler already knows which CIS /
    SOC 2 / NIST controls each check attests, so we union those
    into the strix compliance overlay rather than re-deriving.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from strix.compliance.frameworks import (
    FRAMEWORK_CIS_AWS,
    FRAMEWORK_CIS_AZURE,
    FRAMEWORK_CIS_GCP,
    FRAMEWORK_CIS_KUBERNETES,
    FRAMEWORK_GDPR,
    FRAMEWORK_HIPAA,
    FRAMEWORK_ISO27001,
    FRAMEWORK_NIST_800_53,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
)
from strix.cspm.aws import CspmFinding


logger = logging.getLogger(__name__)


# Default timeout — typical multi-region AWS scan is 5-15 minutes.
# Caller can override for huge accounts.
_DEFAULT_TIMEOUT_SECONDS = 1800

# Supported providers. Prowler also supports kubernetes / m365;
# expose those when we add their compliance catalogs.
SUPPORTED_PROVIDERS = ("aws", "azure", "gcp", "kubernetes")


@dataclass
class ProwlerScanResult:
    """One Prowler invocation's outcome."""
    provider: str
    findings: list[CspmFinding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Availability detection
# ---------------------------------------------------------------------------


def is_prowler_available() -> bool:
    """True when `prowler` is on $PATH. Used by the dispatch
    specialist to decide whether to shell out or use built-in
    boto3 checks."""
    return shutil.which("prowler") is not None


def get_prowler_version() -> str | None:
    """Return the installed Prowler version string, or None when
    the binary isn't present / the call fails. Used in tool
    metadata so customers know which check corpus they got."""
    if not is_prowler_available():
        return None
    try:
        proc = subprocess.run(
            ["prowler", "--version"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        out = (proc.stdout or proc.stderr or "").strip()
        # `Prowler 4.5.0` → 4.5.0
        for tok in out.split():
            if tok and tok[0].isdigit():
                return tok
        return out or None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


# ---------------------------------------------------------------------------
# Severity / framework translation
# ---------------------------------------------------------------------------


# Prowler OCSF severity strings → strix severity ladder.
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    "unknown": "low",
}


def _translate_severity(s: str | None) -> str:
    if not s:
        return "medium"
    return _SEVERITY_MAP.get(s.strip().lower(), "medium")


def _translate_provider(p: str | None) -> str | None:
    if not p:
        return None
    p = p.strip().lower()
    if p in ("aws", "amazon", "amazon web services"):
        return "aws"
    if p in ("azure", "microsoft", "microsoft azure"):
        return "azure"
    if p in ("gcp", "google", "google cloud"):
        return "gcp"
    if p in ("kubernetes", "k8s"):
        return "kubernetes"
    return p


def _translate_framework(key: str, provider: str | None) -> str | None:
    """Map a Prowler compliance-key + provider → a strix
    framework constant. Returns None when there's no strix
    catalog for it (FedRAMP, ENS, AWS-Foundational, etc.) —
    caller skips those gracefully."""
    k = (key or "").upper().replace("_", "-")
    # CIS keys disambiguate by provider — Prowler doesn't suffix
    # the framework name with the provider, but the compliance
    # file the check belongs to does.
    if k.startswith("CIS"):
        return {
            "aws": FRAMEWORK_CIS_AWS,
            "azure": FRAMEWORK_CIS_AZURE,
            "gcp": FRAMEWORK_CIS_GCP,
            "kubernetes": FRAMEWORK_CIS_KUBERNETES,
        }.get(provider or "")
    if "SOC-2" in k or k.startswith("SOC2"):
        return FRAMEWORK_SOC2
    if "ISO-27001" in k or k.startswith("ISO27001"):
        return FRAMEWORK_ISO27001
    if "PCI" in k:
        return FRAMEWORK_PCI_DSS
    if "HIPAA" in k:
        return FRAMEWORK_HIPAA
    if "GDPR" in k:
        return FRAMEWORK_GDPR
    if "NIST-800-53" in k:
        return FRAMEWORK_NIST_800_53
    # FedRAMP / ENS / AWS-Foundational / Well-Architected:
    # no strix catalog yet — skip rather than mis-map.
    return None


def _extract_compliance(
    unmapped: dict[str, Any], provider: str | None,
) -> dict[str, list[str]]:
    """Pull Prowler's `unmapped.compliance` dict + translate
    framework keys to strix constants. Drops un-translatable
    frameworks rather than mis-bucketing them."""
    raw = unmapped.get("compliance") or {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key, ctrls in raw.items():
        fw = _translate_framework(str(key), provider)
        if fw is None or not isinstance(ctrls, list):
            continue
        ids = sorted({str(c).strip() for c in ctrls if c})
        if ids:
            out.setdefault(fw, []).extend(ids)
    return {fw: sorted(set(ids)) for fw, ids in out.items()}


# ---------------------------------------------------------------------------
# OCSF parser
# ---------------------------------------------------------------------------


def parse_prowler_ocsf(content: str | dict | list) -> list[CspmFinding]:
    """Parse Prowler OCSF JSON output → CspmFinding list.

    Accepts either a JSON string, an already-parsed list, or a
    single object. Robust to missing optional fields — OCSF is a
    superset schema and not every check populates every field.

    Only FAIL findings are emitted (PASS / MANUAL are dropped).
    """
    if isinstance(content, str):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
    else:
        data = content

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []

    out: list[CspmFinding] = []
    for item in data:
        finding = _parse_one_ocsf(item)
        if finding is not None:
            out.append(finding)
    return out


def _parse_one_ocsf(item: Any) -> CspmFinding | None:
    if not isinstance(item, dict):
        return None

    status = (item.get("status_code") or "").upper()
    if status != "FAIL":
        # PASS / MANUAL / SKIP — not actionable as findings.
        return None

    cloud = item.get("cloud") or {}
    provider = _translate_provider(cloud.get("provider"))
    account_uid = (cloud.get("account") or {}).get("uid")
    region = cloud.get("region") or None

    unmapped = item.get("unmapped") or {}
    check_id = (
        unmapped.get("check_id")
        or unmapped.get("CheckID")
        or (item.get("finding_info") or {}).get("uid")
        or "unknown"
    )
    service = (
        unmapped.get("service_name")
        or unmapped.get("ServiceName")
        or "unknown"
    )

    # Resource — first entry's UID is the canonical ARN.
    resources = item.get("resources") or []
    if resources and isinstance(resources, list) and isinstance(resources[0], dict):
        resource_arn = (
            resources[0].get("uid")
            or resources[0].get("name")
            or "unknown"
        )
    else:
        resource_arn = "unknown"

    # Title + risk = the message body. Title is short; risk is
    # the why; both useful.
    fi = item.get("finding_info") or {}
    title = fi.get("title") or check_id
    desc = (
        item.get("risk_details")
        or fi.get("desc")
        or unmapped.get("status_extended")
        or unmapped.get("StatusExtended")
        or ""
    )
    message = f"{title} — {desc}" if desc else title
    # OCSF status_extended is often the most actionable per-resource
    # message ("S3 Bucket mybucket has public access set to true").
    # If we have it, prefer it.
    status_ext = (
        unmapped.get("status_extended")
        or unmapped.get("StatusExtended")
    )
    if status_ext:
        message = str(status_ext)

    severity = _translate_severity(item.get("severity"))
    compliance = _extract_compliance(unmapped, provider)

    metadata: dict[str, Any] = {
        "source": "prowler",
        "check_id": check_id,
        "check_title": title,
    }
    if compliance:
        # Stash so the emit path can attach as `compliance_controls`
        # directly — bypassing the strix CWE/category lookup that
        # would only produce a strict subset.
        metadata["prowler_compliance"] = compliance
    # Preserve helpful Prowler context for downstream renderers.
    if unmapped.get("categories"):
        metadata["categories"] = unmapped.get("categories")
    if item.get("remediation"):
        metadata["remediation"] = item.get("remediation")
    if unmapped.get("related_url") or unmapped.get("RelatedUrl"):
        metadata["related_url"] = (
            unmapped.get("related_url") or unmapped.get("RelatedUrl")
        )

    return CspmFinding(
        rule_id=f"prowler:{check_id}",
        severity=severity,
        message=message,
        service=str(service),
        region=region if region and region != "global" else None,
        resource_arn=str(resource_arn),
        account_id=str(account_uid) if account_uid else None,
        cwe=None,           # Prowler doesn't emit CWE — compliance is its taxonomy.
        category="misconfig",
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Subprocess invocation
# ---------------------------------------------------------------------------


def _build_prowler_argv(
    *,
    provider: str,
    output_dir: Path,
    output_basename: str,
    profile: str | None,
    role_arn: str | None,
    regions: list[str] | None,
    checks: list[str] | None,
    services: list[str] | None,
    compliance: list[str] | None,
    extra_args: list[str] | None,
) -> list[str]:
    """Build the Prowler argv. Kept pure for unit-testing."""
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"unsupported provider {provider!r}; "
            f"expected one of {SUPPORTED_PROVIDERS}"
        )

    argv: list[str] = [
        "prowler", provider,
        "--output-formats", "json-ocsf",
        "--output-directory", str(output_dir),
        "--output-filename", output_basename,
        "--no-banner",
        "--status", "FAIL",
    ]

    # Provider-specific auth flags.
    if provider == "aws":
        if profile:
            argv += ["--profile", profile]
        if role_arn:
            argv += ["--role", role_arn]
        if regions:
            argv += ["--filter-region", *regions]

    if checks:
        argv += ["--check", *checks]
    if services:
        argv += ["--service", *services]
    if compliance:
        argv += ["--compliance", *compliance]

    if extra_args:
        argv += list(extra_args)
    return argv


def _find_ocsf_output(output_dir: Path, basename: str) -> Path | None:
    """Prowler writes `<basename>.ocsf.json` (sometimes with a
    timestamp suffix depending on version). Return the first match."""
    candidates = list(output_dir.glob(f"{basename}.ocsf.json"))
    if candidates:
        return candidates[0]
    # v4 may suffix with timestamp / extra dot — match liberally.
    candidates = list(output_dir.glob(f"{basename}*.ocsf.json"))
    if candidates:
        return sorted(candidates)[-1]
    # Last resort: any ocsf.json in the dir.
    candidates = list(output_dir.glob("*.ocsf.json"))
    if candidates:
        return sorted(candidates)[-1]
    return None


def run_prowler(
    *,
    provider: str = "aws",
    profile: str | None = None,
    role_arn: str | None = None,
    regions: list[str] | None = None,
    checks: list[str] | None = None,
    services: list[str] | None = None,
    compliance: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    env_overrides: dict[str, str] | None = None,
    _subprocess_run=subprocess.run,   # injectable for tests
) -> ProwlerScanResult:
    """Invoke Prowler, parse its OCSF output, return findings.

    Args:
        provider: `aws` / `azure` / `gcp` / `kubernetes`.
        profile / role_arn: AWS-only auth pass-through.
        regions: optional region filter (AWS only).
        checks: optional Prowler `--check` list (run a subset).
        services: optional Prowler `--service` list.
        compliance: optional Prowler `--compliance` framework list
            (e.g. `["cis_3.0_aws", "soc2"]`) — when set, Prowler
            only runs checks that map to those frameworks.
        env_overrides: extra env vars to pass to the child
            process (AZURE_*, GOOGLE_APPLICATION_CREDENTIALS,
            AWS_*, etc.).
        _subprocess_run: dependency injection for tests.

    Returns:
        `ProwlerScanResult` — findings (only FAIL), per-invocation
        errors, metadata (return code, version, raw output path).
    """
    if not is_prowler_available():
        return ProwlerScanResult(
            provider=provider,
            errors=[{"source": "prowler",
                     "error": "prowler binary not on PATH"}],
        )

    metadata: dict[str, Any] = {"prowler_version": get_prowler_version()}

    with tempfile.TemporaryDirectory(prefix="strix-prowler-") as tmp:
        output_dir = Path(tmp)
        basename = "strix-scan"
        argv = _build_prowler_argv(
            provider=provider,
            output_dir=output_dir,
            output_basename=basename,
            profile=profile,
            role_arn=role_arn,
            regions=regions,
            checks=checks,
            services=services,
            compliance=compliance,
            extra_args=extra_args,
        )
        env = os.environ.copy()
        if env_overrides:
            env.update(env_overrides)

        try:
            proc = _subprocess_run(
                argv,
                capture_output=True, text=True,
                timeout=timeout_seconds, check=False, env=env,
            )
        except subprocess.TimeoutExpired:
            return ProwlerScanResult(
                provider=provider,
                errors=[{"source": "prowler",
                         "error": f"timed out after {timeout_seconds}s"}],
                metadata=metadata,
            )
        except (FileNotFoundError, OSError) as e:
            return ProwlerScanResult(
                provider=provider,
                errors=[{"source": "prowler",
                         "error": f"subprocess failed: {e}"}],
                metadata=metadata,
            )

        # Prowler exit codes: 0 = no findings, 3 = findings present.
        # Anything else is a real error (auth failure, bad args).
        metadata["prowler_returncode"] = proc.returncode
        if proc.returncode not in (0, 3):
            return ProwlerScanResult(
                provider=provider,
                errors=[{"source": "prowler",
                         "error": (
                             f"non-zero exit ({proc.returncode}): "
                             f"{(proc.stderr or '')[:500]}"
                         )}],
                metadata=metadata,
            )

        output_path = _find_ocsf_output(output_dir, basename)
        if output_path is None:
            return ProwlerScanResult(
                provider=provider,
                errors=[{"source": "prowler",
                         "error": "no OCSF output file produced"}],
                metadata=metadata,
            )
        try:
            content = output_path.read_text(encoding="utf-8")
        except OSError as e:
            return ProwlerScanResult(
                provider=provider,
                errors=[{"source": "prowler",
                         "error": f"read output failed: {e}"}],
                metadata=metadata,
            )

    findings = parse_prowler_ocsf(content)
    return ProwlerScanResult(
        provider=provider,
        findings=findings,
        metadata=metadata,
    )
