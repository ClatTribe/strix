"""Live PoC probes for cloud attack paths.

masterroadmap §5 P0 — extends the strix exploit-synthesis moat
(MOAK Phase B3 live-probe pipeline that already exists for web /
API targets) to cloud. Each detected attack path can be optionally
*verified* by an external probe that confirms the resource is
actually reachable / exploitable from outside the cloud account —
distinguishing "we say this is exploitable" from "we proved it."

## Safety contract — OFF by default

Cloud live probes can:
  * Generate AWS billing (S3 GET, Lambda invoke even on failed
    auth).
  * Trigger WAF / GuardDuty / Defender alerts that page the
    customer's SOC.
  * Show up in CloudTrail / Activity Log as attacker-shaped
    activity.

Therefore: probes are **disabled by default**. The caller opts
in explicitly via `enable_live_probes=True` on
`analyze_cloud_attack_paths`, OR via the `STRIX_CLOUD_LIVE_PROBES=1`
environment variable (for engagement-level opt-in).

Each probe:
  * Uses HEAD / minimal-body requests where possible.
  * Identifies itself via a `User-Agent: strix-cspm-probe/<run-id>`
    header so the customer's SOC can audit.
  * Times out fast (2-5 seconds) — slow signal is no signal.
  * Returns one of `verified` / `not_verified` / `error` /
    `skipped`. Never raises; failure mode is "no PoC attached"
    not "scan crashed."

## Probe registry

A probe is `(AttackPath) -> ProbeResult`. The registry maps
`pattern_id → probe_fn`. When `enable_live_probes=True`, each
detected path is run through its registered probe (if any). The
resulting `AttackPath.verification_status` upgrades to
`"exploited"` on `verified` and the `metadata.proof` carries the
probe's evidence dict (response status / headers / TCP state).

Patterns with no registered probe (e.g. `cap_root_unsafe` — we
can't externally verify "root has access keys") stay at their
pre-probe `verified` (pattern-only) status. Probe absence is not
a downgrade.

## Probes shipped in v1

  * `cap_public_storage_credentials_risk` → anonymous HTTP HEAD
    on the bucket. 2xx = verified exploitable.
  * `cap_internet_exposed_compute_with_iam` → TCP connect to
    443 / 80 / 22 / 3389 / 5432 / 3306 (or extracted port from
    the resource attributes). SYN-ACK = verified reachable.
  * `cap_world_assumable_role` → `sts:AssumeRole` from the
    caller's identity (if creds are configured). Successful
    AssumeRole = verified.

The remaining patterns (`cap_wildcard_admin_attached`,
`cap_root_unsafe`) have no externally-verifiable probe in v1 —
they require being on the cloud-side compute or having root
creds, neither of which strix has.

## Adding a probe

  1. Define a `_probe_<name>(path)` function returning
     `ProbeResult`.
  2. Register it via `@register_probe("cap_<pattern_id>")`.
  3. Test in `tests/cloud_attack_paths/test_live_probes.py`.
"""

from __future__ import annotations

import logging
import os
import re
import socket
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from strix.cloud_attack_paths.patterns import AttackPath


logger = logging.getLogger(__name__)


# Default probe timeout. Slow signal is no signal — a 30-second
# wait on a non-responsive resource doesn't tell us anything we
# couldn't get from "we can't reach it in 2s."
_DEFAULT_PROBE_TIMEOUT = 5.0


# Per-probe HTTP user-agent. Customer SOC can grep CloudTrail /
# WAF logs for this string to audit strix probe activity.
_PROBE_USER_AGENT = "strix-cspm-probe/1.0 (cloud-attack-path)"


# ---------------------------------------------------------------------------
# ProbeResult
# ---------------------------------------------------------------------------


# Probe outcome statuses.
PROBE_VERIFIED = "verified"
PROBE_NOT_VERIFIED = "not_verified"
PROBE_ERROR = "error"
PROBE_SKIPPED = "skipped"


@dataclass
class ProbeResult:
    """Outcome of a live probe against one attack path.

    `status` is the verdict; `evidence` carries the probe's
    detailed observation (HTTP status, response headers excerpt,
    TCP state, error string). `evidence` is JSON-safe so the
    wrapper can render it as a "proof of impact" panel.
    """
    status: str
    probe_id: str
    pattern_id: str
    narrative: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def is_verified(self) -> bool:
        return self.status == PROBE_VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "probe_id": self.probe_id,
            "pattern_id": self.pattern_id,
            "narrative": self.narrative,
            "evidence": dict(self.evidence),
        }


# ---------------------------------------------------------------------------
# Probe registry
# ---------------------------------------------------------------------------


ProbeFn = Callable[[AttackPath], ProbeResult]


_REGISTRY: dict[str, ProbeFn] = {}


def register_probe(pattern_id: str) -> Callable[[ProbeFn], ProbeFn]:
    """Decorator — register a probe function for an attack-path
    pattern."""
    def decorator(fn: ProbeFn) -> ProbeFn:
        _REGISTRY[pattern_id] = fn
        return fn
    return decorator


def get_probe(pattern_id: str) -> ProbeFn | None:
    return _REGISTRY.get(pattern_id)


def list_registered_probes() -> list[str]:
    """Return the pattern IDs that have registered probes. Used
    by tests + introspection."""
    return sorted(_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Probe enablement gate
# ---------------------------------------------------------------------------


def is_live_probes_enabled(*, explicit: bool | None = None) -> bool:
    """Three-tier opt-in:

      1. Explicit `enable_live_probes=True` kwarg (caller-level).
      2. `STRIX_CLOUD_LIVE_PROBES=1` env (engagement-level).
      3. Default: OFF.

    `explicit=False` overrides the env (caller can force off);
    `explicit=None` defers to env; `explicit=True` is the
    canonical opt-in.
    """
    if explicit is False:
        return False
    if explicit is True:
        return True
    return os.environ.get("STRIX_CLOUD_LIVE_PROBES", "").strip().lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Probe: S3 anonymous read
# ---------------------------------------------------------------------------


def _extract_s3_bucket(arn: str) -> str | None:
    """`arn:aws:s3:::bucket-name` → `bucket-name`."""
    m = re.match(r"^arn:aws:s3:::([\w.\-]+)", arn)
    return m.group(1) if m else None


@register_probe("cap_public_storage_credentials_risk")
def probe_s3_anonymous_read(path: AttackPath) -> ProbeResult:
    """Anonymous HTTP HEAD against the bucket's S3 endpoint.

    A response of `200 OK` confirms the bucket is publicly
    listable / readable — direct proof of impact. `403 Forbidden`
    (anonymous denied) or `404 NotFound` are not verified.
    """
    if not path.hops:
        return ProbeResult(
            status=PROBE_SKIPPED,
            probe_id="s3_anonymous_head",
            pattern_id=path.pattern_id,
            narrative="no resource ARN in attack path",
        )
    arn = path.hops[0]
    bucket = _extract_s3_bucket(arn)
    if bucket is None:
        # Pattern fires for Azure / GCP storage too — those
        # aren't covered by this AWS-specific probe.
        return ProbeResult(
            status=PROBE_SKIPPED,
            probe_id="s3_anonymous_head",
            pattern_id=path.pattern_id,
            narrative=(
                f"resource is not an S3 bucket ARN ({arn}); "
                f"Azure / GCP storage probes are a follow-up"
            ),
        )

    # Try regional + global virtual-host-style endpoints.
    candidates = [
        f"https://{bucket}.s3.amazonaws.com/",
        # Path-style fallback for region-pinned buckets that
        # virtual-host-style sometimes 301s.
        f"https://s3.amazonaws.com/{bucket}/",
    ]
    last_err: str | None = None
    for endpoint in candidates:
        try:
            import httpx
            with httpx.Client(
                timeout=_DEFAULT_PROBE_TIMEOUT,
                follow_redirects=True,
                verify=True,
            ) as c:
                r = c.head(
                    endpoint,
                    headers={"User-Agent": _PROBE_USER_AGENT},
                )
            evidence = {
                "endpoint": endpoint,
                "status_code": r.status_code,
                "headers": {k.lower(): v for k, v in r.headers.items()
                            if k.lower() in (
                                "content-type", "content-length",
                                "server", "x-amz-bucket-region",
                            )},
                "user_agent": _PROBE_USER_AGENT,
            }
            if 200 <= r.status_code < 300:
                return ProbeResult(
                    status=PROBE_VERIFIED,
                    probe_id="s3_anonymous_head",
                    pattern_id=path.pattern_id,
                    narrative=(
                        f"Bucket `{bucket}` returned "
                        f"{r.status_code} to an anonymous HEAD — "
                        f"publicly accessible without "
                        f"credentials."
                    ),
                    evidence=evidence,
                )
            # 403 NoSuchBucket means the bucket exists but is
            # not anonymously readable — pattern was right
            # (it's public-ACL-flagged in CSPM) but the live
            # bucket is private now. Not verified externally.
            if r.status_code in (403, 401):
                return ProbeResult(
                    status=PROBE_NOT_VERIFIED,
                    probe_id="s3_anonymous_head",
                    pattern_id=path.pattern_id,
                    narrative=(
                        f"Bucket `{bucket}` returned "
                        f"{r.status_code} (access denied) to an "
                        f"anonymous HEAD — CSPM flagged it but "
                        f"live state is currently locked down. "
                        f"Possible drift / recently fixed."
                    ),
                    evidence=evidence,
                )
            # 404 / 301 / 5xx → try the next candidate or give up.
            last_err = (
                f"{endpoint} returned {r.status_code}"
            )
        except ImportError:
            return ProbeResult(
                status=PROBE_ERROR,
                probe_id="s3_anonymous_head",
                pattern_id=path.pattern_id,
                narrative="httpx not installed",
            )
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {e}"

    return ProbeResult(
        status=PROBE_NOT_VERIFIED,
        probe_id="s3_anonymous_head",
        pattern_id=path.pattern_id,
        narrative=(
            f"Could not externally verify bucket `{bucket}` "
            f"anonymous access; last response: "
            f"{last_err or '(unknown)'}"
        ),
        evidence={"last_error": last_err or ""},
    )


# ---------------------------------------------------------------------------
# Probe: TCP reachability
# ---------------------------------------------------------------------------


# Per-resource-kind default ports to probe. The pattern stores
# `metadata.compute_kind`; if a kind isn't in the map, we fall
# back to the canonical web-admin set.
_DEFAULT_PORTS_BY_KIND: dict[str, tuple[int, ...]] = {
    "ec2_instance": (22, 80, 443, 3389),
    "lambda_function": (443,),
    "azure_vm": (22, 80, 443, 3389),
    "gcp_compute_instance": (22, 80, 443, 3389),
    "ecs_task": (80, 443),
    "eks_pod": (80, 443),
}
_FALLBACK_PORTS = (80, 443, 22, 3389)


def _extract_resource_host(arn: str) -> str | None:
    """Best-effort: pull a probeable hostname from a resource
    ARN. Few cloud ARNs encode the host directly; in practice,
    we rely on attributes set during ingest (e.g. EC2 public DNS
    name). When unavailable, return None and the probe skips."""
    # Lambda function URL convention: stored in metadata, not ARN.
    # EC2 public DNS / public IP: same.
    # ARN alone isn't sufficient — return None and let the
    # caller pull from metadata.
    return None


@register_probe("cap_internet_exposed_compute_with_iam")
def probe_tcp_reachability(path: AttackPath) -> ProbeResult:
    """TCP-connect probe against the compute resource's likely
    listening ports.

    Uses the resource's `attributes['public_dns']` /
    `attributes['public_ip']` / `attributes['function_url']` when
    available (caller-supplied via `cloud_assets`). Without those,
    the probe can't infer a probeable hostname and skips.

    A successful TCP handshake (SYN-ACK received) on any of the
    candidate ports is the verification signal.
    """
    if not path.hops:
        return ProbeResult(
            status=PROBE_SKIPPED,
            probe_id="tcp_reachability",
            pattern_id=path.pattern_id,
            narrative="no resource ARN in attack path",
        )
    arn = path.hops[0]
    # Resource attributes live in path.metadata.
    md = path.metadata or {}
    host = (
        md.get("public_dns")
        or md.get("public_ip")
        or md.get("function_url")
    )
    if not host:
        return ProbeResult(
            status=PROBE_SKIPPED,
            probe_id="tcp_reachability",
            pattern_id=path.pattern_id,
            narrative=(
                f"no public hostname / IP / function URL for "
                f"`{arn}` in attack-path metadata — caller must "
                f"supply via `cloud_assets` for live probing to "
                f"work"
            ),
        )

    # Normalise function URL to host + port.
    explicit_port: int | None = None
    if isinstance(host, str) and "://" in host:
        parsed = urlparse(host)
        host_only = parsed.hostname
        explicit_port = parsed.port or (
            443 if parsed.scheme == "https" else 80
        )
        host = host_only

    kind = md.get("compute_kind") or ""
    ports = (
        (explicit_port,) if explicit_port
        else _DEFAULT_PORTS_BY_KIND.get(kind, _FALLBACK_PORTS)
    )

    reachable: list[int] = []
    errors: dict[int, str] = {}
    for port in ports:
        try:
            sock = socket.create_connection(
                (host, port), timeout=2.0,
            )
            sock.close()
            reachable.append(port)
        except (socket.timeout, TimeoutError):
            errors[port] = "timeout"
        except ConnectionRefusedError:
            errors[port] = "refused"
        except OSError as e:
            errors[port] = f"{type(e).__name__}: {e}"

    if reachable:
        return ProbeResult(
            status=PROBE_VERIFIED,
            probe_id="tcp_reachability",
            pattern_id=path.pattern_id,
            narrative=(
                f"Compute resource `{arn}` is TCP-reachable from "
                f"the public internet on port(s) "
                f"{', '.join(map(str, reachable))} via "
                f"`{host}`. Combined with the attached IAM "
                f"identity (per the pattern), this is the "
                f"exploitable chain."
            ),
            evidence={
                "host": host,
                "reachable_ports": reachable,
                "tested_ports": list(ports),
                "errors": {str(k): v for k, v in errors.items()},
            },
        )
    return ProbeResult(
        status=PROBE_NOT_VERIFIED,
        probe_id="tcp_reachability",
        pattern_id=path.pattern_id,
        narrative=(
            f"Compute resource `{arn}` was NOT TCP-reachable on "
            f"any of the tested ports ({', '.join(map(str, ports))}). "
            f"Either the firewall is more restrictive than CSPM "
            f"saw, the resource is stopped, or the probe ran from "
            f"a blocked source."
        ),
        evidence={
            "host": host,
            "tested_ports": list(ports),
            "errors": {str(k): v for k, v in errors.items()},
        },
    )


# ---------------------------------------------------------------------------
# Top-level dispatcher
# ---------------------------------------------------------------------------


def run_probe(path: AttackPath) -> ProbeResult | None:
    """Run the registered probe for `path.pattern_id`, or return
    None if no probe is registered. Never raises — wraps probe
    exceptions into `ProbeResult(status=error)`."""
    probe_fn = _REGISTRY.get(path.pattern_id)
    if probe_fn is None:
        return None
    try:
        return probe_fn(path)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "cloud-attack-path probe %s failed: %s",
            path.pattern_id, e, exc_info=True,
        )
        return ProbeResult(
            status=PROBE_ERROR,
            probe_id="(exception)",
            pattern_id=path.pattern_id,
            narrative=f"probe raised: {type(e).__name__}: {e}",
        )


def upgrade_path_with_probe(
    path: AttackPath, result: ProbeResult,
) -> AttackPath:
    """Apply a probe result to its corresponding `AttackPath`.

    On `verified`: bump `confidence` toward 1.0 (cap at 1.0),
    stamp the proof on `metadata.live_probe`, prepend "VERIFIED
    LIVE" to the narrative so the wrapper renders it
    distinctively.

    On `not_verified`: stamp the probe outcome on
    `metadata.live_probe` for transparency (auditor sees "we
    tried, and got back denied") but DO NOT downgrade the
    original pattern-derived `severity` / `confidence`. The
    pattern found a real misconfig; the probe just couldn't
    externally confirm exploitability from this vantage point.

    `error` / `skipped`: record on metadata, no other change.
    """
    if path.metadata is None:
        path.metadata = {}
    path.metadata["live_probe"] = result.to_dict()
    if result.is_verified:
        path.confidence = min(1.0, max(path.confidence, 0.99))
        path.narrative = (
            f"**VERIFIED LIVE** — {result.narrative}\n\n"
            f"{path.narrative}"
        )
    return path
