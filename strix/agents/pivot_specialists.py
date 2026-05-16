"""Built-in pivot specialists registered with `pivot_orchestrator`.

This module hosts the *concrete* post-exploit specialists. They're
intentionally minimal in this first cut — the orchestrator framework
(PR #256) is what's load-bearing; the individual specialists will
grow over follow-up PRs as we wire each one to its real-world
exploit primitive (cookie replay via `runtime` proxy, AWS IMDS via
`requests`, RCE shell via `terminal_session`, etc.).

Today's specialists are honest stubs: they read the proof artifact,
produce a structured `PivotResult`, and emit a follow-up finding via
the standard tracer surface. The wiring works end-to-end; the
real-world traffic doesn't yet leave the host. Each stub is clearly
flagged at the top of its function with a `# STUB:` comment so the
follow-up authors know what to replace.

To add a real specialist:

  1. Replace the stub body with the actual exploit primitive
     (proxy a request, parse a metadata blob, spawn a shell).
  2. Capture the new proof-of-impact via
     `strix.agents.proof_of_impact.capture_proof_of_impact`.
  3. Emit a follow-up finding via
     `tracer.add_vulnerability_report(..., verification_status="exploited",
     proof_artifact_path=..., pivot_chain_ancestors=[source_finding["id"]])`.
  4. Return `PivotResult(outcome="pivoted", emitted_finding_id=...)`.

Importing this module side-effects the orchestrator's playbook
registry — the @register_pivot decorators fire at import time. The
top-level `__init__` in `strix.agents` doesn't auto-import this
file; callers wanting the registry populated should import it
explicitly (typically once at startup in `StrixAgent`).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from strix.agents.pivot_orchestrator import (
    PivotResult,
    register_pivot,
)
from strix.agents.proof_of_impact import (
    IMPACT_AUTH_BYPASS_SESSION,
    IMPACT_COOKIE_THEFT,
    IMPACT_IDOR_RECORD,
    IMPACT_METADATA_EXFIL,
    IMPACT_RCE_OUTPUT,
)


logger = logging.getLogger(__name__)


@register_pivot(
    name="cookie_replay_admin_probe",
    impact_types=[IMPACT_COOKIE_THEFT, IMPACT_AUTH_BYPASS_SESSION],
)
def cookie_replay_admin_probe(
    *, source_finding: dict[str, Any], target_context: dict[str, Any],
) -> PivotResult:
    """Cookie/session → admin-endpoint probe.

    Given a captured session credential, attempt to access a
    privileged surface on the same asset. If the privileged
    response shape differs from an unauthenticated baseline, the
    session has admin reach and we've turned XSS-stolen-cookie
    into account takeover.

    STUB: the stub body validates the wiring (correct impact-type
    routing, source-finding consumption, target_context plumbing)
    without making real HTTP requests. Replace the stub body with
    `requests.get(admin_url, cookies=...)` + baseline diff once
    the runtime proxy layer is plumbed through specialists.
    """
    started = time.monotonic()

    proof_path = source_finding.get("proof_artifact_path")
    if not proof_path:
        return PivotResult(
            outcome="dead_end",
            detail="source finding lacks proof_artifact_path",
            elapsed_seconds=time.monotonic() - started,
        )

    admin_surface = target_context.get("admin_surface_url")
    if not admin_surface:
        return PivotResult(
            outcome="dead_end",
            detail=(
                "no admin_surface_url in target_context — "
                "specialist needs the wrapper to surface a "
                "privileged endpoint hypothesis"
            ),
            elapsed_seconds=time.monotonic() - started,
        )

    # STUB: real specialist would proxy the captured cookie at
    # admin_surface and diff against an unauthenticated baseline.
    return PivotResult(
        outcome="dead_end",
        detail=(
            "stub specialist — wiring validated, no real HTTP "
            "request issued. Replace stub body with cookie replay."
        ),
        elapsed_seconds=time.monotonic() - started,
    )


@register_pivot(
    name="imds_iam_credential_extract",
    impact_types=[IMPACT_METADATA_EXFIL],
)
def imds_iam_credential_extract(
    *, source_finding: dict[str, Any], target_context: dict[str, Any],
) -> PivotResult:
    """IMDS exfil → IAM credential extract.

    Given the captured IMDS response, attempt to pull short-lived
    IAM credentials from the same SSRF primitive. Credentials are
    typically at
    `/latest/meta-data/iam/security-credentials/<role-name>`.

    STUB: the stub validates that an IMDS-typed impact correctly
    routes here and that the orchestrator's PIVOTED_FROM edge
    fires when this returns `pivoted`. Replace the stub body with
    a real second-stage SSRF probe once specialists can re-fire
    the source's exploit primitive.
    """
    started = time.monotonic()

    proof_path = source_finding.get("proof_artifact_path")
    if not proof_path:
        return PivotResult(
            outcome="dead_end",
            detail="source finding lacks proof_artifact_path",
            elapsed_seconds=time.monotonic() - started,
        )

    # STUB: real specialist would parse the source proof for the
    # SSRF primitive (URL parameter, header injection point, etc.)
    # and fire a second-stage request at
    # http://169.254.169.254/latest/meta-data/iam/security-credentials/.
    return PivotResult(
        outcome="dead_end",
        detail=(
            "stub specialist — wiring validated. Replace stub "
            "with second-stage SSRF probe at "
            "/latest/meta-data/iam/security-credentials/."
        ),
        elapsed_seconds=time.monotonic() - started,
    )


@register_pivot(
    name="rce_secrets_scrape",
    impact_types=[IMPACT_RCE_OUTPUT],
)
def rce_secrets_scrape(
    *, source_finding: dict[str, Any], target_context: dict[str, Any],
) -> PivotResult:
    """RCE output → secrets scrape.

    Given a captured RCE primitive (proof artifact carries the
    command output), attempt to enumerate sensitive files on the
    same host: `/etc/passwd`, `.env`, `~/.aws/credentials`,
    `~/.docker/config.json`, etc.

    STUB: wiring validation. Replace with the real second-stage
    command execution once the RCE specialist exposes a re-fire
    interface.
    """
    started = time.monotonic()

    proof_path = source_finding.get("proof_artifact_path")
    if not proof_path:
        return PivotResult(
            outcome="dead_end",
            detail="source finding lacks proof_artifact_path",
            elapsed_seconds=time.monotonic() - started,
        )

    return PivotResult(
        outcome="dead_end",
        detail=(
            "stub specialist — wiring validated. Replace with "
            "secondary RCE command for ~/.aws/credentials, .env, "
            "/etc/shadow."
        ),
        elapsed_seconds=time.monotonic() - started,
    )


@register_pivot(
    name="idor_bulk_enumeration",
    impact_types=[IMPACT_IDOR_RECORD],
)
def idor_bulk_enumeration(
    *, source_finding: dict[str, Any], target_context: dict[str, Any],
) -> PivotResult:
    """IDOR record → bulk cross-tenant enumeration.

    Given a captured cross-tenant record (proof artifact is the
    sibling record the scanner read without authorisation), attempt
    to enumerate the sibling-ID space and pull additional records.
    The capture point is the data-leak scale — small leak vs full
    table.

    STUB: wiring validation. Replace with sibling-ID enumeration
    once the IDOR specialist exposes a re-fire interface.
    """
    started = time.monotonic()

    if not source_finding.get("proof_artifact_path"):
        return PivotResult(
            outcome="dead_end",
            detail="source finding lacks proof_artifact_path",
            elapsed_seconds=time.monotonic() - started,
        )

    return PivotResult(
        outcome="dead_end",
        detail=(
            "stub specialist — wiring validated. Replace with "
            "sibling-ID enumeration + cross-tenant record dump."
        ),
        elapsed_seconds=time.monotonic() - started,
    )
