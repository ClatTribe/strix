"""Proof-of-impact capture for the `exploited` verification tier.

Strix's verification gradient (per `strix.telemetry.finding_contract`):

    pattern_match → needs_review → could_not_verify → inconclusive
    → verified → exploited

The `exploited` tier requires the scanner to have run the full attack
end-to-end AND captured an artifact that proves impact — not just a
response-diff signal that the exploit-shape worked. For each impact
type the captured artifact looks different:

  * **XSS / cookie theft**       — the stolen cookie value + the
                                   request that exfiltrated it
  * **SQLi / data dump**         — the rows the scanner read out
                                   (sentinel column / database
                                   version banner)
  * **SSRF / metadata exfil**    — the IMDS / internal-endpoint
                                   response body fetched via the
                                   SSRF
  * **RCE / arbitrary command**  — the command output (`id`, `uname`,
                                   captured flag file)
  * **IDOR / privilege escalation** — the target record the scanner
                                   read / wrote without authorization
  * **Auth bypass**              — the captured session token for an
                                   account the scanner had no
                                   credentials for

This module provides the single canonical helper for writing those
artifacts into the run directory. The scanner gets a relative path
back; that path goes onto the finding under `proof_artifact_path`,
and the contract validator enforces presence.

Kill-switch: `STRIX_PROOF_OF_IMPACT_DISABLED=1` short-circuits all
captures to None (the scanner should fall back to
`verification_status="verified"` when proof can't be captured).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# Impact-type taxonomy — drives the artifact filename + the wrapper's
# evidence-rendering decisions. Each is a *what was actually captured*
# label, not a CWE class.
IMPACT_COOKIE_THEFT = "cookie_theft"
IMPACT_DATA_DUMP = "data_dump"
IMPACT_METADATA_EXFIL = "metadata_exfil"
IMPACT_RCE_OUTPUT = "rce_output"
IMPACT_IDOR_RECORD = "idor_record"
IMPACT_AUTH_BYPASS_SESSION = "auth_bypass_session"
IMPACT_CAPTURED_FLAG = "captured_flag"


VALID_IMPACT_TYPES = frozenset({
    IMPACT_COOKIE_THEFT,
    IMPACT_DATA_DUMP,
    IMPACT_METADATA_EXFIL,
    IMPACT_RCE_OUTPUT,
    IMPACT_IDOR_RECORD,
    IMPACT_AUTH_BYPASS_SESSION,
    IMPACT_CAPTURED_FLAG,
})


_PROOF_DIR_NAME = "proof_of_impact"


def _kill_switched() -> bool:
    return os.environ.get("STRIX_PROOF_OF_IMPACT_DISABLED") == "1"


def _run_dir() -> Path | None:
    """Resolve the active run dir. Falls back to `STRIX_RUN_DIR`
    when no tracer is initialised (e.g. unit tests)."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is not None and hasattr(tracer, "get_run_dir"):
            run_dir = tracer.get_run_dir()
            if run_dir:
                return Path(run_dir)
    except Exception:  # noqa: BLE001
        # Tracer optional — fall through to env var.
        pass
    env = os.environ.get("STRIX_RUN_DIR")
    if env:
        return Path(env)
    return None


def capture_proof_of_impact(
    *,
    finding_fingerprint: str,
    impact_type: str,
    artifact_bytes: bytes | str,
    request_context: dict[str, Any] | None = None,
) -> str | None:
    """Write a proof-of-impact artifact into the run dir.

    Args:
        finding_fingerprint: stable id for the finding the proof
            belongs to. Used as the filename prefix so the artifact
            sorts next to its finding in the run dir listing.
        impact_type: one of the `IMPACT_*` constants. Drives the
            filename suffix + the wrapper's renderer choice.
        artifact_bytes: the captured payload. `str` is encoded as
            UTF-8; `bytes` is written verbatim.
        request_context: optional `{method, url, request_headers,
            response_headers, response_status}` block describing
            the HTTP exchange that produced the artifact. Written
            as a sibling `.context.json` file when supplied.

    Returns:
        The relative path (from the run dir) to the captured
        artifact, suitable for `proof_artifact_path` on a finding.
        Returns `None` when the kill switch is set, the impact
        type is unknown, no run dir is resolvable, or the write
        fails — the scanner should fall back to
        `verification_status="verified"` in that case.
    """
    if _kill_switched():
        return None

    if impact_type not in VALID_IMPACT_TYPES:
        logger.warning(
            "proof_of_impact: unknown impact_type %r — skipping", impact_type,
        )
        return None

    run_dir = _run_dir()
    if run_dir is None:
        return None

    proof_dir = run_dir / _PROOF_DIR_NAME
    try:
        proof_dir.mkdir(parents=True, exist_ok=True)
    except OSError:  # noqa: BLE001
        logger.warning("proof_of_impact: cannot create %s", proof_dir, exc_info=True)
        return None

    # Filename: <fingerprint>.<impact_type>.bin keeps things short +
    # sortable. Sanitise fingerprint of path separators (defence in
    # depth — fingerprints SHOULD already be hex / b32).
    safe_fp = finding_fingerprint.replace("/", "_").replace("\\", "_")[:96]
    artifact_path = proof_dir / f"{safe_fp}.{impact_type}.bin"

    try:
        if isinstance(artifact_bytes, str):
            artifact_path.write_text(artifact_bytes, encoding="utf-8")
        else:
            artifact_path.write_bytes(artifact_bytes)
    except OSError:  # noqa: BLE001
        logger.warning(
            "proof_of_impact: failed to write %s", artifact_path, exc_info=True,
        )
        return None

    # Sibling context blob — what request produced this artifact?
    if request_context is not None:
        import json

        ctx_path = proof_dir / f"{safe_fp}.{impact_type}.context.json"
        try:
            ctx_path.write_text(
                json.dumps(request_context, indent=2, default=str) + "\n",
                encoding="utf-8",
            )
        except (OSError, TypeError, ValueError):  # noqa: BLE001
            logger.warning(
                "proof_of_impact: context write failed for %s",
                artifact_path, exc_info=True,
            )

    # Return path RELATIVE to the run dir so the finding stays
    # portable when the run is archived / moved.
    return str(artifact_path.relative_to(run_dir))
