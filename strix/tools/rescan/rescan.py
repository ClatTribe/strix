"""iter-Q5.9 — `rescan(tool_name, target, captured_state)`.

Per CLAUDE.md §1.5.7 RE-DISPATCH bucket and the consolidated Q5
proposal §4. The L2 lead re-fires an L1 OSS tool from
`anchor_prepass` with newly captured state.

## Canonical use case

After `dispatch_l2_probe(kind="auth_flow")` captures a session, the
lead calls:

  rescan(
      tool_name="scan_sqli_sqlmap",
      target="https://app.example.com/api/orders",
      captured_state={"auth_cookie": "session=abc..."},
  )

…to re-test SQLi as the authed user. The first prepass fire ran
unauthenticated; this re-fires with the captured cookie.

## Why a tool

LLM can't run subprocess / network I/O. The prepass dispatcher is
host-side; this gives the lead access to that dispatch path with
its own kwargs.

## Safety

  - `tool_name` validated against an allow-list (the OSS-wrappers
    that anchor_prepass already fires). Refuses anything else to
    prevent abuse.
  - Capped at 5 rescans per scan (iter-29.9 destructive-
    amplification guard pattern). Sixth and beyond return error.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)


# Allow-list of tools that the lead may re-fire. Each must already
# exist in anchor_prepass (validated at startup via the test in
# `tests/tools/rescan/test_rescan.py`). This is the safety boundary:
# the lead can re-fire any L1 OSS tool, but only those that the
# prepass already trusted to run in the first place.
_ALLOW_LIST: frozenset[str] = frozenset({
    # Deep-exploit web/api (Q5.3 moved these to prepass)
    "scan_sqli_sqlmap",
    "scan_xss_dalfox",
    "scan_smuggling_smuggler",
    "probe_default_creds_hydra",
    "scan_fuzz_ffuf",
    "scan_api_schemathesis",
    # Light-touch detection (also fires in prepass)
    "scan_sqli",
    "scan_xss",
    "scan_nuclei_templates",
    "scan_path_traversal",
    "scan_xxe",
    "scan_ssrf",
    "scan_ssti",
    "scan_cmd_injection",
    "scan_nosql_injection",
    # Discovery (re-fire with new starting point post-auth)
    "crawl_with_katana",
    "openapi_spec_ingest",
    "discover_graphql_endpoints",
    "map_graphql_inql",
    # IP / domain recon
    "fingerprint_services_nmap",
    "probe_hosts_httpx",
    "tls_audit",
    "enumerate_subdomains_subfinder",
    "scan_dns_hygiene_checkdmarc",
    "scan_typosquats_dnstwist",
    "domain_recon_pipeline",
    # Repo verification — credential verifier on top of secrets_scan
    # (prepass). Re-fired via rescan when the lead wants to confirm a
    # specific surfaced secret is still credentialed.
    "verify_credentials_trufflehog",
})


# Per-scan rescan budget. iter-29.9 destructive-amplification guard
# pattern — bounded multipliers on tool dispatch.
_DEFAULT_BUDGET = 5

# Per-process counter keyed by tracer run_id. Reset on new scan.
_rescan_counters: dict[str, int] = {}


def _get_budget() -> int:
    """Env-overridable per-scan cap."""
    raw = os.environ.get("STRIX_RESCAN_BUDGET", "")
    if raw.strip():
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return _DEFAULT_BUDGET


def _run_id() -> str:
    """Stable key for the per-scan budget counter. Falls back to
    process-wide if tracer absent."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is not None:
            return tracer.run_id
    except Exception:  # noqa: BLE001
        pass
    return "_no_tracer"


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1595.002"],
)
def rescan(
    *,
    tool_name: str,
    target: str,
    captured_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Re-fire an L1 OSS tool with new captured state.

    Per CLAUDE.md §1.5.6 — the LLM can't run subprocess; this tool
    re-dispatches the prepass's L1 tools with new args (auth cookies,
    captured CSRF tokens, etc.). The prepass already fired everything
    once; this is the escape hatch for "now I have an authed session,
    re-test SQLi as that user."

    Args:
        tool_name: which L1 tool to re-fire. Must be in the
            allow-list (see _ALLOW_LIST in this module). The list is
            constrained to OSS-wrappers already trusted by
            anchor_prepass — the lead can't arbitrary-tool-dispatch.
        target: target URL / IP / domain (matches what the prepass
            would have passed).
        captured_state: forwarded to the underlying tool as kwargs.
            Common keys: ``auth_cookie``, ``auth_bearer``, ``headers``,
            ``params``. Tool-specific — see each tool's docstring.

    Returns:
        The underlying tool's return dict, plus:
          * ``rescan_budget_remaining``: int
          * ``rescan_blocked_after_this``: bool

    Errors:
        - Unknown tool_name → {"success": False, "reason": ...}
        - Budget exhausted → {"success": False, "reason": "..."}
        - Underlying tool exception → swallowed, returned as
          {"success": False, "reason": ...} (never raises).
    """
    # ── Validate tool_name ────────────────────────────────────
    if not isinstance(tool_name, str) or not tool_name.strip():
        return {
            "success": False, "status": "error",
            "reason": "tool_name is required (non-empty string)",
        }
    tname = tool_name.strip()
    if tname not in _ALLOW_LIST:
        return {
            "success": False, "status": "error",
            "reason": (
                f"tool_name {tname!r} not in rescan allow-list. "
                f"Valid: {sorted(_ALLOW_LIST)[:5]}... "
                f"({len(_ALLOW_LIST)} total). The allow-list is "
                f"constrained to OSS-wrappers that anchor_prepass "
                f"already trusts."
            ),
        }
    # ── Validate target ────────────────────────────────────
    if not isinstance(target, str) or not target.strip():
        return {
            "success": False, "status": "error",
            "reason": "target is required (non-empty string)",
        }

    # ── Budget check ───────────────────────────────────────
    rid = _run_id()
    used = _rescan_counters.get(rid, 0)
    budget = _get_budget()
    if used >= budget:
        return {
            "success": False, "status": "error",
            "reason": (
                f"rescan budget exhausted ({used}/{budget}). Per "
                f"iter-29.9 destructive-amplification guard, the lead "
                f"can't re-fire L1 tools indefinitely. Raise the "
                f"budget via STRIX_RESCAN_BUDGET if a deeper scan is "
                f"genuinely needed."
            ),
            "rescan_budget_remaining": 0,
            "rescan_blocked_after_this": True,
        }

    # ── Dispatch ───────────────────────────────────────────
    kwargs: dict[str, Any] = dict(captured_state or {})
    # Default to common URL-ish param names. The underlying tool's
    # signature will reject if it expects a different name.
    if "url" not in kwargs and "target_url" not in kwargs and "target" not in kwargs:
        kwargs["target_url"] = target  # most common name in prepass tools

    try:
        from strix.tools.registry import get_tool_by_name
        fn = get_tool_by_name(tname)
        if fn is None:
            return {
                "success": False, "status": "error",
                "reason": (
                    f"tool {tname!r} is in the allow-list but not "
                    f"registered (build issue). Re-import strix.tools "
                    f"or rebuild the sandbox image."
                ),
            }
        result = fn(**kwargs)
    except TypeError as e:
        # Most common cause: wrong kwarg name (e.g. `url` vs `target_url`)
        # The lead can read the underlying tool's docstring + retry.
        return {
            "success": False, "status": "error",
            "reason": (
                f"rescan {tname!r}: bad kwargs ({type(e).__name__}): "
                f"{e}. Check the tool's signature — common kwarg "
                f"names: url, target_url, target. The full captured_"
                f"state dict was forwarded as kwargs."
            ),
        }
    except Exception as e:  # noqa: BLE001
        logger.debug("rescan %s raised: %s", tname, e, exc_info=True)
        return {
            "success": False, "status": "error",
            "reason": (
                f"rescan {tname!r}: {type(e).__name__}: {e}"
            ),
        }

    # ── Charge the budget on success ──────────────────────
    _rescan_counters[rid] = used + 1

    if isinstance(result, dict):
        result = dict(result)  # don't mutate the underlying tool's return
        result["rescan_budget_remaining"] = budget - (used + 1)
        result["rescan_blocked_after_this"] = (used + 1) >= budget
    return result


def _reset_counter_for_tests() -> None:
    """Test-only — reset the per-process budget counter."""
    _rescan_counters.clear()
