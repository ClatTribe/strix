"""iter-Q5.10 — `dispatch_l2_probe(kind, **kwargs)`.

Per CLAUDE.md §1.5.7 (RE-DISPATCH bucket) and the consolidated Q5
proposal §4. Collapses three L2-native session-aware probes
(`scan_idor`, `scan_auth_flow`, `scan_business_logic`) under one
umbrella to free L2-catalog slots while keeping the full capability
surface.

## Why one umbrella tool, not three

LLM tool-use accuracy degrades past ~10 visible tools (Invariant
L2-CAP, CLAUDE.md §1.5.5). Each of the 3 probes is genuinely
L2-native — no OSS substitute, requires LLM state-reasoning to set
up — but they share a calling convention (single URL, optional
session state, family-specific kwargs). One umbrella with a `kind`
parameter delivers the same capability for 1 catalog slot instead
of 3, and the umbrella's docstring enumerates each kind's kwargs.

## Why these three together

* `scan_idor` — needs LLM to pair captured user-a + user-b sessions
  against ID-shaped URLs.
* `scan_auth_flow` — needs LLM to pick form fields, drive the
  register-then-login flow.
* `scan_business_logic` — needs LLM to choose price/quantity/role
  fields and abuse-family targeting.

All three: (a) need an LLM-orchestrated setup step, (b) no
standalone OSS scanner can substitute (no nuclei template knows
your app's "successful purchase" marker shape), (c) commit findings
via `tracer.add_vulnerability_report` so L1.5 hooks fire normally.

## Future Q5

Q5.9 (`rescan`) is the L1-tool re-dispatcher (sqlmap / dalfox /
hydra / nuclei — re-fire with new state). `dispatch_l2_probe` is
the L2-native equivalent. The clean split: rescan = OSS,
dispatch_l2_probe = LLM-orchestrated.
"""

from __future__ import annotations

import logging
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Kind enumeration
# ---------------------------------------------------------------------------


_VALID_KINDS: frozenset[str] = frozenset({
    "idor",            # cross-session authz (IDOR / BOLA / BFLA)
    "auth_flow",       # default-cred bruteforce + session capture
    "business_logic",  # price / quantity / role / workflow abuse
})


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1078", "T1190", "T1531"],
)
def dispatch_l2_probe(
    *,
    kind: str,
    **kwargs: Any,
) -> dict[str, Any]:
    """Re-dispatch one of the L2-native session-aware probes.

    Per CLAUDE.md §1.5.6 — tools are the LLM's hands, not its brain.
    These probes can't fire deterministically in `anchor_prepass`
    because they need LLM state-reasoning that prepass doesn't have
    (which session pairs, which mutation fields, which abuse family).
    This umbrella lets the L2 lead choose the right probe shape on a
    surfaced candidate.

    Args:
        kind: one of:
          * ``"idor"`` — cross-session IDOR / BOLA / BFLA probe.
            Required kwargs: ``urls`` (list[str]) or ``url`` (str).
            Optional: ``owner_label`` (default "user-a"),
            ``accessor_label`` (default "user-b"),
            ``test_anon`` (default True),
            ``extra_headers`` (dict),
            ``max_urls`` (default 50).
            Returns a SpecialistResult with CWE-639/CWE-862 findings
            when accessor or anon reads owner's data.

          * ``"auth_flow"`` — default-creds bruteforce + session
            capture. Required: ``login_url``. Optional:
            ``method`` (default "POST"), ``email_field``,
            ``password_field``, ``body_template`` (dict),
            ``extra_headers``, ``label``, ``try_register`` (bool),
            ``register_url``, ``extra_creds`` (list of [user,pass]).
            Returns SpecialistResult; emits CWE-521 on default-corpus
            hit (NOT on user-supplied creds — distinguishes default
            vs. tenant-provided). Writes captured session to
            SecurityContext.AuthState for downstream probes.

          * ``"business_logic"`` — workflow / business-logic abuse.
            Required: ``url``. Optional: ``body_template`` (dict),
            ``method`` (default "POST"), ``extra_headers``,
            ``enabled_families`` (list — default all 5:
            price_tampering, quantity_tampering, role_tampering,
            workflow_skip, param_pollution).
            Returns SpecialistResult with CWE-840/841/235/269/682
            findings per successful abuse family.

        **kwargs: forwarded verbatim to the chosen probe.

    Returns:
        Whatever the underlying probe returns (typically a
        ``SpecialistResult`` shape dict). On unknown ``kind``,
        returns a structured error dict — never raises.
    """
    if not isinstance(kind, str) or not kind.strip():
        return {
            "status": "error",
            "success": False,
            "reason": (
                f"kind is required (one of {sorted(_VALID_KINDS)!r})"
            ),
        }

    kind_norm = kind.strip().lower()
    if kind_norm not in _VALID_KINDS:
        return {
            "status": "error",
            "success": False,
            "reason": (
                f"unknown kind {kind!r}; valid kinds: "
                f"{sorted(_VALID_KINDS)!r}"
            ),
        }

    # Lazy-import the underlying probe so the registry doesn't load
    # all three when only one is needed (and so this module stays
    # cheap to import).
    try:
        if kind_norm == "idor":
            from strix.tools.specialist.scan_idor import scan_idor
            return scan_idor(**kwargs)  # type: ignore[no-any-return]
        if kind_norm == "auth_flow":
            from strix.tools.specialist.scan_auth_flow import scan_auth_flow
            return scan_auth_flow(**kwargs)  # type: ignore[no-any-return]
        if kind_norm == "business_logic":
            from strix.tools.specialist.scan_business_logic import (
                scan_business_logic,
            )
            return scan_business_logic(**kwargs)  # type: ignore[no-any-return]
    except TypeError as e:
        # Wrong kwargs for the chosen probe — surface cleanly.
        return {
            "status": "error",
            "success": False,
            "reason": (
                f"kind={kind_norm}: bad kwargs ({type(e).__name__}): {e}. "
                f"Re-check the docstring for required parameters."
            ),
        }
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "dispatch_l2_probe kind=%s failed: %s", kind_norm, e,
            exc_info=True,
        )
        return {
            "status": "error",
            "success": False,
            "reason": (
                f"kind={kind_norm}: probe raised "
                f"{type(e).__name__}: {e}"
            ),
        }

    # Unreachable — kind_norm was validated above.
    return {  # pragma: no cover
        "status": "error",
        "success": False,
        "reason": f"internal: unhandled kind {kind_norm!r}",
    }
