"""Model fallback chain (§8 of strixredteam.md).

The existing Phase 1.1 failover (in `strix/llm/llm.py::_resolve_failover_model`)
is a single primary → single fallback pair. When the fallback ALSO
gets rate-limited (the common CI scenario where two providers are
hit by the same surge), there's nowhere to go.

This module replaces the static 2-choice mapping with a multi-step
**chain** built dynamically from:

  1. `STRIX_AUTH_PRIORITY` — CSV of providers in preference order
     (e.g. `anthropic,openai,google`)
  2. Tier — HIGH / MID / LOW per agent role
  3. Available credentials — only chain in providers whose API key
     env var is set (avoids dead links)

Per-role tier defaults match Decepticon's `eco` profile:

  | Role / category | Tier |
  |---|---|
  | taint, verifier, exploiter | HIGH |
  | sqli-validator, idor, xss | MID |
  | recon, fingerprint | LOW |

These are sensible defaults; per-deployment override via
`STRIX_FALLBACK_TIER_<ROLE_UPPER>` env vars or programmatic
`pick_chain(role=..., tier=...)`.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `STRIX_AUTH_PRIORITY` | `anthropic,openai,google` | Provider preference order |
| `STRIX_FALLBACK_TIER` | `MID` | Default tier when role unspecified |
| `STRIX_FALLBACK_DISABLED` | unset | Kill switch — single primary, no chain |
| `STRIX_FALLBACK_TIER_<ROLE>` | per role default | Override tier for a specific role |

## Wiring

`LLM._resolve_failover_model()` consults this module to get the
ordered list of failover targets. The existing rolling-window
retry-rate trigger (50% → swap, <25% → revert) is reused; this
module just supplies what to swap TO. When already on a failover
and retries hit threshold again, we step to the next link.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Literal


logger = logging.getLogger(__name__)


Tier = Literal["HIGH", "MID", "LOW"]


# Provider → tier → model. Conservative picks: highest-capability
# Anthropic models for HIGH, balanced midweights for MID, cheapest
# usable for LOW. Update when new model IDs ship.
_PROVIDER_TIER_MODELS: dict[str, dict[Tier, str]] = {
    "anthropic": {
        "HIGH": "anthropic/claude-opus-4-5-20251101",
        "MID": "anthropic/claude-sonnet-4-5-20250929",
        "LOW": "anthropic/claude-haiku-4-5-20251001",
    },
    "openai": {
        "HIGH": "openai/gpt-4o",
        "MID": "openai/gpt-4o-mini",
        "LOW": "openai/gpt-4o-mini",
    },
    "google": {
        "HIGH": "gemini/gemini-2.5-pro",
        "MID": "gemini/gemini-2.5-flash",
        "LOW": "gemini/gemini-2.5-flash-lite",
    },
}


# Provider → env vars whose presence indicates the credential is
# configured. Permissive — any one being set counts. Mirrors the
# auth detection conventions LiteLLM uses internally.
_PROVIDER_CREDENTIAL_ENV: dict[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_API_KEY", "STRIX_ANTHROPIC_API_KEY"),
    "openai": ("OPENAI_API_KEY", "STRIX_OPENAI_API_KEY"),
    "google": (
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "STRIX_GEMINI_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ),
}


# Decepticon's `eco` profile defaults. Maps a role / specialist
# category to the tier the chain should aim for. The role names
# match the strix specialist categories where they exist (`sqli`,
# `xss`, `idor`, `recon`) plus a few synthetic ones from the §8
# example (`taint`, `verifier`).
_ROLE_TIER_DEFAULTS: dict[str, Tier] = {
    # HIGH-tier reasoning — payoff justifies cost
    "taint": "HIGH",
    "verifier": "HIGH",
    "exploiter": "HIGH",
    "lead": "HIGH",
    # MID-tier validation — balanced reasoning + cost
    "sqli": "MID",
    "sqli-validator": "MID",
    "idor": "MID",
    "xss": "MID",
    "auth": "MID",
    # LOW-tier scanning / surface mapping — cheap is fine
    "recon": "LOW",
    "fingerprint": "LOW",
    "scope": "LOW",
}


_DEFAULT_PRIORITY = ("anthropic", "openai", "google")
_DEFAULT_TIER: Tier = "MID"


@dataclass(frozen=True)
class ChainLink:
    """One step in the fallback chain. `provider` is the
    canonical key (`anthropic`, `openai`, `google`). `model` is
    the LiteLLM-format model string. `credential_present` is True
    when the provider's auth env var is set — when False, the link
    is yielded but flagged so callers can skip it."""
    provider: str
    model: str
    tier: Tier
    credential_present: bool


def is_fallback_disabled() -> bool:
    """Kill switch. When set, `pick_chain` returns the empty list."""
    return os.environ.get(
        "STRIX_FALLBACK_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _read_priority() -> tuple[str, ...]:
    raw = (os.environ.get("STRIX_AUTH_PRIORITY") or "").strip()
    if not raw:
        return _DEFAULT_PRIORITY
    parts = tuple(
        p.strip().lower() for p in raw.split(",") if p.strip()
    )
    valid = tuple(p for p in parts if p in _PROVIDER_TIER_MODELS)
    return valid or _DEFAULT_PRIORITY


def _read_default_tier() -> Tier:
    raw = (os.environ.get("STRIX_FALLBACK_TIER") or "").strip().upper()
    if raw in ("HIGH", "MID", "LOW"):
        return raw  # type: ignore[return-value]
    return _DEFAULT_TIER


def _read_role_tier(role: str | None) -> Tier:
    """Determine tier for a role, checking env override before the
    built-in defaults."""
    if role:
        env_name = f"STRIX_FALLBACK_TIER_{role.upper().replace('-', '_')}"
        raw = (os.environ.get(env_name) or "").strip().upper()
        if raw in ("HIGH", "MID", "LOW"):
            return raw  # type: ignore[return-value]
        if role.lower() in _ROLE_TIER_DEFAULTS:
            return _ROLE_TIER_DEFAULTS[role.lower()]
    return _read_default_tier()


def _credential_present(provider: str) -> bool:
    env_vars = _PROVIDER_CREDENTIAL_ENV.get(provider, ())
    return any(os.environ.get(v) for v in env_vars)


def pick_chain(
    *,
    role: str | None = None,
    tier: Tier | None = None,
    include_unavailable: bool = False,
) -> list[ChainLink]:
    """Return the ordered fallback chain.

    Args:
      role: specialist role / agent category. Drives tier selection
        via `_ROLE_TIER_DEFAULTS` unless `tier` is given explicitly.
      tier: explicit tier override. Bypasses role lookup.
      include_unavailable: when True, include links for providers
        without credentials configured. Default False — the chain
        only contains links that can actually serve a request.

    Returns the empty list when:
      - the kill switch is set
      - no providers have credentials AND `include_unavailable=False`
    """
    if is_fallback_disabled():
        return []

    final_tier: Tier = tier or _read_role_tier(role)
    priority = _read_priority()

    chain: list[ChainLink] = []
    for provider in priority:
        tier_map = _PROVIDER_TIER_MODELS.get(provider)
        if not tier_map:
            continue
        model = tier_map.get(final_tier)
        if not model:
            continue
        cred = _credential_present(provider)
        if not cred and not include_unavailable:
            continue
        chain.append(ChainLink(
            provider=provider,
            model=model,
            tier=final_tier,
            credential_present=cred,
        ))
    return chain


def next_link_after(
    current_model: str,
    *,
    role: str | None = None,
    tier: Tier | None = None,
) -> ChainLink | None:
    """Given the model currently in use, return the next link in
    the chain — or None if the chain is exhausted.

    Used by `LLM._resolve_failover_model` when the current failover
    target ALSO hits the retry threshold; advance to the next
    provider instead of latching on a dead one."""
    chain = pick_chain(role=role, tier=tier)
    if not chain:
        return None

    # Find current position by model substring match (handles both
    # full litellm IDs and short aliases).
    cur_lower = (current_model or "").lower()
    for idx, link in enumerate(chain):
        if link.model.lower() in cur_lower or cur_lower in link.model.lower():
            if idx + 1 < len(chain):
                return chain[idx + 1]
            return None

    # Not in chain → start at the head (gives wrapper a way to
    # bootstrap into the chain from an unrelated primary).
    return chain[0]


def get_chain_summary(
    *, role: str | None = None, tier: Tier | None = None,
) -> dict[str, object]:
    """Telemetry snapshot — what chain would be picked under current
    env. Useful for `run_meta.json`."""
    if is_fallback_disabled():
        return {
            "enabled": False,
            "role": role,
            "links": [],
            "priority": list(_read_priority()),
        }
    chain = pick_chain(role=role, tier=tier, include_unavailable=True)
    return {
        "enabled": True,
        "role": role,
        "tier": tier or _read_role_tier(role),
        "priority": list(_read_priority()),
        "links": [
            {
                "provider": link.provider,
                "model": link.model,
                "tier": link.tier,
                "credential_present": link.credential_present,
            }
            for link in chain
        ],
    }
