"""Scanner re-run registry — closes the §4 EXPLOITED → PATCHED loop.

The §4 verification pipeline + Patcher (PRs #241 / #243) ship the
state machine and the propose / verify tools. What was missing:
the wire between `verify_patch(finding_id, ...)` and *actually
re-running the original detector* against the patched target.

This module is that wire. Each scanner that emits findings can
register a re-run callable here; the new `auto_verify_patch` tool
looks up the right callable for a patch's underlying finding,
invokes it, and reports the outcome back into `verify_patch`.

## Why a registry instead of direct dispatch

Two reasons:

1. **Decoupling.** The Patcher specialist doesn't need to know
   which detector originally found the bug. It calls
   `auto_verify_patch(patch_id)` and the registry picks the right
   re-run function from the patch → finding → category mapping.
2. **Pluggability.** Adding a new scanner = registering a new
   re-run callable. No central switch statement to update.

## Callable shape

```python
def my_scanner_rerun(*, finding_context: dict[str, Any]) -> RerunResult:
    \"\"\"Re-fire the original detection. Return a structured
    result indicating whether the original signal still fires
    against the (assumed-patched) target.\"\"\"
    ...
```

`finding_context` is whatever was stored on the Vuln node in the
§3 KG when the finding was first emitted: url, param, method,
detection_kind, db_engine, confidence, etc. The scanner uses
those to reconstruct the original probe.

## When auto-verify isn't possible

Not every category has a deterministic re-run path:

- **SAST findings** (semgrep static-match) → can re-run semgrep
  against the (patched) source if available, otherwise mark as
  `manual_verification_required`.
- **Threat-intel / posture findings** → no re-runnable detection,
  always `manual_verification_required`.
- **Recon findings** → state-machine isn't bug-shaped; skip.

The registry returns `None` for unregistered categories, which
`auto_verify_patch` translates into the "manual" exit status.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `STRIX_RERUN_REGISTRY_DISABLED` | unset | Kill switch — registry returns None for every lookup |
| `STRIX_AUTO_VERIFY_TIMEOUT_SECONDS` | 60 | Per-re-run cap (caller enforces) |
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from typing import Any, Callable, Literal


logger = logging.getLogger(__name__)


RerunOutcome = Literal["still_fires", "no_longer_fires", "indeterminate"]


@dataclass
class RerunResult:
    """Structured outcome of a re-run attempt."""
    outcome: RerunOutcome
    detail: str = ""
    elapsed_seconds: float = 0.0
    evidence: dict[str, Any] | None = None


# Type alias for re-run callables.
RerunFn = Callable[..., RerunResult]


# Process-global registry. Key = (category, cwe) — both fields are
# stored on the §3 KG Vuln node, so the lookup is deterministic.
# A None cwe is the wildcard for any cwe in that category.
_registry: dict[tuple[str, str | None], RerunFn] = {}
_registry_lock = threading.Lock()


def register_rerun(
    *,
    category: str,
    cwe: str | None = None,
) -> Callable[[RerunFn], RerunFn]:
    """Decorator. Registers a re-run callable for one
    `(category, cwe)` pair. CWE=None matches any CWE in the
    category.

    Example:
      ```python
      @register_rerun(category="sqli", cwe="CWE-89")
      def rerun_sqli(*, finding_context):
          ...
      ```
    """
    def decorator(fn: RerunFn) -> RerunFn:
        key = (category.strip().lower(), cwe)
        with _registry_lock:
            _registry[key] = fn
        return fn
    return decorator


def is_disabled() -> bool:
    return os.environ.get(
        "STRIX_RERUN_REGISTRY_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def lookup_rerun(
    *, category: str, cwe: str | None = None,
) -> RerunFn | None:
    """Find the re-run callable for a `(category, cwe)` pair.

    Falls back to the category-wildcard registration (`cwe=None`)
    if the exact `(category, cwe)` isn't registered. Returns None
    if neither is registered or the kill switch is set."""
    if is_disabled():
        return None
    norm_cat = (category or "").strip().lower()
    with _registry_lock:
        # Exact match first
        if cwe is not None:
            fn = _registry.get((norm_cat, cwe))
            if fn is not None:
                return fn
        # Wildcard fallback
        return _registry.get((norm_cat, None))


def list_registered() -> list[tuple[str, str | None]]:
    """Inspection helper — what categories are auto-verifiable
    right now?"""
    with _registry_lock:
        return sorted(_registry.keys(), key=lambda k: (k[0], k[1] or ""))


def reset_for_testing() -> None:
    """Clear the registry. Tests use this in fixtures so a
    test's registration doesn't leak to subsequent tests."""
    with _registry_lock:
        _registry.clear()


# ---------------------------------------------------------------------------
# Default registrations — covered by the KG-adopted scanners.
# Each scanner module imports this and registers its re-run path.
# To avoid circular imports, registrations are deferred until first
# `lookup_rerun` call via `_ensure_registered`.
# ---------------------------------------------------------------------------


_registered = False
_register_lock = threading.Lock()


def _ensure_registered() -> None:
    """Lazily import scanner modules so they register their
    re-run callables. Idempotent — only fires once per process."""
    global _registered  # noqa: PLW0603
    with _register_lock:
        if _registered:
            return
        try:
            # Importing the module is enough — each scanner has a
            # `_register_rerun_handler()` called at module load.
            import strix.tools.specialist.scan_sqli  # noqa: F401
            import strix.tools.specialist.scan_xss   # noqa: F401
            import strix.tools.specialist.scan_ssrf  # noqa: F401
            import strix.tools.specialist.scan_idor  # noqa: F401
            import strix.tools.specialist.scan_cmd_injection  # noqa: F401
            import strix.tools.specialist.scan_xxe   # noqa: F401
            import strix.tools.specialist.scan_path_traversal  # noqa: F401
        except Exception as e:  # noqa: BLE001
            logger.debug("rerun_registry: scanner registration failed: %s", e)
        _registered = True


def lookup_rerun_lazy(
    *, category: str, cwe: str | None = None,
) -> RerunFn | None:
    """Variant of `lookup_rerun` that lazy-registers scanner
    handlers before lookup. Use this from tool entry points; use
    plain `lookup_rerun` from already-imported code."""
    _ensure_registered()
    return lookup_rerun(category=category, cwe=cwe)


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def get_stats() -> dict[str, Any]:
    """Snapshot — which categories are auto-verifiable."""
    if is_disabled():
        return {"enabled": False, "registered_count": 0}
    return {
        "enabled": True,
        "registered_count": len(_registry),
        "categories": list_registered(),
    }
