"""Coverage matrix per target type.

Defines the *minimum* set of attack categories that should be checked for each
target type at each scan mode. At run completion, the tracer compares this
matrix against the categories that actually have a `check.completed` event
and emits a `run.coverage_gap` event for any missing categories — plus
persists the comparison to `coverage.json`.

This is roadmap §7.0 — turning "comprehensive scan" from a vibe into a
deterministic guarantee. A scan that misses a required category is a
regression, not a model preference.

The matrix is conservative: it lists only the categories that are reasonably
achievable today given the tools strix actually ships. Adding a category
without an executable path that emits the matching `check.completed` event
would mean the scan can never satisfy coverage for that target type — that's
worse than no matrix.

Override via `STRIX_COVERAGE_MATRIX_PATH=/path/to/file.json` (JSON with the
same shape as `_DEFAULT_MATRIX`) when an organisation has stricter standards.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# Per (target_type, scan_mode) → set of required category names.
# Categories must match the values used by `tracer.start_check(category=...)`.
# Add a new row here only after the corresponding tool / skill exists in main —
# otherwise the scan can't satisfy coverage and the matrix is just noise.
_DEFAULT_MATRIX: dict[str, dict[str, list[str]]] = {
    "domain": {
        "quick": ["dns_security", "subdomain_takeover"],
        "standard": ["dns_security", "email_security", "subdomain_takeover"],
        "deep": [
            "dns_security",
            "email_security",
            "subdomain_takeover",
            "info_disclosure",  # cloud asset discovery files findings under this category
        ],
    },
    "web_application": {
        "quick": ["sqli", "xss", "idor"],
        "standard": [
            "sqli",
            "xss",
            "idor",
            "ssrf",
            "csrf",
            "open_redirect",
        ],
        "deep": [
            "sqli",
            "xss",
            "idor",
            "ssrf",
            "csrf",
            "authz",
            "auth",
            "open_redirect",
            "jwt",
        ],
    },
    "ip_address": {
        "quick": [],  # nmap-driven; no deterministic tool emits checks yet
        "standard": [],
        "deep": [],
    },
    "local_code": {
        "quick": [],  # awaiting Code-Map / SAST first-pass tools (§7.1)
        "standard": [],
        "deep": [],
    },
    "repository": {
        "quick": [],
        "standard": [],
        "deep": [],
    },
}


def _load_override() -> dict[str, dict[str, list[str]]] | None:
    path = os.environ.get("STRIX_COVERAGE_MATRIX_PATH")
    if not path:
        return None
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            data = json.load(f)
        # Light validation — must be {target_type: {scan_mode: [...] }}.
        if not isinstance(data, dict):
            return None
        for tt, modes in data.items():
            if not isinstance(modes, dict):
                return None
            for sm, cats in modes.items():
                if not isinstance(cats, list) or not all(isinstance(c, str) for c in cats):
                    return None
        return data
    except (OSError, json.JSONDecodeError):
        logger.warning("STRIX_COVERAGE_MATRIX_PATH=%s could not be loaded", path, exc_info=True)
        return None


def get_matrix() -> dict[str, dict[str, list[str]]]:
    return _load_override() or _DEFAULT_MATRIX


def required_categories(target_types: list[str], scan_mode: str) -> set[str]:
    """Union of required categories across the given target types for the
    selected scan mode. Falls back to 'standard' for unknown scan modes."""
    matrix = get_matrix()
    mode = scan_mode if scan_mode in {"quick", "standard", "deep"} else "standard"
    out: set[str] = set()
    for tt in target_types:
        per_mode = matrix.get(tt) or {}
        cats = per_mode.get(mode) or []
        out.update(cats)
    return out


def compute_gaps(
    target_types: list[str],
    scan_mode: str,
    completed_categories: set[str],
) -> dict[str, Any]:
    """Compare what was checked against the required matrix.

    Returns a structured report:
      {
        target_types, scan_mode, required, completed, gaps,
        covered, coverage_percent, status: 'complete'|'incomplete'|'no_matrix'
      }

    `coverage_percent` is None when the required set is empty (avoid divide-by-zero
    and the misleading "100% coverage" claim when no requirements exist for this
    target type yet).
    """
    required = sorted(required_categories(target_types, scan_mode))
    completed = sorted(c for c in completed_categories if c)
    completed_set = set(completed)
    gaps = sorted(c for c in required if c not in completed_set)
    covered = sorted(c for c in required if c in completed_set)

    if not required:
        status = "no_matrix"
        coverage_pct: float | None = None
    elif gaps:
        status = "incomplete"
        coverage_pct = round(len(covered) / len(required), 3)
    else:
        status = "complete"
        coverage_pct = 1.0

    return {
        "target_types": sorted(set(target_types)),
        "scan_mode": scan_mode,
        "required": required,
        "completed": completed,
        "covered": covered,
        "gaps": gaps,
        "coverage_percent": coverage_pct,
        "status": status,
    }
