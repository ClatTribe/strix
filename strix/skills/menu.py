"""Skills menu — progressive-disclosure system-prompt injection (§5 of
strixredteam.md).

Before this module, the lead agent saw only a flat comma-separated
list of skill *names* in the `load_skill` tool description. It had
to guess which one was relevant, or load one speculatively and read
the body before knowing whether it was the right pick. The body of
even one skill is 5-20K tokens — speculative loads were a real cost
sink, and unfamiliar attack classes (e.g. "cache deception" — a real
skill at `strix/skills/vulnerabilities/cache_deception.md`) were
effectively invisible because the agent didn't know to ask.

§5 fixes this with the Decepticon-style two-level disclosure:

  Level 1 — menu (always in the system prompt):
    Available Skills:
      VULNERABILITIES:
      - **sql_injection**: SQL injection testing covering union, blind,
        error-based, and ORM bypass techniques (Triggers: SQL, sqlmap,
        injection)
      ...

  Level 2 — body (fetched on demand via the existing `load_skill` tool).

The menu shows the agent "what's available" so it can pick the right
skill *before* paying the body cost.

## Frontmatter convention

Each `strix/skills/<category>/<skill>.md` already has the basic shape:

```
---
name: skill_name
description: One-line description of what this skill covers.
triggers: [keyword1, keyword2, sqlmap]   # OPTIONAL — Decepticon convention
---
```

`triggers` is optional. When present it's surfaced as a parenthetical
in the menu line, helping the agent keyword-match attack hints in
the user prompt to the skill.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `STRIX_SKILLS_MENU_DISABLED` | unset | Kill switch — empty menu, falls back to legacy flat list |
| `STRIX_SKILLS_MENU_CATEGORIES` | unset (= all) | CSV of categories to include (e.g. `vulnerabilities,tooling`) |
| `STRIX_SKILLS_MENU_MAX_PER_CATEGORY` | unset (= all) | Cap entries per category — useful when the catalog grows |

## Why this is invisible cost reduction

The menu is ~50-100 tokens per skill (vs. 5-20K for the body). For a
~45-skill catalog that is roughly 4-6K tokens added to the system
prompt — paid once at boot, not per call. The savings come from
*not* speculatively loading bodies the agent didn't need, which was
the actual context killer in long runs.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from strix.utils.resource_paths import get_strix_resource_path


logger = logging.getLogger(__name__)


# Categories that aren't user-facing skills — `scan_modes` is the
# behind-the-scenes scan profile, `coordination` is internal handoff
# guidance loaded by the lead automatically. Mirrors the same set
# in `strix/skills/__init__.py::_EXCLUDED_CATEGORIES`.
_EXCLUDED_CATEGORIES = frozenset({"scan_modes", "coordination"})

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_FIELD_RE = re.compile(r"^(\w+)\s*:\s*(.*)$", re.MULTILINE)

# Display ordering for categories — vulnerabilities first (the
# bread-and-butter), then tooling, then everything else alphabetical.
# Phase 4: `chains/` houses cross-cutting meta-skills (KG traversal,
# attack-path synthesis, unknown-vuln hypothesis); displayed after
# the specific-vulnerability and recon skills so the agent reaches
# for it when stuck.
_CATEGORY_ORDER = (
    "vulnerabilities",
    "tooling",
    "protocols",
    "technologies",
    "reconnaissance",
    "frameworks",
    "cloud",
    "chains",
    "custom",
)


def is_menu_disabled() -> bool:
    """Kill switch — when set, `generate_skills_menu` returns the
    empty string, falling back to the legacy `generate_skills_description`
    flat list (which is still wired into the `load_skill` tool's
    `skills` parameter description)."""
    return os.environ.get(
        "STRIX_SKILLS_MENU_DISABLED", ""
    ).lower() in ("1", "true", "yes", "on")


def _get_category_filter() -> set[str] | None:
    """Optional CSV env var to restrict the menu to specific
    categories. Empty / unset = all categories."""
    raw = (os.environ.get("STRIX_SKILLS_MENU_CATEGORIES") or "").strip()
    if not raw:
        return None
    parts = {p.strip() for p in raw.split(",") if p.strip()}
    return parts or None


def _get_max_per_category() -> int | None:
    raw = (os.environ.get("STRIX_SKILLS_MENU_MAX_PER_CATEGORY") or "").strip()
    if not raw:
        return None
    try:
        v = int(float(raw))
    except (ValueError, TypeError):
        return None
    return max(1, v)


def parse_skill_frontmatter(path: Path) -> dict[str, Any] | None:
    """Parse a SKILL.md frontmatter block. Returns a dict with at
    least `name` + `description`, plus `triggers` (list[str]) if
    present. Returns None if the file is unreadable, has no
    frontmatter, or is malformed.

    Tolerant by design — a single bad skill file should not break
    menu rendering for the whole catalog."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        logger.debug("could not read skill file %s: %s", path, e)
        return None

    m = _FRONTMATTER_RE.match(text)
    if not m:
        return None

    raw_block = m.group(1)
    fields: dict[str, Any] = {}
    for field_match in _FIELD_RE.finditer(raw_block):
        key = field_match.group(1).strip()
        value = field_match.group(2).strip()
        if key == "triggers":
            fields[key] = _parse_triggers(value)
        else:
            fields[key] = value

    if "name" not in fields or "description" not in fields:
        return None

    return fields


def _parse_triggers(raw: str) -> list[str]:
    """Parse a YAML-style triggers list. Supports two shapes:

      triggers: [sqlmap, sql injection, union]
      triggers: sqlmap, sql injection, union

    Returns a deduplicated, order-preserving list of trigger
    keywords. Returns empty list when malformed — never raises."""
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    seen: set[str] = set()
    out: list[str] = []
    for piece in raw.split(","):
        kw = piece.strip().strip("'\"")
        if not kw or kw in seen:
            continue
        seen.add(kw)
        out.append(kw)
    return out


def _collect_skills() -> dict[str, list[dict[str, Any]]]:
    """Walk `strix/skills/` and parse frontmatter for every
    `<category>/<skill>.md`. Returns `{category: [{name, description,
    triggers}, ...]}` with categories alphabetised within and the
    skills sorted by name.

    Excluded categories (`scan_modes`, `coordination`) and skills
    missing required frontmatter are silently dropped."""
    skills_dir = get_strix_resource_path("skills")
    if not skills_dir.exists():
        return {}

    out: dict[str, list[dict[str, Any]]] = {}
    for category_dir in sorted(skills_dir.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        category = category_dir.name
        if category in _EXCLUDED_CATEGORIES:
            continue

        entries: list[dict[str, Any]] = []
        for skill_path in sorted(category_dir.glob("*.md")):
            parsed = parse_skill_frontmatter(skill_path)
            if not parsed:
                continue
            # Use the filename stem as the canonical key — `load_skill`
            # looks up by `category/stem` or just `stem`, and many of
            # the existing files have `name:` with hyphens while the
            # filename uses underscores (e.g. `sql-injection` vs
            # `sql_injection.md`). The filename is the truth.
            parsed["name"] = skill_path.stem
            entries.append(parsed)

        if entries:
            out[category] = entries

    return out


def _ordered_categories(categories: list[str]) -> list[str]:
    """Order categories using `_CATEGORY_ORDER` as a preference list,
    with anything not in the preference appended alphabetically.
    Stable so the system prompt doesn't reshuffle between runs."""
    pref = [c for c in _CATEGORY_ORDER if c in categories]
    rest = sorted(c for c in categories if c not in _CATEGORY_ORDER)
    return pref + rest


def generate_skills_menu(
    *,
    category_filter: set[str] | None = None,
    max_per_category: int | None = None,
) -> str:
    """Build the agent-facing skills menu — categorised list of
    `**name**: description (Triggers: kw1, kw2)` lines plus a header
    telling the agent how to fetch a body.

    Args:
      category_filter: when given, only include these categories.
        Defaults to env-driven `STRIX_SKILLS_MENU_CATEGORIES` or all.
      max_per_category: cap entries per category. Defaults to env-driven
        `STRIX_SKILLS_MENU_MAX_PER_CATEGORY` or unlimited.

    Returns the empty string when:
      - the kill switch is set, OR
      - no parseable skills exist (defensive)

    The empty string is the signal to the caller's template to fall
    back to the legacy flat list (which is in the `load_skill` tool's
    parameter description regardless)."""
    if is_menu_disabled():
        return ""

    if category_filter is None:
        category_filter = _get_category_filter()
    if max_per_category is None:
        max_per_category = _get_max_per_category()

    catalog = _collect_skills()
    if not catalog:
        return ""

    if category_filter:
        catalog = {k: v for k, v in catalog.items() if k in category_filter}
        if not catalog:
            return ""

    lines: list[str] = [
        "Available Skills (Level-1 menu — load bodies with `load_skill` when relevant):",
        "",
    ]

    for category in _ordered_categories(list(catalog.keys())):
        entries = catalog[category]
        if max_per_category:
            entries = entries[:max_per_category]
        if not entries:
            continue

        lines.append(f"  {category.upper()}:")
        for entry in entries:
            line = f"  - **{entry['name']}**: {entry['description']}"
            triggers = entry.get("triggers") or []
            if triggers:
                line += f" (Triggers: {', '.join(triggers)})"
            lines.append(line)
        lines.append("")

    lines.append(
        "Pick a skill by name and pass it to `load_skill` when its "
        "description matches the surface or class you're testing. "
        "Don't load bodies speculatively — the menu above is the "
        "discovery layer; the body is the workflow layer."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Inspection helpers (tests + telemetry)
# ---------------------------------------------------------------------------


def get_menu_stats() -> dict[str, Any]:
    """Snapshot of menu state — useful for run_meta.json so wrappers
    can see how the agent's skill catalog was shaped this run."""
    if is_menu_disabled():
        return {"enabled": False, "categories": 0, "skills": 0}
    catalog = _collect_skills()
    total = sum(len(v) for v in catalog.values())
    return {
        "enabled": True,
        "categories": len(catalog),
        "skills": total,
        "category_filter": sorted(_get_category_filter() or []),
        "max_per_category": _get_max_per_category(),
    }
