import os
import re

from strix.utils.resource_paths import get_strix_resource_path


_EXCLUDED_CATEGORIES = {"scan_modes", "coordination"}
_FRONTMATTER_PATTERN = re.compile(r"^---\s*\n.*?\n---\s*\n", re.DOTALL)


# Phase 1C — raise hard 5-cap to env-tunable default 20.
#
# The 5-cap predates the Decepticon two-level menu (strix/skills/menu.py):
# in the old model every skill body sat in the system prompt at agent
# boot, so 5 bodies × ~5-20K tokens already cost 25-100K. With the menu
# in place only the (~50-100 token) menu line per skill is fixed; the
# body costs only when the agent calls `load_skill`. Multi-stack apps
# (Django + Postgres + Stripe + Auth0 + AWS + Cloudflare) routinely
# warrant more than 5 skills; the cap was the bottleneck.
#
# The new default of 20 covers every realistic stack we've seen in
# vibe-coded SaaS audits while still preventing pathological loads.
# Operators can dial higher via `STRIX_SKILLS_MAX_PER_AGENT`. A future
# Phase 1F upgrade will swap the count-based cap for a token-budget
# cap (`STRIX_SKILLS_TOKEN_BUDGET`); the count cap is the safer first
# step and stays as the fallback.
_DEFAULT_MAX_SKILLS_PER_AGENT = 20


def get_max_skills_per_agent() -> int:
    """Resolve the per-agent skill-count cap from the env or fall back
    to the default. Always returns a positive int."""
    raw = (os.environ.get("STRIX_SKILLS_MAX_PER_AGENT") or "").strip()
    if not raw:
        return _DEFAULT_MAX_SKILLS_PER_AGENT
    try:
        n = int(float(raw))
    except (ValueError, TypeError):
        return _DEFAULT_MAX_SKILLS_PER_AGENT
    return max(1, n)


def get_available_skills() -> dict[str, list[str]]:
    skills_dir = get_strix_resource_path("skills")
    available_skills: dict[str, list[str]] = {}

    if not skills_dir.exists():
        return available_skills

    for category_dir in skills_dir.iterdir():
        if category_dir.is_dir() and not category_dir.name.startswith("__"):
            category_name = category_dir.name

            if category_name in _EXCLUDED_CATEGORIES:
                continue

            skills = []

            for file_path in category_dir.glob("*.md"):
                skill_name = file_path.stem
                skills.append(skill_name)

            if skills:
                available_skills[category_name] = sorted(skills)

    return available_skills


def get_all_skill_names() -> set[str]:
    all_skills = set()
    for category_skills in get_available_skills().values():
        all_skills.update(category_skills)
    return all_skills


def validate_skill_names(skill_names: list[str]) -> dict[str, list[str]]:
    available_skills = get_all_skill_names()
    valid_skills = []
    invalid_skills = []

    for skill_name in skill_names:
        if skill_name in available_skills:
            valid_skills.append(skill_name)
        else:
            invalid_skills.append(skill_name)

    return {"valid": valid_skills, "invalid": invalid_skills}


def parse_skill_list(skills: str | None) -> list[str]:
    if not skills:
        return []
    return [s.strip() for s in skills.split(",") if s.strip()]


def validate_requested_skills(
    skill_list: list[str], max_skills: int | None = None,
) -> str | None:
    """Validate a skill-name list against the registry + the per-agent
    count cap. The cap defaults to `get_max_skills_per_agent()` (env-
    tunable via `STRIX_SKILLS_MAX_PER_AGENT`, default 20). Pass an
    explicit `max_skills` to override for a specific call site."""
    cap = max_skills if max_skills is not None else get_max_skills_per_agent()
    if len(skill_list) > cap:
        return (
            f"Cannot specify more than {cap} skills for an agent "
            f"(set STRIX_SKILLS_MAX_PER_AGENT to raise; default is "
            f"{_DEFAULT_MAX_SKILLS_PER_AGENT}). Use comma-separated "
            f"format."
        )

    if not skill_list:
        return None

    validation = validate_skill_names(skill_list)
    if validation["invalid"]:
        available_skills = list(get_all_skill_names())
        return (
            f"Invalid skills: {validation['invalid']}. "
            f"Available skills: {', '.join(available_skills)}"
        )

    return None


def generate_skills_description() -> str:
    available_skills = get_available_skills()

    if not available_skills:
        return "No skills available"

    all_skill_names = get_all_skill_names()

    if not all_skill_names:
        return "No skills available"

    sorted_skills = sorted(all_skill_names)
    skills_str = ", ".join(sorted_skills)

    cap = get_max_skills_per_agent()
    description = (
        f"List of skills to load for this agent (max {cap}). "
        f"Available skills: {skills_str}. "
    )

    example_skills = sorted_skills[:2]
    if example_skills:
        example = f"Example: {', '.join(example_skills)} for specialized agent"
        description += example

    return description


def _get_all_categories() -> dict[str, list[str]]:
    """Get all skill categories including internal ones (scan_modes, coordination)."""
    skills_dir = get_strix_resource_path("skills")
    all_categories: dict[str, list[str]] = {}

    if not skills_dir.exists():
        return all_categories

    for category_dir in skills_dir.iterdir():
        if category_dir.is_dir() and not category_dir.name.startswith("__"):
            category_name = category_dir.name
            skills = []

            for file_path in category_dir.glob("*.md"):
                skill_name = file_path.stem
                skills.append(skill_name)

            if skills:
                all_categories[category_name] = sorted(skills)

    return all_categories


def load_skills(
    skill_names: list[str],
    *,
    loaded_by: str = "unknown",
) -> dict[str, str]:
    """Load skill bodies for the given names. Returns a `{name: body}`
    dict. Frontmatter is stripped from the returned body so it's safe
    to embed in a system prompt directly.

    Phase 5: each successful load emits a `skill.loaded` event via the
    global tracer with `loaded_by` attribution (e.g. 'orchestrator',
    'lead_manual', 'fingerprint_auto'). Failures swallowed; the
    telemetry path never breaks skill loading.
    """
    import logging

    logger = logging.getLogger(__name__)
    skill_content = {}
    skills_dir = get_strix_resource_path("skills")

    all_categories = _get_all_categories()

    for skill_name in skill_names:
        try:
            skill_path = None

            if "/" in skill_name:
                skill_path = f"{skill_name}.md"
            else:
                for category, skills in all_categories.items():
                    if skill_name in skills:
                        skill_path = f"{category}/{skill_name}.md"
                        break

                if not skill_path:
                    root_candidate = f"{skill_name}.md"
                    if (skills_dir / root_candidate).exists():
                        skill_path = root_candidate

            if skill_path and (skills_dir / skill_path).exists():
                full_path = skills_dir / skill_path
                var_name = skill_name.split("/")[-1]
                content = full_path.read_text(encoding="utf-8")
                content = _FRONTMATTER_PATTERN.sub("", content).lstrip()
                skill_content[var_name] = content
                logger.info(f"Loaded skill: {skill_name} -> {var_name}")
                _emit_skill_loaded(
                    skill_name=var_name,
                    skill_path=str(skill_path),
                    body_size=len(content),
                    loaded_by=loaded_by,
                )
            else:
                logger.warning(f"Skill not found: {skill_name}")

        except (FileNotFoundError, OSError, ValueError) as e:
            logger.warning(f"Failed to load skill {skill_name}: {e}")

    return skill_content


def _emit_skill_loaded(
    *,
    skill_name: str,
    skill_path: str,
    body_size: int,
    loaded_by: str,
) -> None:
    """Best-effort emission of a `skill.loaded` event. Phase 5 instruments
    the skill-load path so the wrapper can render:
      * which skills the agent actually loaded per run
      * which loader fired (orchestrator binding vs lead manual vs
        fingerprint auto-load)
      * total skill-context token budget consumed

    Failures swallowed — telemetry must NEVER break skill loading."""
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return
        # Use the existing `emit_event` API if available; otherwise the
        # `add_event` shape. Tolerant to both since the tracer's API
        # has shifted across releases.
        evt = {
            "kind": "skill.loaded",
            "skill_name": skill_name,
            "skill_path": skill_path,
            "body_size_chars": body_size,
            "loaded_by": loaded_by,
        }
        # Try common emission APIs in order
        if hasattr(tracer, "emit_event"):
            tracer.emit_event(**evt)
        elif hasattr(tracer, "add_event"):
            tracer.add_event(evt)
        elif hasattr(tracer, "_events") and isinstance(tracer._events, list):
            tracer._events.append(evt)
    except Exception:  # noqa: BLE001 — telemetry must not break callers
        pass


def get_skill_frontmatter(skill_name: str) -> dict | None:
    """Read frontmatter for a skill by name. Returns parsed dict or None.
    Used by the freshness inspector + by tests to verify metadata.

    Phase 5 conventions: `last_updated` (ISO date), `version` (int)."""
    import re

    skills_dir = get_strix_resource_path("skills")
    all_categories = _get_all_categories()

    skill_path = None
    if "/" in skill_name:
        skill_path = f"{skill_name}.md"
    else:
        for category, skills in all_categories.items():
            if skill_name in skills:
                skill_path = f"{category}/{skill_name}.md"
                break

    if skill_path is None:
        return None
    full_path = skills_dir / skill_path
    if not full_path.exists():
        return None

    try:
        text = full_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not m:
        return None
    block = m.group(1)
    out: dict = {}
    for line in block.split("\n"):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip()
    return out
