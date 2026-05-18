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


# ---------------------------------------------------------------------------
# Phase 6 — KG-driven + asset-driven auto-load mappings
# ---------------------------------------------------------------------------
#
# Today's skill loaders:
#   - Manual via `load_skill` tool (the lead calls it explicitly)
#   - Fingerprint auto-load in `strix/tools/recon/fingerprint.py`
#     (tech-stack detection → skill list)
#   - Orchestrator auto-bind via SpecialistDispatchProfile (PR #325 / §1C)
#
# Phase 6 adds two more loaders:
#   - KG-node-kind → skill: when a `CloudResource` of subtype `aws_lambda`
#     enters the graph, the lead should already know `aws_lambda_attack_surface`
#   - Discovered-asset → skill: `assets.discovered.jsonl` rows declare
#     `type` (web_application / repository / cloud_account / etc.) and
#     `canonical_id` from which we derive richer skill recommendations
#
# Both new loaders compose with the existing two via union (deduplicated).
# Callers query `get_auto_load_skills(target_types=..., kg_node_kinds=...,
# discovered_assets=...)` to get the full pre-attach list.


# Maps KG node kind / subtype to skill names. When a node of this
# kind appears in the project KG (after one or more scans), the
# lead should boot with these skills pre-attached.
#
# Order matters within each list — higher-impact / broader skills
# first, so they're chosen first when the cap is hit.
KG_NODE_KIND_TO_SKILL: dict[str, list[str]] = {
    # Generic node-kind defaults
    "CloudResource": ["cloud_attack_path_traversal"],
    "CloudIdentity": ["aws_iam_chains", "cloud_attack_path_traversal"],
    "Surface": ["asset_discovery_pipeline"],
    "Asset": ["asset_discovery_pipeline"],
    "Vuln": ["cross_asset_chains", "attack_path_synthesis"],
    "Credential": ["cross_asset_chains"],
    "Secret": ["aws_secrets_manager", "cross_asset_chains"],
    "Dependency": ["threat_intel_pivoting"],
    "Role": ["aws_iam_chains", "azure_rbac_chains", "gcp_iam_chains"],
}


# Subtype refinements — when a node has an `attrs.service` or
# `attrs.kind` that's more specific, override / extend the kind-level
# mapping. Keys are concrete subtype strings observed in CloudGraph.
KG_NODE_SUBTYPE_TO_SKILL: dict[str, list[str]] = {
    # AWS resource subtypes
    "aws_s3": ["aws_s3_attack_surface"],
    "aws_lambda": ["aws_lambda_attack_surface"],
    "aws_rds": ["aws_rds_attack_surface"],
    "aws_dynamodb": ["aws_iam_chains"],
    "aws_iam_user": ["aws_iam_chains"],
    "aws_iam_role": ["aws_iam_chains"],
    "aws_secretsmanager": ["aws_secrets_manager"],
    "aws_ec2": ["aws_iam_chains"],
    # Azure
    "azure_storage": ["azure_blob_attack_surface"],
    "azure_blob": ["azure_blob_attack_surface"],
    "azure_function": ["azure_rbac_chains"],
    "azure_vm": ["azure_rbac_chains"],
    # GCP
    "gcp_storage": ["aws_s3_attack_surface"],  # similar shape; keep for proximity
    "gcp_bigquery": ["gcp_bigquery_attack_surface"],
    "gcp_cloudrun": ["gcp_cloud_run_attack_surface"],
    "gcp_cloudfunction": ["gcp_cloud_run_attack_surface"],
    "gcp_iam_sa": ["gcp_iam_chains"],
    # Container
    "container_image": ["dspm_pii_classification"],
    # GraphQL endpoint
    "graphql_endpoint": ["graphql"],
}


# Maps discovered-asset types (`assets.discovered.jsonl`) to skills.
# This fires at scan-setup time when the wrapper passes pre-discovered
# inventory into the engine. Different from KG-node mapping because
# discovered-assets are typed at the wrapper boundary, before any
# scan-side graph nodes exist.
DISCOVERED_ASSET_TYPE_TO_SKILL: dict[str, list[str]] = {
    "web_application": ["asset_discovery_pipeline"],
    "api": ["openapi_recon", "asset_discovery_pipeline"],
    "domain": ["subdomain_strategy", "dns_hygiene_attacks"],
    "ip_address": ["threat_intel_pivoting"],
    "repository": ["asset_discovery_pipeline"],
    "container_image": ["dspm_pii_classification"],
    "cloud_account": [
        "cloud_attack_path_traversal", "aws_iam_chains",
        "azure_rbac_chains", "gcp_iam_chains",
    ],
}


# Per-target-type baseline skills that should always be in scope
# regardless of KG / discovered-asset state. These are the "if you
# only know the target type, load these" defaults.
TARGET_TYPE_TO_SKILL: dict[str, list[str]] = {
    "web_application": [
        "asset_discovery_pipeline",
        "har_burp_ingestion",
    ],
    "api": ["openapi_recon", "asset_discovery_pipeline"],
    "domain": [
        "subdomain_strategy",
        "dns_hygiene_attacks",
        "threat_intel_pivoting",
    ],
    "ip_address": ["threat_intel_pivoting"],
    "repository": ["asset_discovery_pipeline"],
    "cloud_account": [
        "cloud_attack_path_traversal",
        "kev_diff_workflow",
        "threat_intel_pivoting",
    ],
    "container_image": ["dspm_pii_classification"],
}


def get_skills_for_kg_node(
    kind: str, attrs: dict | None = None,
) -> list[str]:
    """Return the skill names suggested for a KG node of this
    kind/subtype. Used by the orchestrator to pre-attach skills
    when the KG indicates a relevant resource is present."""
    skills: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            skills.append(name)

    # Kind-level defaults
    for s in KG_NODE_KIND_TO_SKILL.get(kind, []):
        _add(s)

    # Subtype refinement (when attrs supplies it)
    if attrs:
        subtype = (
            attrs.get("service")
            or attrs.get("kind")
            or attrs.get("subtype")
            or ""
        )
        for s in KG_NODE_SUBTYPE_TO_SKILL.get(subtype, []):
            _add(s)

    # Cross-check: skills must exist in the catalog. Silently drop
    # references to deleted skills; the parity test catches them.
    available = get_all_skill_names()
    return [s for s in skills if s in available]


def get_skills_for_discovered_asset(
    asset_type: str,
) -> list[str]:
    """Return the skill names for a discovered-asset type. Used at
    scan setup when `assets.discovered.jsonl` is consumed."""
    available = get_all_skill_names()
    return [
        s for s in DISCOVERED_ASSET_TYPE_TO_SKILL.get(asset_type, [])
        if s in available
    ]


def get_skills_for_target_type(target_type: str) -> list[str]:
    """Baseline skills for a target type — fires before any KG state
    is established. Combines with KG-node + discovered-asset
    mappings at lead boot."""
    available = get_all_skill_names()
    return [
        s for s in TARGET_TYPE_TO_SKILL.get(target_type, [])
        if s in available
    ]


def get_auto_load_skills(
    *,
    target_types: list[str] | None = None,
    kg_node_kinds: list[tuple[str, dict | None]] | None = None,
    discovered_asset_types: list[str] | None = None,
    max_skills: int | None = None,
) -> list[str]:
    """Union the three Phase 6 auto-load sources into a deduplicated
    skill list ordered by leverage.

    Args:
      target_types: e.g. ['web_application', 'cloud_account']
      kg_node_kinds: list of (kind, attrs_dict) for nodes already
        in the project KG. attrs may be None.
      discovered_asset_types: e.g. ['web_application', 'cloud_account']
        — from assets.discovered.jsonl
      max_skills: optional cap. Defaults to `get_max_skills_per_agent()`.

    The function:
      1. Walks discovered-asset types (richest signal)
      2. Adds target-type baselines
      3. Adds KG-node-kind refinements
      4. Dedups + caps

    Returns the skill name list ready to pass to `load_skills(...)`.
    """
    cap = max_skills if max_skills is not None else get_max_skills_per_agent()
    out: list[str] = []
    seen: set[str] = set()

    def _add_all(names: list[str]) -> None:
        for n in names:
            if n not in seen and len(out) < cap:
                seen.add(n)
                out.append(n)

    # Order: discovered-assets (operator-curated, richest) > target_types
    # > KG-node (refinement after the run starts gathering nodes)
    for at in (discovered_asset_types or []):
        _add_all(get_skills_for_discovered_asset(at))
    for tt in (target_types or []):
        _add_all(get_skills_for_target_type(tt))
    for kind, attrs in (kg_node_kinds or []):
        _add_all(get_skills_for_kg_node(kind, attrs))

    return out


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
