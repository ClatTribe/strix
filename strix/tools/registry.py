import inspect
import logging
import os
import re
from collections.abc import Callable, Iterable
from functools import wraps
from inspect import signature
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as DefusedET

from strix.utils.resource_paths import get_strix_resource_path


tools: list[dict[str, Any]] = []
_tools_by_name: dict[str, Callable[..., Any]] = {}
_tool_param_schemas: dict[str, dict[str, Any]] = {}
logger = logging.getLogger(__name__)


class ImplementedInClientSideOnlyError(Exception):
    def __init__(
        self,
        message: str = "This tool is implemented in the client side only",
    ) -> None:
        self.message = message
        super().__init__(self.message)


def _process_dynamic_content(content: str) -> str:
    if "{{DYNAMIC_SKILLS_DESCRIPTION}}" in content:
        try:
            from strix.skills import generate_skills_description

            skills_description = generate_skills_description()
            content = content.replace("{{DYNAMIC_SKILLS_DESCRIPTION}}", skills_description)
        except ImportError:
            logger.warning("Could not import skills utilities for dynamic schema generation")
            content = content.replace(
                "{{DYNAMIC_SKILLS_DESCRIPTION}}",
                "List of skills to load for this agent (max 5). Skill discovery failed.",
            )

    return content


def _load_xml_schema(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        content = path.read_text(encoding="utf-8")

        content = _process_dynamic_content(content)

        start_tag = '<tool name="'
        end_tag = "</tool>"
        tools_dict = {}

        pos = 0
        while True:
            start_pos = content.find(start_tag, pos)
            if start_pos == -1:
                break

            name_start = start_pos + len(start_tag)
            name_end = content.find('"', name_start)
            if name_end == -1:
                break
            tool_name = content[name_start:name_end]

            end_pos = content.find(end_tag, name_end)
            if end_pos == -1:
                break
            end_pos += len(end_tag)

            tool_element = content[start_pos:end_pos]
            tools_dict[tool_name] = tool_element

            pos = end_pos

            if pos >= len(content):
                break
    except (IndexError, ValueError, UnicodeError) as e:
        logger.warning(f"Error loading schema file {path}: {e}")
        return None
    else:
        return tools_dict


def _parse_param_schema(tool_xml: str) -> dict[str, Any]:
    params: set[str] = set()
    required: set[str] = set()

    params_start = tool_xml.find("<parameters>")
    params_end = tool_xml.find("</parameters>")

    if params_start == -1 or params_end == -1:
        return {"params": set(), "required": set(), "has_params": False}

    params_section = tool_xml[params_start : params_end + len("</parameters>")]

    try:
        root = DefusedET.fromstring(params_section)
    except DefusedET.ParseError:
        return {"params": set(), "required": set(), "has_params": False}

    for param in root.findall(".//parameter"):
        name = param.attrib.get("name")
        if not name:
            continue
        params.add(name)
        if param.attrib.get("required", "false").lower() == "true":
            required.add(name)

    return {"params": params, "required": required, "has_params": bool(params or required)}


def _get_module_name(func: Callable[..., Any]) -> str:
    module = inspect.getmodule(func)
    if not module:
        return "unknown"

    module_name = module.__name__
    if ".tools." in module_name:
        parts = module_name.split(".tools.")[-1].split(".")
        if len(parts) >= 1:
            return parts[0]
    return "unknown"


def _get_schema_path(func: Callable[..., Any]) -> Path | None:
    module = inspect.getmodule(func)
    if not module or not module.__name__:
        return None

    module_name = module.__name__

    if ".tools." not in module_name:
        return None

    parts = module_name.split(".tools.")[-1].split(".")
    if len(parts) < 2:
        return None

    folder = parts[0]
    file_stem = parts[1]
    schema_file = f"{file_stem}_schema.xml"

    return get_strix_resource_path("tools", folder, schema_file)


def _is_sandbox_mode() -> bool:
    return os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"


def _is_browser_disabled() -> bool:
    if os.getenv("STRIX_DISABLE_BROWSER", "").lower() == "true":
        return True

    from strix.config import Config

    val: str = Config.load().get("env", {}).get("STRIX_DISABLE_BROWSER", "")
    return str(val).lower() == "true"


def _has_perplexity_api() -> bool:
    if os.getenv("PERPLEXITY_API_KEY"):
        return True

    from strix.config import Config

    return bool(Config.load().get("env", {}).get("PERPLEXITY_API_KEY"))


def _should_register_tool(
    *,
    sandbox_execution: bool,
    requires_browser_mode: bool,
    requires_web_search_mode: bool,
) -> bool:
    sandbox_mode = _is_sandbox_mode()

    if sandbox_mode and not sandbox_execution:
        return False
    if requires_browser_mode and _is_browser_disabled():
        return False
    return not (requires_web_search_mode and not _has_perplexity_api())


_VALID_PROVENANCE_CLASSES = frozenset({
    "trusted_source",   # KEV catalog, OSV.dev, NVD, MITRE static maps —
                        # authoritative third-party intelligence
    "intel_feed",       # VirusTotal, Shodan, GreyNoise, OTX, AbuseIPDB —
                        # third-party reputation feeds (trust with attribution)
    "target",           # any tool whose output is HTTP body / response from
                        # the customer's target — adversarial-by-default
    "operator_input",   # operator-supplied artifact (HAR file, threat model,
                        # prior findings) — trusted but operator-specific
    "framework",        # internal Strix output (notes, todo, thinking, finish) —
                        # not external content at all
    "mixed",            # tool output combines target + intel; agent must
                        # disambiguate per-field
})


def register_tool(
    func: Callable[..., Any] | None = None,
    *,
    sandbox_execution: bool = True,
    requires_browser_mode: bool = False,
    requires_web_search_mode: bool = False,
    mitre_techniques: list[str] | None = None,
    provenance: str | None = None,
) -> Callable[..., Any]:
    """Register a tool.

    `mitre_techniques` (roadmap §10) — optional list of MITRE ATT&CK
    technique IDs (e.g. `["T1190", "T1592.002"]`) describing the
    primary attacker behaviours this tool models / probes for. Surfaces
    on `tool.execution.started` events so defensive consumers can map
    a Strix scan into their own ATT&CK telemetry. Validated against
    the `T<digits>(.<digits>)?` shape; non-matching entries dropped
    (logged at debug level). Tools without explicit techniques get an
    empty list (the field is always present on the event for schema
    stability).

    `provenance` (roadmap §17.6 / §18 row 10) — optional string
    declaring the trust class of the tool's output. The agent's
    system prompt explains that adversarial-by-default classes
    (`target`, `mixed`) require treating output as potentially
    attacker-controlled, while trusted classes (`trusted_source`,
    `intel_feed`, `operator_input`, `framework`) carry stronger
    epistemic weight. Surfaces on `tool.execution.*` events under
    `actor.provenance`. Composes with #84 indirect-prompt-injection
    sanitisation: #84 redacts unsafe patterns from any tool output;
    provenance gives the agent an additional structural signal
    about which outputs to weight more heavily.

    Valid values: `trusted_source` / `intel_feed` / `target` /
    `operator_input` / `framework` / `mixed`. Unrecognised values
    are dropped (logged at debug); tools without explicit
    provenance default to `target` for HTTP-class tools and
    `framework` for in-process tools — but the safer bet is to
    declare explicitly.
    """
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        if not _should_register_tool(
            sandbox_execution=sandbox_execution,
            requires_browser_mode=requires_browser_mode,
            requires_web_search_mode=requires_web_search_mode,
        ):
            return f

        sandbox_mode = _is_sandbox_mode()
        normalized_techniques = _normalize_mitre_techniques(mitre_techniques)

        # Provenance validation. Unrecognised values logged + dropped
        # to None so a downstream consumer never sees a non-canonical
        # class. Default fallback at lookup time (see
        # `get_tool_provenance`) — declaring explicitly is safer.
        normalized_provenance: str | None = None
        if provenance is not None:
            candidate = str(provenance).strip().lower()
            if candidate in _VALID_PROVENANCE_CLASSES:
                normalized_provenance = candidate
            else:
                logger.debug(
                    "tool %s: dropped non-canonical provenance %r (valid: %s)",
                    f.__name__, provenance, sorted(_VALID_PROVENANCE_CLASSES),
                )

        func_dict = {
            "name": f.__name__,
            "function": f,
            "module": _get_module_name(f),
            "sandbox_execution": sandbox_execution,
            "mitre_techniques": normalized_techniques,
            "provenance": normalized_provenance,
        }

        if not sandbox_mode:
            try:
                schema_path = _get_schema_path(f)
                xml_tools = _load_xml_schema(schema_path) if schema_path else None

                if xml_tools is not None and f.__name__ in xml_tools:
                    func_dict["xml_schema"] = xml_tools[f.__name__]
                else:
                    func_dict["xml_schema"] = (
                        f'<tool name="{f.__name__}">'
                        "<description>Schema not found for tool.</description>"
                        "</tool>"
                    )
            except (TypeError, FileNotFoundError) as e:
                logger.warning(f"Error loading schema for {f.__name__}: {e}")
                func_dict["xml_schema"] = (
                    f'<tool name="{f.__name__}">'
                    "<description>Error loading schema.</description>"
                    "</tool>"
                )

        if not sandbox_mode:
            xml_schema = func_dict.get("xml_schema")
            param_schema = _parse_param_schema(xml_schema if isinstance(xml_schema, str) else "")
            _tool_param_schemas[str(func_dict["name"])] = param_schema

        tools.append(func_dict)
        _tools_by_name[str(func_dict["name"])] = f

        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return f(*args, **kwargs)

        return wrapper

    if func is None:
        return decorator
    return decorator(func)


def get_tool_by_name(name: str) -> Callable[..., Any] | None:
    return _tools_by_name.get(name)


def get_tool_names() -> list[str]:
    return list(_tools_by_name.keys())


def get_tool_param_schema(name: str) -> dict[str, Any] | None:
    return _tool_param_schemas.get(name)


# Roadmap §10 — MITRE ATT&CK technique IDs follow `T<digits>(.<digits>)?`
# (e.g. `T1190`, `T1592.002`). We accept the standard shape and drop
# anything else (with a debug log) so registry data stays clean.
_MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _normalize_mitre_techniques(raw: list[str] | None) -> list[str]:
    """Return a deduplicated, validated, upper-cased list of technique IDs."""
    if not raw:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, str):
            continue
        norm = entry.strip().upper()
        if not _MITRE_TECHNIQUE_RE.match(norm):
            logger.debug("dropping non-conforming MITRE technique id: %r", entry)
            continue
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def get_tool_mitre_techniques(name: str) -> list[str]:
    """Return the MITRE ATT&CK technique IDs registered for a tool.

    Empty list when the tool isn't registered with techniques (or
    isn't registered at all). Surfaces in `tool.execution.started`
    events via `Tracer.log_tool_execution_start`.
    """
    for tool in tools:
        if tool.get("name") == name:
            techniques = tool.get("mitre_techniques") or []
            if isinstance(techniques, list):
                return [str(t) for t in techniques]
            return []
    return []


def get_tool_provenance(name: str) -> str:
    """Return the provenance class for a tool. Always returns one
    of the canonical values — falls back to a sensible default
    when the tool didn't declare explicitly.

    Default policy:
      * sandbox_execution=False (in-process / framework tool) → `framework`
      * sandbox_execution=True  (probes the target) → `target`

    Tools that consume third-party intelligence (cve_lookup, kev_diff,
    vt_reputation, etc.) SHOULD declare `intel_feed` or
    `trusted_source` explicitly — the default `target` is safer
    when undeclared.

    Surfaces on `tool.execution.*` events under `actor.provenance`.
    """
    for tool in tools:
        if tool.get("name") == name:
            declared = tool.get("provenance")
            if declared in _VALID_PROVENANCE_CLASSES:
                return str(declared)
            # Default policy.
            if not tool.get("sandbox_execution", True):
                return "framework"
            return "target"
    # Unknown tool — adversarial-by-default.
    return "target"


def needs_agent_state(tool_name: str) -> bool:
    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        return False
    sig = signature(tool_func)
    return "agent_state" in sig.parameters


def should_execute_in_sandbox(tool_name: str) -> bool:
    # Every L1 anchor tool runs inside the strix-sandbox container
    # in production (PRs #384/#386/#387). The bench harness
    # (`bench_l1_only.py`) measures L1 WITHOUT a sandbox — tools
    # with sandbox_execution=True error out, showing a deliberate
    # bench-vs-production gap. The bench captures the lower-bound
    # measurement; production sees the full anchor coverage.
    for tool in tools:
        if tool.get("name") == tool_name:
            return bool(tool.get("sandbox_execution", True))
    return True


def get_tools_prompt(allowlist: "Iterable[str] | None" = None) -> str:
    """Render the tool catalog as XML schema sections for the system
    prompt.

    Args:
        allowlist: optional iterable of tool names; when provided,
            ONLY tools whose `name` is in the set are rendered. The
            lead agent uses this so its prompt only includes the
            tools it can actually call (per the §8.5 catalog filter
            policy). Without this filter, the model sees ~130 tool
            schemas (~80K tokens) including ones the lead is blocked
            from calling — wasted context AND a temptation for the
            model to call blocked tools that the dispatch guard
            (#172) then refuses.

            When None (default), all registered tools are rendered.
            That preserves legacy parent-spawns-N behaviour for
            sub-agents and any other code path that hasn't opted
            into filtering.

    Returns:
        XML-formatted tool catalog grouped by module.
    """
    allowed: set[str] | None = None
    if allowlist is not None:
        allowed = {n for n in allowlist if isinstance(n, str)}

    tools_by_module: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        if allowed is not None and tool.get("name") not in allowed:
            continue
        module = tool.get("module", "unknown")
        if module not in tools_by_module:
            tools_by_module[module] = []
        tools_by_module[module].append(tool)

    xml_sections = []
    for module, module_tools in sorted(tools_by_module.items()):
        tag_name = f"{module}_tools"
        section_parts = [f"<{tag_name}>"]
        for tool in module_tools:
            tool_xml = tool.get("xml_schema", "")
            if tool_xml:
                indented_tool = "\n".join(f"  {line}" for line in tool_xml.split("\n"))
                section_parts.append(indented_tool)
        section_parts.append(f"</{tag_name}>")
        xml_sections.append("\n".join(section_parts))

    return "\n\n".join(xml_sections)


def clear_registry() -> None:
    tools.clear()
    _tools_by_name.clear()
    _tool_param_schemas.clear()
