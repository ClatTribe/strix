"""Convert strix tool XML schemas to OpenAI-style JSON Schema for
native tool calling (roadmap §8.5 Phase 4).

Why a converter
---------------

Strix's existing tool registry stores `xml_schema` strings shaped like:

    <tool name="scan_xss">
      <description>Probe URLs for reflected XSS...</description>
      <parameters>
        <parameter name="url" type="string" required="true">
          <description>Target URL.</description>
        </parameter>
        <parameter name="params" type="array" required="false">
          <description>Param names to probe.</description>
        </parameter>
      </parameters>
      <returns type="dict"/>
    </tool>

These render into the system prompt as text. The model then writes
`<function=scan_xss>...<parameter=url>...</parameter></function>`
which strix parses out of the raw response. That round-trip is the
source of every prompt-compliance failure surfaced by PRs #163-#175:
gemini outputting `<tool_code>`, `<start_code>`, wrong param names,
JSON-as-string, `param=` (singular) vs `params=` (plural), etc.

Native tool calling (this module's foundation) bypasses that
entirely: the LLM provider receives `tools=[...]` JSON Schema,
returns structured `tool_calls` blocks the API itself validated.
The model can't malform a call because the schema is enforced
provider-side.

Output shape
------------

This module produces OpenAI's tool-use shape which litellm
normalises across providers (Anthropic, Gemini, etc.):

    {
        "type": "function",
        "function": {
            "name": "scan_xss",
            "description": "Probe URLs for reflected XSS...",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL."},
                    "params": {"type": "array", "items": {"type": "string"},
                               "description": "Param names to probe."}
                },
                "required": ["url"]
            }
        }
    }

Coverage notes
--------------

Phase 4a (this PR) handles the common case: scalar param types
(string, number, integer, boolean), object, and array (with default
string items). Full coverage of nested schemas, enums in the XML
`<allowed>` lists, and `default=` attributes is Phase 4b — additive,
won't break existing tool definitions. The converter is conservative:
when in doubt, falls back to `{"type": "string"}` so the model can
still call the tool with reasonable args; runtime validation in the
tool implementation catches the mismatch.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

import defusedxml.ElementTree as DefusedET


logger = logging.getLogger(__name__)


# Mapping from strix XML `type=` attribute values to JSON Schema
# `type` strings. Values not in this map fall back to `"string"`.
_TYPE_MAP: dict[str, str] = {
    "string": "string",
    "str": "string",
    "text": "string",
    "number": "number",
    "float": "number",
    "double": "number",
    "integer": "integer",
    "int": "integer",
    "boolean": "boolean",
    "bool": "boolean",
    "object": "object",
    "dict": "object",
    "array": "array",
    "list": "array",
}


def xml_to_function_schema(xml_text: str) -> dict[str, Any] | None:
    """Convert one tool's XML schema to OpenAI function-call shape.

    Returns None when the input isn't parseable or doesn't have the
    expected `<tool name="...">` envelope. Best-effort: any unparsed
    quirk falls back to a usable shape rather than raising.

    Note on parse strategy: many tool XML schemas contain `<examples>`
    blocks with strix's tool-call notation (e.g.
    `<function=create_agent>`, `<parameter=task>`) which is NOT valid
    XML — `=` is illegal in element names. So a whole-document parse
    fails on those tools. This function extracts the parseable
    subsections (top-level name attribute, top-level `<description>`,
    `<parameters>`) via substring/regex first, then parses only those
    fragments via DefusedET. Robust against arbitrary garbage in
    `<examples>` / `<details>` / `<returns>` / etc.

    Args:
        xml_text: the `<tool name="...">...</tool>` XML string from
            the tool registry.

    Returns:
        `{"type": "function", "function": {"name", "description",
        "parameters"}}` or None.
    """
    if not xml_text or not isinstance(xml_text, str):
        return None

    name = _extract_tool_name(xml_text)
    if not name:
        return None

    description = _extract_top_description(xml_text)
    properties, required = _extract_parameters_section(xml_text)

    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def _extract_tool_name(xml_text: str) -> str | None:
    """Pull the `name="..."` attribute from the first `<tool ...>`
    open tag. Doesn't require well-formed XML."""
    import re as _re
    m = _re.search(r'<tool\s+name="([^"]+)"', xml_text)
    return m.group(1) if m else None


def _extract_top_description(xml_text: str) -> str:
    """Pull just the FIRST top-level `<description>...</description>`
    block. Uses substring search rather than full XML parse so
    invalid examples blocks elsewhere don't trip us up. Truncated to
    1500 chars (some providers reject longer)."""
    import re as _re
    # First `<description>...</description>` after the `<tool ...>` tag.
    # Non-greedy so we stop at the first close tag.
    tool_open_end = xml_text.find(">")
    if tool_open_end == -1:
        return ""
    rest = xml_text[tool_open_end + 1:]
    m = _re.search(r"<description>(.*?)</description>", rest, _re.DOTALL)
    if not m:
        return ""
    text = m.group(1).strip()
    if len(text) > 1500:
        text = text[:1500].rstrip() + " […]"
    return text


def _extract_parameters_section(xml_text: str) -> tuple[dict[str, Any], list[str]]:
    """Locate the `<parameters>...</parameters>` block and parse only
    that as XML (it's the canonical strix parameter format and is
    well-formed by convention)."""
    start = xml_text.find("<parameters>")
    end = xml_text.find("</parameters>")
    if start == -1 or end == -1:
        return {}, []
    section = xml_text[start:end + len("</parameters>")]
    try:
        root = DefusedET.fromstring(section)
    except DefusedET.ParseError as e:
        logger.debug("_extract_parameters_section: parse failed: %s", e)
        return {}, []
    return _extract_parameters(root)


def _extract_parameters(
    params_node: Any,
) -> tuple[dict[str, Any], list[str]]:
    """Walk `<parameters>` → `(properties_dict, required_list)`."""
    if params_node is None:
        return {}, []

    properties: dict[str, Any] = {}
    required: list[str] = []

    for param in params_node.findall("parameter"):
        pname = param.attrib.get("name")
        if not pname:
            continue
        ptype_raw = (param.attrib.get("type") or "string").lower()
        ptype = _TYPE_MAP.get(ptype_raw, "string")
        prequired = param.attrib.get("required", "false").lower() == "true"
        pdesc_node = param.find("description")
        pdesc = pdesc_node.text.strip() if pdesc_node is not None and pdesc_node.text else ""
        if len(pdesc) > 800:
            pdesc = pdesc[:800].rstrip() + " […]"

        prop: dict[str, Any] = {"type": ptype}
        if pdesc:
            prop["description"] = pdesc
        if ptype == "array":
            # Phase 4a: default array items to strings. Many tool
            # schemas don't specify item types; this matches the
            # most-common shape (e.g. `params=["q","email"]`).
            # Phase 4b will read explicit `<items>` children when
            # those are added to the XML schemas.
            prop["items"] = {"type": "string"}

        properties[pname] = prop
        if prequired:
            required.append(pname)

    return properties, required


def get_tools_json_schema(
    allowlist: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Generate the full `tools=[...]` array for a litellm completion
    call.

    Args:
        allowlist: optional iterable of tool names. When provided,
            only the listed tools are included — same semantics as
            `get_tools_prompt(allowlist=...)` (#173). When None,
            the full registry is converted.

    Returns:
        List of OpenAI-shape tool dicts ready to pass as
        `tools=[...]` to `litellm.acompletion`. Empty list when no
        tools are registered or none match the allowlist.
    """
    from strix.tools.registry import tools

    allowed: set[str] | None = None
    if allowlist is not None:
        allowed = {n for n in allowlist if isinstance(n, str)}

    out: list[dict[str, Any]] = []
    for tool in tools:
        if allowed is not None and tool.get("name") not in allowed:
            continue
        xml_schema = tool.get("xml_schema") or ""
        if not isinstance(xml_schema, str):
            continue
        # Some tool entries store a full <tools>...</tools> wrapper;
        # extract the inner <tool name="..."> element by name first
        # if needed.
        tool_xml = _extract_single_tool_element(xml_schema, tool.get("name"))
        if not tool_xml:
            continue
        schema = xml_to_function_schema(tool_xml)
        if schema is not None:
            out.append(schema)
    return out


def _extract_single_tool_element(xml_text: str, name: str | None) -> str | None:
    """When `xml_text` is the original schema file (which can wrap
    multiple `<tool>` blocks under `<tools>`), pull out just the one
    matching `name`. Returns the input unchanged when it's already
    a single `<tool>` element."""
    if not xml_text:
        return None
    stripped = xml_text.lstrip()
    if stripped.startswith("<tool ") or stripped.startswith("<tool>"):
        return xml_text
    if name is None:
        return None
    needle = f'<tool name="{name}"'
    start = xml_text.find(needle)
    if start == -1:
        return None
    end_tag = "</tool>"
    end = xml_text.find(end_tag, start)
    if end == -1:
        return None
    return xml_text[start:end + len(end_tag)]
