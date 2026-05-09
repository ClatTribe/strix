"""Tests for §8.5 Phase 4a — XML→JSON Schema converter for native
tool calling.

Pins the conversion semantics so when Phase 4b/4c flips the LLM
client to `tools=[...]` mode, the schemas the model receives are
correct AND backwards-compatible with the existing tool registry.
"""

from __future__ import annotations

import pytest

from strix.tools.json_schema import (
    get_tools_json_schema,
    xml_to_function_schema,
)
from strix.tools.registry import tools as _tool_registry


@pytest.fixture(autouse=True)
def _seed_registry():
    snapshot = list(_tool_registry)
    yield
    _tool_registry.clear()
    _tool_registry.extend(snapshot)


# ---------------------------------------------------------------------------
# xml_to_function_schema — single-tool conversion
# ---------------------------------------------------------------------------


def test_basic_tool_with_required_string() -> None:
    xml = """
    <tool name="echo">
      <description>Echo a message back.</description>
      <parameters>
        <parameter name="message" type="string" required="true">
          <description>The message to echo.</description>
        </parameter>
      </parameters>
    </tool>
    """
    schema = xml_to_function_schema(xml)
    assert schema is not None
    assert schema["type"] == "function"
    fn = schema["function"]
    assert fn["name"] == "echo"
    assert "Echo a message" in fn["description"]
    assert fn["parameters"]["type"] == "object"
    assert fn["parameters"]["properties"]["message"]["type"] == "string"
    assert "echo" in fn["parameters"]["properties"]["message"]["description"].lower()
    assert fn["parameters"]["required"] == ["message"]


def test_optional_param_not_in_required() -> None:
    xml = """
    <tool name="t">
      <description>d</description>
      <parameters>
        <parameter name="a" type="string" required="true"><description>a</description></parameter>
        <parameter name="b" type="string" required="false"><description>b</description></parameter>
      </parameters>
    </tool>
    """
    schema = xml_to_function_schema(xml)
    assert schema["function"]["parameters"]["required"] == ["a"]
    assert "b" in schema["function"]["parameters"]["properties"]


def test_type_mappings() -> None:
    xml = """
    <tool name="t">
      <description>d</description>
      <parameters>
        <parameter name="s" type="string" required="false"><description>s</description></parameter>
        <parameter name="n" type="number" required="false"><description>n</description></parameter>
        <parameter name="i" type="integer" required="false"><description>i</description></parameter>
        <parameter name="b" type="boolean" required="false"><description>b</description></parameter>
        <parameter name="o" type="object" required="false"><description>o</description></parameter>
        <parameter name="a" type="array" required="false"><description>a</description></parameter>
      </parameters>
    </tool>
    """
    schema = xml_to_function_schema(xml)
    props = schema["function"]["parameters"]["properties"]
    assert props["s"]["type"] == "string"
    assert props["n"]["type"] == "number"
    assert props["i"]["type"] == "integer"
    assert props["b"]["type"] == "boolean"
    assert props["o"]["type"] == "object"
    assert props["a"]["type"] == "array"
    assert props["a"]["items"] == {"type": "string"}


def test_type_aliases_normalised() -> None:
    """Strix XML schemas use mixed conventions — `int` / `bool` /
    `dict` / `list` / `str`. Map them all to canonical JSON Schema."""
    xml = """
    <tool name="t">
      <description>d</description>
      <parameters>
        <parameter name="i" type="int" required="false"><description>i</description></parameter>
        <parameter name="b" type="bool" required="false"><description>b</description></parameter>
        <parameter name="d" type="dict" required="false"><description>d</description></parameter>
        <parameter name="l" type="list" required="false"><description>l</description></parameter>
        <parameter name="s" type="str" required="false"><description>s</description></parameter>
      </parameters>
    </tool>
    """
    schema = xml_to_function_schema(xml)
    props = schema["function"]["parameters"]["properties"]
    assert props["i"]["type"] == "integer"
    assert props["b"]["type"] == "boolean"
    assert props["d"]["type"] == "object"
    assert props["l"]["type"] == "array"
    assert props["s"]["type"] == "string"


def test_unknown_type_falls_back_to_string() -> None:
    """Best-effort: an unrecognised type doesn't crash conversion;
    falls back to string so the tool is still callable."""
    xml = """
    <tool name="t">
      <description>d</description>
      <parameters>
        <parameter name="x" type="weird-custom-type" required="false">
          <description>x</description>
        </parameter>
      </parameters>
    </tool>
    """
    schema = xml_to_function_schema(xml)
    assert schema["function"]["parameters"]["properties"]["x"]["type"] == "string"


def test_empty_or_malformed_xml_returns_none() -> None:
    assert xml_to_function_schema("") is None
    assert xml_to_function_schema("<not-a-tool>") is None
    assert xml_to_function_schema("<wrong>...</wrong>") is None


def test_tool_without_name_returns_none() -> None:
    """`<tool>` without `name=` attribute is unusable — return None."""
    xml = "<tool><description>d</description></tool>"
    assert xml_to_function_schema(xml) is None


def test_tool_without_parameters_yields_empty_properties() -> None:
    """Some tools take no params — should still produce a valid schema."""
    xml = """
    <tool name="ping">
      <description>No-args ping.</description>
    </tool>
    """
    schema = xml_to_function_schema(xml)
    assert schema is not None
    assert schema["function"]["name"] == "ping"
    assert schema["function"]["parameters"]["properties"] == {}
    assert schema["function"]["parameters"]["required"] == []


def test_long_description_truncated() -> None:
    """Function descriptions over ~2K chars get rejected by some
    providers. Cap at 1500 chars + `[…]` marker."""
    long_desc = "x" * 5000
    xml = f"""
    <tool name="t">
      <description>{long_desc}</description>
      <parameters></parameters>
    </tool>
    """
    schema = xml_to_function_schema(xml)
    assert len(schema["function"]["description"]) <= 1510
    assert schema["function"]["description"].endswith("[…]")


def test_long_param_description_truncated() -> None:
    long_desc = "y" * 2000
    xml = f"""
    <tool name="t">
      <description>d</description>
      <parameters>
        <parameter name="x" type="string" required="false">
          <description>{long_desc}</description>
        </parameter>
      </parameters>
    </tool>
    """
    schema = xml_to_function_schema(xml)
    desc = schema["function"]["parameters"]["properties"]["x"]["description"]
    assert len(desc) <= 810


# ---------------------------------------------------------------------------
# get_tools_json_schema — integration with registry
# ---------------------------------------------------------------------------


def _make_registry_entry(name: str, xml_text: str) -> dict:
    return {"name": name, "module": "test", "xml_schema": xml_text}


def test_get_tools_json_schema_full_registry() -> None:
    _tool_registry.clear()
    _tool_registry.extend([
        _make_registry_entry("a", '<tool name="a"><description>aa</description></tool>'),
        _make_registry_entry("b", '<tool name="b"><description>bb</description></tool>'),
    ])
    out = get_tools_json_schema()
    names = {s["function"]["name"] for s in out}
    assert names == {"a", "b"}


def test_get_tools_json_schema_with_allowlist() -> None:
    _tool_registry.clear()
    _tool_registry.extend([
        _make_registry_entry("a", '<tool name="a"><description>aa</description></tool>'),
        _make_registry_entry("b", '<tool name="b"><description>bb</description></tool>'),
        _make_registry_entry("c", '<tool name="c"><description>cc</description></tool>'),
    ])
    out = get_tools_json_schema(allowlist=["a", "c"])
    names = {s["function"]["name"] for s in out}
    assert names == {"a", "c"}


def test_get_tools_json_schema_extracts_from_wrapped_tools() -> None:
    """Some XML schemas live inside a <tools>...</tools> wrapper.
    The converter should still find the named tool block."""
    wrapped = """<tools>
      <tool name="alpha"><description>aa</description></tool>
      <tool name="beta"><description>bb</description></tool>
    </tools>"""
    _tool_registry.clear()
    _tool_registry.append(_make_registry_entry("alpha", wrapped))
    out = get_tools_json_schema()
    names = {s["function"]["name"] for s in out}
    assert "alpha" in names
    # `beta` is in the same XML but its registry entry isn't here,
    # so it shouldn't be returned.
    assert "beta" not in names


def test_get_tools_json_schema_skips_unparseable() -> None:
    _tool_registry.clear()
    _tool_registry.extend([
        _make_registry_entry("good", '<tool name="good"><description>g</description></tool>'),
        _make_registry_entry("bad", "garbage <not xml>"),
    ])
    out = get_tools_json_schema()
    names = {s["function"]["name"] for s in out}
    assert names == {"good"}


# ---------------------------------------------------------------------------
# End-to-end smoke: real tool from the registry converts cleanly
# ---------------------------------------------------------------------------


def test_real_xml_backed_tool_converts_cleanly() -> None:
    """Converts a real tool that ships with an XML schema file. If
    this snapshots the wrong fields, the model-side native call
    will fail. Pinning at least one real conversion catches drift.

    `create_agent` is a stable choice — it ships with an XML schema
    file in the host-side registry and has been in the codebase
    since Phase 1 with its arg shape unchanged."""
    out = get_tools_json_schema(allowlist=["create_agent"])
    assert len(out) == 1
    schema = out[0]
    assert schema["type"] == "function"
    assert schema["function"]["name"] == "create_agent"
    assert schema["function"]["description"]
    props = schema["function"]["parameters"]["properties"]
    # create_agent has at least task / name / skills params.
    assert len(props) >= 3
    # `task` is one of the canonical params and is required.
    assert "task" in props


def test_specialist_without_xml_file_yields_empty_params() -> None:
    """The specialist tools (scan_xss, scan_sqli, scan_misconfig)
    don't currently ship XML schema files — `register_specialist_tool`
    creates a stub. Phase 4a converts them to schemas with empty
    `properties: {}`; Phase 4b will synthesize from the function
    signature. This test pins the current behaviour so the regression
    is detectable when 4b lands."""
    out = get_tools_json_schema(allowlist=["scan_misconfig"])
    assert len(out) == 1
    schema = out[0]
    assert schema["function"]["name"] == "scan_misconfig"
    # Empty properties is the current state — Phase 4b will fix.
    assert schema["function"]["parameters"]["properties"] == {}
