"""Unit tests for the context-aware XSS payload module
(`strix/tools/specialist/xss_contexts.py`).

These tests cover the classifier + payload cohorts in isolation
from the network probe loop. End-to-end behaviour (probe →
detect-context → attack → emit) is covered by
`tests/tools/specialist/test_scan_xss.py`.
"""

from __future__ import annotations

import pytest

from strix.tools.specialist.xss_contexts import (
    CONTEXTS,
    breakout_fired,
    detect_contexts,
    payloads_for_context,
)


CANARY = "STRIXCANARY1234"


# ---------------------------------------------------------------------------
# detect_contexts — happy paths
# ---------------------------------------------------------------------------


def test_canary_not_in_body_returns_empty() -> None:
    assert detect_contexts("<html>no canary here</html>", CANARY) == ()


def test_html_body_classification() -> None:
    body = f"<html><body>You searched for: {CANARY} today</body></html>"
    contexts = detect_contexts(body, CANARY)
    assert "html_body" in contexts


def test_html_attr_double_quoted_classification() -> None:
    body = f'<input type="text" value="{CANARY}">'
    contexts = detect_contexts(body, CANARY)
    assert "html_attr_double" in contexts


def test_html_attr_single_quoted_classification() -> None:
    body = f"<input type='text' value='{CANARY}'>"
    contexts = detect_contexts(body, CANARY)
    assert "html_attr_single" in contexts


def test_html_attr_unquoted_classification() -> None:
    body = f"<input type=text value={CANARY}>"
    contexts = detect_contexts(body, CANARY)
    assert "html_attr_unquoted" in contexts


def test_url_attr_href_classification() -> None:
    body = f'<a href="{CANARY}">click</a>'
    contexts = detect_contexts(body, CANARY)
    assert "url_attr" in contexts
    # MUST NOT also classify as html_attr_double — url_attr is the
    # more specific classification and should win.
    assert "html_attr_double" not in contexts


def test_url_attr_src_classification() -> None:
    body = f"<img src='{CANARY}' alt='x'>"
    contexts = detect_contexts(body, CANARY)
    assert "url_attr" in contexts


def test_url_attr_formaction_classification() -> None:
    body = f'<button formaction="{CANARY}">go</button>'
    contexts = detect_contexts(body, CANARY)
    assert "url_attr" in contexts


def test_js_string_double_classification() -> None:
    body = f'<script>var name = "{CANARY}";</script>'
    contexts = detect_contexts(body, CANARY)
    assert "js_string_double" in contexts


def test_js_string_single_classification() -> None:
    body = f"<script>var name = '{CANARY}';</script>"
    contexts = detect_contexts(body, CANARY)
    assert "js_string_single" in contexts


def test_js_block_classification() -> None:
    """Canary lands as a bare JS identifier — not inside a string."""
    body = f"<script>console.log({CANARY});</script>"
    contexts = detect_contexts(body, CANARY)
    assert "js_block" in contexts


def test_css_inside_style_block_classification() -> None:
    body = f"<style>.cls{{color: {CANARY};}}</style>"
    contexts = detect_contexts(body, CANARY)
    assert "css" in contexts


def test_css_inside_style_attribute_classification() -> None:
    """style="..." attribute is technically CSS context. The current
    heuristic classifies it as an attribute context because the
    style attribute isn't wrapped in <style>...</style> tags. v1
    accepts this — the breakout payloads for html_attr_* still
    work via attribute escape."""
    body = f'<div style="color: {CANARY}">x</div>'
    contexts = detect_contexts(body, CANARY)
    # Either css or html_attr_double is defensible; pin that SOMETHING
    # is detected (not empty / not falsely classified as html_body).
    assert contexts != ()
    assert "html_body" not in contexts


def test_json_response_short_circuits_to_json_reflect() -> None:
    body = f'{{"results": ["{CANARY}"]}}'
    contexts = detect_contexts(body, CANARY, content_type="application/json")
    assert contexts == ("json_reflect",)


def test_json_response_with_charset_short_circuits() -> None:
    body = f'{{"x": "{CANARY}"}}'
    contexts = detect_contexts(
        body, CANARY, content_type="application/json; charset=utf-8",
    )
    assert contexts == ("json_reflect",)


# ---------------------------------------------------------------------------
# detect_contexts — fall-open behaviour
# ---------------------------------------------------------------------------


def test_unclassifiable_body_falls_open_to_html_body() -> None:
    """Plain text response with no tags — heuristic falls open to
    `html_body` so the caller's payload cohort still fires."""
    body = f"Hello {CANARY} world"
    contexts = detect_contexts(body, CANARY)
    assert "html_body" in contexts


def test_multiple_occurrences_dedup_by_context() -> None:
    """Same canary appearing twice in the same context yields ONE
    entry, not two."""
    body = (
        f"<html><body>First: {CANARY}. Second: {CANARY}.</body></html>"
    )
    contexts = detect_contexts(body, CANARY)
    assert contexts.count("html_body") == 1


def test_multiple_distinct_contexts_all_returned() -> None:
    """Same canary in different contexts → all classifications
    appear in the result."""
    body = (
        f'<html><body>{CANARY}</body>'
        f'<input value="{CANARY}">'
        f'<script>var x = "{CANARY}";</script></html>'
    )
    contexts = detect_contexts(body, CANARY)
    assert "html_body" in contexts
    assert "html_attr_double" in contexts
    assert "js_string_double" in contexts


# ---------------------------------------------------------------------------
# Payload cohorts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ctx", CONTEXTS)
def test_every_context_has_at_least_one_payload(ctx: str) -> None:
    """Every context the classifier can return must have a non-empty
    payload cohort. If a future context is added to CONTEXTS without
    a cohort, the classifier would return it and the probe loop
    would silently no-op."""
    cohort = payloads_for_context(ctx)
    assert len(cohort) >= 1, f"context {ctx!r} has empty cohort"


@pytest.mark.parametrize("ctx", CONTEXTS)
def test_payload_templates_carry_canary_placeholder(ctx: str) -> None:
    """Every payload must reference `{canary}` so it can be
    materialised. Evidence templates must too (the canary is part
    of the unique-match check)."""
    for p in payloads_for_context(ctx):
        assert "{canary}" in p.template, (
            f"payload {p.template!r} for context {ctx} missing canary"
        )
        assert "{canary}" in p.evidence_template, (
            f"evidence {p.evidence_template!r} for context {ctx} missing canary"
        )


def test_payloads_for_unknown_context_returns_empty() -> None:
    assert payloads_for_context("nonsense_context") == ()


# ---------------------------------------------------------------------------
# breakout_fired
# ---------------------------------------------------------------------------


def test_breakout_fired_when_evidence_present() -> None:
    payload = payloads_for_context("html_body")[0]
    materialised, evidence = payload.materialise(CANARY)
    body = f"<html>echo: {materialised} more text</html>"
    assert breakout_fired(body, payload, CANARY) is True


def test_breakout_not_fired_when_evidence_escaped() -> None:
    """Server HTML-escapes the breakout characters → evidence
    marker isn't present verbatim → breakout_fired returns False."""
    payload = payloads_for_context("html_body")[0]
    materialised, _ = payload.materialise(CANARY)
    # Simulate server escaping `<` and `>`.
    escaped = materialised.replace("<", "&lt;").replace(">", "&gt;")
    body = f"<html>echo: {escaped} more text</html>"
    assert breakout_fired(body, payload, CANARY) is False


def test_breakout_attr_double_evidence() -> None:
    """Attribute double-quoted breakout: the literal `">` sequence
    must be present un-escaped for the payload to have escaped the
    attribute."""
    payload = payloads_for_context("html_attr_double")[0]
    materialised, _ = payload.materialise(CANARY)
    # Server reflects the payload verbatim into a quoted attribute.
    body = f'<input value="{materialised}">'
    assert breakout_fired(body, payload, CANARY) is True


def test_breakout_attr_double_escaped() -> None:
    payload = payloads_for_context("html_attr_double")[0]
    materialised, _ = payload.materialise(CANARY)
    escaped = materialised.replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
    body = f'<input value="{escaped}">'
    assert breakout_fired(body, payload, CANARY) is False


def test_breakout_js_string_double_evidence() -> None:
    """JS string double-quoted breakout: the literal `";` sequence
    appears un-escaped → JS injection successful."""
    payload = payloads_for_context("js_string_double")[0]
    materialised, _ = payload.materialise(CANARY)
    body = f'<script>var x = "{materialised}";</script>'
    assert breakout_fired(body, payload, CANARY) is True


def test_breakout_js_string_double_escaped() -> None:
    """When server JSON-escapes the JS string (the right defense),
    `\\"` appears instead of `"` and the breakout marker isn't
    present verbatim."""
    payload = payloads_for_context("js_string_double")[0]
    materialised, _ = payload.materialise(CANARY)
    # Realistic JSON-encoded server output.
    escaped = materialised.replace('"', '\\"')
    body = f'<script>var x = "{escaped}";</script>'
    assert breakout_fired(body, payload, CANARY) is False


def test_breakout_url_attr_javascript_scheme() -> None:
    """URL attribute breakout: `javascript:` scheme is the evidence —
    no quote escape required."""
    payload = payloads_for_context("url_attr")[0]
    materialised, _ = payload.materialise(CANARY)
    body = f'<a href="{materialised}">click</a>'
    assert breakout_fired(body, payload, CANARY) is True


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_body_returns_empty() -> None:
    assert detect_contexts("", CANARY) == ()


def test_empty_canary_returns_empty() -> None:
    assert detect_contexts("<html>x</html>", "") == ()


def test_script_block_with_string_escapes_correctly() -> None:
    """JS substring classifier must skip backslash-escaped quotes
    so a `\\"` inside the script doesn't flip parity counting."""
    body = (
        '<script>var a = "\\"escaped\\"";var b = "'
        + CANARY + '";</script>'
    )
    contexts = detect_contexts(body, CANARY)
    assert "js_string_double" in contexts
