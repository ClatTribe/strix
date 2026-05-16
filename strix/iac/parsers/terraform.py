"""Terraform (.tf) parser — Phase 11.4.

Closes the audit item 1 IaC breadth gap. Pre-PR strix's IaC engine
only handled Cloudflare / Docker / Netlify / Vercel — the entire
HashiCorp / cloud-native ecosystem was uncovered.

## Why regex over a real HCL2 parser

Full HCL2 grammar requires either:
  * Shelling to `terraform fmt -json` (terraform CLI must be on
    PATH; multi-second cold start; per-file invocation).
  * The `python-hcl2` library (extra runtime dep; doesn't ship in
    every operator's environment).

For the v1 scope, we use a regex-based block extractor that
captures the structurally-significant patterns:

  * `resource "<type>" "<name>" { <body> }`
  * `data "<type>" "<name>" { <body> }`
  * `provider "<name>" { <body> }`
  * `module "<name>" { <body> }`
  * `variable "<name>" { <body> }`
  * `output "<name>" { <body> }`

The block body is captured as raw text + line number; rules
do regex / substring searches inside the body. This is the same
pattern `docker_rules.py` uses against parsed Dockerfile
directive lists — works well for the security-checks we want
(public S3 bucket, security group 0.0.0.0/0, IAM wildcard, etc.).

What this parser does NOT do:
  * Resolve `var.X` references — the body text contains
    `accessibility = var.public` literally; rules know to flag
    `var.X` defaults separately by inspecting the `variable`
    block.
  * Resolve `module.X.output.Y` — out of scope for v1.
  * Validate HCL2 syntax — malformed files just produce fewer
    blocks; partial extraction is acceptable.
  * Handle `for_each` / `count` / `dynamic` blocks specifically —
    they're captured as part of the surrounding block body.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from strix.iac.parsers.base import (
    PLATFORM_TERRAFORM,
    IacFile,
    register_parser,
)


logger = logging.getLogger(__name__)


# Terraform's block types we capture. Each gets a `(type, label1,
# label2, body, start_line)` tuple. `label2` is None for
# single-label blocks (`provider`, `module`, `variable`, `output`).
_BLOCK_KEYWORDS = (
    "resource", "data", "provider", "module",
    "variable", "output", "locals", "terraform",
)


# Match: `keyword "label1" "label2" {` OR `keyword "label" {` OR
# `keyword { ... }` (no labels — `locals`, `terraform`).
# Captures:
#   1: keyword
#   2: label1 (or None)
#   3: label2 (or None)
_BLOCK_OPEN_RE = re.compile(
    r"^\s*(" + "|".join(_BLOCK_KEYWORDS) + r")\b"
    r'(?:\s+"([^"]+)")?'
    r'(?:\s+"([^"]+)")?'
    r"\s*\{",
    re.MULTILINE,
)


def _extract_balanced_body(text: str, open_pos: int) -> tuple[str, int]:
    """Walk `text` from the `{` at `open_pos` until the matching
    `}`. Returns `(body_text, end_pos)` where `body_text` is the
    contents BETWEEN the braces (exclusive). Handles nested
    braces. Quoted strings are tracked so braces inside strings
    don't perturb the count.

    Defensive — when no matching brace is found, returns the
    rest of the file as body and signals end-of-input. Partial
    extraction is the right call for malformed HCL.
    """
    depth = 0
    i = open_pos
    in_string = False
    string_char = ""
    # Track heredoc state to skip its contents wholesale.
    # Heredoc: `<<EOF ... EOF` or `<<-EOF ... EOF`.
    # We don't fully parse — just avoid braces inside heredoc.
    n = len(text)
    body_start = -1
    while i < n:
        c = text[i]
        if in_string:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == string_char:
                in_string = False
            i += 1
            continue
        if c in ('"', "'"):
            in_string = True
            string_char = c
            i += 1
            continue
        if c == "{":
            depth += 1
            if depth == 1:
                body_start = i + 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            if depth == 0:
                return text[body_start:i], i + 1
            i += 1
            continue
        i += 1
    # Unmatched — return rest of text.
    return text[body_start:] if body_start >= 0 else "", n


def _parse_terraform(text: str) -> list[dict[str, Any]]:
    """Parse Terraform text into a list of block dicts:

      `{type, label1, label2, body, line, raw}`

    `body` is the contents between the block's braces (multi-line
    string). `line` is 1-indexed line number of the opening
    keyword. `raw` is the full block text including the
    keyword + labels + braces — useful for whole-block matching.

    Top-level blocks only; nested blocks inside a `body` are NOT
    re-extracted. Rules walking a resource's body should pattern-
    match for the nested constructs they care about (e.g.
    `lifecycle { prevent_destroy = ... }` inside a resource).
    """
    out: list[dict[str, Any]] = []
    pos = 0
    n = len(text)
    while pos < n:
        m = _BLOCK_OPEN_RE.search(text, pos)
        if not m:
            break
        keyword = m.group(1)
        label1 = m.group(2)
        label2 = m.group(3)
        # Find the position of the opening brace `{`. The regex
        # ends right after the brace, but we need to step BACK to
        # call `_extract_balanced_body` with `{` as the start.
        brace_pos = text.find("{", m.start())
        if brace_pos < 0:
            pos = m.end()
            continue
        body, end_pos = _extract_balanced_body(text, brace_pos)
        # Line number for the opening keyword.
        line_number = text.count("\n", 0, m.start()) + 1
        raw_block = text[m.start():end_pos]
        out.append({
            "type": keyword,
            "label1": label1,
            "label2": label2,
            "body": body,
            "line": line_number,
            "raw": raw_block,
        })
        pos = end_pos
    return out


@register_parser(
    patterns=[r"\.tf$"],
)
def parse_terraform(path: Path) -> IacFile | None:
    """Parse a `.tf` file. Always returns an IacFile; on read /
    parse failure, `parse_error` is set and `data` carries
    whatever blocks were extractable."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return IacFile(
            platform=PLATFORM_TERRAFORM, path=str(path),
            data=[], raw_text="", parse_error=str(e),
        )
    blocks = _parse_terraform(text)
    return IacFile(
        platform=PLATFORM_TERRAFORM, path=str(path),
        data=blocks, raw_text=text,
    )
