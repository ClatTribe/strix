"""Regression guard for the Operational Runbook sections added to
vuln skill bodies (sqli, xss, ssrf).

The post-Decepticon analysis identified strix's vuln-class skill
bodies as taxonomic-but-not-operational — the agent had to invent
the actual sqlmap invocation / curl chain on every run. Adding
copy-paste operational runbooks closes that gap.

These tests pin:
  * Each upgraded skill contains an `Operational Runbook` section.
  * The section appears BEFORE `Validation` (so the agent reads
    operational guidance before the success-criteria checklist).
  * Specific operational markers are present — sqlmap invocation
    in sqli, context-payload table in xss, OAST/metadata sweep in
    ssrf. Loose-pattern matches; doesn't pin exact wording.

When future PRs edit these skill bodies, this file flags accidental
deletions of the operational sections.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.utils.resource_paths import get_strix_resource_path


SKILLS = get_strix_resource_path("skills") / "vulnerabilities"


def _read(name: str) -> str:
    return (SKILLS / f"{name}.md").read_text(encoding="utf-8")


def _section_order(text: str, *markers: str) -> bool:
    """Return True when markers appear in `text` in the given order."""
    positions: list[int] = []
    for m in markers:
        pos = text.find(m)
        if pos < 0:
            return False
        positions.append(pos)
    return positions == sorted(positions)


# ---------------------------------------------------------------------------
# Per-skill operational checks
# ---------------------------------------------------------------------------


def test_sqli_has_operational_runbook() -> None:
    text = _read("sql_injection")
    assert "## Operational Runbook" in text
    # Section ordering: Runbook lands before Validation.
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "sqlmap -u",
    "--batch",
    "--tamper=",
    "--dump",
    "--dbs",
    "auth-bypass payload library",
    "hashcat",
])
def test_sqli_has_operational_markers(marker: str) -> None:
    text = _read("sql_injection")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_xss_has_operational_runbook() -> None:
    text = _read("xss")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "canary",
    "context probing",
    "polyglot",
    "CSP bypass",
    "playwright",
    "browser_action",
])
def test_xss_has_operational_markers(marker: str) -> None:
    text = _read("xss").lower()
    assert marker.lower() in text, f"missing operational marker: {marker!r}"


def test_ssrf_has_operational_runbook() -> None:
    text = _read("ssrf")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "OAST oracle",
    "169.254.169.254",      # AWS metadata
    "metadata.google.internal",
    "Metadata: true",        # Azure
    "kubernetes.io/serviceaccount",
    "gopher://",
    "DNS rebinding",
])
def test_ssrf_has_operational_markers(marker: str) -> None:
    text = _read("ssrf")
    assert marker in text, f"missing operational marker: {marker!r}"


# ---------------------------------------------------------------------------
# Cross-cut: operational sections include shell + python snippets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill", ["sql_injection", "xss", "ssrf"])
def test_operational_runbook_has_runnable_snippets(skill: str) -> None:
    """Every operational runbook should contain at least one fenced
    code block — the value is copy-paste-runnability."""
    text = _read(skill)
    runbook_start = text.find("## Operational Runbook")
    next_section = text.find("\n## ", runbook_start + 1)
    runbook = text[runbook_start:next_section] if next_section > 0 else text[runbook_start:]
    assert "```" in runbook, f"{skill}: operational runbook has no code fences"
    # At least one shell-flavoured block (curl / sqlmap / bash) — proves
    # operational vs purely conceptual content.
    has_shell = any(
        marker in runbook
        for marker in ("curl ", "sqlmap ", "for ", "```bash", "```sh", "```python")
    )
    assert has_shell, f"{skill}: operational runbook has no shell/python snippets"
