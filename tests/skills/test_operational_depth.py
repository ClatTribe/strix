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
    """Return True when markers appear in `text` in the given order.

    Matches `\\n<marker>` so `## Validation` doesn't accidentally
    match inside `### Validation Gaps` (which `text.find` would
    happily return).
    """
    positions: list[int] = []
    for m in markers:
        # Anchor to start-of-line OR start-of-document.
        anchor_a = text.find("\n" + m)
        anchor_b = text.find(m) if text.startswith(m) else -1
        candidates = [p for p in (anchor_a, anchor_b) if p >= 0]
        if not candidates:
            return False
        positions.append(min(candidates))
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


def test_idor_has_operational_runbook() -> None:
    text = _read("idor")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "OWNER",
    "ATTACKER",
    "Bearer",
    "anon variant",
    "Step 7 — record evidence",
    "CWE-862",
    "write-side IDOR",
])
def test_idor_has_operational_markers(marker: str) -> None:
    text = _read("idor")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_jwt_has_operational_runbook() -> None:
    text = _read("authentication_jwt")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "alg: none",
    "algorithm confusion",
    "hashcat -m 16500",
    "jku",
    "kid",
    "jwt_tool.py",
    "RS256",
])
def test_jwt_has_operational_markers(marker: str) -> None:
    text = _read("authentication_jwt")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_rce_has_operational_runbook() -> None:
    text = _read("rce")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "OOB oracle",
    "interactsh",
    "timing oracle",
    "ysoserial",
    "Jinja2 SSTI",
    "/.dockerenv",
    "kubernetes.io/serviceaccount",
])
def test_rce_has_operational_markers(marker: str) -> None:
    text = _read("rce")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_csrf_has_operational_runbook() -> None:
    text = _read("csrf")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "X-CSRF-Token",
    "Content-Type downgrade",
    "Origin",
    "SameSite",
    "enctype=\"text/plain\"",
    "session",
])
def test_csrf_has_operational_markers(marker: str) -> None:
    text = _read("csrf")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_path_traversal_has_operational_runbook() -> None:
    text = _read("path_traversal_lfi_rfi")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "/etc/passwd",
    "%2F",
    "php://filter",
    "data://",
    "Zip Slip",
    "/proc/self/environ",
    "cron",
])
def test_path_traversal_has_operational_markers(marker: str) -> None:
    text = _read("path_traversal_lfi_rfi")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_file_upload_has_operational_runbook() -> None:
    text = _read("insecure_file_uploads")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "shell.jpg.php",
    "shell.phar",
    "magic byte",
    ".htaccess",
    "Zip Slip",
    "ImageTragick",
    "GIF89a",
])
def test_file_upload_has_operational_markers(marker: str) -> None:
    text = _read("insecure_file_uploads").lower()
    assert marker.lower() in text, f"missing operational marker: {marker!r}"


def test_xxe_has_operational_runbook() -> None:
    text = _read("xxe")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "DOCTYPE",
    "ENTITY",
    "169.254.169.254",
    "XInclude",
    "parameter entit",
    "SAML",
])
def test_xxe_has_operational_markers(marker: str) -> None:
    text = _read("xxe")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_mass_assignment_has_operational_runbook() -> None:
    text = _read("mass_assignment")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "is_admin",
    "role=admin",
    "GraphQL mutation",
    "tenant_id",
    "credits",
])
def test_mass_assignment_has_operational_markers(marker: str) -> None:
    text = _read("mass_assignment")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_race_conditions_has_operational_runbook() -> None:
    text = _read("race_conditions")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "Turbo Intruder",
    "asyncio",
    "single-packet",
    "concurrent",
    "TOCTOU",
])
def test_race_conditions_has_operational_markers(marker: str) -> None:
    text = _read("race_conditions")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_subdomain_takeover_has_operational_runbook() -> None:
    text = _read("subdomain_takeover")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "subfinder",
    "amass",
    "crt.sh",
    "subjack",
    "nuclei",
    "NoSuchBucket",
    "herokuapp",
])
def test_subdomain_takeover_has_operational_markers(marker: str) -> None:
    text = _read("subdomain_takeover")
    assert marker in text, f"missing operational marker: {marker!r}"


def test_business_logic_has_operational_runbook() -> None:
    text = _read("business_logic")
    assert "## Operational Runbook" in text
    assert _section_order(text, "## Operational Runbook", "## Validation")


@pytest.mark.parametrize("marker", [
    "state machine",
    "step skipping",
    "step repetition",
    "parameter tampering",
    "negative qty",
    "currency manipulation",
])
def test_business_logic_has_operational_markers(marker: str) -> None:
    text = _read("business_logic").lower()
    assert marker.lower() in text, f"missing operational marker: {marker!r}"


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
