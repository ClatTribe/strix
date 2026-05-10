"""Normalise tracer / JSON / markdown finding inputs into the
`Finding` shape that linkers + correlator operate on.

Three input shapes are common:

  1. **`vulnerabilities.json` rows** — typed dicts with the
     fields `add_vulnerability_report` accepts. The most
     common production input.

  2. **`FindingDraft` instances** — Pydantic models from the
     specialist-tool pipeline. The lead may want to correlate
     findings BEFORE they're emitted to disk.

  3. **Hand-built dicts** — for tests + ad-hoc usage.

The normaliser accepts any of those and produces a `Finding`.
Field extraction is best-effort — missing fields default to
empty strings rather than raising, so a partial finding
doesn't poison the whole correlation pass.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from strix.finding_chains.chain import Finding


# Best-effort package-name extraction from SCA finding titles.
# SCA findings emit titles like:
#   "Vulnerable dependency `npm:lodash@4.17.20` (3 CVEs)"
#   "Vulnerable dependency `pypi:django@4.2.0` (1 CVE) [KEV — actively exploited]"
# Extract `<name>` from the `<eco>:<name>@<version>` token.
_SCA_PACKAGE_RE = re.compile(
    r"`([A-Za-z][A-Za-z0-9-]*?):([@A-Za-z0-9._/-]+?)@([A-Za-z0-9._+!\-]+)`"
)


# CVE id pattern — matches CVE-YYYY-NNNNN or GHSA-xxxx-xxxx-xxxx.
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b",
                     re.IGNORECASE)


def _str(d: dict, *keys: str) -> str:
    """Pick first non-empty string field from `d` matching any key in `keys`."""
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _normalise_cwe(raw: Any) -> str | None:
    """Accept `CWE-79` / `cwe-79` / `79` / list of these → return `CWE-79`."""
    if raw is None:
        return None
    if isinstance(raw, list):
        if not raw:
            return None
        raw = raw[0]
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    if s.upper().startswith("CWE-"):
        return s.upper().split(":", 1)[0].strip()
    if s.isdigit():
        return f"CWE-{s}"
    return None


def _extract_package(title: str, description: str = "") -> str:
    """Pull package name from a SCA-style title."""
    for source in (title, description):
        m = _SCA_PACKAGE_RE.search(source or "")
        if m:
            ecosystem, name, _ = m.groups()
            return f"{ecosystem}:{name}".lower()
    return ""


def _extract_cve(title: str, description: str = "",
                 explicit_cve: str = "") -> str | None:
    """Pull CVE / GHSA id from explicit field or text."""
    if explicit_cve and isinstance(explicit_cve, str):
        return explicit_cve.strip().upper()
    for source in (title, description):
        m = _CVE_RE.search(source or "")
        if m:
            return m.group(1).upper()
    return None


def normalise_finding(raw: Any) -> Finding | None:
    """Convert one raw input (dict / FindingDraft / etc.) to a
    `Finding`. Returns None when the input is unparseable.

    Required fields: `title` and (`category` OR `cwe`). Without
    one of those the linker layer has nothing to match on.
    """
    # Pydantic FindingDraft → dict via `.model_dump()`.
    if hasattr(raw, "model_dump") and callable(raw.model_dump):
        d = raw.model_dump()
    elif isinstance(raw, dict):
        d = raw
    else:
        return None

    title = _str(d, "title")
    category = _str(d, "category", "type")
    cwe = _normalise_cwe(d.get("cwe"))
    if not title or (not category and not cwe):
        return None

    severity = (_str(d, "severity") or "info").lower()
    target = _str(d, "target", "url", "host")
    endpoint = _str(d, "endpoint", "path", "file")
    description = _str(d, "description", "message")
    cve = _extract_cve(title, description, _str(d, "cve"))
    package = _extract_package(title, description)
    if not package:
        # Fallback: explicit `package` field if present.
        package = _str(d, "package").lower()

    finding_id = _str(d, "id", "finding_id", "report_id", "uuid")
    if not finding_id:
        # Synthesise a stable id from title + endpoint when none.
        import hashlib
        h = hashlib.sha1(
            f"{title}|{endpoint}|{cwe}".encode("utf-8")
        ).hexdigest()[:12]
        finding_id = f"f-{h}"

    return Finding(
        id=finding_id,
        title=title,
        category=category,
        severity=severity,
        cwe=cwe,
        target=target,
        endpoint=endpoint,
        description=description,
        cve=cve,
        package=package,
        metadata=dict(d.get("metadata") or {}),
    )


def normalise_findings(raw_inputs: Iterable[Any]) -> list[Finding]:
    """Bulk normaliser. Skips inputs that don't parse cleanly
    rather than raising — one bad row shouldn't poison the
    correlation pass."""
    out: list[Finding] = []
    for raw in raw_inputs:
        f = normalise_finding(raw)
        if f is not None:
            out.append(f)
    return out
