"""Org-level fingerprint: WHOIS, ASN, GitHub org presence, typosquat candidates.

Roadmap §7.3. The "what else does this org expose to the internet" check —
a real domain-target pen-test starts here, but strix today doesn't run any
of these deterministically.

Returns a structured dict the agent can reason about. WHOIS/ASN/GitHub-org
data are informational and surface only in the return value, not as
findings. Typosquats that *resolve* are emitted as low-severity findings
(brand-impersonation risk). Each category emits a check.started /
check.completed pair.

All probes run inside the sandbox. Bounded:
- WHOIS: one `whois` subprocess (~5s timeout)
- ASN: one DNS query against Team Cymru's ASN-mapping zone
- GitHub: one HTTP HEAD per candidate org name (max 3)
- Typosquats: ~25 candidate names, each one DNS resolution
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from typing import Any

from strix.tools.registry import register_tool

from ._common import (
    complete_check,
    dig,
    emit_finding,
    http_head,
    looks_like_domain,
    start_check,
)


logger = logging.getLogger(__name__)
_TOOL_NAME = "org_fingerprint"
_WHOIS_TIMEOUT = 8


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------


_WHOIS_FIELDS: dict[str, list[str]] = {
    # canonical_name → list of regex patterns (case-insensitive, line-anchored)
    "registrar": [r"^\s*Registrar:\s*(.+)$"],
    "creation_date": [
        r"^\s*Creation Date:\s*(.+)$",
        r"^\s*Created On:\s*(.+)$",
        r"^\s*Created:\s*(.+)$",
    ],
    "expiry_date": [
        r"^\s*Registry Expiry Date:\s*(.+)$",
        r"^\s*Registrar Registration Expiration Date:\s*(.+)$",
        r"^\s*Expiry Date:\s*(.+)$",
        r"^\s*Expiration Date:\s*(.+)$",
    ],
    "registrant_organization": [
        r"^\s*Registrant Organization:\s*(.+)$",
        r"^\s*Registrant:\s*(.+)$",
    ],
    "registrant_country": [r"^\s*Registrant Country:\s*(.+)$"],
    "name_servers": [r"^\s*Name Server:\s*(.+)$"],
    "dnssec": [r"^\s*DNSSEC:\s*(.+)$"],
}


def _run_whois(domain: str) -> str:
    try:
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=_WHOIS_TIMEOUT,
            check=False,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning("whois failed for %s: %s", domain, e)
        return ""


def _parse_whois(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    name_servers: list[str] = []

    for canonical, patterns in _WHOIS_FIELDS.items():
        for pat in patterns:
            for m in re.finditer(pat, text, flags=re.IGNORECASE | re.MULTILINE):
                value = m.group(1).strip()
                if not value:
                    continue
                if canonical == "name_servers":
                    name_servers.append(value.lower().rstrip("."))
                elif canonical not in out:
                    out[canonical] = value

    if name_servers:
        # Dedup while preserving order.
        seen: set[str] = set()
        deduped: list[str] = []
        for ns in name_servers:
            if ns not in seen:
                seen.add(ns)
                deduped.append(ns)
        out["name_servers"] = deduped

    # Privacy detection — registrant org commonly contains these markers.
    if reg_org := out.get("registrant_organization", ""):
        privacy_markers = (
            "privacy",
            "redacted",
            "domains by proxy",
            "whoisguard",
            "perfect privacy",
        )
        if any(m in reg_org.lower() for m in privacy_markers):
            out["privacy_protected"] = True

    return out


# ---------------------------------------------------------------------------
# ASN
# ---------------------------------------------------------------------------


def _resolve_first_a(domain: str) -> str | None:
    out = dig(domain, "A")
    if not out:
        return None
    for line in out.splitlines():
        line = line.strip()
        # Match an IPv4 octet quad.
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", line):
            return line
    return None


def _asn_lookup(ip: str) -> dict[str, Any]:
    """Use Team Cymru's IP-to-ASN mapping zone over DNS. No API key."""
    rev = ".".join(reversed(ip.split(".")))
    txt = dig(f"{rev}.origin.asn.cymru.com", "TXT")
    if not txt:
        return {"ip": ip, "lookup_status": "no_response"}

    # Cymru responses are pipe-separated, e.g.
    # "13335 | 1.1.1.0/24 | US | arin | 2010-07-14"
    raw = txt.splitlines()[0].strip().strip('"')
    parts = [p.strip() for p in raw.split("|")]
    if len(parts) >= 5:
        asn_num = parts[0].split()[0]
        return {
            "ip": ip,
            "asn": f"AS{asn_num}" if asn_num.isdigit() else asn_num,
            "prefix": parts[1],
            "country": parts[2],
            "registry": parts[3],
            "allocated": parts[4],
            "lookup_status": "ok",
        }

    # Fall back to an AS-name lookup if available.
    return {"ip": ip, "asn_raw": raw, "lookup_status": "partial"}


# ---------------------------------------------------------------------------
# GitHub org
# ---------------------------------------------------------------------------


def _candidate_org_names(domain: str) -> list[str]:
    """Generate plausible GitHub org-name candidates from a domain."""
    label = domain.lower().split(".")[0]
    candidates: list[str] = [label]
    if "-" in label:
        candidates.append(label.replace("-", ""))
    # Also try without common boilerplate suffixes.
    for suffix in ("-inc", "-co", "-ltd", "-org"):
        if label.endswith(suffix):
            candidates.append(label[: -len(suffix)])
    # Dedup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c not in seen and len(c) >= 2:
            seen.add(c)
            out.append(c)
    return out[:3]  # bounded to keep network footprint minimal


def _check_github_org(name: str) -> dict[str, Any]:
    """One HTTP HEAD per candidate. 200 → exists, 404 → doesn't."""
    url = f"https://github.com/{name}"
    status, _ = http_head(url, follow_redirects=True)
    return {"name": name, "url": url, "exists": status == 200, "status": status}


# ---------------------------------------------------------------------------
# Typosquat candidate generation
# ---------------------------------------------------------------------------


_HOMOGLYPHS: dict[str, list[str]] = {
    "o": ["0"],
    "0": ["o"],
    "i": ["1", "l"],
    "l": ["1", "i"],
    "1": ["i", "l"],
    "rn": ["m"],
    "m": ["rn"],
    "vv": ["w"],
    "w": ["vv"],
    "cl": ["d"],
    "nn": ["m"],
}

_NEIGHBOUR_KEYS: dict[str, str] = {
    "q": "wa",
    "w": "qe",
    "e": "wr",
    "r": "et",
    "t": "ry",
    "y": "tu",
    "u": "yi",
    "i": "uo",
    "o": "ip",
    "p": "o",
    "a": "qs",
    "s": "ad",
    "d": "sf",
    "f": "dg",
    "g": "fh",
    "h": "gj",
    "j": "hk",
    "k": "jl",
    "l": "k",
    "z": "x",
    "x": "zc",
    "c": "xv",
    "v": "cb",
    "b": "vn",
    "n": "bm",
    "m": "n",
}

_ALT_TLDS: tuple[str, ...] = ("net", "org", "co", "io", "info", "biz", "online")


def _typosquat_candidates(domain: str, max_candidates: int = 25) -> list[str]:
    """Generate typosquat candidates via standard transformations.
    Conservative — caps total at `max_candidates` to keep DNS query volume bounded."""
    label, _, tld = domain.partition(".")
    if not label or not tld:
        return []
    out: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        c = candidate.lower()
        if c == domain.lower():
            return
        if c in seen:
            return
        seen.add(c)
        out.append(c)

    # 1. Homoglyph substitutions (highest-quality typosquats).
    for src, dsts in _HOMOGLYPHS.items():
        if src in label:
            for dst in dsts:
                add(label.replace(src, dst, 1) + "." + tld)
                if len(out) >= max_candidates:
                    return out

    # 2. Alternate TLDs on the same label — high-value, attackers register
    #    these heavily for established brands. Run before the noisier
    #    transposition / neighbour-key sources so they aren't crowded out
    #    under tighter caps.
    for alt in _ALT_TLDS:
        if alt != tld:
            add(label + "." + alt)
            if len(out) >= max_candidates:
                return out

    # 3. Adjacent transpositions.
    for i in range(len(label) - 1):
        swapped = label[:i] + label[i + 1] + label[i] + label[i + 2 :]
        if swapped != label:
            add(swapped + "." + tld)
            if len(out) >= max_candidates:
                return out

    # 4. Single-character deletion.
    for i in range(len(label)):
        deleted = label[:i] + label[i + 1 :]
        if len(deleted) >= 2:
            add(deleted + "." + tld)
            if len(out) >= max_candidates:
                return out

    # 5. Neighbour-key substitution (typing errors) — lowest priority.
    for i, ch in enumerate(label):
        for neighbour in _NEIGHBOUR_KEYS.get(ch, ""):
            sub = label[:i] + neighbour + label[i + 1 :]
            add(sub + "." + tld)
            if len(out) >= max_candidates:
                return out

    return out


@dataclass
class _TyposquatResult:
    candidate: str
    resolves: bool
    has_web: bool
    notes: str


def _check_typosquat(candidate: str) -> _TyposquatResult:
    a_record = dig(candidate, "A")
    if not a_record:
        return _TyposquatResult(candidate=candidate, resolves=False, has_web=False, notes="no A record")
    # If it resolves, do a single HEAD to detect a live website.
    status, _ = http_head(f"https://{candidate}/", follow_redirects=False)
    has_web = status > 0 and status < 600
    return _TyposquatResult(
        candidate=candidate,
        resolves=True,
        has_web=has_web,
        notes=f"resolves; HTTPS status={status}" if has_web else "resolves; no live HTTPS",
    )


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1591"],  # Gather Victim Org Information
)
def org_fingerprint(domain: str, skip_typosquats: bool = False) -> dict[str, Any]:
    """Org-level external-recon fingerprint.

    Args:
        domain: apex domain (e.g. "example.com").
        skip_typosquats: when True, skip the typosquat candidate generation
                         + DNS-resolution sweep. Useful for fast pre-flight runs.

    Behaviour:
        - WHOIS → registrar / creation / expiry / nameservers / privacy detection
        - ASN ownership via Team Cymru DNS-mapped origin lookup
        - GitHub org presence (HEAD probes against likely org names)
        - Typosquat candidates: ~25 names via homoglyph / transposition / deletion /
          neighbour-key substitution / alt-TLD; each one DNS-resolved; live ones
          HEAD-probed for a website. Resolved typosquats emit low-severity findings.

    Returns the structured dict; emits structured findings as a side effect for
    typosquats that resolve.
    """
    if not looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    # ---- WHOIS ----
    cev_id = start_check(category="org_fingerprint", surface=domain, tool=_TOOL_NAME)
    whois_text = _run_whois(domain)
    whois = _parse_whois(whois_text) if whois_text else {}
    complete_check(
        cev_id,
        result="not_vulnerable" if whois else "inconclusive",
        evidence=f"whois fields: {sorted(whois.keys())}" if whois else "whois unavailable",
    )

    # ---- ASN ----
    cev_id = start_check(category="asn_ownership", surface=domain, tool=_TOOL_NAME)
    ip = _resolve_first_a(domain)
    asn = _asn_lookup(ip) if ip else {"lookup_status": "no_a_record"}
    complete_check(
        cev_id,
        result="not_vulnerable" if asn.get("asn") else "inconclusive",
        evidence=str(asn),
    )

    # ---- GitHub org ----
    cev_id = start_check(category="github_org_presence", surface=domain, tool=_TOOL_NAME)
    github_candidates = [_check_github_org(n) for n in _candidate_org_names(domain)]
    github_existing = [c for c in github_candidates if c.get("exists")]
    complete_check(
        cev_id,
        result="not_vulnerable" if github_existing else "inconclusive",
        evidence=f"{len(github_existing)} matching GitHub org(s)",
    )

    # ---- Typosquats ----
    typosquat_results: list[dict[str, Any]] = []
    typosquats_resolved: list[str] = []
    if not skip_typosquats:
        cev_id = start_check(category="typosquat", surface=domain, tool=_TOOL_NAME)
        for candidate in _typosquat_candidates(domain):
            r = _check_typosquat(candidate)
            entry = {
                "candidate": r.candidate,
                "resolves": r.resolves,
                "has_web": r.has_web,
                "notes": r.notes,
            }
            typosquat_results.append(entry)
            if r.resolves:
                typosquats_resolved.append(r.candidate)
                emit_finding(
                    title=f"Active typosquat candidate: {r.candidate}",
                    severity="low" if r.has_web else "info",
                    category="info_disclosure",  # closest from the §1 enum
                    cwe=None,
                    target=domain,
                    description=(
                        f"`{r.candidate}` is a one-character variant of `{domain}` and "
                        f"currently resolves via DNS. {r.notes}. "
                        "If this domain is not yours, an attacker could host a clone "
                        "of your site to phish your customers."
                    ),
                    impact=(
                        "Customers receiving phishing email or mistyping the brand name "
                        "may land on attacker-controlled infrastructure that visually "
                        "mimics yours, harvesting credentials or distributing malware."
                    ),
                    remediation=(
                        f"Either register `{r.candidate}` defensively, or verify it's "
                        "owned by you. If a third party owns it, monitor it for "
                        "phishing content and pursue a UDRP / brand-protection takedown "
                        "if it's actively impersonating your brand."
                    ),
                    verification_status="pattern_match",
                )
        complete_check(
            cev_id,
            result="vulnerable" if typosquats_resolved else "not_vulnerable",
            evidence=f"{len(typosquats_resolved)} resolved typosquat(s) of {len(typosquat_results)} probed",
        )

    return {
        "success": True,
        "domain": domain,
        "whois": whois,
        "asn": asn,
        "github_candidates": github_candidates,
        "typosquats_probed": len(typosquat_results),
        "typosquats_resolved": typosquats_resolved,
        "typosquat_details": typosquat_results,
    }
