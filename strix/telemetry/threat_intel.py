"""Threat-intelligence enrichment for findings.

Maps each finding's CWE to OWASP Top 10 (web), OWASP API Top 10, and a
short list of MITRE ATT&CK technique IDs. When a finding has a CVE,
checks the CISA Known Exploited Vulnerabilities (KEV) catalog and
attaches the kev_added_at date.

This module is deliberately fail-open: any lookup failure (no network,
malformed cache, unknown CWE) returns None rather than raising. The
goal is to enrich findings when possible, never to break a scan over
threat-intel concerns.

Network access for the KEV catalog is opt-in:
- STRIX_KEV_DISABLED=1 disables remote fetch entirely (cache-only / no
  enrichment). Useful for offline / air-gapped use.
- STRIX_KEV_URL overrides the catalog URL.
- STRIX_KEV_CACHE_PATH overrides the on-disk cache location (default
  ~/.strix/kev_cache.json).
- The catalog is fetched at most once per 24h per host. Refresh forced
  via `KevCatalog.refresh(force=True)`.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


_KEV_URL_DEFAULT = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_CACHE_TTL_SECONDS = 24 * 60 * 60


# ---------------------------------------------------------------------------
# Static mappings (CWE → framework). Sourced from the official OWASP and
# MITRE references; conservative — only well-known mappings, no guesses.
# ---------------------------------------------------------------------------

# OWASP Top 10 (2021). One CWE may map to multiple categories — we pick the
# most-cited/canonical one. Coverage focused on the CWEs strix actually emits.
_CWE_TO_OWASP_TOP_10: dict[str, str] = {
    "CWE-22": "A01:2021",
    "CWE-200": "A01:2021",
    "CWE-269": "A01:2021",
    "CWE-285": "A01:2021",
    "CWE-352": "A01:2021",
    "CWE-548": "A01:2021",
    "CWE-601": "A01:2021",
    "CWE-639": "A01:2021",
    "CWE-862": "A01:2021",
    "CWE-863": "A01:2021",
    "CWE-261": "A02:2021",
    "CWE-310": "A02:2021",
    "CWE-319": "A02:2021",
    "CWE-326": "A02:2021",
    "CWE-327": "A02:2021",
    "CWE-329": "A02:2021",
    "CWE-330": "A02:2021",
    "CWE-347": "A02:2021",
    "CWE-916": "A02:2021",
    "CWE-77": "A03:2021",
    "CWE-78": "A03:2021",
    "CWE-79": "A03:2021",
    "CWE-89": "A03:2021",
    "CWE-90": "A03:2021",
    "CWE-91": "A03:2021",
    "CWE-94": "A03:2021",
    "CWE-95": "A03:2021",
    "CWE-643": "A03:2021",
    "CWE-1336": "A03:2021",  # SSTI
    "CWE-209": "A04:2021",
    "CWE-256": "A04:2021",
    "CWE-501": "A04:2021",
    "CWE-602": "A04:2021",
    "CWE-799": "A04:2021",
    "CWE-2": "A05:2021",
    "CWE-15": "A05:2021",
    "CWE-16": "A05:2021",
    "CWE-260": "A05:2021",
    "CWE-306": "A05:2021",
    "CWE-388": "A05:2021",
    "CWE-489": "A05:2021",
    "CWE-526": "A05:2021",
    "CWE-611": "A05:2021",
    "CWE-614": "A05:2021",
    "CWE-732": "A05:2021",
    "CWE-756": "A05:2021",
    "CWE-1104": "A06:2021",
    "CWE-1391": "A06:2021",  # weak default config
    "CWE-255": "A07:2021",
    "CWE-287": "A07:2021",
    "CWE-288": "A07:2021",
    "CWE-290": "A07:2021",
    "CWE-294": "A07:2021",
    "CWE-295": "A07:2021",
    "CWE-307": "A07:2021",
    "CWE-384": "A07:2021",
    "CWE-521": "A07:2021",
    "CWE-613": "A07:2021",
    "CWE-640": "A07:2021",
    "CWE-798": "A07:2021",
    "CWE-345": "A08:2021",
    "CWE-426": "A08:2021",
    "CWE-494": "A08:2021",
    "CWE-502": "A08:2021",
    "CWE-829": "A08:2021",
    "CWE-915": "A08:2021",
    "CWE-117": "A09:2021",
    "CWE-223": "A09:2021",
    "CWE-532": "A09:2021",
    "CWE-778": "A09:2021",
    "CWE-918": "A10:2021",
}


# OWASP API Security Top 10 (2023).
_CWE_TO_OWASP_API_TOP_10: dict[str, str] = {
    "CWE-639": "API1:2023",
    "CWE-285": "API1:2023",  # also fits API5
    "CWE-287": "API2:2023",
    "CWE-294": "API2:2023",
    "CWE-307": "API2:2023",
    "CWE-521": "API2:2023",
    "CWE-798": "API2:2023",
    "CWE-915": "API3:2023",
    "CWE-200": "API3:2023",
    "CWE-770": "API4:2023",
    "CWE-405": "API4:2023",
    "CWE-862": "API5:2023",
    "CWE-863": "API5:2023",
    "CWE-840": "API6:2023",  # business logic abuse
    "CWE-918": "API7:2023",
    "CWE-2": "API8:2023",
    "CWE-15": "API8:2023",
    "CWE-16": "API8:2023",
    "CWE-756": "API8:2023",
    "CWE-388": "API8:2023",
    "CWE-1059": "API9:2023",  # improper inventory mgmt
    "CWE-829": "API10:2023",  # unsafe consumption
}


# MITRE ATT&CK technique IDs most directly associated with each CWE class.
# Conservative — list only the most-cited ATT&CK references; consumers can
# expand via their own enrichment pipelines.
_CWE_TO_MITRE_ATTACK: dict[str, list[str]] = {
    "CWE-22": ["T1083", "T1005"],  # File/Dir Discovery, Data from Local System
    "CWE-78": ["T1059"],  # Command and Scripting Interpreter
    "CWE-79": ["T1059.007"],  # JavaScript
    "CWE-89": ["T1190"],  # Exploit Public-Facing Application
    "CWE-94": ["T1059", "T1190"],
    "CWE-200": ["T1213", "T1592"],
    "CWE-269": ["T1068"],  # Exploitation for Privilege Escalation
    "CWE-285": ["T1078"],  # Valid Accounts
    "CWE-287": ["T1078"],
    "CWE-294": ["T1557"],  # Adversary-in-the-Middle
    "CWE-306": ["T1078.004"],  # Cloud Accounts (no auth → impersonation)
    "CWE-307": ["T1110"],  # Brute Force
    "CWE-319": ["T1040"],  # Network Sniffing
    "CWE-327": ["T1552", "T1040"],
    "CWE-345": ["T1565"],  # Data Manipulation
    "CWE-347": ["T1606.001"],  # Forge Web Credentials: Web Cookies
    "CWE-352": ["T1204.001"],  # Malicious Link
    "CWE-384": ["T1606"],  # Forge Web Credentials
    "CWE-434": ["T1190", "T1505.003"],  # Web Shell
    "CWE-502": ["T1190"],
    "CWE-521": ["T1110"],
    "CWE-548": ["T1083"],
    "CWE-601": ["T1204.001"],
    "CWE-611": ["T1190"],
    "CWE-639": ["T1078"],
    "CWE-732": ["T1222"],  # File and Directory Permissions Modification
    "CWE-770": ["T1499"],  # Endpoint Denial of Service
    "CWE-798": ["T1552.001"],  # Unsecured Credentials in Files
    "CWE-829": ["T1195"],  # Supply Chain Compromise
    "CWE-862": ["T1078"],
    "CWE-863": ["T1078"],
    "CWE-915": ["T1190"],  # mass assignment via injection-style
    "CWE-918": ["T1071.001", "T1090"],  # Web Protocols, Proxy
    "CWE-1278": ["T1566"],  # Phishing — when SPF/DMARC missing
    "CWE-1390": ["T1583.001", "T1584"],  # Acquire/Compromise Infrastructure
}


def _normalize_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    s = cwe.strip().upper()
    if s.isdigit():
        s = f"CWE-{s}"
    return s if s.startswith("CWE-") else None


def _normalize_cve(cve: str | None) -> str | None:
    if not cve:
        return None
    s = cve.strip().upper()
    if not s.startswith("CVE-"):
        return None
    return s


def lookup_owasp_top_10(cwe: str | None) -> str | None:
    key = _normalize_cwe(cwe)
    return _CWE_TO_OWASP_TOP_10.get(key) if key else None


def lookup_owasp_api_top_10(cwe: str | None) -> str | None:
    key = _normalize_cwe(cwe)
    return _CWE_TO_OWASP_API_TOP_10.get(key) if key else None


def lookup_mitre_attack(cwe: str | None) -> list[str]:
    key = _normalize_cwe(cwe)
    return list(_CWE_TO_MITRE_ATTACK.get(key, [])) if key else []


# ---------------------------------------------------------------------------
# CISA KEV catalog
# ---------------------------------------------------------------------------


class KevCatalog:
    """In-memory + on-disk-cached lookup for CISA's Known Exploited Vulnerabilities.

    Loads lazily on first lookup. If the on-disk cache exists and is fresh
    (<24h old), uses it. Otherwise fetches from the CISA URL and writes a
    fresh cache. On any fetch failure, falls back to a stale cache when one
    exists; if neither cache nor fetch is available, returns "unknown" for
    every lookup (None) — fail-open.
    """

    def __init__(
        self,
        url: str | None = None,
        cache_path: Path | str | None = None,
        ttl_seconds: int = _CACHE_TTL_SECONDS,
    ) -> None:
        self._url = url or os.environ.get("STRIX_KEV_URL", _KEV_URL_DEFAULT)
        self._cache_path = (
            Path(cache_path)
            if cache_path
            else Path(
                os.environ.get(
                    "STRIX_KEV_CACHE_PATH",
                    str(Path.home() / ".strix" / "kev_cache.json"),
                )
            )
        )
        self._ttl_seconds = ttl_seconds
        self._index: dict[str, dict[str, Any]] | None = None
        self._loaded_at: float | None = None

    # ---- public API ----

    def is_known(self, cve: str | None) -> bool | None:
        """Return True/False if catalog is loaded; None if unable to load
        (in which case the caller treats the answer as "unknown")."""
        cve_id = _normalize_cve(cve)
        if not cve_id:
            return None
        if not self._ensure_loaded():
            return None
        assert self._index is not None
        return cve_id in self._index

    def entry(self, cve: str | None) -> dict[str, Any] | None:
        cve_id = _normalize_cve(cve)
        if not cve_id or not self._ensure_loaded():
            return None
        assert self._index is not None
        return self._index.get(cve_id)

    def loaded(self) -> bool:
        return self._index is not None

    def refresh(self, force: bool = False) -> bool:
        """Refresh the on-disk cache. Returns True on success."""
        if not force:
            self._ensure_loaded()
            return self._index is not None
        self._index = None
        self._loaded_at = None
        return self._load_remote()

    # ---- internals ----

    def _ensure_loaded(self) -> bool:
        if self._index is not None:
            return True
        if os.environ.get("STRIX_KEV_DISABLED"):
            return False
        if self._load_cache_if_fresh():
            return True
        if self._load_remote():
            return True
        # Last-resort: stale cache.
        return self._load_cache_any()

    def _build_index(self, payload: dict[str, Any]) -> None:
        vulns = payload.get("vulnerabilities") or []
        index: dict[str, dict[str, Any]] = {}
        for v in vulns:
            cve_id = (v.get("cveID") or "").strip().upper()
            if not cve_id:
                continue
            index[cve_id] = {
                "cve_id": cve_id,
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "vuln_name": v.get("vulnerabilityName"),
                "added_at": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "required_action": v.get("requiredAction"),
                "ransomware_use": v.get("knownRansomwareCampaignUse"),
            }
        self._index = index
        self._loaded_at = time.time()
        logger.info("loaded KEV catalog with %d entries", len(index))

    def _load_cache_if_fresh(self) -> bool:
        if not self._cache_path.exists():
            return False
        try:
            age = time.time() - self._cache_path.stat().st_mtime
            if age > self._ttl_seconds:
                return False
            return self._load_cache_any()
        except OSError:
            return False

    def _load_cache_any(self) -> bool:
        if not self._cache_path.exists():
            return False
        try:
            with self._cache_path.open("r", encoding="utf-8") as f:
                payload = json.load(f)
            self._build_index(payload)
            return True
        except (OSError, json.JSONDecodeError):
            logger.warning("failed to read KEV cache at %s", self._cache_path, exc_info=True)
            return False

    def _load_remote(self) -> bool:
        try:
            payload = _fetch_json(self._url)
        except Exception:  # noqa: BLE001
            logger.warning("KEV remote fetch failed: %s", self._url, exc_info=True)
            return False
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._cache_path.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
        except OSError:
            logger.warning("failed to write KEV cache at %s", self._cache_path, exc_info=True)
        self._build_index(payload)
        return True


def _fetch_json(url: str, timeout: int = 15) -> dict[str, Any]:
    """Tiny stdlib JSON fetcher. Avoids adding a httpx dep here."""
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": "strix-kev-fetcher/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.load(r)


# Module-level singleton, lazily-initialised. Tests can override via
# `set_default_catalog(KevCatalog(...))`.
_default_catalog: KevCatalog | None = None


def get_default_catalog() -> KevCatalog:
    global _default_catalog
    if _default_catalog is None:
        _default_catalog = KevCatalog()
    return _default_catalog


def set_default_catalog(catalog: KevCatalog | None) -> None:
    """Replace the module-level singleton. None resets to lazy init."""
    global _default_catalog
    _default_catalog = catalog


# ---------------------------------------------------------------------------
# Single-shot enrichment helper
# ---------------------------------------------------------------------------


def enrich(cwe: str | None, cve: str | None) -> dict[str, Any]:
    """Build a threat-intel enrichment dict for one finding. Always safe;
    returns an empty dict when nothing applicable is known."""
    enriched: dict[str, Any] = {}

    owasp = lookup_owasp_top_10(cwe)
    if owasp:
        enriched["owasp_top_10"] = owasp

    api = lookup_owasp_api_top_10(cwe)
    if api:
        enriched["owasp_api_top_10"] = api

    techniques = lookup_mitre_attack(cwe)
    if techniques:
        enriched["mitre_attack"] = techniques

    cve_id = _normalize_cve(cve)
    if cve_id:
        catalog = get_default_catalog()
        is_known = catalog.is_known(cve_id)
        if is_known is True:
            entry = catalog.entry(cve_id) or {}
            enriched["is_kev"] = True
            if entry.get("added_at"):
                enriched["kev_added_at"] = entry["added_at"]
            if entry.get("due_date"):
                enriched["kev_due_date"] = entry["due_date"]
            if entry.get("ransomware_use"):
                enriched["kev_ransomware_use"] = entry["ransomware_use"]
            enriched["cisa_kev_url"] = (
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            )
        elif is_known is False:
            enriched["is_kev"] = False
        # is_known is None → catalog unavailable, leave field unset.

    return enriched
