"""SQLite cache for threat-intel feeds.

Schema (kept intentionally simple — feeds populate, lookup reads):

  cves(cve_id PK, description, cvss_score, severity, published, modified, kev INTEGER, epss REAL, sources TEXT)
  cve_components(cve_id FK, vendor, product, version_pattern)  -- many per CVE
  kev_entries(cve_id PK, vendor, product, vuln_name, date_added, due_date, ransomware INT, notes)
  feed_meta(feed_name PK, last_polled, last_updated_at, status, error)

Indexes:
  ix_cve_components_product (lower(product))
  ix_cves_kev (kev) WHERE kev=1
  ix_cves_epss (epss)

Best-effort throughout — failures swallowed and surfaced via
`feed_meta.status='error'`.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator


logger = logging.getLogger(__name__)


_DEFAULT_CACHE_PATH = Path.home() / ".cache" / "strix" / "threat_intel.db"
_LOCK = threading.RLock()


def cache_path() -> Path:
    """Resolve the cache DB path. Override via `STRIX_THREAT_INTEL_CACHE` env."""
    override = os.environ.get("STRIX_THREAT_INTEL_CACHE")
    if override:
        return Path(override).expanduser()
    return _DEFAULT_CACHE_PATH


def _ensure_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL,
    severity TEXT,
    published TEXT,
    modified TEXT,
    kev INTEGER NOT NULL DEFAULT 0,
    epss REAL,
    sources TEXT,                -- JSON list of source names
    raw TEXT                     -- raw feed record for forensic reads
);

CREATE INDEX IF NOT EXISTS ix_cves_kev ON cves(kev);
CREATE INDEX IF NOT EXISTS ix_cves_epss ON cves(epss);
CREATE INDEX IF NOT EXISTS ix_cves_severity ON cves(severity);

CREATE TABLE IF NOT EXISTS cve_components (
    cve_id TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    version_pattern TEXT,
    -- version_pattern semantics:
    --   "*"           any version
    --   "1.2.3"       exact match
    --   "<1.2.3"      strict less-than
    --   ">=1.2.0,<1.3.0"  range
    PRIMARY KEY (cve_id, vendor, product, version_pattern)
);

CREATE INDEX IF NOT EXISTS ix_cve_components_product
    ON cve_components(lower(product));

CREATE TABLE IF NOT EXISTS kev_entries (
    cve_id TEXT PRIMARY KEY,
    vendor TEXT,
    product TEXT,
    vuln_name TEXT,
    date_added TEXT,
    due_date TEXT,
    ransomware INTEGER NOT NULL DEFAULT 0,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS feed_meta (
    feed_name TEXT PRIMARY KEY,
    last_polled TEXT,
    last_updated_at TEXT,
    status TEXT,                 -- 'ok' | 'error' | 'unknown'
    error TEXT,
    record_count INTEGER NOT NULL DEFAULT 0
);

-- Phase 6.6 dynamic refresh: top-N popular packages per ecosystem.
-- Refreshed daily by `feeds/popular_packages.py` (anvaka npm gist
-- + hugovk pypi top-packages JSON). The malicious-package
-- typosquat detector reads from this table; if empty (cache not
-- yet refreshed), it falls back to a small hardcoded corpus.
CREATE TABLE IF NOT EXISTS popular_packages (
    ecosystem TEXT NOT NULL,     -- 'npm' | 'pypi' | ...
    name TEXT NOT NULL,           -- lowercased canonical package name
    rank INTEGER,                 -- 1 = most-downloaded; null when source
                                  -- doesn't supply ordering
    PRIMARY KEY (ecosystem, name)
);
CREATE INDEX IF NOT EXISTS ix_popular_packages_eco ON popular_packages(ecosystem);

-- Phase 6.6 dynamic refresh: known-malicious packages.
-- Refreshed daily by `feeds/ossf_malicious.py` from OSV.dev's
-- per-ecosystem bulk export, filtered to MAL-* advisories
-- (the OSSF malicious-packages namespace). Hit at scan time
-- to flag installed packages that are confirmed malicious —
-- distinct from "vulnerable but legitimate" (that's the cves
-- table).
CREATE TABLE IF NOT EXISTS malicious_packages (
    ecosystem TEXT NOT NULL,     -- 'npm' | 'pypi' | ...
    name TEXT NOT NULL,           -- lowercased canonical package name
    advisory_id TEXT NOT NULL,    -- e.g. 'MAL-2023-0001' (OSV id)
    summary TEXT,
    detected_at TEXT,             -- ISO-8601 timestamp of malicious detection
    severity TEXT,                -- 'critical' | 'high' | 'medium' (default: critical)
    affected_versions TEXT,       -- JSON list; empty = ALL versions
    PRIMARY KEY (ecosystem, name, advisory_id)
);
CREATE INDEX IF NOT EXISTS ix_malicious_packages_lookup
    ON malicious_packages(ecosystem, name);

-- iter-21.2 — active-exploitation campaign correlation.
--
-- A "campaign" is one entry from a threat-intel feed describing
-- a coordinated attacker activity. Sources include:
--   * AlienVault OTX pulses (https://otx.alienvault.com/api/v1/)
--   * MISP community feeds (event-shaped)
--   * Mandiant ASM / MS Defender TI campaign reports
--   * Recorded Future Community / IntelX
--
-- Each campaign typically references multiple CVEs that the
-- attacker(s) leverage. The `campaign_cve_links` mapping lets us
-- answer "which active campaigns are using CVE-X right now?"
-- when emitting a finding, mirroring the way KEV answers "is
-- this CVE in CISA's exploited-in-wild catalog?".
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id TEXT PRIMARY KEY,    -- feed-prefixed (e.g. 'otx:65f...', 'misp:1234')
    source TEXT NOT NULL,            -- 'otx' | 'misp' | 'mandiant' | 'recorded_future'
    name TEXT,                       -- pulse / event / report title
    description TEXT,
    author TEXT,                     -- pulse author / curator
    first_seen TEXT,                 -- ISO-8601 of first appearance
    last_seen TEXT,                  -- ISO-8601 of last update (some feeds re-update)
    severity TEXT,                   -- 'critical' | 'high' | 'medium' | 'low' | null
    references_json TEXT,            -- JSON array of reference URLs
    tags_json TEXT                   -- JSON array of feed tags / TLP / sector
);

CREATE INDEX IF NOT EXISTS ix_campaigns_source ON campaigns(source);
CREATE INDEX IF NOT EXISTS ix_campaigns_last_seen ON campaigns(last_seen);

CREATE TABLE IF NOT EXISTS campaign_cve_links (
    cve_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    PRIMARY KEY (cve_id, campaign_id)
);

CREATE INDEX IF NOT EXISTS ix_campaign_cve_links_cve
    ON campaign_cve_links(cve_id);
CREATE INDEX IF NOT EXISTS ix_campaign_cve_links_campaign
    ON campaign_cve_links(campaign_id);

-- iter-22.7 — exploit-availability cache.
--
-- For each CVE, track whether a public PoC / Metasploit module /
-- Exploit-DB entry exists. Operationally, "is there a working
-- exploit?" is the single biggest prioritization signal AFTER
-- KEV (Tenable's data: ~78% of breaches use CVEs with public
-- PoCs vs ~12% with KEV-only).
--
-- Sources (poll separately; this cache just stores the facts):
--   * PoC-in-GitHub (nomi-sec/PoC-in-GitHub) — daily-refreshed,
--     ~50% high-EPSS CVEs have a GitHub PoC entry within 24h.
--   * Metasploit module catalog — local `msfconsole search` output
--     OR cached `~/.msf4/db.tsv`-style export.
--   * Exploit-DB via `searchsploit --json -e <CVE>`.
--   * Vulncheck Initial Access (premium tier; optional).
CREATE TABLE IF NOT EXISTS cve_exploit_availability (
    cve_id TEXT PRIMARY KEY,
    has_public_poc INTEGER NOT NULL DEFAULT 0,
    poc_count INTEGER NOT NULL DEFAULT 0,
    poc_top_url TEXT,                 -- highest-stars PoC repo URL
    has_msf_module INTEGER NOT NULL DEFAULT 0,
    msf_module_name TEXT,
    has_exploit_db INTEGER NOT NULL DEFAULT 0,
    exploit_db_id TEXT,
    sources_json TEXT,                -- JSON array: which feeds populated this row
    last_seen TEXT,                   -- ISO-8601 of most-recent feed-poll update
    raw_json TEXT                     -- per-source raw blobs (for audit)
);

CREATE INDEX IF NOT EXISTS ix_cve_exploit_avail_has_poc
    ON cve_exploit_availability(has_public_poc)
    WHERE has_public_poc=1;
CREATE INDEX IF NOT EXISTS ix_cve_exploit_avail_has_msf
    ON cve_exploit_availability(has_msf_module)
    WHERE has_msf_module=1;
"""


@dataclass
class CVERecord:
    """One CVE record as returned by the lookup layer."""
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    severity: str | None = None
    published: str | None = None
    modified: str | None = None
    kev: bool = False
    epss: float | None = None
    sources: list[str] = field(default_factory=list)
    components: list[dict[str, str]] = field(default_factory=list)
    kev_meta: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "published": self.published,
            "modified": self.modified,
            "kev": self.kev,
            "epss": self.epss,
            "sources": list(self.sources),
            "components": list(self.components),
            "kev_meta": self.kev_meta,
        }


@contextmanager
def connect(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    """Yield a connection with the schema ensured. Caller owns the
    transaction (commit / rollback)."""
    p = path or cache_path()
    _ensure_dir(p)
    with _LOCK:
        conn = sqlite3.connect(str(p), timeout=30, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.executescript(_SCHEMA)
            yield conn
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Write helpers (used by feeds/*)
# ---------------------------------------------------------------------------


def upsert_cves(records: Iterable[dict[str, Any]], *, source: str) -> int:
    """Insert / update CVE records. Each record may have:
        cve_id, description, cvss_score, severity, published,
        modified, components (list of {vendor, product, version_pattern})

    `source` is appended to the cves.sources JSON list.
    Returns the count actually upserted.
    """
    n = 0
    with connect() as conn:
        cur = conn.cursor()
        cur.execute("BEGIN")
        try:
            for r in records:
                cve_id = r.get("cve_id")
                if not isinstance(cve_id, str) or not cve_id.strip():
                    continue
                cve_id = cve_id.strip().upper()

                # Merge sources: pull existing, add new, write back.
                cur.execute(
                    "SELECT sources FROM cves WHERE cve_id=?", (cve_id,),
                )
                row = cur.fetchone()
                existing_sources: list[str] = []
                if row and row["sources"]:
                    try:
                        existing_sources = json.loads(row["sources"])
                    except Exception:  # noqa: BLE001
                        existing_sources = []
                if source and source not in existing_sources:
                    existing_sources.append(source)
                sources_json = json.dumps(existing_sources)

                cur.execute(
                    """
                    INSERT INTO cves
                        (cve_id, description, cvss_score, severity,
                         published, modified, kev, epss, sources, raw)
                    VALUES (?, ?, ?, ?, ?, ?,
                            COALESCE((SELECT kev FROM cves WHERE cve_id=?), 0),
                            COALESCE((SELECT epss FROM cves WHERE cve_id=?), NULL),
                            ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        description = COALESCE(excluded.description, cves.description),
                        cvss_score  = COALESCE(excluded.cvss_score, cves.cvss_score),
                        severity    = COALESCE(excluded.severity, cves.severity),
                        published   = COALESCE(excluded.published, cves.published),
                        modified    = excluded.modified,
                        sources     = excluded.sources,
                        raw         = COALESCE(excluded.raw, cves.raw)
                    """,
                    (
                        cve_id,
                        r.get("description") or "",
                        r.get("cvss_score"),
                        r.get("severity"),
                        r.get("published"),
                        r.get("modified"),
                        cve_id, cve_id,
                        sources_json,
                        json.dumps(r.get("raw")) if r.get("raw") is not None else None,
                    ),
                )

                # Replace components for this CVE — feeds always write
                # the full set per record.
                comps = r.get("components") or []
                if isinstance(comps, list):
                    cur.execute(
                        "DELETE FROM cve_components WHERE cve_id=?",
                        (cve_id,),
                    )
                    for c in comps:
                        if not isinstance(c, dict):
                            continue
                        try:
                            cur.execute(
                                """
                                INSERT OR IGNORE INTO cve_components
                                    (cve_id, vendor, product, version_pattern)
                                VALUES (?, ?, ?, ?)
                                """,
                                (
                                    cve_id,
                                    (c.get("vendor") or "").strip().lower() or None,
                                    (c.get("product") or "").strip().lower() or None,
                                    (c.get("version_pattern") or "*").strip(),
                                ),
                            )
                        except Exception as e:  # noqa: BLE001
                            logger.debug(
                                "upsert_cves component insert failed for %s: %s",
                                cve_id, e,
                            )
                n += 1
            cur.execute("COMMIT")
        except Exception as e:  # noqa: BLE001
            cur.execute("ROLLBACK")
            logger.warning("upsert_cves failed: %s", e, exc_info=True)
            raise
    return n


def upsert_kev_entries(records: Iterable[dict[str, Any]]) -> int:
    """Insert / update KEV entries. Each record:
        cve_id, vendor, product, vuln_name, date_added, due_date,
        ransomware, notes
    Also flips the `kev=1` flag on the corresponding cves row."""
    n = 0
    with connect() as conn:
        cur = conn.cursor()
        cur.execute("BEGIN")
        try:
            # Reset the kev flag on every CVE; we'll flip it on for
            # the rows in this batch. This way drops from the KEV
            # catalog (rare) are reflected.
            cur.execute("UPDATE cves SET kev=0")

            for r in records:
                cve_id = r.get("cve_id")
                if not isinstance(cve_id, str) or not cve_id.strip():
                    continue
                cve_id = cve_id.strip().upper()
                cur.execute(
                    """
                    INSERT INTO kev_entries
                        (cve_id, vendor, product, vuln_name, date_added,
                         due_date, ransomware, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        vendor      = excluded.vendor,
                        product     = excluded.product,
                        vuln_name   = excluded.vuln_name,
                        date_added  = excluded.date_added,
                        due_date    = excluded.due_date,
                        ransomware  = excluded.ransomware,
                        notes       = excluded.notes
                    """,
                    (
                        cve_id,
                        (r.get("vendor") or "").strip(),
                        (r.get("product") or "").strip(),
                        (r.get("vuln_name") or "").strip(),
                        r.get("date_added"),
                        r.get("due_date"),
                        1 if r.get("ransomware") else 0,
                        (r.get("notes") or "").strip(),
                    ),
                )
                # Ensure cves row exists (KEV may name a CVE we
                # haven't ingested yet).
                cur.execute(
                    """
                    INSERT INTO cves (cve_id, kev, sources)
                    VALUES (?, 1, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET kev=1
                    """,
                    (cve_id, json.dumps(["kev"])),
                )
                # Add a (vendor, product, *) component row ONLY when
                # this CVE has no existing components — otherwise we'd
                # broaden a more-specific NVD bound (e.g. ">=2.4.0,
                # <2.4.55") to a wildcard. The case we cover here is
                # KEV-only CVEs (no NVD record yet); the lookup-by-
                # product query then still finds them.
                vendor = (r.get("vendor") or "").strip().lower() or None
                product = (r.get("product") or "").strip().lower() or None
                if product:
                    cur.execute(
                        "SELECT 1 FROM cve_components WHERE cve_id=?",
                        (cve_id,),
                    )
                    has_components = cur.fetchone() is not None
                    if not has_components:
                        cur.execute(
                            """
                            INSERT OR IGNORE INTO cve_components
                                (cve_id, vendor, product, version_pattern)
                            VALUES (?, ?, ?, '*')
                            """,
                            (cve_id, vendor, product),
                        )
                n += 1
            cur.execute("COMMIT")
        except Exception as e:  # noqa: BLE001
            cur.execute("ROLLBACK")
            logger.warning("upsert_kev_entries failed: %s", e, exc_info=True)
            raise
    return n


def upsert_epss_scores(scores: Iterable[tuple[str, float]]) -> int:
    """Update EPSS probability for each (cve_id, score) pair.
    Creates the cves row if missing (so EPSS-only entries surface)."""
    n = 0
    with connect() as conn:
        cur = conn.cursor()
        cur.execute("BEGIN")
        try:
            for cve_id, score in scores:
                if not isinstance(cve_id, str) or not cve_id.strip():
                    continue
                cve_id = cve_id.strip().upper()
                if not isinstance(score, (int, float)):
                    continue
                cur.execute(
                    """
                    INSERT INTO cves (cve_id, epss, sources)
                    VALUES (?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET epss=excluded.epss
                    """,
                    (cve_id, float(score), json.dumps(["epss"])),
                )
                n += 1
            cur.execute("COMMIT")
        except Exception as e:  # noqa: BLE001
            cur.execute("ROLLBACK")
            logger.warning("upsert_epss_scores failed: %s", e, exc_info=True)
            raise
    return n


def upsert_popular_packages(
    records: Iterable[tuple[str, str, int | None]],
    *,
    replace_ecosystem: str | None = None,
) -> int:
    """Upsert popular-package rankings.

    Args:
        records: iterable of (ecosystem, name, rank) tuples.
            `rank` may be None when the source doesn't supply ordering.
        replace_ecosystem: when set, DELETE all existing rows for that
            ecosystem before inserting. Used by the daily feed to keep
            the corpus fresh — yesterday's "top 500" gets fully
            replaced rather than merged so packages that drop off
            the list don't linger forever.

    Returns count upserted.
    """
    n = 0
    with connect() as conn:
        cur = conn.cursor()
        cur.execute("BEGIN")
        try:
            if replace_ecosystem:
                cur.execute(
                    "DELETE FROM popular_packages WHERE ecosystem=?",
                    (replace_ecosystem.lower(),),
                )
            for eco, name, rank in records:
                if not isinstance(eco, str) or not isinstance(name, str):
                    continue
                eco_norm = eco.strip().lower()
                name_norm = name.strip().lower()
                if not eco_norm or not name_norm:
                    continue
                cur.execute(
                    """
                    INSERT INTO popular_packages (ecosystem, name, rank)
                    VALUES (?, ?, ?)
                    ON CONFLICT(ecosystem, name) DO UPDATE SET
                        rank = excluded.rank
                    """,
                    (eco_norm, name_norm,
                     int(rank) if isinstance(rank, int) else None),
                )
                n += 1
            cur.execute("COMMIT")
        except Exception as e:  # noqa: BLE001
            cur.execute("ROLLBACK")
            logger.warning("upsert_popular_packages failed: %s", e, exc_info=True)
            raise
    return n


def fetch_popular_packages(
    ecosystem: str, *, limit: int = 1000,
) -> set[str]:
    """Return a set of canonical (lowercased) package names for the
    given ecosystem. Used by `malicious.py::_detect_typosquat` as
    the corpus to compare against. Returns empty set when the cache
    isn't populated — caller falls back to the small hardcoded
    corpus."""
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT name FROM popular_packages
            WHERE ecosystem = ?
            ORDER BY rank IS NULL, rank
            LIMIT ?
            """,
            (ecosystem.strip().lower(), int(limit)),
        )
        return {r["name"] for r in cur.fetchall()}


def upsert_malicious_packages(records: Iterable[dict[str, Any]]) -> int:
    """Upsert known-malicious package advisories.

    Each record:
        {ecosystem, name, advisory_id, summary?, detected_at?,
         severity?, affected_versions?}

    `severity` defaults to "critical" (the OSSF feed only lists
    confirmed-malicious packages — not "suspicious"; severity
    isn't graduated like CVE). `affected_versions` is a list;
    empty / None means "all versions".
    """
    n = 0
    with connect() as conn:
        cur = conn.cursor()
        cur.execute("BEGIN")
        try:
            for r in records:
                if not isinstance(r, dict):
                    continue
                eco = (r.get("ecosystem") or "").strip().lower()
                name = (r.get("name") or "").strip().lower()
                advisory_id = (r.get("advisory_id") or "").strip()
                if not eco or not name or not advisory_id:
                    continue
                versions_raw = r.get("affected_versions") or []
                if isinstance(versions_raw, list):
                    versions_json = json.dumps(versions_raw)
                else:
                    versions_json = json.dumps([])
                cur.execute(
                    """
                    INSERT INTO malicious_packages
                        (ecosystem, name, advisory_id, summary,
                         detected_at, severity, affected_versions)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ecosystem, name, advisory_id) DO UPDATE SET
                        summary = excluded.summary,
                        detected_at = excluded.detected_at,
                        severity = excluded.severity,
                        affected_versions = excluded.affected_versions
                    """,
                    (
                        eco, name, advisory_id,
                        (r.get("summary") or "")[:2048],
                        r.get("detected_at"),
                        (r.get("severity") or "critical").lower(),
                        versions_json,
                    ),
                )
                n += 1
            cur.execute("COMMIT")
        except Exception as e:  # noqa: BLE001
            cur.execute("ROLLBACK")
            logger.warning("upsert_malicious_packages failed: %s", e, exc_info=True)
            raise
    return n


def fetch_malicious_packages(
    ecosystem: str, name: str,
) -> list[dict[str, Any]]:
    """Return all malicious-package advisories matching
    (ecosystem, name). Empty list when no entries — meaning we
    have NO evidence the package is malicious (NOT a guarantee
    of safety; the cache may be stale or the malicious feed may
    not yet cover this ecosystem).

    Caller checks the returned `affected_versions` against the
    actual installed version: empty list = all versions affected.
    """
    if not ecosystem or not name:
        return []
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT * FROM malicious_packages
            WHERE ecosystem = ? AND name = ?
            ORDER BY detected_at DESC
            """,
            (ecosystem.strip().lower(), name.strip().lower()),
        )
        out: list[dict[str, Any]] = []
        for row in cur.fetchall():
            d = dict(row)
            try:
                d["affected_versions"] = json.loads(d["affected_versions"] or "[]")
            except Exception:  # noqa: BLE001
                d["affected_versions"] = []
            out.append(d)
        return out


def record_feed_status(
    feed_name: str, *,
    status: str = "ok",
    error: str | None = None,
    record_count: int = 0,
    last_updated_at: str | None = None,
) -> None:
    """Record feed-poll metadata for `cache_status()` introspection."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO feed_meta
                (feed_name, last_polled, last_updated_at, status, error, record_count)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(feed_name) DO UPDATE SET
                last_polled       = excluded.last_polled,
                last_updated_at   = excluded.last_updated_at,
                status            = excluded.status,
                error             = excluded.error,
                record_count      = excluded.record_count
            """,
            (feed_name, now, last_updated_at or now, status,
             (error or "")[:1024], int(record_count)),
        )


# ---------------------------------------------------------------------------
# Read helpers (used by lookup.py)
# ---------------------------------------------------------------------------


def _row_to_cve(row: sqlite3.Row, components_rows: list[sqlite3.Row] | None = None,
                kev_meta_row: sqlite3.Row | None = None) -> CVERecord:
    sources: list[str] = []
    if row["sources"]:
        try:
            sources = json.loads(row["sources"])
        except Exception:  # noqa: BLE001
            sources = []
    return CVERecord(
        cve_id=row["cve_id"],
        description=row["description"] or "",
        cvss_score=row["cvss_score"],
        severity=row["severity"],
        published=row["published"],
        modified=row["modified"],
        kev=bool(row["kev"]),
        epss=row["epss"],
        sources=sources,
        components=[
            {
                "vendor": c["vendor"] or "",
                "product": c["product"] or "",
                "version_pattern": c["version_pattern"] or "*",
            }
            for c in (components_rows or [])
        ],
        kev_meta=(
            {
                "vendor": kev_meta_row["vendor"],
                "product": kev_meta_row["product"],
                "vuln_name": kev_meta_row["vuln_name"],
                "date_added": kev_meta_row["date_added"],
                "due_date": kev_meta_row["due_date"],
                "ransomware": bool(kev_meta_row["ransomware"]),
                "notes": kev_meta_row["notes"],
            }
            if kev_meta_row else None
        ),
    )


def fetch_cve(cve_id: str) -> CVERecord | None:
    """Look up a single CVE by ID."""
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None
    cve_id = cve_id.strip().upper()
    with connect() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM cves WHERE cve_id=?", (cve_id,))
        row = cur.fetchone()
        if row is None:
            return None
        cur.execute(
            "SELECT * FROM cve_components WHERE cve_id=?", (cve_id,),
        )
        comps = cur.fetchall()
        cur.execute("SELECT * FROM kev_entries WHERE cve_id=?", (cve_id,))
        kev_row = cur.fetchone()
        return _row_to_cve(row, comps, kev_row)


def fetch_cves_for_product(
    product: str, *, vendor: str | None = None,
    only_kev: bool = False, min_epss: float = 0.0,
    limit: int = 200,
) -> list[CVERecord]:
    """Look up CVEs whose component matches `(vendor, product)`.
    Vendor is optional — when omitted, matches any vendor with the
    same product name."""
    if not isinstance(product, str) or not product.strip():
        return []
    product = product.strip().lower()

    where = ["lower(cc.product) = ?"]
    params: list[Any] = [product]
    if vendor:
        where.append("lower(cc.vendor) = ?")
        params.append(vendor.strip().lower())
    if only_kev:
        where.append("c.kev = 1")
    where.append("(c.epss IS NULL OR c.epss >= ?)")
    params.append(float(min_epss))

    sql = f"""
        SELECT DISTINCT c.*
        FROM cves c
        JOIN cve_components cc ON cc.cve_id = c.cve_id
        WHERE {' AND '.join(where)}
        ORDER BY c.kev DESC, c.epss DESC NULLS LAST, c.cvss_score DESC NULLS LAST
        LIMIT ?
    """
    params.append(int(limit))

    with connect() as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        cve_rows = cur.fetchall()
        out: list[CVERecord] = []
        for row in cve_rows:
            cur.execute(
                "SELECT * FROM cve_components WHERE cve_id=?", (row["cve_id"],),
            )
            comps = cur.fetchall()
            cur.execute(
                "SELECT * FROM kev_entries WHERE cve_id=?", (row["cve_id"],),
            )
            kev_row = cur.fetchone()
            out.append(_row_to_cve(row, comps, kev_row))
        return out


def fetch_kev_list(limit: int = 5000) -> list[CVERecord]:
    """All KEV-flagged CVEs in the cache."""
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT c.*
            FROM cves c
            WHERE c.kev = 1
            ORDER BY c.epss DESC NULLS LAST, c.cve_id DESC
            LIMIT ?
            """,
            (int(limit),),
        )
        cve_rows = cur.fetchall()
        out: list[CVERecord] = []
        for row in cve_rows:
            cur.execute(
                "SELECT * FROM kev_entries WHERE cve_id=?", (row["cve_id"],),
            )
            kev_row = cur.fetchone()
            cur.execute(
                "SELECT * FROM cve_components WHERE cve_id=?", (row["cve_id"],),
            )
            comps = cur.fetchall()
            out.append(_row_to_cve(row, comps, kev_row))
        return out


def fetch_recently_exploited(
    *, min_epss: float = 0.5, limit: int = 100,
) -> list[CVERecord]:
    """High-EPSS or KEV-recent CVEs."""
    with connect() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT c.*
            FROM cves c
            WHERE c.kev = 1 OR c.epss >= ?
            ORDER BY c.kev DESC, c.epss DESC NULLS LAST, c.modified DESC
            LIMIT ?
            """,
            (float(min_epss), int(limit)),
        )
        cve_rows = cur.fetchall()
        out: list[CVERecord] = []
        for row in cve_rows:
            cur.execute(
                "SELECT * FROM cve_components WHERE cve_id=?", (row["cve_id"],),
            )
            comps = cur.fetchall()
            cur.execute(
                "SELECT * FROM kev_entries WHERE cve_id=?", (row["cve_id"],),
            )
            kev_row = cur.fetchone()
            out.append(_row_to_cve(row, comps, kev_row))
        return out


def fetch_feed_meta() -> list[dict[str, Any]]:
    """Per-feed status records for cache_status() introspection."""
    with connect() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM feed_meta ORDER BY feed_name")
        return [dict(r) for r in cur.fetchall()]


def reset_for_testing(path: Path | None = None) -> None:
    """Test-only — drop and recreate the schema."""
    p = path or cache_path()
    if p.exists():
        try:
            p.unlink()
        except Exception:  # noqa: BLE001
            pass
    with connect(p) as conn:
        conn.executescript(_SCHEMA)


# ---------------------------------------------------------------------------
# iter-21.2 — campaign correlation read/write helpers.
# ---------------------------------------------------------------------------


def upsert_campaign(record: dict[str, Any]) -> bool:
    """Insert / update one campaign row. Returns True on success.

    Expected keys: `campaign_id` (str, feed-prefixed and unique),
    `source`, plus any of: `name`, `description`, `author`,
    `first_seen`, `last_seen`, `severity`, `references` (list),
    `tags` (list). Best-effort: returns False on any DB error.
    """
    cid = record.get("campaign_id")
    src = record.get("source")
    if not isinstance(cid, str) or not cid.strip():
        return False
    if not isinstance(src, str) or not src.strip():
        return False
    refs = record.get("references")
    tags = record.get("tags")
    refs_json = json.dumps(refs) if isinstance(refs, list) else None
    tags_json = json.dumps(tags) if isinstance(tags, list) else None
    try:
        with connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO campaigns
                    (campaign_id, source, name, description, author,
                     first_seen, last_seen, severity,
                     references_json, tags_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(campaign_id) DO UPDATE SET
                    source           = excluded.source,
                    name             = COALESCE(excluded.name,
                                                campaigns.name),
                    description      = COALESCE(excluded.description,
                                                campaigns.description),
                    author           = COALESCE(excluded.author,
                                                campaigns.author),
                    first_seen       = COALESCE(campaigns.first_seen,
                                                excluded.first_seen),
                    last_seen        = COALESCE(excluded.last_seen,
                                                campaigns.last_seen),
                    severity         = COALESCE(excluded.severity,
                                                campaigns.severity),
                    references_json  = COALESCE(excluded.references_json,
                                                campaigns.references_json),
                    tags_json        = COALESCE(excluded.tags_json,
                                                campaigns.tags_json)
                """,
                (
                    cid.strip(), src.strip(),
                    record.get("name"), record.get("description"),
                    record.get("author"),
                    record.get("first_seen"), record.get("last_seen"),
                    record.get("severity"),
                    refs_json, tags_json,
                ),
            )
            return True
    except Exception as e:  # noqa: BLE001
        logger.warning("upsert_campaign failed: %s", e, exc_info=True)
        return False


def link_campaign_to_cves(
    campaign_id: str, cve_ids: Iterable[str],
) -> int:
    """Link one campaign to N CVEs. Idempotent (PRIMARY KEY on the
    composite). Returns the number of rows attempted to insert.
    Failures are swallowed; returns 0 on DB error.
    """
    if not isinstance(campaign_id, str) or not campaign_id.strip():
        return 0
    pairs = [
        (cve_id.strip(), campaign_id.strip())
        for cve_id in cve_ids
        if isinstance(cve_id, str) and cve_id.strip()
    ]
    if not pairs:
        return 0
    try:
        with connect() as conn:
            cur = conn.cursor()
            cur.executemany(
                """
                INSERT OR IGNORE INTO campaign_cve_links
                    (cve_id, campaign_id)
                VALUES (?, ?)
                """,
                pairs,
            )
            return len(pairs)
    except Exception as e:  # noqa: BLE001
        logger.warning("link_campaign_to_cves failed: %s", e, exc_info=True)
        return 0


def upsert_exploit_availability(record: dict[str, Any]) -> bool:
    """Insert / update one cve_exploit_availability row. iter-22.7.

    Expected keys: `cve_id` (required); any of `has_public_poc`,
    `poc_count`, `poc_top_url`, `has_msf_module`, `msf_module_name`,
    `has_exploit_db`, `exploit_db_id`, `sources` (list[str]),
    `last_seen` (ISO-8601), `raw` (dict — serialised to JSON).
    Returns True on success.
    """
    cve_id = record.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        return False
    src = record.get("sources")
    src_json = json.dumps(src) if isinstance(src, list) else None
    raw = record.get("raw")
    raw_json = json.dumps(raw) if isinstance(raw, dict) else None
    try:
        with connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cve_exploit_availability
                    (cve_id, has_public_poc, poc_count, poc_top_url,
                     has_msf_module, msf_module_name, has_exploit_db,
                     exploit_db_id, sources_json, last_seen, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    has_public_poc  = excluded.has_public_poc,
                    poc_count       = excluded.poc_count,
                    poc_top_url     = COALESCE(excluded.poc_top_url,
                                               cve_exploit_availability.poc_top_url),
                    has_msf_module  = excluded.has_msf_module,
                    msf_module_name = COALESCE(excluded.msf_module_name,
                                               cve_exploit_availability.msf_module_name),
                    has_exploit_db  = excluded.has_exploit_db,
                    exploit_db_id   = COALESCE(excluded.exploit_db_id,
                                               cve_exploit_availability.exploit_db_id),
                    sources_json    = COALESCE(excluded.sources_json,
                                               cve_exploit_availability.sources_json),
                    last_seen       = COALESCE(excluded.last_seen,
                                               cve_exploit_availability.last_seen),
                    raw_json        = COALESCE(excluded.raw_json,
                                               cve_exploit_availability.raw_json)
                """,
                (
                    cve_id.strip().upper(),
                    1 if record.get("has_public_poc") else 0,
                    int(record.get("poc_count") or 0),
                    record.get("poc_top_url"),
                    1 if record.get("has_msf_module") else 0,
                    record.get("msf_module_name"),
                    1 if record.get("has_exploit_db") else 0,
                    record.get("exploit_db_id"),
                    src_json,
                    record.get("last_seen"),
                    raw_json,
                ),
            )
            return True
    except Exception as e:  # noqa: BLE001
        logger.warning("upsert_exploit_availability failed: %s", e, exc_info=True)
        return False


def fetch_exploit_availability(cve_id: str) -> dict[str, Any] | None:
    """Return the exploit-availability row for a CVE, or None when
    no entry exists in the cache. iter-22.7.
    """
    if not isinstance(cve_id, str) or not cve_id.strip():
        return None
    try:
        with connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM cve_exploit_availability WHERE cve_id=?",
                (cve_id.strip().upper(),),
            )
            row = cur.fetchone()
            if row is None:
                return None
            d = dict(row)
            srcs = d.pop("sources_json", None)
            raw = d.pop("raw_json", None)
            try:
                d["sources"] = json.loads(srcs) if srcs else []
            except (ValueError, TypeError):
                d["sources"] = []
            try:
                d["raw"] = json.loads(raw) if raw else {}
            except (ValueError, TypeError):
                d["raw"] = {}
            # Coerce SQLite bool columns to Python bool
            for k in ("has_public_poc", "has_msf_module", "has_exploit_db"):
                d[k] = bool(d.get(k))
            return d
    except Exception as e:  # noqa: BLE001
        logger.debug("fetch_exploit_availability(%s) failed: %s", cve_id, e)
        return None


def fetch_campaigns_for_cve(
    cve_id: str, *, limit: int = 25,
) -> list[dict[str, Any]]:
    """Return campaigns linked to a CVE, ordered by `last_seen`
    descending (most recently active first). Each entry is a dict
    with the full campaign row + parsed `references` / `tags`.
    Returns [] on cache error or missing CVE.
    """
    if not isinstance(cve_id, str) or not cve_id.strip():
        return []
    try:
        with connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT c.*
                FROM campaigns c
                JOIN campaign_cve_links l
                  ON l.campaign_id = c.campaign_id
                WHERE l.cve_id = ?
                ORDER BY COALESCE(c.last_seen, c.first_seen) DESC
                LIMIT ?
                """,
                (cve_id.strip(), max(1, min(limit, 100))),
            )
            out: list[dict[str, Any]] = []
            for row in cur.fetchall():
                d = dict(row)
                refs = d.pop("references_json", None)
                tags = d.pop("tags_json", None)
                try:
                    d["references"] = json.loads(refs) if refs else []
                except (ValueError, TypeError):
                    d["references"] = []
                try:
                    d["tags"] = json.loads(tags) if tags else []
                except (ValueError, TypeError):
                    d["tags"] = []
                out.append(d)
            return out
    except Exception as e:  # noqa: BLE001
        logger.debug("fetch_campaigns_for_cve(%s) failed: %s", cve_id, e)
        return []
