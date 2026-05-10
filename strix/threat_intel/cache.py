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
