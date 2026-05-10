"""FIRST.org Exploit Prediction Scoring System (EPSS).

Source: https://www.first.org/epss/
Daily CSV: https://epss.cyentia.com/epss_scores-current.csv.gz

Each row is `(cve, epss, percentile)`. EPSS is the probability that
a CVE will be exploited in the next 30 days; a value of 0.97 means
"high confidence this gets weaponized soon."

The full file is ~5MB compressed (~30MB uncompressed); ~250K rows.

For our use case we don't need ALL CVEs — only the ones we've
already ingested via NVD or KEV. So this poller filters EPSS to
the subset of CVEs already in the cache.

Best-effort throughout; HTTP / parse failures swallowed.
"""

from __future__ import annotations

import csv
import gzip
import io
import logging
import re
from typing import Any

from strix.threat_intel import cache as ti_cache


logger = logging.getLogger(__name__)


EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _http_get(url: str, *, timeout: float = 60.0) -> bytes:
    import urllib.request
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "strix-threat-intel/1.0 (+https://github.com/usestrix/strix)",
            "Accept": "application/gzip, application/octet-stream",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _decompress(raw: bytes) -> bytes:
    """Handle either gzipped or plain CSV."""
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    return raw


def _parse_epss_csv(raw: bytes) -> list[tuple[str, float]]:
    """Parse the EPSS CSV header + rows. The first non-comment line
    is the column header `cve,epss,percentile`."""
    text = _decompress(raw).decode("utf-8", errors="replace")
    out: list[tuple[str, float]] = []
    reader = csv.reader(io.StringIO(text))
    header_seen = False
    for row in reader:
        if not row:
            continue
        # Skip metadata comment lines like `#model_version:v2024.04.16,score_date:...`
        if row[0].startswith("#"):
            continue
        if not header_seen:
            header_seen = True
            # Validate header roughly.
            if "cve" not in row[0].lower():
                # Treat first row as data; some daily snapshots
                # don't include a header.
                pass
            else:
                continue
        if len(row) < 2:
            continue
        cve_id = (row[0] or "").strip().upper()
        # CVE-YYYY-N+ shape; reject malformed (e.g. "CVE-X").
        if not _CVE_ID_RE.match(cve_id):
            continue
        try:
            score = float(row[1])
        except (TypeError, ValueError):
            continue
        out.append((cve_id, score))
    return out


def poll_epss(
    *,
    url: str = EPSS_URL,
    fetch: callable | None = None,
    only_cached: bool = True,
) -> dict[str, Any]:
    """Fetch + persist EPSS scores.

    Args:
        url: override the daily CSV URL.
        fetch: optional callable `(url) -> bytes` for testing.
        only_cached: when True (default), only persists EPSS for
            CVEs already in the cache. Otherwise stores all 250K
            rows (the cache grows by ~30MB).

    Returns:
        {"status": ..., "ingested": N, "skipped": N, "error": ...}
    """
    fetch = fetch or _http_get
    try:
        raw = fetch(url)
    except Exception as e:  # noqa: BLE001
        msg = f"EPSS fetch failed: {type(e).__name__}: {e}"
        logger.warning(msg)
        ti_cache.record_feed_status("epss", status="error", error=msg)
        return {"status": "error", "ingested": 0, "skipped": 0, "error": msg}

    try:
        rows = _parse_epss_csv(raw)
    except Exception as e:  # noqa: BLE001
        msg = f"EPSS parse failed: {type(e).__name__}: {e}"
        logger.warning(msg)
        ti_cache.record_feed_status("epss", status="error", error=msg)
        return {"status": "error", "ingested": 0, "skipped": 0, "error": msg}

    if only_cached:
        # Filter to CVEs already in the cache.
        with ti_cache.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT cve_id FROM cves")
            known = {r["cve_id"] for r in cur.fetchall()}
        filtered = [(c, s) for (c, s) in rows if c in known]
        skipped = len(rows) - len(filtered)
    else:
        filtered = rows
        skipped = 0

    try:
        n = ti_cache.upsert_epss_scores(filtered)
    except Exception as e:  # noqa: BLE001
        msg = f"EPSS upsert failed: {type(e).__name__}: {e}"
        ti_cache.record_feed_status("epss", status="error", error=msg)
        return {"status": "error", "ingested": 0, "skipped": skipped,
                "error": msg}

    ti_cache.record_feed_status("epss", status="ok", record_count=n)
    return {"status": "ok", "ingested": n, "skipped": skipped, "error": None}
