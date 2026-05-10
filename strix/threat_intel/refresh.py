"""CLI for periodic threat-intel feed refresh.

Usage:
    python -m strix.threat_intel.refresh           # poll all feeds
    python -m strix.threat_intel.refresh --only kev,epss
    python -m strix.threat_intel.refresh --nvd-days 30
    python -m strix.threat_intel.refresh --status   # print cache status

Designed to run as a cron / GitHub Actions / sidecar daemon. The
KEV catalog updates ~weekly, EPSS daily, NVD continuously — so a
daily run keeps the cache same-day fresh.

Exit codes:
  0 — all requested feeds succeeded
  1 — at least one feed failed (see stderr)
  2 — bad arguments
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from strix.threat_intel.feeds.epss import poll_epss
from strix.threat_intel.feeds.kev import poll_kev
from strix.threat_intel.feeds.nvd import poll_nvd_recent
from strix.threat_intel.lookup import cache_status


_FEEDS = {
    "kev": "CISA Known Exploited Vulnerabilities",
    "epss": "FIRST.org EPSS scores",
    "nvd": "NIST NVD CVE 2.0 (recent window)",
}


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        level=logging.DEBUG if verbose else logging.INFO,
    )


def _print_status() -> None:
    s = cache_status()
    print(f"Cache: {s['cache_path']}")
    print(f"Totals: cves={s['totals']['cves']:,} "
          f"kev={s['totals']['kev']:,} with_epss={s['totals']['with_epss']:,}")
    print()
    print(f"{'feed':<12} {'status':<8} {'records':<10} last_polled")
    print("-" * 70)
    for f in s["feeds"]:
        print(f"{f.get('feed_name', '?'):<12} "
              f"{f.get('status', '?'):<8} "
              f"{f.get('record_count', 0):<10} "
              f"{f.get('last_polled', '?')}")
        if f.get("error"):
            print(f"  error: {f['error'][:200]}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="strix.threat_intel.refresh",
        description=(
            "Refresh the threat-intel cache from public feeds "
            "(CISA KEV / FIRST EPSS / NVD)."
        ),
    )
    parser.add_argument(
        "--only",
        help=(
            "Comma-separated feed names to refresh "
            "(default: all). Available: " + ", ".join(_FEEDS.keys())
        ),
    )
    parser.add_argument(
        "--nvd-days",
        type=int, default=14,
        help="NVD recent-window size in days (1-120, default 14).",
    )
    parser.add_argument(
        "--epss-all",
        action="store_true",
        help=(
            "Persist EPSS for every CVE (~250K rows / ~30MB). "
            "Default behaviour persists only for CVEs already in "
            "the cache."
        ),
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print cache status and exit.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
    )
    args = parser.parse_args(argv)

    _setup_logging(args.verbose)

    if args.status:
        _print_status()
        return 0

    requested = (
        [s.strip() for s in args.only.split(",") if s.strip()]
        if args.only else list(_FEEDS.keys())
    )
    invalid = [f for f in requested if f not in _FEEDS]
    if invalid:
        print(f"error: unknown feed(s): {invalid}. "
              f"Available: {list(_FEEDS.keys())}", file=sys.stderr)
        return 2

    overall_ok = True
    results: dict[str, dict] = {}

    if "kev" in requested:
        print("[refresh] polling KEV ...")
        r = poll_kev()
        results["kev"] = r
        print(f"  KEV: status={r['status']} ingested={r.get('ingested')} "
              f"catalog_version={r.get('catalog_version')}")
        if r["status"] != "ok":
            overall_ok = False
            print(f"  error: {r.get('error')}", file=sys.stderr)

    if "nvd" in requested:
        print(f"[refresh] polling NVD (last {args.nvd_days} days) ...")
        r = poll_nvd_recent(days=args.nvd_days)
        results["nvd"] = r
        print(f"  NVD: status={r['status']} ingested={r.get('ingested')} "
              f"pages={r.get('pages')}")
        if r["status"] != "ok":
            overall_ok = False
            print(f"  error: {r.get('error')}", file=sys.stderr)

    if "epss" in requested:
        print("[refresh] polling EPSS ...")
        r = poll_epss(only_cached=not args.epss_all)
        results["epss"] = r
        print(f"  EPSS: status={r['status']} ingested={r.get('ingested')} "
              f"skipped={r.get('skipped')}")
        if r["status"] != "ok":
            overall_ok = False
            print(f"  error: {r.get('error')}", file=sys.stderr)

    print()
    print("=== summary ===")
    print(json.dumps({"overall_ok": overall_ok, "feeds": results},
                     indent=2, default=str))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
