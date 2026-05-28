#!/usr/bin/env python3
"""iter-Q5.34c — generate a flat scan-entry-points landing page for
the WAVSEP fixture.

WAVSEP's root `/wavsep/` page documents that "the index page of the
project intentionally lacks links and forms" — the category names are
bare `<b>` tags, NOT anchors. Crawlers (katana, nuclei templates,
sqlmap with `--crawl`) start there and dead-end immediately.

This script reads `expected-cases.csv` and emits a flat HTML page with
every test case URL as an `<a href>` link, served by the same Tomcat
via a docker-compose volume mount at
`/wavsep/scan-entry-points.html`. Pointing strix's `-t` at that page
gives every L1 scanner a one-hop view of the full corpus.

Run as part of the docker-compose `up` step (the harness owns the
invocation) or manually:

    python3 benchmarks/per_target/fixtures/web/wavsep/generate_entrypoints.py
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

_HERE = Path(__file__).parent
_CSV = _HERE / "expected-cases.csv"
_HTML_OUT = _HERE / "scan-entry-points.html"


def main() -> int:
    by_category: dict[str, list[str]] = defaultdict(list)
    with open(_CSV, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("url_path"):
                continue
            parts = next(csv.reader([line]))
            if len(parts) < 4:
                continue
            url_path = parts[0].strip()
            category = parts[1].strip()
            by_category[category].append(url_path)

    total = sum(len(v) for v in by_category.values())

    html: list[str] = []
    html.append("<!DOCTYPE html>")
    html.append("<html><head>")
    html.append("<meta charset='utf-8'>")
    html.append(
        "<title>WAVSEP — strix scan entry points "
        "(iter-Q5.34c)</title>"
    )
    html.append("</head><body>")
    html.append("<h1>strix WAVSEP entry points</h1>")
    html.append(
        f"<p>Generated landing page for the strix L1-DAST bench. "
        f"Lists {total} WAVSEP test case URLs as crawlable anchors "
        f"so katana / sqlmap-crawl / nuclei discover the full corpus. "
        f"The root <code>/wavsep/</code> intentionally lacks links — "
        f"this page works around that.</p>"
    )
    for category in sorted(by_category):
        paths = sorted(by_category[category])
        html.append(f"<h2>{category} ({len(paths)} cases)</h2>")
        html.append("<ul>")
        for p in paths:
            html.append(f'<li><a href="{p}">{p}</a></li>')
        html.append("</ul>")
    html.append("</body></html>")

    _HTML_OUT.write_text("\n".join(html), encoding="utf-8")
    print(f"wrote {_HTML_OUT}: {total} links across "
          f"{len(by_category)} categories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
