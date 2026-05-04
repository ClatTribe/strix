"""HAR / Burp project traffic ingestion (roadmap §7.0 / §18 row 3).

First move on every real pen-test is "give me your Burp file."
Strix today has no way to consume a recorded request graph. This
module reads HAR (HTTP Archive 1.2) and Burp project export XML
files, builds a structured request inventory, and lets the
agent skip the BFS-crawl phase entirely when traffic was
pre-recorded.

Composes with:
- The webapp-recon-pipeline (#91) — ingestion pre-seeds the
  webapp_surface_map.
- Cluster-A safety — exclude-path / rate-limit still apply when
  the agent re-issues ingested requests.
"""

from .traffic_ingest import ingest_har_file, ingest_burp_file


__all__ = ["ingest_har_file", "ingest_burp_file"]
