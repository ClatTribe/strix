"""Threat-intelligence feed ingestion (MISP / STIX 2.x / TAXII 2.1).

Roadmap §10 threat-intelligence enrichment (last open item).
For enterprise deployments that already curate threat-intel feeds,
fetch a feed URL and surface the IoCs as additional context for the
agent. Auto-detects whether the feed is MISP, raw STIX 2.x bundle,
or a TAXII 2.1 collection. When `target_filter` is supplied, emits
info findings for IoCs that match the in-scope targets.
"""

from .threat_feed_ingest import threat_feed_ingest


__all__ = ["threat_feed_ingest"]
