"""Cross-target correlation engine.

Roadmap §17.1. Reads existing scan artifacts (current run's findings,
surface_map.json, threat-intel caches, customer threat-feed output)
and emits `cross_target.correlation` findings for the standard
multi-target join patterns the strategic overview claims as the
AI-native edge:

- domain × ip-reputation
- kev × customer-stack
- cve × customer-threat-feed
- threat-feed × scan-detected-IoC

Each correlation references TWO target surfaces and is auto-deduped
per (class, target_a, target_b) tuple.
"""

from .cross_target_correlate import cross_target_correlate


__all__ = ["cross_target_correlate"]
