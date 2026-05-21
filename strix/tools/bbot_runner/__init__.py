"""iter-21.6.1 — `bbot` (BlackLanternSecurity ASM tool) wrapper.

Currently wraps bbot's BUCKET-DISCOVERY modules. The bucket
sub-iter replaces the in-house `scan_public_bucket_exposure`
from PR #400 (reverted via PR #401) — strix already wraps OSS
scanners (trivy, semgrep, gitleaks, nuclei, checkov, osv-scanner)
rather than reimplementing them, and bbot's bucket modules ship
broader cloud coverage (AWS / GCP / Azure / DigitalOcean /
Firebase / IBM COS) + DNS / CT-log chaining than anything we'd
reasonably hand-roll.

Future expansion: bbot's broader ASM modules (subdomain enum,
port scan, fingerprinting, cloud-asset discovery, vulnerability
modules) are out of scope for this PR but the runner module is
the natural home for them.
"""

from __future__ import annotations

from strix.tools.bbot_runner.scan_buckets_via_bbot import (  # noqa: F401
    scan_buckets_via_bbot,
)


__all__ = ["scan_buckets_via_bbot"]
