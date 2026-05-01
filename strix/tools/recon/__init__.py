"""Deterministic recon tools for domain / network targets.

These tools wrap well-known sandbox utilities (`dig`, `whois`, HTTP HEAD
probes) and emit structured findings via the tracer's `add_vulnerability_report`
API. The agent invokes them during the recon phase; outputs are deterministic
and complementary to the agent's LLM-driven reasoning.

Each tool follows the same contract:
- runs to completion (no streaming, no long-poll)
- emits findings as a side effect when something is detected
- returns a structured dict the agent can read for further reasoning
- never raises — all failures are reported in the return value
"""

from .cloud_assets import discover_cloud_assets
from .dns_hygiene import dns_hygiene_check
from .takeover import subdomain_takeover_check


__all__ = [
    "discover_cloud_assets",
    "dns_hygiene_check",
    "subdomain_takeover_check",
]
