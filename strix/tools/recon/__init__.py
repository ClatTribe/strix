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
from .code_search import code_search_for_domain
from .dns_hygiene import dns_hygiene_check
from .domain_pipeline import domain_recon_pipeline
from .fingerprint import fingerprint_tech_stack
from .org_recon import org_fingerprint
from .passive_dns import passive_dns_history
from .phase import record_phase
from .reverse_ip import reverse_ip_discovery
from .subdomain_enum_tool import subdomain_enum
from .takeover import subdomain_takeover_check


__all__ = [
    "code_search_for_domain",
    "discover_cloud_assets",
    "dns_hygiene_check",
    "domain_recon_pipeline",
    "fingerprint_tech_stack",
    "org_fingerprint",
    "passive_dns_history",
    "record_phase",
    "reverse_ip_discovery",
    "subdomain_enum",
    "subdomain_takeover_check",
]
