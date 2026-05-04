"""Privacy-policy / cookie-policy / DPA presence detection (roadmap §16).

Per `web_application` target, probe canonical legal-document paths
and emit a `legal_documents` finding per surface — informational
when present, low when absent on a customer-facing app.

GDPR Art. 13/14, CCPA, India DPDP all require these published.
Easy deterministic check; high-value compliance signal.
"""

from .legal_compliance_probe import legal_compliance_probe


__all__ = ["legal_compliance_probe"]
