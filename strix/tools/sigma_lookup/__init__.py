"""MITRE ATT&CK → Sigma detection rule mapping.

Roadmap §10 expert-pentester gap audit (🟡 important). Closes the
loop on the #66 ATT&CK tagging by surfacing Sigma rules from the
SigmaHQ corpus that detect a given technique. Display-only — does
NOT emit findings; the agent integrates the rule list into existing
findings via the report's `references` field or the wrapper's
display layer.
"""

from .sigma_lookup import sigma_rules_for_technique


__all__ = ["sigma_rules_for_technique"]
