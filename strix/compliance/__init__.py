"""Compliance evidence emission (roadmap §4b).

Engine-side. Maps emitted findings to compliance-control IDs
(SOC 2 / ISO 27001 / PCI DSS / OWASP ASVS) and produces a
machine-readable `compliance_evidence.json` artifact the
wrapper consumes for compliance dashboards / auditor handoff.

Strategic position (per §3.1):
  * Engine emits `compliance_evidence.json` (this module's
    output).
  * Wrapper renders SOC 2 trust portals, auditor PDFs,
    customer-attestation collection, risk-register management.
  * Engine does NOT generate auditor-facing prose, policy
    templates, or per-customer dashboards.

How findings get tagged:

  1. **Auto-derive from CWE** (most findings). `mappings.py`
     has CWE → list of (framework, control_id) tuples for every
     CWE strix's specialists emit. No per-rule retrofit needed.
  2. **Category fallback** (CWE-less findings). SCA emits
     `category="vulnerable_dependency"` without CWE; we map
     the category to `SOC 2 CC6.8` / `ISO A.5.21` / etc.
  3. **Explicit override**. A finding that wants to declare
     additional controls can include
     `metadata.compliance.{framework}: [...]` and it gets
     unioned with the auto-derived set.

Evidence pass/fail per control:
  * `fail`     — at least one high or critical finding
  * `warn`     — at least one low or medium finding
  * `info`     — info-severity only
  * `pass`     — control is covered by ≥ 1 rule in our
                 corpus AND no findings hit it
  * `untested` — control is in the framework catalog but no
                 rule in our corpus maps to it (a coverage gap
                 the wrapper should surface)

What v1 ships:
  * 4 framework catalogs: SOC 2, ISO 27001:2022, PCI DSS 4.0,
    OWASP ASVS 4.0
  * CWE → control map for ~35 CWEs strix's specialists already
    emit
  * Category → control map for SCA / IaC / SAST general categories
  * `emit_compliance_evidence` LLM specialist
  * `compliance_evidence.json` artifact alongside
    `vulnerabilities.json` + `finding_chains.json`

Out of scope for v1 (deferred to follow-up):
  * HIPAA Security Rule (164.308 / 164.312) — needs legal
    review of the mappings.
  * GDPR Art. 32 / EU AI Act — same.
  * CIS Benchmarks — infrastructure-specific; closer to IaC
    rules than control mappings.
  * PII / data-classification flow tagging — extends Phase 9
    anomaly detection, not core compliance work.
  * Compliance-bundle scan modes (`--compliance soc2` filtering
    the rule set) — useful but orthogonal to evidence emission.
"""

from strix.compliance.evidence import (  # noqa: F401
    ComplianceReport,
    ControlEvidence,
    build_evidence_report,
    write_compliance_evidence,
)
from strix.compliance.frameworks import (  # noqa: F401
    ALL_FRAMEWORKS,
    Control,
    get_control,
    get_framework_controls,
)
from strix.compliance.mappings import (  # noqa: F401
    CATEGORY_TO_CONTROLS,
    CWE_TO_CONTROLS,
    controls_for,
    untested_controls,
)
from strix.compliance.tools import emit_compliance_evidence  # noqa: F401
