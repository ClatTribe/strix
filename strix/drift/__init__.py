"""IaC ↔ CSPM drift correlation.

IaC scans (`strix.iac`) report the *intent* declared in Terraform /
K8s manifests. CSPM scans (`strix.cspm`) report the *actual* state
of a live cloud account. Drift correlation cross-references the
two:

  * **iac_root_cause** — both scans flag the same rule class on the
    same resource. Fix the IaC and re-apply; the live finding will
    clear.

  * **drift** — CSPM flags a finding the IaC scan didn't. Someone
    changed the resource in the console / outside Terraform, OR the
    resource was created outside IaC entirely. Either re-apply
    Terraform to overwrite, or import the resource into state and
    fix in IaC.

  * **iac_unfollowed** — IaC flags a finding CSPM doesn't see live.
    The IaC declares a bad config but it hasn't been applied (yet),
    or the live resource was hand-fixed without updating IaC.
    Next deploy reintroduces the issue — fix the IaC.

  * **uncorrelated_cspm** — CSPM finding for a rule class strix has
    no IaC analog for (e.g. root account MFA, password policy).
    Live-only attestation, no drift comparison possible.

Why ship this: it's the single answer to "is my Terraform
authoritative?". Auditors need it; developers need it before they
fix the wrong layer.
"""

from __future__ import annotations

from strix.drift.correlator import (
    DRIFT_CLASSIFICATION_IAC_ROOT_CAUSE,
    DRIFT_CLASSIFICATION_DRIFT,
    DRIFT_CLASSIFICATION_IAC_UNFOLLOWED,
    DriftFinding,
    DriftReport,
    RULE_CLASS_MAP,
    correlate,
)


# Side-effect import — register specialist tool.
from strix.drift import tools as _tools  # noqa: E402, F401
