"""Tests for CIS Benchmark mappings — audit item §10.

CIS Controls v8 alone was <2% framework coverage. This adds:

  * CIS Docker Benchmark v1.6.0 catalog
  * CIS Kubernetes Benchmark v1.8.0 catalog
  * CIS AWS Foundations Benchmark v3.0 catalog
  * Rule-ID → control mappings for the IaC + container_image
    rule corpus, plus container scan category mappings
    (image_signing, secrets, sca, misconfiguration).
"""

from __future__ import annotations

import pytest

from strix.compliance.frameworks import (
    ALL_FRAMEWORKS,
    FRAMEWORK_CIS_AWS,
    FRAMEWORK_CIS_DOCKER,
    FRAMEWORK_CIS_KUBERNETES,
    Control,
    get_control,
    get_framework_controls,
)
from strix.compliance.mappings import (
    RULE_ID_TO_CONTROLS,
    controls_for,
    controls_for_by_framework,
    covered_controls,
    rules_for_control,
)


# ---------------------------------------------------------------------------
# Framework registration
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("framework", [
    FRAMEWORK_CIS_DOCKER,
    FRAMEWORK_CIS_KUBERNETES,
    FRAMEWORK_CIS_AWS,
])
def test_cis_benchmark_framework_registered(framework: str) -> None:
    assert framework in ALL_FRAMEWORKS, (
        f"{framework} not in ALL_FRAMEWORKS — wrapper "
        f"compliance dashboards would skip it"
    )


@pytest.mark.parametrize("framework,min_controls", [
    (FRAMEWORK_CIS_DOCKER, 8),
    (FRAMEWORK_CIS_KUBERNETES, 9),
    (FRAMEWORK_CIS_AWS, 6),
])
def test_cis_benchmark_catalog_has_controls(
    framework: str, min_controls: int,
) -> None:
    """Each CIS Benchmark catalog ships with at least the
    rule-corpus-testable subset. If a future edit drops below
    this floor, the wrapper renders an empty framework — same
    UX problem as not registering it at all."""
    controls = get_framework_controls(framework)
    assert len(controls) >= min_controls, (
        f"{framework} only has {len(controls)} controls "
        f"(expected >= {min_controls})"
    )


def test_every_cis_control_has_title_and_description() -> None:
    """Auditor renderings need title + description. An empty
    description makes the control unintelligible without going
    back to the official PDF."""
    for fw in (FRAMEWORK_CIS_DOCKER, FRAMEWORK_CIS_KUBERNETES,
               FRAMEWORK_CIS_AWS):
        for ctrl in get_framework_controls(fw):
            assert ctrl.title.strip(), (
                f"{fw}:{ctrl.id} has no title"
            )
            assert ctrl.description.strip(), (
                f"{fw}:{ctrl.id} has no description"
            )


# ---------------------------------------------------------------------------
# Rule_id mapping anti-rot
# ---------------------------------------------------------------------------


def test_every_rule_mapped_control_exists() -> None:
    """If a rule maps to (`cis_kubernetes`, `5.2.99`) and that
    control isn't in the K8S catalog, the wrapper renders a broken
    reference. Same anti-rot guard the CWE map already has."""
    for rule_id, controls in RULE_ID_TO_CONTROLS.items():
        for fw, cid in controls:
            assert get_control(fw, cid) is not None, (
                f"rule {rule_id} maps to ({fw}, {cid}) but that "
                f"control isn't in the {fw} catalog"
            )


def test_every_rule_mapping_uses_known_framework() -> None:
    for rule_id, controls in RULE_ID_TO_CONTROLS.items():
        for fw, _cid in controls:
            assert fw in ALL_FRAMEWORKS, (
                f"rule {rule_id} maps to unknown framework `{fw}`"
            )


# ---------------------------------------------------------------------------
# Specific rule → control assertions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_id,framework,control_id", [
    # CIS AWS Foundations
    ("TF_AWS_S3_PUBLIC_ACL", FRAMEWORK_CIS_AWS, "2.1.5"),
    ("TF_AWS_S3_NO_VERSIONING", FRAMEWORK_CIS_AWS, "2.1.7"),
    ("TF_AWS_EBS_NO_ENCRYPTION", FRAMEWORK_CIS_AWS, "2.2.1"),
    ("TF_AWS_RDS_NO_ENCRYPTION", FRAMEWORK_CIS_AWS, "2.3.1"),
    ("TF_AWS_IAM_WILDCARD_POLICY", FRAMEWORK_CIS_AWS, "1.16"),
    ("TF_AWS_SG_OPEN_INGRESS", FRAMEWORK_CIS_AWS, "5.2"),
    # CIS Kubernetes
    ("K8S_PRIVILEGED_CONTAINER", FRAMEWORK_CIS_KUBERNETES, "5.2.1"),
    ("K8S_RUN_AS_ROOT", FRAMEWORK_CIS_KUBERNETES, "5.2.6"),
    ("K8S_ALLOW_PRIV_ESC", FRAMEWORK_CIS_KUBERNETES, "5.2.5"),
    ("K8S_RBAC_WILDCARD", FRAMEWORK_CIS_KUBERNETES, "5.1.3"),
    ("K8S_SERVICE_NODEPORT", FRAMEWORK_CIS_KUBERNETES, "5.4.2"),
    # K8S_HOST_NAMESPACE_SHARING — one rule fans out to 5.2.2/3/4
    ("K8S_HOST_NAMESPACE_SHARING", FRAMEWORK_CIS_KUBERNETES, "5.2.2"),
    ("K8S_HOST_NAMESPACE_SHARING", FRAMEWORK_CIS_KUBERNETES, "5.2.3"),
    ("K8S_HOST_NAMESPACE_SHARING", FRAMEWORK_CIS_KUBERNETES, "5.2.4"),
    # CIS Docker
    ("dockerfile-user-root", FRAMEWORK_CIS_DOCKER, "4.1"),
    ("dockerfile-no-user-directive", FRAMEWORK_CIS_DOCKER, "4.1"),
    ("dockerfile-latest-tag", FRAMEWORK_CIS_DOCKER, "4.4"),
    ("dockerfile-add-from-url", FRAMEWORK_CIS_DOCKER, "4.9"),
    ("dockerfile-env-hardcoded-secret", FRAMEWORK_CIS_DOCKER, "4.10"),
    ("compose-privileged-container", FRAMEWORK_CIS_DOCKER, "5.4"),
    ("compose-host-network-mode", FRAMEWORK_CIS_DOCKER, "5.9"),
    ("compose-docker-socket-mount", FRAMEWORK_CIS_DOCKER, "5.31"),
])
def test_rule_id_maps_to_expected_cis_control(
    rule_id: str, framework: str, control_id: str,
) -> None:
    """Rule → CIS control mappings the auditor will be reading.
    Parametrized so every rule's evidence pointer is pinned —
    a rename or accidental delete fails loudly."""
    assert (framework, control_id) in RULE_ID_TO_CONTROLS[rule_id], (
        f"{rule_id} no longer maps to {framework}:{control_id}"
    )


# ---------------------------------------------------------------------------
# controls_for(rule_id=...) resolution
# ---------------------------------------------------------------------------


def test_controls_for_rule_id_only() -> None:
    """A pure rule_id lookup returns just the CIS rows — no CWE
    contamination."""
    out = controls_for(rule_id="K8S_PRIVILEGED_CONTAINER")
    assert (FRAMEWORK_CIS_KUBERNETES, "5.2.1") in out
    assert (FRAMEWORK_CIS_DOCKER, "5.4") in out
    # No SOC2/PCI controls from this rule alone — CIS-only.
    frameworks = {fw for fw, _ in out}
    assert frameworks == {FRAMEWORK_CIS_KUBERNETES, FRAMEWORK_CIS_DOCKER}


def test_controls_for_unions_cwe_category_and_rule_id() -> None:
    """All three signals should union — an IaC finding typically
    has all three set."""
    out = controls_for(
        cwe="CWE-732",            # incorrect permission assignment
        category="misconfig",
        rule_id="K8S_PRIVILEGED_CONTAINER",
    )
    # From rule_id.
    assert (FRAMEWORK_CIS_KUBERNETES, "5.2.1") in out
    # From CWE.
    assert ("soc2", "CC6.1") in out
    # From category.
    assert ("nist_800_53", "CM-6") in out


def test_controls_for_unknown_rule_id_returns_empty_for_rule_only() -> None:
    """An unknown rule_id contributes nothing — caller's other
    signals (cwe/category) still resolve normally."""
    out = controls_for(rule_id="MADE_UP_RULE_999")
    assert out == []


def test_controls_for_rule_id_trims_whitespace() -> None:
    a = controls_for(rule_id="K8S_PRIVILEGED_CONTAINER")
    b = controls_for(rule_id="  K8S_PRIVILEGED_CONTAINER  ")
    assert a == b


def test_controls_for_by_framework_groups_rule_id_results() -> None:
    """`controls_for_by_framework` returns
    `{framework: [control_ids]}` — IaC findings render this on
    the wrapper as a per-framework panel."""
    out = controls_for_by_framework(
        rule_id="K8S_HOST_NAMESPACE_SHARING",
    )
    assert FRAMEWORK_CIS_KUBERNETES in out
    assert "5.2.2" in out[FRAMEWORK_CIS_KUBERNETES]
    assert "5.2.3" in out[FRAMEWORK_CIS_KUBERNETES]
    assert "5.2.4" in out[FRAMEWORK_CIS_KUBERNETES]
    # Sorted alphabetically.
    assert out[FRAMEWORK_CIS_KUBERNETES] == sorted(
        out[FRAMEWORK_CIS_KUBERNETES]
    )


# ---------------------------------------------------------------------------
# Container category mappings (image_signing, secrets, sca,
# misconfiguration)
# ---------------------------------------------------------------------------


def test_image_signing_category_maps_to_cis_docker_4_5() -> None:
    """cosign / signature-verification findings supply evidence
    for CIS Docker 4.5 (Content trust)."""
    out = controls_for(category="image_signing")
    assert (FRAMEWORK_CIS_DOCKER, "4.5") in out


def test_secrets_category_maps_to_cis_docker_4_10() -> None:
    """Secrets-in-image finding → CIS Docker 4.10 (no secrets in
    Dockerfiles)."""
    out = controls_for(category="secrets")
    assert (FRAMEWORK_CIS_DOCKER, "4.10") in out


def test_sca_category_maps_to_cis_v8_16_11() -> None:
    """Container CVE scan → CIS Controls 16.11 (vetted modules /
    services)."""
    out = controls_for(category="sca")
    assert ("cis", "16.11") in out


# ---------------------------------------------------------------------------
# Coverage / inverse lookup
# ---------------------------------------------------------------------------


def test_covered_controls_includes_cis_benchmark_rows() -> None:
    """Adding rule_id-driven mappings should bump covered_controls."""
    covered = covered_controls()
    assert (FRAMEWORK_CIS_KUBERNETES, "5.2.1") in covered
    assert (FRAMEWORK_CIS_AWS, "2.1.5") in covered
    assert (FRAMEWORK_CIS_DOCKER, "4.10") in covered


def test_rules_for_control_includes_rule_prefix() -> None:
    """`rules_for_control` returns rule-keys prefixed with `rule:`
    to distinguish them from CWE/category keys in the auditor's
    evidence-source list."""
    rules = rules_for_control(FRAMEWORK_CIS_KUBERNETES, "5.2.1")
    # K8S_PRIVILEGED_CONTAINER + compose-privileged-container both
    # map to K8S 5.2.1 (compose maps as cross-coverage).
    assert "rule:K8S_PRIVILEGED_CONTAINER" in rules
    assert "rule:compose-privileged-container" in rules


def test_rules_for_control_aws_iam_wildcard() -> None:
    rules = rules_for_control(FRAMEWORK_CIS_AWS, "1.16")
    assert "rule:TF_AWS_IAM_WILDCARD_POLICY" in rules


# ---------------------------------------------------------------------------
# Cross-asset coverage: container categories rendered alongside CWE
# ---------------------------------------------------------------------------


def test_image_signing_category_also_carries_supply_chain_controls() -> None:
    """image_signing should map to A08:2021 + NIST SI-7 +
    ISO A.5.21 in addition to CIS Docker 4.5 — supply-chain
    integrity is multi-framework."""
    out = controls_for(category="image_signing")
    frameworks = {fw for fw, _ in out}
    assert "owasp_top10" in frameworks
    assert "nist_800_53" in frameworks
    assert "iso27001" in frameworks
    assert FRAMEWORK_CIS_DOCKER in frameworks
