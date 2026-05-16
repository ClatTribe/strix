"""Unit tests for `strix.compliance.frameworks`."""

from __future__ import annotations

import pytest

from strix.compliance.frameworks import (
    ALL_FRAMEWORKS,
    Control,
    FRAMEWORK_HIPAA,
    FRAMEWORK_ISO27001,
    FRAMEWORK_OWASP_ASVS,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
    all_controls,
    get_control,
    get_framework_controls,
)


# ---------------------------------------------------------------------------
# Catalog completeness
# ---------------------------------------------------------------------------


def test_all_frameworks_registered() -> None:
    assert FRAMEWORK_SOC2 in ALL_FRAMEWORKS
    assert FRAMEWORK_ISO27001 in ALL_FRAMEWORKS
    assert FRAMEWORK_PCI_DSS in ALL_FRAMEWORKS
    assert FRAMEWORK_OWASP_ASVS in ALL_FRAMEWORKS
    assert FRAMEWORK_HIPAA in ALL_FRAMEWORKS
    assert len(ALL_FRAMEWORKS) == 5


def test_hipaa_has_technical_safeguards() -> None:
    """§164.312 (Technical Safeguards) is the HIPAA subsection
    most AppSec findings map to. Must include access control,
    transmission security, integrity, person auth."""
    hipaa = {c.id for c in get_framework_controls(FRAMEWORK_HIPAA)}
    assert "164.312(a)(1)" in hipaa       # access control
    assert "164.312(c)(1)" in hipaa       # integrity
    assert "164.312(d)" in hipaa          # person/entity auth
    assert "164.312(e)(1)" in hipaa       # transmission security


def test_hipaa_has_administrative_safeguards() -> None:
    """§164.308 — risk analysis + access auth + login monitoring
    + password management are the AppSec-touchable subset."""
    hipaa = {c.id for c in get_framework_controls(FRAMEWORK_HIPAA)}
    assert "164.308(a)(5)(ii)(B)" in hipaa  # malicious software
    assert "164.308(a)(5)(ii)(D)" in hipaa  # password management
    assert "164.308(a)(4)(ii)(B)" in hipaa  # access authorization


def test_each_framework_has_controls() -> None:
    """Anti-rot — every framework catalog should be non-empty."""
    for fw in ALL_FRAMEWORKS:
        controls = get_framework_controls(fw)
        assert len(controls) >= 5, fw


def test_soc2_has_cc6_controls() -> None:
    """CC6 (logical access) is the SOC 2 trust criteria most
    AppSec findings map to. Must include CC6.1 + CC6.6 +
    CC6.7."""
    soc2 = {c.id for c in get_framework_controls(FRAMEWORK_SOC2)}
    assert "CC6.1" in soc2
    assert "CC6.6" in soc2
    assert "CC6.7" in soc2


def test_iso27001_has_application_security_controls() -> None:
    iso = {c.id for c in get_framework_controls(FRAMEWORK_ISO27001)}
    assert "A.8.26" in iso  # application security requirements
    assert "A.8.28" in iso  # secure coding


def test_pci_dss_has_req6_injection_controls() -> None:
    pci = {c.id for c in get_framework_controls(FRAMEWORK_PCI_DSS)}
    assert "6.5.1" in pci  # injection
    assert "6.5.7" in pci  # XSS
    assert "6.3.2" in pci  # third-party inventory


def test_asvs_has_input_validation_chapter() -> None:
    asvs = {c.id for c in get_framework_controls(FRAMEWORK_OWASP_ASVS)}
    assert "V5.3.3" in asvs  # XSS output encoding
    assert "V5.3.4" in asvs  # parameterised queries
    assert "V5.3.8" in asvs  # OS command injection prevention


# ---------------------------------------------------------------------------
# Control lookup
# ---------------------------------------------------------------------------


def test_get_control_returns_full_metadata() -> None:
    c = get_control(FRAMEWORK_SOC2, "CC6.1")
    assert c is not None
    assert c.framework == FRAMEWORK_SOC2
    assert c.id == "CC6.1"
    assert c.title  # non-empty
    assert c.description  # non-empty


def test_get_control_unknown_returns_none() -> None:
    assert get_control(FRAMEWORK_SOC2, "CC99.99") is None
    assert get_control("not-a-framework", "CC6.1") is None


def test_control_fqid_format() -> None:
    c = get_control(FRAMEWORK_OWASP_ASVS, "V5.3.4")
    assert c is not None
    assert c.fqid == "owasp_asvs:V5.3.4"


def test_control_dataclass_is_frozen() -> None:
    """Controls should be immutable — they're shared static
    catalog data, not per-finding state."""
    c = get_control(FRAMEWORK_SOC2, "CC6.1")
    with pytest.raises((AttributeError, Exception)):
        c.title = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# all_controls
# ---------------------------------------------------------------------------


def test_all_controls_returns_union_across_frameworks() -> None:
    out = all_controls()
    fws = {c.framework for c in out}
    assert fws == set(ALL_FRAMEWORKS)


def test_all_controls_with_subset_filter() -> None:
    out = all_controls(frameworks=[FRAMEWORK_SOC2])
    assert all(c.framework == FRAMEWORK_SOC2 for c in out)
    assert len(out) >= 5
