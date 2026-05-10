"""Unit tests for `strix.compliance.mappings`."""

from __future__ import annotations

import pytest

from strix.compliance.frameworks import (
    ALL_FRAMEWORKS,
    Control,
    FRAMEWORK_ISO27001,
    FRAMEWORK_OWASP_ASVS,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
    all_controls,
    get_control,
)
from strix.compliance.mappings import (
    CATEGORY_TO_CONTROLS,
    CWE_TO_CONTROLS,
    controls_for,
    covered_controls,
    untested_controls,
)


# ---------------------------------------------------------------------------
# Anti-rot — every mapping references a control that exists
# ---------------------------------------------------------------------------


def test_every_cwe_mapped_control_exists_in_catalog() -> None:
    """If we map CWE-89 to soc2:CC6.1 but CC6.1 isn't in the
    SOC 2 catalog, the wrapper renders a broken reference. This
    is an anti-rot guard for editing either side."""
    for cwe, controls in CWE_TO_CONTROLS.items():
        for fw, cid in controls:
            assert get_control(fw, cid) is not None, (
                f"{cwe} maps to ({fw}, {cid}) but that control "
                f"isn't in the {fw} catalog"
            )


def test_every_category_mapped_control_exists_in_catalog() -> None:
    for cat, controls in CATEGORY_TO_CONTROLS.items():
        for fw, cid in controls:
            assert get_control(fw, cid) is not None, (
                f"category `{cat}` maps to ({fw}, {cid}) but "
                f"that control isn't in the {fw} catalog"
            )


def test_every_mapping_uses_known_framework() -> None:
    """No typos in framework names."""
    for cwe, controls in CWE_TO_CONTROLS.items():
        for fw, _cid in controls:
            assert fw in ALL_FRAMEWORKS, (
                f"{cwe} maps to unknown framework `{fw}`"
            )


# ---------------------------------------------------------------------------
# CWE coverage breadth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cwe,expected_frameworks", [
    # SQLi must hit all 4 frameworks (it's the most-canonical
    # injection class).
    ("CWE-89", {"soc2", "iso27001", "pci_dss", "owasp_asvs"}),
    # XSS likewise.
    ("CWE-79", {"soc2", "iso27001", "pci_dss", "owasp_asvs"}),
    # Hardcoded credentials must hit all 4.
    ("CWE-798", {"soc2", "iso27001", "pci_dss", "owasp_asvs"}),
    # Path traversal — must hit all 4.
    ("CWE-22", {"soc2", "iso27001", "pci_dss", "owasp_asvs"}),
])
def test_canonical_cwes_hit_all_frameworks(
    cwe: str, expected_frameworks: set[str],
) -> None:
    """The most-common CWE classes should map to controls in
    every framework. If any drops out, customers using that
    framework get a coverage gap."""
    controls = CWE_TO_CONTROLS[cwe]
    actual = {fw for fw, _ in controls}
    assert expected_frameworks <= actual, (
        f"{cwe} missing frameworks: "
        f"{expected_frameworks - actual}"
    )


def test_strix_emitted_cwes_are_all_mapped() -> None:
    """Every CWE that appears in strix's emit paths should have
    a mapping. This is the key consistency test — a missing
    mapping means findings emit without compliance metadata."""
    # CWEs known to be emitted by strix's specialists.
    expected_cwes = {
        "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94",
        "CWE-200", "CWE-209", "CWE-269", "CWE-287", "CWE-295",
        "CWE-306", "CWE-326", "CWE-327", "CWE-338", "CWE-347",
        "CWE-352", "CWE-400", "CWE-434", "CWE-489", "CWE-502",
        "CWE-601", "CWE-611", "CWE-614", "CWE-732", "CWE-798",
        "CWE-862", "CWE-915", "CWE-916", "CWE-918", "CWE-922",
        "CWE-1004", "CWE-1321", "CWE-1336",
    }
    missing = expected_cwes - set(CWE_TO_CONTROLS.keys())
    assert not missing, (
        f"strix emits these CWEs but they have no compliance "
        f"mapping: {sorted(missing)}"
    )


# ---------------------------------------------------------------------------
# controls_for resolution
# ---------------------------------------------------------------------------


def test_controls_for_cwe_only() -> None:
    out = controls_for(cwe="CWE-89")
    assert (FRAMEWORK_PCI_DSS, "6.5.1") in out
    assert (FRAMEWORK_OWASP_ASVS, "V5.3.4") in out


def test_controls_for_category_only() -> None:
    out = controls_for(category="vulnerable_dependency")
    assert (FRAMEWORK_SOC2, "CC6.8") in out


def test_controls_for_unions_cwe_and_category() -> None:
    """Both CWE + category supplied → union of both control sets."""
    out = controls_for(cwe="CWE-89", category="sast")
    # CWE-89 controls.
    assert (FRAMEWORK_PCI_DSS, "6.5.1") in out
    # `sast` category catch-all.
    assert (FRAMEWORK_PCI_DSS, "6.2") in out


def test_controls_for_unknown_cwe_returns_empty() -> None:
    assert controls_for(cwe="CWE-99999") == []


def test_controls_for_unknown_category_returns_empty() -> None:
    assert controls_for(category="totally-fake-category") == []


def test_controls_for_neither_returns_empty() -> None:
    assert controls_for() == []


def test_controls_for_normalises_cwe_case() -> None:
    """`cwe-89` should resolve to the same set as `CWE-89`."""
    a = controls_for(cwe="CWE-89")
    b = controls_for(cwe="cwe-89")
    assert sorted(a) == sorted(b)


# ---------------------------------------------------------------------------
# Coverage / untested-controls
# ---------------------------------------------------------------------------


def test_covered_controls_is_non_empty() -> None:
    out = covered_controls()
    assert len(out) > 10


def test_untested_controls_filters_to_subset() -> None:
    """Some controls in our framework catalogs (e.g. SOC 2 CC6.3
    access removal) aren't covered by AppSec rules at all —
    expected to appear in the untested set."""
    untested = untested_controls()
    untested_ids = {(fw, cid) for fw, cid in untested}
    # CC6.3 (access removal) is admin / org-policy work; no
    # AppSec rule can verify it. Should be untested.
    assert (FRAMEWORK_SOC2, "CC6.3") in untested_ids


def test_untested_subset_to_one_framework() -> None:
    """`untested_controls(frameworks=['soc2'])` returns only
    SOC 2 entries."""
    untested = untested_controls(frameworks=[FRAMEWORK_SOC2])
    assert all(fw == FRAMEWORK_SOC2 for fw, _ in untested)
