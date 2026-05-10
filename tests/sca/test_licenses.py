"""Unit tests for `strix.sca.licenses` — Phase 6.7 SPDX
classification + copyleft / commercial-restricted flagging."""

from __future__ import annotations

import pytest

from strix.sca.licenses import (
    FAMILY_COMMERCIAL_RESTRICTED,
    FAMILY_COPYLEFT,
    FAMILY_PERMISSIVE,
    FAMILY_UNKNOWN,
    FAMILY_WEAK_COPYLEFT,
    classify_license,
    find_license_violations,
)
from strix.sca.parsers.base import Package


def _pkg(name: str, *, ecosystem: str = "npm", license="MIT",
         dev_only: bool = False, version: str = "1.0.0") -> Package:
    return Package(
        ecosystem=ecosystem, name=name, version=version,
        dev_only=dev_only, source_path="lockfile",
        metadata={"license": license},
    )


# ---------------------------------------------------------------------------
# classify_license — string / list / dict / compound shapes
# ---------------------------------------------------------------------------


def test_classify_permissive_strings() -> None:
    for s in ("MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "0BSD"):
        assert classify_license(s) == FAMILY_PERMISSIVE, s


def test_classify_case_insensitive() -> None:
    assert classify_license("mit") == FAMILY_PERMISSIVE
    assert classify_license("APACHE-2.0") == FAMILY_PERMISSIVE


def test_classify_weak_copyleft() -> None:
    for s in ("LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0"):
        assert classify_license(s) == FAMILY_WEAK_COPYLEFT, s


def test_classify_copyleft() -> None:
    for s in ("GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"):
        assert classify_license(s) == FAMILY_COPYLEFT, s


def test_classify_commercial_restricted() -> None:
    for s in ("BUSL-1.1", "Elastic-2.0", "proprietary", "see license"):
        assert classify_license(s) == FAMILY_COMMERCIAL_RESTRICTED, s


def test_classify_none_or_empty_is_unknown() -> None:
    assert classify_license(None) == FAMILY_UNKNOWN
    assert classify_license("") == FAMILY_UNKNOWN


def test_classify_unrecognised_string_is_unknown() -> None:
    assert classify_license("WeirdCustomLicense-9.9") == FAMILY_UNKNOWN


def test_classify_npm_legacy_dict_form() -> None:
    """npm's legacy: `{"type": "MIT", "url": "..."}`."""
    assert classify_license({"type": "MIT", "url": "x"}) == FAMILY_PERMISSIVE
    assert classify_license({"name": "GPL-3.0"}) == FAMILY_COPYLEFT


def test_classify_composer_list_form() -> None:
    """composer's convention: `["MIT"]` or `["MIT", "GPL-2.0"]`."""
    assert classify_license(["MIT"]) == FAMILY_PERMISSIVE


def test_classify_list_with_mixed_uses_worst_case() -> None:
    """List with both MIT and GPL → worst case = copyleft. The
    licensee can pick either, but the conservative engineering
    default is "assume worst case for the auditor"."""
    assert classify_license(["MIT", "GPL-3.0"]) == FAMILY_COPYLEFT
    assert classify_license(["MIT", "Apache-2.0"]) == FAMILY_PERMISSIVE


def test_classify_compound_or_expression() -> None:
    """`(MIT OR Apache-2.0)` → permissive (both choices safe)."""
    assert classify_license("(MIT OR Apache-2.0)") == FAMILY_PERMISSIVE


def test_classify_compound_with_gpl_alternative_is_copyleft() -> None:
    """`(MIT OR GPL-3.0)` → copyleft (worst case)."""
    assert classify_license("(MIT OR GPL-3.0)") == FAMILY_COPYLEFT


def test_classify_compound_and_expression_uses_worst() -> None:
    """`MIT AND CC0-1.0` → permissive (both permissive)."""
    assert classify_license("MIT AND CC0-1.0") == FAMILY_PERMISSIVE


def test_classify_with_exception_clause() -> None:
    """`GPL-3.0 WITH Classpath-exception-2.0` → still copyleft
    (the exception narrows the GPL but doesn't make it permissive
    for our purposes)."""
    assert (
        classify_license("GPL-3.0 WITH Classpath-exception-2.0")
        == FAMILY_COPYLEFT
    )


def test_classify_unrecognised_compound_is_unknown() -> None:
    assert classify_license("(WeirdA OR WeirdB)") == FAMILY_UNKNOWN


def test_classify_empty_list_is_unknown() -> None:
    assert classify_license([]) == FAMILY_UNKNOWN


def test_classify_dict_without_type_or_name_is_unknown() -> None:
    assert classify_license({"url": "https://example.com"}) == FAMILY_UNKNOWN


# ---------------------------------------------------------------------------
# find_license_violations — policy enforcement
# ---------------------------------------------------------------------------


def test_no_violations_for_all_permissive() -> None:
    pkgs = [_pkg("a"), _pkg("b", license="Apache-2.0")]
    assert find_license_violations(pkgs) == []


def test_copyleft_emits_high_severity_violation() -> None:
    pkgs = [_pkg("gpl-pkg", license="GPL-3.0")]
    violations = find_license_violations(pkgs)
    assert len(violations) == 1
    v = violations[0]
    assert v.family == FAMILY_COPYLEFT
    assert v.severity == "high"
    assert "GPL" in v.rationale or "copyleft" in v.rationale.lower()


def test_agpl_specifically_calls_out_saas_implication() -> None:
    """AGPL is the SaaS killer — the rationale should mention
    network-use/distribution so the wrapper renders the right
    explanation."""
    pkgs = [_pkg("agpl-pkg", license="AGPL-3.0")]
    violations = find_license_violations(pkgs)
    assert len(violations) == 1
    assert "network" in violations[0].rationale.lower()


def test_commercial_restricted_emits_high_severity() -> None:
    pkgs = [_pkg("busl-pkg", license="BUSL-1.1")]
    violations = find_license_violations(pkgs)
    assert len(violations) == 1
    assert violations[0].family == FAMILY_COMMERCIAL_RESTRICTED
    assert violations[0].severity == "high"


def test_unknown_license_emits_medium_severity() -> None:
    pkgs = [_pkg("mystery", license=None)]
    violations = find_license_violations(pkgs)
    assert len(violations) == 1
    assert violations[0].family == FAMILY_UNKNOWN
    assert violations[0].severity == "medium"


def test_weak_copyleft_quiet_by_default() -> None:
    """LGPL/MPL/EPL — safe for SaaS link-only, no violation by
    default."""
    pkgs = [_pkg("lgpl-pkg", license="LGPL-3.0")]
    assert find_license_violations(pkgs) == []


def test_weak_copyleft_can_be_flagged_via_policy() -> None:
    """Stricter policy: customer requires permissive-only."""
    pkgs = [_pkg("lgpl-pkg", license="LGPL-3.0")]
    violations = find_license_violations(pkgs, allow_weak_copyleft=False)
    assert len(violations) == 1
    assert violations[0].family == FAMILY_WEAK_COPYLEFT
    assert violations[0].severity == "low"


def test_allow_copyleft_suppresses_gpl_violations() -> None:
    """OSS / GPL-licensed downstream → don't flag GPL deps."""
    pkgs = [_pkg("gpl-pkg", license="GPL-3.0")]
    assert find_license_violations(pkgs, allow_copyleft=True) == []


def test_allow_unknown_suppresses_missing_license() -> None:
    pkgs = [_pkg("mystery", license=None)]
    assert find_license_violations(pkgs, allow_unknown=True) == []


def test_skip_dev_only_default_true() -> None:
    """Dev-only deps (test runners, linters) don't ship to prod →
    license terms typically don't apply. Skipped by default."""
    pkgs = [_pkg("test-tool", license="GPL-3.0", dev_only=True)]
    assert find_license_violations(pkgs) == []


def test_dev_only_violations_emitted_when_disabled() -> None:
    pkgs = [_pkg("test-tool", license="GPL-3.0", dev_only=True)]
    violations = find_license_violations(pkgs, skip_dev_only=False)
    assert len(violations) == 1


def test_packages_without_license_metadata_skipped() -> None:
    """Parser doesn't surface license for some ecosystems (cargo /
    go) → no `license` key in metadata. Those skip cleanly,
    don't error, don't false-positive."""
    pkg = Package(
        ecosystem="cargo", name="serde", version="1.0",
        source_path="Cargo.lock", metadata={"checksum": "x"},
    )
    assert find_license_violations([pkg]) == []


def test_violations_ordered_by_severity_descending() -> None:
    pkgs = [
        _pkg("mystery", license=None),                  # medium
        _pkg("gpl", license="GPL-3.0"),                 # high
        _pkg("commercial", license="BUSL-1.1"),         # high
    ]
    violations = find_license_violations(pkgs)
    assert len(violations) == 3
    severities = [v.severity for v in violations]
    # All highs come before mediums.
    assert severities == sorted(
        severities, key=lambda s: -{"high": 3, "medium": 2, "low": 1}[s],
    )
