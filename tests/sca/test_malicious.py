"""Unit tests for `strix.sca.malicious` — Phase 6.6 typosquat /
install-script / missing-license heuristics."""

from __future__ import annotations

import pytest

from strix.sca.malicious import (
    INDICATOR_INSTALL_SCRIPT,
    INDICATOR_NO_LICENSE,
    INDICATOR_TYPOSQUAT,
    _detect_install_script,
    _detect_no_license,
    _detect_typosquat,
    _levenshtein,
    analyse_package,
    analyse_packages,
)
from strix.sca.parsers.base import Package


def _pkg(name: str, *, ecosystem: str = "npm", direct: bool = True,
         version: str = "1.0.0", **md) -> Package:
    return Package(
        ecosystem=ecosystem, name=name, version=version, direct=direct,
        source_path="lockfile", metadata=md,
    )


# ---------------------------------------------------------------------------
# Levenshtein helper
# ---------------------------------------------------------------------------


def test_levenshtein_zero_for_identical() -> None:
    assert _levenshtein("lodash", "lodash") == 0


def test_levenshtein_one_substitution() -> None:
    assert _levenshtein("lodash", "lodahs") == 2  # transpose = 2 edits
    assert _levenshtein("requests", "reqests") == 1  # delete one char
    assert _levenshtein("requests", "reqeusts") == 2


def test_levenshtein_caps_at_max_d_plus_one() -> None:
    """Distance > max_d returns max_d+1 quickly (no-op for typosquat)."""
    assert _levenshtein("lodash", "completely-different", max_d=2) == 3
    assert _levenshtein("a", "abcdefg", max_d=2) == 3  # length diff alone


def test_levenshtein_empty_strings() -> None:
    assert _levenshtein("", "") == 0
    assert _levenshtein("a", "") == 1
    assert _levenshtein("", "abcd", max_d=5) == 4


# ---------------------------------------------------------------------------
# Typosquat detection
# ---------------------------------------------------------------------------


def test_typosquat_distance_one_npm_high_severity() -> None:
    """`reqeusts` vs `requests` (typo of swapped letters) → high
    severity, distance 1 isn't right (it's actually 2 edits — swap
    is 2). Use a true distance-1 case."""
    pkg = _pkg("reqests", ecosystem="pypi")  # missing one char
    ind = _detect_typosquat(pkg)
    assert ind is not None
    assert ind.indicator == INDICATOR_TYPOSQUAT
    assert ind.extra["typosquat_target"] == "requests"
    assert ind.extra["edit_distance"] == 1
    assert ind.severity == "high"


def test_typosquat_distance_two_medium_severity() -> None:
    """`reqeusts` (transposition = 2 edits) → medium severity."""
    pkg = _pkg("reqeusts", ecosystem="pypi")
    ind = _detect_typosquat(pkg)
    assert ind is not None
    assert ind.severity == "medium"
    assert ind.extra["edit_distance"] == 2


def test_typosquat_npm_lodash() -> None:
    pkg = _pkg("lodahs", ecosystem="npm")
    ind = _detect_typosquat(pkg)
    assert ind is not None
    assert ind.extra["typosquat_target"] == "lodash"


def test_typosquat_real_package_returns_none() -> None:
    """Popular packages must NOT flag themselves as typosquats."""
    assert _detect_typosquat(_pkg("lodash", ecosystem="npm")) is None
    assert _detect_typosquat(_pkg("requests", ecosystem="pypi")) is None


def test_typosquat_substring_legit_variant_returns_none() -> None:
    """`lodash-fp` / `lodash-extra` are legitimate variants
    (substring match), not squats. The detector must NOT flag
    these."""
    assert _detect_typosquat(_pkg("lodash-fp", ecosystem="npm")) is None
    assert _detect_typosquat(_pkg("lodash-extra", ecosystem="npm")) is None
    assert _detect_typosquat(_pkg("react-router", ecosystem="npm")) is None


def test_typosquat_short_names_skipped() -> None:
    """Names < 4 chars produce too many false positives. Skipped."""
    assert _detect_typosquat(_pkg("foo", ecosystem="npm")) is None
    assert _detect_typosquat(_pkg("ws", ecosystem="npm")) is None


def test_typosquat_scoped_packages_skipped() -> None:
    """Scoped names (`@scope/x`) have built-in protection — the
    scope itself is the security barrier. Detector skips them."""
    pkg = _pkg("@scope/lodahs", ecosystem="npm")
    assert _detect_typosquat(pkg) is None


def test_typosquat_unsupported_ecosystem_returns_none() -> None:
    """v1 only handles npm + pypi. Other ecosystems → no signal."""
    assert _detect_typosquat(_pkg("serde", ecosystem="cargo")) is None
    assert _detect_typosquat(_pkg("symfony/ovrride", ecosystem="composer")) is None


def test_typosquat_no_match_returns_none() -> None:
    """A unique name nothing close to popular → no flag."""
    pkg = _pkg("xyz-totally-unique-9c14e", ecosystem="npm")
    assert _detect_typosquat(pkg) is None


# ---------------------------------------------------------------------------
# Install-script detection
# ---------------------------------------------------------------------------


def test_install_script_direct_dep_medium() -> None:
    """A direct dep with hasInstallScript=True → medium (you
    chose it; verify the upstream)."""
    pkg = _pkg("sharp", ecosystem="npm", direct=True, has_install_script=True)
    ind = _detect_install_script(pkg)
    assert ind is not None
    assert ind.indicator == INDICATOR_INSTALL_SCRIPT
    assert ind.severity == "medium"


def test_install_script_transitive_dep_high() -> None:
    """Transitive dep with hasInstallScript=True → high severity
    because you didn't pick it; some other package's maintainer
    did."""
    pkg = _pkg("evil-tx", ecosystem="npm", direct=False, has_install_script=True)
    ind = _detect_install_script(pkg)
    assert ind is not None
    assert ind.severity == "high"


def test_install_script_without_flag_returns_none() -> None:
    pkg = _pkg("sharp", ecosystem="npm", direct=True)  # no flag
    assert _detect_install_script(pkg) is None


def test_install_script_non_npm_returns_none() -> None:
    pkg = _pkg("django", ecosystem="pypi", has_install_script=True)
    assert _detect_install_script(pkg) is None


# ---------------------------------------------------------------------------
# Missing-license detection
# ---------------------------------------------------------------------------


def test_no_license_when_field_explicitly_none() -> None:
    pkg = _pkg("sus", ecosystem="npm", license=None)
    ind = _detect_no_license(pkg)
    assert ind is not None
    assert ind.indicator == INDICATOR_NO_LICENSE
    assert ind.severity == "low"


def test_no_license_when_empty_string() -> None:
    pkg = _pkg("sus", ecosystem="npm", license="")
    ind = _detect_no_license(pkg)
    assert ind is not None


def test_no_license_when_empty_list() -> None:
    """composer convention: license is `[]`."""
    pkg = _pkg("sus/x", ecosystem="composer", license=[])
    ind = _detect_no_license(pkg)
    assert ind is not None


def test_no_license_quiet_when_field_present() -> None:
    pkg = _pkg("ok", ecosystem="npm", license="MIT")
    assert _detect_no_license(pkg) is None


def test_no_license_quiet_when_field_absent_from_metadata() -> None:
    """If the parser didn't surface license at all (e.g. cargo /
    go), the absence is a parser limitation, not a signal."""
    pkg = _pkg("serde", ecosystem="cargo")  # no `license` in metadata
    assert _detect_no_license(pkg) is None


# ---------------------------------------------------------------------------
# Bulk analyse_packages + multi-indicator
# ---------------------------------------------------------------------------


def test_analyse_package_collects_multiple_indicators() -> None:
    """A package can have a typosquat name AND no license — both
    indicators should fire on a single analysis."""
    pkg = _pkg("reqests", ecosystem="pypi", license=None)
    report = analyse_package(pkg)
    indicators = {i.indicator for i in report.indicators}
    assert INDICATOR_TYPOSQUAT in indicators
    assert INDICATOR_NO_LICENSE in indicators


def test_analyse_packages_one_report_per_input() -> None:
    pkgs = [
        _pkg("lodash", ecosystem="npm", license="MIT"),  # clean
        _pkg("lodahs", ecosystem="npm", license="MIT"),  # typosquat
        _pkg("evil", ecosystem="npm", direct=False, has_install_script=True),
    ]
    reports = analyse_packages(pkgs)
    assert len(reports) == 3
    by_name = {r.package.name: r for r in reports}
    assert by_name["lodash"].indicators == []
    assert any(
        i.indicator == INDICATOR_TYPOSQUAT
        for i in by_name["lodahs"].indicators
    )
    assert any(
        i.indicator == INDICATOR_INSTALL_SCRIPT
        for i in by_name["evil"].indicators
    )


def test_severity_max_orders_correctly() -> None:
    """Multiple indicators on one package → severity_max picks the
    highest."""
    pkg = _pkg("evil", ecosystem="npm", direct=False,
               has_install_script=True, license=None)
    report = analyse_package(pkg)
    # install_script (high) > no_license (low) → high.
    assert report.severity_max == "high"
