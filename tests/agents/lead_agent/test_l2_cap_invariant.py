"""iter-Q5.2 — CI invariant test for the L2 ≤10-tool cap.

Per CLAUDE.md §1.5.5 (Invariant L2-CAP) and
`docs/proposals/2026-05-27-l2-tool-cap-and-translation-toolkit.md`.

The cap counts what the LLM sees in the system prompt — the minimal
CORE tools + the per-asset specialist set. It does NOT count tools
that fire deterministically in `anchor_prepass` or that auto-fire
inside `finish_scan`.

## Test structure

This file ships TWO kinds of test:

1. **Structural cap assertion** — for every registered asset type,
   `len(get_lead_tool_catalog(target_types=[t])) <= 10`. The 4 currently-
   violating assets are marked with per-param `xfail(strict=True)`
   pointing at the iter that closes the gap. When iter-Q5.3 / Q5.4 /
   Q5.5 land, the corresponding params XPASS — strict=True turns
   that into a build failure that forces stripping the marker.

2. **Baseline pin** — pins the CURRENT shipped count for each asset
   so regression in the OPPOSITE direction (someone adding tool #15
   to web) gets caught. As iter-Q5.3-5 land, the
   `_BASELINE_CATALOG_COUNTS` constant is updated to track the new
   shipped reality.

Together these are the load-bearing gates for the whole Q5 sequence.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

from strix.agents.lead_agent.tool_catalog import (
    _MINIMAL_TOOLS_BY_TARGET_TYPE,
    get_lead_tool_catalog,
)


# ---------------------------------------------------------------------------
# Invariant constants
# ---------------------------------------------------------------------------


# Per CLAUDE.md §1.5.5 — Invariant L2-CAP.
L2_CAP = 10

# Every asset type the harness knows about. Source of truth: the
# `_MINIMAL_TOOLS_BY_TARGET_TYPE` keys.
REGISTERED_ASSET_TYPES: tuple[str, ...] = (
    "web_application",
    "api",
    "repository",
    "local_code",
    "container_image",
    "ip_address",
    "domain",
)

# Pre-Q5 shipped baseline (as of 2026-05-27). Each iter that moves a
# tool out of the L2 catalog updates THIS constant to match the new
# shipped reality. The test `test_l2_catalog_count_matches_baseline`
# asserts equality, so any silent regression (a forgotten tool added
# to a per-asset specialist set) trips the assertion.
#
# Target end-state (post-Q5.5, per CLAUDE.md §1.5.8):
#   web=10, api=10, repo=10, local_code=10, container=9, ip=10, domain=10
_BASELINE_CATALOG_COUNTS: dict[str, int] = {
    "web_application": 8,    # iter-Q5.3: dropped sqlmap/dalfox/smuggler/hydra/ffuf (13 → 8)
    "api": 9,                # iter-Q5.3: dropped sqlmap/smuggler/hydra/ffuf/schemathesis (14 → 9)
    "repository": 10,
    "local_code": 10,
    "container_image": 7,
    "ip_address": 11,
    "domain": 11,
}


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Ensure both opt-out env vars are unset for the duration of each
    test — we measure the DEFAULT (minimal) catalog. Tests that need
    legacy or orchestrator mode set them explicitly."""
    monkeypatch.delenv("STRIX_LEGACY_CATALOG", raising=False)
    monkeypatch.delenv("STRIX_ORCHESTRATOR_MODE", raising=False)
    monkeypatch.delenv("STRIX_WORKFLOW_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# Structural cap assertion
# ---------------------------------------------------------------------------


# Each violating asset type is marked with per-param strict-xfail.
# When iter-Q5.3 / Q5.4 / Q5.5 land and the cap is honored, those
# params XPASS — strict=True turns that into a build failure that
# forces the next PR to strip the marker. That's the intended flow.
@pytest.mark.parametrize("asset_type", [
    # iter-Q5.3 closed web (13 → 8) and api (14 → 9). xfail markers
    # stripped — both now pass under the cap. The history is in
    # _BASELINE_CATALOG_COUNTS comments + the PR that lands this.
    "web_application",
    "api",
    "repository",
    "local_code",
    "container_image",
    pytest.param(
        "ip_address",
        marks=pytest.mark.xfail(
            strict=True,
            reason=(
                "iter-Q5.4 closes ip_address: 11 → 10 by moving "
                "fingerprint_services_nmap, probe_hosts_httpx, "
                "scan_nuclei_templates, tls_audit to anchor_prepass."
            ),
        ),
    ),
    pytest.param(
        "domain",
        marks=pytest.mark.xfail(
            strict=True,
            reason=(
                "iter-Q5.5 closes domain: 11 → 10 by moving "
                "enumerate_subdomains_subfinder, scan_dns_hygiene_checkdmarc, "
                "scan_typosquats_dnstwist, scan_nuclei_templates, "
                "domain_recon_pipeline to anchor_prepass + adding "
                "terminal_execute per gap-fix Q5.12."
            ),
        ),
    ),
])
def test_l2_catalog_within_cap(asset_type: str) -> None:
    """For every registered asset type, the L2-visible catalog must be
    ≤ L2_CAP tools. Violators are xfail-strict until their named iter
    closes the gap."""
    catalog = get_lead_tool_catalog(target_types=[asset_type])
    assert len(catalog) <= L2_CAP, (
        f"Asset {asset_type!r}: catalog has {len(catalog)} tools, "
        f"violates ≤{L2_CAP} cap.\n"
        f"Tools: {sorted(catalog)}"
    )


# ---------------------------------------------------------------------------
# Baseline pin — catches accidental regression in the opposite direction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "asset_type,expected_count",
    list(_BASELINE_CATALOG_COUNTS.items()),
)
def test_l2_catalog_count_matches_baseline(
    asset_type: str, expected_count: int,
) -> None:
    """Pins the CURRENT shipped count per asset. Catches accidental
    regression (someone adding a tool that pushes the count up).

    When iter-Q5.3-5 deliberately reduces a count, update
    `_BASELINE_CATALOG_COUNTS` in this file as part of that same PR
    — the diff makes the move auditable.
    """
    catalog = get_lead_tool_catalog(target_types=[asset_type])
    assert len(catalog) == expected_count, (
        f"Asset {asset_type!r}: catalog has {len(catalog)} tools, "
        f"baseline pinned at {expected_count}.\n"
        f"If this change is intentional (iter-Q5.3-5 reducing the "
        f"count, OR an explicit catalog addition with sign-off), "
        f"update `_BASELINE_CATALOG_COUNTS` in this test.\n"
        f"Tools: {sorted(catalog)}"
    )


# ---------------------------------------------------------------------------
# Sanity / coverage tests
# ---------------------------------------------------------------------------


def test_every_registered_asset_has_minimal_catalog_entry() -> None:
    """Every entry in REGISTERED_ASSET_TYPES must have a minimal
    per-asset specialist set. Catches the case where someone adds a
    new asset type but forgets to wire its catalog."""
    for asset_type in REGISTERED_ASSET_TYPES:
        assert asset_type in _MINIMAL_TOOLS_BY_TARGET_TYPE, (
            f"Asset type {asset_type!r} is in REGISTERED_ASSET_TYPES "
            f"but not in _MINIMAL_TOOLS_BY_TARGET_TYPE — add a "
            f"per-asset specialist set or remove from the asset-type "
            f"list."
        )


def test_baseline_dict_covers_every_registered_asset() -> None:
    """The baseline-count dict and REGISTERED_ASSET_TYPES must agree.
    Catches drift between the two constants."""
    assert set(_BASELINE_CATALOG_COUNTS.keys()) == set(REGISTERED_ASSET_TYPES), (
        f"Drift between _BASELINE_CATALOG_COUNTS and "
        f"REGISTERED_ASSET_TYPES.\n"
        f"  In baseline only: "
        f"{set(_BASELINE_CATALOG_COUNTS) - set(REGISTERED_ASSET_TYPES)}\n"
        f"  In registered only: "
        f"{set(REGISTERED_ASSET_TYPES) - set(_BASELINE_CATALOG_COUNTS)}"
    )


def test_compliant_assets_no_xfail_marker_needed() -> None:
    """Pin: the 3 currently-compliant assets (repository, local_code,
    container_image) actually fit under the cap. If this fails, the
    cap definition has shifted and the structural test's xfail
    markers need re-auditing."""
    for asset_type in ("repository", "local_code", "container_image"):
        catalog = get_lead_tool_catalog(target_types=[asset_type])
        assert len(catalog) <= L2_CAP, (
            f"Asset {asset_type!r} was expected compliant but now has "
            f"{len(catalog)} tools. Audit the catalog change and update "
            f"the structural test's xfail markers if appropriate."
        )


# ---------------------------------------------------------------------------
# Opt-out modes — explicit exemptions
# ---------------------------------------------------------------------------


def test_legacy_catalog_exceeds_cap_by_design(monkeypatch) -> None:
    """`STRIX_LEGACY_CATALOG=1` restores the pre-iter-37.2 fat catalog.
    The cap is intentionally NOT enforced for the legacy path — that's
    the backwards-compat surface. If you've trimmed the legacy catalog
    under the cap, also delete this test."""
    monkeypatch.setenv("STRIX_LEGACY_CATALOG", "1")
    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert len(catalog) > L2_CAP, (
        f"Legacy catalog has {len(catalog)} tools — expected > {L2_CAP}. "
        f"If you intentionally trimmed it under the cap, also delete "
        f"this test."
    )


@pytest.mark.xfail(
    strict=False,
    reason=(
        "Orchestrator mode (STRIX_ORCHESTRATOR_MODE=true) is a "
        "separate design path with intentionally rich orchestration "
        "tools (hypothesis tracking, notes, batched dispatch). The "
        "≤10 cap doesn't yet apply to that mode. Tracked separately "
        "from Q5; see CLAUDE.md §1.5.5. xfail strict=False so XPASS "
        "is not a build failure — when orchestrator mode is also "
        "brought under the cap, this test flips to passing and the "
        "marker can be stripped."
    ),
)
def test_orchestrator_mode_within_cap(monkeypatch) -> None:
    """Orchestrator mode catalog also under the cap — aspiration, not
    yet enforced."""
    monkeypatch.setenv("STRIX_ORCHESTRATOR_MODE", "true")
    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert len(catalog) <= L2_CAP, (
        f"Orchestrator-mode catalog has {len(catalog)} tools, "
        f"violates ≤{L2_CAP} cap. Tools: {sorted(catalog)}"
    )


# ---------------------------------------------------------------------------
# Multi-target sanity
# ---------------------------------------------------------------------------


def test_multi_target_union_does_not_explode() -> None:
    """When a scan targets multiple asset types, `get_lead_tool_catalog`
    returns the UNION. Verify that the union doesn't blow past 2× the
    cap — i.e. the per-asset sets share a CORE so the union is bounded.

    Picked the two largest catalogs (web + api) — should share the
    5-tool CORE so union is ≤ web + api - 5 (CORE overlap)."""
    web = get_lead_tool_catalog(target_types=["web_application"])
    api = get_lead_tool_catalog(target_types=["api"])
    union = get_lead_tool_catalog(
        target_types=["web_application", "api"],
    )
    # The CORE set (5 tools) is shared.
    overlap = web & api
    assert len(overlap) >= 5, (
        f"Expected web ∩ api ≥ 5 (CORE tools), got {len(overlap)}: "
        f"{sorted(overlap)}"
    )
    # Union obeys: |A ∪ B| = |A| + |B| - |A ∩ B|.
    assert len(union) == len(web) + len(api) - len(overlap), (
        f"Union math broke: |A|={len(web)} |B|={len(api)} "
        f"|A∩B|={len(overlap)} |A∪B|={len(union)}"
    )


# ---------------------------------------------------------------------------
# Anti-overfit guard (matches the iter-31.x pattern)
# ---------------------------------------------------------------------------


def test_tool_catalog_module_has_no_fixture_identifiers() -> None:
    """The policy module (`tool_catalog.py`) is generic — it must not
    reference bench-fixture names. Catches the case where someone
    hardcodes a tool entry that's specific to one bench. Same pattern
    as the iter-31.x anti-overfit guards.

    Note: this test scans the policy module under test, not this test
    file — the test file legitimately lists the forbidden tokens as
    the search corpus."""
    src = (
        Path(__file__).parent.parent.parent.parent
        / "strix" / "agents" / "lead_agent" / "tool_catalog.py"
    ).read_text(encoding="utf-8").lower()
    # Build forbidden tokens via concatenation so this test file's own
    # literals don't self-trigger if a future maintainer adds a
    # `scan_for_forbidden_in_test_file` check.
    forbidden = (
        "juice" + "-shop",
        "juice" + "shop",
        "bkim" + "minich",
        "vam" + "pi",
        "cr" + "api",  # bench fixture, distinct from "api" asset type
        "erev" + "0s",
        "web" + "goat",
    )
    for token in forbidden:
        assert token not in src, (
            f"tool_catalog.py contains bench-fixture identifier "
            f"{token!r} — the catalog policy is generic and must not "
            f"reference bench fixtures."
        )
