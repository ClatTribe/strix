"""Tests for iter-35.3 — register recon tools in _ANCHORS_WEB/_API.

The L2 Lead (especially on lightweight models like Gemini Flash) was
not reliably invoking `crawl_with_katana` despite the iter-32.2
recon-first directive in the system prompt. Adding it to the
deterministic anchor sequence ensures recon ALWAYS runs.

This sits alongside iter-35.1 (host-side katana removed) and
iter-32.1 (record_endpoint_discovered wiring) — together they close
the surface_breadth=0% diagnostic gap.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.agents.lead_agent.anchor_prepass import (
    _ANCHORS_API,
    _ANCHORS_WEB,
    _ANCHORS_BY_TARGET_TYPE,
    _api_target_url_kwargs,
)


def _names_in_anchor_list(anchors) -> list[str]:
    return [tool_name for (tool_name, _kwargs_builder) in anchors]


def test_crawl_with_katana_in_anchors_api():
    """API targets must include crawl_with_katana so SPA-style API
    consoles (Swagger UI, API explorers) get JS-crawled."""
    names = _names_in_anchor_list(_ANCHORS_API)
    assert "crawl_with_katana" in names, (
        "iter-35.3: `crawl_with_katana` missing from _ANCHORS_API. "
        "Without it the deterministic prepass doesn't run JS-aware "
        "recon and the L2 Lead is the only path that might invoke it."
    )


def test_crawl_with_katana_in_anchors_web():
    """Web targets must include crawl_with_katana (inherited via
    _ANCHORS_API extension)."""
    names = _names_in_anchor_list(_ANCHORS_WEB)
    assert "crawl_with_katana" in names, (
        "iter-35.3: `crawl_with_katana` missing from _ANCHORS_WEB"
    )


def test_crawl_with_katana_uses_correct_kwargs_builder():
    """The kwargs builder must produce `{target_url: ...}` matching
    the registered tool's signature. The runtime kwarg-mismatch bug
    bit us hard in iter-19 — defend against it."""
    anchors_dict = {name: builder for (name, builder) in _ANCHORS_API}
    assert "crawl_with_katana" in anchors_dict
    builder = anchors_dict["crawl_with_katana"]
    kwargs = builder("http://app", "", "crawl_with_katana")
    assert "target_url" in kwargs, (
        "iter-35.3: kwargs builder for crawl_with_katana must produce "
        "`target_url=` (the tool's signature accepts target_url, not url)"
    )
    assert kwargs["target_url"] == "http://app"


def test_crawl_with_katana_precedes_specialist_scans_in_anchor_order():
    """Recon must run before the specialist scan_* tools so when
    those run, they have an endpoint inventory from workflow_state."""
    names = _names_in_anchor_list(_ANCHORS_API)
    katana_idx = names.index("crawl_with_katana")
    for specialist in ("scan_sqli", "scan_xxe", "scan_ssrf"):
        if specialist in names:
            assert katana_idx < names.index(specialist), (
                f"iter-35.3: crawl_with_katana must precede {specialist} "
                f"in anchor order (so the specialist sees discovered "
                f"endpoints in workflow_state when it fires)"
            )


def test_iter_35_3_marker_present_in_source():
    """The iter-35.3 comment must be discoverable so future
    maintainers see the rationale."""
    import strix.agents.lead_agent.anchor_prepass as mod
    src = Path(mod.__file__).read_text()
    assert "iter-35.3" in src, "iter-35.3 marker missing from source"


def test_anchors_lookup_matches_for_web_and_api():
    """Defensive: _ANCHORS_BY_TARGET_TYPE must point to the same
    lists we just verified."""
    assert _ANCHORS_BY_TARGET_TYPE["api"] is _ANCHORS_API
    assert _ANCHORS_BY_TARGET_TYPE["web_application"] is _ANCHORS_WEB


def test_anchor_list_has_no_duplicate_tool_names():
    """If iter-35.3 added crawl_with_katana twice (e.g. once in API
    and once in WEB-only section), that'd double-fire. Defend."""
    for label, anchors in (("api", _ANCHORS_API), ("web", _ANCHORS_WEB)):
        names = _names_in_anchor_list(anchors)
        dups = [n for n in set(names) if names.count(n) > 1]
        assert not dups, (
            f"iter-35.3: duplicate anchor tool names in {label}: {dups}"
        )
