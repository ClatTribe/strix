"""Tests for engine-wishlist §2 fast first-pass profile."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# LLMConfig.scan_mode validation
# ---------------------------------------------------------------------------


def test_llm_config_accepts_initial_mode(monkeypatch) -> None:
    """`initial` is a valid scan_mode in LLMConfig."""
    monkeypatch.setenv("STRIX_LLM", "openai/test-model")
    # Avoid touching real config files.
    from strix.llm.config import LLMConfig

    cfg = LLMConfig(scan_mode="initial", model_name="openai/test-model")
    assert cfg.scan_mode == "initial"


def test_llm_config_unknown_mode_falls_back_to_deep(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/test-model")
    from strix.llm.config import LLMConfig

    cfg = LLMConfig(scan_mode="banana", model_name="openai/test-model")
    assert cfg.scan_mode == "deep"


def test_llm_config_preserves_existing_modes(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_LLM", "openai/test-model")
    from strix.llm.config import LLMConfig

    for mode in ("quick", "standard", "deep"):
        cfg = LLMConfig(scan_mode=mode, model_name="openai/test-model")
        assert cfg.scan_mode == mode


# ---------------------------------------------------------------------------
# llm.py reasoning_effort mapping
# ---------------------------------------------------------------------------


def test_reasoning_effort_is_low_for_initial_mode() -> None:
    """`initial` mode should pin reasoning_effort=low — recon-only
    scans don't need deep reasoning, and low effort hits the
    10%-of-standard cost target."""
    # The mapping lives inline in StrixLLM.__init__; rather than
    # spin up the whole class (which pulls in litellm + agent
    # init), check the source for the documented branch.
    from strix.llm import llm as llm_module
    source = Path(llm_module.__file__).read_text(encoding="utf-8")
    # Look for the `initial` mode branch.
    assert "scan_mode == \"initial\"" in source
    # And confirm it pins to "low" (the rest of the conditional
    # cascade preserves quick=medium / deep=high).
    initial_idx = source.find("scan_mode == \"initial\"")
    nearby = source[initial_idx : initial_idx + 250]
    assert "\"low\"" in nearby


# ---------------------------------------------------------------------------
# CLI flags
# ---------------------------------------------------------------------------


def test_cli_accepts_scan_mode_initial(monkeypatch) -> None:
    """`--scan-mode initial` parses cleanly."""
    from strix.interface.main import parse_arguments
    monkeypatch.setattr(
        sys, "argv",
        ["strix", "-t", "https://x.example/", "-m", "initial", "-n"],
    )
    # The wrapper-specific resolver runs inside parse_arguments.
    # We're just checking the value lands on args.scan_mode.
    args = parse_arguments()
    assert args.scan_mode == "initial"


def test_cli_profile_alias_resolves_to_scan_mode(monkeypatch) -> None:
    """`--profile initial` overrides --scan-mode default."""
    from strix.interface.main import parse_arguments
    monkeypatch.setattr(
        sys, "argv",
        ["strix", "-t", "https://x.example/", "--profile", "initial", "-n"],
    )
    args = parse_arguments()
    assert args.scan_mode == "initial"


def test_cli_profile_takes_precedence_over_scan_mode(monkeypatch) -> None:
    """When both are set, --profile wins (per the doc's framing —
    --profile is the wrapper's preferred surface)."""
    from strix.interface.main import parse_arguments
    monkeypatch.setattr(
        sys, "argv",
        [
            "strix", "-t", "https://x.example/",
            "-m", "standard", "--profile", "initial", "-n",
        ],
    )
    args = parse_arguments()
    assert args.scan_mode == "initial"


def test_strix_scan_profile_env_picked_up_when_no_flag(monkeypatch) -> None:
    """STRIX_SCAN_PROFILE=initial sets the mode when neither flag
    is supplied."""
    from strix.interface.main import parse_arguments
    monkeypatch.setattr(
        sys, "argv",
        ["strix", "-t", "https://x.example/", "-n"],
    )
    monkeypatch.setenv("STRIX_SCAN_PROFILE", "initial")
    args = parse_arguments()
    assert args.scan_mode == "initial"


def test_explicit_scan_mode_overrides_env(monkeypatch) -> None:
    """An explicit non-default --scan-mode beats the env var
    (i.e. user wrote `-m standard` knowingly)."""
    from strix.interface.main import parse_arguments
    monkeypatch.setattr(
        sys, "argv",
        [
            "strix", "-t", "https://x.example/", "-m", "standard", "-n",
        ],
    )
    monkeypatch.setenv("STRIX_SCAN_PROFILE", "initial")
    args = parse_arguments()
    assert args.scan_mode == "standard"


# ---------------------------------------------------------------------------
# Skill template
# ---------------------------------------------------------------------------


def test_initial_skill_template_exists() -> None:
    """The skill template must exist for the LLM prompt loader to
    find it. `strix/skills/scan_modes/initial.md`."""
    import strix
    skill_path = (
        Path(strix.__file__).parent / "skills" / "scan_modes" / "initial.md"
    )
    assert skill_path.is_file()
    body = skill_path.read_text(encoding="utf-8")
    # Sanity: front-matter + key directives.
    assert "name: initial" in body
    # The doc-listed coverage areas all named:
    for keyword in (
        "Surface mapping", "Dependency CVE", "Secret scanning",
        "IaC misconfiguration",
    ):
        assert keyword in body, f"missing coverage section: {keyword}"
    # The doc-listed skip list is enumerated:
    for keyword in (
        "MOAK", "Authentication bypass", "business-logic", "Deep crawl",
    ):
        assert keyword.lower() in body.lower(), (
            f"missing skip directive: {keyword}"
        )
