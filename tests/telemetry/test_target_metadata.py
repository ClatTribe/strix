"""Tests for engine-wishlist §3 target-metadata pass-through.

Hermetic — pure JSON file I/O via tmp_path + LLMConfig state
assertions; no LLM / no network."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# load_target_metadata
# ---------------------------------------------------------------------------


def test_load_returns_dict_from_explicit_path(tmp_path) -> None:
    from strix.interface.target_metadata import load_target_metadata

    metadata = {
        "language": "python",
        "framework_hints": ["django", "celery"],
        "tags": ["prod", "pci-scope"],
    }
    p = tmp_path / "meta.json"
    p.write_text(json.dumps(metadata))

    result = load_target_metadata(path=str(p))
    assert result == metadata


def test_load_falls_back_to_env_var(tmp_path, monkeypatch) -> None:
    from strix.interface.target_metadata import load_target_metadata

    metadata = {"language": "go"}
    p = tmp_path / "meta.json"
    p.write_text(json.dumps(metadata))

    monkeypatch.setenv("STRIX_TARGET_METADATA", str(p))
    result = load_target_metadata()
    assert result == {"language": "go"}


def test_explicit_path_takes_precedence_over_env(tmp_path, monkeypatch) -> None:
    from strix.interface.target_metadata import load_target_metadata

    explicit = tmp_path / "explicit.json"
    explicit.write_text(json.dumps({"language": "python"}))
    env_path = tmp_path / "env.json"
    env_path.write_text(json.dumps({"language": "rust"}))

    monkeypatch.setenv("STRIX_TARGET_METADATA", str(env_path))
    result = load_target_metadata(path=str(explicit))
    assert result == {"language": "python"}


def test_load_returns_empty_when_no_source() -> None:
    from strix.interface.target_metadata import load_target_metadata

    # No path, no env var (cleared via the function default).
    if "STRIX_TARGET_METADATA" in os.environ:
        del os.environ["STRIX_TARGET_METADATA"]
    assert load_target_metadata() == {}


def test_load_returns_empty_on_missing_file(tmp_path) -> None:
    from strix.interface.target_metadata import load_target_metadata

    missing = tmp_path / "nope.json"
    assert load_target_metadata(path=str(missing)) == {}


def test_load_returns_empty_on_malformed_json(tmp_path) -> None:
    from strix.interface.target_metadata import load_target_metadata

    p = tmp_path / "bad.json"
    p.write_text("{ this isn't json")
    assert load_target_metadata(path=str(p)) == {}


def test_load_rejects_non_object_top_level(tmp_path) -> None:
    """List / string / number at top level → empty dict + warning."""
    from strix.interface.target_metadata import load_target_metadata

    p = tmp_path / "list.json"
    p.write_text("[1, 2, 3]")
    assert load_target_metadata(path=str(p)) == {}


def test_load_caps_oversized_files(tmp_path) -> None:
    """A 2MB metadata blob is silently ignored — caps runaway."""
    from strix.interface.target_metadata import load_target_metadata

    # 2 MB blob — exceeds the 1 MB cap.
    p = tmp_path / "huge.json"
    p.write_text('{"' + "x" * (2 * 1024 * 1024) + '": 1}')
    assert load_target_metadata(path=str(p)) == {}


# ---------------------------------------------------------------------------
# render_for_prompt
# ---------------------------------------------------------------------------


def test_render_includes_documented_keys() -> None:
    from strix.interface.target_metadata import render_for_prompt

    rendered = render_for_prompt({
        "language": "python",
        "framework_hints": ["django", "celery"],
        "tags": ["prod"],
        "owner": "@payments-team",
    })
    assert "language: python" in rendered
    assert "django, celery" in rendered
    assert "prod" in rendered
    assert "@payments-team" in rendered


def test_render_separates_documented_and_extra_keys() -> None:
    from strix.interface.target_metadata import render_for_prompt

    rendered = render_for_prompt({
        "language": "python",
        "wrapper_custom_field": "value",
    })
    assert "language: python" in rendered
    # Extra keys appear under "Other metadata".
    assert "Other metadata" in rendered
    assert "wrapper_custom_field" in rendered


def test_render_empty_metadata_returns_empty_string() -> None:
    from strix.interface.target_metadata import render_for_prompt

    assert render_for_prompt({}) == ""


def test_render_contains_priority_directive() -> None:
    """The rendered block must tell the model HOW to use the
    metadata — otherwise it's just noise."""
    from strix.interface.target_metadata import render_for_prompt

    rendered = render_for_prompt({"language": "python"})
    assert "prioritise" in rendered.lower()


# ---------------------------------------------------------------------------
# LLMConfig integration
# ---------------------------------------------------------------------------


def test_llm_config_propagates_metadata_into_system_prompt_context(
    monkeypatch,
) -> None:
    """target_metadata kwarg lands in `system_prompt_context` so
    the jinja render picks it up automatically."""
    monkeypatch.setenv("STRIX_LLM", "openai/test-model")
    from strix.llm.config import LLMConfig

    metadata = {
        "language": "python",
        "framework_hints": ["django"],
    }
    cfg = LLMConfig(
        scan_mode="standard",
        model_name="openai/test-model",
        target_metadata=metadata,
    )
    assert cfg.target_metadata == metadata
    assert cfg.system_prompt_context.get("target_metadata") == metadata
    rendered = cfg.system_prompt_context.get("target_metadata_rendered")
    assert isinstance(rendered, str)
    assert "django" in rendered


def test_llm_config_empty_metadata_no_prompt_keys(monkeypatch) -> None:
    """Empty metadata dict doesn't pollute system_prompt_context."""
    monkeypatch.setenv("STRIX_LLM", "openai/test-model")
    from strix.llm.config import LLMConfig

    cfg = LLMConfig(
        scan_mode="standard",
        model_name="openai/test-model",
        target_metadata={},
    )
    assert cfg.target_metadata == {}
    assert "target_metadata" not in cfg.system_prompt_context


def test_llm_config_default_no_metadata(monkeypatch) -> None:
    """Caller omits target_metadata entirely — no breakage."""
    monkeypatch.setenv("STRIX_LLM", "openai/test-model")
    from strix.llm.config import LLMConfig

    cfg = LLMConfig(
        scan_mode="standard", model_name="openai/test-model",
    )
    assert cfg.target_metadata == {}


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_loads_metadata_via_file_flag(monkeypatch, tmp_path) -> None:
    """`--target-metadata-file PATH` populates args.target_metadata."""
    from strix.interface.main import parse_arguments

    p = tmp_path / "m.json"
    p.write_text(json.dumps({"language": "go", "tags": ["prod"]}))

    monkeypatch.setattr(
        sys, "argv",
        [
            "strix", "-t", "https://x.example/",
            "--target-metadata-file", str(p), "-n",
        ],
    )
    args = parse_arguments()
    assert args.target_metadata == {"language": "go", "tags": ["prod"]}


def test_cli_loads_metadata_via_env(monkeypatch, tmp_path) -> None:
    from strix.interface.main import parse_arguments

    p = tmp_path / "m.json"
    p.write_text(json.dumps({"language": "rust"}))

    monkeypatch.setattr(
        sys, "argv",
        ["strix", "-t", "https://x.example/", "-n"],
    )
    monkeypatch.setenv("STRIX_TARGET_METADATA", str(p))
    args = parse_arguments()
    assert args.target_metadata == {"language": "rust"}


def test_cli_no_metadata_when_neither_set(monkeypatch) -> None:
    from strix.interface.main import parse_arguments

    monkeypatch.delenv("STRIX_TARGET_METADATA", raising=False)
    monkeypatch.setattr(
        sys, "argv",
        ["strix", "-t", "https://x.example/", "-n"],
    )
    args = parse_arguments()
    assert args.target_metadata == {}


def test_cli_malformed_metadata_falls_back_to_empty(
    monkeypatch, tmp_path,
) -> None:
    """Malformed file → empty dict, scan continues."""
    from strix.interface.main import parse_arguments

    p = tmp_path / "bad.json"
    p.write_text("{not even json")

    monkeypatch.setattr(
        sys, "argv",
        [
            "strix", "-t", "https://x.example/",
            "--target-metadata-file", str(p), "-n",
        ],
    )
    args = parse_arguments()
    assert args.target_metadata == {}
