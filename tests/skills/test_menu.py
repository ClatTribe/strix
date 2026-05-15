"""Tests for the §5 progressive-disclosure skills menu.

The menu walks `strix/skills/<category>/*.md`, parses frontmatter,
and emits a categorised string for the system prompt. These tests
pin:

  * Frontmatter parsing — name/description required, triggers optional
  * Trigger list parsing — [a, b, c] AND `a, b, c` shapes
  * Excluded categories (`scan_modes`, `coordination`) are skipped
  * Menu structure — header + category labels + bullet entries
  * Category ordering — preferred list first, rest alphabetical, stable
  * Kill switch (STRIX_SKILLS_MENU_DISABLED) returns empty string
  * Env-driven category filter
  * Env-driven max-per-category cap
  * Defensive: malformed files don't break the whole menu
  * Real-skill smoke — every shipped skill parses
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.skills import menu as m


# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------


def test_parse_basic_frontmatter(tmp_path: Path) -> None:
    f = tmp_path / "skill.md"
    f.write_text(
        "---\n"
        "name: my_skill\n"
        "description: Test skill description.\n"
        "---\n"
        "\n# Body\n",
        encoding="utf-8",
    )
    result = m.parse_skill_frontmatter(f)
    assert result == {
        "name": "my_skill",
        "description": "Test skill description.",
    }


def test_parse_frontmatter_with_triggers_list(tmp_path: Path) -> None:
    f = tmp_path / "skill.md"
    f.write_text(
        "---\n"
        "name: s\n"
        "description: d\n"
        "triggers: [alpha, beta, gamma]\n"
        "---\n",
        encoding="utf-8",
    )
    result = m.parse_skill_frontmatter(f)
    assert result is not None
    assert result["triggers"] == ["alpha", "beta", "gamma"]


def test_parse_frontmatter_with_triggers_csv(tmp_path: Path) -> None:
    """Both `[a, b]` and `a, b` shapes are accepted — humans write both."""
    f = tmp_path / "skill.md"
    f.write_text(
        "---\nname: s\ndescription: d\ntriggers: alpha, beta, gamma\n---\n",
        encoding="utf-8",
    )
    result = m.parse_skill_frontmatter(f)
    assert result is not None
    assert result["triggers"] == ["alpha", "beta", "gamma"]


def test_parse_triggers_dedup_preserves_order() -> None:
    assert m._parse_triggers("[foo, bar, foo, baz]") == ["foo", "bar", "baz"]


def test_parse_triggers_empty_returns_empty_list() -> None:
    assert m._parse_triggers("") == []
    assert m._parse_triggers("[]") == []


def test_parse_triggers_strips_quotes() -> None:
    assert m._parse_triggers("['quoted', \"double\", unquoted]") == [
        "quoted", "double", "unquoted",
    ]


def test_parse_frontmatter_missing_required_returns_none(tmp_path: Path) -> None:
    f = tmp_path / "skill.md"
    f.write_text("---\nname: s\n---\nbody\n", encoding="utf-8")
    assert m.parse_skill_frontmatter(f) is None


def test_parse_frontmatter_no_block_returns_none(tmp_path: Path) -> None:
    f = tmp_path / "skill.md"
    f.write_text("# Just a body, no frontmatter\n", encoding="utf-8")
    assert m.parse_skill_frontmatter(f) is None


def test_parse_frontmatter_unreadable_returns_none(tmp_path: Path) -> None:
    """Defensive: a single bad file doesn't crash the parser."""
    bogus = tmp_path / "does_not_exist.md"
    assert m.parse_skill_frontmatter(bogus) is None


# ---------------------------------------------------------------------------
# Menu generation — using the real strix/skills/ directory
# ---------------------------------------------------------------------------


def test_menu_has_header_and_categories(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_SKILLS_MENU_CATEGORIES", raising=False)
    monkeypatch.delenv("STRIX_SKILLS_MENU_MAX_PER_CATEGORY", raising=False)

    out = m.generate_skills_menu()

    assert "Available Skills" in out
    # Vulnerabilities are the first preferred category and always present.
    assert "VULNERABILITIES:" in out
    # The footer should tell the agent to use `load_skill` for bodies.
    assert "load_skill" in out


def test_menu_excludes_internal_categories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`scan_modes` and `coordination` are internal and must not
    appear in the menu the lead sees."""
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    out = m.generate_skills_menu()
    assert "SCAN_MODES:" not in out
    assert "COORDINATION:" not in out


def test_menu_lists_known_real_skills(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Smoke check — a handful of well-known shipped skills appear."""
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    out = m.generate_skills_menu()
    # These three are stable, well-known skills.
    assert "**sql_injection**" in out
    assert "**xss**" in out
    assert "**ssrf**" in out


def test_menu_category_order_is_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-rendering must produce byte-identical output — the prompt
    cache hates non-determinism."""
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    a = m.generate_skills_menu()
    b = m.generate_skills_menu()
    assert a == b


def test_menu_vulnerabilities_appears_before_tooling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Decepticon's claim is that ordering matters for selection —
    vulnerabilities is the bread-and-butter category and should
    come first."""
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    out = m.generate_skills_menu()
    v_idx = out.index("VULNERABILITIES:")
    t_idx = out.index("TOOLING:")
    assert v_idx < t_idx


# ---------------------------------------------------------------------------
# Kill switch & env config
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "True", "yes", "ON"])
def test_kill_switch_returns_empty(
    val: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SKILLS_MENU_DISABLED", val)
    assert m.generate_skills_menu() == ""


def test_kill_switch_unset_is_falsy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    assert not m.is_menu_disabled()


def test_env_category_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_SKILLS_MENU_CATEGORIES", "tooling")
    out = m.generate_skills_menu()
    assert "TOOLING:" in out
    assert "VULNERABILITIES:" not in out


def test_env_category_filter_csv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.setenv(
        "STRIX_SKILLS_MENU_CATEGORIES", "tooling, vulnerabilities",
    )
    out = m.generate_skills_menu()
    assert "TOOLING:" in out
    assert "VULNERABILITIES:" in out
    assert "TECHNOLOGIES:" not in out


def test_env_category_filter_unknown_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Filtering down to a non-existent category yields empty menu,
    which the template handles as a no-render."""
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_SKILLS_MENU_CATEGORIES", "does_not_exist")
    assert m.generate_skills_menu() == ""


def test_env_max_per_category_caps_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_SKILLS_MENU_CATEGORIES", "vulnerabilities")
    monkeypatch.setenv("STRIX_SKILLS_MENU_MAX_PER_CATEGORY", "2")
    out = m.generate_skills_menu()
    # Two bullets in the vulnerabilities block, plus the header and
    # the footer paragraph. Count bullet entries.
    body = out.split("VULNERABILITIES:")[1].split("\n\n")[0]
    bullet_count = sum(1 for ln in body.splitlines() if ln.strip().startswith("- **"))
    assert bullet_count == 2


def test_env_max_per_category_invalid_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.setenv("STRIX_SKILLS_MENU_MAX_PER_CATEGORY", "not-a-number")
    # Should not raise, and should produce the full menu.
    out = m.generate_skills_menu()
    assert "Available Skills" in out


# ---------------------------------------------------------------------------
# Programmatic API (overrides the env)
# ---------------------------------------------------------------------------


def test_programmatic_category_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_SKILLS_MENU_CATEGORIES", raising=False)
    out = m.generate_skills_menu(category_filter={"protocols"})
    assert "PROTOCOLS:" in out
    assert "VULNERABILITIES:" not in out


def test_programmatic_max_per_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_SKILLS_MENU_MAX_PER_CATEGORY", raising=False)
    out_capped = m.generate_skills_menu(
        category_filter={"vulnerabilities"}, max_per_category=1,
    )
    out_full = m.generate_skills_menu(category_filter={"vulnerabilities"})
    assert len(out_capped) < len(out_full)


# ---------------------------------------------------------------------------
# Defensive — bad files don't break the menu
# ---------------------------------------------------------------------------


def test_real_skills_all_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every shipped SKILL.md must have parseable frontmatter — this
    guards against regressions when skills are added/edited."""
    from strix.utils.resource_paths import get_strix_resource_path
    skills_dir = get_strix_resource_path("skills")
    skipped: list[str] = []
    for category_dir in skills_dir.iterdir():
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        if category_dir.name in m._EXCLUDED_CATEGORIES:
            continue
        for skill_path in category_dir.glob("*.md"):
            parsed = m.parse_skill_frontmatter(skill_path)
            if parsed is None:
                skipped.append(str(skill_path.relative_to(skills_dir)))
    assert not skipped, (
        "Skill files missing required frontmatter: "
        + ", ".join(skipped)
    )


# ---------------------------------------------------------------------------
# get_menu_stats — telemetry shape
# ---------------------------------------------------------------------------


def test_get_menu_stats_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STRIX_SKILLS_MENU_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_SKILLS_MENU_CATEGORIES", raising=False)
    monkeypatch.delenv("STRIX_SKILLS_MENU_MAX_PER_CATEGORY", raising=False)
    stats = m.get_menu_stats()
    assert stats["enabled"] is True
    assert stats["categories"] > 0
    assert stats["skills"] > 0
    assert "category_filter" in stats


def test_get_menu_stats_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_SKILLS_MENU_DISABLED", "1")
    stats = m.get_menu_stats()
    assert stats == {"enabled": False, "categories": 0, "skills": 0}
