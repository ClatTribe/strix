"""Per-ecosystem lockfile parser tests.

Each ecosystem has at least one canonical happy-path fixture under
`tests/sca/fixtures/`. We pin behaviour for:
  * extracting (name, version) pairs
  * canonicalising names (lowercase, dash-vs-underscore for pypi)
  * dev_only flag wiring
  * skipping unsupported / unparseable entries
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Importing this package triggers parser registration via the
# side-effect imports in `parsers/__init__.py`.
import strix.sca.parsers  # noqa: F401
from strix.sca.parsers.base import (
    Package,
    find_lockfiles,
    parse_lockfile,
)


FIXTURES = Path(__file__).parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _by_name(pkgs: list[Package]) -> dict[str, Package]:
    """Index a Package list by name. Asserts uniqueness — every
    fixture in this suite has a single version per package."""
    out: dict[str, Package] = {}
    for p in pkgs:
        assert p.name not in out, f"duplicate package: {p.name}"
        out[p.name] = p
    return out


# ---------------------------------------------------------------------------
# package-lock.json (npm v2/v3)
# ---------------------------------------------------------------------------


def test_package_lock_v3_extracts_packages() -> None:
    pkgs = parse_lockfile(FIXTURES / "package-lock.json")
    by = _by_name(pkgs)
    # All four entries from the fixture: express, qs (transitive),
    # lodash, jest (dev).
    assert {"express", "qs", "lodash", "jest"} <= set(by.keys())
    assert by["express"].version == "4.17.1"
    assert by["express"].ecosystem == "npm"
    assert by["lodash"].version == "4.17.20"
    assert by["qs"].version == "6.7.0"


def test_package_lock_v3_dev_only_flag() -> None:
    pkgs = parse_lockfile(FIXTURES / "package-lock.json")
    by = _by_name(pkgs)
    assert by["jest"].dev_only is True
    assert by["express"].dev_only is False


# ---------------------------------------------------------------------------
# yarn.lock (Yarn 1 classic)
# ---------------------------------------------------------------------------


def test_yarn_lock_classic_extracts_packages() -> None:
    pkgs = parse_lockfile(FIXTURES / "yarn.lock")
    by = _by_name(pkgs)
    assert "express" in by and by["express"].version == "4.17.1"
    assert "lodash" in by and by["lodash"].version == "4.17.20"
    # Scoped names preserve the leading @scope/.
    assert "@scope/utility" in by
    assert by["@scope/utility"].version == "1.5.2"


def test_yarn_lock_all_ecosystem_npm() -> None:
    pkgs = parse_lockfile(FIXTURES / "yarn.lock")
    assert pkgs and all(p.ecosystem == "npm" for p in pkgs)


# ---------------------------------------------------------------------------
# pnpm-lock.yaml
# ---------------------------------------------------------------------------


def test_pnpm_lock_extracts_packages() -> None:
    pkgs = parse_lockfile(FIXTURES / "pnpm-lock.yaml")
    by = _by_name(pkgs)
    assert "express" in by and by["express"].version == "4.17.1"
    assert "lodash" in by and by["lodash"].version == "4.17.20"
    assert "jest" in by and by["jest"].version == "29.5.0"


def test_pnpm_lock_dev_only_flag() -> None:
    pkgs = parse_lockfile(FIXTURES / "pnpm-lock.yaml")
    by = _by_name(pkgs)
    assert by["jest"].dev_only is True
    assert by["express"].dev_only is False


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------


def test_requirements_pinned_only() -> None:
    pkgs = parse_lockfile(FIXTURES / "requirements.txt")
    by = _by_name(pkgs)
    # 3 pinned: django, requests, flask. Editable + range are skipped.
    assert set(by.keys()) == {"django", "requests", "flask"}
    assert by["django"].version == "4.2.0"
    assert all(p.ecosystem == "pypi" for p in pkgs)


def test_requirements_skips_editable_and_ranges() -> None:
    pkgs = parse_lockfile(FIXTURES / "requirements.txt")
    names = {p.name for p in pkgs}
    # urllib3 has a range specifier (>=) — must be skipped.
    assert "urllib3" not in names
    # editable install -e ... must be skipped.
    assert "foo" not in names


# ---------------------------------------------------------------------------
# Pipfile.lock
# ---------------------------------------------------------------------------


def test_pipfile_lock_default_and_develop() -> None:
    pkgs = parse_lockfile(FIXTURES / "Pipfile.lock")
    by = _by_name(pkgs)
    assert by["django"].version == "4.2.0"
    assert by["django"].dev_only is False
    assert by["requests"].version == "2.28.2"
    # pytest is in `develop` → dev_only.
    assert by["pytest"].dev_only is True


# ---------------------------------------------------------------------------
# poetry.lock + uv.lock
# ---------------------------------------------------------------------------


def test_poetry_lock_extracts_categories() -> None:
    pkgs = parse_lockfile(FIXTURES / "poetry.lock")
    by = _by_name(pkgs)
    assert by["django"].version == "4.2.0"
    assert by["django"].dev_only is False
    # Jinja2 → canonical lowercase name.
    assert "jinja2" in by
    # pytest is category=dev → dev_only.
    assert by["pytest"].dev_only is True


def test_uv_lock_extracts_packages() -> None:
    pkgs = parse_lockfile(FIXTURES / "uv.lock")
    by = _by_name(pkgs)
    assert by["flask"].version == "2.3.0"
    assert by["werkzeug"].version == "2.3.7"
    assert all(p.ecosystem == "pypi" for p in pkgs)


# ---------------------------------------------------------------------------
# Cargo.lock
# ---------------------------------------------------------------------------


def test_cargo_lock_extracts_packages() -> None:
    pkgs = parse_lockfile(FIXTURES / "Cargo.lock")
    by = _by_name(pkgs)
    assert by["serde"].version == "1.0.160"
    assert by["tokio"].version == "1.28.0"
    assert all(p.ecosystem == "cargo" for p in pkgs)


# ---------------------------------------------------------------------------
# Gemfile.lock
# ---------------------------------------------------------------------------


def test_gemfile_lock_extracts_top_level_packages() -> None:
    pkgs = parse_lockfile(FIXTURES / "Gemfile.lock")
    by = _by_name(pkgs)
    # Top-level (4-space) entries become packages; nested deps are skipped.
    assert by["actionview"].version == "7.0.4"
    assert by["activesupport"].version == "7.0.4"
    assert by["rack"].version == "2.2.6.4"
    assert by["nokogiri"].version == "1.13.10"
    assert all(p.ecosystem == "rubygems" for p in pkgs)


# ---------------------------------------------------------------------------
# composer.lock
# ---------------------------------------------------------------------------


def test_composer_lock_extracts_packages_and_dev() -> None:
    pkgs = parse_lockfile(FIXTURES / "composer.lock")
    by = _by_name(pkgs)
    # Composer pins as "v5.4.20" — the leading "v" is stripped.
    assert by["symfony/console"].version == "5.4.20"
    assert by["symfony/console"].dev_only is False
    assert by["monolog/monolog"].version == "2.8.0"
    # phpunit is in packages-dev → dev_only.
    assert by["phpunit/phpunit"].dev_only is True
    assert all(p.ecosystem == "composer" for p in pkgs)


# ---------------------------------------------------------------------------
# go.sum / go.mod
# ---------------------------------------------------------------------------


def test_go_sum_extracts_modules() -> None:
    pkgs = parse_lockfile(FIXTURES / "go.sum")
    by = _by_name(pkgs)
    assert by["github.com/gin-gonic/gin"].version == "v1.9.0"
    assert by["github.com/sirupsen/logrus"].version == "v1.9.0"
    # Pseudo-version handled like any other.
    assert "golang.org/x/crypto" in by
    # +incompatible suffix stripped.
    assert by["github.com/old/incompat"].version == "v1.4.0"
    assert all(p.ecosystem == "go" for p in pkgs)


def test_go_mod_extracts_direct_deps() -> None:
    pkgs = parse_lockfile(FIXTURES / "go.mod")
    by = _by_name(pkgs)
    assert by["github.com/gin-gonic/gin"].version == "v1.9.0"
    assert by["github.com/sirupsen/logrus"].version == "v1.9.0"


# ---------------------------------------------------------------------------
# parse_lockfile dispatch + find_lockfiles
# ---------------------------------------------------------------------------


def test_parse_lockfile_unknown_format(tmp_path: Path) -> None:
    bogus = tmp_path / "weird.thing"
    bogus.write_text("...")
    assert parse_lockfile(bogus) == []


def test_parse_lockfile_missing_file(tmp_path: Path) -> None:
    assert parse_lockfile(tmp_path / "nope.json") == []


def test_parse_lockfile_corrupt_json(tmp_path: Path) -> None:
    f = tmp_path / "package-lock.json"
    f.write_text("{not json")
    # Parser swallows the error and returns [].
    assert parse_lockfile(f) == []


def test_find_lockfiles_skips_node_modules(tmp_path: Path) -> None:
    # Real lockfile at root.
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {}}'
    )
    # Lockfile inside node_modules (must be skipped).
    nm = tmp_path / "node_modules" / "x"
    nm.mkdir(parents=True)
    (nm / "package-lock.json").write_text("{}")
    found = find_lockfiles(tmp_path)
    assert any(p.name == "package-lock.json" for p in found)
    assert not any("node_modules" in str(p) for p in found)


def test_find_lockfiles_walks_all_supported_formats(tmp_path: Path) -> None:
    # Drop one of each supported lockfile in a subdirectory.
    (tmp_path / "Cargo.lock").write_text("[[package]]\nname=\"x\"\nversion=\"1\"\n")
    sub = tmp_path / "py"
    sub.mkdir()
    (sub / "requirements.txt").write_text("requests==1.0\n")
    (sub / "Pipfile.lock").write_text('{"default": {}, "develop": {}}')
    found = {p.name for p in find_lockfiles(tmp_path)}
    assert "Cargo.lock" in found
    assert "requirements.txt" in found
    assert "Pipfile.lock" in found
