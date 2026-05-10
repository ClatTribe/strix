"""Unit tests for `strix.sca.reachability` — Phase 6.4
import-level reachability scoring.

Pins:
  * Direct vs transitive_only vs unused vs unknown classification.
  * Severity demotion math + KEV / EPSS overrides.
  * npm import extraction (subpaths, scoped, relative skip).
  * pypi import extraction (from / import / aliasing).
  * Repo walk skips node_modules and other heavy dirs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.sca.parsers.base import Package
from strix.sca.reachability import (
    PackageReachability,
    REACH_DIRECT,
    REACH_TRANSITIVE_ONLY,
    REACH_UNKNOWN,
    REACH_UNUSED,
    RepoImports,
    _extract_npm_imports,
    _extract_pypi_imports,
    annotate_matches,
    classify_package,
    collect_repo_imports,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pkg(name: str, *, ecosystem: str = "npm", direct: bool = True,
         version: str = "1.0.0") -> Package:
    return Package(
        ecosystem=ecosystem, name=name, version=version, direct=direct,
        source_path="lockfile",
    )


def _imports(npm: set[str] | None = None, pypi: set[str] | None = None,
             *, js_files: int = 1, py_files: int = 1) -> RepoImports:
    return RepoImports(
        npm_imports=npm or set(),
        pypi_imports=pypi or set(),
        js_files_scanned=js_files,
        py_files_scanned=py_files,
        importing_files_by_pkg={},
    )


# ---------------------------------------------------------------------------
# npm import extraction
# ---------------------------------------------------------------------------


def test_npm_extract_require_call() -> None:
    code = 'const _ = require("lodash");'
    assert _extract_npm_imports(code) == {"lodash"}


def test_npm_extract_esm_import() -> None:
    code = "import express from 'express';"
    assert _extract_npm_imports(code) == {"express"}


def test_npm_extract_named_import() -> None:
    code = "import { merge } from 'lodash';"
    assert _extract_npm_imports(code) == {"lodash"}


def test_npm_extract_subpath_import_normalises_to_top_level() -> None:
    """`lodash/merge` and `lodash/fp/cloneDeep` both → "lodash"."""
    code = """
        const merge = require('lodash/merge');
        import cloneDeep from 'lodash/fp/cloneDeep';
    """
    assert _extract_npm_imports(code) == {"lodash"}


def test_npm_extract_scoped_package_preserved() -> None:
    code = "import x from '@scope/utility';"
    assert _extract_npm_imports(code) == {"@scope/utility"}


def test_npm_extract_scoped_subpath() -> None:
    """`@scope/pkg/subpath` → `@scope/pkg`."""
    code = "import x from '@scope/pkg/dist/foo';"
    assert _extract_npm_imports(code) == {"@scope/pkg"}


def test_npm_extract_skips_relative() -> None:
    code = """
        import a from './local';
        import b from '../parent';
        const c = require('/abs/path');
    """
    assert _extract_npm_imports(code) == set()


def test_npm_extract_skips_node_builtin_prefix() -> None:
    code = "const fs = require('node:fs');"
    assert _extract_npm_imports(code) == set()


def test_npm_extract_multiple_packages() -> None:
    code = """
        const _ = require('lodash');
        import express from 'express';
        const ejs = require('ejs');
    """
    assert _extract_npm_imports(code) == {"lodash", "express", "ejs"}


# ---------------------------------------------------------------------------
# pypi import extraction
# ---------------------------------------------------------------------------


def test_pypi_extract_simple_import() -> None:
    code = "import django"
    assert "django" in _extract_pypi_imports(code)


def test_pypi_extract_from_import() -> None:
    code = "from django.db import models"
    assert "django" in _extract_pypi_imports(code)


def test_pypi_extract_top_level_only() -> None:
    """`from foo.bar.baz import X` → record `foo` only."""
    code = "from foo.bar.baz import X"
    assert _extract_pypi_imports(code) == {"foo"}


def test_pypi_extract_multiple_on_one_line() -> None:
    code = "import a, b.c, d as e"
    out = _extract_pypi_imports(code)
    assert {"a", "b", "d"} <= out


def test_pypi_extract_alias_yaml_to_pyyaml() -> None:
    """`import yaml` → distribution name is `pyyaml`."""
    code = "import yaml"
    out = _extract_pypi_imports(code)
    assert "yaml" in out
    assert "pyyaml" in out  # alias expansion


def test_pypi_extract_alias_bs4_to_beautifulsoup4() -> None:
    code = "from bs4 import BeautifulSoup"
    out = _extract_pypi_imports(code)
    assert "beautifulsoup4" in out


def test_pypi_extract_alias_jwt_to_pyjwt() -> None:
    code = "import jwt"
    out = _extract_pypi_imports(code)
    assert "pyjwt" in out


# ---------------------------------------------------------------------------
# classify_package — the core logic
# ---------------------------------------------------------------------------


def test_classify_direct_import_when_imported() -> None:
    pkg = _pkg("lodash")
    repo = _imports(npm={"lodash"})
    repo.importing_files_by_pkg[("npm", "lodash")] = ["app.js"]
    r = classify_package(pkg, repo)
    assert r.status == REACH_DIRECT
    assert "app.js" in r.importing_files


def test_classify_unused_for_unimported_direct_dep() -> None:
    """Direct dep in lockfile but no import → unused (dead dep)."""
    pkg = _pkg("never-used", direct=True)
    repo = _imports(npm=set())
    r = classify_package(pkg, repo)
    assert r.status == REACH_UNUSED


def test_classify_transitive_only_for_unimported_transitive() -> None:
    """Transitive dep with no import → transitive_only (intermediate
    dep brought it in, app code never touches it)."""
    pkg = _pkg("ms", direct=False)
    repo = _imports(npm={"express"})  # express imported, not ms
    r = classify_package(pkg, repo)
    assert r.status == REACH_TRANSITIVE_ONLY


def test_classify_unknown_when_no_source_files_for_ecosystem() -> None:
    pkg = _pkg("django", ecosystem="pypi")
    repo = _imports(py_files=0)  # no .py files scanned
    r = classify_package(pkg, repo)
    assert r.status == REACH_UNKNOWN


def test_classify_unknown_for_unsupported_ecosystem() -> None:
    """v1 only handles npm + pypi — cargo / composer / go return
    `unknown` so severity isn't quietly demoted."""
    pkg = _pkg("serde", ecosystem="cargo")
    repo = _imports()
    r = classify_package(pkg, repo)
    assert r.status == REACH_UNKNOWN


def test_classify_pypi_direct_import() -> None:
    pkg = _pkg("django", ecosystem="pypi")
    repo = _imports(pypi={"django"})
    repo.importing_files_by_pkg[("pypi", "django")] = ["app.py"]
    r = classify_package(pkg, repo)
    assert r.status == REACH_DIRECT


# ---------------------------------------------------------------------------
# Severity demotion + KEV / EPSS overrides
# ---------------------------------------------------------------------------


def test_demote_unused_drops_two_tiers() -> None:
    r = PackageReachability(status=REACH_UNUSED, importing_files=[], reason="")
    assert r.adjusted_severity("critical", kev=False, epss=0.0) == "medium"
    assert r.adjusted_severity("high", kev=False, epss=0.0) == "low"
    assert r.adjusted_severity("medium", kev=False, epss=0.0) == "info"


def test_demote_transitive_only_drops_one_tier() -> None:
    r = PackageReachability(
        status=REACH_TRANSITIVE_ONLY, importing_files=[], reason="",
    )
    assert r.adjusted_severity("critical", kev=False, epss=0.0) == "high"
    assert r.adjusted_severity("high", kev=False, epss=0.0) == "medium"


def test_demote_direct_import_no_op() -> None:
    r = PackageReachability(
        status=REACH_DIRECT, importing_files=["app.js"], reason="",
    )
    for sev in ("info", "low", "medium", "high", "critical"):
        assert r.adjusted_severity(sev, kev=False, epss=0.0) == sev


def test_demote_unknown_no_op() -> None:
    """`unknown` must never demote — we don't penalise findings when
    we can't see the source tree."""
    r = PackageReachability(status=REACH_UNKNOWN, importing_files=[], reason="")
    assert r.adjusted_severity("critical", kev=False, epss=0.0) == "critical"


def test_kev_overrides_demotion() -> None:
    """KEV-listed CVEs must NEVER be demoted by reachability — they're
    actively exploited; even a "dead" package is a real threat."""
    r = PackageReachability(status=REACH_UNUSED, importing_files=[], reason="")
    assert r.adjusted_severity("critical", kev=True, epss=0.0) == "critical"
    assert r.adjusted_severity("high", kev=True, epss=0.0) == "high"


def test_high_epss_overrides_demotion() -> None:
    """EPSS ≥ 0.5 (high probability of exploitation in the next 30
    days) is the same override class as KEV."""
    r = PackageReachability(
        status=REACH_TRANSITIVE_ONLY, importing_files=[], reason="",
    )
    assert r.adjusted_severity("high", kev=False, epss=0.7) == "high"
    assert r.adjusted_severity("high", kev=False, epss=0.5) == "high"
    # Below threshold → demote applies normally.
    assert r.adjusted_severity("high", kev=False, epss=0.49) == "medium"


def test_demote_floor_at_info() -> None:
    """Two-tier demotion from `low` should clamp at `info`, not error."""
    r = PackageReachability(status=REACH_UNUSED, importing_files=[], reason="")
    assert r.adjusted_severity("low", kev=False, epss=0.0) == "info"
    assert r.adjusted_severity("info", kev=False, epss=0.0) == "info"


# ---------------------------------------------------------------------------
# Repo-walk integration (real tmpfs)
# ---------------------------------------------------------------------------


def test_collect_repo_imports_finds_npm_and_pypi(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const _ = require('lodash');\n"
        "import express from 'express';\n"
    )
    (tmp_path / "model.py").write_text(
        "import django\n"
        "from requests import get\n"
    )
    repo = collect_repo_imports(tmp_path)
    assert "lodash" in repo.npm_imports
    assert "express" in repo.npm_imports
    assert "django" in repo.pypi_imports
    assert "requests" in repo.pypi_imports
    assert repo.js_files_scanned == 1
    assert repo.py_files_scanned == 1


def test_collect_repo_imports_skips_node_modules(tmp_path: Path) -> None:
    """Critical correctness check: every package's own imports live
    under node_modules. If we descended in, every transitive dep
    would falsely look directly imported (because the dep itself
    requires it)."""
    (tmp_path / "app.js").write_text("const x = require('app-pkg');")
    nm = tmp_path / "node_modules" / "evil"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text("const evil = require('evil-only-pkg');")
    repo = collect_repo_imports(tmp_path)
    assert "app-pkg" in repo.npm_imports
    assert "evil-only-pkg" not in repo.npm_imports


def test_collect_repo_imports_skips_dot_git_and_venv(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import django")
    git = tmp_path / ".git"
    git.mkdir()
    (git / "spurious.py").write_text("import this_should_not_appear")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "package.py").write_text("import alsohidden")
    repo = collect_repo_imports(tmp_path)
    assert "django" in repo.pypi_imports
    assert "this_should_not_appear" not in repo.pypi_imports
    assert "alsohidden" not in repo.pypi_imports


def test_collect_repo_imports_records_importing_files(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("require('lodash');")
    (tmp_path / "b.js").write_text("require('lodash');")
    (tmp_path / "c.js").write_text("require('express');")
    repo = collect_repo_imports(tmp_path)
    files = repo.importing_files_by_pkg[("npm", "lodash")]
    assert len(files) == 2
    assert any("a.js" in f for f in files)
    assert any("b.js" in f for f in files)


# ---------------------------------------------------------------------------
# annotate_matches — bulk classifier
# ---------------------------------------------------------------------------


def test_annotate_matches_classifies_each_package(tmp_path: Path) -> None:
    """End-to-end: take a Package list + a repo, produce a verdict
    dict keyed by (ecosystem, name)."""
    (tmp_path / "app.js").write_text(
        "const _ = require('lodash');\n"
    )
    from strix.sca.match import PackageMatch
    matches = [
        PackageMatch(package=_pkg("lodash"), cves=[]),
        PackageMatch(package=_pkg("never-used", direct=True), cves=[]),
        PackageMatch(package=_pkg("ms", direct=False), cves=[]),
    ]
    out = annotate_matches(matches, repo_path=tmp_path)
    assert out[("npm", "lodash")].status == REACH_DIRECT
    assert out[("npm", "never-used")].status == REACH_UNUSED
    assert out[("npm", "ms")].status == REACH_TRANSITIVE_ONLY
