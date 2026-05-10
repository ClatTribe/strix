"""Integration tests for Phase 6.6 (malicious heuristics) + 6.7
(license compliance) wired through `scan_sca_lockfiles`.

These exercise the full pipeline: real lockfile on disk → parsed
→ analysed → finding emitted with the right category, severity,
and `tool_metadata` rollup. The unit tests in `test_malicious.py`
+ `test_licenses.py` prove the math; these prove the integration.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.sca.tools import scan_sca_lockfiles
from strix.threat_intel import cache as ti_cache


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


# ---------------------------------------------------------------------------
# Helpers — build a tiny repo with a planted condition
# ---------------------------------------------------------------------------


def _write_lockfile(src: Path, packages: list[dict]) -> None:
    """Write a minimal package-lock.json v3 with the supplied
    package entries. Each `packages` item has the shape:
        {"name": str, "version": str, "license": ..., "dev": bool,
         "hasInstallScript": bool}
    """
    pkgs = {
        "": {"dependencies": {p["name"]: p["version"] for p in packages}},
    }
    for p in packages:
        node_key = f"node_modules/{p['name']}"
        pkgs[node_key] = {
            "version": p["version"],
            "license": p.get("license"),
        }
        if p.get("hasInstallScript"):
            pkgs[node_key]["hasInstallScript"] = True
        if p.get("dev"):
            pkgs[node_key]["dev"] = True
    src.mkdir(exist_ok=True)
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0",
        "lockfileVersion": 3, "requires": True,
        "packages": pkgs,
    }))
    # Stub source so reachability has something to walk; we don't
    # care about the imports in these tests because malicious /
    # license analyses are independent of reachability.
    (src / "app.js").write_text("// stub")


# ---------------------------------------------------------------------------
# 6.6 — typosquat surfacing
# ---------------------------------------------------------------------------


def test_typosquat_finding_emitted(tmp_path: Path, tmp_cache) -> None:
    """A package named `lodahs` (typo of `lodash`) → emits a
    `malicious_dependency` finding tagged with the typosquat
    indicator."""
    _write_lockfile(tmp_path / "src", [
        {"name": "lodahs", "version": "1.0.0", "license": "MIT"},
        {"name": "ok-pkg", "version": "1.0.0", "license": "MIT"},
    ])
    result = scan_sca_lockfiles(repo_path=str(tmp_path / "src"))
    assert result["status"] == "ok"
    findings = [d for d in result["findings"]
                if d["category"] == "malicious_dependency"]
    titles = " | ".join(f["title"] for f in findings)
    assert any("lodahs" in t for t in [f["title"] for f in findings]), titles
    assert any("typosquat" in t for t in [f["title"] for f in findings]), titles


def test_install_script_finding_for_transitive_dep(
    tmp_path: Path, tmp_cache,
) -> None:
    """A transitive dep with hasInstallScript=True → high-severity
    `malicious_dependency` finding."""
    pkgs = {
        "": {"dependencies": {"sharp": "1.0.0"}},
        "node_modules/sharp": {"version": "1.0.0", "license": "MIT"},
        # Transitive: not in the root deps list, has install hook.
        "node_modules/sharp/node_modules/evil-tx": {
            "version": "1.0.0", "license": "MIT",
            "hasInstallScript": True,
        },
    }
    src = tmp_path / "src"
    src.mkdir()
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0",
        "lockfileVersion": 3, "requires": True,
        "packages": pkgs,
    }))
    (src / "app.js").write_text("// stub")

    result = scan_sca_lockfiles(repo_path=str(src))
    findings = [d for d in result["findings"]
                if d["category"] == "malicious_dependency"]
    install_script_findings = [
        f for f in findings if "install_script" in f["title"]
    ]
    assert install_script_findings, [f["title"] for f in findings]
    # Transitive → high severity.
    f = install_script_findings[0]
    assert f["severity"] == "high"


def test_malicious_disabled_skips_pass(tmp_path: Path, tmp_cache) -> None:
    """`with_malicious_detection=False` → no malicious_dependency
    findings even when patterns are present."""
    _write_lockfile(tmp_path / "src", [
        {"name": "lodahs", "version": "1.0.0", "license": "MIT"},
    ])
    result = scan_sca_lockfiles(
        repo_path=str(tmp_path / "src"),
        with_malicious_detection=False,
    )
    findings = [d for d in result["findings"]
                if d["category"] == "malicious_dependency"]
    assert findings == []
    assert result["tool_metadata"]["malicious"]["enabled"] is False


def test_malicious_stats_in_tool_metadata(tmp_path: Path, tmp_cache) -> None:
    """The wrapper-facing rollup: `tool_metadata.malicious.by_indicator`
    counts each indicator type so dashboards can render headline
    numbers without recounting."""
    _write_lockfile(tmp_path / "src", [
        {"name": "lodahs", "version": "1.0.0", "license": "MIT"},
        {"name": "reqests", "version": "1.0.0", "license": "MIT"},
    ])
    # Force pypi shape for one to test mixed-ecosystem rollup.
    src = tmp_path / "py"
    src.mkdir()
    (src / "requirements.txt").write_text("reqests==1.0.0\n")
    (src / "package-lock.json").write_text(json.dumps({
        "name": "demo", "version": "1.0.0",
        "lockfileVersion": 3, "requires": True,
        "packages": {
            "": {"dependencies": {"lodahs": "1.0.0"}},
            "node_modules/lodahs": {"version": "1.0.0", "license": "MIT"},
        },
    }))
    (src / "app.js").write_text("// stub")

    result = scan_sca_lockfiles(repo_path=str(src))
    md = result["tool_metadata"]["malicious"]
    assert md["enabled"] is True
    assert md["by_indicator"]["typosquat"] >= 2  # lodahs + reqests


# ---------------------------------------------------------------------------
# 6.7 — license compliance surfacing
# ---------------------------------------------------------------------------


def test_gpl_emits_license_violation_finding(
    tmp_path: Path, tmp_cache,
) -> None:
    """A GPL-3.0 dep → high-severity `license_violation` finding."""
    _write_lockfile(tmp_path / "src", [
        {"name": "gpl-pkg", "version": "1.0.0", "license": "GPL-3.0"},
        {"name": "ok-pkg", "version": "1.0.0", "license": "MIT"},
    ])
    result = scan_sca_lockfiles(repo_path=str(tmp_path / "src"))
    findings = [d for d in result["findings"]
                if d["category"] == "license_violation"]
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "high"
    assert "gpl-pkg" in f["title"].lower()
    assert "GPL" in f["title"] or "copyleft" in f["title"].lower()


def test_agpl_calls_out_saas_in_writeup(tmp_path: Path, tmp_cache) -> None:
    """AGPL is the SaaS-killer — the rationale must reference
    network use."""
    _write_lockfile(tmp_path / "src", [
        {"name": "agpl-pkg", "version": "1.0.0", "license": "AGPL-3.0"},
    ])
    result = scan_sca_lockfiles(repo_path=str(tmp_path / "src"))
    findings = [d for d in result["findings"]
                if d["category"] == "license_violation"]
    assert len(findings) == 1
    # description (not title) carries the rationale; the FindingDraft
    # title is shorter.
    desc = findings[0]["description"]
    assert "network" in desc.lower() or "saas" in desc.lower(), desc


def test_unknown_license_emits_medium(tmp_path: Path, tmp_cache) -> None:
    _write_lockfile(tmp_path / "src", [
        {"name": "mystery", "version": "1.0.0", "license": None},
    ])
    result = scan_sca_lockfiles(repo_path=str(tmp_path / "src"))
    findings = [d for d in result["findings"]
                if d["category"] == "license_violation"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"


def test_license_check_disabled(tmp_path: Path, tmp_cache) -> None:
    _write_lockfile(tmp_path / "src", [
        {"name": "gpl-pkg", "version": "1.0.0", "license": "GPL-3.0"},
    ])
    result = scan_sca_lockfiles(
        repo_path=str(tmp_path / "src"),
        with_license_check=False,
    )
    findings = [d for d in result["findings"]
                if d["category"] == "license_violation"]
    assert findings == []
    assert result["tool_metadata"]["licenses"]["enabled"] is False


def test_license_inventory_in_tool_metadata(
    tmp_path: Path, tmp_cache,
) -> None:
    """Per-family rollup must cover ALL packages, not just
    violations — wrapper renders the license-pie chart from this."""
    _write_lockfile(tmp_path / "src", [
        {"name": "p1", "version": "1.0.0", "license": "MIT"},
        {"name": "p2", "version": "1.0.0", "license": "Apache-2.0"},
        {"name": "p3", "version": "1.0.0", "license": "GPL-3.0"},
        {"name": "p4", "version": "1.0.0", "license": "LGPL-2.1"},
        {"name": "p5", "version": "1.0.0", "license": None},
    ])
    result = scan_sca_lockfiles(repo_path=str(tmp_path / "src"))
    by_family = result["tool_metadata"]["licenses"]["by_family"]
    assert by_family["permissive"] == 2
    assert by_family["copyleft"] == 1
    assert by_family["weak_copyleft"] == 1
    assert by_family["unknown"] == 1


def test_allow_copyleft_policy_suppresses_gpl(
    tmp_path: Path, tmp_cache,
) -> None:
    _write_lockfile(tmp_path / "src", [
        {"name": "gpl-pkg", "version": "1.0.0", "license": "GPL-3.0"},
    ])
    result = scan_sca_lockfiles(
        repo_path=str(tmp_path / "src"),
        license_allow_copyleft=True,
    )
    findings = [d for d in result["findings"]
                if d["category"] == "license_violation"]
    assert findings == []


# ---------------------------------------------------------------------------
# Cross — malicious + license + CVE all stack
# ---------------------------------------------------------------------------


def test_all_three_passes_emit_independently(
    tmp_path: Path, tmp_cache,
) -> None:
    """A single repo can produce CVE findings + malicious findings
    + license findings — and each shows up in its own category, not
    bleeding into the others."""
    _write_lockfile(tmp_path / "src", [
        # Vulnerable + permissive license.
        {"name": "lodash", "version": "4.17.20", "license": "MIT"},
        # Typosquat + permissive license.
        {"name": "lodahs", "version": "1.0.0", "license": "MIT"},
        # Clean name + GPL license.
        {"name": "gpl-pkg", "version": "1.0.0", "license": "GPL-3.0"},
    ])
    ti_cache.upsert_cves(
        [{
            "cve_id": "TEST-LODASH",
            "cvss_score": 7.4, "severity": "high",
            "components": [{
                "vendor": "npm", "product": "lodash",
                "version_pattern": "*",
            }],
        }],
        source="integration-test",
    )

    result = scan_sca_lockfiles(repo_path=str(tmp_path / "src"))
    by_cat: dict[str, list] = {}
    for d in result["findings"]:
        by_cat.setdefault(d["category"], []).append(d)
    assert "vulnerable_dependency" in by_cat
    assert "malicious_dependency" in by_cat
    assert "license_violation" in by_cat
    # And each rollup is non-empty.
    assert result["tool_metadata"]["vulnerable_packages"] == 1
    assert result["tool_metadata"]["malicious"]["by_indicator"]["typosquat"] == 1
    assert result["tool_metadata"]["licenses"]["by_family"]["copyleft"] == 1
