"""Integration tests for `scan_iac` LLM specialist — Phase 11."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.iac.tools import scan_iac


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo


def test_returns_error_for_missing_repo_path() -> None:
    result = scan_iac(repo_path="")
    assert result["status"] == "error"


def test_returns_error_for_nonexistent_dir(tmp_path: Path) -> None:
    result = scan_iac(repo_path=str(tmp_path / "doesnt-exist"))
    assert result["status"] == "error"


def test_returns_partial_when_no_iac_files(tmp_path: Path) -> None:
    """A repo without any IaC files → partial with a clear hint."""
    repo = _make_repo(tmp_path)
    (repo / "src.js").write_text("// not iac")
    result = scan_iac(repo_path=str(repo))
    assert result["status"] == "partial"
    assert "no IaC files found" in (result.get("error") or "")


def test_emits_findings_for_misconfigured_vercel(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "vercel.json").write_text(json.dumps({
        "headers": [{
            "source": "/api/(.*)",
            "headers": [
                {"key": "Access-Control-Allow-Origin", "value": "*"},
                {"key": "Access-Control-Allow-Credentials", "value": "true"},
            ],
        }],
    }))
    result = scan_iac(repo_path=str(repo))
    assert result["status"] == "ok"
    titles = [d["title"] for d in result["findings"]]
    assert any("vercel-cors-wildcard-with-credentials" in t for t in titles)


def test_emits_findings_for_dockerfile_misconfigs(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "Dockerfile").write_text(
        "FROM alpine\n"  # :latest implicit
        "ENV OPENAI_KEY=sk-deadbeefDEADBEEF1234567890abcdef\n"
        "CMD ['app']\n"
        # No USER directive.
    )
    result = scan_iac(repo_path=str(repo))
    assert result["status"] == "ok"
    rule_ids = {d["title"].split(" — ")[0].split(" ", 1)[1]
                for d in result["findings"]}
    assert any("dockerfile-no-user-directive" in r for r in rule_ids)
    assert any("dockerfile-latest-tag" in r for r in rule_ids)
    assert any("dockerfile-env-hardcoded-secret" in r for r in rule_ids)


def test_findings_carry_iac_category(tmp_path: Path) -> None:
    """Cross-asset routing depends on `category` to pivot — pin
    the categories that the rule pack emits."""
    repo = _make_repo(tmp_path)
    (repo / "vercel.json").write_text(json.dumps({
        "redirects": [{"source": "/go", "destination": "https://:url"}],
    }))
    result = scan_iac(repo_path=str(repo))
    cats = {d["category"] for d in result["findings"]}
    assert "open_redirect" in cats


def test_severity_descending_in_findings(tmp_path: Path) -> None:
    """Findings should arrive in severity-descending order so
    the lead's `max_findings` cap keeps the highest-priority
    items."""
    repo = _make_repo(tmp_path)
    (repo / "vercel.json").write_text(json.dumps({
        # critical (hardcoded secret)
        "env": {"AWS_KEY": "AKIAIOSFODNN7EXAMPLE"},
        # low (large maxDuration)
        "functions": {"api/x.js": {"maxDuration": 600}},
    }))
    result = scan_iac(repo_path=str(repo))
    severities = [d["severity"] for d in result["findings"]]
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    assert severities == sorted(severities, key=lambda s: -rank[s])


def test_tool_metadata_shape(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "vercel.json").write_text("{}")
    (repo / "Dockerfile").write_text("FROM alpine:3.19\nUSER 1001\n")
    result = scan_iac(repo_path=str(repo))
    md = result["tool_metadata"]
    for k in (
        "engine", "files_scanned", "files_by_platform",
        "findings_total", "findings_by_platform",
        "critical_count", "high_count",
    ):
        assert k in md, k
    assert md["engine"] == "iac-v1"
    assert md["files_scanned"] >= 2


# ---------------------------------------------------------------------------
# Lead-agent catalog placement
# ---------------------------------------------------------------------------


def test_scan_iac_in_repository_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
    cat = get_lead_tool_catalog(target_types=["repository"])
    assert "scan_iac" in cat


def test_scan_iac_in_local_code_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
    cat = get_lead_tool_catalog(target_types=["local_code"])
    assert "scan_iac" in cat


def test_scan_iac_in_web_application_catalog() -> None:
    """Web target with co-located source — vibe-coded SaaS workflow."""
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
    cat = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_iac" in cat


def test_scan_iac_not_in_pure_network_catalogs() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
    for tt in ("domain", "ip_address"):
        cat = get_lead_tool_catalog(target_types=[tt])
        assert "scan_iac" not in cat, tt
