"""Tests for the nuclei template YAML parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.tools.nuclei_runner.parser import (
    HttpRequest,
    Matcher,
    Template,
    parse_template,
    parse_template_dir,
    parse_template_file,
)


_FIXTURES = Path(__file__).parent / "fixtures" / "templates"


def test_parse_apache_flink_template() -> None:
    tpl = parse_template_file(_FIXTURES / "apache-flink-unauth.yaml")
    assert tpl is not None
    assert tpl.id == "apache-flink-unauth-fixture"
    assert tpl.info.severity == "critical"
    assert tpl.info.cve_id == ["CVE-2020-17519"]
    assert tpl.info.cwe_id == ["CWE-552"]
    assert "cve" in tpl.info.tags
    assert "apache" in tpl.info.tags
    assert tpl.is_supported
    assert len(tpl.http) == 1
    req = tpl.http[0]
    assert req.method == "GET"
    assert "{{BaseURL}}/jobmanager/logs" in req.paths
    assert req.matchers_condition == "and"
    assert len(req.matchers) == 2
    types = {m.type for m in req.matchers}
    assert types == {"word", "status"}


def test_parse_jenkins_template_csv_tags() -> None:
    """Tags shipped CSV-style still parse into a list."""
    tpl = parse_template_file(_FIXTURES / "jenkins-login-panel.yaml")
    assert tpl is not None
    assert "panel" in tpl.info.tags
    assert "jenkins" in tpl.info.tags
    assert tpl.info.severity == "info"


def test_parse_log4shell_negative_matcher() -> None:
    tpl = parse_template_file(_FIXTURES / "log4shell.yaml")
    assert tpl is not None
    assert tpl.info.cve_id == ["CVE-2021-44228"]
    # The first matcher is a negative case-insensitive header word match.
    word_m = next(m for m in tpl.http[0].matchers if m.type == "word")
    assert word_m.negative is True
    assert word_m.case_insensitive is True
    assert word_m.part == "header"


def test_parse_unsupported_workflow_is_marked() -> None:
    tpl = parse_template_file(_FIXTURES / "unsupported-workflow.yaml")
    assert tpl is not None
    assert "workflows" in tpl.unsupported_kinds
    assert tpl.is_supported is False


def test_parse_template_dir_filter_by_tags() -> None:
    out = list(parse_template_dir(_FIXTURES, tags=["apache"]))
    ids = {t.id for t in out}
    # log4shell-fixture has "apache" tag too — that's fine, just confirm
    # apache-flink is in the matched set.
    assert "apache-flink-unauth-fixture" in ids


def test_parse_template_dir_filter_by_severity() -> None:
    out = list(parse_template_dir(_FIXTURES, severity=["critical"]))
    sevs = {t.info.severity for t in out}
    assert sevs == {"critical"}


def test_parse_template_dir_filter_by_template_ids() -> None:
    out = list(parse_template_dir(
        _FIXTURES, template_ids=["jenkins-login-panel-fixture"],
    ))
    assert len(out) == 1
    assert out[0].id == "jenkins-login-panel-fixture"


def test_parse_template_dir_only_supported_excludes_workflow() -> None:
    out = list(parse_template_dir(_FIXTURES, only_supported=True))
    ids = {t.id for t in out}
    assert "unsupported-workflow-fixture" not in ids


def test_parse_template_dir_max_templates_caps() -> None:
    out = list(parse_template_dir(_FIXTURES, max_templates=1))
    assert len(out) == 1


def test_parse_invalid_template_returns_none() -> None:
    # No id field.
    result = parse_template({"info": {"name": "x"}})
    assert result is None
    # Empty id.
    result = parse_template({"id": "  ", "info": {}})
    assert result is None


def test_parse_template_with_no_http_is_unsupported() -> None:
    tpl = parse_template({
        "id": "no-http-fixture",
        "info": {"name": "x", "severity": "info"},
    })
    assert tpl is not None
    assert tpl.has_http is False
    assert tpl.is_supported is False


def test_parse_legacy_requests_field() -> None:
    """Older templates use `requests:` instead of `http:`."""
    tpl = parse_template({
        "id": "legacy-fixture",
        "info": {"name": "x", "severity": "low"},
        "requests": [{
            "method": "GET",
            "path": ["{{BaseURL}}/x"],
            "matchers": [{"type": "status", "status": [200]}],
        }],
    })
    assert tpl is not None
    assert tpl.has_http is True


def test_parse_template_file_handles_missing_path(tmp_path) -> None:
    assert parse_template_file(tmp_path / "doesnotexist.yaml") is None


def test_parse_template_file_handles_invalid_yaml(tmp_path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(":\nthis is\n: not: yaml")
    assert parse_template_file(bad) is None
