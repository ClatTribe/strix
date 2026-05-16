"""Tests for Helm chart parser + rules (Phase 11.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.iac.parsers.base import PLATFORM_HELM
from strix.iac.parsers.helm import parse_helm_chart, parse_helm_values
from strix.iac.rules import run_rules
from strix.iac.rules.helm_rules import (
    helm_chart_dep_unpinned,
    helm_chart_deprecated,
    helm_chart_deprecated_api_version,
    helm_values_floating_image_tag,
    helm_values_hardcoded_secret,
)


def _chart_dir(tmp_path: Path, chart_yaml: str, values_yaml: str | None = None):
    d = tmp_path / "chart"
    d.mkdir()
    (d / "Chart.yaml").write_text(chart_yaml)
    if values_yaml is not None:
        (d / "values.yaml").write_text(values_yaml)
    return d


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parse_chart_yaml_returns_iacfile(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: mychart
version: 1.0.0
""")
    iac = parse_helm_chart(d / "Chart.yaml")
    assert iac is not None
    assert iac.platform == PLATFORM_HELM
    assert iac.data["kind"] == "chart"
    assert iac.data["chart"]["name"] == "mychart"


def test_parse_chart_yaml_skips_when_no_name(tmp_path: Path) -> None:
    """A YAML file named Chart.yaml without a `name:` field is
    not a real Helm chart — skip rather than misclassify."""
    d = tmp_path / "x"
    d.mkdir()
    (d / "Chart.yaml").write_text("foo: bar")
    assert parse_helm_chart(d / "Chart.yaml") is None


def test_parse_values_yaml_requires_sibling_chart(tmp_path: Path) -> None:
    """A values.yaml without a sibling Chart.yaml is just a
    generic config file — skip."""
    d = tmp_path / "config"
    d.mkdir()
    (d / "values.yaml").write_text("image:\n  tag: latest")
    assert parse_helm_values(d / "values.yaml") is None


def test_parse_values_yaml_with_sibling_chart(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, "apiVersion: v2\nname: x\nversion: 1.0.0",
                   "image:\n  tag: latest")
    iac = parse_helm_values(d / "values.yaml")
    assert iac is not None
    assert iac.data["kind"] == "values"
    assert iac.data["values"]["image"]["tag"] == "latest"


# ---------------------------------------------------------------------------
# Chart.yaml rules
# ---------------------------------------------------------------------------


def test_helm_v1_apiversion_flagged(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v1
name: oldchart
version: 1.0.0
""")
    iac = parse_helm_chart(d / "Chart.yaml")
    out = helm_chart_deprecated_api_version(iac)
    assert len(out) == 1
    assert out[0].severity == "medium"


def test_helm_v2_apiversion_not_flagged(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: newchart
version: 1.0.0
""")
    iac = parse_helm_chart(d / "Chart.yaml")
    assert helm_chart_deprecated_api_version(iac) == []


def test_helm_deprecated_chart_flagged(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: oldchart
version: 1.0.0
deprecated: true
""")
    iac = parse_helm_chart(d / "Chart.yaml")
    out = helm_chart_deprecated(iac)
    assert len(out) == 1


def test_helm_unpinned_dependency_flagged(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: mychart
version: 1.0.0
dependencies:
  - name: redis
    version: ""
  - name: postgres
    version: "*"
""")
    iac = parse_helm_chart(d / "Chart.yaml")
    out = helm_chart_dep_unpinned(iac)
    assert len(out) == 2


def test_helm_pinned_dependency_not_flagged(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: mychart
version: 1.0.0
dependencies:
  - name: redis
    version: "1.2.3"
  - name: postgres
    version: "~1.5.0"
""")
    iac = parse_helm_chart(d / "Chart.yaml")
    assert helm_chart_dep_unpinned(iac) == []


# ---------------------------------------------------------------------------
# values.yaml rules
# ---------------------------------------------------------------------------


def test_helm_floating_latest_tag_flagged(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: mychart
version: 1.0.0
""", """
image:
  repository: myapp
  tag: latest
""")
    iac = parse_helm_values(d / "values.yaml")
    out = helm_values_floating_image_tag(iac)
    assert len(out) == 1
    assert "latest" in out[0].metadata["tag"]


def test_helm_pinned_tag_not_flagged(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: mychart
version: 1.0.0
""", """
image:
  tag: 1.2.3
""")
    iac = parse_helm_values(d / "values.yaml")
    assert helm_values_floating_image_tag(iac) == []


def test_helm_main_tag_flagged(tmp_path: Path) -> None:
    """`main` / `master` are also floating tags."""
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: mychart
version: 1.0.0
""", """
image:
  tag: main
""")
    iac = parse_helm_values(d / "values.yaml")
    out = helm_values_floating_image_tag(iac)
    assert len(out) == 1


def test_helm_nested_floating_tag_detected(tmp_path: Path) -> None:
    """The values file has multiple images at different paths;
    one is floating. The walker must find it."""
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: mychart
version: 1.0.0
""", """
api:
  image:
    tag: 1.2.3
worker:
  image:
    tag: latest
""")
    iac = parse_helm_values(d / "values.yaml")
    out = helm_values_floating_image_tag(iac)
    assert len(out) == 1
    assert "worker" in out[0].metadata["path"]


def test_helm_hardcoded_secret_in_values_critical(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v2
name: mychart
version: 1.0.0
""", """
api_key: "AKIAEXAMPLE12345678X"
""")
    iac = parse_helm_values(d / "values.yaml")
    out = helm_values_hardcoded_secret(iac)
    assert len(out) == 1
    assert out[0].severity == "critical"
    assert out[0].cwe == "CWE-798"


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------


def test_run_rules_dispatches_to_helm_rules(tmp_path: Path) -> None:
    d = _chart_dir(tmp_path, """
apiVersion: v1
name: oldchart
version: 1.0.0
deprecated: true
""")
    iac = parse_helm_chart(d / "Chart.yaml")
    findings = run_rules(iac)
    assert any(f.rule_id == "HELM_CHART_DEPRECATED_API_VERSION" for f in findings)
    assert any(f.rule_id == "HELM_CHART_DEPRECATED" for f in findings)
    for f in findings:
        assert f.platform == PLATFORM_HELM
