"""Helm chart parser — Phase 11.4.

Helm charts have a standard layout:
  ```
  mychart/
    Chart.yaml
    values.yaml
    templates/
      deployment.yaml      # contains {{ .Values.X }} — NOT scanned
      service.yaml
  ```

For v1 we parse `Chart.yaml` (metadata: name, version, apiVersion,
dependencies) and `values.yaml` (default values applied to the
templates). Template files contain Go-template syntax that
strix can't safely evaluate without rendering, so they're left
to the operator to `helm template > rendered.yaml` and then run
strix against the rendered output.

This is a pragmatic v1 choice — we catch Chart-level issues
(deprecated apiVersion, missing version pin, untrusted
dependency) and values-level issues (`securityContext: false`
defaults, hardcoded passwords) without trying to be a Helm
runtime.

## Output shape

For `Chart.yaml`:
  `{kind: "chart", chart: {apiVersion, name, version, appVersion,
    dependencies, deprecated}}`

For `values.yaml`:
  `{kind: "values", values: <full yaml as dict>}`
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from strix.iac.parsers.base import (
    PLATFORM_HELM,
    IacFile,
    register_parser,
)


logger = logging.getLogger(__name__)


def _parse_chart_yaml(text: str) -> dict[str, Any]:
    """Parse a Chart.yaml. Returns the normalised metadata or
    an empty dict on parse failure."""
    import yaml

    try:
        data = yaml.safe_load(text) or {}
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "apiVersion": str(data.get("apiVersion") or ""),
        "name": str(data.get("name") or ""),
        "version": str(data.get("version") or ""),
        "appVersion": str(data.get("appVersion") or ""),
        "type": str(data.get("type") or "application"),
        "deprecated": bool(data.get("deprecated", False)),
        "dependencies": (
            data.get("dependencies") or []
            if isinstance(data.get("dependencies"), list) else []
        ),
        "raw": data,
    }


def _parse_values_yaml(text: str) -> dict[str, Any]:
    """Parse a values.yaml. Returns the parsed dict or empty
    on failure."""
    import yaml

    try:
        data = yaml.safe_load(text)
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


@register_parser(
    filenames=["chart.yaml", "chart.yml"],
)
def parse_helm_chart(path: Path) -> IacFile | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return IacFile(
            platform=PLATFORM_HELM, path=str(path),
            data={"kind": "chart", "chart": {}},
            raw_text="", parse_error=str(e),
        )
    chart = _parse_chart_yaml(text)
    if not chart.get("name"):
        # Doesn't look like a Helm Chart — skip.
        return None
    return IacFile(
        platform=PLATFORM_HELM, path=str(path),
        data={"kind": "chart", "chart": chart},
        raw_text=text,
    )


@register_parser(
    filenames=["values.yaml", "values.yml"],
)
def parse_helm_values(path: Path) -> IacFile | None:
    """A `values.yaml` in a chart's root is a Helm artefact;
    one elsewhere in a repo might just be a generic config file.
    We parse it conservatively and let rules decide what's a
    real Helm signal.

    Heuristic: only treat as Helm if there's a sibling
    `Chart.yaml`. Otherwise skip — generic `values.yaml` in
    application code shouldn't fan out to Helm rules.
    """
    chart_yaml = path.parent / "Chart.yaml"
    chart_yml = path.parent / "Chart.yml"
    if not (chart_yaml.exists() or chart_yml.exists()):
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return IacFile(
            platform=PLATFORM_HELM, path=str(path),
            data={"kind": "values", "values": {}},
            raw_text="", parse_error=str(e),
        )
    values = _parse_values_yaml(text)
    return IacFile(
        platform=PLATFORM_HELM, path=str(path),
        data={"kind": "values", "values": values},
        raw_text=text,
    )
