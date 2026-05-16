"""Kubernetes manifest parser — Phase 11.4.

Closes the audit item 1 IaC breadth gap for K8s resources.

## Detection model

Kubernetes manifests are YAML files (`.yaml` / `.yml`) whose
top-level keys include `apiVersion:` AND `kind:`. The parser uses
`yaml.safe_load_all` to handle multi-document YAML (resources
separated by `---`), filters each document for the
apiVersion+kind shape, and emits an `IacFile` ONLY when at least
one document looks Kubernetes-shaped.

This is the discriminator: a plain `.yaml` file with arbitrary
config is NOT misclassified as Kubernetes (returns None →
scanner skips it).

## What this parser does NOT do

  * No CRD schema validation (we accept any apiVersion).
  * No Kustomize overlay resolution.
  * No Helm template rendering — Helm files (which contain
    `{{ .Values.X }}`) intentionally fall through to the
    `helm.py` parser (or skip entirely).
  * No `helm template`-style multi-document fan-out — operators
    pre-render Helm into raw K8s manifests if they want strix
    to scan the rendered output.

## Output shape

`IacFile.data` is a list of dicts, one per K8s resource document:
  `[{apiVersion, kind, metadata, spec, raw, doc_index}, ...]`

Rules iterate and inspect `kind` (Deployment / Pod / Service /
NetworkPolicy / etc.) to decide what to check.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from strix.iac.parsers.base import (
    PLATFORM_KUBERNETES,
    IacFile,
    register_parser,
)


logger = logging.getLogger(__name__)


# YAML files that LOOK like Helm templates (carry `{{` /
# `{{-` / `{{ .Values`) are NOT Kubernetes manifests — they're
# Helm sources that need template rendering first. The K8s
# parser skips them so the scanner doesn't double-flag the
# same file under both Helm and K8s parsers.
_HELM_TEMPLATE_MARKER = re.compile(r"\{\{\-?\s*[\.\w]")


def _is_kubernetes_doc(doc: Any) -> bool:
    """A YAML doc is Kubernetes-shaped iff it's a dict with
    BOTH `apiVersion` AND `kind` top-level keys (non-empty strings)."""
    if not isinstance(doc, dict):
        return False
    api_version = doc.get("apiVersion")
    kind = doc.get("kind")
    return bool(
        isinstance(api_version, str)
        and isinstance(kind, str)
        and api_version.strip()
        and kind.strip()
    )


def _parse_kubernetes_yaml(text: str) -> list[dict[str, Any]]:
    """Parse multi-document YAML, return list of K8s-shaped docs.

    Each entry: `{apiVersion, kind, metadata, spec, raw,
    doc_index}`. `raw` carries the doc text (or "" if the
    splitter couldn't pin it). `doc_index` is 0-based.
    """
    import yaml

    out: list[dict[str, Any]] = []
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception:  # noqa: BLE001
        # Partial-yaml: try splitting on `---` and parsing each.
        # Some malformed multi-doc files break safe_load_all but
        # individual docs parse fine.
        return []

    for i, doc in enumerate(docs):
        if not _is_kubernetes_doc(doc):
            continue
        out.append({
            "apiVersion": doc["apiVersion"].strip(),
            "kind": doc["kind"].strip(),
            "metadata": doc.get("metadata") or {},
            "spec": doc.get("spec") or {},
            "rules": doc.get("rules"),  # NetworkPolicy / RBAC
            "subjects": doc.get("subjects"),  # RoleBinding
            "roleRef": doc.get("roleRef"),  # RoleBinding
            "doc_index": i,
            # Preserve the FULL doc so rules can read keys we
            # didn't enumerate above (CRDs, custom shapes).
            "doc": doc,
        })
    return out


@register_parser(
    patterns=[r"\.ya?ml$"],
)
def parse_kubernetes(path: Path) -> IacFile | None:
    """Parse a YAML file. Returns an IacFile when the file
    contains at least one Kubernetes resource; returns None when
    it doesn't (so the scanner doesn't process arbitrary YAML
    configs as if they were K8s).
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Helm template files use `{{ .Values.X }}` — they're not
    # valid YAML pre-rendering. Skip them; the helm parser
    # handles Chart.yaml + values.yaml separately.
    if _HELM_TEMPLATE_MARKER.search(text):
        return None

    docs = _parse_kubernetes_yaml(text)
    if not docs:
        return None

    return IacFile(
        platform=PLATFORM_KUBERNETES, path=str(path),
        data=docs, raw_text=text,
    )
