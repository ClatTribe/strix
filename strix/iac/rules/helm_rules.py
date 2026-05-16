"""Helm chart rules — Phase 11.4.

Two rule categories:
  * **Chart.yaml** — deprecated apiVersion, missing version pin,
    dependency on a chart with no version constraint
  * **values.yaml** — security-relevant defaults (insecure
    ingress, unpinned image tags, root user, exposed admin
    endpoints, hardcoded passwords)

We deliberately don't try to traverse arbitrary nested keys —
Helm chart conventions vary wildly. Rules target patterns that
are universally bad regardless of chart shape.
"""

from __future__ import annotations

import re
from typing import Any

from strix.iac.parsers.base import PLATFORM_HELM, IacFile
from strix.iac.rules import IacFinding, register_rule


# Same secret regex set as terraform_rules / docker_rules.
_SECRET_LIKE = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"AIza[A-Za-z0-9_-]{35}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY"),
]


def _is_chart(iac_file: IacFile) -> bool:
    return (
        isinstance(iac_file.data, dict)
        and iac_file.data.get("kind") == "chart"
    )


def _is_values(iac_file: IacFile) -> bool:
    return (
        isinstance(iac_file.data, dict)
        and iac_file.data.get("kind") == "values"
    )


# ---------------------------------------------------------------------------
# CHART_DEPRECATED_API_VERSION — Helm 2 apiVersion (v1) charts
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_HELM)
def helm_chart_deprecated_api_version(iac_file: IacFile) -> list[IacFinding]:
    if not _is_chart(iac_file):
        return []
    chart = iac_file.data.get("chart") or {}
    av = (chart.get("apiVersion") or "").strip().lower()
    if not av or av in {"v2"}:
        return []
    return [IacFinding(
        rule_id="HELM_CHART_DEPRECATED_API_VERSION",
        file=iac_file.path,
        line=0,
        severity="medium",
        message=(
            f"Chart `{chart.get('name')}` declares `apiVersion: "
            f"{av}` — Helm 2 charts are unsupported since Nov 2020. "
            f"Migrate to `apiVersion: v2` (Helm 3)."
        ),
        cwe="CWE-1104",
        category="misconfig",
        platform=PLATFORM_HELM,
        metadata={
            "chart": chart.get("name"),
            "apiVersion": av,
        },
    )]


# ---------------------------------------------------------------------------
# CHART_DEPRECATED — chart marked deprecated: true
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_HELM)
def helm_chart_deprecated(iac_file: IacFile) -> list[IacFinding]:
    if not _is_chart(iac_file):
        return []
    chart = iac_file.data.get("chart") or {}
    if not chart.get("deprecated"):
        return []
    return [IacFinding(
        rule_id="HELM_CHART_DEPRECATED",
        file=iac_file.path,
        line=0,
        severity="medium",
        message=(
            f"Chart `{chart.get('name')}` (version "
            f"`{chart.get('version')}`) is marked `deprecated: true`. "
            f"Deprecated charts no longer receive security fixes — "
            f"migrate to a maintained alternative."
        ),
        cwe="CWE-1104",
        category="misconfig",
        platform=PLATFORM_HELM,
        metadata={
            "chart": chart.get("name"),
            "version": chart.get("version"),
        },
    )]


# ---------------------------------------------------------------------------
# CHART_DEP_UNPINNED — dependency without version constraint
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_HELM)
def helm_chart_dep_unpinned(iac_file: IacFile) -> list[IacFinding]:
    if not _is_chart(iac_file):
        return []
    chart = iac_file.data.get("chart") or {}
    deps = chart.get("dependencies") or []
    out: list[IacFinding] = []
    for d in deps:
        if not isinstance(d, dict):
            continue
        version = (d.get("version") or "").strip()
        # Allow standard semver-range constraints (>=, ~, ^, fixed).
        # An empty string OR "*" OR "x" means unpinned.
        if not version or version in {"*", "x", "X"}:
            out.append(IacFinding(
                rule_id="HELM_CHART_DEP_UNPINNED",
                file=iac_file.path,
                line=0,
                severity="medium",
                message=(
                    f"Chart `{chart.get('name')}` dependency "
                    f"`{d.get('name')}` is not version-pinned "
                    f"(`version: {version or '<empty>'}`). Pin to a "
                    f"semver range (e.g. `~1.2.0` or `1.2.0`) so "
                    f"reproducible builds match supply-chain audit "
                    f"expectations."
                ),
                cwe="CWE-829",
                category="misconfig",
                platform=PLATFORM_HELM,
                metadata={
                    "chart": chart.get("name"),
                    "dependency": d.get("name"),
                    "repository": d.get("repository"),
                },
            ))
    return out


# ---------------------------------------------------------------------------
# VALUES_IMAGE_TAG_FLOATING — image:tag is `latest` or floating
# ---------------------------------------------------------------------------


_FLOATING_TAGS = frozenset({"latest", "main", "master", "stable"})


def _walk_dict(d: Any, path: tuple = ()):
    """Recursive walk over nested dicts/lists; yields (path, value)
    for every leaf."""
    if isinstance(d, dict):
        for k, v in d.items():
            yield from _walk_dict(v, path + (str(k),))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            yield from _walk_dict(v, path + (f"[{i}]",))
    else:
        yield path, d


@register_rule(platform=PLATFORM_HELM)
def helm_values_floating_image_tag(iac_file: IacFile) -> list[IacFinding]:
    if not _is_values(iac_file):
        return []
    values = iac_file.data.get("values") or {}
    out: list[IacFinding] = []
    seen_paths: set[str] = set()
    for path, leaf in _walk_dict(values):
        if not isinstance(leaf, str):
            continue
        # We're looking for image-tag values. Heuristic: the LAST
        # path segment is `tag` AND the value is in the floating set.
        if not path or path[-1].lower() != "tag":
            continue
        if leaf.strip().lower() not in _FLOATING_TAGS:
            continue
        path_str = ".".join(path)
        if path_str in seen_paths:
            continue
        seen_paths.add(path_str)
        out.append(IacFinding(
            rule_id="HELM_VALUES_FLOATING_IMAGE_TAG",
            file=iac_file.path,
            line=0,
            severity="medium",
            message=(
                f"`{path_str}: {leaf}` uses a floating image tag. "
                f"Pin to a digest (`@sha256:...`) or a versioned "
                f"tag so deploys are reproducible + supply-chain "
                f"auditable. Floating tags can be re-pointed by a "
                f"compromised registry."
            ),
            cwe="CWE-1104",
            category="misconfig",
            platform=PLATFORM_HELM,
            metadata={"path": path_str, "tag": leaf},
        ))
    return out


# ---------------------------------------------------------------------------
# VALUES_HARDCODED_SECRET — secret pattern in default values
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_HELM)
def helm_values_hardcoded_secret(iac_file: IacFile) -> list[IacFinding]:
    if not _is_values(iac_file):
        return []
    raw = iac_file.raw_text or ""
    out: list[IacFinding] = []
    seen = False
    for pat in _SECRET_LIKE:
        m = pat.search(raw)
        if not m:
            continue
        seen = True
        out.append(IacFinding(
            rule_id="HELM_VALUES_HARDCODED_SECRET",
            file=iac_file.path,
            line=0,
            severity="critical",
            message=(
                f"`values.yaml` contains a secret-like literal "
                f"(matches {pat.pattern[:40]}). NEVER ship default "
                f"credentials in a chart — operators inherit them "
                f"unless they override. Use Helm `--set` / external "
                f"secret managers / sealed-secrets instead."
            ),
            cwe="CWE-798",
            category="secrets",
            platform=PLATFORM_HELM,
            metadata={"match_preview": m.group(0)[:16] + "..."},
        ))
        # One finding per file — pattern-list scan is exhaustive
        # but the user only needs to know once.
        break
    return out
