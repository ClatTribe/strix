"""Helper for specialist scanners to populate the typed KG (§3 follow-up).

The §3 typed KG ships with `add_node` / `add_edge` primitives but no
*caller* — specialist scanners that find vulnerabilities don't yet
populate the graph that powers `query_paths` chain planning. This
module is the thin adapter: one call from a successful `_emit_finding`
populates `Vuln` + `Surface` + `AFFECTS` consistently.

Why this lives in `strix/agents/` and not inside `knowledge_graph.py`:
the KG module is pure data structure; this is the *AppSec-flavoured
glue* that knows how to translate a finding into the canonical
node/edge triple. Keeping it separate lets the graph stay
domain-neutral.

## Idempotency

Surfaces are de-duplicated by `(url, param, method)` triple via a
process-global cache: probing `/login?username=x` ten times with
different payloads produces ten `Vuln` nodes but one `Surface`
node. The `AFFECTS` edge from each `Vuln` to that single
`Surface` is what chain-planning queries traverse.

## Kill switch

When `STRIX_KG_DISABLED=1` is set the underlying graph operations
no-op. This helper inherits that behaviour automatically — no
additional env var.
"""

from __future__ import annotations

import logging
import threading
from typing import Any
from urllib.parse import urlsplit, urlunsplit


logger = logging.getLogger(__name__)


# Process-global surface-dedup cache. Key is the canonicalised
# `(url_no_query, param, method)` triple; value is the KG node id
# returned by `add_node`. Thread-safe behind a single lock — the
# KG itself is already locked at the mutation level, but this map
# needs its own check-then-insert critical section.
_surface_cache: dict[tuple[str, str, str], str] = {}
_surface_cache_lock = threading.Lock()


def reset_surface_cache_for_testing() -> None:
    """Clear the de-dup cache. Tests must call this in fixtures so
    a prior test's surface IDs don't leak into the assertions."""
    with _surface_cache_lock:
        _surface_cache.clear()


def _canonicalise_url(url: str) -> str:
    """Drop the query + fragment so two probes against
    `/login?x=1` and `/login?x=2` collapse onto one Surface."""
    try:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except (ValueError, AttributeError):
        return url


# Threat-intel asset dedup cache. ThreatIntel observations target
# Asset nodes (domain / ip / hash / package / email), not Surface
# nodes — so they need their own dedup keyed by `(asset_type,
# value)`.
_asset_cache: dict[tuple[str, str], str] = {}
_asset_cache_lock = threading.Lock()


def reset_asset_cache_for_testing() -> None:
    """Clear the threat-intel asset dedup cache. Tests must call
    this in fixtures."""
    with _asset_cache_lock:
        _asset_cache.clear()


# Dependency node dedup. Same scanner can surface the same package
# repeatedly across a scan (lockfile parse → vuln check → SBOM
# emit all touch the same `log4j 2.14.0`). The dedup key is
# `(canonical_name, version_or_unknown, ecosystem_or_unknown)` so
# a customer running log4j 2.14.0 on Maven AND a separate log4j
# 2.17.1 in another service stays two distinct nodes.
_dependency_cache: dict[tuple[str, str, str], str] = {}
_dependency_cache_lock = threading.Lock()


def reset_dependency_cache_for_testing() -> None:
    """Clear the Dependency dedup cache. Tests must call this in
    fixtures."""
    with _dependency_cache_lock:
        _dependency_cache.clear()


def record_dependency_in_kg(
    *,
    name: str,
    version: str | None = None,
    ecosystem: str | None = None,
    source: str = "",
    cve_ids: list[str] | None = None,
) -> str | None:
    """Emit a `Dependency` node into the KG, keyed for dedup so the
    same package surfaced twice doesn't bloat the graph.

    This is the producer side of the CVE-relevance evaluator
    (`strix.agents.exploit_builder.cve_relevance`) — every
    inventory-aware scanner / tool that can identify a deployed
    technology should call this. Three canonical caller classes:

      * **SCA / lockfile parsers** — pass `ecosystem=<npm|pypi|
        maven|nuget|...>`, `name=<package>`, `version=<semver>`,
        `source="sca_lockfiles"` (or whichever scanner).
      * **Web-target fingerprinters** — pass `name=<framework
        or server>` (`nginx`, `react`, `wordpress`), `version=<
        from-header-or-bundle-hash>`, `ecosystem=None` for
        non-package techs, `source="sbom_extract"` or
        `"fingerprint"`.
      * **Container scanners** (future) — pass package names from
        the image's OS layer + app layer, `ecosystem="os"` for
        system packages.

    Returns the new node id (or the existing one when dedup
    hits); `None` when the KG is disabled or emission fails.
    Best-effort; never raises.

    Args:
      name: the canonical product / package name. Will be
        normalised via `cve_relevance._canonical_product` so
        callers can pass whatever shape their data source emits
        (Maven groupId:artifactId, npm `@scope/pkg`, Java
        fully-qualified name, etc.).
      version: semver / version string when known; None when
        the scanner couldn't determine it (some fingerprinters
        only recognise the product). Surfacing without a version
        is still useful — `RelevanceTier.PRODUCT_MATCH`
        downstream surfaces it as a coarse alert.
      ecosystem: `npm`, `pypi`, `maven`, `gem`, `nuget`, `cargo`,
        `go`, `os` (system packages), or None (web tech).
      source: which scanner emitted this. Stored in `props`
        so the wrapper can attribute evidence.
      cve_ids: optional list of CVE IDs already associated with
        this package version (typically from SCA's prior advisory
        lookup). Stored as a list on the node.

    Dedup:
      `(canonical_name, version_or_'unknown', ecosystem_or_'unknown')`
      → one Dependency node. Re-emission updates `cve_ids` and
      `source` (additive — multiple scanners contributing to one
      Dependency record).
    """
    if not isinstance(name, str) or not name.strip():
        return None

    try:
        from strix.agents.exploit_builder.cve_relevance import (
            _canonical_product,
        )
        from strix.agents.knowledge_graph import get_kg, is_disabled
    except ImportError:
        return None

    if is_disabled():
        return None

    canonical = _canonical_product(name)
    if not canonical:
        return None

    norm_version = (version or "").strip() or None
    norm_ecosystem = (ecosystem or "").strip().lower() or None
    cache_key = (
        canonical,
        norm_version or "unknown",
        norm_ecosystem or "unknown",
    )

    kg = get_kg()

    try:
        with _dependency_cache_lock:
            existing_id = _dependency_cache.get(cache_key)
            if existing_id is not None and kg.get_node(existing_id) is not None:
                # Update path — merge cve_ids + sources additively.
                if cve_ids or source:
                    node = kg.get_node(existing_id)
                    if node is not None:
                        merged_cves = set(node.props.get("cve_ids") or [])
                        merged_cves.update(cve_ids or [])
                        merged_sources = set(
                            (node.props.get("sources") or [])
                        )
                        if source:
                            merged_sources.add(source)
                        # `update_node` would be ideal but for now
                        # we mutate via direct prop write (the KG
                        # serialiser sees the change on next
                        # `save`).
                        node.props["cve_ids"] = sorted(merged_cves)
                        node.props["sources"] = sorted(merged_sources)
                return existing_id

            props: dict[str, Any] = {
                "name": canonical,
                "name_raw": name,
            }
            if norm_version:
                props["version"] = norm_version
            if norm_ecosystem:
                props["ecosystem"] = norm_ecosystem
            if source:
                props["sources"] = [source]
            if cve_ids:
                props["cve_ids"] = list(cve_ids)

            node = kg.add_node(type="Dependency", props=props)
            _dependency_cache[cache_key] = node.id
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "kg_emit: record_dependency failed: %s", e, exc_info=True,
        )
        return None

    return node.id


def record_threat_intel_in_kg(
    *,
    source: str,
    asset_type: str,
    asset_value: str,
    verdict: str,
    score: float | None = None,
    detail: str = "",
    finding_id: str | None = None,
) -> tuple[str | None, str | None]:
    """P4 — Emit `ThreatIntel` + (deduplicated) `Asset` + `OBSERVED`
    triple for threat-intel / reputation / posture scanners.

    The §3 Vuln→Surface→AFFECTS triple doesn't fit observations
    from threat-intel feeds (vt_reputation, kev_diff, nvd_lookup,
    hibp_breach, otx_lookup, greynoise, cve_lookup, monitoring_
    posture, domain_reputation). Those scanners produce
    *observations about an asset* — "domain has malicious
    reputation," "package version matches a known CVE," "email
    appears in HIBP breach corpus" — not vulnerabilities at a
    Surface. This helper records them with the right shape.

    Returns `(threat_intel_id, asset_id)` — both `None` when the
    KG is disabled or emission fails. Best-effort; never raises.

    Args:
      source: which scanner / data source produced the
        observation (`vt_reputation`, `kev_diff`, `nvd_lookup`,
        `hibp_breach`, `otx_lookup`, `greynoise`, `cve_lookup`,
        `monitoring_posture`, `domain_reputation`).
      asset_type: shape of the subject — `domain`, `ip_address`,
        `email`, `package`, `cve_id`, `hash`, `url`.
      asset_value: the actual indicator value.
      verdict: classification — `malicious`, `suspicious`,
        `benign`, `breached`, `kev_listed`, `cve_match`,
        `compliance_fail`, `unknown`.
      score: optional numeric (0.0–1.0 or 0–100 — convention
        varies by source; preserve as recorded).
      detail: one-line free-form context.
      finding_id: optional finding ID when this observation
        was also emitted as a vulnerability finding.

    Surface dedup: `(asset_type, asset_value)` → one Asset node.
    Multiple ThreatIntel observations about the same asset fan
    out to distinct ThreatIntel nodes pointing at the shared
    Asset (e.g. `vt_reputation` + `domain_reputation` both
    flag the same domain → 1 Asset, 2 ThreatIntel, 2 OBSERVED
    edges)."""
    try:
        from strix.agents.knowledge_graph import get_kg, is_disabled
    except ImportError:
        return None, None

    if is_disabled():
        return None, None

    kg = get_kg()
    cache_key = (asset_type, asset_value)

    try:
        with _asset_cache_lock:
            asset_id = _asset_cache.get(cache_key)
            if asset_id is None or kg.get_node(asset_id) is None:
                asset_node = kg.add_node(
                    type="Asset",
                    props={"type": asset_type, "value": asset_value},
                )
                asset_id = asset_node.id
                _asset_cache[cache_key] = asset_id

        ti_props: dict[str, Any] = {
            "source": source,
            "verdict": verdict,
        }
        if score is not None:
            ti_props["score"] = float(score)
        if detail:
            ti_props["detail"] = detail
        if finding_id:
            ti_props["finding_id"] = finding_id

        ti_node = kg.add_node(type="ThreatIntel", props=ti_props)

        kg.add_edge(
            type="OBSERVED",
            source=ti_node.id,
            target=asset_id,
            props={"verdict": verdict} if verdict else None,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("kg_emit: record_threat_intel failed: %s", e, exc_info=True)
        return None, None

    return ti_node.id, asset_id


def record_finding_in_kg(
    *,
    finding_id: str | None,
    url: str,
    param: str,
    cwe: str,
    severity: str,
    category: str,
    method: str = "GET",
    detection_kind: str = "",
    db_engine: str | None = None,
    confidence: float | None = None,
) -> tuple[str | None, str | None]:
    """Emit `Vuln` + (deduplicated) `Surface` + `AFFECTS` triple.

    Returns `(vuln_node_id, surface_node_id)` — both `None` when
    the KG is disabled or emission fails. Best-effort throughout;
    never raises (a KG-helper bug must not break a scanner's
    successful finding).

    Args:
      finding_id: tracer's finding ID. Stored on the Vuln node so
        downstream reporting can join finding_id → KG nodes.
      url: probe URL (will be canonicalised — query stripped).
      param: parameter name that carried the payload.
      cwe: CWE string (e.g. `CWE-89`).
      severity: severity string (e.g. `high`, `critical`).
      category: vuln category (e.g. `sqli`, `xss`, `idor`).
      method: HTTP method, default `GET`.
      detection_kind: optional sub-classifier (`error`, `boolean`,
        `reflected`, `stored`, `dom`). Stored on the Vuln node.
      db_engine: SQLi-only — DB engine fingerprint when known.
      confidence: optional float from the detector for downstream
        chain-planning confidence propagation.
    """
    try:
        from strix.agents.knowledge_graph import get_kg, is_disabled
    except ImportError:
        return None, None

    if is_disabled():
        return None, None

    kg = get_kg()
    canon_url = _canonicalise_url(url)
    cache_key = (canon_url, param, method.upper())

    try:
        with _surface_cache_lock:
            surface_node_id = _surface_cache.get(cache_key)
            if surface_node_id is None or kg.get_node(surface_node_id) is None:
                surface_node = kg.add_node(
                    type="Surface",
                    props={
                        "url": canon_url,
                        "param": param,
                        "method": method.upper(),
                    },
                )
                surface_node_id = surface_node.id
                _surface_cache[cache_key] = surface_node_id

        vuln_props: dict[str, Any] = {
            "cwe": cwe,
            "severity": (severity or "").lower(),
            "category": category,
        }
        if finding_id:
            vuln_props["finding_id"] = finding_id
        if detection_kind:
            vuln_props["detection_kind"] = detection_kind
        if db_engine:
            vuln_props["db_engine"] = db_engine
        if confidence is not None:
            vuln_props["confidence"] = float(confidence)

        vuln_node = kg.add_node(type="Vuln", props=vuln_props)

        kg.add_edge(
            type="AFFECTS",
            source=vuln_node.id,
            target=surface_node_id,
            props={"detected_via": detection_kind} if detection_kind else None,
        )
    except Exception as e:  # noqa: BLE001
        # KG-helper bugs must NOT break scanner emission paths.
        # The finding has already been recorded via the tracer;
        # losing the KG side-effect is acceptable degraded mode.
        logger.debug("kg_emit: record_finding failed: %s", e, exc_info=True)
        return None, None

    return vuln_node.id, surface_node_id
