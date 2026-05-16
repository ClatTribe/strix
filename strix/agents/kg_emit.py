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


# Asset dedup for recon-discovered assets. Same Asset can be
# surfaced by multiple recon tools (subfinder + crtsh + amass
# all find the same subdomain). Dedup key is `(asset_type, value)`
# — identical to the threat-intel Asset cache so a subdomain
# discovered by `subdomain_enum_tool` AND flagged by
# `vt_reputation` lands on the SAME Asset node.
_recon_asset_cache: dict[tuple[str, str], str] = {}
_recon_asset_cache_lock = threading.Lock()


def reset_recon_asset_cache_for_testing() -> None:
    """Clear the recon Asset dedup cache. Tests must call this in
    fixtures so prior-test Asset ids don't leak."""
    with _recon_asset_cache_lock:
        _recon_asset_cache.clear()


# Secret / Credential dedup. Key is `(kind, fingerprint)` —
# fingerprint is a sha256 of the raw secret so duplicate
# detections in the same scan collapse, but we never store the
# raw value. Crypto-grade dedup discipline: the same secret
# leaked in two files = one Secret node + two Vuln-with-LEAKS-
# edge pairs.
_secret_cache: dict[tuple[str, str], str] = {}
_secret_cache_lock = threading.Lock()


def reset_secret_cache_for_testing() -> None:
    """Clear Secret/Credential dedup cache. Tests must call this
    in fixtures."""
    with _secret_cache_lock:
        _secret_cache.clear()


def _fingerprint(raw: str | bytes) -> str:
    """Stable opaque id for a secret. SHA-256 hex, truncated to
    16 chars — same shape as Strix uses elsewhere for finding
    fingerprints. Length is intentional: long enough that
    collisions are astronomically unlikely in a single scan,
    short enough that the KG renders cleanly."""
    import hashlib
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    return hashlib.sha256(data).hexdigest()[:16]


def record_secret_in_kg(
    *,
    finding_id: str | None,
    raw_value: str | None = None,
    fingerprint: str | None = None,
    masked: str = "",
    secret_type: str = "unknown",
    detected_in: str = "",
    confidence: float | None = None,
) -> str | None:
    """Emit a `Secret` node + a `LEAKS` edge from the finding's
    Vuln node when present.

    Caller passes EITHER `raw_value` (we hash it locally and
    discard) OR a pre-computed `fingerprint`. The raw value is
    NEVER stored on the node — only the hash + the masked
    representation the scanner already prepared for the wrapper.

    Args:
      finding_id: tracer's finding id. When supplied AND the
        Vuln node already exists in the KG (via
        `record_finding_in_kg` or the tracer auto-emit), a
        `LEAKS` edge is added from that Vuln to the new Secret.
      raw_value: the discovered secret. Hashed here, not stored.
        Either this OR `fingerprint` must be set.
      fingerprint: pre-computed fingerprint (when raw_value isn't
        available — e.g. SaaS leak indicator).
      masked: short masked form for wrapper display (e.g.
        `AKIA****1234`). Stored on the node verbatim.
      secret_type: canonical kind tag — `aws_access_key`,
        `github_token`, `slack_webhook`, `gcp_service_account`,
        `private_key`, `jwt`, `db_password`, `api_key`,
        `oauth_token`, `unknown`.
      detected_in: free-form locator (e.g. `src/config.py:42`).
        Stored on the Secret node as `first_seen_in` if not
        already set on a dedup re-hit.
      confidence: optional 0.0-1.0 from the detector.

    Returns the Secret node id (or the existing one when dedup
    hits); `None` when the KG is disabled, the raw_value/
    fingerprint pair is missing, or emission fails.
    """
    if raw_value is None and not fingerprint:
        return None

    try:
        from strix.agents.knowledge_graph import get_kg, is_disabled
    except ImportError:
        return None

    if is_disabled():
        return None

    fp = (fingerprint or "").strip() or _fingerprint(raw_value or "")
    if not fp:
        return None

    kind = (secret_type or "unknown").strip().lower()
    cache_key = (kind, fp)

    kg = get_kg()

    try:
        with _secret_cache_lock:
            secret_id = _secret_cache.get(cache_key)
            if secret_id is None or kg.get_node(secret_id) is None:
                props: dict[str, Any] = {
                    "kind": kind,
                    "fingerprint": fp,
                }
                if masked:
                    props["masked"] = masked
                if detected_in:
                    props["first_seen_in"] = detected_in
                if confidence is not None:
                    props["confidence"] = float(confidence)
                node = kg.add_node(type="Secret", props=props)
                secret_id = node.id
                _secret_cache[cache_key] = secret_id

        # LEAKS edge from the Vuln (when we can find it by
        # finding_id) → Secret node. Vuln nodes carry
        # `props.finding_id` so we can resolve.
        if finding_id:
            vuln_match = next(
                (
                    n for n in kg.query_nodes(type="Vuln")
                    if n.props.get("finding_id") == finding_id
                ),
                None,
            )
            if vuln_match is not None:
                # Don't double-edge — check existing first.
                existing_edges = kg.query_edges(
                    type="LEAKS", source=vuln_match.id, target=secret_id,
                )
                if not existing_edges:
                    kg.add_edge(
                        type="LEAKS",
                        source=vuln_match.id,
                        target=secret_id,
                    )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "kg_emit: record_secret failed: %s", e, exc_info=True,
        )
        return None

    return secret_id


def record_credential_in_kg(
    *,
    finding_id: str | None,
    username: str | None = None,
    masked_password: str = "",
    service: str = "",
    detected_in: str = "",
    credential_kind: str = "username_password",
) -> str | None:
    """Emit a `Credential` node + a `LEAKS` edge from the finding's
    Vuln node when present.

    Different from `record_secret_in_kg` — Credential nodes are
    USER-IDENTIFIED accounts (a username paired with a password
    or auth proof). Secret nodes are anonymous tokens (API keys,
    private keys).

    Args:
      finding_id: tracer's finding id (for LEAKS edge attachment).
      username: the discovered username / email.
      masked_password: short masked form (`hunt****` /
        `eyJ...****`). The raw password / token is NEVER stored.
      service: which SaaS / system the credential is for
        (`github`, `aws`, `okta`, `internal`).
      detected_in: free-form locator.
      credential_kind: `username_password`, `oauth_token`,
        `api_key`, `session_token`, `cert`, `ssh_key`.

    Dedup key: `(service, username, credential_kind)` —
    rotating a single user's password adds context to the
    existing node rather than a duplicate.

    Returns the Credential node id; `None` on disabled KG / bad
    input / emission failure.
    """
    if not isinstance(username, str) or not username.strip():
        return None

    try:
        from strix.agents.knowledge_graph import get_kg, is_disabled
    except ImportError:
        return None

    if is_disabled():
        return None

    norm_user = username.strip().lower()
    norm_service = (service or "unknown").strip().lower()
    norm_kind = (credential_kind or "username_password").strip().lower()
    cache_key = (f"{norm_service}|{norm_user}", norm_kind)

    kg = get_kg()

    try:
        with _secret_cache_lock:
            cred_id = _secret_cache.get(cache_key)
            if cred_id is None or kg.get_node(cred_id) is None:
                props: dict[str, Any] = {
                    "kind": norm_kind,
                    "username": norm_user,
                    "service": norm_service,
                }
                if masked_password:
                    props["masked_password"] = masked_password
                if detected_in:
                    props["first_seen_in"] = detected_in
                node = kg.add_node(type="Credential", props=props)
                cred_id = node.id
                _secret_cache[cache_key] = cred_id

        if finding_id:
            vuln_match = next(
                (
                    n for n in kg.query_nodes(type="Vuln")
                    if n.props.get("finding_id") == finding_id
                ),
                None,
            )
            if vuln_match is not None:
                existing_edges = kg.query_edges(
                    type="LEAKS", source=vuln_match.id, target=cred_id,
                )
                if not existing_edges:
                    kg.add_edge(
                        type="LEAKS",
                        source=vuln_match.id,
                        target=cred_id,
                    )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "kg_emit: record_credential failed: %s", e, exc_info=True,
        )
        return None

    return cred_id


def record_asset_in_kg(
    *,
    asset_type: str,
    value: str,
    source: str = "",
    parent_value: str | None = None,
    properties: dict[str, Any] | None = None,
) -> str | None:
    """Emit (or update) an `Asset` node for a recon-discovered surface.

    Designed for the recon-side discovery scanners
    (`subdomain_enum_tool`, `reverse_ip`, `mail_recon`,
    `passive_dns_history`, `discover_cloud_assets`, etc.) — each
    discovered subdomain / IP / MX record / bucket / account
    becomes an Asset node. The wrapper renders the asset tree;
    cross-scanner correlation (threat-intel observations + recon
    discovery) joins on the shared Asset.

    Coalesces with the threat-intel Asset cache so the same node
    surfaces both discovery AND observation. `record_threat_intel_in_kg`
    will reuse the Asset id when called on a key that's already
    in this cache, and vice versa.

    Args:
      asset_type: shape of the discovered thing —
        `domain`, `subdomain`, `ip_address`, `email`, `mx_record`,
        `cloud_bucket`, `cloud_account`, `url`.
      value: the canonical value (lowercase for domains, IP
        textually, URL canonicalised).
      source: which recon scanner produced this discovery
        (`subdomain_enum_tool`, `reverse_ip`, `mail_recon`, ...).
        Accumulated as a `sources` list on re-discovery — multiple
        scanners contributing to one Asset gets all sources.
      parent_value: optional parent-asset value for hierarchical
        recon (e.g. `parent_value="example.com"` for a discovered
        subdomain `api.example.com`). Stored as `parent` prop —
        the wrapper renders the parent tree without a separate
        edge type.
      properties: optional extra props (e.g.
        `{"resolved_ips": ["1.2.3.4"], "asn": 13335}`). Merged
        additively on re-discovery.

    Returns the Asset node id (or the existing one when dedup
    hits); `None` when the KG is disabled or emission fails.
    Best-effort; never raises.
    """
    if not isinstance(asset_type, str) or not asset_type.strip():
        return None
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        from strix.agents.knowledge_graph import get_kg, is_disabled
    except ImportError:
        return None

    if is_disabled():
        return None

    norm_type = asset_type.strip().lower()
    norm_value = value.strip().lower()
    cache_key = (norm_type, norm_value)

    kg = get_kg()

    try:
        # The recon cache + threat-intel cache share the same key
        # shape so the dedup is cross-cache. Check both before
        # creating a new node.
        with _recon_asset_cache_lock:
            existing_id = _recon_asset_cache.get(cache_key)
        if existing_id is None:
            with _asset_cache_lock:
                existing_id = _asset_cache.get(cache_key)

        if existing_id is not None and kg.get_node(existing_id) is not None:
            # Update path — merge sources + properties additively.
            node = kg.get_node(existing_id)
            if node is not None:
                if source:
                    sources = set(node.props.get("sources") or [])
                    sources.add(source)
                    node.props["sources"] = sorted(sources)
                if parent_value and not node.props.get("parent"):
                    node.props["parent"] = parent_value.strip().lower()
                if properties:
                    for k, v in properties.items():
                        if k not in node.props:
                            node.props[k] = v
            # Mirror to both caches so subsequent lookups hit.
            with _recon_asset_cache_lock:
                _recon_asset_cache[cache_key] = existing_id
            return existing_id

        props: dict[str, Any] = {
            "type": norm_type,
            "value": norm_value,
        }
        if source:
            props["sources"] = [source]
        if parent_value:
            props["parent"] = parent_value.strip().lower()
        if properties:
            for k, v in properties.items():
                if k not in props:
                    props[k] = v

        node = kg.add_node(type="Asset", props=props)
        with _recon_asset_cache_lock:
            _recon_asset_cache[cache_key] = node.id
        with _asset_cache_lock:
            _asset_cache[cache_key] = node.id
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "kg_emit: record_asset failed: %s", e, exc_info=True,
        )
        return None

    return node.id


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


# Code-location Surface dedup. SAST + IaC findings address
# `file:start_line` rather than `url:param:method`; they need
# their own dedup namespace so a URL-shaped Surface doesn't
# accidentally collide with a code-shaped one.
_code_surface_cache: dict[tuple[str, int], str] = {}
_code_surface_cache_lock = threading.Lock()


def reset_code_surface_cache_for_testing() -> None:
    """Tests must call in fixtures to keep ids stable."""
    with _code_surface_cache_lock:
        _code_surface_cache.clear()


def record_code_finding_in_kg(
    *,
    finding_id: str | None,
    file_path: str,
    start_line: int,
    cwe: str,
    severity: str,
    category: str,
    end_line: int | None = None,
    rule_id: str | None = None,
    confidence: float | None = None,
) -> tuple[str | None, str | None]:
    """SAST / IaC analogue of `record_finding_in_kg` — emits the
    `Vuln + Surface + AFFECTS` triple but with a code-location-
    shaped Surface (`file_path:start_line` keyed) rather than the
    URL-shaped Surface used for DAST findings.

    Without this path SAST + IaC findings sit outside the KG,
    blocking cross-tool chaining (a SAST hit on `auth.py:42`
    can't link to a DAST IDOR finding on `/api/user/{id}` even
    though they describe the same defect). The wrapper's
    cross-finding correlator reads `Surface` nodes regardless of
    shape, so once these are in the graph the existing
    `chaining_graph` patterns light up.

    Dedup key: `(file_path, start_line)`. Two SAST rules firing
    on the same line collapse to one Surface with two Vulns
    affecting it — the same shape DAST uses for "two probes
    against the same URL+param".

    Returns `(vuln_node_id, surface_node_id)` — both `None` when
    KG is disabled or emission fails. Never raises.
    """
    if not isinstance(file_path, str) or not file_path.strip():
        return None, None
    if not isinstance(start_line, int) or start_line < 1:
        return None, None

    try:
        from strix.agents.knowledge_graph import get_kg, is_disabled
    except ImportError:
        return None, None

    if is_disabled():
        return None, None

    kg = get_kg()
    cache_key = (file_path.strip(), start_line)

    try:
        with _code_surface_cache_lock:
            surface_node_id = _code_surface_cache.get(cache_key)
            if surface_node_id is None or kg.get_node(surface_node_id) is None:
                surface_props: dict[str, Any] = {
                    "file": file_path.strip(),
                    "start_line": start_line,
                    # `kind=code_location` differentiates this
                    # Surface from URL-shaped ones in graph queries.
                    "kind": "code_location",
                }
                if end_line is not None and end_line >= start_line:
                    surface_props["end_line"] = end_line
                surface_node = kg.add_node(
                    type="Surface", props=surface_props,
                )
                surface_node_id = surface_node.id
                _code_surface_cache[cache_key] = surface_node_id

        vuln_props: dict[str, Any] = {
            "cwe": cwe,
            "severity": (severity or "").lower(),
            "category": category,
        }
        if finding_id:
            vuln_props["finding_id"] = finding_id
        if rule_id:
            vuln_props["rule_id"] = rule_id
        if confidence is not None:
            vuln_props["confidence"] = float(confidence)

        vuln_node = kg.add_node(type="Vuln", props=vuln_props)
        kg.add_edge(
            type="AFFECTS",
            source=vuln_node.id,
            target=surface_node_id,
            props={"rule_id": rule_id} if rule_id else None,
        )
    except Exception as e:  # noqa: BLE001
        logger.debug(
            "kg_emit: record_code_finding failed: %s", e, exc_info=True,
        )
        return None, None

    return vuln_node.id, surface_node_id
