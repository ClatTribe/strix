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
