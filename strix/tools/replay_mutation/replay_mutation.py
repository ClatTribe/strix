"""Replay-with-mutation orchestrator (workitem.md Phase 5.5).

For each captured request in an endpoints inventory, dispatches
the matching specialists from the Phase 2-4 library. Conditionally —
specialists that take URL/host-shaped params (SSRF) only run when
a candidate param exists; ID-shaped specialists (IDOR) only when a
numeric/UUID segment is present.

The endpoint inventory shape matches the output of
`ingest_har_file` / `ingest_burp_file`:

    {
      "method": "GET",
      "url": "http://example.com/api/items?id=1",
      "params": ["id"],
      ...
    }

Result shape (`SpecialistResult`-like):

    {
      "status": "ok",
      "endpoints_replayed": 42,
      "specialists_invoked": 156,
      "findings_count": 7,
      "per_specialist": {
        "scan_sqli": {"hits": 2, "misses": 12, ...},
        ...
      },
      "evidence": [...],
      "errors": [...]
    }
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


# Map specialist tool name → param-name lexicon that decides
# whether to dispatch. The lexicons mirror each specialist's own
# inference logic so the orchestrator picks the right targets
# without duplicating regex.
#
# `None` means "always dispatch when ANY query param exists".
_SPECIALIST_PARAM_LEXICON: dict[str, set[str] | None] = {
    "scan_sqli": None,            # any param could be SQLi
    "scan_xss": None,             # any param could be reflected
    "scan_nosql_injection": {
        "username", "user", "email", "id", "uid", "userid",
        "q", "query", "search", "filter", "category", "name",
        "password", "passwd", "pwd", "token", "secret",
    },
    "scan_path_traversal": {
        "file", "filename", "filepath", "path", "doc", "document",
        "template", "page", "include", "inc", "load", "view",
        "show", "download", "dl", "image", "img", "src", "name",
        "open", "read", "fetch", "asset", "resource", "static",
        "data", "log", "f",
    },
    "scan_ssrf": {
        "url", "target", "uri", "image", "img", "src", "callback",
        "webhook", "redirect", "redirect_to", "dest", "destination",
        "host", "endpoint", "proxy", "fetch", "load", "feed",
        "u", "to", "next", "return", "continue", "data",
    },
    "scan_cmd_injection": {
        "host", "hostname", "addr", "ip", "domain", "target",
        "url", "ping", "lookup", "dns", "cmd", "command", "exec",
        "shell", "run", "execute", "query", "input", "data",
        "file", "filename", "path", "name",
    },
    "scan_ssti": {
        "name", "username", "user", "greeting", "message", "body",
        "subject", "content", "template", "q", "query", "search",
        "text", "comment", "title", "description", "msg", "reply",
        "input", "data", "value",
    },
    "scan_xpath_injection": {
        "username", "user", "uid", "userid", "id", "email",
        "password", "passwd", "pwd", "token", "name",
        "role", "group", "department",
        "q", "query", "search", "filter", "category",
    },
    "scan_ldap_injection": {
        "username", "user", "uid", "userid", "email", "mail",
        "cn", "dn", "sn", "givenname", "name",
        "filter", "search", "q", "query",
        "department", "ou", "group",
    },
}


_NUMERIC_ID_RE = re.compile(r"^\d+$")
_UUID_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _has_id_segment(url: str) -> bool:
    """True when the URL has a numeric/UUID path segment — IDOR
    candidate."""
    try:
        parts = urlparse(url)
        for seg in parts.path.split("/"):
            if _NUMERIC_ID_RE.match(seg) or _UUID_ID_RE.match(seg):
                return True
    except Exception:  # noqa: BLE001
        return False
    return False


def _params_match_lexicon(
    params: list[str], lexicon: set[str] | None,
) -> list[str]:
    """Return the subset of params that match the lexicon (or all
    params when lexicon is None)."""
    if lexicon is None:
        return list(params)
    return [p for p in params if isinstance(p, str) and p.lower() in lexicon]


def _safe_invoke(tool_name: str, **kwargs: Any) -> dict[str, Any]:
    """Resolve the specialist by name from the registry and call it.
    Returns the SpecialistResult dict; falls back to an error result
    when the tool isn't registered."""
    try:
        from strix.tools.specialist.registry import (
            get_specialist_descriptor,
        )
        desc = get_specialist_descriptor(tool_name)
        if desc is None or desc.func is None:
            return {
                "status": "error",
                "error": f"specialist {tool_name!r} not registered",
                "findings": [], "evidence": [],
            }
        return desc.func(**kwargs)
    except Exception as e:  # noqa: BLE001
        logger.debug("replay invoke %s failed: %s", tool_name, e, exc_info=True)
        return {
            "status": "error",
            "error": f"{type(e).__name__}: {e}",
            "findings": [], "evidence": [],
        }


# iter-22.9: removed `@register_tool` — consolidated into
# `replay_mutation(source="endpoints", ...)` below. Internal
# helper retained for direct in-module calls.
def replay_mutation_on_endpoints(
    endpoints: list[dict[str, Any]],
    *,
    families: list[str] | None = None,
    max_endpoints: int = 200,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """For each endpoint in the inventory, dispatch matching
    specialists from the Phase 2-4 library.

    Args:
        endpoints: list of endpoint records (output shape of
            `ingest_har_file` / `ingest_burp_file`). Each record
            should have at minimum `url` and `params`.
        families: optional subset of specialist tool names to run
            (default: all in `_SPECIALIST_PARAM_LEXICON` plus
            `scan_idor` and `scan_secrets_in_response`).
        max_endpoints: cap to bound fan-out.
        extra_headers: forwarded to every specialist call.

    Returns: aggregated dict (see module docstring).
    """
    if not isinstance(endpoints, list):
        return {
            "status": "error",
            "error": "endpoints must be a list",
            "findings": [], "evidence": [],
        }

    capped = endpoints[: max(0, int(max_endpoints))]
    requested_families = list(families) if families else (
        list(_SPECIALIST_PARAM_LEXICON.keys())
        + ["scan_idor", "scan_secrets_in_response"]
    )

    per_specialist: dict[str, dict[str, int]] = {
        name: {"hits": 0, "misses": 0, "errors": 0, "calls": 0}
        for name in requested_families
    }
    aggregate_findings: list[dict[str, Any]] = []
    evidence: list[str] = []
    errors: list[str] = []
    specialists_invoked = 0

    for ep in capped:
        if not isinstance(ep, dict):
            continue
        url = ep.get("url")
        params = ep.get("params") or []
        if not isinstance(url, str) or not url.strip():
            continue
        if not isinstance(params, list):
            params = []

        # Run param-bound specialists.
        for tool_name in requested_families:
            lexicon = _SPECIALIST_PARAM_LEXICON.get(tool_name)
            # IDOR + secrets are URL-bound, not param-shaped.
            if tool_name == "scan_idor":
                if not _has_id_segment(url):
                    continue
                result = _safe_invoke(
                    tool_name, url=url, extra_headers=extra_headers,
                )
            elif tool_name == "scan_secrets_in_response":
                result = _safe_invoke(
                    tool_name, url=url, extra_headers=extra_headers,
                )
            else:
                if lexicon is None:
                    targeted_params = list(params)
                else:
                    targeted_params = _params_match_lexicon(params, lexicon)
                if not targeted_params:
                    continue
                result = _safe_invoke(
                    tool_name, url=url, params=targeted_params,
                    extra_headers=extra_headers,
                )

            per_specialist[tool_name]["calls"] += 1
            specialists_invoked += 1

            if not isinstance(result, dict):
                per_specialist[tool_name]["errors"] += 1
                continue
            if result.get("status") == "error":
                per_specialist[tool_name]["errors"] += 1
                errors.append(
                    f"{tool_name} {url}: "
                    f"{(result.get('error') or '')[:200]}"
                )
                continue
            findings = result.get("findings") or []
            if isinstance(findings, list) and findings:
                per_specialist[tool_name]["hits"] += 1
                aggregate_findings.extend(findings)
                evidence.append(
                    f"{tool_name} HIT on {url}: "
                    f"{len(findings)} finding(s)"
                )
            else:
                per_specialist[tool_name]["misses"] += 1

    # Phase 1.6 — provenance log
    try:
        from strix.agents.decision_log import record_decision
        record_decision(
            kind="specialist_invocation",
            target=(capped[0].get("url") if capped else ""),
            actor={"tool_name": "replay_mutation_on_endpoints"},
            input={
                "endpoints_count": len(capped),
                "families": requested_families,
            },
            output={
                "specialists_invoked": specialists_invoked,
                "findings_count": len(aggregate_findings),
            },
        )
    except Exception:  # noqa: BLE001
        pass

    return {
        "status": "ok",
        "endpoints_replayed": len(capped),
        "specialists_invoked": specialists_invoked,
        "findings_count": len(aggregate_findings),
        "per_specialist": per_specialist,
        "evidence": evidence[:100],
        "errors": errors[:50],
    }


# iter-22.9: removed `@register_tool` — consolidated into
# `replay_mutation(source="har", file_path=...)`. Internal helper.
def replay_mutation_from_har_file(
    path: str,
    *,
    families: list[str] | None = None,
    max_endpoints: int = 200,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Parse a HAR file and replay each captured request with the
    mutation matrix. Convenience over `ingest_har_file` +
    `replay_mutation_on_endpoints`."""
    try:
        from strix.tools.traffic_ingest.traffic_ingest import (
            ingest_har_file,
        )
    except Exception as e:  # noqa: BLE001
        return {
            "status": "error",
            "error": f"ingest_har_file unavailable: {type(e).__name__}: {e}",
        }
    ingested = ingest_har_file(path)
    if not ingested.get("success"):
        return {
            "status": "error",
            "error": f"HAR ingest failed: {ingested.get('error', 'unknown')}",
        }
    endpoints = ingested.get("endpoints") or []
    return replay_mutation_on_endpoints(
        endpoints=endpoints,
        families=families,
        max_endpoints=max_endpoints,
        extra_headers=extra_headers,
    )


# iter-22.9: removed `@register_tool` — consolidated into
# `replay_mutation(source="burp", file_path=...)`. Internal helper.
def replay_mutation_from_burp_file(
    path: str,
    *,
    families: list[str] | None = None,
    max_endpoints: int = 200,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Parse a Burp project XML export and replay each captured
    request with the mutation matrix."""
    try:
        from strix.tools.traffic_ingest.traffic_ingest import (
            ingest_burp_file,
        )
    except Exception as e:  # noqa: BLE001
        return {
            "status": "error",
            "error": f"ingest_burp_file unavailable: {type(e).__name__}: {e}",
        }
    ingested = ingest_burp_file(path)
    if not ingested.get("success"):
        return {
            "status": "error",
            "error": f"Burp ingest failed: {ingested.get('error', 'unknown')}",
        }
    endpoints = ingested.get("endpoints") or []
    return replay_mutation_on_endpoints(
        endpoints=endpoints,
        families=families,
        max_endpoints=max_endpoints,
        extra_headers=extra_headers,
    )


@register_tool(
    sandbox_execution=False,
    mitre_techniques=["T1190"],
    provenance="framework",
)
def replay_mutation(
    source: str,
    endpoints: list[dict[str, Any]] | None = None,
    file_path: str | None = None,
    families: list[str] | None = None,
    max_endpoints: int = 200,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Unified replay-with-mutation orchestrator — replaces
    `replay_mutation_on_endpoints`, `replay_mutation_from_har_file`,
    and `replay_mutation_from_burp_file` (iter-22.9 catalog
    consolidation per
    `docs/l2-architecture-evaluation.md §5.2`).

    Mode dispatch by `source`:

      * `source="endpoints"` — requires `endpoints=` (the inventory
        list, typically from `ingest_har_file` / `ingest_burp_file`
        or `openapi_spec_ingest`).
      * `source="har"` — requires `file_path=` (HAR JSON path).
      * `source="burp"` — requires `file_path=` (Burp XML export).

    Args:
        source: one of `endpoints` / `har` / `burp`.
        endpoints: inventory list (mode `endpoints` only).
        file_path: filesystem path (modes `har` and `burp`).
        families: optional specialist families filter (e.g.
            `["sqli", "xxe"]`) — defaults to the full library.
        max_endpoints: cap how many endpoints the mutation matrix
            covers (default 200).
        extra_headers: optional extra headers added to every
            replay (auth tokens, scope headers, etc.).

    Returns: `SpecialistResult`-shaped dict with `status`,
    `endpoints_replayed`, `specialists_invoked`, `findings_count`,
    `per_specialist`, `evidence`, `errors`. Errors return as
    `{"status": "error", "error": ...}` — never raises.
    """
    src = (source or "").strip().lower()
    if src == "endpoints":
        if not isinstance(endpoints, list):
            return {
                "status": "error",
                "error": (
                    "replay_mutation(source='endpoints') requires "
                    "`endpoints=` list"
                ),
            }
        return replay_mutation_on_endpoints(
            endpoints=endpoints,
            families=families,
            max_endpoints=max_endpoints,
            extra_headers=extra_headers,
        )
    if src == "har":
        if not isinstance(file_path, str) or not file_path.strip():
            return {
                "status": "error",
                "error": (
                    "replay_mutation(source='har') requires "
                    "`file_path=` (path to HAR JSON)"
                ),
            }
        return replay_mutation_from_har_file(
            path=file_path,
            families=families,
            max_endpoints=max_endpoints,
            extra_headers=extra_headers,
        )
    if src == "burp":
        if not isinstance(file_path, str) or not file_path.strip():
            return {
                "status": "error",
                "error": (
                    "replay_mutation(source='burp') requires "
                    "`file_path=` (path to Burp XML export)"
                ),
            }
        return replay_mutation_from_burp_file(
            path=file_path,
            families=families,
            max_endpoints=max_endpoints,
            extra_headers=extra_headers,
        )
    return {
        "status": "error",
        "error": (
            f"replay_mutation: invalid source={source!r}. "
            "Use 'endpoints' / 'har' / 'burp'."
        ),
    }
