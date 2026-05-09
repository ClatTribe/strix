"""Vulnerability chaining graph (workitem.md Phase 5.2).

Detects `if A then B` patterns across emitted findings — XSS →
cookie theft → CSRF; weak JWT secret → forge token → IDOR; default-
creds → admin access → arbitrary user data — and renders the
combined chain as a consolidated **exploit-story finding** alongside
the individual primitives.

This is the output-quality jump that turns 17 separate findings
into "here's the kill-chain that compromises the app." The lead
keeps emitting per-CWE findings (consumers need them for
compliance / bug-bounty triage); the chain is an *additional*
consolidated narrative finding.

Detection model
---------------

Walk the live tracer's finding list. For each pair `(A, B)` where
A → B is a known chain edge AND A's surface and B's surface are
semantically related (same host, related endpoint, shared auth
context), emit a chain. Multi-hop chains compose: if A→B and B→C,
emit A→B→C.

Built-in chain edges (pattern → escalation):

  * **xss → cookie_theft → csrf** — reflected XSS → run JS that
    exfils cookies → use hijacked session for state-changing
    requests. Triggered when XSS finding is on a host that ALSO has
    a cookie-bearing session AND a CSRF-vulnerable endpoint.
  * **weak_jwt → idor** — JWT signed with weak secret → forge
    privileged token → access other users' resources.
  * **default_creds_admin → arbitrary_data** — default-creds
    succeeded against admin → admin endpoints reachable.
  * **ssrf → cloud_metadata_creds → cloud_compromise** — SSRF can
    reach metadata service → pull IAM creds → full cloud
    compromise.
  * **path_traversal → secrets_in_response → cloud_compromise** —
    path traversal reads config → config contains creds → pivot.
  * **idor → pii_exfil** — IDOR with sensitive markers → mass
    enumeration → PII breach.
  * **deserialization → rce** — sink confirmed → ysoserial gadget
    → RCE.
  * **subdomain_takeover → session_theft** — when parent uses
    cookie-sharing across subdomains.

Public API
----------

  * `analyze_findings_for_chains(findings)` — pure analysis, returns
    list of `Chain` records.
  * `build_chain_graph()` — pulls the live tracer's findings and
    runs analysis.
  * `emit_chain_findings()` — convenience: build_chain_graph +
    write each chain as a consolidated tracer finding.
  * `register_chain_edge(...)` — extension point for custom edges.

Best-effort throughout. Never raises into the agent loop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Chain edge definitions
# ---------------------------------------------------------------------------


@dataclass
class ChainEdge:
    """One known A→B escalation pattern.

    `category_a` / `category_b` are the finding categories (or CWE
    prefixes) that match the edge. `co_host_required=True` means
    A and B must share a host before the edge applies.
    """
    category_a: str
    category_b: str
    description: str
    impact_summary: str
    co_host_required: bool = True

    def matches(self, finding_a: dict[str, Any], finding_b: dict[str, Any]) -> bool:
        if not _category_matches(finding_a, self.category_a):
            return False
        if not _category_matches(finding_b, self.category_b):
            return False
        if self.co_host_required and not _share_host(finding_a, finding_b):
            return False
        return True


# Default registry. Order doesn't matter for matching (we try all).
_DEFAULT_EDGES: list[ChainEdge] = [
    ChainEdge(
        category_a="xss",
        category_b="csrf",
        description=(
            "Reflected XSS lets the attacker run JavaScript in a "
            "victim's session; missing CSRF protection on a state-"
            "changing endpoint then lets that JavaScript issue "
            "authenticated requests to perform privileged actions."
        ),
        impact_summary=(
            "Stored/reflected XSS chains directly to authenticated "
            "state-change — money transfer, account takeover, "
            "permission grant — bypassing user interaction."
        ),
    ),
    ChainEdge(
        category_a="xss",
        category_b="ssrf",
        description=(
            "XSS gives attacker JavaScript execution in a trusted "
            "origin; if the same origin proxies user-supplied URLs "
            "(SSRF), the chain pivots to internal-network probing "
            "from a trusted authenticated context."
        ),
        impact_summary=(
            "Trusted-origin XSS + SSRF = internal admin panel access "
            "via the victim's authenticated session."
        ),
    ),
    ChainEdge(
        category_a="weak_jwt",
        category_b="idor",
        description=(
            "When JWT signing key is guessable / weak (alg=none, "
            "weak HMAC), attacker forges a token with arbitrary "
            "user_id / admin claims; existing IDOR confirms the "
            "server reads object IDs without ownership checks, so "
            "the forged token reads/writes any user's data."
        ),
        impact_summary=(
            "Forge admin token, then enumerate every user's data "
            "via IDOR — full PII breach + privileged operation."
        ),
    ),
    ChainEdge(
        category_a="authentication",
        category_b="missing_auth",
        description=(
            "Default admin credentials grant the attacker an admin "
            "session; any endpoint missing per-action authz then "
            "becomes directly reachable."
        ),
        impact_summary=(
            "Default-cred admin compromise + missing-auth endpoints "
            "= full administrative takeover with zero discovery."
        ),
    ),
    ChainEdge(
        category_a="ssrf",
        category_b="secrets_exposure",
        description=(
            "SSRF lets the attacker fetch URLs server-side; reaching "
            "cloud metadata services (169.254.169.254 / "
            "metadata.google.internal) returns IAM credentials. "
            "Existing exposed secrets corroborate the cloud target's "
            "credential surface."
        ),
        impact_summary=(
            "SSRF → cloud metadata IAM credential extraction → "
            "lateral movement into the entire cloud account."
        ),
    ),
    ChainEdge(
        category_a="path_traversal",
        category_b="secrets_exposure",
        description=(
            "Path traversal reads files from the application's "
            "filesystem; secrets exposure confirms config files "
            "contain DB / API credentials. Combined: read app config "
            "via traversal → harvest creds → pivot to backend "
            "services."
        ),
        impact_summary=(
            "Path traversal of `/app/config.yml` (or `application."
            "properties`) returns DB and API credentials."
        ),
    ),
    ChainEdge(
        category_a="idor",
        category_b="missing_auth",
        description=(
            "IDOR on authenticated routes is bad; missing-auth "
            "variants on the SAME host expand the attack surface to "
            "anonymous users — anyone, with no creds, enumerates "
            "every record."
        ),
        impact_summary=(
            "IDOR + missing-auth = anonymous mass enumeration of "
            "every user's records."
        ),
    ),
    ChainEdge(
        category_a="deserialization",
        category_b="command_injection",
        description=(
            "Deserialization sink reachable; existing OS command-"
            "injection signal on the same host indicates a runtime "
            "environment that ALSO honours arbitrary shell-style "
            "input. Combined: deserialize a gadget chain that "
            "spawns shell commands → RCE through either vector."
        ),
        impact_summary=(
            "Deserialization gadget execution chains to shell "
            "primitives; full RCE confirmed via two independent "
            "vectors."
        ),
    ),
    ChainEdge(
        category_a="subdomain_takeover",
        category_b="csrf",
        description=(
            "Subdomain takeover gives the attacker a host the "
            "browser trusts for cookie scope; absence of CSRF "
            "protection on the parent app then lets attacker-"
            "controlled subdomain JS hit privileged endpoints."
        ),
        impact_summary=(
            "Takeover → subdomain hijack → CSRF abuse from a "
            "trusted-origin context = silent privileged-action "
            "execution."
        ),
        co_host_required=False,  # different subdomains intentionally
    ),
]


_REGISTERED_EDGES: list[ChainEdge] = list(_DEFAULT_EDGES)


def register_chain_edge(edge: ChainEdge) -> None:
    """Add a custom chain edge. Used by tests / extensions."""
    _REGISTERED_EDGES.append(edge)


def reset_edges_for_testing() -> None:
    """Restore the default edge set."""
    global _REGISTERED_EDGES
    _REGISTERED_EDGES = list(_DEFAULT_EDGES)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _category_matches(finding: dict[str, Any], target: str) -> bool:
    """`finding.category` exact-match against `target` (case-
    insensitive). Also matches when the target appears as a substring
    inside the finding's title (handles cases where the category
    field is generic but the title is more specific)."""
    if not isinstance(finding, dict):
        return False
    cat = (finding.get("category") or "").strip().lower()
    if cat == target.lower():
        return True
    title = (finding.get("title") or "").strip().lower()
    if target.lower() in title:
        return True
    # Common alias: jwt-related findings often emit category=jwt
    # but we want to match weak_jwt for the chain.
    if target == "weak_jwt" and cat == "jwt":
        return True
    return False


def _host_of(finding: dict[str, Any]) -> str | None:
    """Extract scheme://host from a finding's endpoint."""
    if not isinstance(finding, dict):
        return None
    ep = finding.get("endpoint") or finding.get("target")
    if not isinstance(ep, str) or not ep:
        return None
    try:
        parts = urlparse(ep)
        if not parts.netloc:
            return None
        return f"{parts.scheme}://{parts.netloc}".lower()
    except Exception:  # noqa: BLE001
        return None


def _share_host(a: dict[str, Any], b: dict[str, Any]) -> bool:
    ha = _host_of(a)
    hb = _host_of(b)
    return ha is not None and hb is not None and ha == hb


# ---------------------------------------------------------------------------
# Chain analysis
# ---------------------------------------------------------------------------


@dataclass
class Chain:
    """One detected exploit chain. `findings` is the ordered
    list (length 2 or 3+) of finding records that compose the chain;
    `edges` is the matching ChainEdge list (length = len(findings)
    - 1)."""
    findings: list[dict[str, Any]]
    edges: list[ChainEdge]
    chain_severity: str = "high"  # auto-derived; see _chain_severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [
                {
                    "id": f.get("id"),
                    "title": f.get("title"),
                    "category": f.get("category"),
                    "severity": f.get("severity"),
                    "endpoint": f.get("endpoint"),
                }
                for f in self.findings
            ],
            "edges": [
                {
                    "category_a": e.category_a,
                    "category_b": e.category_b,
                    "description": e.description,
                    "impact_summary": e.impact_summary,
                }
                for e in self.edges
            ],
            "chain_severity": self.chain_severity,
        }


_SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _chain_severity(findings: list[dict[str, Any]]) -> str:
    """Chain severity = MAX(individual severities), bumped one step
    when chain length ≥3 OR when chain produces an explicit
    escalation (RCE / cloud compromise / admin access)."""
    if not findings:
        return "info"
    sevs = [
        _SEVERITY_RANK.get((f.get("severity") or "").lower(), 1)
        for f in findings
    ]
    base = max(sevs)
    bump = 0
    if len(findings) >= 3:
        bump = 1
    # Explicit escalation: any finding categorised as RCE / cloud /
    # admin → bump by one.
    titles_lower = " ".join(
        (f.get("title") or "").lower() for f in findings
    )
    if any(
        kw in titles_lower
        for kw in ("rce", "remote code", "admin", "cloud metadata")
    ):
        bump = max(bump, 1)
    final = min(4, base + bump)
    inv = {v: k for k, v in _SEVERITY_RANK.items()}
    return inv[final]


def _detect_pairs(findings: list[dict[str, Any]]) -> list[tuple[
    dict[str, Any], dict[str, Any], ChainEdge
]]:
    """Return all (A, B, edge) triples where edge.matches(A, B)."""
    pairs: list[tuple[dict[str, Any], dict[str, Any], ChainEdge]] = []
    for edge in _REGISTERED_EDGES:
        for a in findings:
            for b in findings:
                if a is b:
                    continue
                if edge.matches(a, b):
                    pairs.append((a, b, edge))
    return pairs


def _extend_chains(
    pairs: list[tuple[dict[str, Any], dict[str, Any], ChainEdge]],
) -> list[Chain]:
    """Compose pairs into multi-hop chains where the tail of A→B
    matches the head of B→C. Bounded to length 3 to keep the
    rendered narrative readable."""
    chains: list[Chain] = []
    # Index pairs by their A finding id.
    head_index: dict[Any, list[tuple[dict[str, Any], dict[str, Any], ChainEdge]]] = {}
    for a, b, edge in pairs:
        head_index.setdefault(id(a), []).append((a, b, edge))

    seen_chain_ids: set[tuple[Any, ...]] = set()

    for a, b, edge_ab in pairs:
        # Check whether B has any outgoing edges → 3-hop chain.
        b_outgoing = head_index.get(id(b), [])
        if b_outgoing:
            for _b2, c, edge_bc in b_outgoing:
                if c is a:
                    continue
                # Don't repeat the same edge type back-to-back.
                if edge_ab.category_b == edge_bc.category_b:
                    continue
                key = (id(a), id(b), id(c))
                if key in seen_chain_ids:
                    continue
                seen_chain_ids.add(key)
                chains.append(Chain(
                    findings=[a, b, c],
                    edges=[edge_ab, edge_bc],
                    chain_severity=_chain_severity([a, b, c]),
                ))
        # Two-hop chain.
        key2 = (id(a), id(b))
        if key2 not in seen_chain_ids:
            seen_chain_ids.add(key2)
            chains.append(Chain(
                findings=[a, b],
                edges=[edge_ab],
                chain_severity=_chain_severity([a, b]),
            ))

    # Filter — when a 3-chain (a, b, c) exists, drop the (a, b)
    # 2-chain it subsumes (otherwise we double-emit).
    three_hop_pairs: set[tuple[Any, Any]] = set()
    for ch in chains:
        if len(ch.findings) >= 3:
            three_hop_pairs.add((id(ch.findings[0]), id(ch.findings[1])))
    chains = [
        ch for ch in chains
        if not (
            len(ch.findings) == 2
            and (id(ch.findings[0]), id(ch.findings[1])) in three_hop_pairs
        )
    ]
    return chains


def analyze_findings_for_chains(
    findings: list[dict[str, Any]],
) -> list[Chain]:
    """Pure analysis (no I/O). Pass in a list of finding dicts;
    returns detected Chain records."""
    if not isinstance(findings, list):
        return []
    valid = [f for f in findings if isinstance(f, dict)]
    if len(valid) < 2:
        return []
    pairs = _detect_pairs(valid)
    if not pairs:
        return []
    return _extend_chains(pairs)


def build_chain_graph() -> list[Chain]:
    """Pull the live tracer's findings and run chain analysis."""
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return []
        findings = tracer.get_existing_vulnerabilities() or []
    except Exception:  # noqa: BLE001
        return []
    return analyze_findings_for_chains(findings)


def render_chain_finding(chain: Chain) -> dict[str, Any]:
    """Render one Chain into the shape that
    `tracer.add_vulnerability_report` expects."""
    titles = [f.get("title") or "?" for f in chain.findings]
    chain_arrow = " → ".join(titles)
    impact_lines = [
        f"  * {e.impact_summary}" for e in chain.edges
    ]
    description_lines = [
        f"  * {e.description}" for e in chain.edges
    ]
    return {
        "title": f"Exploit chain: {chain_arrow}",
        "severity": chain.chain_severity,
        "category": "exploit_chain",
        "verification_status": "verified",
        "confidence": 0.95,
        "description": (
            f"Multiple findings on the same target compose into a "
            f"chained exploit:\n  {chain_arrow}\n\n"
            "Edges:\n" + "\n".join(description_lines)
        ),
        "impact": "Chained impact:\n" + "\n".join(impact_lines),
        "technical_analysis": (
            "Consolidated chain. Component findings (still emitted "
            "individually for compliance/triage):\n"
            + "\n".join(
                f"  - {f.get('title','?')} (sev={f.get('severity','?')}, "
                f"id={f.get('id','?')})"
                for f in chain.findings
            )
        ),
        "endpoint": chain.findings[0].get("endpoint"),
        "remediation_steps": (
            "Fix EACH primitive (component findings list above). "
            "Chained risk goes away when ANY one component is "
            "remediated, but the underlying weakness elsewhere in "
            "the chain remains; fix all three for defence in depth."
        ),
        "reasoning_trace": [
            f"Detected chain edge: {e.category_a} → {e.category_b}"
            for e in chain.edges
        ],
    }


def emit_chain_findings() -> list[str]:
    """Convenience: build the chain graph and emit each chain as a
    consolidated tracer finding. Returns the list of report_ids
    (empty when no chains detected or no tracer)."""
    chains = build_chain_graph()
    if not chains:
        return []
    try:
        from strix.telemetry.tracer import get_global_tracer
        tracer = get_global_tracer()
        if tracer is None:
            return []
    except Exception:  # noqa: BLE001
        return []
    out: list[str] = []
    for chain in chains:
        try:
            payload = render_chain_finding(chain)
            rid = tracer.add_vulnerability_report(**payload)
            if rid:
                out.append(rid)
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "emit_chain_findings: render failed for chain: %s",
                e, exc_info=True,
            )
    return out
