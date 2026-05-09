"""Cross-tool security context for the §8.5 single-lead architecture.

Problem
-------

The lead agent today calls 50+ tools per scan. Each tool's output
flows back into the conversation history, gets compressed by
`MemoryCompressor` after ~90% of the context window fills, and
eventually disappears. By turn 30 the lead has typically forgotten:

  * What tech stack `scan_misconfig` fingerprinted on the first
    GET — meaningful for SQLi payload selection (MSSQL vs MySQL),
    cookie-attribute scoring, version-CVE lookups.
  * What auth tokens / session cookies it captured during recon —
    needed to probe authenticated endpoints (admin section,
    `/api/Baskets/<id>` IDOR, JWT replay).
  * Which endpoints it's already probed and what status they
    returned — leads to redundant reprobing.
  * Partial signals from earlier probes that didn't rise to
    "finding" — `/redirect?to=` reflected the URL but no XSS
    fired; that's a candidate open-redirect that needs follow-up.

A senior security engineer keeps a structured notebook (Burp
sitemap + custom notes). This module is that notebook for the
lead agent: a structured fact ledger that's:

  1. **Auto-populated** by specialists when they finish (no
     prompt-compliance dependency — the data lands regardless of
     what the model emits in its message).
  2. **Rendered into the system prompt** every turn so the model
     always sees current state. Survives memory compression.
  3. **Queryable via tools** so the lead can inspect specific
     subsections without re-rendering the whole context.
  4. **Persisted** to `<run_dir>/security_context.jsonl` so the
     wrapper can replay the lead's reasoning.

Schema (illustrative — see actual dataclasses below):

  TechStack: server / language / framework / database / cms /
             version_disclosed / raw_headers
  EndpointInfo: path / methods_seen / params_seen / auth_required /
                last_status / response_headers / probed_for / notes
  AuthState: label / cookies / bearer / csrf_token / notes /
             captured_at
  PartialSignal: surface / signal / next_probe / timestamp /
                 category_hint  — observations that don't rise to
                 a finding YET but are worth chaining with later
                 findings (e.g. URL reflected in Location header is
                 a candidate open-redirect)
  SecurityContext: target_url + the four above

Renders into the system prompt as a structured `SECURITY CONTEXT:`
block — the lead literally sees its own notebook every turn.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TechStack:
    server: str | None = None
    language: str | None = None
    framework: str | None = None
    database: str | None = None
    cms: str | None = None
    version_disclosed: bool = False
    raw_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class EndpointInfo:
    path: str
    methods_seen: list[str] = field(default_factory=list)
    params_seen: list[str] = field(default_factory=list)
    auth_required: bool | None = None
    last_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    probed_for: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class AuthState:
    label: str
    cookies: dict[str, str] = field(default_factory=dict)
    bearer: str | None = None
    csrf_token: str | None = None
    notes: str = ""
    captured_at: str = ""


@dataclass
class PartialSignal:
    surface: str
    signal: str
    next_probe: str
    timestamp: str = ""
    category_hint: str = ""


@dataclass
class SecurityContext:
    target_url: str = ""
    tech_stack: TechStack = field(default_factory=TechStack)
    endpoints: dict[str, EndpointInfo] = field(default_factory=dict)
    auth_states: dict[str, AuthState] = field(default_factory=dict)
    partial_signals: list[PartialSignal] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "tech_stack": asdict(self.tech_stack),
            "endpoints": {k: asdict(v) for k, v in self.endpoints.items()},
            "auth_states": {k: asdict(v) for k, v in self.auth_states.items()},
            "partial_signals": [asdict(s) for s in self.partial_signals],
        }


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------


_lock = threading.Lock()
_global_context: SecurityContext | None = None


def get_security_context() -> SecurityContext:
    """Return the process-wide SecurityContext singleton, creating
    on first access."""
    global _global_context
    with _lock:
        if _global_context is None:
            _global_context = SecurityContext()
        return _global_context


def reset_security_context() -> None:
    """Reset for tests."""
    global _global_context
    with _lock:
        _global_context = None


def set_target_url(url: str) -> None:
    """Set when the scan starts — used for endpoint canonicalization."""
    if not isinstance(url, str) or not url.strip():
        return
    ctx = get_security_context()
    with _lock:
        ctx.target_url = url.strip()
    _persist()


# ---------------------------------------------------------------------------
# Update API — specialists call these
# ---------------------------------------------------------------------------


def update_tech_stack(**kwargs: Any) -> None:
    """Update tech-stack fields. Only non-None values overwrite —
    a later specialist that doesn't know the database doesn't wipe
    a prior fingerprint."""
    ctx = get_security_context()
    with _lock:
        for k, v in kwargs.items():
            if v is None:
                continue
            if k == "raw_headers":
                # Handled specially below — merge, don't overwrite.
                continue
            if hasattr(ctx.tech_stack, k):
                setattr(ctx.tech_stack, k, v)
        # Merge raw_headers if provided (preserves headers seen in
        # earlier responses).
        if "raw_headers" in kwargs and isinstance(kwargs["raw_headers"], dict):
            ctx.tech_stack.raw_headers.update(kwargs["raw_headers"])
    _persist()


def record_endpoint(
    path: str,
    *,
    method: str | None = None,
    status: int | None = None,
    params: list[str] | None = None,
    auth_required: bool | None = None,
    response_headers: dict[str, str] | None = None,
    probed_for: str | None = None,
    notes: str = "",
) -> None:
    """Record / update one endpoint."""
    if not isinstance(path, str) or not path.strip():
        return
    path = _canonical_path(path)
    ctx = get_security_context()
    with _lock:
        info = ctx.endpoints.get(path)
        if info is None:
            info = EndpointInfo(path=path)
            ctx.endpoints[path] = info
        if method and method.upper() not in info.methods_seen:
            info.methods_seen.append(method.upper())
        if status is not None:
            info.last_status = status
        if params:
            for p in params:
                if p and p not in info.params_seen:
                    info.params_seen.append(p)
        if auth_required is not None:
            info.auth_required = auth_required
        if response_headers:
            info.response_headers.update(response_headers)
        if probed_for and probed_for not in info.probed_for:
            info.probed_for.append(probed_for)
        if notes:
            info.notes = (info.notes + " " + notes).strip()[:500]
    _persist()


def record_auth_state(
    label: str,
    *,
    cookies: dict[str, str] | None = None,
    bearer: str | None = None,
    csrf_token: str | None = None,
    notes: str = "",
) -> None:
    """Record a captured auth state (anon vs user-X vs admin)."""
    if not isinstance(label, str) or not label.strip():
        return
    label = label.strip()
    ctx = get_security_context()
    with _lock:
        state = ctx.auth_states.get(label)
        if state is None:
            state = AuthState(
                label=label,
                captured_at=datetime.now(timezone.utc).isoformat(),
            )
            ctx.auth_states[label] = state
        if cookies:
            state.cookies.update(cookies)
        if bearer:
            state.bearer = bearer
        if csrf_token:
            state.csrf_token = csrf_token
        if notes:
            state.notes = (state.notes + " " + notes).strip()[:500]
    _persist()


def record_partial_signal(
    *,
    surface: str,
    signal: str,
    next_probe: str = "",
    category_hint: str = "",
) -> None:
    """A partial signal worth follow-up. Specialists call this when
    they observe something interesting but not strong enough to emit
    a finding (e.g. URL reflection in a Location header is a
    candidate open-redirect)."""
    if not surface or not signal:
        return
    ctx = get_security_context()
    sig = PartialSignal(
        surface=surface,
        signal=signal,
        next_probe=next_probe,
        category_hint=category_hint,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    with _lock:
        # De-dup on surface+signal
        for existing in ctx.partial_signals:
            if existing.surface == surface and existing.signal == signal:
                return
        ctx.partial_signals.append(sig)
        # Bound list to 50 most recent
        if len(ctx.partial_signals) > 50:
            ctx.partial_signals = ctx.partial_signals[-50:]
    _persist()


# ---------------------------------------------------------------------------
# Read API
# ---------------------------------------------------------------------------


def get_endpoint(path: str) -> EndpointInfo | None:
    if not path:
        return None
    return get_security_context().endpoints.get(_canonical_path(path))


def list_endpoints() -> list[EndpointInfo]:
    return list(get_security_context().endpoints.values())


def get_auth_state(label: str) -> AuthState | None:
    return get_security_context().auth_states.get(label)


def list_auth_states() -> list[AuthState]:
    return list(get_security_context().auth_states.values())


def list_partial_signals() -> list[PartialSignal]:
    return list(get_security_context().partial_signals)


# ---------------------------------------------------------------------------
# Render — for system prompt injection
# ---------------------------------------------------------------------------


def render_for_prompt(*, max_endpoints: int = 30, max_signals: int = 20) -> str:
    """Render a compact, model-readable snapshot of the current
    SecurityContext for inclusion in the system prompt every turn.

    The shape is deliberately verbose-with-structure (not pure JSON)
    so the model parses it as factual context, not as data to
    transform. Caps prevent unbounded prompt growth on long scans.

    Also surfaces SPECIALIST RECOMMENDATIONS — concrete next-call
    suggestions for unprobed endpoints. The post-#178 benchmark
    showed the lead happily exploring with `send_request` /
    `browser_action` while never invoking the deterministic
    specialists. Surfacing the specialist hint inline in the
    notebook gives the model a clear handoff: it sees an unprobed
    endpoint AND the exact specialist that would auto-emit a
    finding for it.
    """
    ctx = get_security_context()
    parts: list[str] = []

    parts.append(f"TARGET: {ctx.target_url or '(not yet set)'}")

    # Tech stack
    ts = ctx.tech_stack
    if any([ts.server, ts.language, ts.framework, ts.database, ts.cms]):
        ts_lines = ["TECH STACK:"]
        if ts.server: ts_lines.append(f"  - server: {ts.server}")
        if ts.language: ts_lines.append(f"  - language: {ts.language}")
        if ts.framework: ts_lines.append(f"  - framework: {ts.framework}")
        if ts.database: ts_lines.append(f"  - database: {ts.database}  ← informs SQLi payload selection")
        if ts.cms: ts_lines.append(f"  - cms: {ts.cms}")
        if ts.version_disclosed:
            ts_lines.append("  - VERSION DISCLOSURE detected (CVE-lookup candidate)")
        parts.append("\n".join(ts_lines))

    # Endpoints (most-probed first)
    eps = list(ctx.endpoints.values())
    if eps:
        eps_sorted = sorted(eps, key=lambda e: -len(e.probed_for))[:max_endpoints]
        ep_lines = [f"ENDPOINTS DISCOVERED ({len(eps)} total{', showing top ' + str(max_endpoints) if len(eps) > max_endpoints else ''}):"]
        for e in eps_sorted:
            methods = ",".join(e.methods_seen) or "?"
            status = e.last_status or "?"
            params = ",".join(e.params_seen[:5]) or "(none)"
            auth = "auth-required" if e.auth_required else ("anon-ok" if e.auth_required is False else "?")
            probed = ",".join(e.probed_for) or "(none)"
            ep_lines.append(
                f"  - {e.path} [{methods}] last_status={status} "
                f"auth={auth} params={params} probed_for={probed}"
            )
        parts.append("\n".join(ep_lines))

    # Auth states
    if ctx.auth_states:
        au_lines = ["AUTH STATES CAPTURED:"]
        for state in ctx.auth_states.values():
            cookies = list(state.cookies.keys())
            bearer = "yes" if state.bearer else "no"
            csrf = "yes" if state.csrf_token else "no"
            au_lines.append(
                f"  - {state.label}: cookies={cookies} bearer={bearer} csrf={csrf}"
            )
            if state.bearer and state.bearer.startswith("eyJ"):
                au_lines.append(
                    f"    → JWT token captured. Run jwt_audit on it."
                )
        parts.append("\n".join(au_lines))

    # Partial signals — these are the "things to chase next"
    if ctx.partial_signals:
        ps_recent = ctx.partial_signals[-max_signals:]
        ps_lines = [f"PARTIAL SIGNALS ({len(ctx.partial_signals)} observed, showing last {len(ps_recent)}):"]
        ps_lines.append("  ↳ These are observations worth follow-up — chase before declaring scan complete.")
        for s in ps_recent:
            cat = f" [{s.category_hint}]" if s.category_hint else ""
            ps_lines.append(f"  - {s.surface}{cat}: {s.signal}")
            if s.next_probe:
                ps_lines.append(f"    → next: {s.next_probe}")
        parts.append("\n".join(ps_lines))

    # Specialist recommendations — concrete next-call hints for
    # unprobed endpoints. Drives the lead toward auto-emit specialists
    # rather than manual send_request loops.
    recs = _specialist_recommendations(eps if 'eps' in dir() else [])
    if recs:
        rec_lines = ["SPECIALIST RECOMMENDATIONS — invoke these for fast deterministic findings:"]
        for r in recs[:6]:
            rec_lines.append(f"  → {r}")
        parts.append("\n".join(rec_lines))

    if not parts[1:]:
        # Only target URL — return a minimal stub so the section
        # isn't empty (helps the model see "ledger exists, populate it")
        return parts[0] + "\n(SecurityContext is empty — populate it as you probe.)"

    return "\n\n".join(parts)


def _specialist_recommendations(endpoints: list[Any]) -> list[str]:
    """Generate concrete specialist-invocation suggestions based on
    discovered endpoints. The lead sees these in its prompt every
    turn — much more actionable than a generic 'use specialists'
    directive.

    Heuristics:
      * `/login` or `/signin` (POST) without sqli-probed → scan_sqli
      * `/search` or `/query` with `q=` param → scan_xss + scan_sqli
      * `/redirect`, `/return`, `/next` with `to=`/`url=` → open_redirect_check
      * `/api/*/{N}` (numeric path segment) → scan_sqli with path-param
      * `/whoami`, `/me`, `/profile` returning JSON → jwt_audit hint
      * Any endpoint with a Server header showing version → cve_lookup hint
    """
    recs: list[str] = []
    seen: set[str] = set()

    for ep in endpoints:
        if not hasattr(ep, "path"):
            continue
        path = ep.path.lower()
        params = list(ep.params_seen) if hasattr(ep, "params_seen") else []
        probed = set(getattr(ep, "probed_for", []) or [])

        # Login endpoints — auth-flow + SQLi via POST body
        if any(p in path for p in ("/login", "/signin", "/auth")) and "POST" in (ep.methods_seen or []):
            if "auth" not in probed:
                key = f"scan_auth_flow:{ep.path}"
                if key not in seen:
                    seen.add(key)
                    recs.append(
                        f"scan_auth_flow on {ep.path} (login_url='{ep.path}', "
                        f"try_register=True) — tries default creds, captures session, "
                        f"auto-emits CWE-521 + writes JWT/cookies to AuthState"
                    )
            if "sqli" not in probed:
                key = f"scan_sqli:{ep.path}"
                if key not in seen:
                    seen.add(key)
                    recs.append(
                        f"scan_sqli on {ep.path} (POST/JSON: method='POST', "
                        f"body_template={{'email':'x','password':'x'}}, "
                        f"params=['email']) — auto-emits if vulnerable"
                    )
        # Search/query endpoints with q= param — XSS + SQLi
        if (any(p in path for p in ("/search", "/query", "/find")) or "q" in params or "query" in params):
            if "xss" not in probed:
                key = f"scan_xss:{ep.path}"
                if key not in seen:
                    seen.add(key)
                    qparam = "q" if "q" in params else ("query" if "query" in params else "q")
                    recs.append(f"scan_xss on {ep.path} (params=['{qparam}']) — auto-emits reflected XSS")
            if "sqli" not in probed:
                key = f"scan_sqli:{ep.path}"
                if key not in seen:
                    seen.add(key)
                    qparam = "q" if "q" in params else ("query" if "query" in params else "q")
                    recs.append(f"scan_sqli on {ep.path} (params=['{qparam}']) — auto-emits SQLi")
        # Redirect endpoints
        if any(p in path for p in ("/redirect", "/return", "/goto", "/forward")) or any(
                p in params for p in ("to", "url", "next", "redirect", "return", "dest")):
            if "open_redirect" not in probed:
                key = f"open_redirect:{ep.path}"
                if key not in seen:
                    seen.add(key)
                    recs.append(f"open_redirect_check on {ep.path} — auto-emits if redirect-shaped param accepts external URLs")
        # Path-param numeric IDs — IDOR/SQLi candidate
        import re as _re
        if _re.search(r"/\d+(/|$|\?)", path):
            if "sqli" not in probed:
                key = f"scan_sqli_path:{ep.path}"
                if key not in seen:
                    seen.add(key)
                    # Convert /api/Baskets/123 → /api/Baskets/{id}
                    template = _re.sub(r"/\d+(/|$|\?)", r"/{id}\1", path)
                    recs.append(
                        f"scan_sqli on {template} (path-param: method='GET', params=['id']) — auto-emits SQLi via path"
                    )
        # JWT-relevant endpoints
        if any(p in path for p in ("/whoami", "/me", "/profile", "/user")) and "GET" in (ep.methods_seen or []):
            key = f"jwt:{ep.path}"
            if key not in seen:
                seen.add(key)
                recs.append(f"jwt_audit on any token captured from {ep.path} — alg=none / weak HMAC / kid manipulation")

        # XXE-prone endpoints — XML/SOAP-shaped paths
        if any(p in path for p in ("/b2b", "/soap", "/xml", "/v2/orders",
                                    "/wsdl", "/services/")):
            if "xxe" not in probed:
                key = f"scan_xxe:{ep.path}"
                if key not in seen:
                    seen.add(key)
                    recs.append(
                        f"scan_xxe on {ep.path} — POSTs DOCTYPE-entity payloads, "
                        f"auto-emits on file disclosure / cloud-metadata SSRF"
                    )

    return recs


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _run_dir() -> str | None:
    """Return the run dir if STRIX_RUN_DIR is set, else None."""
    return os.environ.get("STRIX_RUN_DIR") or None


def _persist() -> None:
    """Best-effort persist to `<run_dir>/security_context.json`.
    Single-file overwrite (not append-log) — the latest snapshot is
    canonical. Failure is silent so the agent loop never breaks."""
    rd = _run_dir()
    if not rd:
        return
    try:
        ctx = get_security_context()
        path = os.path.join(rd, "security_context.json")
        os.makedirs(rd, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(ctx.to_dict(), f, indent=2, default=str)
    except Exception:  # noqa: BLE001
        logger.debug("security_context persist failed", exc_info=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical_path(path_or_url: str) -> str:
    """Canonicalize an endpoint key. Strip scheme+host so two probes
    with different host headers but the same path collapse."""
    from urllib.parse import urlparse
    p = path_or_url.strip()
    if "://" in p:
        parsed = urlparse(p)
        path = parsed.path or "/"
        if parsed.query:
            return path + "?" + parsed.query
        return path
    return p
