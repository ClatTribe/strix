"""Have I Been Pwned domain breach lookup.

For a domain target, queries HIBP's public `/api/v3/breaches?domain=…`
endpoint and emits per-severity-tier findings summarising the
historical breaches that included email addresses at that domain.

Pairs naturally with `org_fingerprint` (#16): when the agent has
identified a domain as belonging to the target organisation, this
tool surfaces breach history affecting employees of that org.
Actionable for prioritising authentication findings — credential-
stuffing risk, phishing-readiness assessment, MFA-rollout urgency.

The HIBP `/api/v3/breaches?domain=<d>` endpoint is **public, free,
no API key required**. It returns breach metadata only (the list of
breaches that included emails from the domain), never individual
breached email addresses. The richer `/api/v3/breacheddomain/<d>`
endpoint that returns email→breach mapping requires a paid API key
*and* verified domain ownership — out of scope for this tool.

A `User-Agent` header is required by HIBP (returns 403 without one).

Methodology:

1. Validate the domain (apex-domain format, no IPs, no URLs).
2. GET `https://haveibeenpwned.com/api/v3/breaches?domain=<d>` with
   a descriptive User-Agent.
3. Filter the breach list:
   - Drop entries with `IsFabricated=True` (mislabelled / hoax data).
   - Drop entries with `IsSpamList=True` (not a security breach).
   - Drop entries with `IsRetired=True` (HIBP has removed them).
4. Per-breach severity:
   - +1 if `DataClasses` includes "Passwords" or "Password hashes".
   - +1 if `BreachDate` is within the last 12 months (recent enough
     to materially affect credential-stuffing / phishing risk).
   - +1 if `PwnCount` ≥ 1,000,000 (mass breach — likely targeted by
     attackers; published widely).
   - +1 if `IsSensitive=True` (HIBP's "sensitive" flag — adult
     content, medical, etc., where exposure adds real-world harm).
   - Total ≥ 3 → high; 2 → medium; 1 → low; 0 → still emitted as
     low (any genuine breach is finding-worthy, even old ones).
5. **Per-severity dedup** — at most one finding per severity tier
   per domain, listing the top 5 breaches in that tier ordered by
   recency × pwn_count.

Findings:

- **High** (CWE-200, breach_exposure) — breach_score ≥ 3 (recent +
  passwords + mass).
- **Medium** (CWE-200) — breach_score 2 (e.g. recent + passwords,
  or recent + mass without passwords).
- **Low** (CWE-200) — any other genuine breach.

Each finding includes `description_plain` + `recommended_action`:
- HIGH → "treat user accounts at this domain as credential-stuffing
  targets; force password rotation; enforce MFA; consider blocking
  passwords seen in HIBP's pwned-passwords API at sign-in".
- MEDIUM → "review which users at this domain may have been
  affected; advise password rotation for sensitive accounts;
  consider MFA rollout urgency".
- LOW → "informational — older breaches still relevant for
  long-tail credential-stuffing attempts".

`verification_status=verified` since HIBP is the authoritative
public source and breach metadata is unambiguous.

Cache: per-domain JSON cache under `~/.strix/hibp_cache/`. 24-hour
TTL. Stale cache served on network failure (fail-open with `error`
populated). Disable with `STRIX_HIBP_NO_CACHE=1`.

Composes with cluster-A safety: rate-limit applies to the HIBP
request; `--exclude-path` doesn't apply (URL is HIBP, not the
customer's domain).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "hibp_breach_check"
_DEFAULT_TIMEOUT = 15.0
_DEFAULT_CACHE_TTL_SECONDS = 24 * 3600
_HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breaches"
_USER_AGENT = "strix-hibp-breach-check/1.0"

# Recent-breach window (days). Breaches dated within this window get
# the recency boost.
_RECENT_BREACH_DAYS = 365

# Mass-breach threshold (number of accounts).
_MASS_BREACH_THRESHOLD = 1_000_000

# Password-shaped DataClasses values. HIBP uses several variants
# across breaches.
_PASSWORD_DATACLASSES = (
    "passwords", "password hashes",
)

# Top-N breaches to list per severity-tier finding.
_BREACHES_PER_FINDING = 5

_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z]{2,63})+$"
)


# ---------------------------------------------------------------------------
# HTTP helper (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(
    url: str, *, headers: dict[str, str] | None = None, timeout: float = _DEFAULT_TIMEOUT
) -> dict[str, Any]:
    """GET via cluster-A safety. Returns {status, headers, body, error?}."""
    headers = dict(headers or {})
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, headers=headers, timeout=int(timeout))
            if r.get("skipped"):
                return {"status": 0, "headers": {}, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": r.get("body") or "",
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)
    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            throttle_for_rate_limit,
        )

        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:512 * 1024],  # breach list can be large
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "headers": {}, "body": "", "error": str(e)}


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------


def _normalize_domain(domain: str) -> str | None:
    if not domain or not isinstance(domain, str):
        return None
    domain = domain.strip().rstrip(".").lower()
    if not domain:
        return None
    if "://" in domain:
        from urllib.parse import urlparse

        parsed = urlparse(domain)
        domain = (parsed.hostname or "").lower()
        if not domain:
            return None
    if len(domain) > 253:
        return None
    if not _DOMAIN_RE.match(domain):
        return None
    return domain


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def _cache_dir() -> Path:
    return Path.home() / ".strix" / "hibp_cache"


def _cache_path(domain: str) -> Path:
    safe = hashlib.sha256(domain.encode("utf-8")).hexdigest()[:16]
    return _cache_dir() / f"{safe}.json"


def _cache_read(domain: str, *, fresh_only: bool) -> dict[str, Any] | None:
    if os.environ.get("STRIX_HIBP_NO_CACHE") == "1":
        return None
    path = _cache_path(domain)
    if not path.exists():
        return None
    if fresh_only:
        age = time.time() - path.stat().st_mtime
        if age > _DEFAULT_CACHE_TTL_SECONDS:
            return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError) as e:
        logger.debug("hibp_breach cache read failed: %s", e)
        return None


def _cache_write(domain: str, payload: dict[str, Any]) -> None:
    if os.environ.get("STRIX_HIBP_NO_CACHE") == "1":
        return
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        with _cache_path(domain).open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except OSError as e:
        logger.debug("hibp_breach cache write failed: %s", e)


# ---------------------------------------------------------------------------
# Breach severity scoring
# ---------------------------------------------------------------------------


def _parse_breach_date(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        # HIBP BreachDate is ISO-8601 (YYYY-MM-DD).
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _has_passwords(data_classes: list[str] | None) -> bool:
    if not data_classes or not isinstance(data_classes, list):
        return False
    lowered = {str(d).lower() for d in data_classes}
    return any(p in lowered for p in _PASSWORD_DATACLASSES)


def _score_breach(breach: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Return (score, processed_record). score is 0-4."""
    name = breach.get("Name") or breach.get("name") or "unknown"
    title = breach.get("Title") or breach.get("title") or name
    breach_date_str = breach.get("BreachDate") or breach.get("breach_date")
    pwn_count = int(breach.get("PwnCount") or breach.get("pwn_count") or 0)
    data_classes = breach.get("DataClasses") or breach.get("data_classes") or []
    is_sensitive = bool(breach.get("IsSensitive") or breach.get("is_sensitive"))
    is_verified = bool(breach.get("IsVerified", True) or breach.get("is_verified", True))
    domain = breach.get("Domain") or breach.get("domain")

    has_pw = _has_passwords(data_classes)
    parsed_date = _parse_breach_date(breach_date_str)
    is_recent = False
    if parsed_date is not None:
        age_days = (datetime.now(timezone.utc) - parsed_date).days
        is_recent = age_days <= _RECENT_BREACH_DAYS
    is_mass = pwn_count >= _MASS_BREACH_THRESHOLD

    score = 0
    if has_pw:
        score += 1
    if is_recent:
        score += 1
    if is_mass:
        score += 1
    if is_sensitive:
        score += 1

    record = {
        "name": name,
        "title": title,
        "domain": domain,
        "breach_date": breach_date_str,
        "pwn_count": pwn_count,
        "data_classes": list(data_classes),
        "has_passwords": has_pw,
        "is_recent": is_recent,
        "is_mass": is_mass,
        "is_sensitive": is_sensitive,
        "is_verified": is_verified,
        "score": score,
    }
    return score, record


def _score_to_severity(score: int) -> str:
    if score >= 3:
        return "high"
    if score == 2:
        return "medium"
    return "low"


def _process_breaches(
    raw_breaches: list[Any],
) -> list[dict[str, Any]]:
    """Filter + score + sort."""
    processed: list[dict[str, Any]] = []
    for entry in raw_breaches:
        if not isinstance(entry, dict):
            continue
        if entry.get("IsFabricated") or entry.get("is_fabricated"):
            continue
        if entry.get("IsSpamList") or entry.get("is_spam_list"):
            continue
        if entry.get("IsRetired") or entry.get("is_retired"):
            continue
        score, record = _score_breach(entry)
        record["severity"] = _score_to_severity(score)
        processed.append(record)
    # Sort by (severity-rank desc, recency, pwn_count). Severity rank
    # high=3 medium=2 low=1.
    sev_rank = {"high": 3, "medium": 2, "low": 1}

    def _key(r: dict[str, Any]) -> tuple[int, str, int]:
        return (
            sev_rank.get(r["severity"], 0),
            r.get("breach_date") or "",
            r.get("pwn_count") or 0,
        )

    processed.sort(key=_key, reverse=True)
    return processed


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    target: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    finding_id = tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="breach_exposure",
        cwe="CWE-200",
        target=target,
        endpoint=target,
        description=description,
        impact=(
            "Breach exposure data tells attackers which credentials "
            "to try first. Real-world attack chains: (1) credential-"
            "stuffing — replay leaked username:password pairs against "
            "the target's login; (2) targeted phishing — emails to "
            "users known to have used a breached service; (3) "
            "password-spray — try the most common breach passwords "
            "(`123456`, `qwerty`, etc.) against the full email list. "
            "Recent breaches with passwords + mass exposure (>= 1M "
            "accounts) are the highest-priority signal."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="verified",
    )
    # P4 — ThreatIntel projection. HIBP observes that a domain
    # or email appears in a breach corpus.
    try:
        from strix.agents.kg_emit import record_threat_intel_in_kg
        asset_type = "email" if "@" in target else "domain"
        record_threat_intel_in_kg(
            source="hibp_breach",
            asset_type=asset_type,
            asset_value=target,
            verdict="breached",
            detail=title[:120],
            finding_id=finding_id,
        )
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).debug(
            "hibp_breach: kg threat-intel record failed: %s", e, exc_info=True,
        )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1589.001"],  # Gather Victim Identity Info: Credentials
)
def hibp_breach_check(
    domain: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Look up historical breaches affecting users at a domain.

    Args:
        domain: Apex domain to query (e.g. `example.com`,
            `contoso.com`). URL-shaped input auto-stripped to
            hostname. IPs / invalid hostnames rejected.
        timeout: Per-request timeout in seconds (default 15).

    Returns:
        {
          success, domain, queried_at, from_cache,
          breach_count: int,
          breaches: [
            {name, title, domain, breach_date, pwn_count,
             data_classes, has_passwords, is_recent, is_mass,
             is_sensitive, is_verified, score, severity},
            ...
          ],
          findings_emitted: int,
          error?,
        }

    Findings:
        Per-severity-tier dedup: at most one finding per (domain,
        severity-tier). Each finding lists the top 5 breaches in that
        tier ordered by recency × pwn_count.

        - **High** (CWE-200, breach_exposure) — breach_score ≥ 3
          (recent + passwords + mass + sensitive sum to 3 or more).
        - **Medium** — breach_score 2.
        - **Low** — any other genuine breach (filtered through
          IsFabricated / IsSpamList / IsRetired).

    Notes:
        - Public HIBP endpoint, no API key required.
        - `User-Agent` header is required by HIBP (returns 403
          without).
        - 24-hour cache under `~/.strix/hibp_cache/`. Stale cache
          served on network failure (fail-open with `error`
          populated). Disable with `STRIX_HIBP_NO_CACHE=1`.
        - Composes with cluster-A safety: rate-limit applies.
    """
    domain_norm = _normalize_domain(domain)
    if domain_norm is None:
        return {
            "success": False,
            "error": f"invalid domain (not an apex hostname): {domain!r}",
        }

    cev = _start_check("hibp_breach", domain_norm)

    # Cache fast path.
    cached = _cache_read(domain_norm, fresh_only=True)
    if cached is not None:
        cached["from_cache"] = True
        _complete_check(
            cev,
            result="vulnerable" if cached.get("findings_emitted") else "not_vulnerable",
            evidence=f"{cached.get('breach_count', 0)} HIBP breach(es) for {domain_norm} (cached)",
        )
        return cached

    # Live query.
    url = f"{_HIBP_API_URL}?domain={domain_norm}"
    headers = {
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
    }
    response = _http_get(url, headers=headers, timeout=timeout)

    if response.get("skipped"):
        # Stable artefact even on filter — caller knows nothing ran.
        result = {
            "success": True,
            "domain": domain_norm,
            "queried_at": int(time.time()),
            "from_cache": False,
            "breach_count": 0,
            "breaches": [],
            "findings_emitted": 0,
            "error": "HIBP query filtered by --exclude-path (unexpected)",
        }
        _complete_check(cev, "inconclusive", "filtered by --exclude-path")
        return result

    if response.get("error"):
        # Try stale cache.
        stale = _cache_read(domain_norm, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            stale["error"] = (
                f"HIBP query failed ({response['error']}); served stale cache"
            )
            _complete_check(
                cev,
                result="vulnerable" if stale.get("findings_emitted") else "not_vulnerable",
                evidence=(
                    f"{stale.get('breach_count', 0)} breach(es) for "
                    f"{domain_norm} (stale cache; {response['error']})"
                ),
            )
            return stale
        _complete_check(cev, "inconclusive", f"HIBP query failed: {response['error']}")
        return {
            "success": False,
            "domain": domain_norm,
            "error": response["error"],
            "breaches": [],
            "findings_emitted": 0,
            "from_cache": False,
        }

    status = response.get("status", 0)
    body = response.get("body") or ""

    # HIBP returns 200 + array (possibly empty). Other codes are
    # treated as errors.
    if status == 200:
        try:
            payload = json.loads(body) if body.strip() else []
        except (ValueError, TypeError) as e:
            _complete_check(cev, "inconclusive", f"HIBP invalid JSON: {e}")
            return {
                "success": False,
                "domain": domain_norm,
                "error": f"HIBP invalid JSON: {e}",
                "breaches": [],
                "findings_emitted": 0,
                "from_cache": False,
            }
        if not isinstance(payload, list):
            payload = []
    elif status == 404:
        # HIBP returns 404 for some "no breach" responses on the
        # individual-breach endpoint, but the breaches?domain= one
        # returns 200+[] when none. Treat 404 as no breaches anyway.
        payload = []
    elif status == 403:
        # Likely missing User-Agent or rate-limited. Try stale.
        stale = _cache_read(domain_norm, fresh_only=False)
        if stale is not None:
            stale["from_cache"] = True
            stale["error"] = "HIBP returned 403; served stale cache"
            _complete_check(
                cev,
                result="vulnerable" if stale.get("findings_emitted") else "not_vulnerable",
                evidence=f"HIBP 403 for {domain_norm}; stale cache",
            )
            return stale
        _complete_check(cev, "inconclusive", "HIBP returned 403")
        return {
            "success": False,
            "domain": domain_norm,
            "error": "HIBP returned 403 (forbidden / rate-limited)",
            "breaches": [],
            "findings_emitted": 0,
            "from_cache": False,
        }
    else:
        _complete_check(cev, "inconclusive", f"HIBP returned status {status}")
        return {
            "success": False,
            "domain": domain_norm,
            "error": f"HIBP returned unexpected status {status}",
            "breaches": [],
            "findings_emitted": 0,
            "from_cache": False,
        }

    processed = _process_breaches(payload)
    breach_count = len(processed)

    # Per-severity dedup: emit at most one finding per (severity).
    findings_emitted = 0
    by_severity: dict[str, list[dict[str, Any]]] = {"high": [], "medium": [], "low": []}
    for r in processed:
        by_severity[r["severity"]].append(r)

    severity_order = ("high", "medium", "low")
    severity_recos = {
        "high": (
            "Treat user accounts at this domain as credential-stuffing "
            "targets. Force a password rotation for all users. Enforce "
            "MFA on every authentication path. Block passwords that "
            "appear in HIBP's pwned-passwords API at sign-in (the API "
            "is free; integrate via the k-anonymity hash-prefix "
            "endpoint). Monitor login failures for stuffing patterns."
        ),
        "medium": (
            "Review which users at this domain may have been affected "
            "(via the breach's HIBP page). Advise password rotation "
            "for sensitive accounts (admins, finance, executives). "
            "Accelerate MFA rollout if not already enforced."
        ),
        "low": (
            "Informational — older breaches still feed long-tail "
            "credential-stuffing attempts. Maintain MFA on critical "
            "accounts; block known-compromised passwords at sign-in "
            "via HIBP's pwned-passwords API."
        ),
    }
    severity_plain = {
        "high": (
            "Users at this domain were exposed in recent, large-scale "
            "breaches that included passwords. Attackers can use the "
            "leaked credentials to log in to your application directly "
            "(credential stuffing) or to phish your users with "
            "convincing pretexts."
        ),
        "medium": (
            "Users at this domain were exposed in recent breaches. "
            "Whether passwords leaked or just email addresses, this "
            "raises the credential-stuffing and phishing risk for "
            "your users."
        ),
        "low": (
            "Users at this domain appear in older or lower-impact "
            "breaches. The risk is reduced compared to recent "
            "password leaks but still relevant for long-tail "
            "credential-stuffing attempts."
        ),
    }

    for sev in severity_order:
        bucket = by_severity[sev]
        if not bucket:
            continue
        top = bucket[:_BREACHES_PER_FINDING]
        breach_lines = [
            f"{r['title']} ({r.get('breach_date') or 'unknown'}, "
            f"{r.get('pwn_count') or 0:,} accounts; "
            f"data: {', '.join(r['data_classes'][:5]) or 'unknown'})"
            for r in top
        ]
        title = (
            f"HIBP breach exposure on {domain_norm} — "
            f"{len(bucket)} {sev}-severity breach(es)"
        )
        description = (
            f"HIBP reports {breach_count} breach record(s) for `{domain_norm}` "
            f"after filtering fabricated / spam / retired entries. "
            f"This finding aggregates the {len(bucket)} {sev}-severity "
            f"breach(es). Top {len(top)} listed:\n- " + "\n- ".join(breach_lines)
        )
        _emit_finding(
            title=title,
            severity=sev,
            target=domain_norm,
            description=description,
            description_plain=severity_plain[sev],
            recommended_action=severity_recos[sev],
        )
        findings_emitted += 1

    result = {
        "success": True,
        "domain": domain_norm,
        "queried_at": int(time.time()),
        "from_cache": False,
        "breach_count": breach_count,
        "breaches": processed,
        "findings_emitted": findings_emitted,
    }
    _cache_write(domain_norm, result)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{breach_count} HIBP breach(es) for {domain_norm}",
    )
    return result
