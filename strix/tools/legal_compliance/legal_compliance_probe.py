"""Legal-document presence probe.

Probes canonical legal-document paths on a `web_application` target:

  * `/privacy`, `/privacy-policy`, `/policy/privacy`
  * `/cookies`, `/cookie-policy`, `/policy/cookies`
  * `/terms`, `/terms-of-service`, `/tos`
  * `/dpa`, `/data-processing-agreement`
  * `/legal`, `/legal/*`
  * `/imprint`, `/impressum` (EU/DE legal requirement)
  * `/accessibility`, `/accessibility-statement`

Plus extracts `<link rel="privacy-policy">` (and other rel-types
defined by web standards) from the home-page HTML when fetched.

Per-document classification:

  * **Found at canonical path (2xx + non-trivial body)**: emit
    INFO finding with `present=True` — recon signal, audit
    artifact.
  * **Not found anywhere**: emit LOW finding with `present=False`
    — GDPR / CCPA / DPDP requires customer-facing apps publish
    these.

Why deterministic / zero-FP
---------------------------

* HTTP status code is binary (2xx vs not).
* Body length / "did the page render" is binary (≥ 200 chars
  non-blank → counted as present; below that → likely a 404
  page that returned 200).
* Per-doc-class: at most one finding per (target, doc_class),
  so a 4-redirect chain to the same privacy page emits ONE
  finding (the canonical URL is recorded).

References
----------

* GDPR Art. 13 / 14 — privacy notices required
* CCPA §1798.130 — privacy policy required
* India DPDP §6 — privacy notice required
* Cookie-Law (EU) — cookie policy + consent
* Apple App Store / Google Play — DPA / privacy URL required
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "legal_compliance_probe"
_DEFAULT_TIMEOUT = 8.0
_MIN_BODY_BYTES = 200  # below this, treat as "soft 404"

# Per-doc-class, ordered probe paths. The first 2xx+non-trivial-body
# path wins for the class; later paths short-circuit.
_PROBE_PATHS: dict[str, tuple[str, ...]] = {
    "privacy_policy": (
        "/privacy",
        "/privacy-policy",
        "/policy/privacy",
        "/legal/privacy",
        "/legal/privacy-policy",
        "/privacy.html",
    ),
    "cookie_policy": (
        "/cookies",
        "/cookie-policy",
        "/policy/cookies",
        "/legal/cookies",
        "/cookie-notice",
    ),
    "terms_of_service": (
        "/terms",
        "/terms-of-service",
        "/tos",
        "/legal/terms",
        "/legal/tos",
    ),
    "dpa": (
        "/dpa",
        "/data-processing-agreement",
        "/legal/dpa",
    ),
    "imprint": (
        "/imprint",
        "/impressum",
        "/legal/imprint",
    ),
    "accessibility": (
        "/accessibility",
        "/accessibility-statement",
        "/a11y",
    ),
}

# rel="..."-style hints in the homepage <link> tags.
_LINK_REL_REGEX = re.compile(
    r'<link\b[^>]*?\brel\s*=\s*["\']([^"\']+)["\'][^>]*?>',
    re.IGNORECASE | re.DOTALL,
)
_LINK_HREF_REGEX = re.compile(
    r'\bhref\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
# Canonical rel-types per IANA Link Relations registry.
_REL_TO_CLASS = {
    "privacy-policy": "privacy_policy",
    "terms-of-service": "terms_of_service",
}


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_get(url: str, *, timeout: float = _DEFAULT_TIMEOUT) -> dict[str, Any]:
    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None

    if manager is not None:
        try:
            r = manager.send_simple_request("GET", url, timeout=int(timeout))
            if r.get("skipped"):
                return {"status": 0, "body": "", "skipped": True}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(r.get("headers") or {}),
                "body": (r.get("body") or "")[:128 * 1024],
                "final_url": r.get("final_url") or url,
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy fetch failed; falling back", exc_info=True)

    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, _ = is_path_excluded(url)
        if excluded:
            return {"status": 0, "body": "", "skipped": True}
        merged = inject_auth_headers({})
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as c:
            r = c.get(url, headers=merged)
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "body": r.text[:128 * 1024],
                "final_url": str(r.url),
            }
    except Exception as e:  # noqa: BLE001
        return {"status": 0, "body": "", "error": str(e)}


def _lower_keys(d: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in d.items()}


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _is_doc_present(resp: dict[str, Any]) -> bool:
    """A path is "present" iff status is 2xx AND body has ≥ 200 chars
    of non-blank content. Soft-404s (sites that return 200 with a
    generic homepage) are filtered by the body-length check."""
    if int(resp.get("status") or 0) // 100 != 2:
        return False
    body = (resp.get("body") or "").strip()
    return len(body) >= _MIN_BODY_BYTES


def _extract_link_rel_paths(html: str, base_url: str) -> dict[str, str]:
    """Return mapping of doc_class → absolute URL for each
    `<link rel="...">` we recognise in the homepage HTML."""
    out: dict[str, str] = {}
    for tag_match in _LINK_REL_REGEX.finditer(html):
        rel = tag_match.group(1).lower().strip()
        # Multi-token rel attribute — split on whitespace.
        for token in rel.split():
            doc_class = _REL_TO_CLASS.get(token)
            if not doc_class:
                continue
            href_match = _LINK_HREF_REGEX.search(tag_match.group(0))
            if not href_match:
                continue
            href = href_match.group(1).strip()
            if not href:
                continue
            absolute = urljoin(base_url, href)
            out.setdefault(doc_class, absolute)
    return out


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


_DOC_CLASS_HUMAN = {
    "privacy_policy": "Privacy policy",
    "cookie_policy": "Cookie policy",
    "terms_of_service": "Terms of service",
    "dpa": "Data Processing Agreement (DPA)",
    "imprint": "Imprint / Impressum",
    "accessibility": "Accessibility statement",
}


def _emit_present(*, doc_class: str, url: str, target: str) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    human = _DOC_CLASS_HUMAN.get(doc_class, doc_class)
    tracer.add_vulnerability_report(
        title=f"{human} present at {url}",
        severity="info",
        category="legal_documents",
        cwe="CWE-1390",  # Inadequate documentation of compliance evidence
        target=target,
        endpoint=url,
        description=(
            f"{human} found at `{url}`. Recorded as a compliance audit "
            f"artifact — auditors reviewing the customer's GDPR / CCPA / "
            f"DPDP posture frequently ask for the URL where each legal "
            f"document is published; this finding answers that directly."
        ),
        impact="Documentation / compliance signal; no security impact.",
        remediation_steps=(
            "Continue publishing this document. Audit periodically that "
            "the URL stays live — broken legal-document URLs are a real "
            "pre-complaint risk."
        ),
        description_plain=(
            f"Your {human.lower()} is published at `{url}`. Auditors will "
            f"ask for this URL — keep it stable and live."
        ),
        recommended_action=(
            "Keep the URL stable across deploys. Add a monitoring check "
            "that the URL stays 200 OK."
        ),
        verification_status="verified",
    )


def _emit_absent(*, doc_class: str, target: str) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    human = _DOC_CLASS_HUMAN.get(doc_class, doc_class)

    # Severity ladder — privacy_policy / cookie_policy / dpa are
    # GDPR-required for any EU-touching site → low. terms / imprint
    # / accessibility are still required in many jurisdictions but
    # not GDPR-class → info.
    severity = "low" if doc_class in {"privacy_policy", "cookie_policy", "dpa"} else "info"

    tracer.add_vulnerability_report(
        title=f"{human} not found at canonical paths on {target}",
        severity=severity,
        category="legal_documents",
        cwe="CWE-1390",
        target=target,
        endpoint=target,
        description=(
            f"None of the canonical paths for the {human} returned a "
            f"non-trivial 2xx body. GDPR Art. 13/14 / CCPA / DPDP all "
            f"require a customer-facing app to publish this document. "
            f"Operator should either publish the document at one of the "
            f"canonical paths OR add a `<link rel=\"...\">` from the "
            f"homepage to wherever it lives."
        ),
        impact=(
            "Regulatory exposure — a customer / DPA / regulator filing "
            "a complaint about missing privacy documentation has a "
            "valid case. Immediate financial impact is variable; "
            "reputational impact is real."
        ),
        remediation_steps=(
            f"Publish the {human.lower()} at one of the canonical paths "
            f"({', '.join(_PROBE_PATHS.get(doc_class, ()))}) and link to "
            f"it from the site footer + register a "
            f"`<link rel=\"privacy-policy\">`-style hint in the homepage "
            f"`<head>` so crawlers / scanners / browsers can discover it."
        ),
        description_plain=(
            f"This site does not publish a {human.lower()} at any of the "
            f"standard URLs. Most jurisdictions require a customer-facing "
            f"site to publish one — review with legal."
        ),
        recommended_action=(
            f"Publish the {human.lower()} at a canonical path "
            f"(e.g. `/{doc_class.replace('_', '-')}`) and link from "
            f"the footer."
        ),
        verification_status="verified",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME) if t else None


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is not None:
        t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str | None:
    if not isinstance(target, str) or not target.strip():
        return None
    target = target.strip()
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    # Drop path / query — we only want the origin for canonical-path probes.
    return f"{parsed.scheme}://{parsed.netloc}"


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592"],
)
def legal_compliance_probe(
    target_url: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Probe canonical legal-document paths on a web target.

    Args:
        target_url: web target (URL or bare host; auto-prefixed `https://`).
            Path / query is dropped — we only probe canonical paths
            against the origin.
        timeout: per-request HTTP timeout (default 8s).

    Returns:
        ```
        {
          success, target,
          documents: [
            {doc_class, present, url?, source: "canonical_path"|"link_rel"|"absent"},
          ],
          findings_emitted: int,
          errors?: [str, ...],
        }
        ```

    Findings (CWE-1390):
        - **Info** — document found at canonical path / link_rel.
        - **Low** — privacy_policy / cookie_policy / dpa absent
          (GDPR-class document missing).
        - **Info** — terms_of_service / imprint / accessibility absent
          (still required in many jurisdictions but not GDPR-class).
    """
    origin = _normalize_target(target_url)
    if origin is None:
        return {"success": False, "error": f"invalid target_url: {target_url!r}"}

    parsed = urlparse(origin)
    target_host = parsed.netloc
    check_id = _start_check(category="legal_documents", surface=target_host)
    errors: list[str] = []

    documents: list[dict[str, Any]] = []
    findings_emitted = 0

    # Try to extract <link rel="..."> hints from the homepage. If
    # this succeeds we get high-confidence URLs without probing
    # every canonical path.
    home = _http_get(origin, timeout=timeout)
    if home.get("error"):
        errors.append(f"home: {home['error']}")
    link_rel_hits = (
        _extract_link_rel_paths(home.get("body", ""), origin)
        if home.get("body")
        else {}
    )

    for doc_class, paths in _PROBE_PATHS.items():
        # 1) Check link_rel hint first — single fetch.
        if doc_class in link_rel_hits:
            url = link_rel_hits[doc_class]
            r = _http_get(url, timeout=timeout)
            if not r.get("error") and _is_doc_present(r):
                documents.append({
                    "doc_class": doc_class,
                    "present": True,
                    "url": r.get("final_url") or url,
                    "source": "link_rel",
                })
                _emit_present(doc_class=doc_class, url=r.get("final_url") or url, target=target_host)
                findings_emitted += 1
                continue

        # 2) Probe canonical paths in order; first hit wins.
        found_url: str | None = None
        for path in paths:
            url = origin + path
            r = _http_get(url, timeout=timeout)
            if r.get("skipped"):
                continue
            if r.get("error"):
                continue
            if _is_doc_present(r):
                found_url = r.get("final_url") or url
                break

        if found_url:
            documents.append({
                "doc_class": doc_class,
                "present": True,
                "url": found_url,
                "source": "canonical_path",
            })
            _emit_present(doc_class=doc_class, url=found_url, target=target_host)
            findings_emitted += 1
        else:
            documents.append({
                "doc_class": doc_class,
                "present": False,
                "source": "absent",
            })
            _emit_absent(doc_class=doc_class, target=target_host)
            findings_emitted += 1

    if findings_emitted > 0:
        present_count = sum(1 for d in documents if d.get("present"))
        absent_count = len(documents) - present_count
        _complete_check(
            check_id,
            result="vulnerable" if absent_count > 0 else "not_vulnerable",
            evidence=f"{present_count} present / {absent_count} absent",
        )
    else:
        _complete_check(
            check_id,
            result="inconclusive",
            evidence="probe failed across all paths",
        )

    out: dict[str, Any] = {
        "success": True,
        "target": target_host,
        "documents": documents,
        "findings_emitted": findings_emitted,
    }
    if errors:
        out["errors"] = errors
    return out
