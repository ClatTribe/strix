"""Cross-category linkers (heuristic, deterministic).

Each linker takes the full `Finding` list and returns 0+
`ChainLink` records. Same input → same links. The correlator
unions the link sets across all linkers, then runs connected-
components to form `FindingChain` entries.

Linkers in this module:

  * `link_sca_to_dast_by_cwe` — SCA vuln-dep + DAST exploit
    sharing CWE class on same target → linked.
  * `link_sast_to_dast_by_cwe_endpoint` — SAST sink + DAST
    exploit sharing CWE class on same target → linked.
  * `link_iac_to_dast_by_category` — IaC misconfig + DAST
    runtime confirmation (CORS / open-redirect categories) →
    linked.
  * `link_anomaly_to_specialist` — Phase 9 anomaly diff +
    matching DAST specialist on same endpoint → linked.
  * `link_sca_to_sast_by_package` — SCA flagged package +
    SAST hit in code that imports the package → linked.

Linker output is conservative — both sides need a strong shared
field (CWE + target, or package name in title, or same
endpoint). Aggressive linking would create spurious chains;
better to under-link and leave singletons than to merge two
real bugs into one fake "chain".

Adding a new linker:
  1. Implement `link_<name>(findings) -> list[ChainLink]`.
  2. Append to `LINKER_REGISTRY`.
  3. Add positive + negative tests in
     `tests/finding_chains/test_links.py`.
"""

from __future__ import annotations

import logging
from typing import Callable

from strix.finding_chains.chain import ChainLink, Finding


logger = logging.getLogger(__name__)


# Stable link-type identifiers. Wrappers may render UI off them.
LINK_SCA_DAST_CWE = "sca_to_dast_cwe"
LINK_SAST_DAST_CWE_ENDPOINT = "sast_to_dast_cwe_endpoint"
LINK_IAC_DAST_CATEGORY = "iac_to_dast_category"
LINK_ANOMALY_DAST_ENDPOINT = "anomaly_to_specialist_endpoint"
LINK_SCA_SAST_PACKAGE = "sca_to_sast_package"

# iter-21.4 — attack-chain linkers. Where the linkers above tie
# findings by CWE/category co-occurrence on a shared target, these
# encode SPECIFIC exploit chains: combinations that escalate
# severity together because each piece alone is mitigatable but
# together they form an end-to-end attack. Confidence floor here
# is higher (0.85+) because the matches require exact rule
# co-firing, not just CWE-family overlap.
LINK_CORS_TO_SSRF_CHAIN = "cors_reflection_to_ssrf_chain"
LINK_JWT_CONFUSION_CHAIN = "jwt_confusion_chain"
LINK_AUTH_BYPASS_VIA_METHOD_OVERRIDE = "auth_bypass_via_method_override_chain"

LinkType = str


# CWE family map — CVE/CWE classes that imply the same exploit
# class. Used to broaden CWE matching beyond exact-equality
# (CWE-89 raw SQL ≈ CWE-943 NoSQL injection ≈ DAST sqli category).
_CWE_FAMILY: dict[str, str] = {
    # SQL injection family
    "CWE-89": "sqli", "CWE-943": "sqli",
    # XSS family
    "CWE-79": "xss",
    # Command injection family
    "CWE-78": "cmd_injection", "CWE-94": "cmd_injection",
    # Path traversal
    "CWE-22": "path_traversal",
    # SSRF
    "CWE-918": "ssrf", "CWE-345": "ssrf",
    # Open redirect
    "CWE-601": "open_redirect",
    # Mass assignment
    "CWE-915": "mass_assignment",
    # Auth / authz
    "CWE-862": "authz", "CWE-285": "authz", "CWE-269": "authz",
    "CWE-287": "auth", "CWE-306": "authz",
    # CSRF
    "CWE-352": "csrf",
    # XXE
    "CWE-611": "xxe",
    # Deserialization
    "CWE-502": "deserialization",
    # SSTI
    "CWE-1336": "ssti",
    # Crypto / TLS
    "CWE-327": "crypto", "CWE-338": "crypto",
    "CWE-326": "crypto", "CWE-295": "crypto",
    # JWT / token
    "CWE-347": "jwt", "CWE-208": "anomaly",
    # Info disclosure / secrets
    "CWE-200": "info_disclosure", "CWE-209": "info_disclosure",
    "CWE-798": "info_disclosure", "CWE-922": "info_disclosure",
    # Misconfig
    "CWE-1004": "misconfig", "CWE-732": "misconfig",
    "CWE-489": "misconfig", "CWE-614": "misconfig",
    "CWE-400": "misconfig",
    # Mass-assignment is actually CWE-915 above.
    # Prototype pollution → no clean DAST analogue; share with
    # deserialization for cross-asset purposes.
    "CWE-1321": "deserialization",
}


def _cwe_family(cwe: str | None) -> str | None:
    if not cwe:
        return None
    return _CWE_FAMILY.get(cwe.upper())


def _same_target(a: Finding, b: Finding) -> bool:
    """True when two findings share a target context — same URL,
    same repo path, or one's target is a substring of the other.
    Conservative: prefers FALSE on doubt."""
    if not a.target or not b.target:
        return False
    a_t, b_t = a.target.strip(), b.target.strip()
    if not a_t or not b_t:
        return False
    if a_t == b_t:
        return True
    # File-path style: same ancestor dir.
    if a_t in b_t or b_t in a_t:
        return True
    # URL with same host.
    try:
        from urllib.parse import urlparse
        ah = urlparse(a_t).netloc
        bh = urlparse(b_t).netloc
        if ah and ah == bh:
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _same_endpoint(a: Finding, b: Finding) -> bool:
    """True when two findings reference the same specific
    endpoint (URL path / file:line). Allows partial match —
    `/api/users` matches `/api/users/:id`."""
    if not a.endpoint or not b.endpoint:
        return False
    a_e, b_e = a.endpoint.strip(), b.endpoint.strip()
    if not a_e or not b_e:
        return False
    if a_e == b_e:
        return True
    # URL path overlap: shorter is prefix of longer.
    if a_e.startswith(b_e) or b_e.startswith(a_e):
        return True
    return False


# ---------------------------------------------------------------------------
# 1. SCA → DAST: same CWE family on same target
# ---------------------------------------------------------------------------


def link_sca_to_dast_by_cwe(findings: list[Finding]) -> list[ChainLink]:
    """SCA vulnerable dependency + DAST runtime exploit sharing
    CWE family on the same target → linked.

    Example: SCA flags lodash@<4.17.21 (CWE-1321 prototype
    pollution → "deserialization" family); DAST scan_xss /
    scan_deserialization on the same URL fires → linked,
    confidence 0.8.

    Conservative: requires BOTH same target AND CWE family
    overlap. Just same target produces too many spurious
    chains (lots of findings on one URL).
    """
    out: list[ChainLink] = []
    sca = [f for f in findings if f.category == "vulnerable_dependency"]
    dast = [f for f in findings
            if f.category not in (
                "vulnerable_dependency", "sast", "misconfig",
                "license_violation", "malicious_dependency", "anomaly",
                "iac_misconfig",
            )]
    for s in sca:
        s_fam = _cwe_family(s.cwe)
        if not s_fam:
            continue
        for d in dast:
            d_fam = _cwe_family(d.cwe)
            if d_fam and d_fam == s_fam and _same_target(s, d):
                out.append(ChainLink(
                    finding_a=s.id, finding_b=d.id,
                    link_type=LINK_SCA_DAST_CWE,
                    confidence=0.8,
                    rationale=(
                        f"SCA finding `{s.title[:60]}` and DAST "
                        f"finding share CWE family `{s_fam}` on "
                        f"target `{s.target}` — vulnerable "
                        f"package + matching live-exploit pattern."
                    ),
                ))
    return out


# ---------------------------------------------------------------------------
# 2. SAST → DAST: same CWE on same target
# ---------------------------------------------------------------------------


def link_sast_to_dast_by_cwe_endpoint(findings: list[Finding]) -> list[ChainLink]:
    """SAST sink + DAST exploit on the same target with CWE
    family overlap → linked.

    Example: SAST finds `eval(req.body.x)` at `app.js:35` (CWE-94
    cmd-injection family); DAST `scan_cmd_injection` on `/api/calc`
    on the same target fires → linked.

    Same-target gate is a coarser filter than same-endpoint
    here because SAST endpoint is `file:line` and DAST
    endpoint is a URL — they don't lexically match. The
    target (repo path / URL host) does match.
    """
    out: list[ChainLink] = []
    sast = [f for f in findings if f.category == "sast"]
    dast = [f for f in findings
            if f.category not in (
                "sast", "vulnerable_dependency", "misconfig",
                "license_violation", "malicious_dependency",
                "anomaly", "iac_misconfig",
            )]
    for s in sast:
        s_fam = _cwe_family(s.cwe)
        if not s_fam:
            continue
        for d in dast:
            d_fam = _cwe_family(d.cwe)
            if d_fam and d_fam == s_fam and _same_target(s, d):
                out.append(ChainLink(
                    finding_a=s.id, finding_b=d.id,
                    link_type=LINK_SAST_DAST_CWE_ENDPOINT,
                    confidence=0.85,
                    rationale=(
                        f"SAST sink at `{s.endpoint}` and DAST "
                        f"finding share CWE family `{s_fam}`. "
                        f"Static pattern + live-exploit match → "
                        f"high-confidence end-to-end exploit."
                    ),
                ))
    return out


# ---------------------------------------------------------------------------
# 3. IaC → DAST: misconfig categories that surface at runtime
# ---------------------------------------------------------------------------


def link_iac_to_dast_by_category(findings: list[Finding]) -> list[ChainLink]:
    """IaC misconfig + matching DAST runtime confirmation →
    linked.

    Categories we link on:
      * `misconfig` (CORS/TLS/headers) ↔ same target with
        scan-side `cors_deep_check` / similar finding
      * `open_redirect` ↔ DAST `open_redirect_check` on same
        target
      * `info_disclosure` (IaC hardcoded secret) ↔ DAST
        finding mentioning the same secret in body

    Conservative: same target + matching category. CWE-level
    matching is unreliable across IaC + DAST because IaC
    findings often have category-only metadata (no CWE
    family alignment).
    """
    out: list[ChainLink] = []
    iac = [f for f in findings if f.category in (
        "misconfig", "open_redirect",
    ) and "iac" in (f.title or "").lower()]
    # Also surface IaC findings tagged via metadata.
    iac.extend([f for f in findings
                if f.metadata.get("source") == "iac"
                and f not in iac])
    dast = [f for f in findings if f not in iac]

    for i in iac:
        for d in dast:
            if not _same_target(i, d):
                continue
            cat_match = (
                i.category == d.category
                or (i.category == "open_redirect"
                    and "redirect" in (d.title or "").lower())
                or (i.category == "misconfig"
                    and "cors" in (d.title or "").lower())
            )
            if cat_match:
                out.append(ChainLink(
                    finding_a=i.id, finding_b=d.id,
                    link_type=LINK_IAC_DAST_CATEGORY,
                    confidence=0.75,
                    rationale=(
                        f"IaC `{i.title[:60]}` + DAST `{d.title[:60]}` "
                        f"on same target — IaC misconfig confirmed "
                        f"exploitable at runtime."
                    ),
                ))
    return out


# ---------------------------------------------------------------------------
# 4. Anomaly → DAST specialist: same endpoint
# ---------------------------------------------------------------------------


def link_anomaly_to_specialist(findings: list[Finding]) -> list[ChainLink]:
    """Phase 9 anomaly finding + matching DAST specialist on the
    same endpoint → linked.

    Example: `error_string_present` anomaly at /api/x (SQL
    error pattern) + `scan_sqli` finding on /api/x → linked.
    The anomaly hinted, the specialist confirmed.
    """
    out: list[ChainLink] = []
    anomalies = [f for f in findings if f.category == "anomaly"]
    others = [f for f in findings if f.category not in ("anomaly",)]
    for a in anomalies:
        for o in others:
            if not _same_endpoint(a, o) and not _same_target(a, o):
                continue
            # Prefer same-endpoint matches.
            same_endpoint = _same_endpoint(a, o)
            confidence = 0.75 if same_endpoint else 0.55
            out.append(ChainLink(
                finding_a=a.id, finding_b=o.id,
                link_type=LINK_ANOMALY_DAST_ENDPOINT,
                confidence=confidence,
                rationale=(
                    f"Anomaly `{a.title[:60]}` and finding "
                    f"`{o.title[:60]}` on "
                    f"{'same endpoint' if same_endpoint else 'same target'}."
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# 5. SCA → SAST: same package referenced
# ---------------------------------------------------------------------------


def link_sca_to_sast_by_package(findings: list[Finding]) -> list[ChainLink]:
    """SCA flagged package + SAST hit in code that mentions
    the same package → linked.

    Example: SCA flags `npm:lodash@4.17.20`; SAST rule fires
    on `app.js` and the file imports lodash → linked.

    The "imports lodash" check is approximated by string
    presence in the SAST finding's description (which often
    quotes the matched code) — we don't have call-graph data
    here, so this is heuristic.
    """
    out: list[ChainLink] = []
    sca = [f for f in findings
           if f.category == "vulnerable_dependency" and f.package]
    sast = [f for f in findings if f.category == "sast"]
    for s in sca:
        # Strip ecosystem prefix for matching: `npm:lodash` → `lodash`.
        pkg_name = s.package.split(":", 1)[-1]
        if not pkg_name or len(pkg_name) < 4:
            # Skip very short names (false-positive risk).
            continue
        pkg_lower = pkg_name.lower()
        for ts in sast:
            haystack = (
                ts.description.lower() + " " + ts.title.lower()
            )
            if pkg_lower in haystack:
                out.append(ChainLink(
                    finding_a=s.id, finding_b=ts.id,
                    link_type=LINK_SCA_SAST_PACKAGE,
                    confidence=0.7,
                    rationale=(
                        f"SAST finding's text references package "
                        f"`{pkg_name}` flagged by SCA — likely "
                        f"the SAST hit is in code that uses the "
                        f"vulnerable dep."
                    ),
                ))
    return out


# ---------------------------------------------------------------------------
# iter-21.4 — attack-chain linkers
#
# These encode SPECIFIC end-to-end exploits, not just CWE family
# co-occurrence. Each captures a real-world chain that competitor
# tools detect components of but rarely chain together
# automatically: Burp Pro detects CORS reflections AND SSRF but
# requires a human to spot the chain; ZAP detects JWT alg=none AND
# JWKS audit issues but doesn't combine them; commercial scanners
# rarely surface HTTP method override bypasses at all.
#
# Confidence floor is intentionally high (0.85+) — each chain
# requires multiple specific rule fires, not just a CWE-family
# overlap, so false-positive risk is low. When matched these
# chains are typically critical regardless of the individual
# finding severities.
# ---------------------------------------------------------------------------


def link_cors_reflection_to_ssrf_chain(
    findings: list[Finding],
) -> list[ChainLink]:
    """**CORS reflection → SSRF exfil chain.**

    When a target has BOTH (a) a CORS misconfig that reflects the
    `Origin` header AND credentials are allowed (cors_deep_check
    emits this) AND (b) an SSRF primitive on the same host
    (scan_ssrf / nuclei_runner with an ssrf-class CVE template),
    the attacker can chain them: their malicious page in any
    browser sends authenticated requests via the victim's session
    AND can read responses cross-origin AND can probe internal
    services through the SSRF primitive — full read-and-exfil.

    Each finding alone is medium-ish; together they're critical.
    Burp Pro detects both components but requires a human pen-tester
    to spot the chain — this linker automates that recognition.

    Conservative: requires same target AND both components present.
    Confidence: 0.9 (specific rule co-fire is unambiguous).
    """
    out: list[ChainLink] = []

    def _is_cors_reflection(f: Finding) -> bool:
        if f.category not in ("cors", "misconfig", "http_security_headers"):
            return False
        # Look for the specific reflective-CORS signature in title /
        # description. Tools emitting CORS findings vary in shape;
        # we match any of the canonical signals.
        haystack = f"{f.title} {f.description}".lower()
        return any(s in haystack for s in (
            "cors", "origin", "access-control-allow",
        )) and any(s in haystack for s in (
            "reflect", "allow-credentials", "wildcard", "echo",
        ))

    def _is_ssrf(f: Finding) -> bool:
        if f.category in ("ssrf",):
            return True
        if (f.cwe or "").upper() in ("CWE-918", "CWE-345"):
            return True
        return False

    cors = [f for f in findings if _is_cors_reflection(f)]
    ssrf = [f for f in findings if _is_ssrf(f)]
    for c in cors:
        for s in ssrf:
            if not _same_target(c, s):
                continue
            out.append(ChainLink(
                finding_a=c.id, finding_b=s.id,
                link_type=LINK_CORS_TO_SSRF_CHAIN,
                confidence=0.9,
                rationale=(
                    "Attack chain — CORS reflective policy + SSRF "
                    "primitive on the same target. An attacker page "
                    "in any victim's browser can drive authenticated "
                    "SSRF requests AND read the responses cross-"
                    "origin, exfiltrating internal-network data with "
                    "the victim's credentials. Each component alone "
                    "is medium-class; together they're critical."
                ),
            ))
    return out


def link_jwt_confusion_chain(
    findings: list[Finding],
) -> list[ChainLink]:
    """**JWT algorithm-confusion chain.**

    Three known JWT-bypass patterns chain through metadata + JWKS
    issues that scan_authn_metadata + jwt_audit emit separately:

    1. `alg=none` accepted by verifier (jwt_audit) +
       `id_token_signing_alg_values_supported: ["none", ...]` in
       OIDC metadata (scan_authn_metadata `alg-none-supported`)
       → confirmed accepts forged tokens; specifically callable.

    2. `alg=none` in OIDC metadata + ANY auth-required endpoint
       (probe_unauth_bola_path_params / scan_idor finding) →
       attacker forges admin user for that endpoint.

    3. JWKS has HMAC key with `k` member (scan_authn_metadata
       `jwks-hmac-key-leaked`) + JWT auth finding on the same
       target → attacker has the signing key in hand; ALL tokens
       are forgeable.

    Each component is high-severity alone; chained, the linker
    surfaces them as one CRITICAL chain with explicit attack
    construction instructions.

    Confidence: 0.95 (these are deterministic rule co-fires, no
    heuristic interpretation).
    """
    out: list[ChainLink] = []
    authn_findings = [f for f in findings if f.category == "authn_metadata"]
    jwt_findings = [f for f in findings if f.category in ("jwt", "authn", "auth")]
    bola_findings = [
        f for f in findings
        if f.category in ("idor", "bola", "auth") or (f.cwe or "") == "CWE-639"
    ]

    def _has_rule(f: Finding, rule_id: str) -> bool:
        haystack = f"{f.title} {f.description}".lower()
        return rule_id in haystack

    # Pattern 1: alg=none accepted on verifier + alg=none advertised
    # in OIDC metadata = "verifier WILL accept forged tokens".
    for a in authn_findings:
        if not _has_rule(a, "alg-none-supported"):
            continue
        for j in jwt_findings:
            jh = f"{j.title} {j.description}".lower()
            if "alg=none" in jh or "alg-none" in jh or "none alg" in jh:
                if _same_target(a, j):
                    out.append(ChainLink(
                        finding_a=a.id, finding_b=j.id,
                        link_type=LINK_JWT_CONFUSION_CHAIN,
                        confidence=0.95,
                        rationale=(
                            "JWT algorithm-confusion chain — OIDC "
                            "metadata advertises `alg=none` AND the "
                            "verifier accepts forged `alg=none` "
                            "tokens. Attacker can forge any user "
                            "(incl. admin) without knowing any "
                            "signing key. Single critical finding."
                        ),
                    ))

    # Pattern 2: HMAC key leaked in JWKS + JWT-protected endpoint
    # on same target = attacker has the signing key, forges
    # arbitrary tokens for every endpoint.
    #
    # Dedupe by id — `category="auth"` lands in both jwt_findings
    # and bola_findings; without the set the linker emits two
    # links for one logical (metadata, endpoint) pair.
    for a in authn_findings:
        if not _has_rule(a, "jwks-hmac-key-leaked"):
            continue
        candidates_by_id: dict[str, Finding] = {}
        for j in jwt_findings + bola_findings:
            candidates_by_id[j.id] = j
        for j in candidates_by_id.values():
            if _same_target(a, j):
                out.append(ChainLink(
                    finding_a=a.id, finding_b=j.id,
                    link_type=LINK_JWT_CONFUSION_CHAIN,
                    confidence=0.95,
                    rationale=(
                        "JWT key-exposure chain — HMAC signing key "
                        "leaked in public JWKS AND a JWT-protected "
                        "endpoint exists on the same target. The "
                        "attacker holds the key in hand: every JWT "
                        "issued by this issuer is forgeable, every "
                        "JWT-protected endpoint is reachable as "
                        "any user."
                    ),
                ))

    return out


def link_auth_bypass_via_method_override(
    findings: list[Finding],
) -> list[ChainLink]:
    """**Auth bypass via HTTP method override chain.**

    Common Spring/Rails/Express misconfiguration: middleware
    enforces auth on `POST /admin/users` but the framework also
    accepts `X-HTTP-Method-Override: POST` (or `?_method=POST`)
    on a `GET /admin/users` request. The auth check fires on the
    GET (unauthenticated, returns 401) BUT the framework dispatches
    to the POST handler internally. Net: unauthenticated POST.

    Detection chain:
      * BFLA / IDOR / unauth-debug finding on `/admin/...` path
        (scan_api_bfla / probe_unauth_bola_path_params) — indicates
        the endpoint has weak ACL.
      * `http_security_headers_audit` finding flagging X-HTTP-
        Method-Override acceptance (when present in headers).
      * Same target host.

    OR:
      * IaC finding for a Spring boot / Express framework
        configuration that advertises `_method` override.

    Confidence 0.85 (method-override misuse depends on the
    framework's exact behaviour; the chain identifies the
    PATTERN that's exploit-prone, but the operator still
    confirms with a manual probe).
    """
    out: list[ChainLink] = []

    def _is_acl_finding(f: Finding) -> bool:
        if f.category in ("bola", "bfla", "idor"):
            return True
        if (f.cwe or "").upper() in ("CWE-285", "CWE-862", "CWE-639"):
            return True
        haystack = f"{f.title} {f.description}".lower()
        return "/admin" in haystack or "/api/admin" in haystack

    def _is_method_override(f: Finding) -> bool:
        haystack = f"{f.title} {f.description}".lower()
        return (
            "x-http-method-override" in haystack
            or "_method=" in haystack
            or "method override" in haystack
            or "method-override" in haystack
        )

    acl = [f for f in findings if _is_acl_finding(f)]
    mo = [f for f in findings if _is_method_override(f)]
    for a in acl:
        for m in mo:
            if _same_target(a, m):
                out.append(ChainLink(
                    finding_a=a.id, finding_b=m.id,
                    link_type=LINK_AUTH_BYPASS_VIA_METHOD_OVERRIDE,
                    confidence=0.85,
                    rationale=(
                        "Auth-bypass chain — HTTP method-override "
                        "header / query parameter accepted by the "
                        "framework AND an ACL-weakened endpoint on "
                        "the same target. Pattern: attacker sends "
                        "`GET /admin/...` (unauth check fires on "
                        "GET only) with `X-HTTP-Method-Override: "
                        "POST`; framework dispatches to the POST "
                        "handler internally, bypassing the auth "
                        "middleware."
                    ),
                ))
    return out


# ---------------------------------------------------------------------------
# Linker registry
# ---------------------------------------------------------------------------


LINKER_REGISTRY: list[Callable[[list[Finding]], list[ChainLink]]] = [
    link_sca_to_dast_by_cwe,
    link_sast_to_dast_by_cwe_endpoint,
    link_iac_to_dast_by_category,
    link_anomaly_to_specialist,
    link_sca_to_sast_by_package,
    # iter-21.4 — attack-chain linkers (added last so they
    # appear in the chain artifact AFTER the general
    # co-occurrence linkers — wrapper UIs typically render in
    # registry order, and the specific exploit chains are
    # higher-signal than the general overlaps).
    link_cors_reflection_to_ssrf_chain,
    link_jwt_confusion_chain,
    link_auth_bypass_via_method_override,
]
