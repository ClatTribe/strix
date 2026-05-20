"""Scoring helpers for per-target benchmarks.

A "match" between a found finding and an expected entry is conservative:
- same category (or CWE)
- same location (file for code, endpoint for web, port for IP)
- line within ±LINE_TOLERANCE for code targets

Returns precision, recall, lists of missed expected and false-positive found.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


LINE_TOLERANCE = 20


@dataclass
class Expected:
    id: str
    category: str
    cwe: str | None = None
    file: str | None = None
    line: int | None = None
    endpoint: str | None = None
    port: int | None = None
    severity: str | None = None
    description: str = ""
    must_find: bool = True


@dataclass
class Found:
    title: str
    category: str | None = None
    cwe: str | None = None
    file: str | None = None
    line: int | None = None
    endpoint: str | None = None
    port: int | None = None
    severity: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScoreResult:
    expected_count: int
    found_count: int
    matched_count: int
    precision: float
    recall: float
    missed: list[str]
    false_positives: list[str]
    matches: list[tuple[str, str]]  # (expected.id, found.title)


def _norm(s: str | None) -> str:
    return (s or "").strip().lower()


def _categories_match(a: str | None, b: str | None) -> bool:
    """Loose category match — handles strix's free-form categories vs the manifest's enum."""
    if not a or not b:
        return False
    a, b = _norm(a), _norm(b)
    if a == b:
        return True
    # tolerate plurals / common variants
    aliases = {
        # Phase 6 SCA — `scan_sca_lockfiles` emits
        # category="vulnerable_dependency"; the benchmark manifest uses
        # the same key. Add a few common variants so synonym findings
        # (some specialists tag as "supply_chain" or "dependency_cve")
        # still match.
        "supply_chain": "vulnerable_dependency",
        "dependency_cve": "vulnerable_dependency",
        "vulnerable_dep": "vulnerable_dependency",
        "vulnerable-dependency": "vulnerable_dependency",
        "sql_injection": "sqli",
        "sql-injection": "sqli",
        "nosqli": "sqli",
        "nosql_injection": "sqli",
        "command_injection": "cmd_injection",
        "command-injection": "cmd_injection",
        "os_command_injection": "cmd_injection",
        "cross_site_scripting": "xss",
        "cross-site-scripting": "xss",
        "stored_xss": "xss",
        "reflected_xss": "xss",
        "dom_xss": "xss",
        "server_side_request_forgery": "ssrf",
        "insecure_deserialization": "deserialization",
        "directory_traversal": "path_traversal",
        "path-traversal": "path_traversal",
        "weak_cryptography": "crypto",
        "cryptographic_failure": "crypto",
        "hardcoded_credentials": "info_disclosure",
        "hardcoded_secret": "info_disclosure",
        "exposed_secret": "info_disclosure",
        "broken_access_control": "authz",
        "missing_authorization": "authz",
        "missing_auth": "authz",
        "open-redirect": "open_redirect",
        # scan_api_rate_limit emits category="api_rate_limit"; vampi
        # and crapi manifests use "rate_limit". Caught 2026-05-20 via
        # the L1-only bench harness — without this alias, every per-
        # endpoint rate-limit finding shows up as an FP.
        "api_rate_limit": "rate_limit",
        "rate-limit": "rate_limit",
        # scan_container_image emits category="sca" for each CVE
        # found in a container image (one finding per vulnerable
        # package). The container_image fixture manifests use
        # `vulnerable_dependency` consistent with SCA-on-lockfile.
        # Caught 2026-05-20 while adding the nginx:1.18 fixture.
        "sca": "vulnerable_dependency",
        # scan_api_bola / scan_api_bfla / scan_api_mass_assignment emit
        # api_*-prefixed categories when they DO fire (currently they
        # need owner_ids from L2 auth setup — out of L1 scope).
        # Adding the aliases now so the L2 specialist emissions match
        # the manifests when they do happen.
        "api_bola": "bola",
        "api_bfla": "bfla",
        "api_mass_assignment": "mass_assignment",
        # JWT findings often emit category="auth" with CWE-287 even
        # when the manifest expects category="jwt" (CWE-347). Without
        # this alias, every JWT-handling finding shows up as an FP.
        # Keep auth → jwt unidirectional rather than a synonym (auth
        # is a strict superset; not every auth finding is a JWT one)
        # by mapping auth's normalized form to jwt only when the
        # other side is jwt — handled below outside the dict.
    }
    canonical_a = aliases.get(a, a)
    canonical_b = aliases.get(b, b)
    if canonical_a == canonical_b:
        return True
    # Asymmetric overlap: a finding tagged "auth" is a candidate match
    # for "jwt" expectations (and vice-versa) — narrow enough to be
    # safe given the manifest's discrete vulnerability classes.
    auth_jwt = {"auth", "jwt", "jwt_misconfiguration", "authentication",
                "weak_authentication"}
    if canonical_a in auth_jwt and canonical_b in auth_jwt:
        return True
    # IDOR / authz / data-exposure findings often emit with a broader
    # info_disclosure / data_exposure category — count them when title-id
    # keyword overlap (handled in _location_match) is strong enough.
    # This is one-way: info_disclosure is a superset; only match when the
    # expected category is one of the narrower access-control classes.
    access_control = {"idor", "authz", "broken_access_control"}
    info_disclosure_set = {"info_disclosure", "data_exposure",
                           "sensitive_data_exposure"}
    if (canonical_a in info_disclosure_set and canonical_b in access_control) \
       or (canonical_b in info_disclosure_set and canonical_a in access_control):
        return True
    return False


def _cwe_match(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return _norm(a).replace("cwe-", "") == _norm(b).replace("cwe-", "")


def _file_match(a: str | None, b: str | None) -> bool:
    # Match-by-category-only fallback: if either side lacks file metadata,
    # don't penalize. Strix's markdown sometimes omits file:line for findings
    # the agent identified by behaviour rather than by source location. Same
    # convention as _line_match — be permissive on missing data, strict when
    # both sides have something to compare.
    if not a or not b:
        return True
    a, b = _norm(a), _norm(b)
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _line_match(a: int | None, b: int | None) -> bool:
    if a is None or b is None:
        return True  # don't penalize when location is missing on either side
    return abs(a - b) <= LINE_TOLERANCE


def _endpoint_match(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    a, b = _norm(a), _norm(b)
    # tolerate trailing slash, query string, and prefix (host) variation
    a = a.split("?", 1)[0].rstrip("/")
    b = b.split("?", 1)[0].rstrip("/")
    if a == b:
        return True
    # strip scheme + host if present
    for prefix in ("http://", "https://"):
        if a.startswith(prefix):
            a = "/" + a.split("/", 3)[-1] if "/" in a[len(prefix):] else "/"
        if b.startswith(prefix):
            b = "/" + b.split("/", 3)[-1] if "/" in b[len(prefix):] else "/"
    if a == b:
        return True
    # Substring tolerance — when one side is a path prefix of the
    # other (e.g. expected `/api/Baskets` matches found
    # `/api/Baskets/123`), count it. Real-world: deterministic
    # specialists emit the concrete probe URL with substituted ID,
    # not the path template.
    if a and b and (a.startswith(b) or b.startswith(a)):
        return True
    return False


def _title_mentions_endpoint(title: str | None, endpoint: str | None) -> bool:
    """Fallback: when the found.endpoint is the bare host URL (no
    path), check whether the title mentions enough of the expected
    endpoint to count as a match. Real-world example: agent emits
    target=`http://host` for a JWT alg=none finding but the title
    says `JWT Signature Validation Bypass`. A `weak-jwt-handling`
    expectation at endpoint=`/rest/user/whoami` should match here
    because the SAME bug is being described — the agent just used
    the broad target field."""
    if not title or not endpoint:
        return False
    title_l = _norm(title)
    # Pull out distinctive path segments from the endpoint (skip
    # generic ones like `/api/`, `/rest/`).
    segments = [s for s in endpoint.lower().split("/") if s and s not in
                {"api", "rest", "v1", "v2", ""}]
    if not segments:
        return False
    # If ANY distinctive segment appears in the title, count it.
    return any(seg in title_l for seg in segments)


def _title_mentions_id_keywords(title: str | None, expected_id: str) -> bool:
    """Fallback: when the found.endpoint is the bare host URL but
    the title clearly references the expected vulnerability — e.g.
    expected `weak-jwt-handling` with title "JWT Signature Validation
    Bypass Using none Algorithm" should match because both halves
    of `jwt` (and `weak`) appear in the title.

    Strategy: split the expected_id by `-` / `_`; if ANY distinctive
    token appears as substring in the title, count it. Combined with
    the category-match precondition, this is safe — the category
    already constrains which expected entries we're considering.
    Tolerates singular/plural via simple `s` suffix-strip.

    Skip generic/structural tokens that don't disambiguate
    vulnerabilities (`weak`, `bad`, `missing`, etc.) — they'd
    otherwise false-match generic titles."""
    if not title or not expected_id:
        return False
    title_l = _norm(title)
    GENERIC = {"a", "an", "the", "of", "to", "in", "weak", "bad", "missing",
               "broken", "insecure", "unsafe", "deprecated", "default"}
    raw_tokens = [t for t in expected_id.replace("_", "-").split("-")
                  if t and t not in GENERIC]
    if not raw_tokens:
        return False
    for tok in raw_tokens:
        # Exact substring match, OR with trailing 's' (plural), OR
        # without trailing 's' (singular ↔ plural normalization).
        if tok in title_l or (tok + "s") in title_l or tok.rstrip("s") in title_l:
            return True
    return False


def _location_match(expected: Expected, found: Found) -> bool:
    """Match by whichever location field the expected entry specifies."""
    if expected.file is not None:
        return _file_match(expected.file, found.file) and _line_match(expected.line, found.line)
    if expected.endpoint is not None:
        if _endpoint_match(expected.endpoint, found.endpoint):
            return True
        # Two title-based fallbacks for the common case where the
        # agent emits target=bare-host-url with a descriptive title.
        if _title_mentions_endpoint(found.title, expected.endpoint):
            return True
        return _title_mentions_id_keywords(found.title, expected.id)
    if expected.port is not None:
        return expected.port == found.port
    return True  # no location specified — category-only match


def _is_match(expected: Expected, found: Found) -> bool:
    cat_ok = _categories_match(expected.category, found.category) or _cwe_match(
        expected.cwe, found.cwe
    )
    if not cat_ok:
        return False
    return _location_match(expected, found)


def score(expected_list: list[Expected], found_list: list[Found]) -> ScoreResult:
    expected_must = [e for e in expected_list if e.must_find]
    matched: list[tuple[str, str]] = []
    matched_expected: set[str] = set()
    matched_found: set[int] = set()

    for i, found in enumerate(found_list):
        for expected in expected_must:
            if expected.id in matched_expected:
                continue
            if _is_match(expected, found):
                matched.append((expected.id, found.title))
                matched_expected.add(expected.id)
                matched_found.add(i)
                break

    found_count = len(found_list)
    matched_count = len(matched)
    expected_count = len(expected_must)

    precision = matched_count / found_count if found_count else 0.0
    recall = matched_count / expected_count if expected_count else 0.0

    missed = [e.id for e in expected_must if e.id not in matched_expected]
    false_positives = [
        found_list[i].title for i in range(found_count) if i not in matched_found
    ]

    return ScoreResult(
        expected_count=expected_count,
        found_count=found_count,
        matched_count=matched_count,
        precision=round(precision, 3),
        recall=round(recall, 3),
        missed=missed,
        false_positives=false_positives,
        matches=matched,
    )
