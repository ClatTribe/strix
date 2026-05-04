"""Session-cookie predictability / entropy analyzer.

Catches dev-built session schemes that are sequential, low-entropy,
or time-based. The analyses are deterministic and run on a sample
of N cookie values.

Two acquisition modes:

1.  **Authenticate-N-times** — caller provides `auth_url`, `method`,
    optional `body` / `headers`, and `cookie_name`. The tool hits the
    URL `samples` times via cluster-A (no follow-redirects), reads
    `Set-Cookie` from each response, extracts the value of the named
    cookie, and analyses the resulting set.
2.  **Pre-collected** — caller provides `cookie_values: list[str]`
    directly. The agent / wrapper has already harvested cookies via
    its own login flow and just wants the analysis.

Analyses applied to the sample set:

- **Sample diversity** — count unique values; if `unique_count < 2`,
  every login returned the same value → critical CWE-330 (cookie
  is constant or session is not actually being minted).
- **Shannon entropy** (per-cookie) — bits per character × character
  count, averaged. Flags `entropy_bits < 64` per cookie as low
  entropy. We compute the entropy on the cookie's character
  alphabet (URL-safe base64, hex, base16, etc., auto-detected from
  the alphabet observed across the sample).
- **Chi-squared bias** — for the most common character class
  (lowercase hex / URL-safe base64), counts observed frequency of
  each symbol vs uniform expectation. Large χ² with `p < 0.001`
  flags non-uniform alphabet distribution (e.g. timestamps masked
  as hex).
- **Sequential-counter detection** — sort cookie values
  lexicographically and bytewise. If the sorted set decodes to a
  monotonically-increasing integer sequence (modulo any prefix /
  suffix) the session is sequential.
- **NIST SP 800-22 mini-tests** (on the concatenated bit stream of
  the sample, length-padded to a multiple of 8):
    - Frequency / monobit (proportion of 1-bits in (-3σ, +3σ)).
    - Runs test (number of runs of identical bits).
    - Longest-run test (longest run of 1s in 8-bit blocks).

Severity:

- **Critical** (CWE-330) — sample size ≥ 2 and `unique_count` < 2
  (cookie value constant across logins).
- **High** (CWE-330) — sequential-counter detected (sorted sample
  decodes to monotonic integers) OR average per-cookie Shannon
  entropy < 32 bits (any modern session must reach 64+ bits).
- **Medium** (CWE-330) — average per-cookie entropy 32-64 bits OR
  any NIST sub-test fails OR χ² test fails (`p < 0.001`).
- **Low** (CWE-330) — average entropy 64-80 bits (just above
  acceptable; flagged for visibility).

Skip cases:

- `samples < 2` AND no `cookie_values` → can't measure variability.
  Tool returns success with `inconclusive=True`.
- `auth_url` returns no `Set-Cookie` for the named cookie → caller
  is hitting the wrong endpoint or the cookie isn't actually being
  minted; tool returns success with `inconclusive=True`.

Each finding carries `description_plain` + `recommended_action`
(use a CSPRNG — `secrets.token_urlsafe(32)` in Python,
`crypto/rand` in Go, `SecureRandom` in Java; never derive session
IDs from user IDs / timestamps / sequential counters; minimum
128 bits of entropy; rotate on privilege escalation).

`verification_status=needs_review` since low-sample-size analyses
have variance — the agent should re-run with `samples=64` if
flagged and the user wants confirmation.

Composes with cluster-A safety. MITRE T1556.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "session_entropy_check"
_DEFAULT_TIMEOUT = 10.0
_MAX_RESPONSE_SCAN = 64 * 1024
_DEFAULT_SAMPLES = 16
_MAX_SAMPLES = 128


# Alphabet families used for chi-squared bias.
_HEX_LOWER = "0123456789abcdef"
_HEX_UPPER = "0123456789ABCDEF"
_B64_URLSAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64_STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B16 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # base32

_ALPHABETS: list[tuple[str, str]] = [
    ("hex_lower", _HEX_LOWER),
    ("hex_upper", _HEX_UPPER),
    ("base64_urlsafe", _B64_URLSAFE),
    ("base64_standard", _B64_STANDARD),
    ("base32", _B16),
]


# ---------------------------------------------------------------------------
# HTTP fetch (cluster-A composing)
# ---------------------------------------------------------------------------


def _http_request(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Send a request via cluster-A safety. Returns
    {status, headers, set_cookie_list, body, error?, skipped?}."""
    headers = dict(headers or {})

    try:
        from strix.tools.proxy.proxy_manager import get_proxy_manager

        manager = get_proxy_manager()
    except Exception:  # noqa: BLE001
        manager = None
    if manager is not None:
        try:
            r = manager.send_simple_request(
                method, url, headers=headers, body=body, timeout=int(timeout)
            )
            if r.get("skipped"):
                return {
                    "status": 0, "headers": {}, "set_cookie_list": [],
                    "body": "", "skipped": True,
                }
            response_headers = r.get("headers") or {}
            return {
                "status": int(r.get("status_code") or 0),
                "headers": _lower_keys(response_headers),
                "set_cookie_list": _extract_set_cookie_list(response_headers),
                "body": (r.get("body") or "")[:_MAX_RESPONSE_SCAN],
            }
        except Exception:  # noqa: BLE001
            logger.debug("proxy send_simple_request failed; falling back", exc_info=True)

    try:
        import httpx

        from strix.tools.proxy.http_safety import (
            inject_auth_headers,
            is_path_excluded,
            throttle_for_rate_limit,
        )

        excluded, _ = is_path_excluded(url)
        if excluded:
            return {
                "status": 0, "headers": {}, "set_cookie_list": [],
                "body": "", "skipped": True,
            }
        merged = inject_auth_headers(headers)
        throttle_for_rate_limit()
        with httpx.Client(timeout=timeout, follow_redirects=False, verify=False) as c:
            content = body.encode("utf-8") if body else None
            r = c.request(method, url, headers=merged, content=content)
            # httpx exposes Set-Cookie via response.headers.get_list()
            set_cookie_list = list(r.headers.get_list("set-cookie")) if r.headers else []
            return {
                "status": r.status_code,
                "headers": _lower_keys(dict(r.headers)),
                "set_cookie_list": set_cookie_list,
                "body": r.text[:_MAX_RESPONSE_SCAN],
            }
    except Exception as e:  # noqa: BLE001
        return {
            "status": 0, "headers": {}, "set_cookie_list": [],
            "body": "", "error": str(e),
        }


def _lower_keys(headers: dict[str, Any]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers.items()}


def _extract_set_cookie_list(headers: dict[str, Any]) -> list[str]:
    """Pull the list of Set-Cookie headers out of a header mapping.
    Some HTTP libraries return multi-Set-Cookie joined with ', '
    (which is wrong because cookie values can contain commas), some
    return a list. We accept either."""
    if not headers:
        return []
    for key, value in headers.items():
        if str(key).lower() == "set-cookie":
            if isinstance(value, list):
                return [str(v) for v in value]
            return [str(value)]
    return []


# ---------------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------------


def _extract_cookie_value(set_cookie_lines: list[str], name: str) -> str | None:
    """Find the cookie named `name` in the list of Set-Cookie header
    lines and return its value (URL-decoded as-is — we don't decode
    %xx because we want the raw transport bytes for entropy
    analysis)."""
    target = name.strip()
    for line in set_cookie_lines:
        # Set-Cookie: NAME=VALUE; Path=/; ...
        for part in line.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            cookie_name, _, cookie_value = part.partition("=")
            if cookie_name.strip() == target:
                return cookie_value.strip()
            # Only check the first cookie-name=value (subsequent
            # parts are attributes, e.g. Path, Domain, Max-Age).
            break
    return None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def _shannon_entropy_bits(value: str) -> float:
    """Shannon entropy of the string value in bits (per-character
    entropy × length)."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = float(len(value))
    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h * len(value)


def _detect_alphabet(values: list[str]) -> tuple[str, str]:
    """Return (label, alphabet_string) for the smallest alphabet
    that all observed characters fit into. Returns
    ('printable', <observed>) if no canonical alphabet matches."""
    observed = set("".join(values))
    for label, alphabet in _ALPHABETS:
        if observed.issubset(set(alphabet)):
            return (label, alphabet)
    return ("printable", "".join(sorted(observed)))


def _chi_squared(values: list[str], alphabet: str) -> tuple[float, float]:
    """Pearson χ² of character frequency vs uniform expectation
    over `alphabet`. Returns (chi2, p_value_approx). p_value is a
    coarse approximation: we reject (p < 0.001) when chi2 exceeds
    the upper-tail threshold for df=len(alphabet)-1."""
    concat = "".join(values)
    if not concat or not alphabet:
        return (0.0, 1.0)
    n = len(concat)
    expected = n / len(alphabet)
    if expected <= 0:
        return (0.0, 1.0)
    counts = Counter(concat)
    chi2 = 0.0
    for symbol in alphabet:
        c = counts.get(symbol, 0)
        chi2 += ((c - expected) ** 2) / expected

    # χ² critical value for p=0.001 by degrees of freedom (df).
    # Pre-tabulated for common df: 15 (hex), 31 (b32), 63 (b64).
    df = len(alphabet) - 1
    crit_table = {
        15: 37.697,    # hex (df=15)
        31: 61.098,    # base32 (df=31)
        63: 103.4,     # base64 (df=63)
    }
    crit = crit_table.get(df)
    if crit is None:
        # Fallback: for large df, the χ²(df, 0.001) ≈ df + 3*sqrt(2*df).
        crit = df + 3 * math.sqrt(2 * df)

    p_approx = 0.0005 if chi2 > crit else 0.5
    return (chi2, p_approx)


def _detect_sequential_counter(values: list[str]) -> tuple[bool, str]:
    """Returns (is_sequential, evidence). Tries:
    - All values are decimal numbers and form a monotonic sequence.
    - All values are hex and form a monotonic sequence.
    - All values are URL-safe base64 of fixed-width integers.
    - Common-prefix / common-suffix stripped, the residue is
      sequential as decimal or hex.
    """
    if len(values) < 2:
        return (False, "")

    # Strip common prefix / suffix.
    prefix = _common_prefix(values)
    suffix = _common_suffix([v[len(prefix):] for v in values])
    cores: list[str] = []
    for v in values:
        core = v[len(prefix):]
        if suffix:
            core = core[: -len(suffix)] if core.endswith(suffix) else core
        cores.append(core)

    # Decimal monotonic?
    if all(c.isdigit() for c in cores):
        nums = [int(c) for c in cores]
        if _monotonic_with_small_step(nums):
            return (True, f"decimal monotonic; prefix={prefix!r}, suffix={suffix!r}")

    # Hex monotonic?
    hex_ok = all(re.fullmatch(r"[0-9a-fA-F]+", c) for c in cores) and all(cores)
    if hex_ok:
        try:
            nums = [int(c, 16) for c in cores]
            if _monotonic_with_small_step(nums):
                return (True, f"hex monotonic; prefix={prefix!r}, suffix={suffix!r}")
        except ValueError:
            pass

    return (False, "")


def _common_prefix(values: list[str]) -> str:
    if not values:
        return ""
    p = values[0]
    for v in values[1:]:
        i = 0
        while i < min(len(p), len(v)) and p[i] == v[i]:
            i += 1
        p = p[:i]
        if not p:
            break
    return p


def _common_suffix(values: list[str]) -> str:
    if not values:
        return ""
    rev = [v[::-1] for v in values]
    return _common_prefix(rev)[::-1]


def _monotonic_with_small_step(nums: list[int]) -> bool:
    """True if `nums` (after sorting) is strictly increasing AND the
    diff sequence is tightly clustered — i.e. the values look like
    they came from a counter, not from a CSPRNG.

    Random-uniform samples produce widely-varying gaps; a real
    counter produces near-constant gaps. Heuristic: require
    max_diff / min_diff < 3 (counter steps are within 3× of each
    other) — uniform-random samples typically show ratios of 50×+.
    """
    if len(nums) < 2:
        return False
    s = sorted(nums)
    if any(b <= a for a, b in zip(s, s[1:])):
        return False
    diffs = [b - a for a, b in zip(s, s[1:])]
    if not diffs:
        return False
    min_diff = min(diffs)
    max_diff = max(diffs)
    if min_diff <= 0:
        return False
    # Counter heuristic: gaps are within 3× of each other.
    return (max_diff / min_diff) < 3


def _bit_stream(values: list[str], alphabet: str = "") -> str:
    """Concatenated bit string from the sample.

    If `alphabet` is supplied and matches the values' character set,
    each character is encoded as its alphabet index in the minimum
    number of bits (4 for hex, 5 for base32, 6 for base64). This
    produces a bit-stream that reflects the actual encoded entropy,
    not the structural high-bit-always-zero bias of ASCII.

    If alphabet is empty or characters don't all fit, falls back to
    8-bit ASCII per character (correct for arbitrary printable
    bytes; less precise for known-encoding cookies).

    Truncates to a multiple of 8.
    """
    if alphabet:
        bits_per_char = 0
        n = len(alphabet)
        if n > 0:
            # Smallest power-of-two ≥ alphabet size.
            bits_per_char = (n - 1).bit_length() if n > 1 else 1
        if bits_per_char and all(c in alphabet for v in values for c in v):
            bits = "".join(
                format(alphabet.index(c), f"0{bits_per_char}b")
                for v in values for c in v
            )
            rem = len(bits) % 8
            if rem:
                bits = bits[: -rem]
            return bits
    bits = "".join(format(ord(c) & 0xFF, "08b") for v in values for c in v)
    rem = len(bits) % 8
    if rem:
        bits = bits[: -rem]
    return bits


def _frequency_test(bits: str) -> tuple[bool, float]:
    """NIST monobit. Returns (passed, observed_proportion)."""
    if not bits:
        return (True, 0.5)
    n = len(bits)
    s = bits.count("1") - bits.count("0")
    proportion = bits.count("1") / n
    s_obs = abs(s) / math.sqrt(n)
    # p-value approximation: erfc(s_obs / sqrt(2))
    p_value = math.erfc(s_obs / math.sqrt(2))
    return (p_value >= 0.01, proportion)


def _runs_test(bits: str) -> tuple[bool, int]:
    """NIST runs test on a bit string. Returns (passed, run_count)."""
    if not bits:
        return (True, 0)
    n = len(bits)
    pi = bits.count("1") / n
    if abs(pi - 0.5) >= (2 / math.sqrt(n)):
        return (False, 0)
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            runs += 1
    expected = 2 * n * pi * (1 - pi)
    if expected <= 0:
        return (True, runs)
    s_obs = abs(runs - expected) / (2 * math.sqrt(2 * n) * pi * (1 - pi))
    p_value = math.erfc(s_obs)
    return (p_value >= 0.01, runs)


def _longest_run_test(bits: str) -> tuple[bool, int]:
    """NIST longest-run test (mini, M=8 block size). Returns
    (passed, longest_run_observed).

    Counts 8-bit blocks where the longest run of 1s reaches the
    maximum (8). For genuine CSPRNG output, all-1s blocks occur with
    probability 1/256 per block, so a few are expected. We reject
    only when more than 5% of blocks show the full 8-bit run — the
    smoking gun for stuck-bit / structural-1 generators.
    """
    if len(bits) < 128:
        return (True, 0)
    full_run_blocks = 0
    longest = 0
    block_count = 0
    for i in range(0, len(bits) - 7, 8):
        block_count += 1
        block = bits[i: i + 8]
        run = max_run = 0
        for c in block:
            if c == "1":
                run += 1
                max_run = max(max_run, run)
            else:
                run = 0
        if max_run >= 8:
            full_run_blocks += 1
        longest = max(longest, max_run)
    if block_count == 0:
        return (True, longest)
    full_run_ratio = full_run_blocks / block_count
    # Reject only when > 5% of blocks are all-1s — far above the
    # 1/256 (~0.4%) expected from CSPRNG output.
    return (full_run_ratio < 0.05, longest)


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_finding(
    *,
    title: str,
    severity: str,
    target: str,
    endpoint: str,
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
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="weak_session_id",
        cwe="CWE-330",
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Session IDs derived from sequential counters, "
            "timestamps, or low-entropy sources let an attacker "
            "predict valid session tokens for other users without "
            "ever interacting with their browser. Real-world impact: "
            "account takeover via session prediction; brute-forcing "
            "session IDs from an authenticated baseline; bypass of "
            "rate-limits on the login endpoint by jumping straight "
            "to authenticated requests."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="needs_review",
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
    mitre_techniques=["T1556"],  # Modify Authentication Process
)
def session_entropy_check(
    target_url: str | None = None,
    cookie_name: str = "session",
    samples: int = _DEFAULT_SAMPLES,
    method: str = "GET",
    body: str = "",
    headers: dict[str, str] | None = None,
    cookie_values: list[str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Analyze session-cookie predictability / entropy.

    Two acquisition modes:
        - **auth-N-times**: provide `target_url` (and optionally
          `method` / `body` / `headers`). The tool hits the URL
          `samples` times via cluster-A and reads the named cookie
          from each response.
        - **pre-collected**: provide `cookie_values` directly. The
          analysis runs on the supplied list.

    Args:
        target_url: URL that mints the session cookie. Required
            unless `cookie_values` is supplied.
        cookie_name: Name of the cookie to harvest (default
            `session`). Common alternatives: `JSESSIONID`,
            `PHPSESSID`, `connect.sid`, `_app_session`.
        samples: How many cookies to harvest (default 16,
            min 2, max 128).
        method: HTTP method for the auth probe. Default GET.
        body: Optional request body for POST-style logins.
        headers: Optional extra request headers.
        cookie_values: Pre-harvested cookie values; bypasses the
            HTTP probe phase.
        timeout: Per-probe timeout in seconds (default 10).

    Returns:
        {
          success, target_url?, cookie_name, samples_requested,
          samples_collected, unique_count,
          analyses: {
            shannon_entropy_avg_bits, shannon_entropy_min_bits,
            alphabet, chi_squared, chi_squared_p_value,
            sequential_counter: {detected, evidence},
            nist: {frequency: {passed, proportion},
                   runs: {passed, run_count},
                   longest_run: {passed, longest_run}},
          },
          findings_emitted, inconclusive?, reason?
        }

    Findings:
        - **Critical** CWE-330 — every cookie identical (constant).
        - **High** — sequential-counter detected; or avg entropy
          < 32 bits.
        - **Medium** — entropy 32-64 bits; or any NIST/χ² test
          fails.
        - **Low** — entropy 64-80 bits.

    Notes:
        - Read-only.
        - Composes with cluster-A safety; `--exclude-path` skips.
        - `verification_status=needs_review`.
    """
    if cookie_values is not None:
        # Pre-collected mode.
        target_host = "(pre-collected)"
        endpoint = "(pre-collected)"
        samples_requested = len(cookie_values)
    else:
        if not target_url:
            return {
                "success": False,
                "error": "either target_url or cookie_values is required",
            }
        target_url_norm = _normalize_target(target_url)
        if target_url_norm is None:
            return {"success": False, "error": f"invalid target_url: {target_url!r}"}
        target_host = (urlparse(target_url_norm).hostname or "").lower()
        endpoint = target_url_norm
        if not target_host:
            return {"success": False, "error": f"could not resolve hostname from {target_url!r}"}
        target_url = target_url_norm
        samples_requested = max(2, min(int(samples), _MAX_SAMPLES))

    cev = _start_check("session_entropy", target_host)

    # ---- Acquisition ----
    if cookie_values is None:
        collected: list[str] = []
        last_status = 0
        for i in range(samples_requested):
            response = _http_request(
                method, target_url,  # type: ignore[arg-type]
                headers=headers, body=body, timeout=timeout,
            )
            if response.get("skipped"):
                _complete_check(cev, "inconclusive", "URL excluded by --exclude-path")
                return {
                    "success": True,
                    "target_url": target_url,
                    "cookie_name": cookie_name,
                    "samples_requested": samples_requested,
                    "samples_collected": 0,
                    "unique_count": 0,
                    "analyses": {},
                    "findings_emitted": 0,
                    "inconclusive": True,
                    "reason": "excluded by --exclude-path",
                }
            last_status = int(response.get("status") or 0)
            value = _extract_cookie_value(
                response.get("set_cookie_list") or [], cookie_name
            )
            if value:
                collected.append(value)
        cookies = collected

        if len(cookies) < 2:
            _complete_check(
                cev, "inconclusive",
                f"only collected {len(cookies)} sample(s); cookie {cookie_name!r} not minted by {target_url}",
            )
            return {
                "success": True,
                "target_url": target_url,
                "cookie_name": cookie_name,
                "samples_requested": samples_requested,
                "samples_collected": len(cookies),
                "unique_count": len(set(cookies)),
                "analyses": {},
                "findings_emitted": 0,
                "inconclusive": True,
                "reason": (
                    f"cookie {cookie_name!r} not present in Set-Cookie "
                    f"after {samples_requested} probes "
                    f"(last status {last_status}); the endpoint may not mint "
                    "a fresh cookie per request"
                ),
            }
    else:
        cookies = list(cookie_values)
        if len(cookies) < 2:
            _complete_check(
                cev, "inconclusive",
                f"caller supplied {len(cookies)} cookie value(s); need ≥ 2",
            )
            return {
                "success": True,
                "cookie_name": cookie_name,
                "samples_requested": len(cookies),
                "samples_collected": len(cookies),
                "unique_count": len(set(cookies)),
                "analyses": {},
                "findings_emitted": 0,
                "inconclusive": True,
                "reason": "need at least 2 cookie values",
            }

    # ---- Analysis ----
    unique_count = len(set(cookies))
    analyses: dict[str, Any] = {
        "samples": len(cookies),
        "unique_count": unique_count,
    }

    # Constant value across logins → critical.
    if unique_count < 2:
        _emit_finding(
            title=f"Session cookie {cookie_name!r} is constant on {target_host}",
            severity="critical",
            target=target_host,
            endpoint=endpoint,
            description=(
                f"Across {len(cookies)} requests, the {cookie_name!r} "
                f"cookie returned only {unique_count} unique value(s). "
                f"Either the application reuses the same session ID "
                f"across users, or the endpoint isn't actually minting "
                f"a fresh session."
            ),
            description_plain=(
                "Your server returned the SAME session cookie for "
                "every login attempt — sessions are not isolated "
                "between users. Any user logging in receives the "
                "same session value, which means an attacker who "
                "harvests one session ID has access to every "
                "logged-in user's account."
            ),
            recommended_action=(
                "Mint a fresh session ID per login using a CSPRNG: "
                "`secrets.token_urlsafe(32)` in Python, "
                "`crypto/rand` in Go, `SecureRandom` in Java. "
                "Bind the session record to the user, store server-"
                "side, and rotate the ID on privilege escalation. "
                "Never derive session IDs from user IDs / "
                "timestamps / sequential counters."
            ),
        )
        _complete_check(cev, "vulnerable", "constant cookie value")
        return {
            "success": True,
            "target_url": target_url if cookie_values is None else None,
            "cookie_name": cookie_name,
            "samples_requested": samples_requested,
            "samples_collected": len(cookies),
            "unique_count": unique_count,
            "analyses": analyses,
            "findings_emitted": 1,
        }

    # Shannon entropy (per-cookie average + min).
    entropies = [_shannon_entropy_bits(v) for v in cookies]
    analyses["shannon_entropy_avg_bits"] = sum(entropies) / len(entropies)
    analyses["shannon_entropy_min_bits"] = min(entropies)

    # Alphabet detection + χ² bias.
    alphabet_label, alphabet_chars = _detect_alphabet(cookies)
    analyses["alphabet"] = alphabet_label
    chi2, chi2_p = _chi_squared(cookies, alphabet_chars)
    analyses["chi_squared"] = chi2
    analyses["chi_squared_p_value"] = chi2_p

    # Sequential-counter detection.
    seq_detected, seq_evidence = _detect_sequential_counter(cookies)
    analyses["sequential_counter"] = {
        "detected": seq_detected, "evidence": seq_evidence,
    }

    # NIST mini-tests — bit stream encoded by alphabet index when
    # possible, so we measure encoded entropy rather than structural
    # ASCII high-bit bias.
    bits = _bit_stream(cookies, alphabet_chars)
    freq_passed, freq_proportion = _frequency_test(bits)
    runs_passed, runs_count = _runs_test(bits)
    long_passed, long_value = _longest_run_test(bits)
    analyses["nist"] = {
        "frequency": {"passed": freq_passed, "proportion": freq_proportion},
        "runs": {"passed": runs_passed, "run_count": runs_count},
        "longest_run": {"passed": long_passed, "longest_run": long_value},
    }
    nist_failures = sum(1 for p in (freq_passed, runs_passed, long_passed) if not p)

    findings_emitted = 0

    # Sequential counter → high.
    if seq_detected:
        _emit_finding(
            title=f"Session cookie {cookie_name!r} is a sequential counter on {target_host}",
            severity="high",
            target=target_host,
            endpoint=endpoint,
            description=(
                f"Across {len(cookies)} samples, the cookie values "
                f"decode to a monotonically-increasing integer "
                f"sequence. {seq_evidence}."
            ),
            description_plain=(
                "Your session cookies are sequential — each user's "
                "session ID is just the previous user's plus a "
                "small constant. An attacker who logs in and "
                "observes their own session ID can predict every "
                "other user's session ID. This is a complete "
                "session-prediction primitive."
            ),
            recommended_action=(
                "Replace the sequential session-ID generator with a "
                "CSPRNG-backed one: `secrets.token_urlsafe(32)` in "
                "Python (224 bits), `crypto/rand` in Go, "
                "`SecureRandom.getInstance(\"NativePRNG\")` in Java. "
                "Use at least 128 bits. The session record can keep "
                "an internal sequential ID for joins / queries; the "
                "ID exposed to the client must be CSPRNG-random."
            ),
        )
        findings_emitted += 1

    avg_entropy = analyses["shannon_entropy_avg_bits"]
    if avg_entropy < 32:
        _emit_finding(
            title=f"Session cookie {cookie_name!r} has very low entropy ({avg_entropy:.1f} bits) on {target_host}",
            severity="high",
            target=target_host,
            endpoint=endpoint,
            description=(
                f"Average per-cookie Shannon entropy across {len(cookies)} "
                f"samples is {avg_entropy:.1f} bits. Modern session "
                f"IDs require ≥ 64 bits; ≥ 128 bits is recommended."
            ),
            description_plain=(
                "Your session cookies don't have enough randomness. "
                "An attacker can brute-force the session-ID space "
                "in seconds. This is the same risk class as a 32-bit "
                "password."
            ),
            recommended_action=(
                "Use a CSPRNG to mint at least 128 bits of session "
                "ID material. In Python: "
                "`secrets.token_urlsafe(32)` (32 bytes = 256 bits). "
                "In Go: `crypto/rand` + `base64.URLEncoding`. In "
                "Java: `SecureRandom.getInstance(\"NativePRNG\")` + "
                "`Base64.getUrlEncoder()`."
            ),
        )
        findings_emitted += 1
    elif avg_entropy < 64:
        _emit_finding(
            title=f"Session cookie {cookie_name!r} has low entropy ({avg_entropy:.1f} bits) on {target_host}",
            severity="medium",
            target=target_host,
            endpoint=endpoint,
            description=(
                f"Average per-cookie Shannon entropy is {avg_entropy:.1f} "
                f"bits; recommended minimum is 64 bits, target is 128."
            ),
            description_plain=(
                "Your session cookies have less randomness than the "
                "modern minimum. An attacker can't brute-force the "
                "space in seconds, but a determined attack with "
                "modest compute can. Treat as a medium-priority "
                "weakness; rotate the session generator."
            ),
            recommended_action=(
                "Use at least 128 bits of CSPRNG-backed session ID. "
                "`secrets.token_urlsafe(32)` (Python), `crypto/rand` "
                "(Go), `SecureRandom` (Java)."
            ),
        )
        findings_emitted += 1
    elif avg_entropy < 80:
        _emit_finding(
            title=f"Session cookie {cookie_name!r} has marginal entropy ({avg_entropy:.1f} bits) on {target_host}",
            severity="low",
            target=target_host,
            endpoint=endpoint,
            description=(
                f"Average per-cookie Shannon entropy is {avg_entropy:.1f} "
                f"bits — above the strict minimum of 64, but below the "
                f"128-bit target for production session IDs."
            ),
            description_plain=(
                "Your session cookies are above the bare-minimum "
                "entropy threshold but below the modern target of "
                "128 bits. Bump the generator's output length to "
                "reach 128+ bits as a defense-in-depth."
            ),
            recommended_action=(
                "Increase the session ID length so that each cookie "
                "carries ≥ 128 bits of entropy."
            ),
        )
        findings_emitted += 1

    # χ² bias OR NIST failures → medium (only if not already
    # over-shadowed by a higher-severity entropy finding).
    if (chi2_p < 0.001 or nist_failures > 0) and avg_entropy >= 64:
        details = []
        if chi2_p < 0.001:
            details.append(f"χ² = {chi2:.1f} (p < 0.001) — non-uniform alphabet")
        if not freq_passed:
            details.append(f"NIST frequency failed (proportion {freq_proportion:.3f})")
        if not runs_passed:
            details.append(f"NIST runs failed (run_count {runs_count})")
        if not long_passed:
            details.append(f"NIST longest-run failed (run length {long_value})")
        _emit_finding(
            title=f"Session cookie {cookie_name!r} has biased distribution on {target_host}",
            severity="medium",
            target=target_host,
            endpoint=endpoint,
            description=(
                f"Across {len(cookies)} samples ({analyses['alphabet']} "
                f"alphabet), bias detected: {'; '.join(details)}."
            ),
            description_plain=(
                "Your session cookies look random at first glance "
                "but a statistical analysis shows bias: certain "
                "characters or bit positions are more common than "
                "uniform-random output would produce. Likely cause: "
                "the generator is mixing in time-based or counter "
                "values, OR encoding fewer bits than the cookie "
                "string suggests."
            ),
            recommended_action=(
                "Audit the session-ID generator. Replace with a "
                "CSPRNG output that's directly base64-URL-encoded "
                "(no string formatting / templating that injects "
                "structure)."
            ),
        )
        findings_emitted += 1

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=(
            f"{findings_emitted} session-entropy finding(s); avg entropy "
            f"{avg_entropy:.1f} bits; sequential={seq_detected}"
        ),
    )

    return {
        "success": True,
        "target_url": target_url if cookie_values is None else None,
        "cookie_name": cookie_name,
        "samples_requested": samples_requested,
        "samples_collected": len(cookies),
        "unique_count": unique_count,
        "analyses": analyses,
        "findings_emitted": findings_emitted,
    }


def _normalize_target(target: str) -> str | None:
    if not target or not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return None
    if not parsed.netloc:
        return None
    return target
