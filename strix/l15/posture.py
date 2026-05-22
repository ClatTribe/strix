"""iter-25.4 — defensive-posture awareness (Gap 10 in docs/L2-optimization.md).

Before any L1.5 amplify call or L2 specialist dispatch fires deterministic
payloads at the target, we need to know:

  1. Is there a WAF in front? (Cloudflare / Akamai / AWS WAF / Imperva / ...)
  2. What's the rate-limit ceiling? (3 rps? 30? 300?)
  3. Is there a CDN we should look behind for the origin?

Without this, the probe-bundle bursts in Wave 4 will blacklist the
scanner IP on the first Cloudflare-fronted target. With this, every
amplify call routes through the SecurityPosture and switches to
stealth mode when needed.

This module owns:
  * `SecurityPosture` dataclass — the immutable record of what we
    found about the target's defensive layer.
  * `probe_defensive_posture(target_url)` — runs the deterministic
    checks (wafw00f wrap + quick rate-limit burst + CDN cname walk)
    and returns a SecurityPosture.
  * `get_posture(target_url)` / `set_posture(...)` — process-local
    cache so subsequent amplify calls don't re-probe.

The probe itself is recall-safe: any internal error returns a
``SecurityPosture(stealth_mode_required=False, ...)`` default. We
default to NON-stealth so a probe failure doesn't silently neuter the
scan; a real engineer would prefer "we couldn't measure, fire at full
speed" over "we couldn't measure, do nothing".

When you DO want safe-by-default behaviour (e.g. paid customer
scanning their own production target), pass ``conservative=True`` to
`probe_defensive_posture` — failure then returns
``stealth_mode_required=True`` instead.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess  # noqa: S404
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


_DEFAULT_RPS_PROBE_TIMEOUT_S = 6
_RPS_PROBE_BURST = 8  # send N requests in quick succession
_WAFW00F_TIMEOUT_S = 30


@dataclass(frozen=True)
class SecurityPosture:
    """Snapshot of the target's defensive layer.

    Fields are all derived deterministically; no LLM. Whenever a new
    L1.5 amplify call (or L2 specialist dispatch) is about to fire,
    the orchestrator reads this and adjusts:

      * concurrency cap = ``max(1, rate_limit_rps // 2)``
      * payload set = stealth variants if ``stealth_mode_required``
      * target host = ``origin_candidates[0]`` if present (bypass
        CDN to hit the origin directly)
    """
    target: str
    waf_detected: bool = False
    waf_vendor: str | None = None
    rate_limit_rps: int | None = None
    cdn_detected: bool = False
    origin_candidates: tuple[str, ...] = ()
    stealth_mode_required: bool = False
    measurement_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "waf_detected": self.waf_detected,
            "waf_vendor": self.waf_vendor,
            "rate_limit_rps": self.rate_limit_rps,
            "cdn_detected": self.cdn_detected,
            "origin_candidates": list(self.origin_candidates),
            "stealth_mode_required": self.stealth_mode_required,
            "measurement_error": self.measurement_error,
        }


# ---------------- WAF detection ----------------

# Header signatures — cheap pre-check before shelling out to wafw00f.
# Order matters: more specific matches first.
_WAF_HEADER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    # (header_name, substring, vendor_label)
    ("server", "cloudflare", "cloudflare"),
    ("cf-ray", "", "cloudflare"),
    ("server", "akamai", "akamai"),
    ("x-akamai-transformed", "", "akamai"),
    ("x-amzn-waf-action", "", "aws_waf"),
    ("x-amz-cf-id", "", "cloudfront"),
    ("x-cdn", "imperva", "imperva"),
    ("x-iinfo", "", "imperva"),
    ("x-sucuri-id", "", "sucuri"),
    ("server", "barracuda", "barracuda"),
    ("server", "f5", "f5_bigip"),
    ("x-cdn", "fastly", "fastly"),
    ("server", "fastly", "fastly"),
    ("x-served-by", "fastly", "fastly"),
    ("x-fortinet-banner", "", "fortinet"),
    ("server", "varnish", "varnish"),  # not a WAF strictly, but caches matter
)

_CDN_VENDORS = {
    "cloudflare", "akamai", "cloudfront", "fastly", "sucuri",
}


def _check_waf_via_headers(headers: dict[str, str]) -> tuple[bool, str | None, bool]:
    """Cheap WAF/CDN sniff from response headers.

    Returns (waf_detected, vendor, is_cdn).
    """
    lowered = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    for name, substr, vendor in _WAF_HEADER_SIGNATURES:
        v = lowered.get(name.lower())
        if v is None:
            continue
        if substr and substr not in v:
            continue
        return True, vendor, vendor in _CDN_VENDORS
    return False, None, False


def _wafw00f_available() -> bool:
    if os.environ.get(
        "STRIX_WAFW00F_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which("wafw00f") is not None


def _check_waf_via_wafw00f(target: str) -> tuple[bool, str | None]:
    """Shell out to wafw00f for a positive ID.

    Only fires if the header check came up empty AND the binary is
    available. wafw00f is in /opt/pipx/venvs/wafw00f/bin/ via the
    Dockerfile pipx install (line 146 of containers/Dockerfile).
    """
    if not _wafw00f_available():
        return False, None
    try:
        result = subprocess.run(  # noqa: S603
            ["wafw00f", "-a", "-o", "-", target],
            check=False, capture_output=True,
            text=True, timeout=_WAFW00F_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.debug("wafw00f invocation failed: %s", e)
        return False, None
    stdout = (result.stdout or "").lower()
    if "is behind " in stdout or "detected" in stdout:
        # Try to pull the vendor name out of the stdout.
        # wafw00f's format: "[+] The site ... is behind <vendor> ..."
        for vendor in (
            "cloudflare", "akamai", "imperva", "incapsula",
            "aws", "fastly", "sucuri", "f5", "barracuda",
            "fortinet", "wordfence", "modsecurity",
        ):
            if vendor in stdout:
                return True, vendor
        return True, "unknown"
    return False, None


# ---------------- Rate-limit probe ----------------

def _measure_rate_limit_rps(target: str) -> int | None:
    """Fire a quick burst and observe whether the server applies 429s.

    Strategy: send ``_RPS_PROBE_BURST`` HEAD requests as fast as
    httpx allows. Measure elapsed wall time. If we see a 429 / 503 /
    Retry-After in any response, lower the ceiling. Otherwise the
    measured RPS is the ceiling.

    Best-effort. Returns ``None`` on any network error so the caller
    treats RPS as "unknown" rather than "infinite".
    """
    try:
        import httpx  # noqa: PLC0415
    except ImportError:
        logger.debug("httpx not importable; skipping rate-limit probe")
        return None

    start = time.monotonic()
    saw_throttle = False
    successful = 0
    try:
        with httpx.Client(
            timeout=_DEFAULT_RPS_PROBE_TIMEOUT_S,
            follow_redirects=False,
            verify=False,  # noqa: S501 — probe, not auth
        ) as client:
            for _ in range(_RPS_PROBE_BURST):
                try:
                    resp = client.head(target)
                except (httpx.RequestError, OSError):
                    continue
                successful += 1
                if resp.status_code in (429, 503):
                    saw_throttle = True
                    break
                if resp.headers.get("Retry-After"):
                    saw_throttle = True
                    break
    except Exception as e:  # noqa: BLE001
        logger.debug("rate-limit probe failed: %s", e)
        return None

    elapsed = max(0.01, time.monotonic() - start)
    if successful == 0:
        return None
    if saw_throttle:
        # We hit the ceiling — calibrate to a conservative
        # fraction of the observed RPS.
        observed = successful / elapsed
        return max(1, int(observed * 0.3))
    # Didn't see a throttle in the burst. Return the observed RPS as
    # the *lower bound* (the actual ceiling is higher; the caller
    # should treat this as "≥ this many RPS").
    return max(1, int(successful / elapsed))


# ---------------- CDN / origin discovery ----------------

def _discover_origin_candidates(host: str) -> tuple[str, ...]:
    """Walk the CNAME chain to find a candidate origin.

    Defensive: a CDN-fronted host usually CNAMEs to the CDN domain.
    The eventual A-record is the CDN's IP. To find the origin we'd
    need DNS history (passive DNS), which we don't ship yet — leave
    this as a stub returning the resolved A-records (which are the
    CDN IPs in the common case) plus any subdomain that has
    ``origin``/``backend``/``api-internal`` in its name.

    Future iters: integrate dnsdb/SecurityTrails passive DNS.
    """
    candidates: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({info[4][0] for info in infos})
        candidates.extend(ips)
    except (socket.gaierror, OSError):
        pass
    return tuple(candidates)


# ---------------- Public API ----------------

_lock = threading.RLock()
_posture_cache: dict[str, SecurityPosture] = {}


def probe_defensive_posture(
    target_url: str,
    *,
    conservative: bool = False,
) -> SecurityPosture:
    """Run all defensive-posture checks against the target.

    Args:
        target_url: full URL or bare host. We normalise to a URL.
        conservative: when True, an internal failure returns
            ``stealth_mode_required=True``. When False (default), a
            failure returns ``stealth_mode_required=False`` so a
            measurement glitch doesn't silently neuter the scan.

    Returns:
        ``SecurityPosture`` dataclass.
    """
    target = target_url.strip()
    if not target:
        return SecurityPosture(
            target="", measurement_error="empty target",
            stealth_mode_required=conservative,
        )

    if "://" not in target:
        target = "http://" + target

    try:
        parsed = urlparse(target)
        host = parsed.hostname or target
    except Exception:  # noqa: BLE001
        host = target

    waf_detected = False
    waf_vendor: str | None = None
    cdn_detected = False
    measurement_error: str | None = None

    # 1) Cheap header-based WAF / CDN check via httpx.
    try:
        import httpx  # noqa: PLC0415
        with httpx.Client(
            timeout=_DEFAULT_RPS_PROBE_TIMEOUT_S,
            follow_redirects=False,
            verify=False,  # noqa: S501
        ) as client:
            r = client.head(target)
            hdrs = dict(r.headers)
        waf_detected, waf_vendor, cdn_detected = _check_waf_via_headers(hdrs)
    except Exception as e:  # noqa: BLE001
        measurement_error = f"header-probe-failed: {type(e).__name__}"

    # 2) If header check empty, try wafw00f for positive ID.
    if not waf_detected:
        wafw00f_detected, wafw00f_vendor = _check_waf_via_wafw00f(target)
        if wafw00f_detected:
            waf_detected = True
            waf_vendor = wafw00f_vendor
            if wafw00f_vendor in _CDN_VENDORS:
                cdn_detected = True

    # 3) Rate-limit probe.
    rps = _measure_rate_limit_rps(target)

    # 4) Origin candidates (only meaningful if CDN detected).
    origins: tuple[str, ...] = ()
    if cdn_detected:
        origins = _discover_origin_candidates(host)

    stealth_required = waf_detected or bool(
        rps is not None and rps < 5
    )

    posture = SecurityPosture(
        target=target,
        waf_detected=waf_detected,
        waf_vendor=waf_vendor,
        rate_limit_rps=rps,
        cdn_detected=cdn_detected,
        origin_candidates=origins,
        stealth_mode_required=stealth_required,
        measurement_error=measurement_error,
    )
    with _lock:
        _posture_cache[target] = posture
        # Also cache by bare host for convenience.
        if host and host != target:
            _posture_cache[host] = posture
    return posture


def get_posture(target_url: str) -> SecurityPosture | None:
    """Return the cached posture for a target, or None if not yet probed."""
    if not target_url:
        return None
    t = target_url.strip()
    if "://" not in t:
        t_url = "http://" + t
    else:
        t_url = t
    with _lock:
        return _posture_cache.get(t_url) or _posture_cache.get(t)


def set_posture(posture: SecurityPosture) -> None:
    """Manually inject a posture (used by tests + by the bench harness)."""
    with _lock:
        _posture_cache[posture.target] = posture


def clear_cache() -> None:
    """Wipe the posture cache. Tests use this between cases."""
    with _lock:
        _posture_cache.clear()


def stealth_required(target_url: str) -> bool:
    """Convenience: is stealth mode required for this target?

    Returns False if we haven't probed yet (caller probably wants to
    call ``probe_defensive_posture`` first).
    """
    p = get_posture(target_url)
    return bool(p and p.stealth_mode_required)


def rate_limit_cap(target_url: str, default: int = 30) -> int:
    """Convenience: concurrent-RPS ceiling for amplify calls.

    Returns ``default`` when we haven't probed or the probe didn't
    produce a measurement.
    """
    p = get_posture(target_url)
    if p is None or p.rate_limit_rps is None:
        return default
    return max(1, p.rate_limit_rps // 2)
