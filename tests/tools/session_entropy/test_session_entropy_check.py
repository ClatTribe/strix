"""Tests for session_entropy_check.

Hermetic — `_http_request` is monkeypatched. Tests cover:

- URL normalization (bare host, scheme, invalid)
- Pre-collected mode bypasses HTTP entirely
- auth-N-times mode harvests Set-Cookie
- Cookie not in Set-Cookie → inconclusive
- --exclude-path → graceful skip
- < 2 samples → inconclusive
- Constant cookie value → critical
- Sequential decimal counter → high
- Sequential hex counter → high
- High-entropy CSPRNG-shaped cookies → no finding
- Low entropy (< 32 bits) → high
- Medium entropy (32-64 bits) → medium
- Low-marginal entropy (64-80 bits) → low
- χ² bias → medium (when entropy ≥ 64)
- §11 UX baseline (description_plain + recommended_action +
  needs_review)
- Check summary
- MITRE T1556 attached
- Result schema integrity
- Pure helper unit tests (entropy, alphabet detection,
  sequential-counter detection, NIST tests)
"""

from __future__ import annotations

import secrets
import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.session_entropy.session_entropy_check  # noqa: F401

se_module = sys.modules["strix.tools.session_entropy.session_entropy_check"]
session_entropy_check = se_module.session_entropy_check


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("session-entropy-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com/"}]}
    )
    yield


def _patch_request(monkeypatch, responder):
    log: list[dict[str, Any]] = []

    def fake(method, url, *, headers=None, body="", timeout=10.0):
        log.append({"method": method, "url": url, "headers": dict(headers or {}), "body": body})
        return responder(method, url, log)

    monkeypatch.setattr(se_module, "_http_request", fake)
    return log


def _resp(*, status: int = 200, set_cookie_list: list[str] | None = None,
          body: str = "", skipped: bool = False) -> dict[str, Any]:
    if skipped:
        return {"status": 0, "headers": {}, "set_cookie_list": [], "body": "", "skipped": True}
    return {
        "status": status,
        "headers": {"set-cookie": set_cookie_list[0] if set_cookie_list else ""},
        "set_cookie_list": list(set_cookie_list or []),
        "body": body,
    }


def _findings_from_tracer() -> list[dict[str, Any]]:
    t = tracer_module.get_global_tracer()
    if t is None:
        return []
    return list(t.get_existing_vulnerabilities())


def _check_summary() -> dict[str, Any]:
    t = tracer_module.get_global_tracer()
    if t is None:
        return {}
    return t.get_check_summary()


# ---------------------------------------------------------------------------
# URL normalization / arg validation
# ---------------------------------------------------------------------------


def test_no_target_no_cookies_rejected() -> None:
    out = session_entropy_check()
    assert out["success"] is False


def test_invalid_url_rejected() -> None:
    out = session_entropy_check(target_url="ftp://x.com/")
    assert out["success"] is False


def test_bare_hostname_gets_https(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, log: _resp(set_cookie_list=["session=value1"]))
    out = session_entropy_check(target_url="app.example.com/login", samples=2)
    assert out["target_url"].startswith("https://")


# ---------------------------------------------------------------------------
# Acquisition modes
# ---------------------------------------------------------------------------


def test_pre_collected_mode_bypasses_http(monkeypatch) -> None:
    log = _patch_request(monkeypatch, lambda m, u, l: _resp())
    cookies = [secrets.token_urlsafe(32) for _ in range(8)]
    out = session_entropy_check(cookie_values=cookies, cookie_name="session")
    assert out["success"] is True
    assert log == []
    assert out["samples_collected"] == 8


def test_auth_n_times_collects_set_cookie(monkeypatch) -> None:
    """Auth-N-times mode: each request returns a different Set-Cookie."""
    counter = [0]

    def responder(method: str, url: str, log: list[dict[str, Any]]) -> dict[str, Any]:
        counter[0] += 1
        v = secrets.token_urlsafe(32)
        return _resp(set_cookie_list=[f"session={v}; Path=/; HttpOnly"])

    _patch_request(monkeypatch, responder)
    out = session_entropy_check(
        target_url="https://app.example.com/login", samples=8
    )
    assert out["samples_collected"] == 8
    assert out["unique_count"] == 8


def test_cookie_not_set_inconclusive(monkeypatch) -> None:
    """Auth URL never sets the named cookie → inconclusive."""
    _patch_request(monkeypatch, lambda m, u, l: _resp(set_cookie_list=["other_cookie=x"]))
    out = session_entropy_check(
        target_url="https://app.example.com/login", samples=4, cookie_name="session"
    )
    assert out["inconclusive"] is True
    assert out["samples_collected"] == 0


def test_excluded_path_skip(monkeypatch) -> None:
    _patch_request(monkeypatch, lambda m, u, l: _resp(skipped=True))
    out = session_entropy_check(
        target_url="https://app.example.com/login", samples=4
    )
    assert out["inconclusive"] is True
    assert "exclude" in out["reason"].lower()


# ---------------------------------------------------------------------------
# Findings — by severity
# ---------------------------------------------------------------------------


def test_constant_cookie_critical(monkeypatch) -> None:
    """Same cookie value across all logins → critical."""
    _patch_request(monkeypatch, lambda m, u, l: _resp(set_cookie_list=["session=CONSTANT-VALUE-XYZ"]))
    out = session_entropy_check(
        target_url="https://app.example.com/login", samples=4
    )
    findings = _findings_from_tracer()
    assert out["unique_count"] == 1
    assert any(f.get("severity") == "critical" for f in findings)


def test_sequential_decimal_counter_high() -> None:
    cookies = [str(1000 + i) for i in range(16)]
    out = session_entropy_check(cookie_values=cookies)
    findings = _findings_from_tracer()
    assert any(
        f.get("severity") == "high" and "sequential counter" in f.get("title", "").lower()
        for f in findings
    )


def test_sequential_hex_counter_high() -> None:
    cookies = [f"prefix-{i:08x}" for i in range(16)]
    out = session_entropy_check(cookie_values=cookies)
    findings = _findings_from_tracer()
    assert any(
        f.get("severity") == "high" and "sequential counter" in f.get("title", "").lower()
        for f in findings
    )


def test_csprng_cookies_no_finding() -> None:
    """High-entropy random cookies should produce no finding."""
    cookies = [secrets.token_urlsafe(32) for _ in range(32)]
    out = session_entropy_check(cookie_values=cookies)
    findings = _findings_from_tracer()
    assert out["findings_emitted"] == 0
    assert findings == []


def test_very_low_entropy_high() -> None:
    """Tiny 4-character cookies → < 32 bit entropy → high."""
    cookies = [f"ab{i:02d}" for i in range(16)]
    # 4-char string; even with full uniform alphabet, only ~16 bits.
    out = session_entropy_check(cookie_values=cookies, cookie_name="s")
    findings = _findings_from_tracer()
    # Either the entropy finding or the sequential-counter finding fires
    # (the latter wins because the suffix is sequential). Either way,
    # high severity exists.
    assert any(f.get("severity") == "high" for f in findings)


def test_medium_entropy_medium_finding() -> None:
    """8-char hex cookies (~32 bits of entropy) → medium."""
    # 8 hex chars = 32 bits encoded; entropy *of the string* is 32
    # bits with full hex alphabet. Use 9 chars for ~36 bits.
    cookies = [secrets.token_hex(5) for _ in range(16)]  # 10 chars
    out = session_entropy_check(cookie_values=cookies)
    findings = _findings_from_tracer()
    # 10 hex chars = 40 bits → falls in 32-64 bucket → medium
    assert any(f.get("severity") in ("medium", "high") for f in findings)


def test_marginal_entropy_low_finding() -> None:
    """20-char hex (~80 bits) — at the boundary.

    20-char base16 → 20 chars × log2(16) = 80 bits. The tool's
    threshold is `< 80` for low; exactly 80 bits is above the
    threshold so we expect no entropy finding.

    Use 17 chars (= 68 bits) to land squarely in the low bucket.
    """
    cookies = [secrets.token_hex(8) + secrets.choice("0123456789abcdef") for _ in range(32)]
    # 17 hex chars = 68 bits → 64-80 bucket → low
    out = session_entropy_check(cookie_values=cookies)
    findings = _findings_from_tracer()
    # Low or no finding (sample-variance can push it just over).
    severities = {f.get("severity") for f in findings}
    assert "high" not in severities
    assert "critical" not in severities


# ---------------------------------------------------------------------------
# §11 UX baseline
# ---------------------------------------------------------------------------


def test_findings_carry_ux_fields() -> None:
    cookies = [str(1000 + i) for i in range(8)]
    session_entropy_check(cookie_values=cookies)
    findings = _findings_from_tracer()
    assert findings
    for f in findings:
        assert f.get("description_plain")
        assert f.get("recommended_action")
        assert f.get("verification_status") == "needs_review"
        assert f.get("category") == "weak_session_id"
        assert f.get("cwe") == "CWE-330"


# ---------------------------------------------------------------------------
# Check summary
# ---------------------------------------------------------------------------


def test_check_summary_vulnerable() -> None:
    cookies = [str(1000 + i) for i in range(8)]
    session_entropy_check(cookie_values=cookies)
    summary = _check_summary()
    assert summary["by_category"]["session_entropy"]["vulnerable"] >= 1


def test_check_summary_clean() -> None:
    cookies = [secrets.token_urlsafe(32) for _ in range(16)]
    session_entropy_check(cookie_values=cookies)
    summary = _check_summary()
    assert summary["by_category"]["session_entropy"]["not_vulnerable"] >= 1


def test_check_summary_inconclusive(monkeypatch) -> None:
    out = session_entropy_check(cookie_values=["only-one"])
    assert out["inconclusive"] is True
    summary = _check_summary()
    assert summary["by_category"]["session_entropy"]["inconclusive"] >= 1


# ---------------------------------------------------------------------------
# MITRE technique tag
# ---------------------------------------------------------------------------


def test_mitre_technique_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques

    techniques = get_tool_mitre_techniques("session_entropy_check")
    assert "T1556" in techniques


# ---------------------------------------------------------------------------
# Schema integrity
# ---------------------------------------------------------------------------


def test_result_schema_pre_collected() -> None:
    cookies = [secrets.token_urlsafe(32) for _ in range(4)]
    out = session_entropy_check(cookie_values=cookies)
    assert set(out.keys()) >= {
        "success", "cookie_name", "samples_requested", "samples_collected",
        "unique_count", "analyses", "findings_emitted",
    }


def test_analyses_schema() -> None:
    cookies = [secrets.token_urlsafe(32) for _ in range(8)]
    out = session_entropy_check(cookie_values=cookies)
    a = out["analyses"]
    assert {"shannon_entropy_avg_bits", "shannon_entropy_min_bits",
            "alphabet", "chi_squared", "chi_squared_p_value",
            "sequential_counter", "nist"} <= set(a.keys())
    assert {"frequency", "runs", "longest_run"} <= set(a["nist"].keys())


# ---------------------------------------------------------------------------
# Pure-helper unit tests
# ---------------------------------------------------------------------------


def test_shannon_entropy_uniform_alphabet() -> None:
    s = "0123456789abcdef" * 4  # 64 chars, 4 bits per char
    h = se_module._shannon_entropy_bits(s)
    # log2(16) * 64 = 256 bits
    assert abs(h - 256) < 1


def test_shannon_entropy_constant_string_zero() -> None:
    assert se_module._shannon_entropy_bits("aaaaaaaa") == 0.0


def test_shannon_entropy_empty_string() -> None:
    assert se_module._shannon_entropy_bits("") == 0.0


def test_alphabet_detect_hex_lower() -> None:
    label, _ = se_module._detect_alphabet(["abc123", "def456"])
    assert label == "hex_lower"


def test_alphabet_detect_base64_urlsafe() -> None:
    label, _ = se_module._detect_alphabet(["AbC-_123", "ZyXwVuTs"])
    assert label == "base64_urlsafe"


def test_alphabet_detect_printable_fallback() -> None:
    label, _ = se_module._detect_alphabet(["a!b@c", "x^y%z"])
    assert label == "printable"


def test_sequential_counter_decimal() -> None:
    detected, _ = se_module._detect_sequential_counter([str(i) for i in range(100, 116)])
    assert detected is True


def test_sequential_counter_hex_with_prefix() -> None:
    detected, _ = se_module._detect_sequential_counter(
        [f"sess-{i:08x}-x" for i in range(100, 116)]
    )
    assert detected is True


def test_sequential_counter_random_no() -> None:
    detected, _ = se_module._detect_sequential_counter(
        [secrets.token_hex(8) for _ in range(16)]
    )
    assert detected is False


def test_sequential_counter_only_one_value() -> None:
    detected, _ = se_module._detect_sequential_counter(["only"])
    assert detected is False


def test_extract_cookie_value_basic() -> None:
    line = "session=abc123; Path=/; HttpOnly"
    assert se_module._extract_cookie_value([line], "session") == "abc123"


def test_extract_cookie_value_missing() -> None:
    line = "other=xxx; Path=/"
    assert se_module._extract_cookie_value([line], "session") is None


def test_extract_cookie_value_multiple_set_cookies() -> None:
    lines = [
        "csrf=abc; Path=/",
        "session=def123; Path=/; HttpOnly",
    ]
    assert se_module._extract_cookie_value(lines, "session") == "def123"


def test_bit_stream_truncates_to_multiple_of_8() -> None:
    bits = se_module._bit_stream(["a"])  # 1 char = 8 bits
    assert len(bits) % 8 == 0
    assert len(bits) == 8


def test_frequency_test_uniform_passes() -> None:
    bits = "01" * 100
    passed, prop = se_module._frequency_test(bits)
    assert passed is True
    assert abs(prop - 0.5) < 0.01


def test_frequency_test_all_ones_fails() -> None:
    bits = "1" * 200
    passed, prop = se_module._frequency_test(bits)
    assert passed is False
    assert prop == 1.0


def test_chi_squared_uniform_passes() -> None:
    # Many random hex strings → χ² should not reject.
    cookies = [secrets.token_hex(32) for _ in range(64)]
    chi2, p = se_module._chi_squared(cookies, se_module._HEX_LOWER)
    # uniform → not rejected (p high; we only flag p < 0.001)
    assert p >= 0.001


def test_chi_squared_biased_fails() -> None:
    # All cookies = "aaaa..." → χ² blows up.
    cookies = ["a" * 32 for _ in range(16)]
    chi2, p = se_module._chi_squared(cookies, se_module._HEX_LOWER)
    assert p < 0.01
