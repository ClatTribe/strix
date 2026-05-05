"""Tests for the §8.5 Phase 0.A sanitiser fix — token-count keys
must NOT be redacted (incident #147 suggestion 5).

Pins the new `_TOKEN_COUNT_KEY_PATTERN` allow-list so a future
sanitiser change can't quietly re-redact `cached_tokens` /
`input_tokens` and break cost-bisection telemetry.
"""

from __future__ import annotations

import pytest

from strix.telemetry.utils import TelemetrySanitizer


# ---------------------------------------------------------------------------
# Token-count keys are exempt from sensitive-key redaction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key,value",
    [
        ("input_tokens", 50_000),
        ("output_tokens", 1_500),
        ("cached_tokens", 30_000),
        ("prompt_tokens", 50_000),
        ("completion_tokens", 1_500),
        ("reasoning_tokens", 500),
        ("system_tokens", 50_000),                    # §8.5 Phase 0.A
        ("agent_identity_tokens", 100),                # §8.5 Phase 0.A
        ("conversation_tokens", 20_000),               # §8.5 Phase 0.A
        ("total_input_tokens_estimated", 70_100),     # §8.5 Phase 0.A
        ("measured_input_tokens", 71_000),            # §8.5 Phase 0.A
        ("measured_cached_tokens", 40_000),           # §8.5 Phase 0.A
        ("tokens_consumed", 100_000),                  # run_budget #113
        ("tokens_remaining", 50_000),                  # run_budget #113
        ("tokens_cap", 200_000),                       # run_budget #113
        ("token_count", 1_234),
    ],
)
def test_token_count_keys_pass_through_numeric(key: str, value: int) -> None:
    s = TelemetrySanitizer()
    out = s.sanitize({key: value})
    assert out[key] == value, f"key {key!r} was incorrectly redacted"


# ---------------------------------------------------------------------------
# Real credential keys still get redacted (regression guard)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key,value",
    [
        ("auth_token", "Bearer abc123"),
        ("api_token", "sk-secret"),
        ("api_key", "k-12345"),
        ("bearer_token", "xyz"),
        ("password", "hunter2"),
        ("authorization", "Bearer foo"),
        ("session_token", "session-abc"),
        ("credential", "creds-blob"),
        ("private_key", "-----BEGIN..."),
    ],
)
def test_credential_keys_still_redacted(key: str, value: str) -> None:
    s = TelemetrySanitizer()
    out = s.sanitize({key: value})
    assert out[key] == "[REDACTED]", (
        f"key {key!r} should still be redacted but got {out[key]!r}"
    )


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_nested_token_count_keys_pass_through() -> None:
    """Nested dicts: the recursive sanitise call must also exempt
    token-count keys at every level."""
    s = TelemetrySanitizer()
    out = s.sanitize({
        "cumulative": {
            "input_tokens": 100_000,
            "cached_tokens": 70_000,
            "cost": 0.42,
        },
    })
    assert out["cumulative"]["input_tokens"] == 100_000
    assert out["cumulative"]["cached_tokens"] == 70_000


def test_token_count_keys_with_string_values_still_pass_through() -> None:
    """When a token-count key happens to carry a string (e.g. error
    message), the value still passes through scrubadub but not the
    sensitive-key guard. This is the path that broke in incident #147
    suggestion 5: `consumed.cached_tokens` was passed as int but
    redacted because the key matched 'token'."""
    s = TelemetrySanitizer()
    out = s.sanitize({"input_tokens": "1234"})  # string-typed but count semantic
    # Either passes through ("1234") or scrubadub-cleaned. Must NOT be [REDACTED].
    assert out["input_tokens"] != "[REDACTED]"


def test_screenshot_key_still_redacted() -> None:
    """Don't accidentally widen the exemption to screenshot keys."""
    s = TelemetrySanitizer()
    out = s.sanitize({"screenshot_data": "base64-blob..."})
    assert out["screenshot_data"] != "base64-blob..."  # still redacted
