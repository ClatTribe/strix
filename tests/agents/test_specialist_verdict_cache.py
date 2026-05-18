"""Tests for `strix/agents/specialist_verdict_cache.py`.

Step 2 of the v2 cost-optimization plan (workflow phase 4 —
specialist dispatch). The cache stores negative-verdict BLOCKED
results keyed on `(category, endpoint_shape, auth_state)` and
short-circuits subsequent dispatches on structurally similar
endpoints.

Recall-safety contract pinned by these tests:
  * PASSED results NEVER enter the cache (would suppress real
    findings on similar endpoints).
  * Vague BLOCKED reasons (no "no-signal" pattern) do NOT cache.
  * ITERATION_CAP_REACHED / BUDGET_EXCEEDED / ERROR /
    DENIED_BY_SCAN_MODE never cache.
  * Cache hit + miss boundaries are deterministic per the
    canonicalization rules in `canonicalize_endpoint`.

Kill switch (`STRIX_VERDICT_CACHE_DISABLED=1`) bypasses
lookup AND store.
"""

from __future__ import annotations

import pytest

from strix.agents import specialist_verdict_cache as vc


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_VERDICT_CACHE_DISABLED", raising=False)
    vc.reset()
    yield
    vc.reset()


# ---------------------------------------------------------------------------
# Endpoint canonicalization
# ---------------------------------------------------------------------------


def test_canonicalize_numeric_id() -> None:
    assert vc.canonicalize_endpoint("/api/v1/users/12345") == "/api/v1/users/{id}"


def test_canonicalize_uuid() -> None:
    assert vc.canonicalize_endpoint(
        "/api/v1/orders/550e8400-e29b-41d4-a716-446655440000"
    ) == "/api/v1/orders/{uuid}"


def test_canonicalize_long_hex_hash() -> None:
    assert vc.canonicalize_endpoint(
        "/api/cache/" + "a" * 32
    ) == "/api/cache/{hash}"


def test_canonicalize_keeps_trailing_path_distinct() -> None:
    """`/users/{id}/profile` and `/users/{id}/settings` MUST stay
    distinct — they hit different handlers."""
    a = vc.canonicalize_endpoint("/users/12/profile")
    b = vc.canonicalize_endpoint("/users/12/settings")
    assert a != b
    assert a == "/users/{id}/profile"
    assert b == "/users/{id}/settings"


def test_canonicalize_strips_url_prefix() -> None:
    assert vc.canonicalize_endpoint(
        "https://vampi.local:5001/api/users/42"
    ) == "/api/users/{id}"


def test_canonicalize_strips_query_string() -> None:
    assert vc.canonicalize_endpoint(
        "/api/search?q=foo&page=2"
    ) == "/api/search"


def test_canonicalize_strips_fragment() -> None:
    assert vc.canonicalize_endpoint("/page#section") == "/page"


def test_canonicalize_strips_trailing_slash() -> None:
    assert vc.canonicalize_endpoint("/api/users/") == "/api/users"
    # Root stays as "/"
    assert vc.canonicalize_endpoint("/") == "/"


def test_canonicalize_lowercases() -> None:
    assert vc.canonicalize_endpoint("/API/Users/42") == "/api/users/{id}"


def test_canonicalize_empty_returns_empty() -> None:
    assert vc.canonicalize_endpoint("") == ""
    assert vc.canonicalize_endpoint(None) == ""
    assert vc.canonicalize_endpoint("   ") == ""


# ---------------------------------------------------------------------------
# make_key
# ---------------------------------------------------------------------------


def test_make_key_normalizes_components() -> None:
    k = vc.make_key(
        category="SQLi", endpoint="/api/users/42", auth_state="USER_A",
    )
    assert k is not None
    assert k.category == "sqli"
    assert k.endpoint_shape == "/api/users/{id}"
    assert k.auth_state == "user_a"


def test_make_key_returns_none_without_endpoint() -> None:
    assert vc.make_key(category="sqli", endpoint=None, auth_state=None) is None
    assert vc.make_key(category="sqli", endpoint="", auth_state=None) is None


def test_make_key_returns_none_without_category() -> None:
    assert vc.make_key(category="", endpoint="/x", auth_state=None) is None


def test_make_key_defaults_auth_state_to_anon() -> None:
    k = vc.make_key(category="sqli", endpoint="/x", auth_state=None)
    assert k is not None
    assert k.auth_state == "anon"


# ---------------------------------------------------------------------------
# Store + lookup
# ---------------------------------------------------------------------------


def test_record_cacheable_blocked_then_hit() -> None:
    """Canonical happy path: BLOCKED + 'no SQL backend' is cached;
    a same-shape dispatch hits."""
    stored = vc.record(
        category="sqli",
        endpoint="/api/users/42",
        auth_state="user_a",
        status="BLOCKED",
        reason="no SQL backend; ORM-only stack",
        objective="probe SQLi on /api/users/{id}",
    )
    assert stored is True

    hit = vc.should_skip(
        category="sqli", endpoint="/api/users/99", auth_state="user_a",
    )
    assert hit is not None
    assert "no SQL backend" in hit.reason
    assert hit.hit_count == 1


def test_record_does_not_cache_passed() -> None:
    """PASSED MUST NEVER cache. A successful exploit on one
    endpoint must not suppress dispatch on a similar one."""
    stored = vc.record(
        category="sqli",
        endpoint="/api/users/42",
        auth_state="user_a",
        status="PASSED",
        reason="union-based SQLi confirmed",
        objective="x",
        findings_count=1,
    )
    assert stored is False
    assert vc.should_skip(
        category="sqli", endpoint="/api/users/99", auth_state="user_a",
    ) is None


def test_record_does_not_cache_iteration_cap_reached() -> None:
    """Iteration cap means the specialist didn't conclude — the
    next dispatch on a similar endpoint might succeed."""
    stored = vc.record(
        category="sqli", endpoint="/api/users/42", auth_state="user_a",
        status="ITERATION_CAP_REACHED",
        reason="ran out of iterations exploring auth bypass",
        objective="x",
    )
    assert stored is False


def test_record_does_not_cache_error() -> None:
    stored = vc.record(
        category="sqli", endpoint="/api/users/42", auth_state="user_a",
        status="ERROR",
        reason="inner LLM call timed out",
        objective="x",
    )
    assert stored is False


def test_record_does_not_cache_budget_exceeded() -> None:
    stored = vc.record(
        category="sqli", endpoint="/api/users/42", auth_state="user_a",
        status="BUDGET_EXCEEDED",
        reason="hit cost cap before finishing probes",
        objective="x",
    )
    assert stored is False


def test_record_does_not_cache_denied_by_scan_mode() -> None:
    stored = vc.record(
        category="sqli", endpoint="/api/users/42", auth_state="user_a",
        status="DENIED_BY_SCAN_MODE",
        reason="cap hit",
        objective="x",
    )
    assert stored is False


def test_record_does_not_cache_vague_blocked_reason() -> None:
    """A BLOCKED with a non-'no-signal' reason MUST NOT cache —
    the next dispatch might flip the verdict."""
    stored = vc.record(
        category="sqli", endpoint="/api/users/42", auth_state="user_a",
        status="BLOCKED",
        reason="specialist couldn't determine; will revisit",
        objective="x",
    )
    assert stored is False


def test_record_does_not_cache_blocked_with_findings() -> None:
    """Defence-in-depth: BLOCKED + findings_count > 0 should
    never cache, even if the reason looks cacheable. The
    specialist emitted something — a similar surface might too."""
    stored = vc.record(
        category="sqli", endpoint="/api/users/42", auth_state="user_a",
        status="BLOCKED",
        reason="no SQL backend on the third endpoint, but...",
        objective="x",
        findings_count=2,
    )
    assert stored is False


# ---------------------------------------------------------------------------
# Cache hit/miss boundaries
# ---------------------------------------------------------------------------


def _seed(category: str, endpoint: str, auth_state: str | None = "user_a") -> None:
    """Seed a canonical no-signal BLOCKED entry for use in
    boundary tests."""
    vc.record(
        category=category, endpoint=endpoint, auth_state=auth_state,
        status="BLOCKED", reason="no SQL backend", objective="x",
    )


def test_cache_miss_on_different_category() -> None:
    _seed("sqli", "/api/users/42")
    assert vc.should_skip(
        category="xss", endpoint="/api/users/99", auth_state="user_a",
    ) is None


def test_cache_miss_on_different_endpoint_shape() -> None:
    _seed("sqli", "/api/users/42")
    # /api/orders/<id> is a completely different shape
    assert vc.should_skip(
        category="sqli", endpoint="/api/orders/42", auth_state="user_a",
    ) is None


def test_cache_miss_on_different_auth_state() -> None:
    _seed("sqli", "/api/users/42", auth_state="user_a")
    # admin context might surface different behaviour
    assert vc.should_skip(
        category="sqli", endpoint="/api/users/99", auth_state="admin",
    ) is None


def test_cache_miss_on_trailing_path_difference() -> None:
    """Critical recall safeguard — `/users/{id}` and
    `/users/{id}/profile` MUST be distinct cache buckets."""
    _seed("sqli", "/api/users/42")
    # Same shape root + extra segment → different shape
    assert vc.should_skip(
        category="sqli", endpoint="/api/users/99/profile",
        auth_state="user_a",
    ) is None


def test_cache_hit_increments_hit_count() -> None:
    _seed("sqli", "/api/users/42")
    for i in range(3):
        h = vc.should_skip(
            category="sqli", endpoint=f"/api/users/{100 + i}",
            auth_state="user_a",
        )
        assert h is not None
    # After 3 hits, hit_count == 3
    assert vc.stats()["total_hits"] == 3


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_disables_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed("sqli", "/api/users/42")
    monkeypatch.setenv("STRIX_VERDICT_CACHE_DISABLED", "1")
    assert vc.should_skip(
        category="sqli", endpoint="/api/users/99", auth_state="user_a",
    ) is None


def test_kill_switch_disables_record(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_VERDICT_CACHE_DISABLED", "1")
    stored = vc.record(
        category="sqli", endpoint="/api/users/42", auth_state="user_a",
        status="BLOCKED", reason="no SQL backend", objective="x",
    )
    assert stored is False


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


def test_reset_clears_cache() -> None:
    _seed("sqli", "/api/users/42")
    assert vc.stats()["size"] == 1
    vc.reset()
    assert vc.stats()["size"] == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_stats_reports_entries_and_hits() -> None:
    _seed("sqli", "/api/users/42")
    _seed("xss", "/api/search")
    vc.should_skip(category="sqli", endpoint="/api/users/99", auth_state="user_a")
    s = vc.stats()
    assert s["size"] == 2
    assert s["total_hits"] == 1
    entries = sorted(s["entries"], key=lambda e: e["category"])
    assert entries[0]["category"] in ("sqli", "xss")
