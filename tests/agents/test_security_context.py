"""Tests for §8.5 — SecurityContext cross-tool fact ledger.

Pins the structure + render shape so the model's prompt always
contains predictable `TARGET:` / `TECH STACK:` / `ENDPOINTS:` /
`AUTH STATES:` / `PARTIAL SIGNALS:` blocks. Without that pinning
a future PR could rename a field and break the lead's reasoning
silently.
"""

from __future__ import annotations

import pytest

from strix.agents.security_context import (
    get_security_context,
    list_endpoints,
    list_partial_signals,
    record_auth_state,
    record_endpoint,
    record_partial_signal,
    render_for_prompt,
    reset_security_context,
    set_target_url,
    update_tech_stack,
)


@pytest.fixture(autouse=True)
def _isolate_context():
    reset_security_context()
    yield
    reset_security_context()


# ---------------------------------------------------------------------------
# Singleton + reset
# ---------------------------------------------------------------------------


def test_get_returns_same_instance() -> None:
    a = get_security_context()
    b = get_security_context()
    assert a is b


def test_reset_clears_state() -> None:
    set_target_url("http://example.com")
    update_tech_stack(server="Apache")
    reset_security_context()
    ctx = get_security_context()
    assert ctx.target_url == ""
    assert ctx.tech_stack.server is None


# ---------------------------------------------------------------------------
# Tech stack
# ---------------------------------------------------------------------------


def test_tech_stack_partial_updates_dont_wipe() -> None:
    """Two specialists update different fields — neither wipes the
    other's data."""
    update_tech_stack(server="Apache/2.2.22", language="PHP/5.3")
    update_tech_stack(database="MySQL")
    ctx = get_security_context()
    assert ctx.tech_stack.server == "Apache/2.2.22"
    assert ctx.tech_stack.language == "PHP/5.3"
    assert ctx.tech_stack.database == "MySQL"


def test_tech_stack_none_values_ignored() -> None:
    """Calling update_tech_stack(database=None) doesn't wipe a prior
    fingerprint."""
    update_tech_stack(database="MySQL")
    update_tech_stack(database=None, server="Apache")
    ctx = get_security_context()
    assert ctx.tech_stack.database == "MySQL"
    assert ctx.tech_stack.server == "Apache"


def test_raw_headers_merge() -> None:
    update_tech_stack(raw_headers={"X-Powered-By": "PHP/5.3"})
    update_tech_stack(raw_headers={"Server": "Apache/2.2.22"})
    ctx = get_security_context()
    assert ctx.tech_stack.raw_headers == {
        "X-Powered-By": "PHP/5.3",
        "Server": "Apache/2.2.22",
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def test_record_endpoint_canonicalizes_path() -> None:
    record_endpoint("http://example.com/login", method="POST", status=200)
    record_endpoint("/login", method="GET", status=405)
    eps = list_endpoints()
    assert len(eps) == 1
    e = eps[0]
    assert e.path == "/login"
    assert "POST" in e.methods_seen
    assert "GET" in e.methods_seen
    # Latest status wins.
    assert e.last_status == 405


def test_record_endpoint_dedups_methods_and_params() -> None:
    record_endpoint("/api/x", method="POST", params=["q", "page"])
    record_endpoint("/api/x", method="POST", params=["q"])  # dup
    e = list_endpoints()[0]
    assert e.methods_seen == ["POST"]
    assert sorted(e.params_seen) == ["page", "q"]


def test_record_endpoint_appends_probed_categories() -> None:
    record_endpoint("/api/x", probed_for="sqli")
    record_endpoint("/api/x", probed_for="xss")
    record_endpoint("/api/x", probed_for="sqli")  # dup
    e = list_endpoints()[0]
    assert sorted(e.probed_for) == ["sqli", "xss"]


def test_endpoint_with_query_string_kept() -> None:
    """`/redirect?to=test` and `/redirect?to=other` collapse onto
    the same path with the QS in the key. Some endpoints behave
    very differently with different params — keep them apart."""
    record_endpoint("http://example.com/redirect?to=test", method="GET")
    record_endpoint("http://example.com/redirect?to=other", method="GET")
    paths = {e.path for e in list_endpoints()}
    # Both kept distinctly. (Phase 1 — Phase 2 may collapse on
    # path-only with param-name awareness.)
    assert "/redirect?to=test" in paths
    assert "/redirect?to=other" in paths


# ---------------------------------------------------------------------------
# Auth states
# ---------------------------------------------------------------------------


def test_record_auth_state_basic() -> None:
    record_auth_state(
        "user-alice",
        cookies={"session": "abc123"},
        bearer="eyJ.payload.sig",
    )
    ctx = get_security_context()
    state = ctx.auth_states["user-alice"]
    assert state.cookies == {"session": "abc123"}
    assert state.bearer == "eyJ.payload.sig"


def test_auth_state_merges_cookies_across_calls() -> None:
    record_auth_state("user", cookies={"a": "1"})
    record_auth_state("user", cookies={"b": "2"})
    state = get_security_context().auth_states["user"]
    assert state.cookies == {"a": "1", "b": "2"}


# ---------------------------------------------------------------------------
# Partial signals
# ---------------------------------------------------------------------------


def test_record_partial_signal_dedup() -> None:
    record_partial_signal(
        surface="/redirect?to=", signal="URL reflected in Location",
        next_probe="test absolute URL",
    )
    record_partial_signal(
        surface="/redirect?to=", signal="URL reflected in Location",
        next_probe="test absolute URL",
    )
    sigs = list_partial_signals()
    assert len(sigs) == 1


def test_partial_signal_distinct_signals_kept() -> None:
    record_partial_signal(surface="/x", signal="signal A")
    record_partial_signal(surface="/x", signal="signal B")
    assert len(list_partial_signals()) == 2


def test_partial_signal_bounded_to_50() -> None:
    for i in range(60):
        record_partial_signal(surface=f"/{i}", signal=f"sig_{i}")
    assert len(list_partial_signals()) == 50
    # Most-recent kept.
    surfaces = [s.surface for s in list_partial_signals()]
    assert "/59" in surfaces
    assert "/0" not in surfaces


# ---------------------------------------------------------------------------
# Render — the prompt-facing surface
# ---------------------------------------------------------------------------


def test_render_includes_target() -> None:
    set_target_url("http://example.com")
    out = render_for_prompt()
    assert "TARGET:" in out
    assert "http://example.com" in out


def test_render_empty_context_has_stub() -> None:
    out = render_for_prompt()
    assert "TARGET:" in out
    assert "(SecurityContext is empty" in out


def test_render_includes_tech_stack_with_db_hint() -> None:
    set_target_url("http://x")
    update_tech_stack(server="Apache/2.2", database="MySQL", language="PHP")
    out = render_for_prompt()
    assert "TECH STACK:" in out
    assert "Apache/2.2" in out
    assert "MySQL" in out
    # The DB hint that informs SQLi payload selection.
    assert "informs SQLi payload" in out


def test_render_includes_version_disclosure_warning() -> None:
    set_target_url("http://x")
    update_tech_stack(server="Apache/2.2.22", version_disclosed=True)
    out = render_for_prompt()
    assert "VERSION DISCLOSURE detected" in out


def test_render_includes_endpoints_sorted_by_probed_count() -> None:
    set_target_url("http://x")
    record_endpoint("/a", method="GET", status=200)
    record_endpoint("/b", method="GET", status=200, probed_for="xss")
    record_endpoint("/b", probed_for="sqli")
    record_endpoint("/c", method="GET", status=200, probed_for="xss")
    out = render_for_prompt()
    assert "ENDPOINTS DISCOVERED" in out
    # /b has 2 probes; /c has 1; /a has 0. /b should come first.
    assert out.index("/b") < out.index("/c") < out.index("/a")


def test_render_caps_endpoint_count() -> None:
    set_target_url("http://x")
    for i in range(50):
        record_endpoint(f"/path{i}", method="GET")
    out = render_for_prompt(max_endpoints=10)
    # 10 paths in output max; "showing top 10" indicator.
    assert "showing top 10" in out
    rendered = sum(1 for i in range(50) if f"/path{i}" in out)
    assert rendered == 10


def test_render_includes_auth_states_with_jwt_hint() -> None:
    set_target_url("http://x")
    record_auth_state("user", bearer="eyJhbGciOiJIUzI1NiJ9.payload.sig")
    out = render_for_prompt()
    assert "AUTH STATES CAPTURED" in out
    assert "user" in out
    # JWT hint for follow-up.
    assert "Run jwt_audit on it" in out


def test_render_includes_partial_signals() -> None:
    set_target_url("http://x")
    record_partial_signal(
        surface="/redirect?to=",
        signal="URL value reflected verbatim in 302 Location header",
        next_probe="test with absolute external URL like https://evil.example",
        category_hint="open_redirect",
    )
    out = render_for_prompt()
    assert "PARTIAL SIGNALS" in out
    assert "/redirect" in out
    assert "open_redirect" in out
    assert "next:" in out
    # The chase-them-down nudge.
    assert "chase before declaring scan complete" in out


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_persistence_writes_run_dir_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("STRIX_RUN_DIR", str(tmp_path))
    set_target_url("http://example.com")
    update_tech_stack(server="nginx")
    record_endpoint("/login", method="POST")
    sc_path = tmp_path / "security_context.json"
    assert sc_path.exists()
    import json
    data = json.loads(sc_path.read_text())
    assert data["target_url"] == "http://example.com"
    assert data["tech_stack"]["server"] == "nginx"
    assert "/login" in data["endpoints"]


def test_persistence_no_run_dir_silent(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_RUN_DIR", raising=False)
    # Should not raise.
    set_target_url("http://example.com")
    update_tech_stack(server="nginx")
