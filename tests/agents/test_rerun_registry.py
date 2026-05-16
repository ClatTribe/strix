"""Tests for the P1 rerun_registry — the bridge between proposed
patches and re-firing the original detection.

Covers:
  * Decorator-style registration with (category, cwe) keys
  * CWE wildcard registration (cwe=None matches any CWE)
  * Exact-match takes precedence over wildcard
  * lookup returns None when not registered
  * Kill switch (STRIX_RERUN_REGISTRY_DISABLED)
  * RerunResult dataclass shape
  * list_registered + get_stats inspection helpers
  * Lazy registration via lookup_rerun_lazy triggers scanner imports
"""

from __future__ import annotations

import pytest

from strix.agents import rerun_registry as rr


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    rr.reset_for_testing()
    # Also force _registered=False so lazy-registration tests have a
    # clean slate.
    rr._registered = False
    monkeypatch.delenv("STRIX_RERUN_REGISTRY_DISABLED", raising=False)
    yield
    rr.reset_for_testing()


def _stub_handler(*, finding_context: dict) -> rr.RerunResult:
    return rr.RerunResult(outcome="no_longer_fires", detail="stub")


# ---------------------------------------------------------------------------
# Registration / lookup
# ---------------------------------------------------------------------------


def test_register_and_lookup_exact() -> None:
    rr.register_rerun(category="sqli", cwe="CWE-89")(_stub_handler)
    found = rr.lookup_rerun(category="sqli", cwe="CWE-89")
    assert found is _stub_handler


def test_lookup_wildcard_fallback() -> None:
    """Registration with cwe=None matches any CWE in the category."""
    rr.register_rerun(category="custom")(_stub_handler)
    assert rr.lookup_rerun(category="custom", cwe="CWE-999") is _stub_handler


def test_exact_match_beats_wildcard() -> None:
    def wildcard_fn(*, finding_context: dict) -> rr.RerunResult:
        return rr.RerunResult(outcome="indeterminate", detail="wildcard")

    def exact_fn(*, finding_context: dict) -> rr.RerunResult:
        return rr.RerunResult(outcome="no_longer_fires", detail="exact")

    rr.register_rerun(category="sqli")(wildcard_fn)
    rr.register_rerun(category="sqli", cwe="CWE-89")(exact_fn)

    found = rr.lookup_rerun(category="sqli", cwe="CWE-89")
    assert found is exact_fn


def test_lookup_unknown_returns_none() -> None:
    assert rr.lookup_rerun(category="not_registered") is None


def test_case_insensitive_category() -> None:
    rr.register_rerun(category="SQLi", cwe="CWE-89")(_stub_handler)
    assert rr.lookup_rerun(category="sqli", cwe="CWE-89") is _stub_handler
    assert rr.lookup_rerun(category="SQLI", cwe="CWE-89") is _stub_handler


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("val", ["1", "true", "True", "yes", "ON"])
def test_kill_switch_returns_none(
    val: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    rr.register_rerun(category="sqli", cwe="CWE-89")(_stub_handler)
    monkeypatch.setenv("STRIX_RERUN_REGISTRY_DISABLED", val)
    assert rr.lookup_rerun(category="sqli", cwe="CWE-89") is None


# ---------------------------------------------------------------------------
# RerunResult shape
# ---------------------------------------------------------------------------


def test_rerun_result_default_fields() -> None:
    r = rr.RerunResult(outcome="still_fires")
    assert r.detail == ""
    assert r.elapsed_seconds == 0.0
    assert r.evidence is None


def test_rerun_result_with_evidence() -> None:
    r = rr.RerunResult(
        outcome="no_longer_fires",
        detail="passed",
        elapsed_seconds=1.5,
        evidence={"status": 403},
    )
    assert r.evidence == {"status": 403}


@pytest.mark.parametrize("outcome", ["still_fires", "no_longer_fires", "indeterminate"])
def test_rerun_result_outcomes(outcome: str) -> None:
    r = rr.RerunResult(outcome=outcome)  # type: ignore[arg-type]
    assert r.outcome == outcome


# ---------------------------------------------------------------------------
# Inspection / telemetry
# ---------------------------------------------------------------------------


def test_list_registered() -> None:
    rr.register_rerun(category="sqli", cwe="CWE-89")(_stub_handler)
    rr.register_rerun(category="xss", cwe="CWE-79")(_stub_handler)
    keys = rr.list_registered()
    assert ("sqli", "CWE-89") in keys
    assert ("xss", "CWE-79") in keys


def test_get_stats_enabled() -> None:
    rr.register_rerun(category="sqli", cwe="CWE-89")(_stub_handler)
    s = rr.get_stats()
    assert s["enabled"] is True
    assert s["registered_count"] == 1


def test_get_stats_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_RERUN_REGISTRY_DISABLED", "1")
    s = rr.get_stats()
    assert s == {"enabled": False, "registered_count": 0}


# ---------------------------------------------------------------------------
# Lazy registration via scanner imports
# ---------------------------------------------------------------------------


def test_lookup_lazy_with_kill_switch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`lookup_rerun_lazy` still respects the kill switch."""
    monkeypatch.setenv("STRIX_RERUN_REGISTRY_DISABLED", "1")
    assert rr.lookup_rerun_lazy(category="sqli", cwe="CWE-89") is None


def test_scanner_registration_imports() -> None:
    """When the canonical 7 scanner modules are imported, the
    expected handlers land in the registry.

    Modules register at import time. This test verifies the
    registrations happen and survive a manual re-import of the
    scanner modules within the same process (importlib reload to
    ensure the registration code re-fires)."""
    import importlib
    # Force-reload each scanner to re-trigger top-level register
    # calls. (Once a module is in sys.modules, plain `import` is
    # a no-op.)
    for modname in (
        "strix.tools.specialist.scan_sqli",
        "strix.tools.specialist.scan_xss",
        "strix.tools.specialist.scan_ssrf",
        "strix.tools.specialist.scan_idor",
        "strix.tools.specialist.scan_cmd_injection",
        "strix.tools.specialist.scan_xxe",
        "strix.tools.specialist.scan_path_traversal",
    ):
        try:
            mod = importlib.import_module(modname)
            importlib.reload(mod)
        except Exception:  # noqa: BLE001
            pass

    keys = rr.list_registered()
    cats = {k[0] for k in keys}
    # All 7 scanners should have registered (idor registers twice
    # — one for CWE-639, one for CWE-862 missing_auth — and
    # cmd_injection registers under both `cmd_injection` and
    # `command_injection`).
    for expected in ("sqli", "xss", "ssrf", "idor", "missing_auth",
                     "cmd_injection", "command_injection", "xxe",
                     "path_traversal"):
        assert expected in cats, f"missing scanner registration: {expected}"
