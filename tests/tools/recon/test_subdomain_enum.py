"""Tests for subdomain_enum.

Hermetic — every external call (subprocess, dig, http_get_text) is mocked.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import subdomain_enum_tool as se


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("se-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_invalid_domain_rejected() -> None:
    out = se.subdomain_enum("not a domain")
    assert out["success"] is False


def test_unknown_source_rejected() -> None:
    out = se.subdomain_enum("example.com", sources="subfinder,bogus")
    assert out["success"] is False
    assert "bogus" in str(out["error"])


# ---------------------------------------------------------------------------
# Per-source mocking
# ---------------------------------------------------------------------------


def test_subfinder_only_source(monkeypatch) -> None:
    monkeypatch.setattr(se, "_enum_subfinder", lambda d, m: ["api.example.com", "blog.example.com"])
    out = se.subdomain_enum("example.com", sources="subfinder")
    assert out["success"] is True
    assert "api.example.com" in out["subdomains"]
    assert out["per_source_counts"]["subfinder"] == 2


def test_amass_source(monkeypatch) -> None:
    monkeypatch.setattr(se, "_enum_amass", lambda d, m: ["secret.example.com"])
    out = se.subdomain_enum("example.com", sources="amass")
    assert "secret.example.com" in out["subdomains"]


def test_dns_bruteforce_uses_default_wordlist(monkeypatch) -> None:
    captured: list[str] = []

    def fake_dig(host: str, record_type: str = "A", **_: Any) -> str:
        captured.append(host)
        return "1.2.3.4" if host == "api.example.com" else ""

    monkeypatch.setattr(se, "dig", fake_dig)
    out = se.subdomain_enum("example.com", sources="dns_bruteforce", max_per_source=200)
    # Should have queried many candidates from the default wordlist.
    assert len(captured) > 50
    # `api` is in the default wordlist; only it resolves.
    assert out["subdomains"] == ["api.example.com"]


def test_dns_bruteforce_custom_wordlist(monkeypatch, tmp_path) -> None:
    custom = tmp_path / "wl.txt"
    custom.write_text("# comment line\nfoo\nbar\n# another comment\nbaz\n")
    captured: list[str] = []

    def fake_dig(host: str, record_type: str = "A", **_: Any) -> str:
        captured.append(host)
        return ""

    monkeypatch.setattr(se, "dig", fake_dig)
    se.subdomain_enum("example.com", sources="dns_bruteforce", wordlist=str(custom))
    # Custom wordlist should produce exactly foo/bar/baz queries.
    queried_hosts = [h for h in captured if h.endswith(".example.com")]
    assert "foo.example.com" in queried_hosts
    assert "bar.example.com" in queried_hosts
    assert "baz.example.com" in queried_hosts
    # Comments not queried.
    assert not any(h.startswith("# comment") for h in queried_hosts)


def test_dns_bruteforce_respects_max_per_source(monkeypatch) -> None:
    """Once max hits, bruteforce stops querying — it doesn't enumerate the full wordlist."""
    queries: list[str] = []

    def fake_dig(host: str, record_type: str = "A", **_: Any) -> str:
        queries.append(host)
        return "1.2.3.4"  # everything resolves

    monkeypatch.setattr(se, "dig", fake_dig)
    out = se.subdomain_enum("example.com", sources="dns_bruteforce", max_per_source=3)
    assert len(out["subdomains"]) == 3
    # Once we hit 3 results, we should stop dispatching new queries.
    assert len(queries) == 3


# ---------------------------------------------------------------------------
# Permutations
# ---------------------------------------------------------------------------


def test_permutations_use_other_sources_as_seeds(monkeypatch) -> None:
    monkeypatch.setattr(se, "_enum_subfinder", lambda d, m: ["api.example.com"])
    monkeypatch.setattr(se, "_enum_amass", lambda d, m: [])
    monkeypatch.setattr(se, "_enum_wayback", lambda d, m: [])
    # Custom wordlist that's empty so dns_bruteforce yields nothing.
    monkeypatch.setattr(se, "_read_wordlist", lambda p: [])

    captured: list[str] = []

    def fake_dig(host: str, record_type: str = "A", **_: Any) -> str:
        captured.append(host)
        # Permute: prod-api.example.com resolves
        return "9.9.9.9" if host == "prod-api.example.com" else ""

    monkeypatch.setattr(se, "dig", fake_dig)
    out = se.subdomain_enum("example.com")
    assert "prod-api.example.com" in out["subdomains"]


def test_explicit_permutation_seeds(monkeypatch) -> None:
    captured: list[str] = []

    def fake_dig(host: str, record_type: str = "A", **_: Any) -> str:
        captured.append(host)
        return "1.2.3.4" if host == "dev-blog.example.com" else ""

    monkeypatch.setattr(se, "dig", fake_dig)
    out = se.subdomain_enum(
        "example.com",
        sources="permutations",
        permutation_seeds="blog.example.com",
    )
    assert "dev-blog.example.com" in out["subdomains"]


# ---------------------------------------------------------------------------
# Wayback
# ---------------------------------------------------------------------------


def test_wayback_extracts_subdomains_from_cdx(monkeypatch) -> None:
    cdx_body = (
        "https://api.example.com/v1/users\n"
        "http://blog.example.com/post-1\n"
        "https://www.example.com/\n"
        "https://other-domain.org/x\n"  # outside scope, should be filtered
    )
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (200, cdx_body))
    out = se.subdomain_enum("example.com", sources="wayback")
    subs = out["subdomains"]
    assert "api.example.com" in subs
    assert "blog.example.com" in subs
    assert "www.example.com" in subs
    assert "other-domain.org" not in subs


def test_wayback_failure_returns_empty(monkeypatch) -> None:
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (500, ""))
    out = se.subdomain_enum("example.com", sources="wayback")
    assert out["per_source_counts"]["wayback"] == 0


# ---------------------------------------------------------------------------
# Multi-source merging
# ---------------------------------------------------------------------------


def test_multi_source_dedup(monkeypatch) -> None:
    monkeypatch.setattr(se, "_enum_subfinder", lambda d, m: ["api.example.com", "blog.example.com"])
    monkeypatch.setattr(se, "_enum_amass", lambda d, m: ["api.example.com", "secret.example.com"])
    monkeypatch.setattr(se, "_enum_wayback", lambda d, m: [])
    monkeypatch.setattr(se, "_read_wordlist", lambda p: [])
    monkeypatch.setattr(se, "dig", lambda *a, **kw: "")
    out = se.subdomain_enum(
        "example.com", sources="subfinder,amass", max_per_source=100
    )
    # api.example.com appears in both sources; should be deduped.
    assert out["subdomains"].count("api.example.com") == 1
    assert "blog.example.com" in out["subdomains"]
    assert "secret.example.com" in out["subdomains"]
    assert out["total_unique"] == 3


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_emits_one_check_per_source(monkeypatch) -> None:
    monkeypatch.setattr(se, "_enum_subfinder", lambda d, m: [])
    monkeypatch.setattr(se, "_enum_amass", lambda d, m: [])
    monkeypatch.setattr(se, "_enum_wayback", lambda d, m: [])
    monkeypatch.setattr(se, "_read_wordlist", lambda p: [])
    monkeypatch.setattr(se, "dig", lambda *a, **kw: "")

    se.subdomain_enum("example.com", sources="subfinder,amass,dns_bruteforce,wayback")
    summary = tracer_module.get_global_tracer().get_check_summary()
    # 4 explicit sources + permutations auto-runs (with empty seeds → 0 hits, but still emits).
    # When sources is comma-separated subset (not all/default), permutations only runs if
    # explicitly requested. So 4 events here.
    assert summary["total"] == 4
    assert "subdomain_enum" in summary["by_category"]
