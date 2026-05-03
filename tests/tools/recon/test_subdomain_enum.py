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


# ---------------------------------------------------------------------------
# Certificate Transparency sources (crt.sh + certspotter)
# ---------------------------------------------------------------------------


def test_normalize_ct_hostname_basic() -> None:
    assert se._normalize_ct_hostname("api.example.com", "example.com") == "api.example.com"
    assert se._normalize_ct_hostname("API.Example.Com", "example.com") == "api.example.com"
    # Wildcard prefix stripped.
    assert se._normalize_ct_hostname("*.api.example.com", "example.com") == "api.example.com"
    # Trailing dot stripped.
    assert se._normalize_ct_hostname("api.example.com.", "example.com") == "api.example.com"
    # Apex itself is in scope.
    assert se._normalize_ct_hostname("example.com", "example.com") == "example.com"


def test_normalize_ct_hostname_off_scope_dropped() -> None:
    assert se._normalize_ct_hostname("api.attacker.com", "example.com") is None
    # Substring trick — `evil-example.com` ≠ subdomain of `example.com`.
    assert se._normalize_ct_hostname("evil-example.com", "example.com") is None
    # Empty / non-string.
    assert se._normalize_ct_hostname("", "example.com") is None
    assert se._normalize_ct_hostname(None, "example.com") is None
    assert se._normalize_ct_hostname(42, "example.com") is None
    # Too long → rejected.
    assert se._normalize_ct_hostname("x" * 254 + ".example.com", "example.com") is None


def test_crtsh_source_parses_name_value(monkeypatch) -> None:
    """crt.sh `name_value` is newline-separated SANs across multiple records."""
    response = """[
        {"name_value": "api.example.com\\nadmin.example.com\\nattacker.com",
         "common_name": "api.example.com"},
        {"name_value": "*.dev.example.com\\nstaging.example.com",
         "common_name": "*.dev.example.com"}
    ]"""
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (200, response))
    out = se.subdomain_enum("example.com", sources="crtsh")
    subs = set(out["subdomains"])
    assert "api.example.com" in subs
    assert "admin.example.com" in subs
    assert "dev.example.com" in subs  # wildcard-prefix stripped
    assert "staging.example.com" in subs
    # Off-scope entry filtered.
    assert "attacker.com" not in subs
    assert out["per_source_counts"]["crtsh"] == 4


def test_crtsh_handles_404(monkeypatch) -> None:
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (404, ""))
    out = se.subdomain_enum("example.com", sources="crtsh")
    assert out["per_source_counts"]["crtsh"] == 0


def test_crtsh_handles_invalid_json(monkeypatch) -> None:
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (200, "not json"))
    out = se.subdomain_enum("example.com", sources="crtsh")
    assert out["per_source_counts"]["crtsh"] == 0


def test_crtsh_handles_rate_limited(monkeypatch) -> None:
    """504 / 429 → soft failure, source contributes 0."""
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (504, ""))
    out = se.subdomain_enum("example.com", sources="crtsh")
    assert out["per_source_counts"]["crtsh"] == 0


def test_certspotter_source_parses_dns_names(monkeypatch) -> None:
    """certspotter returns a list of issuance objects with `dns_names` arrays."""
    response = """[
        {"dns_names": ["api.example.com", "admin.example.com"]},
        {"dns_names": ["*.dev.example.com", "staging.example.com", "neighbour.com"]}
    ]"""
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (200, response))
    out = se.subdomain_enum("example.com", sources="certspotter")
    subs = set(out["subdomains"])
    assert "api.example.com" in subs
    assert "admin.example.com" in subs
    assert "dev.example.com" in subs
    assert "staging.example.com" in subs
    # Off-scope filtered.
    assert "neighbour.com" not in subs
    assert out["per_source_counts"]["certspotter"] == 4


def test_certspotter_handles_unauthenticated_403(monkeypatch) -> None:
    """certspotter sometimes 403s on heavy unauth use."""
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (403, ""))
    out = se.subdomain_enum("example.com", sources="certspotter")
    assert out["per_source_counts"]["certspotter"] == 0


def test_certspotter_handles_non_list_response(monkeypatch) -> None:
    """If the API returns an error object (dict) instead of a list, no crash."""
    monkeypatch.setattr(
        se, "http_get_text", lambda url, **kw: (200, '{"error": "rate limited"}'),
    )
    out = se.subdomain_enum("example.com", sources="certspotter")
    assert out["per_source_counts"]["certspotter"] == 0


def test_ct_sources_in_default_set(monkeypatch) -> None:
    """When `sources='default'`, crtsh + certspotter should run."""
    crtsh_called = {"hit": False}
    certspotter_called = {"hit": False}

    def fake_get_text(url, **kw):
        if "crt.sh" in url:
            crtsh_called["hit"] = True
        elif "certspotter" in url:
            certspotter_called["hit"] = True
        return (200, "[]")

    monkeypatch.setattr(se, "http_get_text", fake_get_text)
    monkeypatch.setattr(se, "_enum_subfinder", lambda d, m: [])
    monkeypatch.setattr(se, "_enum_amass", lambda d, m: [])
    monkeypatch.setattr(se, "_read_wordlist", lambda p: [])
    monkeypatch.setattr(se, "dig", lambda *a, **kw: "")
    se.subdomain_enum("example.com", sources="default")
    assert crtsh_called["hit"] is True
    assert certspotter_called["hit"] is True


def test_ct_dedup_across_sources(monkeypatch) -> None:
    """When crtsh + certspotter both find the same subdomain, the merged
    list should dedup."""
    monkeypatch.setattr(se, "_enum_crtsh", lambda d, m: ["api.example.com", "admin.example.com"])
    monkeypatch.setattr(se, "_enum_certspotter", lambda d, m: ["api.example.com", "secret.example.com"])
    out = se.subdomain_enum("example.com", sources="crtsh,certspotter", max_per_source=100)
    # api.example.com appears in both; should be counted once in merged.
    assert out["subdomains"].count("api.example.com") == 1
    assert "admin.example.com" in out["subdomains"]
    assert "secret.example.com" in out["subdomains"]
    assert out["total_unique"] == 3


def test_max_per_source_caps_ct_results(monkeypatch) -> None:
    """Verify max_per_source caps the per-source result count."""
    # crt.sh-shaped response with 100 names; max_per_source=10 should cap.
    names = [f"sub{i}.example.com" for i in range(100)]
    record = {"name_value": "\n".join(names), "common_name": names[0]}
    import json as _json
    body = _json.dumps([record])
    monkeypatch.setattr(se, "http_get_text", lambda url, **kw: (200, body))
    out = se.subdomain_enum("example.com", sources="crtsh", max_per_source=10)
    assert out["per_source_counts"]["crtsh"] == 10
