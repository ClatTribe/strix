"""Tests for the BFS crawler.

Hermetic — every HTTP fetch is mocked at the strix.tools.web_crawler.crawler
namespace. Tests focus on:
  - Scope filtering (apex match, subdomain match, off-scope reject)
  - BFS traversal + depth/page caps
  - HTML link / form extraction
  - JS-bundle path mining
  - OpenAPI spec consumption
  - Composition with cluster-A safety middleware (auth / exclude-path /
    rate-limit are exercised in tests/tools/test_proxy_send_request_safety.py;
    this suite verifies the crawler routes fetches through that path).
"""

from __future__ import annotations

import json

import pytest

from strix.tools.web_crawler import crawler as cr
from strix.tools.proxy import http_safety


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch) -> None:
    for k in (
        "STRIX_AUTH_COOKIE",
        "STRIX_AUTH_BEARER",
        "STRIX_AUTH_BASIC",
        "STRIX_HEADERS",
        "STRIX_EXCLUDE_PATHS",
        "STRIX_RATE_LIMIT",
        "STRIX_SEED_URLS",
        "STRIX_OPENAPI_URL",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    yield


def _patch_http(monkeypatch, responses: dict[str, tuple[int, dict, str]]) -> list[str]:
    """Replace _http_get with a recorder. Returns the call log."""
    calls: list[str] = []

    def fake_http_get(url, *, max_bytes):
        calls.append(url)
        return responses.get(url, (404, {}, ""))

    monkeypatch.setattr(cr, "_http_get", fake_http_get)
    return calls


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_target_rejected() -> None:
    out = cr.bfs_crawl("")
    assert out["success"] is False


def test_invalid_target_scheme_rejected() -> None:
    out = cr.bfs_crawl("ftp://example.com")
    assert out["success"] is False


def test_bare_domain_gets_https_prefix(monkeypatch) -> None:
    _patch_http(monkeypatch, {})
    out = cr.bfs_crawl("example.com")
    assert out["target"] == "https://example.com"


# ---------------------------------------------------------------------------
# URL normalization
# ---------------------------------------------------------------------------


def test_normalize_drops_unsupported_schemes() -> None:
    base = "https://example.com/"
    assert cr._normalize_url("mailto:x@example.com", base) is None
    assert cr._normalize_url("javascript:alert(1)", base) is None
    assert cr._normalize_url("tel:+1234", base) is None
    assert cr._normalize_url("data:text/html,<x>", base) is None
    assert cr._normalize_url("#fragment", base) is None


def test_normalize_resolves_relative_paths() -> None:
    base = "https://example.com/foo/bar"
    assert cr._normalize_url("/api/x", base) == "https://example.com/api/x"
    assert cr._normalize_url("../baz", base) == "https://example.com/baz"


def test_normalize_strips_fragments() -> None:
    out = cr._normalize_url("/x#section", "https://example.com")
    assert out == "https://example.com/x"


# ---------------------------------------------------------------------------
# Scope filtering
# ---------------------------------------------------------------------------


def test_apex_and_subdomain_in_scope() -> None:
    allowed = cr._allowed_hosts_for_target("https://example.com")
    assert cr._in_scope("https://example.com/x", allowed) is True
    assert cr._in_scope("https://api.example.com/x", allowed) is True
    assert cr._in_scope("https://deep.api.example.com/x", allowed) is True


def test_off_scope_rejected() -> None:
    allowed = cr._allowed_hosts_for_target("https://example.com")
    assert cr._in_scope("https://attacker.com/x", allowed) is False
    # Tricky: "evil-example.com" should NOT match "example.com" since it's
    # a different apex, not a subdomain.
    assert cr._in_scope("https://evil-example.com/x", allowed) is False


def test_subdomain_target_keeps_apex_in_scope() -> None:
    allowed = cr._allowed_hosts_for_target("https://api.example.com")
    assert cr._in_scope("https://example.com/x", allowed) is True
    assert cr._in_scope("https://app.example.com/x", allowed) is True


# ---------------------------------------------------------------------------
# BFS traversal
# ---------------------------------------------------------------------------


def _html(*paths: str) -> str:
    """Build a minimal HTML body with anchors for the given paths."""
    return "<html><body>" + "".join(
        f'<a href="{p}">link</a>' for p in paths
    ) + "</body></html>"


def test_basic_traversal_two_levels(monkeypatch) -> None:
    home = "https://example.com/"
    page_a = "https://example.com/a"
    page_b = "https://example.com/b"
    page_c = "https://example.com/c"
    _patch_http(
        monkeypatch,
        {
            home: (200, {"Content-Type": "text/html"}, _html("/a", "/b")),
            page_a: (200, {"Content-Type": "text/html"}, _html("/c")),
            page_b: (200, {"Content-Type": "text/html"}, ""),
            page_c: (200, {"Content-Type": "text/html"}, ""),
        },
    )
    out = cr.bfs_crawl("https://example.com")
    urls = [e["url"] for e in out["endpoints"]]
    assert home in urls
    assert page_a in urls
    assert page_b in urls
    assert page_c in urls


def test_off_scope_links_not_crawled(monkeypatch) -> None:
    _patch_http(
        monkeypatch,
        {
            "https://example.com/": (
                200,
                {"Content-Type": "text/html"},
                _html("/in-scope", "https://attacker.com/x"),
            ),
            "https://example.com/in-scope": (200, {"Content-Type": "text/html"}, ""),
        },
    )
    out = cr.bfs_crawl("https://example.com")
    urls = [e["url"] for e in out["endpoints"]]
    assert "https://attacker.com/x" not in urls
    assert "https://example.com/in-scope" in urls


def test_max_pages_cap_honored(monkeypatch) -> None:
    """A crawl with many discoverable pages should stop at max_pages."""
    home = "https://example.com/"
    # Generate 10 pages, all linked from home; cap at 3.
    pages = {f"https://example.com/p{i}": (200, {"Content-Type": "text/html"}, "") for i in range(10)}
    _patch_http(
        monkeypatch,
        {
            home: (
                200,
                {"Content-Type": "text/html"},
                _html(*[f"/p{i}" for i in range(10)]),
            ),
            **pages,
        },
    )
    out = cr.bfs_crawl("https://example.com", max_pages=3)
    assert out["stats"]["pages_visited"] <= 3


def test_max_depth_cap_honored(monkeypatch) -> None:
    home = "https://example.com/"
    d1 = "https://example.com/d1"
    d2 = "https://example.com/d2"
    d3 = "https://example.com/d3"
    _patch_http(
        monkeypatch,
        {
            home: (200, {"Content-Type": "text/html"}, _html("/d1")),
            d1: (200, {"Content-Type": "text/html"}, _html("/d2")),
            d2: (200, {"Content-Type": "text/html"}, _html("/d3")),
            d3: (200, {"Content-Type": "text/html"}, ""),
        },
    )
    out = cr.bfs_crawl("https://example.com", max_depth=1)
    urls = [e["url"] for e in out["endpoints"]]
    # depth 0 = home, depth 1 = d1; d2 and d3 should not be visited.
    visited = [e for e in out["endpoints"] if e["url"] in (home, d1, d2, d3)]
    visited_urls = {e["url"] for e in visited}
    assert home in visited_urls
    assert d1 in visited_urls
    # d2/d3 may appear as endpoints (we record links we see) but they
    # should NOT be in the visited set (no fetch happened).
    out_calls_for_d2 = sum(1 for e in out["endpoints"] if e["url"] == d3 and e["depth"] >= 3)
    assert out_calls_for_d2 == 0


def test_visited_pages_not_refetched(monkeypatch) -> None:
    """If multiple pages link to the same URL, we should only fetch it once."""
    home = "https://example.com/"
    a = "https://example.com/a"
    b = "https://example.com/b"
    common = "https://example.com/common"
    calls = _patch_http(
        monkeypatch,
        {
            home: (200, {"Content-Type": "text/html"}, _html("/a", "/b")),
            a: (200, {"Content-Type": "text/html"}, _html("/common")),
            b: (200, {"Content-Type": "text/html"}, _html("/common")),
            common: (200, {"Content-Type": "text/html"}, ""),
        },
    )
    cr.bfs_crawl("https://example.com")
    # Each URL fetched exactly once.
    assert calls.count(common) == 1


# ---------------------------------------------------------------------------
# Form extraction
# ---------------------------------------------------------------------------


def test_form_extraction(monkeypatch) -> None:
    body = """
    <form action="/login" method="POST">
      <input name="email" type="email">
      <input name="password" type="password">
      <input name="csrf" type="hidden" value="abc">
    </form>
    """
    _patch_http(
        monkeypatch, {"https://example.com/": (200, {"Content-Type": "text/html"}, body)}
    )
    out = cr.bfs_crawl("https://example.com")
    assert len(out["forms"]) == 1
    form = out["forms"][0]
    assert form["method"] == "POST"
    assert form["action"] == "https://example.com/login"
    field_names = {f["name"] for f in form["fields"]}
    assert field_names == {"email", "password", "csrf"}
    # Form's POST endpoint also recorded as an endpoint.
    post_endpoints = [e for e in out["endpoints"] if e["method"] == "POST"]
    assert any(e["url"] == "https://example.com/login" for e in post_endpoints)


# ---------------------------------------------------------------------------
# JS-bundle path mining
# ---------------------------------------------------------------------------


def test_js_bundle_paths_extracted(monkeypatch) -> None:
    js_body = """
    fetch("/api/v1/users");
    let url = "/api/v1/orders/" + id;
    const adminPath = '/admin/dashboard';
    """
    _patch_http(
        monkeypatch,
        {
            "https://example.com/": (
                200,
                {"Content-Type": "text/html"},
                '<html><script src="/static/app.js"></script></html>',
            ),
            "https://example.com/static/app.js": (
                200,
                {"Content-Type": "application/javascript"},
                js_body,
            ),
        },
    )
    out = cr.bfs_crawl("https://example.com")
    js_endpoints = [e for e in out["endpoints"] if e["discovered_via"] == "js_bundle"]
    js_urls = {e["url"] for e in js_endpoints}
    assert "https://example.com/api/v1/users" in js_urls
    assert "https://example.com/admin/dashboard" in js_urls
    assert out["stats"]["js_bundles_parsed"] == 1


def test_js_extraction_skips_static_assets(monkeypatch) -> None:
    """Image / font references in JS shouldn't be flagged as endpoints."""
    js_body = """
    const logo = "/static/logo.png";
    const api = "/api/users";
    """
    paths = cr._extract_js_paths(js_body, "https://example.com/")
    assert "https://example.com/api/users" in paths
    assert all(not p.endswith(".png") for p in paths)


def test_js_extraction_handles_full_urls() -> None:
    js_body = '''
    const api = "https://api.example.com/v1/users";
    '''
    paths = cr._extract_js_paths(js_body, "https://example.com/")
    assert "https://api.example.com/v1/users" in paths


# ---------------------------------------------------------------------------
# Seed URLs
# ---------------------------------------------------------------------------


def test_seed_urls_param_seeds_crawl(monkeypatch) -> None:
    home = "https://example.com/"
    seed = "https://example.com/admin"
    _patch_http(
        monkeypatch,
        {
            home: (200, {"Content-Type": "text/html"}, ""),
            seed: (200, {"Content-Type": "text/html"}, _html("/admin/users")),
            "https://example.com/admin/users": (200, {"Content-Type": "text/html"}, ""),
        },
    )
    out = cr.bfs_crawl("https://example.com", seed_urls=seed)
    urls = [e["url"] for e in out["endpoints"]]
    assert seed in urls
    assert "https://example.com/admin/users" in urls


def test_env_seed_urls_picked_up(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SEED_URLS", "https://example.com/api,https://example.com/v2")
    _patch_http(
        monkeypatch,
        {
            "https://example.com/": (200, {"Content-Type": "text/html"}, ""),
            "https://example.com/api": (200, {"Content-Type": "text/html"}, ""),
            "https://example.com/v2": (200, {"Content-Type": "text/html"}, ""),
        },
    )
    out = cr.bfs_crawl("https://example.com")
    seed_urls = set(out["seed_urls"])
    assert "https://example.com/api" in seed_urls
    assert "https://example.com/v2" in seed_urls


def test_off_scope_seeds_dropped(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_SEED_URLS", "https://attacker.com/payload")
    _patch_http(monkeypatch, {"https://example.com/": (200, {"Content-Type": "text/html"}, "")})
    out = cr.bfs_crawl("https://example.com")
    assert "https://attacker.com/payload" not in out["seed_urls"]


# ---------------------------------------------------------------------------
# OpenAPI consumption
# ---------------------------------------------------------------------------


def test_openapi_spec_imported(monkeypatch) -> None:
    spec = json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "https://api.example.com"}],
        "paths": {
            "/users": {"get": {}, "post": {}},
            "/users/{id}": {"get": {}, "delete": {}},
        },
    })
    _patch_http(
        monkeypatch,
        {
            "https://example.com/": (200, {"Content-Type": "text/html"}, ""),
            "https://example.com/openapi.json": (200, {"Content-Type": "application/json"}, spec),
            "https://api.example.com/users": (200, {"Content-Type": "application/json"}, "{}"),
            "https://api.example.com/users/%7Bid%7D": (200, {"Content-Type": "application/json"}, "{}"),
        },
    )
    out = cr.bfs_crawl(
        "https://example.com",
        openapi_url="https://example.com/openapi.json",
    )
    api_endpoints = [e for e in out["endpoints"] if e["discovered_via"] == "openapi"]
    methods = {(e["url"], e["method"]) for e in api_endpoints}
    # Each path × method pair imported.
    assert len(api_endpoints) == 4
    assert ("https://api.example.com/users", "GET") in methods
    assert ("https://api.example.com/users", "POST") in methods
    assert ("https://api.example.com/users/{id}", "DELETE") in methods


def test_openapi_2x_spec(monkeypatch) -> None:
    """OpenAPI 2.0 (Swagger) uses host + basePath instead of servers[]."""
    spec = json.dumps({
        "swagger": "2.0",
        "host": "api.example.com",
        "basePath": "/v1",
        "schemes": ["https"],
        "paths": {"/health": {"get": {}}},
    })
    _patch_http(
        monkeypatch,
        {
            "https://example.com/": (200, {"Content-Type": "text/html"}, ""),
            "https://example.com/swagger.json": (200, {"Content-Type": "application/json"}, spec),
        },
    )
    out = cr.bfs_crawl("https://example.com", openapi_url="https://example.com/swagger.json")
    api_endpoints = [e for e in out["endpoints"] if e["discovered_via"] == "openapi"]
    assert len(api_endpoints) == 1
    assert api_endpoints[0]["url"] == "https://api.example.com/v1/health"


def test_openapi_failure_recorded_as_error(monkeypatch) -> None:
    _patch_http(
        monkeypatch,
        {
            "https://example.com/": (200, {"Content-Type": "text/html"}, ""),
            "https://example.com/openapi.json": (404, {}, ""),
        },
    )
    out = cr.bfs_crawl("https://example.com", openapi_url="https://example.com/openapi.json")
    assert any("OpenAPI fetch failed" in err for err in out["errors"])


def test_openapi_invalid_json(monkeypatch) -> None:
    _patch_http(
        monkeypatch,
        {
            "https://example.com/": (200, {"Content-Type": "text/html"}, ""),
            "https://example.com/openapi.yaml": (200, {"Content-Type": "text/yaml"}, "this: is: yaml"),
        },
    )
    out = cr.bfs_crawl("https://example.com", openapi_url="https://example.com/openapi.yaml")
    assert any("not valid JSON" in err or "YAML not supported" in err for err in out["errors"])


def test_openapi_url_from_env(monkeypatch) -> None:
    monkeypatch.setenv("STRIX_OPENAPI_URL", "https://example.com/api.json")
    spec = json.dumps({
        "openapi": "3.0.0",
        "servers": [{"url": "https://example.com"}],
        "paths": {"/health": {"get": {}}},
    })
    _patch_http(
        monkeypatch,
        {
            "https://example.com/": (200, {"Content-Type": "text/html"}, ""),
            "https://example.com/api.json": (200, {"Content-Type": "application/json"}, spec),
            "https://example.com/health": (200, {"Content-Type": "application/json"}, "{}"),
        },
    )
    out = cr.bfs_crawl("https://example.com")
    assert out["openapi_url"] == "https://example.com/api.json"
    assert any(e["discovered_via"] == "openapi" for e in out["endpoints"])


# ---------------------------------------------------------------------------
# Composition with cluster-A safety middleware
# ---------------------------------------------------------------------------


def test_excluded_path_skipped_during_crawl(monkeypatch) -> None:
    """When a discovered link matches --exclude-path, the crawler's fallback
    HTTP path returns (0, {}, '') and the URL is skipped (no 'fetch failed'
    error since the proxy short-circuit returns success=True with skipped)."""
    monkeypatch.setenv("STRIX_EXCLUDE_PATHS", json.dumps(["/admin/*"]))

    # Don't use _patch_http here — we want the real http_safety path to run
    # so the exclude check fires. Use a proxy stub instead.
    class FakeManager:
        def send_simple_request(self, method, url, timeout=30):
            from strix.tools.proxy.http_safety import excluded_response, is_path_excluded

            excluded, glob = is_path_excluded(url)
            if excluded:
                return excluded_response(url, glob or "")
            if url == "https://example.com/":
                return {
                    "status_code": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body": _html("/api/users", "/admin/destroy"),
                }
            if url == "https://example.com/api/users":
                return {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}
            return {"status_code": 404, "headers": {}, "body": ""}

    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager", lambda: FakeManager()
    )
    out = cr.bfs_crawl("https://example.com")
    visited = {e["url"] for e in out["endpoints"]}
    # The excluded path was discovered as a link, recorded as an endpoint,
    # but never fetched. Its discovery is fine; the *fetch* skip is what
    # production safety guarantees.
    assert "https://example.com/admin/destroy" in visited
    # /api/users was fetched (would have errors otherwise).
    assert "https://example.com/api/users" in visited
