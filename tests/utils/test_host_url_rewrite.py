"""iter-Q5.23 — pin the host-side docker-alias → loopback rewrite.

Background in `strix/utils/host_url_rewrite.py`. These tests are
load-bearing for the cure that lets `fingerprint_tech_stack` and
`openapi_spec_ingest` (both `sandbox_execution=False`) actually probe
fixtures whose URLs use `host.docker.internal` (the form the bench
hands sandbox-routed tools post iter-Q5.21).
"""

from __future__ import annotations

import pytest

from strix.utils.host_url_rewrite import to_host_loopback, to_host_loopback_host


# ---------------------------------------------------------------------------
# to_host_loopback — full URL rewriting
# ---------------------------------------------------------------------------


def test_rewrites_basic_http_url() -> None:
    """The vampi-shaped case: docker host-gateway URL → loopback."""
    got = to_host_loopback("http://host.docker.internal:5001")
    assert got == "http://127.0.0.1:5001"


def test_rewrites_https_url() -> None:
    """Scheme is preserved exactly."""
    got = to_host_loopback("https://host.docker.internal/api")
    assert got == "https://127.0.0.1/api"


def test_preserves_path_query_fragment() -> None:
    """The juiceshop-shaped case: nontrivial path + query."""
    got = to_host_loopback(
        "http://host.docker.internal:3001/rest/products?q=apple#frag"
    )
    assert got == "http://127.0.0.1:3001/rest/products?q=apple#frag"


def test_preserves_userinfo() -> None:
    """userinfo in netloc — preserved through the rewrite."""
    got = to_host_loopback("http://user:pw@host.docker.internal:8080/x")
    assert got == "http://user:pw@127.0.0.1:8080/x"


def test_preserves_username_only() -> None:
    got = to_host_loopback("http://user@host.docker.internal/x")
    assert got == "http://user@127.0.0.1/x"


def test_preserves_default_port() -> None:
    """No explicit port — none added on rewrite."""
    got = to_host_loopback("http://host.docker.internal/")
    assert got == "http://127.0.0.1/"


def test_leaves_real_hostnames_unchanged() -> None:
    """Real domains must pass through untouched — the rewrite is
    only for the docker host-gateway alias."""
    inputs = [
        "https://example.com/path",
        "http://api.example.com:8080/",
        "https://127.0.0.1:3000/",
        "http://localhost:5000/api",
    ]
    for url in inputs:
        assert to_host_loopback(url) == url, url


def test_empty_string_passthrough() -> None:
    """Defensive — empty / None inputs pass through cleanly so
    callers don't have to pre-check."""
    assert to_host_loopback("") == ""


@pytest.mark.parametrize("bad", [None, 123, [], {}, object()])
def test_non_string_passthrough(bad: object) -> None:
    """Non-string inputs (or None) return unchanged — no crash."""
    assert to_host_loopback(bad) is bad  # type: ignore[arg-type]


def test_does_not_rewrite_substring_match_in_path() -> None:
    """`host.docker.internal` appearing in the PATH (not netloc) is
    not a hostname collision — leave it alone."""
    url = "http://example.com/lookup?host=host.docker.internal"
    assert to_host_loopback(url) == url


def test_handles_malformed_url_gracefully() -> None:
    """A URL urlparse can't decompose — return verbatim. Don't crash."""
    bad = "not://[a url at all"
    # Don't assert exact return value (urlparse may or may not raise);
    # only that the call doesn't itself raise.
    got = to_host_loopback(bad)
    assert isinstance(got, str)


# ---------------------------------------------------------------------------
# to_host_loopback_host — bare-hostname variant
# ---------------------------------------------------------------------------


def test_bare_hostname_alias_rewrites() -> None:
    """Bare hostname (no scheme) — used by tools that take
    `host:port` strings."""
    assert to_host_loopback_host("host.docker.internal") == "127.0.0.1"


def test_bare_hostname_with_port_rewrites() -> None:
    """Bare hostname:port form preserves the port suffix."""
    assert (
        to_host_loopback_host("host.docker.internal:6379") == "127.0.0.1:6379"
    )


def test_bare_hostname_real_passes_through() -> None:
    assert to_host_loopback_host("example.com") == "example.com"
    assert to_host_loopback_host("api.example.com:443") == "api.example.com:443"


def test_bare_hostname_empty_passthrough() -> None:
    assert to_host_loopback_host("") == ""


# ---------------------------------------------------------------------------
# Integration smoke — the rewrite is wired into both consumers
# ---------------------------------------------------------------------------


def test_fingerprint_probe_uses_rewrite(monkeypatch: pytest.MonkeyPatch) -> None:
    """`_probe_http` must apply the rewrite before issuing the HTTP
    request. Stub httpx so we can capture the URL it sees."""
    from strix.tools.recon import fingerprint

    captured_urls: list[str] = []

    class _FakeResp:
        status_code = 200

        @property
        def headers(self) -> dict[str, str]:  # type: ignore[override]
            return {}

        @property
        def text(self) -> str:  # type: ignore[override]
            return ""

    class _FakeClient:
        def __init__(self, *a, **kw) -> None:  # noqa: D401
            pass

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, *exc) -> None:
            return None

        def head(self, url: str) -> _FakeResp:
            captured_urls.append(url)
            return _FakeResp()

        def get(self, url: str, **kw) -> _FakeResp:
            captured_urls.append(url)
            return _FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "Client", _FakeClient)

    fingerprint._probe_http("http://host.docker.internal:5001/")
    # Both HEAD + GET fired with the rewritten URL.
    assert captured_urls, "expected at least one HTTP call"
    for url in captured_urls:
        assert "host.docker.internal" not in url
        assert "127.0.0.1:5001" in url


def test_openapi_ingest_fetch_uses_rewrite(monkeypatch: pytest.MonkeyPatch) -> None:
    """`_http_fetch` must apply the rewrite before httpx.get. Stub
    httpx and capture."""
    import importlib
    openapi_spec_ingest = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest"
    )

    captured_urls: list[str] = []

    class _FakeResp:
        status_code = 200
        text = "{}"

    class _FakeClient:
        def __init__(self, *a, **kw) -> None:  # noqa: D401
            pass

        def __enter__(self) -> "_FakeClient":
            return self

        def __exit__(self, *exc) -> None:
            return None

        def get(self, url: str, **kw) -> _FakeResp:
            captured_urls.append(url)
            return _FakeResp()

    import httpx
    monkeypatch.setattr(httpx, "Client", _FakeClient)

    openapi_spec_ingest._http_fetch(
        "http://host.docker.internal:5001/openapi.json",
        timeout=5.0,
    )
    assert captured_urls == ["http://127.0.0.1:5001/openapi.json"]


def test_openapi_ingest_fetcher_injection_skips_rewrite() -> None:
    """When a `fetcher` is injected (test seam), the rewrite is NOT
    applied — tests own URL normalization. This pins the
    intentional bypass so it stays a documented opt-out."""
    import importlib
    openapi_spec_ingest = importlib.import_module(
        "strix.tools.openapi_ingest.openapi_spec_ingest"
    )

    seen: list[str] = []

    def _fetcher(url: str, *, timeout: float) -> tuple[int, str]:
        seen.append(url)
        return 0, ""

    openapi_spec_ingest._http_fetch(
        "http://host.docker.internal:5001/openapi.json",
        timeout=5.0,
        fetcher=_fetcher,
    )
    assert seen == ["http://host.docker.internal:5001/openapi.json"]
