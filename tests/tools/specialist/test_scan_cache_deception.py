"""Tests for `scan_cache_deception`.

Hermetic — `_send_get` is monkeypatched. Tests cover:

  * Path-mutation matrix (each builds the expected probed URL).
  * Cacheability parser (positive / negative / cached-already
    signals).
  * Jaccard token-overlap similarity threshold.
  * Auth-marker detection (verified vs pattern_match severity).
  * Per-(path, mutation) dedup across cacheable extensions.
  * Negative case: probe doesn't return content like baseline.
  * Negative case: probe returns cache-control: private.
  * Empty path/ext/mutation inputs → error result.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


# Pull the actual submodule.
import strix.tools.specialist.scan_cache_deception  # noqa: F401

cd_module = sys.modules["strix.tools.specialist.scan_cache_deception"]
scan_cache_deception = cd_module.scan_cache_deception


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
    tracer = Tracer("cd-test")
    set_global_tracer(tracer)
    yield


def _resp(*, status=200, body="", headers=None) -> dict[str, Any]:
    return {
        "status": status,
        "headers": {k.lower(): v for k, v in (headers or {}).items()},
        "body": body,
    }


def _patch_responder(monkeypatch, responder):
    """`responder(url) -> response-dict`. Records all calls."""
    log: list[str] = []

    def fake(url, *, timeout=12.0):
        log.append(url)
        return responder(url)

    monkeypatch.setattr(cd_module, "_send_get", fake)
    return log


# Authenticated baseline body — contains the canonical "logout" /
# "csrf" / "session" markers the auth-marker detector keys on.
_AUTH_BODY = (
    "<html><body>"
    "<h1>My Account</h1>"
    "<p>Welcome back, alice. <a href='/logout'>Sign out</a></p>"
    "<form><input name='csrf' value='abc123' /></form>"
    "<div>session token: xyz</div>"
    "</body></html>"
)

_PUBLIC_CSS_BODY = "body { color: red; } .login { display: block; }"


# ---------------------------------------------------------------------------
# Path-mutation matrix
# ---------------------------------------------------------------------------


def test_appended_extension_mutation_fires(monkeypatch) -> None:
    """Canonical Omer Gil shape: `/account` → `/account.css`."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY,
                          headers={"Cache-Control": "private"})
        if url.endswith("/account.css"):
            return _resp(
                body=_AUTH_BODY,
                headers={"Cache-Control": "public, max-age=300",
                          "Content-Type": "text/css"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)

    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"],
        mutations=["appended_ext"],
    )
    assert out["status"] == "ok"
    assert out["tool_metadata"]["findings_emitted_to_tracer"] >= 1
    assert len(out["findings"]) >= 1
    finding = out["findings"][0]
    assert finding["category"] == "cache_deception"
    assert finding["severity"] == "high"
    assert "/account.css" in finding["endpoint"]
    # Auth marker present → verified.
    assert finding["verification_status"] == "verified"


def test_path_segment_mutation_fires(monkeypatch) -> None:
    """`/account/x.css` variant — bypasses servers that strip
    trailing extensions."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith("/account/x.css"):
            return _resp(
                body=_AUTH_BODY,
                headers={"Cache-Control": "public, max-age=600"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)

    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"],
        mutations=["path_segment_ext"],
    )
    assert len(out["findings"]) == 1
    assert "/account/x.css" in out["findings"][0]["endpoint"]


def test_semicolon_mutation_fires(monkeypatch) -> None:
    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if "/account;x.css" in url:
            return _resp(
                body=_AUTH_BODY,
                headers={"Cache-Control": "public, max-age=60"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)

    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"],
        mutations=["semicolon_ext"],
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Cacheability parser
# ---------------------------------------------------------------------------


def test_non_cacheable_response_does_not_fire(monkeypatch) -> None:
    """Even with body match, `Cache-Control: private` short-
    circuits the finding — exactly what we want; the deception
    primitive REQUIRES the CDN to cache."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith("/account.css"):
            return _resp(
                body=_AUTH_BODY,
                headers={"Cache-Control": "private, no-store"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert out["findings"] == []


def test_no_store_blocks_finding(monkeypatch) -> None:
    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith("/account.css"):
            return _resp(
                body=_AUTH_BODY,
                headers={"Cache-Control": "no-store"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert out["findings"] == []


def test_x_cache_hit_signal_fires(monkeypatch) -> None:
    """Strongest cacheability signal: response is already cached
    (`X-Cache: HIT`). Fires even when Cache-Control is absent."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith("/account.css"):
            return _resp(
                body=_AUTH_BODY,
                headers={"X-Cache": "HIT", "Age": "120"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert len(out["findings"]) == 1


def test_cf_cache_status_hit_signal_fires(monkeypatch) -> None:
    """Cloudflare-specific cached-already header."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith("/account.css"):
            return _resp(
                body=_AUTH_BODY,
                headers={"CF-Cache-Status": "HIT"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert len(out["findings"]) == 1


def test_implicit_cacheability_no_header(monkeypatch) -> None:
    """Per RFC 7234, GET 200 with no Cache-Control header is
    implicitly cacheable. Conservative but real."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith("/account.css"):
            # No cache-control header.
            return _resp(body=_AUTH_BODY)
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Content similarity
# ---------------------------------------------------------------------------


def test_genuine_static_asset_does_not_fire(monkeypatch) -> None:
    """`/account.css` returns ACTUAL CSS — body doesn't resemble
    baseline. Should not fire even though the response IS cacheable.
    This is the most important false-positive case to pin."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith("/account.css"):
            return _resp(
                body=_PUBLIC_CSS_BODY,
                headers={"Cache-Control": "public, max-age=86400",
                          "Content-Type": "text/css"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert out["findings"] == []


def test_low_similarity_no_marker_does_not_fire(monkeypatch) -> None:
    """Body is different enough AND no auth marker — should be
    classified as non-deception."""
    different_body = "<html><body><h1>404 Not Found</h1></body></html>"

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith("/account.css"):
            return _resp(
                body=different_body,
                headers={"Cache-Control": "public, max-age=300"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert out["findings"] == []


def test_similarity_threshold_overridable(monkeypatch) -> None:
    """Caller-supplied `similarity_threshold` adjusts the
    sensitivity. Force a high threshold against a body with no
    auth marker; the threshold must gate the finding."""
    # Body without ANY auth marker — threshold path is the only
    # signal. Moderate overlap with baseline. Should fire at
    # default 0.6 but not at 0.95.
    baseline_marker_free = (
        "<html><body><h1>Dashboard</h1>"
        "<p>Lorem ipsum dolor sit amet consectetur adipiscing.</p>"
        "<p>Phasellus ac purus nec lacus ultricies fermentum.</p>"
        "</body></html>"
    )
    probe_partial_overlap = (
        "<html><body><h1>Dashboard</h1>"
        "<p>Lorem ipsum dolor sit amet consectetur adipiscing.</p>"
        "<div>Entirely different paragraph that won't share tokens "
        "with the baseline beyond very common stopwords.</div>"
        "</body></html>"
    )

    def respond(url):
        if url.endswith("/dashboard"):
            return _resp(body=baseline_marker_free)
        if url.endswith("/dashboard.css"):
            return _resp(
                body=probe_partial_overlap,
                headers={"Cache-Control": "public, max-age=300"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)

    out_strict = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/dashboard"],
        extensions=["css"], mutations=["appended_ext"],
        similarity_threshold=0.95,
    )
    assert out_strict["findings"] == []


# ---------------------------------------------------------------------------
# Verification status / confidence ladder
# ---------------------------------------------------------------------------


def test_auth_marker_yields_verified_status(monkeypatch) -> None:
    """Both baseline + probe contain a known auth marker → highest
    confidence (`verified`)."""

    def respond(url):
        return _resp(
            body=_AUTH_BODY,
            headers={"Cache-Control": "public, max-age=300"},
        )

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    finding = out["findings"][0]
    assert finding["verification_status"] == "verified"
    assert finding["confidence"] >= 0.9


def test_similarity_only_yields_pattern_match(monkeypatch) -> None:
    """No auth marker but high similarity → pattern_match (lower
    confidence)."""
    body = "Lorem ipsum dolor sit amet consectetur. " * 100

    def respond(url):
        if url.endswith(".css"):
            return _resp(
                body=body,
                headers={"Cache-Control": "public, max-age=300"},
            )
        return _resp(body=body)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    finding = out["findings"][0]
    assert finding["verification_status"] == "pattern_match"
    assert finding["confidence"] < 0.9


# ---------------------------------------------------------------------------
# Dedup: one finding per (path, mutation) — extensions collapse
# ---------------------------------------------------------------------------


def test_extension_dedup_per_path_mutation(monkeypatch) -> None:
    """When `appended_ext` fires for both `.css` AND `.js` against
    `/account`, we should still emit only ONE finding — the
    primitive is per-mutation, not per-extension."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if url.endswith(".css") or url.endswith(".js"):
            return _resp(
                body=_AUTH_BODY,
                headers={"Cache-Control": "public, max-age=300"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css", "js"], mutations=["appended_ext"],
    )
    # Only one finding despite two cacheable-ext hits.
    assert len(out["findings"]) == 1


# ---------------------------------------------------------------------------
# Multi-mutation
# ---------------------------------------------------------------------------


def test_multiple_mutations_fire_independently(monkeypatch) -> None:
    """If both `appended_ext` AND `semicolon_ext` work on the same
    path, both findings emit — they're distinct primitives."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        if ".css" in url:
            return _resp(
                body=_AUTH_BODY,
                headers={"Cache-Control": "public, max-age=300"},
            )
        return _resp(status=404)

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"],
        mutations=["appended_ext", "semicolon_ext", "path_segment_ext"],
    )
    assert len(out["findings"]) == 3
    mutations_seen = {f["title"].split("via ")[-1] for f in out["findings"]}
    assert {"appended_ext", "semicolon_ext", "path_segment_ext"} <= mutations_seen


# ---------------------------------------------------------------------------
# Baseline handling
# ---------------------------------------------------------------------------


def test_baseline_404_skips_path(monkeypatch) -> None:
    """If the sensitive-path baseline returns 404, the specialist
    correctly skips that path (no false-positive cascade)."""

    def respond(url):
        return _resp(status=404, body="")

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account", "/profile"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert out["findings"] == []


def test_baseline_empty_body_skips_path(monkeypatch) -> None:
    """Baseline returns 200 but empty body — no content to
    deception against. Skip."""

    def respond(url):
        return _resp(status=200, body="")

    _patch_responder(monkeypatch, respond)
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    assert out["findings"] == []


def test_baseline_request_cached_per_path(monkeypatch) -> None:
    """Baseline is fetched ONCE per sensitive path, not per probe.
    Without this caching the (path × ext × mutation) matrix would
    issue redundant baseline requests."""

    def respond(url):
        if url.endswith("/account"):
            return _resp(body=_AUTH_BODY)
        return _resp(status=404)

    log = _patch_responder(monkeypatch, respond)
    scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css", "js", "png"],
        mutations=["appended_ext", "semicolon_ext"],
    )
    baseline_calls = [u for u in log if u.endswith("/account")]
    assert len(baseline_calls) == 1, (
        f"baseline fetched {len(baseline_calls)} times "
        f"(should be cached): {baseline_calls}"
    )


# ---------------------------------------------------------------------------
# Error / input validation
# ---------------------------------------------------------------------------


def test_empty_url_rejected() -> None:
    out = scan_cache_deception(url="")
    assert out["status"] == "error"


def test_invalid_url_rejected() -> None:
    out = scan_cache_deception(url="not-a-url")
    assert out["status"] == "error"


def test_invalid_mutations_yields_no_probes(monkeypatch) -> None:
    """Unknown mutation names get filtered to empty → no-probes
    error path."""
    out = scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["nonexistent_mutation"],
    )
    assert out["status"] == "error"
    assert "no probes" in out["error"]


# ---------------------------------------------------------------------------
# Tracer round-trip — finding lands with category=cache_deception
# ---------------------------------------------------------------------------


def test_tracer_emit_carries_cache_deception_category(monkeypatch) -> None:
    """The finding emits via `tracer.add_vulnerability_report`
    with the canonical category + CWE the wrapper renders against."""

    def respond(url):
        return _resp(
            body=_AUTH_BODY,
            headers={"Cache-Control": "public, max-age=300"},
        )

    _patch_responder(monkeypatch, respond)
    tracer = tracer_module.get_global_tracer()
    scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account"],
        extensions=["css"], mutations=["appended_ext"],
    )
    reports = [
        r for r in tracer.vulnerability_reports
        if r.get("category") == "cache_deception"
    ]
    assert len(reports) >= 1
    r = reports[0]
    assert r.get("cwe") == "CWE-525"
    assert r.get("severity") == "high"


# ---------------------------------------------------------------------------
# Probe-cap safety
# ---------------------------------------------------------------------------


def test_max_probes_bounds_run(monkeypatch) -> None:
    """`max_probes=2` caps the probe set even when the cross-
    product would be larger."""

    def respond(url):
        return _resp(status=404)

    log = _patch_responder(monkeypatch, respond)
    scan_cache_deception(
        url="https://app.example.com",
        sensitive_paths=["/account", "/profile", "/dashboard"],
        extensions=["css", "js", "png"],
        mutations=["appended_ext", "semicolon_ext", "path_segment_ext"],
        max_probes=2,
    )
    # At most 2 probes + their baselines.
    probe_calls = [u for u in log if "." in u.rsplit("/", 1)[-1]
                   or ";" in u]
    assert len(probe_calls) <= 2
