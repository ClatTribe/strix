"""Tests for `strix/agents/recon_cache.py` — step 5 of the v2
cost-optimization plan (workflow phase 2 — recon).

Recall-safety contract pinned by tests:
  * Only successful runs cache; failed runs always re-run.
  * Different scan_mode = different cache entry (deep doesn't
    replay quick's recon, and vice versa).
  * Different params = different cache entry (max_pages,
    enable_* flags, etc. all factor in).
  * Expired entries miss; the pipeline re-runs.
  * Kill switch bypasses both lookup and store.
  * Bad on-disk entries (corrupt JSON, schema mismatch) miss
    safely — the pipeline re-runs rather than crashing.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from strix.agents import recon_cache as rc


@pytest.fixture(autouse=True)
def _isolate_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Every test gets a fresh cache directory under tmp_path."""
    monkeypatch.setenv("STRIX_RECON_CACHE_DIR", str(tmp_path / "recon_cache"))
    monkeypatch.delenv("STRIX_RECON_CACHE_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_SCAN_MODE", raising=False)
    rc.clear()
    yield
    rc.clear()


# ---------------------------------------------------------------------------
# Target normalization
# ---------------------------------------------------------------------------


def test_normalize_target_strips_default_ports() -> None:
    assert rc._normalize_target("https://example.com:443/") == "https://example.com"
    assert rc._normalize_target("http://example.com:80/foo") == "http://example.com/foo"


def test_normalize_target_keeps_nondefault_ports() -> None:
    assert rc._normalize_target("https://example.com:8443/api") == "https://example.com:8443/api"


def test_normalize_target_lowercases_host_scheme() -> None:
    assert rc._normalize_target("HTTPS://Example.COM/PATH") == "https://example.com/PATH"


def test_normalize_target_strips_trailing_slash() -> None:
    assert rc._normalize_target("https://example.com/foo/") == "https://example.com/foo"
    assert rc._normalize_target("https://example.com/") == "https://example.com"


def test_normalize_target_assumes_https_when_scheme_missing() -> None:
    assert rc._normalize_target("example.com/path") == "https://example.com/path"


def test_normalize_target_handles_empty() -> None:
    assert rc._normalize_target("") == ""
    assert rc._normalize_target(None) == ""


# ---------------------------------------------------------------------------
# make_key — same shape = same key, different shape = different key
# ---------------------------------------------------------------------------


def test_make_key_stable_across_calls() -> None:
    k1 = rc.make_key(
        pipeline="webapp_recon_pipeline",
        target_url="https://example.com",
        params={"max_pages": 200, "max_depth": 3},
        scan_mode="standard",
    )
    k2 = rc.make_key(
        pipeline="webapp_recon_pipeline",
        target_url="https://example.com",
        params={"max_depth": 3, "max_pages": 200},  # dict order shouldn't matter
        scan_mode="standard",
    )
    assert k1 == k2


def test_make_key_normalizes_target() -> None:
    k1 = rc.make_key(
        pipeline="webapp_recon_pipeline",
        target_url="https://example.com:443/",
        params={"max_pages": 200},
        scan_mode="standard",
    )
    k2 = rc.make_key(
        pipeline="webapp_recon_pipeline",
        target_url="HTTPS://Example.COM/",
        params={"max_pages": 200},
        scan_mode="standard",
    )
    assert k1 == k2


def test_make_key_differs_on_pipeline() -> None:
    k1 = rc.make_key(pipeline="webapp_recon_pipeline", target_url="https://x")
    k2 = rc.make_key(pipeline="domain_recon_pipeline", target_url="https://x")
    assert k1 != k2


def test_make_key_differs_on_scan_mode() -> None:
    k1 = rc.make_key(pipeline="p", target_url="https://x", scan_mode="quick")
    k2 = rc.make_key(pipeline="p", target_url="https://x", scan_mode="deep")
    assert k1 != k2


def test_make_key_differs_on_params() -> None:
    k1 = rc.make_key(pipeline="p", target_url="https://x", params={"max_pages": 200})
    k2 = rc.make_key(pipeline="p", target_url="https://x", params={"max_pages": 500})
    assert k1 != k2


# ---------------------------------------------------------------------------
# put / get round-trip
# ---------------------------------------------------------------------------


def _sample_result() -> dict:
    return {
        "success": True,
        "target_url": "https://example.com",
        "surface_map": {"endpoints": ["/", "/api", "/login"]},
    }


def test_put_then_get_returns_cached_result() -> None:
    stored = rc.put(
        pipeline="webapp_recon_pipeline",
        target_url="https://example.com",
        result=_sample_result(),
        params={"max_pages": 200},
        scan_mode="standard",
    )
    assert stored is True
    hit = rc.get(
        pipeline="webapp_recon_pipeline",
        target_url="https://example.com",
        params={"max_pages": 200},
        scan_mode="standard",
    )
    assert hit is not None
    assert hit["surface_map"]["endpoints"] == ["/", "/api", "/login"]


def test_get_miss_on_fresh_cache() -> None:
    hit = rc.get(
        pipeline="webapp_recon_pipeline",
        target_url="https://example.com",
        params={"max_pages": 200},
        scan_mode="standard",
    )
    assert hit is None


# ---------------------------------------------------------------------------
# Recall-safety: failed runs never cache
# ---------------------------------------------------------------------------


def test_put_rejects_failed_run() -> None:
    stored = rc.put(
        pipeline="webapp_recon_pipeline",
        target_url="https://example.com",
        result={"success": False, "error": "timeout"},
    )
    assert stored is False
    # And nothing landed on disk:
    assert rc.stats()["entries"] == 0


def test_put_rejects_non_dict_result() -> None:
    assert rc.put(
        pipeline="p", target_url="https://x", result="not a dict",  # type: ignore[arg-type]
    ) is False
    assert rc.put(
        pipeline="p", target_url="https://x", result=None,  # type: ignore[arg-type]
    ) is False


def test_put_rejects_empty_target() -> None:
    assert rc.put(
        pipeline="p", target_url="", result=_sample_result(),
    ) is False


# ---------------------------------------------------------------------------
# Recall-safety: different shapes never share a cache entry
# ---------------------------------------------------------------------------


def test_get_miss_on_different_scan_mode() -> None:
    rc.put(
        pipeline="p", target_url="https://example.com",
        result=_sample_result(), scan_mode="quick",
    )
    # deep scan should NOT replay quick's recon
    assert rc.get(
        pipeline="p", target_url="https://example.com", scan_mode="deep",
    ) is None


def test_get_miss_on_different_params() -> None:
    rc.put(
        pipeline="p", target_url="https://example.com",
        result=_sample_result(), params={"max_pages": 200},
    )
    assert rc.get(
        pipeline="p", target_url="https://example.com",
        params={"max_pages": 500},  # different depth → miss
    ) is None


def test_get_miss_on_different_pipeline() -> None:
    rc.put(
        pipeline="webapp_recon_pipeline", target_url="https://example.com",
        result=_sample_result(),
    )
    assert rc.get(
        pipeline="domain_recon_pipeline", target_url="https://example.com",
    ) is None


# ---------------------------------------------------------------------------
# TTL expiry
# ---------------------------------------------------------------------------


def test_get_miss_when_entry_expired(tmp_path: Path) -> None:
    """Force a stored_at timestamp older than the TTL by writing
    the entry manually + back-dating it."""
    rc.put(
        pipeline="p", target_url="https://x",
        result=_sample_result(), ttl_hours=1,
    )
    # Find the file + back-date stored_at by 2 hours
    entries = list(Path(rc._cache_root()).glob("*.json"))
    assert len(entries) == 1
    f = entries[0]
    with f.open() as fh:
        entry = json.load(fh)
    entry["stored_at"] = time.time() - 2 * 3600  # 2 hours ago
    with f.open("w") as fh:
        json.dump(entry, fh)

    # TTL is 1h → 2h-old entry should miss
    assert rc.get(pipeline="p", target_url="https://x") is None


def test_get_hit_when_within_ttl() -> None:
    rc.put(
        pipeline="p", target_url="https://x",
        result=_sample_result(), ttl_hours=24,
    )
    hit = rc.get(pipeline="p", target_url="https://x")
    assert hit is not None


def test_get_ttl_override_can_shorten() -> None:
    """Caller can request a tighter TTL than the stored one."""
    rc.put(
        pipeline="p", target_url="https://x",
        result=_sample_result(), ttl_hours=24,
    )
    # Back-date the entry to 2h ago
    f = next(Path(rc._cache_root()).glob("*.json"))
    with f.open() as fh:
        entry = json.load(fh)
    entry["stored_at"] = time.time() - 2 * 3600
    with f.open("w") as fh:
        json.dump(entry, fh)

    # Stored with 24h TTL but caller wants only 1h freshness → miss
    assert rc.get(pipeline="p", target_url="https://x", ttl_hours=1) is None
    # But a 3h TTL would still hit
    assert rc.get(pipeline="p", target_url="https://x", ttl_hours=3) is not None


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_blocks_put(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_RECON_CACHE_DISABLED", "1")
    assert rc.put(
        pipeline="p", target_url="https://x", result=_sample_result(),
    ) is False


def test_kill_switch_blocks_get(monkeypatch: pytest.MonkeyPatch) -> None:
    rc.put(
        pipeline="p", target_url="https://x", result=_sample_result(),
    )
    monkeypatch.setenv("STRIX_RECON_CACHE_DISABLED", "1")
    assert rc.get(pipeline="p", target_url="https://x") is None


# ---------------------------------------------------------------------------
# Corrupt / malformed on-disk entries fall through to miss
# ---------------------------------------------------------------------------


def test_corrupt_json_returns_miss(tmp_path: Path) -> None:
    """A corrupt entry should NEVER crash — it should miss and
    let the pipeline re-run from scratch."""
    rc.put(pipeline="p", target_url="https://x", result=_sample_result())
    f = next(Path(rc._cache_root()).glob("*.json"))
    f.write_text("{not valid json", encoding="utf-8")
    assert rc.get(pipeline="p", target_url="https://x") is None


def test_wrong_schema_returns_miss() -> None:
    rc.put(pipeline="p", target_url="https://x", result=_sample_result())
    f = next(Path(rc._cache_root()).glob("*.json"))
    with f.open() as fh:
        entry = json.load(fh)
    entry["schema"] = "some_other_schema/v1"
    with f.open("w") as fh:
        json.dump(entry, fh)
    assert rc.get(pipeline="p", target_url="https://x") is None


# ---------------------------------------------------------------------------
# clear + stats
# ---------------------------------------------------------------------------


def test_clear_removes_all_entries() -> None:
    rc.put(pipeline="p", target_url="https://a", result=_sample_result())
    rc.put(pipeline="p", target_url="https://b", result=_sample_result())
    assert rc.stats()["entries"] == 2
    removed = rc.clear()
    assert removed == 2
    assert rc.stats()["entries"] == 0


def test_stats_reports_entries_and_size() -> None:
    rc.put(pipeline="p", target_url="https://a", result=_sample_result())
    s = rc.stats()
    assert s["entries"] == 1
    assert s["size_bytes"] > 0
