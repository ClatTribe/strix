"""Tests for the refresh CLI."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from strix.threat_intel import cache as ti_cache
from strix.threat_intel.refresh import main as refresh_main


@pytest.fixture
def tmp_cache(tmp_path, monkeypatch):
    db = tmp_path / "ti.db"
    monkeypatch.setenv("STRIX_THREAT_INTEL_CACHE", str(db))
    ti_cache.reset_for_testing(db)
    yield db


def test_refresh_status_only(tmp_cache, capsys) -> None:
    rc = refresh_main(["--status"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Cache:" in out
    assert "Totals:" in out


def test_refresh_unknown_feed(tmp_cache, capsys) -> None:
    rc = refresh_main(["--only", "definitelynotafeed"])
    assert rc == 2


def test_refresh_kev_success(tmp_cache, monkeypatch) -> None:
    """Mock KEV poll so the CLI runs end-to-end without network."""
    def fake_poll_kev(**_kw):
        ti_cache.record_feed_status("kev", status="ok", record_count=42)
        return {"status": "ok", "ingested": 42, "catalog_version": "x",
                "release_date": "2024-09-04", "error": None}

    monkeypatch.setattr(
        "strix.threat_intel.refresh.poll_kev", fake_poll_kev,
    )
    rc = refresh_main(["--only", "kev"])
    assert rc == 0
    feeds = ti_cache.fetch_feed_meta()
    assert any(f["feed_name"] == "kev" and f["status"] == "ok" for f in feeds)


def test_refresh_one_feed_failure_returns_nonzero(tmp_cache, monkeypatch) -> None:
    monkeypatch.setattr(
        "strix.threat_intel.refresh.poll_kev",
        lambda **_kw: {"status": "error", "ingested": 0, "error": "bad"},
    )
    rc = refresh_main(["--only", "kev"])
    assert rc == 1
