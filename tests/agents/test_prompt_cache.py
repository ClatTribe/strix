"""Tests for `strix/agents/prompt_cache.py` — step 8 (final) of
the v2 cost-optimization plan (workflow phase 1 — boot).

Recall-safety contract pinned by tests:
  * Persistence is writes-only — never modifies prompt content.
  * Empty / non-string prompts return cleanly without raising.
  * Kill switch (`STRIX_PROMPT_CACHE_DISABLED=1`) skips disk
    writes + dedup detection.
  * IO errors (read-only cache dir, missing file) don't crash
    the LLM init path.
  * Stable content hash — same string in, same hash out.
  * Dedup detection — `first_seen=True` on the first call,
    `False` on subsequent identical calls; `seen_count`
    increments.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.agents import prompt_cache as pc


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("STRIX_PROMPT_CACHE_DIR", str(tmp_path / "prompts"))
    monkeypatch.delenv("STRIX_PROMPT_CACHE_DISABLED", raising=False)
    pc.clear()
    yield
    pc.clear()


# ---------------------------------------------------------------------------
# content_hash — stable + deterministic
# ---------------------------------------------------------------------------


def test_content_hash_is_stable() -> None:
    h1 = pc.content_hash("hello world")
    h2 = pc.content_hash("hello world")
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_content_hash_differs_on_different_content() -> None:
    assert pc.content_hash("a") != pc.content_hash("b")


def test_content_hash_empty_returns_empty() -> None:
    assert pc.content_hash("") == ""
    assert pc.content_hash(None) == ""  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# persist — first-seen detection + dedup
# ---------------------------------------------------------------------------


def test_persist_first_call_writes_file() -> None:
    stats = pc.persist(prompt="hello world", scan_mode="standard")
    assert stats["first_seen"] is True
    assert stats["seen_count"] == 1
    assert stats["byte_size"] == len("hello world")
    assert Path(stats["path"]).exists()
    assert Path(stats["path"]).read_text() == "hello world"


def test_persist_repeat_call_increments_seen_count() -> None:
    pc.persist(prompt="hello world")
    stats = pc.persist(prompt="hello world")
    assert stats["first_seen"] is False
    assert stats["seen_count"] == 2


def test_persist_different_prompts_get_different_files() -> None:
    s1 = pc.persist(prompt="prompt A")
    s2 = pc.persist(prompt="prompt B")
    assert s1["hash"] != s2["hash"]
    assert s1["path"] != s2["path"]
    assert Path(s1["path"]).exists()
    assert Path(s2["path"]).exists()


def test_persist_metadata_accumulates_targets_and_modes(
    tmp_path: Path,
) -> None:
    pc.persist(prompt="same", target="https://a.com", scan_mode="quick", role="lead")
    pc.persist(prompt="same", target="https://b.com", scan_mode="standard", role="lead")
    pc.persist(prompt="same", target="https://b.com", scan_mode="standard", role="specialist")
    idx = json.loads((pc._cache_root() / "index.json").read_text())
    h = pc.content_hash("same")
    entry = idx[h]
    assert entry["seen_count"] == 3
    assert set(entry["targets"]) == {"https://a.com", "https://b.com"}
    assert set(entry["scan_modes"]) == {"quick", "standard"}
    assert set(entry["roles"]) == {"lead", "specialist"}


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------


def test_lookup_returns_persisted_content() -> None:
    stats = pc.persist(prompt="round-trip me")
    back = pc.lookup(stats["hash"])
    assert back == "round-trip me"


def test_lookup_miss_returns_none() -> None:
    assert pc.lookup("0" * 64) is None
    assert pc.lookup("") is None
    assert pc.lookup(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Empty / invalid inputs
# ---------------------------------------------------------------------------


def test_persist_empty_prompt_returns_no_op() -> None:
    stats = pc.persist(prompt="")
    assert stats["path"] is None
    assert stats["seen_count"] == 0
    assert stats["byte_size"] == 0


def test_persist_non_string_returns_no_op() -> None:
    stats = pc.persist(prompt=12345)  # type: ignore[arg-type]
    assert stats["path"] is None


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_skips_disk_write(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_PROMPT_CACHE_DISABLED", "1")
    stats = pc.persist(prompt="hello")
    assert stats["disabled"] is True
    assert stats["path"] is None
    # No files written
    root = pc._cache_root()
    if root.exists():
        assert list(root.glob("*.txt")) == []


def test_kill_switch_disables_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    stats = pc.persist(prompt="hello")
    monkeypatch.setenv("STRIX_PROMPT_CACHE_DISABLED", "1")
    assert pc.lookup(stats["hash"]) is None


# ---------------------------------------------------------------------------
# Recall-safety: persistence does NOT mutate the prompt
# ---------------------------------------------------------------------------


def test_persist_does_not_mutate_input() -> None:
    """Critical canary — this module is writes-only. The
    persisted file must be byte-identical to what was passed in.
    A re-render bug here would silently change what the LLM
    sees."""
    original = (
        "You are a security specialist. " * 100
        + "\n\nObjective: probe SQLi on /api/users/{id}."
    )
    stats = pc.persist(prompt=original)
    assert Path(stats["path"]).read_text() == original


# ---------------------------------------------------------------------------
# stats + clear
# ---------------------------------------------------------------------------


def test_stats_tracks_entries_and_seen_count() -> None:
    pc.persist(prompt="A")
    pc.persist(prompt="A")
    pc.persist(prompt="B")
    s = pc.stats()
    assert s["entries"] == 2
    assert s["total_seen_count"] == 3
    assert s["total_byte_size"] == 2  # "A" + "B"


def test_clear_removes_all_entries() -> None:
    pc.persist(prompt="A")
    pc.persist(prompt="B")
    removed = pc.clear()
    assert removed == 2
    assert pc.stats()["entries"] == 0
    # Index file also gone
    assert not (pc._cache_root() / "index.json").exists()


# ---------------------------------------------------------------------------
# IO errors fall through silently
# ---------------------------------------------------------------------------


def test_corrupt_index_falls_through_to_empty(tmp_path: Path) -> None:
    """A corrupt index.json must NEVER crash persist(); it
    should be treated as an empty index and the entry written
    fresh."""
    pc.persist(prompt="seed entry")
    (pc._cache_root() / "index.json").write_text("not valid json")
    # Re-persisting a new prompt should still succeed
    stats = pc.persist(prompt="new entry")
    assert stats["path"] is not None
    assert Path(stats["path"]).exists()
