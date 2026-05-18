"""Tests for engine-wishlist §1 batch mode + §7 Researcher cache.

Hermetic — pure file I/O via tmp_path + DI'd single_target_runner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from strix.interface.batch_mode import (
    BatchManifest,
    BatchTarget,
    BatchTargetResult,
    load_target_list,
    run_batch,
)
from strix.interface.researcher_cache import (
    ResearcherCacheEntry,
    cache_path,
    invalidate_cache,
    read_cache,
    write_cache,
)


# ===========================================================================
# §1 — load_target_list
# ===========================================================================


def test_loads_valid_jsonl(tmp_path) -> None:
    p = tmp_path / "targets.jsonl"
    p.write_text(
        '{"id": "a", "type": "repository", "value": "https://x/a"}\n'
        '{"id": "b", "type": "web_application", "value": "https://x/b"}\n'
    )
    targets = load_target_list(p)
    assert len(targets) == 2
    assert targets[0].id == "a"
    assert targets[0].type == "repository"
    assert targets[1].type == "web_application"


def test_skips_blanks_and_comments(tmp_path) -> None:
    p = tmp_path / "t.jsonl"
    p.write_text(
        "# this is a comment\n"
        "\n"
        '{"id": "a", "type": "repository", "value": "https://x/a"}\n'
        "  \n"
    )
    targets = load_target_list(p)
    assert len(targets) == 1


def test_carries_metadata(tmp_path) -> None:
    p = tmp_path / "t.jsonl"
    p.write_text(
        '{"id": "a", "type": "repository", "value": "https://x", '
        '"metadata": {"language": "python", "tags": ["pci"]}}\n'
    )
    [t] = load_target_list(p)
    assert t.metadata == {"language": "python", "tags": ["pci"]}


def test_raises_on_missing_file(tmp_path) -> None:
    with pytest.raises(ValueError, match="not found"):
        load_target_list(tmp_path / "absent.jsonl")


def test_raises_on_malformed_json(tmp_path) -> None:
    p = tmp_path / "bad.jsonl"
    p.write_text('{"id": "a"\n')
    with pytest.raises(ValueError, match="malformed JSON"):
        load_target_list(p)


def test_raises_on_missing_required_field(tmp_path) -> None:
    p = tmp_path / "t.jsonl"
    p.write_text('{"id": "a", "type": "repository"}\n')  # no value
    with pytest.raises(ValueError, match="missing required field"):
        load_target_list(p)


def test_raises_on_non_object_row(tmp_path) -> None:
    p = tmp_path / "t.jsonl"
    p.write_text('"just a string"\n')
    with pytest.raises(ValueError, match="must be a JSON object"):
        load_target_list(p)


def test_raises_on_empty_file(tmp_path) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_text("\n# only comments\n")
    with pytest.raises(ValueError, match="zero valid"):
        load_target_list(p)


def test_enforces_max_targets_cap(tmp_path) -> None:
    p = tmp_path / "huge.jsonl"
    p.write_text(
        "\n".join(
            f'{{"id": "t{n}", "type": "repository", "value": "https://x/{n}"}}'
            for n in range(50)
        )
    )
    with pytest.raises(ValueError, match="max_targets"):
        load_target_list(p, max_targets=10)


# ===========================================================================
# §1 — run_batch dispatcher
# ===========================================================================


def _ok_result(target: BatchTarget, run_dir: Path) -> BatchTargetResult:
    run_dir.mkdir(parents=True, exist_ok=True)
    return BatchTargetResult(
        target_id=target.id,
        run_dir=str(run_dir),
        status="completed",
        cost_usd=1.0,
        findings_count=2,
    )


def test_dispatcher_runs_every_target(tmp_path) -> None:
    manifest = BatchManifest(
        batch_id="b1",
        targets=[
            BatchTarget(id="a", type="repository", value="x"),
            BatchTarget(id="b", type="repository", value="y"),
        ],
        output_dir=tmp_path,
    )
    summary = run_batch(manifest, single_target_runner=_ok_result)
    assert summary["status"] == "completed"
    assert summary["total_targets"] == 2
    assert summary["targets_completed"] == 2
    assert summary["targets_failed"] == 0
    assert summary["cumulative_cost_usd"] == pytest.approx(2.0)


def test_dispatcher_writes_batch_meta_json(tmp_path) -> None:
    manifest = BatchManifest(
        batch_id="b2",
        targets=[BatchTarget(id="a", type="repository", value="x")],
        output_dir=tmp_path,
    )
    summary = run_batch(manifest, single_target_runner=_ok_result)
    meta_path = manifest.batch_dir / "batch_meta.json"
    assert meta_path.is_file()
    body = json.loads(meta_path.read_text())
    assert body["batch_id"] == "b2"
    assert body == summary


def test_dispatcher_enforces_cost_cap(tmp_path) -> None:
    """First target costs $1; second target costs $5 (over cap);
    remaining targets must be skipped + status is
    cost_cap_reached."""
    def _runner(target, run_dir):
        run_dir.mkdir(parents=True, exist_ok=True)
        cost = 1.0 if target.id == "a" else 5.0
        return BatchTargetResult(
            target_id=target.id, run_dir=str(run_dir),
            status="completed", cost_usd=cost,
        )

    manifest = BatchManifest(
        batch_id="b3",
        targets=[
            BatchTarget(id="a", type="repository", value="x"),
            BatchTarget(id="b", type="repository", value="y"),
            BatchTarget(id="c", type="repository", value="z"),
        ],
        cost_cap_usd=4.0,
        output_dir=tmp_path,
    )
    summary = run_batch(manifest, single_target_runner=_runner)
    assert summary["status"] == "cost_cap_reached"
    # a completed, b completed (triggered the cap), c skipped.
    statuses = [r["status"] for r in summary["results"]]
    assert statuses == ["completed", "completed", "skipped"]


def test_dispatcher_isolates_per_target_failure(tmp_path) -> None:
    """A raise from one runner doesn't stop the batch."""
    def _runner(target, run_dir):
        if target.id == "b":
            raise RuntimeError("synthetic")
        return _ok_result(target, run_dir)

    manifest = BatchManifest(
        batch_id="b4",
        targets=[
            BatchTarget(id="a", type="repository", value="x"),
            BatchTarget(id="b", type="repository", value="y"),
            BatchTarget(id="c", type="repository", value="z"),
        ],
        output_dir=tmp_path,
    )
    summary = run_batch(manifest, single_target_runner=_runner)
    assert summary["status"] == "partial"
    assert summary["targets_completed"] == 2
    assert summary["targets_failed"] == 1


# ===========================================================================
# §7 — Researcher cache
# ===========================================================================


def test_write_then_read_cache_round_trips(tmp_path) -> None:
    out = write_cache(
        "proj-x", {"stack": ["python", "django"]},
        workdir=tmp_path,
    )
    assert out == tmp_path / "researcher_cache" / "proj-x.json"
    entry = read_cache("proj-x", workdir=tmp_path)
    assert entry is not None
    assert entry.project_id == "proj-x"
    assert entry.researcher_output == {"stack": ["python", "django"]}


def test_read_missing_cache_returns_none(tmp_path) -> None:
    assert read_cache("no-such-project", workdir=tmp_path) is None


def test_read_cache_rejects_old_version(tmp_path) -> None:
    p = cache_path("proj-x", workdir=tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "project_id": "proj-x",
        "engine_version": "v0-experimental",
        "created_at": "2026-05-18T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "researcher_output": {"x": 1},
    }))
    assert read_cache("proj-x", workdir=tmp_path) is None


def test_read_cache_rejects_expired(tmp_path) -> None:
    p = cache_path("proj-x", workdir=tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "project_id": "proj-x",
        "engine_version": "v1",
        "created_at": "2020-01-01T00:00:00Z",
        "expires_at": "2020-01-02T00:00:00Z",  # already expired
        "researcher_output": {"x": 1},
    }))
    assert read_cache("proj-x", workdir=tmp_path) is None


def test_read_cache_rejects_malformed(tmp_path) -> None:
    p = cache_path("proj-x", workdir=tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{ not json")
    assert read_cache("proj-x", workdir=tmp_path) is None


def test_read_cache_explicit_path_overrides_project_id(tmp_path) -> None:
    """When the caller passes an explicit path, the project_id
    field is irrelevant for lookup."""
    explicit = tmp_path / "custom.json"
    explicit.write_text(json.dumps({
        "project_id": "different-pid",
        "engine_version": "v1",
        "created_at": "2026-05-18T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "researcher_output": {"v": 1},
    }))
    entry = read_cache("anything", explicit_path=explicit)
    assert entry is not None
    assert entry.researcher_output == {"v": 1}


def test_write_cache_no_project_id_returns_none(tmp_path) -> None:
    """Defensive — empty project_id → no file."""
    assert write_cache("", {"x": 1}, workdir=tmp_path) is None


def test_invalidate_cache_removes_file(tmp_path) -> None:
    write_cache("proj-x", {"x": 1}, workdir=tmp_path)
    p = cache_path("proj-x", workdir=tmp_path)
    assert p.exists()
    assert invalidate_cache("proj-x", workdir=tmp_path) is True
    assert not p.exists()
    # Second call → False (no file).
    assert invalidate_cache("proj-x", workdir=tmp_path) is False


# ===========================================================================
# CLI integration
# ===========================================================================


def test_cli_target_list_populates_batch_manifest(
    monkeypatch, tmp_path,
) -> None:
    from strix.interface.main import parse_arguments

    p = tmp_path / "t.jsonl"
    p.write_text(
        '{"id": "a", "type": "repository", "value": "https://x/a"}\n'
        '{"id": "b", "type": "web_application", "value": "https://x/b"}\n'
    )

    monkeypatch.setattr(
        sys, "argv",
        ["strix", "--target-list", str(p), "-n"],
    )
    args = parse_arguments()
    assert args.batch_manifest is not None
    assert len(args.batch_manifest.targets) == 2
    # targets_info populated from manifest with target_id flowing
    # through.
    assert len(args.targets_info) == 2
    assert args.targets_info[0]["target_id"] == "a"
    assert args.targets_info[1]["target_id"] == "b"


def test_cli_target_list_with_cost_cap_and_batch_id(
    monkeypatch, tmp_path,
) -> None:
    from strix.interface.main import parse_arguments

    p = tmp_path / "t.jsonl"
    p.write_text(
        '{"id": "a", "type": "repository", "value": "https://x/a"}\n'
    )
    monkeypatch.setattr(
        sys, "argv",
        [
            "strix", "--target-list", str(p),
            "--batch-cost-cap", "5.0",
            "--batch-id", "my-batch-001",
            "-n",
        ],
    )
    args = parse_arguments()
    assert args.batch_manifest.cost_cap_usd == 5.0
    assert args.batch_manifest.batch_id == "my-batch-001"


def test_cli_rejects_target_list_combined_with_t(
    monkeypatch, tmp_path, capsys,
) -> None:
    from strix.interface.main import parse_arguments

    p = tmp_path / "t.jsonl"
    p.write_text(
        '{"id": "a", "type": "repository", "value": "https://x/a"}\n'
    )
    monkeypatch.setattr(
        sys, "argv",
        [
            "strix", "-t", "https://x/", "--target-list", str(p), "-n",
        ],
    )
    with pytest.raises(SystemExit):
        parse_arguments()
    err = capsys.readouterr().err
    assert "cannot be combined" in err.lower()


def test_cli_requires_one_of_t_or_target_list(monkeypatch, capsys) -> None:
    from strix.interface.main import parse_arguments

    monkeypatch.setattr(sys, "argv", ["strix", "-n"])
    with pytest.raises(SystemExit):
        parse_arguments()
    err = capsys.readouterr().err
    assert "target-list" in err or "-t" in err


def test_cli_malformed_target_list_fails_early(
    monkeypatch, tmp_path, capsys,
) -> None:
    from strix.interface.main import parse_arguments

    p = tmp_path / "bad.jsonl"
    p.write_text("{not even json\n")
    monkeypatch.setattr(
        sys, "argv",
        ["strix", "--target-list", str(p), "-n"],
    )
    with pytest.raises(SystemExit):
        parse_arguments()
    err = capsys.readouterr().err
    assert "malformed" in err.lower() or "target-list" in err.lower()


def test_cli_auto_generates_batch_id_when_omitted(
    monkeypatch, tmp_path,
) -> None:
    from strix.interface.main import parse_arguments

    p = tmp_path / "t.jsonl"
    p.write_text(
        '{"id": "a", "type": "repository", "value": "https://x/a"}\n'
    )
    monkeypatch.setattr(
        sys, "argv",
        ["strix", "--target-list", str(p), "-n"],
    )
    args = parse_arguments()
    # Auto-generated has the "batch-" prefix.
    assert args.batch_manifest.batch_id.startswith("batch-")
