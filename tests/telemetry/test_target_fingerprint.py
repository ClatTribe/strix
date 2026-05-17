"""Tests for engine-wishlist §5 target fingerprinting.

Hermetic — every external call (`subprocess.run`, HTTP, TLS) is
DI'd through the keyword args on `compute_fingerprint`."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry.target_fingerprint import (
    TargetFingerprint,
    _FINGERPRINT_VERSION,
    compute_fingerprint,
    find_prior_run_for_target,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _Proc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _make_run(plan: dict[tuple[str, ...], _Proc]):
    """Build a fake subprocess.run that matches by argv-tuple."""
    def _run(argv, **_kwargs):
        key = tuple(argv)
        for k, v in plan.items():
            if tuple(k) == key:
                return v
            # Match prefix (for tests that want "any docker call" to succeed).
            if tuple(k) == key[:len(k)]:
                return v
        # Unmatched → simulate not-found.
        raise FileNotFoundError(f"unexpected argv: {argv}")
    return _run


# ---------------------------------------------------------------------------
# repository — remote URL via git ls-remote
# ---------------------------------------------------------------------------


def test_repository_remote_url_uses_ls_remote() -> None:
    run = _make_run({
        ("git", "ls-remote", "--symref", "https://github.com/acme/x", "HEAD"):
            _Proc(stdout="ref: refs/heads/main HEAD\nabc123\trefs/heads/main\n"),
    })
    fp = compute_fingerprint(
        "repository", "https://github.com/acme/x", _subprocess_run=run,
    )
    assert fp is not None
    assert fp.target_type == "repository"
    assert fp.digest  # non-empty hex
    assert "git:ls-remote" in fp.sources
    assert fp.algo_version == _FINGERPRINT_VERSION


def test_repository_remote_changes_when_head_changes() -> None:
    """Two different HEAD outputs MUST produce different digests."""
    run_v1 = _make_run({
        ("git", "ls-remote", "--symref", "https://github.com/acme/x", "HEAD"):
            _Proc(stdout="abc111\trefs/heads/main\n"),
    })
    run_v2 = _make_run({
        ("git", "ls-remote", "--symref", "https://github.com/acme/x", "HEAD"):
            _Proc(stdout="def222\trefs/heads/main\n"),
    })
    fp1 = compute_fingerprint(
        "repository", "https://github.com/acme/x", _subprocess_run=run_v1,
    )
    fp2 = compute_fingerprint(
        "repository", "https://github.com/acme/x", _subprocess_run=run_v2,
    )
    assert fp1 is not None and fp2 is not None
    assert fp1.digest != fp2.digest


def test_repository_remote_failure_returns_none() -> None:
    """ls-remote failure (auth issue, network) → None → caller falls
    through to running the scan."""
    run = _make_run({
        ("git", "ls-remote", "--symref", "https://x/y", "HEAD"):
            _Proc(stdout="", stderr="fatal: auth", returncode=128),
    })
    fp = compute_fingerprint(
        "repository", "https://x/y", _subprocess_run=run,
    )
    assert fp is None


def test_repository_remote_git_missing_returns_none() -> None:
    """No git on PATH → FileNotFoundError surfaces as None."""
    def _no_git(*a, **k):
        raise FileNotFoundError("git not found")
    fp = compute_fingerprint(
        "repository", "https://x/y", _subprocess_run=_no_git,
    )
    assert fp is None


# ---------------------------------------------------------------------------
# repository — local path
# ---------------------------------------------------------------------------


def test_repository_local_path_uses_rev_parse(tmp_path) -> None:
    run = _make_run({
        ("git", "-C", str(tmp_path), "rev-parse", "HEAD"):
            _Proc(stdout="abc123\n"),
    })
    fp = compute_fingerprint(
        "repository", str(tmp_path), _subprocess_run=run,
    )
    assert fp is not None
    assert "git:HEAD" in fp.sources


def test_repository_local_path_includes_lockfile_hashes(tmp_path) -> None:
    """If a recognised lockfile is present, its contents contribute
    to the fingerprint — same HEAD but different lockfile = different
    digest."""
    (tmp_path / "package-lock.json").write_text('{"v": 1}')
    run = _make_run({
        ("git", "-C", str(tmp_path), "rev-parse", "HEAD"):
            _Proc(stdout="abc123\n"),
    })
    fp_with_lock = compute_fingerprint(
        "repository", str(tmp_path), _subprocess_run=run,
    )
    assert fp_with_lock is not None
    assert any("package-lock.json" in s for s in fp_with_lock.sources)

    # Mutate lockfile → fingerprint must change.
    (tmp_path / "package-lock.json").write_text('{"v": 2}')
    fp_changed = compute_fingerprint(
        "repository", str(tmp_path), _subprocess_run=run,
    )
    assert fp_changed.digest != fp_with_lock.digest


def test_repository_local_missing_path_returns_none(tmp_path) -> None:
    missing = tmp_path / "does-not-exist"
    fp = compute_fingerprint("repository", str(missing))
    assert fp is None


# ---------------------------------------------------------------------------
# container_image
# ---------------------------------------------------------------------------


def test_container_image_pinned_digest_short_circuits() -> None:
    """`image@sha256:xxx` already carries its identity — no docker call."""
    pinned = (
        "ghcr.io/acme/x@sha256:"
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    )
    fp = compute_fingerprint(
        "container_image", pinned,
        _subprocess_run=lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("docker should not be called for a pinned digest"),
        ),
    )
    assert fp is not None
    assert "pin:sha256" in fp.sources


def test_container_image_via_buildx_inspect() -> None:
    run = _make_run({
        ("docker", "buildx", "imagetools", "inspect", "ghcr.io/acme/x:v1"):
            _Proc(stdout=(
                "Name:    ghcr.io/acme/x:v1\n"
                "Digest:  sha256:cafef00d\n"
                "MediaType: application/vnd.docker...\n"
            )),
    })
    fp = compute_fingerprint(
        "container_image", "ghcr.io/acme/x:v1", _subprocess_run=run,
    )
    assert fp is not None
    assert "buildx" in fp.sources


def test_container_image_falls_back_to_manifest_inspect() -> None:
    """If `buildx` fails, fall through to `docker manifest inspect`."""
    def _run(argv, **_):
        if argv[:3] == ["docker", "buildx", "imagetools"]:
            return _Proc(returncode=1, stderr="not supported")
        if argv[:3] == ["docker", "manifest", "inspect"]:
            return _Proc(
                stdout='{"schemaVersion": 2, "config": {"digest": "sha256:abc"}}',
            )
        raise FileNotFoundError(argv)
    fp = compute_fingerprint(
        "container_image", "registry.example/x:latest",
        _subprocess_run=_run,
    )
    assert fp is not None
    assert any("manifest" in s for s in fp.sources)


def test_container_image_all_paths_fail_returns_none() -> None:
    """If neither docker tool works, return None."""
    def _run(*a, **k):
        return _Proc(returncode=1, stderr="boom")
    fp = compute_fingerprint(
        "container_image", "registry.example/x:latest",
        _subprocess_run=_run,
    )
    assert fp is None


# ---------------------------------------------------------------------------
# web_application — HTTP digest only (TLS bypassed)
# ---------------------------------------------------------------------------


def test_web_application_https_uses_tls_and_body(tmp_path) -> None:
    def _tls(host, port):
        return "tls-deadbeef"
    def _http(url, timeout):
        body = b"<html>hello</html>"
        headers = {"Content-Type": "text/html", "Date": "irrelevant"}
        return body, headers
    fp = compute_fingerprint(
        "web_application", "https://example.com/",
        _tls_get=_tls, _http_get=_http,
    )
    assert fp is not None
    assert "tls:cert" in fp.sources
    assert "http:body" in fp.sources
    assert "http:headers" in fp.sources


def test_web_application_volatile_headers_dont_change_digest() -> None:
    """Two responses with different Date/Set-Cookie/CF-Ray headers
    but same body MUST produce identical digests — those headers
    are scrubbed before digesting."""
    def _tls(host, port):
        return "tls-deadbeef"
    def _http_v1(url, timeout):
        return b"<html>same</html>", {
            "Content-Type": "text/html",
            "Date": "Mon, 01 Jan 2026 00:00:00 GMT",
            "Set-Cookie": "session=abc",
            "CF-Ray": "AAA",
        }
    def _http_v2(url, timeout):
        return b"<html>same</html>", {
            "Content-Type": "text/html",
            "Date": "Tue, 02 Jan 2026 00:00:00 GMT",
            "Set-Cookie": "session=xyz",
            "CF-Ray": "BBB",
        }
    fp1 = compute_fingerprint(
        "web_application", "https://example.com/",
        _tls_get=_tls, _http_get=_http_v1,
    )
    fp2 = compute_fingerprint(
        "web_application", "https://example.com/",
        _tls_get=_tls, _http_get=_http_v2,
    )
    assert fp1.digest == fp2.digest


def test_web_application_body_change_changes_digest() -> None:
    def _tls(host, port):
        return "tls-deadbeef"
    def _http_v1(url, timeout):
        return b"<html>v1</html>", {"Content-Type": "text/html"}
    def _http_v2(url, timeout):
        return b"<html>v2</html>", {"Content-Type": "text/html"}
    fp1 = compute_fingerprint(
        "web_application", "https://x/", _tls_get=_tls, _http_get=_http_v1,
    )
    fp2 = compute_fingerprint(
        "web_application", "https://x/", _tls_get=_tls, _http_get=_http_v2,
    )
    assert fp1.digest != fp2.digest


def test_web_application_all_probes_failing_returns_none() -> None:
    def _tls(host, port):
        return None
    def _http(url, timeout):
        raise RuntimeError("network down")
    fp = compute_fingerprint(
        "web_application", "https://x/", _tls_get=_tls, _http_get=_http,
    )
    assert fp is None


def test_api_target_uses_same_algorithm_as_web_application() -> None:
    def _tls(host, port):
        return "tls-x"
    def _http(url, timeout):
        return b"{}", {"Content-Type": "application/json"}
    fp = compute_fingerprint(
        "api", "https://api.example/v1/",
        _tls_get=_tls, _http_get=_http,
    )
    assert fp is not None
    # Same source set as web_application.
    assert "tls:cert" in fp.sources
    assert "http:body" in fp.sources


# ---------------------------------------------------------------------------
# Out-of-scope target types (v1 returns None — caller scans)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ttype", ["cloud_account", "domain", "ip_address"])
def test_unsupported_target_types_return_none(ttype) -> None:
    fp = compute_fingerprint(ttype, "anything")
    assert fp is None


def test_empty_target_value_returns_none() -> None:
    fp = compute_fingerprint("repository", "")
    assert fp is None


# ---------------------------------------------------------------------------
# Same-target stability — same inputs MUST hash identically
# ---------------------------------------------------------------------------


def test_same_inputs_produce_identical_digest(tmp_path) -> None:
    run = _make_run({
        ("git", "-C", str(tmp_path), "rev-parse", "HEAD"):
            _Proc(stdout="abc123\n"),
    })
    fp1 = compute_fingerprint(
        "repository", str(tmp_path), _subprocess_run=run,
    )
    fp2 = compute_fingerprint(
        "repository", str(tmp_path), _subprocess_run=run,
    )
    assert fp1.digest == fp2.digest


# ---------------------------------------------------------------------------
# find_prior_run_for_target — filesystem lookup
# ---------------------------------------------------------------------------


def _write_run_meta(
    runs_root: Path,
    run_name: str,
    target_value: str,
    digest: str,
    *,
    status: str = "completed",
    algo_version: str = _FINGERPRINT_VERSION,
) -> Path:
    run_dir = runs_root / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_meta.json").write_text(json.dumps({
        "run_id": run_name,
        "run_name": run_name,
        "status": status,
        "targets": [{"original": target_value}],
        "target_fingerprint": {
            "target_type": "repository",
            "target_value": target_value,
            "digest": digest,
            "sources": ["git:HEAD"],
            "computed_at": "2026-05-18T00:00:00Z",
            "algo_version": algo_version,
        },
    }))
    return run_dir


def test_find_prior_picks_most_recent_completed(tmp_path) -> None:
    _write_run_meta(tmp_path, "old", "https://x/", "OLD")
    new_dir = _write_run_meta(tmp_path, "new", "https://x/", "NEW")
    # Touch to set mtime newer.
    import os
    os.utime(new_dir, None)

    result = find_prior_run_for_target(
        "https://x/", runs_root=tmp_path,
    )
    assert result is not None
    run_dir, fp = result
    assert fp.digest == "NEW"


def test_find_prior_skips_other_targets(tmp_path) -> None:
    _write_run_meta(tmp_path, "other", "https://other/", "OTHER")
    result = find_prior_run_for_target(
        "https://target/", runs_root=tmp_path,
    )
    assert result is None


def test_find_prior_skips_skipped_unchanged_chain(tmp_path) -> None:
    """A 'skipped_unchanged' prior run isn't considered — we want
    to chain back to the last full scan, otherwise a broken chain
    of skips perpetuates an old fingerprint forever."""
    _write_run_meta(
        tmp_path, "real", "https://x/", "REAL", status="completed",
    )
    _write_run_meta(
        tmp_path, "skipped", "https://x/", "REAL",
        status="skipped_unchanged",
    )

    result = find_prior_run_for_target(
        "https://x/", runs_root=tmp_path,
    )
    assert result is not None
    run_dir, fp = result
    assert run_dir.name == "real"


def test_find_prior_rejects_old_algorithm_version(tmp_path) -> None:
    """If the stored fingerprint was computed with a different algo
    version, it's not comparable — return None so the scan runs."""
    _write_run_meta(
        tmp_path, "old-algo", "https://x/", "X",
        algo_version="v0-experimental",
    )
    assert find_prior_run_for_target(
        "https://x/", runs_root=tmp_path,
    ) is None


def test_find_prior_explicit_run_dir_skips_target_match(tmp_path) -> None:
    """When the caller passes explicit_prior_run_dir, we trust the
    caller — no target-value matching."""
    explicit = _write_run_meta(
        tmp_path, "explicit", "https://different/", "EXPLICIT",
    )
    result = find_prior_run_for_target(
        "https://target-not-matching/",  # ignored
        runs_root=tmp_path,
        explicit_prior_run_dir=explicit,
    )
    assert result is not None
    run_dir, fp = result
    assert fp.digest == "EXPLICIT"


def test_find_prior_returns_none_when_runs_root_missing(tmp_path) -> None:
    missing = tmp_path / "nope"
    assert find_prior_run_for_target(
        "https://x/", runs_root=missing,
    ) is None
