"""Tests for iter-21.6.1 `scan_buckets_via_bbot`.

We mock the `bbot` subprocess to keep tests hermetic — bbot itself
takes 30s+ for real DNS-driven discovery, plus reaches out to
public DNS / CT log endpoints, neither of which belongs in CI.

Test coverage:
  * Subprocess wrapper degradation when bbot isn't on PATH or
    env kill switch is set.
  * Target normalization (URL → host; bare IP rejected).
  * Bucket-module bundle env override.
  * Event classification (STORAGE_BUCKET → info, FINDING-with-
    public-bucket-language → critical).
  * Provider inference from URL.
  * End-to-end with mocked subprocess returning a synthetic
    NDJSON event stream.
  * Registration + anchor-prepass wiring.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


# Route through sys.modules to get the SUBMODULE (the package's
# __init__.py re-exports a function with the same name; without
# this we'd bind to the function and `monkeypatch.setattr(mod,
# "_run_bbot_scan", ...)` would fail).
import strix.tools.bbot_runner.scan_buckets_via_bbot  # noqa: F401,E501
sbb = sys.modules[
    "strix.tools.bbot_runner.scan_buckets_via_bbot"
]
scan_buckets_via_bbot = sbb.scan_buckets_via_bbot


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_BBOT_DISABLED", raising=False)
    monkeypatch.delenv("STRIX_BBOT_BUCKET_MODULES", raising=False)


# ---------------------------------------------------------------------------
# Availability + kill switch
# ---------------------------------------------------------------------------


def test_bbot_disabled_env_returns_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_BBOT_DISABLED", "1")
    result = scan_buckets_via_bbot("https://example.com")
    assert result["status"] == "partial"
    assert "bbot" in result["reason"]


def test_bbot_not_on_path_returns_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    result = scan_buckets_via_bbot("https://example.com")
    assert result["status"] == "partial"


# ---------------------------------------------------------------------------
# Target normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("https://example.com", "example.com"),
    ("http://api.example.com/v1", "api.example.com"),
    ("example.com", "example.com"),
    ("example.com:8080", "example.com"),
    ("HTTPS://Example.COM/", "example.com"),
])
def test_normalize_target_strips_to_host(raw, expected) -> None:
    assert sbb._normalize_target(raw) == expected


def test_normalize_rejects_bare_ip() -> None:
    assert sbb._normalize_target("192.168.1.1") is None


def test_normalize_rejects_empty() -> None:
    assert sbb._normalize_target("") is None
    assert sbb._normalize_target("   ") is None


# ---------------------------------------------------------------------------
# Bucket-module bundle config
# ---------------------------------------------------------------------------


def test_default_modules_include_five_providers() -> None:
    mods = sbb._bucket_modules()
    assert "bucket_aws" in mods
    assert "bucket_azure" in mods
    assert "bucket_gcp" in mods
    assert "bucket_digitalocean" in mods
    assert "bucket_firebase" in mods


def test_env_override_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "STRIX_BBOT_BUCKET_MODULES", "bucket_aws,bucket_azure",
    )
    mods = sbb._bucket_modules()
    assert mods == ("bucket_aws", "bucket_azure")


def test_env_empty_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_BBOT_BUCKET_MODULES", "")
    mods = sbb._bucket_modules()
    assert "bucket_aws" in mods  # default still applies


# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------


def test_classify_storage_bucket_event_emits_info() -> None:
    event = {
        "type": "STORAGE_BUCKET",
        "data": {
            "name": "acme-backups",
            "url": "https://acme-backups.s3.amazonaws.com/",
            "provider": "aws_s3",
        },
    }
    f = sbb._classify_event(event)
    assert f is not None
    assert f["severity"] == "info"
    assert f["provider"] == "aws_s3"
    assert "acme-backups" in f["title"]


def test_classify_finding_with_public_keyword_emits_critical() -> None:
    event = {
        "type": "FINDING",
        "data": {
            "description": "Bucket is publicly listable",
            "url": "https://acme-backups.s3.amazonaws.com/",
            "name": "acme-backups",
        },
        "tags": ["bucket", "aws"],
    }
    f = sbb._classify_event(event)
    assert f is not None
    assert f["severity"] == "critical"
    assert f["provider"] == "aws_s3"


def test_classify_finding_open_keyword_also_critical() -> None:
    event = {
        "type": "FINDING",
        "data": {
            "description": "Open bucket detected",
            "url": "https://x.storage.googleapis.com/x",
        },
    }
    f = sbb._classify_event(event)
    assert f is not None
    assert f["severity"] == "critical"
    assert f["provider"] == "gcp_gcs"


def test_classify_unrelated_event_returns_none() -> None:
    """SCAN_START, DNS_NAME, OPEN_TCP_PORT etc. don't map to bucket findings."""
    assert sbb._classify_event({"type": "SCAN_START"}) is None
    assert sbb._classify_event({"type": "DNS_NAME", "data": "x.com"}) is None
    assert sbb._classify_event(
        {"type": "FINDING", "data": {"description": "SSL cert expires soon"}},
    ) is None


def test_classify_garbage_event_no_raise() -> None:
    """Defence-in-depth: malformed events must not crash the classifier."""
    assert sbb._classify_event({}) is None
    assert sbb._classify_event({"type": "STORAGE_BUCKET", "data": None}) is None
    assert sbb._classify_event({"type": "STORAGE_BUCKET", "data": "string"}) is None


# ---------------------------------------------------------------------------
# Provider inference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,expected", [
    ("https://acme.s3.amazonaws.com/", "aws_s3"),
    ("https://s3-us-east-1.amazonaws.com/acme", "aws_s3"),
    ("https://storage.googleapis.com/acme/o", "gcp_gcs"),
    ("https://acme.blob.core.windows.net/files", "azure_blob"),
    ("https://acme.digitaloceanspaces.com/", "digitalocean_spaces"),
    ("https://acme.firebaseio.com/", "firebase"),
    ("https://random.example.com/", None),
])
def test_provider_from_url(url, expected) -> None:
    assert sbb._provider_from_url(url) == expected


# ---------------------------------------------------------------------------
# End-to-end with mocked subprocess
# ---------------------------------------------------------------------------


def _mock_bbot(
    monkeypatch: pytest.MonkeyPatch,
    *,
    on_path: bool = True,
    events: list[dict] | None = None,
    returncode: int = 0,
    stderr: str = "",
):
    """Patch shutil.which + subprocess.run to simulate bbot.
    Returns the subprocess.run mock for caller inspection."""
    import shutil
    import subprocess

    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/bbot" if (on_path and b == "bbot") else None,
    )

    stdout = "\n".join(json.dumps(e) for e in (events or []))
    fake_result = MagicMock()
    fake_result.returncode = returncode
    fake_result.stdout = stdout
    fake_result.stderr = stderr
    run_mock = MagicMock(return_value=fake_result)
    monkeypatch.setattr(subprocess, "run", run_mock)
    return run_mock


def test_end_to_end_no_findings(monkeypatch) -> None:
    """When bbot returns only non-bucket events, the scan succeeds
    with zero findings."""
    _mock_bbot(monkeypatch, events=[
        {"type": "SCAN_START", "data": {"id": "abc"}},
        {"type": "DNS_NAME", "data": "example.com"},
    ])
    result = scan_buckets_via_bbot("https://example.com")
    assert result["status"] == "ok"
    assert result["total_findings"] == 0


def test_end_to_end_storage_bucket_emits_info(monkeypatch) -> None:
    _mock_bbot(monkeypatch, events=[
        {
            "type": "STORAGE_BUCKET",
            "data": {
                "name": "acme-backups",
                "url": "https://acme-backups.s3.amazonaws.com/",
                "provider": "aws_s3",
            },
        },
    ])
    result = scan_buckets_via_bbot("https://acme.com")
    assert result["status"] == "ok"
    assert result["total_findings"] == 1
    assert result["findings"][0]["severity"] == "info"


def test_end_to_end_critical_finding_for_public_bucket(monkeypatch) -> None:
    _mock_bbot(monkeypatch, events=[
        {
            "type": "STORAGE_BUCKET",
            "data": {
                "name": "acme-backups",
                "url": "https://acme-backups.s3.amazonaws.com/",
                "provider": "aws_s3",
            },
        },
        {
            "type": "FINDING",
            "data": {
                "description": "Bucket is publicly listable",
                "url": "https://acme-backups.s3.amazonaws.com/",
                "name": "acme-backups",
            },
            "tags": ["bucket"],
        },
    ])
    result = scan_buckets_via_bbot("https://acme.com")
    assert result["status"] == "ok"
    # Two findings: discovery (info) + public (critical)
    assert result["total_findings"] == 2
    severities = {f["severity"] for f in result["findings"]}
    assert "info" in severities
    assert "critical" in severities


def test_bbot_subprocess_failure_returns_error(monkeypatch) -> None:
    _mock_bbot(
        monkeypatch, returncode=2, stderr="bbot internal error",
    )
    result = scan_buckets_via_bbot("https://acme.com")
    assert result["status"] == "error"
    assert "bbot internal error" in result["reason"]


def test_bbot_malformed_ndjson_ignored(monkeypatch) -> None:
    """Garbled lines in the bbot NDJSON output are skipped (rather
    than crashing the wrapper)."""
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which", lambda b: "/usr/local/bin/bbot" if b == "bbot" else None,
    )
    stdout_lines = [
        json.dumps({"type": "DNS_NAME", "data": "x.com"}),
        "this is not json",
        json.dumps({
            "type": "STORAGE_BUCKET",
            "data": {
                "name": "acme",
                "url": "https://acme.s3.amazonaws.com/",
                "provider": "aws_s3",
            },
        }),
        "another garbage line {{}}",
    ]
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = "\n".join(stdout_lines)
    fake_result.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake_result))
    result = scan_buckets_via_bbot("https://acme.com")
    assert result["status"] == "ok"
    assert result["total_findings"] == 1  # only the well-formed bucket event matched


def test_bare_ip_target_returns_partial(monkeypatch) -> None:
    _mock_bbot(monkeypatch)
    result = scan_buckets_via_bbot("192.168.1.1")
    assert result["status"] == "partial"
    assert "bare IP" in result["reason"] or "domain" in result["reason"]


# ---------------------------------------------------------------------------
# Registration + anchor wiring
# ---------------------------------------------------------------------------


def test_scan_buckets_via_bbot_registered() -> None:
    import strix.tools  # noqa: F401 side-effect
    from strix.tools.registry import get_tool_by_name, get_tool_names

    assert "scan_buckets_via_bbot" in get_tool_names()
    assert callable(get_tool_by_name("scan_buckets_via_bbot"))


def test_bbot_wired_into_api_anchors() -> None:
    from strix.agents.lead_agent.anchor_prepass import _ANCHORS_API
    tool_names = [name for name, _ in _ANCHORS_API]
    assert "scan_buckets_via_bbot" in tool_names
