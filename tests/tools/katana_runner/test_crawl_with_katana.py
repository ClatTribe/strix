"""Tests for iter-22.1 `crawl_with_katana` wrapper."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock

import pytest


import strix.tools.katana_runner.crawl_with_katana  # noqa: F401,E501
cwk_mod = sys.modules["strix.tools.katana_runner.crawl_with_katana"]
crawl_with_katana = cwk_mod.crawl_with_katana


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("STRIX_KATANA_DISABLED", raising=False)


def test_error_when_empty():
    out = crawl_with_katana("")
    assert out["status"] == "error"


def test_partial_when_binary_missing(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _b: None)
    out = crawl_with_katana("https://example.com")
    assert out["status"] == "partial"


def test_partial_when_disabled(monkeypatch):
    monkeypatch.setenv("STRIX_KATANA_DISABLED", "1")
    out = crawl_with_katana("https://example.com")
    assert out["status"] == "partial"


def test_parses_jsonl_endpoints(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/katana" if b == "katana" else None)
    lines = [
        json.dumps({"request": {"endpoint": "https://example.com/api?id=1",
                                 "method": "GET"}}),
        json.dumps({"request": {"endpoint": "https://example.com/login",
                                 "method": "POST"}}),
        # Duplicate — should dedup
        json.dumps({"request": {"endpoint": "https://example.com/api?id=1",
                                 "method": "GET"}}),
        "garbage line",
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = crawl_with_katana("https://example.com")
    assert out["status"] == "ok"
    assert out["endpoints_discovered"] == 2
    urls = {e["url"] for e in out["endpoints"]}
    assert "https://example.com/api?id=1" in urls
    assert "https://example.com/login" in urls
    # Param extraction
    api = next(e for e in out["endpoints"] if "/api?" in e["url"])
    assert "id" in api["params"]


def test_max_pages_caps(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/katana" if b == "katana" else None)
    lines = [
        json.dumps({"request": {"endpoint": f"https://x.com/p{i}", "method": "GET"}})
        for i in range(50)
    ]
    fake = MagicMock()
    fake.returncode = 0
    fake.stdout = "\n".join(lines)
    fake.stderr = ""
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))
    out = crawl_with_katana("https://x.com", max_pages=10)
    assert out["endpoints_discovered"] == 10


def test_iter_28_3_defaults_enable_js_and_forms(monkeypatch):
    """iter-28.3 — headless + js-crawl + form-extract default on.

    The L2 Juice Shop full-challenge bench (3/109) traced the L1
    surface gap to katana running HTTP-only, no JS, no form extract.
    Flipping these defaults to on is a non-overfit change because
    every SPA needs JS rendering and form extraction.

    Regression-guards against accidental revert: assert the default
    invocation contains -headless -jc -jsl -fx flags.
    """
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/katana" if b == "katana" else None,
    )
    run_mock = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(subprocess, "run", run_mock)

    crawl_with_katana("https://x.com")  # default args

    cmd = run_mock.call_args[0][0]
    assert "-headless" in cmd, "headless must default ON post-iter-28.3 (SPA coverage)"
    assert "-jc" in cmd, "JS-crawl must default ON post-iter-28.3 (bundled-endpoint discovery)"
    assert "-jsl" in cmd, "jsluice must default ON post-iter-28.3 (webpack/rollup parse)"
    assert "-fx" in cmd, "form-extract must default ON post-iter-28.3 (auth-seed input)"


def test_iter_28_3_forms_surfaced_in_output(monkeypatch):
    """katana -fx emits forms inline in JSONL; parser surfaces them
    under result['forms'] for the auth-seed primitive (iter-28.4) +
    form-aware scan_sqli/xss to consume."""
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/katana" if b == "katana" else None,
    )
    lines = [
        json.dumps({
            "request": {"endpoint": "https://x.com/register", "method": "GET"},
            "forms": [{
                "action": "/api/Users/",
                "method": "POST",
                "parameters": [
                    {"name": "email", "type": "email"},
                    {"name": "password", "type": "password"},
                ],
            }],
        }),
    ]
    fake = MagicMock(returncode=0, stdout="\n".join(lines), stderr="")
    monkeypatch.setattr(subprocess, "run", MagicMock(return_value=fake))

    out = crawl_with_katana("https://x.com")
    assert out["forms_discovered"] == 1
    assert out["forms"][0]["action"] == "/api/Users/"
    assert out["forms"][0]["method"] == "POST"
    input_names = {i["name"] for i in out["forms"][0]["inputs"]}
    assert input_names == {"email", "password"}


def test_iter_28_3_opt_out_flags(monkeypatch):
    """Operators can opt OUT of the heavier crawl for known
    server-rendered targets via headless=False / js_crawl=False /
    extract_forms=False."""
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/katana" if b == "katana" else None,
    )
    run_mock = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(subprocess, "run", run_mock)

    crawl_with_katana(
        "https://x.com",
        headless=False, js_crawl=False, extract_forms=False,
    )

    cmd = run_mock.call_args[0][0]
    assert "-headless" not in cmd
    assert "-jc" not in cmd
    assert "-jsl" not in cmd
    assert "-fx" not in cmd


def test_timeout_returns_error(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda b: "/usr/local/bin/katana" if b == "katana" else None)
    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="katana", timeout=180)
    monkeypatch.setattr(subprocess, "run", _boom)
    out = crawl_with_katana("https://x.com")
    assert out["status"] == "error"


def test_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("crawl_with_katana"))
