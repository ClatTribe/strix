"""Tests for iter-Q6.1 — sqlmap auto `--forms --crawl=2` on bare URLs.

Closes the WAVSEP SQLi 0%-recall gap diagnosed in the Q5.34l bench:
sqlmap fired 102 times on bare-path URLs (no ?param=value), each
exiting in ~100 ms with "no parameter(s) found for testing" and
emitting zero findings.

Coverage:
  * `_resolve_forms` — autodetect on no-? URLs, off on ?-having URLs,
    explicit kwarg wins over env wins over autodetect
  * `_resolve_crawl_depth` — default 2 when forms, 0 otherwise,
    kwarg + env overrides
  * `_resolve_timeout` — default 300, env override, kwarg override
  * argv emission: --forms / --crawl flags appear or are omitted
    per the resolved values
  * Regression: existing query-param URL invocation pattern still
    works unchanged (no breaking change to callers)
"""

from __future__ import annotations

import importlib
import json
from unittest.mock import MagicMock

import pytest

sci = importlib.import_module("strix.tools.sqlmap_runner.scan_sqli_sqlmap")
scan = sci.scan_sqli_sqlmap


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    for k in (
        "STRIX_SQLMAP_DISABLED", "STRIX_SQLMAP_FORMS_AUTO",
        "STRIX_SQLMAP_CRAWL_DEPTH", "STRIX_SQLMAP_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(k, raising=False)


# ----------------------------------------------------------------------
# _resolve_forms
# ----------------------------------------------------------------------

class TestResolveForms:
    def test_explicit_true_kwarg(self):
        assert sci._resolve_forms(True, "https://x/p") is True

    def test_explicit_false_kwarg(self):
        # Even on a bare URL, explicit False wins.
        assert sci._resolve_forms(False, "https://x/p") is False

    def test_autodetect_bare_url(self):
        """No `?` in URL → autodetect returns True."""
        assert sci._resolve_forms(
            None,
            "http://x:8098/wavsep/active/SQL-Injection/Case01-X.jsp",
        ) is True

    def test_autodetect_url_with_query(self):
        """? present → sqlmap has a direct injection point; autodetect False."""
        assert sci._resolve_forms(None, "https://x/p?id=1") is False

    def test_autodetect_no_target_url(self):
        """request_file mode (no target_url) — autodetect False."""
        assert sci._resolve_forms(None, None) is False
        assert sci._resolve_forms(None, "") is False

    @pytest.mark.parametrize("v", ["0", "false", "no", "off"])
    def test_env_disables_autodetect(self, monkeypatch, v):
        monkeypatch.setenv("STRIX_SQLMAP_FORMS_AUTO", v)
        assert sci._resolve_forms(None, "https://x/p") is False

    def test_kwarg_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("STRIX_SQLMAP_FORMS_AUTO", "0")
        # Explicit True kwarg should override env disable.
        assert sci._resolve_forms(True, "https://x/p") is True


# ----------------------------------------------------------------------
# _resolve_crawl_depth
# ----------------------------------------------------------------------

class TestResolveCrawlDepth:
    def test_default_when_forms_true(self):
        assert sci._resolve_crawl_depth(None, forms=True) == 2

    def test_default_when_forms_false(self):
        assert sci._resolve_crawl_depth(None, forms=False) == 0

    def test_kwarg_wins(self):
        assert sci._resolve_crawl_depth(5, forms=False) == 5
        assert sci._resolve_crawl_depth(0, forms=True) == 0

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("STRIX_SQLMAP_CRAWL_DEPTH", "3")
        assert sci._resolve_crawl_depth(None, forms=True) == 3

    def test_env_garbage_falls_back(self, monkeypatch):
        monkeypatch.setenv("STRIX_SQLMAP_CRAWL_DEPTH", "garbage")
        assert sci._resolve_crawl_depth(None, forms=True) == 2

    def test_negative_clamped_to_zero(self):
        assert sci._resolve_crawl_depth(-1, forms=True) == 0


# ----------------------------------------------------------------------
# _resolve_timeout
# ----------------------------------------------------------------------

class TestResolveTimeout:
    def test_default(self):
        assert sci._resolve_timeout(None) == 300

    def test_kwarg_wins(self):
        assert sci._resolve_timeout(600) == 600

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("STRIX_SQLMAP_TIMEOUT_SECONDS", "900")
        assert sci._resolve_timeout(None) == 900

    def test_floor_30_seconds(self):
        """Below 30s is too short for sqlmap to do anything useful."""
        assert sci._resolve_timeout(5) == 30


# ----------------------------------------------------------------------
# Argv emission — the integration test that proves the bug is fixed
# ----------------------------------------------------------------------

def _mock_sqlmap(monkeypatch, stdout: str = "", returncode: int = 0):
    """Stub sqlmap binary present + capture argv."""
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/sqlmap" if b == "sqlmap" else None,
    )
    captured: list[list[str]] = []

    class _Proc:
        def __init__(self):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    def _run(cmd, **_):
        captured.append(list(cmd))
        return _Proc()

    monkeypatch.setattr(sci.subprocess, "run", _run)
    return captured


class TestArgvEmission:
    def test_bare_url_emits_forms_and_crawl(self, monkeypatch):
        """The WAVSEP fix: bare URL gets --forms --crawl=2 automatically."""
        captured = _mock_sqlmap(monkeypatch)
        scan(target_url="http://x:8098/wavsep/active/SQL-Injection/Case01-X.jsp")
        cmd = captured[0]
        assert "--forms" in cmd
        assert "--crawl" in cmd
        assert cmd[cmd.index("--crawl") + 1] == "2"

    def test_query_url_omits_forms_and_crawl(self, monkeypatch):
        """Backwards-compat: ?id=1 URLs use original injection-point mode."""
        captured = _mock_sqlmap(monkeypatch)
        scan(target_url="http://x/page.php?id=1")
        cmd = captured[0]
        assert "--forms" not in cmd
        assert "--crawl" not in cmd

    def test_explicit_forms_false_omits_flag(self, monkeypatch):
        captured = _mock_sqlmap(monkeypatch)
        scan(
            target_url="http://x:8098/wavsep/active/SQL-Injection/Case01-X.jsp",
            forms=False,
        )
        cmd = captured[0]
        assert "--forms" not in cmd
        # crawl_depth defaults to 0 when forms=False → also omitted.
        assert "--crawl" not in cmd

    def test_explicit_crawl_depth_zero_omits_flag(self, monkeypatch):
        """User can ask for --forms without crawl (single-page form test)."""
        captured = _mock_sqlmap(monkeypatch)
        scan(
            target_url="http://x/p",
            forms=True,
            crawl_depth=0,
        )
        cmd = captured[0]
        assert "--forms" in cmd
        assert "--crawl" not in cmd

    def test_explicit_crawl_depth_passed_through(self, monkeypatch):
        captured = _mock_sqlmap(monkeypatch)
        scan(target_url="http://x/p", forms=True, crawl_depth=5)
        cmd = captured[0]
        assert "--crawl" in cmd
        assert cmd[cmd.index("--crawl") + 1] == "5"

    def test_env_forms_auto_disable_keeps_old_behaviour(self, monkeypatch):
        """Operators can opt out via STRIX_SQLMAP_FORMS_AUTO=0."""
        monkeypatch.setenv("STRIX_SQLMAP_FORMS_AUTO", "0")
        captured = _mock_sqlmap(monkeypatch)
        scan(target_url="http://x/bare-path")
        cmd = captured[0]
        assert "--forms" not in cmd
        assert "--crawl" not in cmd

    def test_existing_flags_unchanged(self, monkeypatch):
        """Q6.1 must not break --batch / --random-agent / --risk / --level."""
        captured = _mock_sqlmap(monkeypatch)
        scan(target_url="http://x/p?id=1", risk=2, level=3, dbms_hint="mysql")
        cmd = captured[0]
        assert "--batch" in cmd
        assert "--random-agent" in cmd
        assert "--risk" in cmd and cmd[cmd.index("--risk") + 1] == "2"
        assert "--level" in cmd and cmd[cmd.index("--level") + 1] == "3"
        assert "--dbms" in cmd and cmd[cmd.index("--dbms") + 1] == "mysql"

    def test_request_file_mode_no_forms_autoadd(self, monkeypatch, tmp_path):
        """`-r request.txt` mode already has injection points; no --forms."""
        rfile = tmp_path / "req.txt"
        rfile.write_text("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        captured = _mock_sqlmap(monkeypatch)
        scan(request_file=str(rfile))
        cmd = captured[0]
        assert "--forms" not in cmd
        assert "--crawl" not in cmd


# ----------------------------------------------------------------------
# Regression — keep existing recall-safe degrades working
# ----------------------------------------------------------------------

class TestRecallSafeDegradesPreserved:
    def test_partial_when_binary_missing(self, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, "which", lambda _b: None)
        out = scan(target_url="http://x/p")
        assert out["status"] == "partial"

    def test_partial_when_disabled(self, monkeypatch):
        monkeypatch.setenv("STRIX_SQLMAP_DISABLED", "1")
        out = scan(target_url="http://x/p")
        assert out["status"] == "partial"

    def test_error_when_no_target_or_request_file(self):
        out = scan()
        assert out["status"] == "error"


# ----------------------------------------------------------------------
# Anti-overfit
# ----------------------------------------------------------------------

def test_no_fixture_identifiers_in_q6_1_impl():
    """Source-grep: resolver helpers don't reference SUT identifiers.

    The autodetect heuristic must be generic — not tuned to a single
    bench fixture.
    """
    import inspect
    banned = {"juice-shop", "vampi", "crapi", "wavsep", "getedunext", "bkimminich"}
    for fn_name in ("_resolve_forms", "_resolve_crawl_depth", "_resolve_timeout"):
        src = inspect.getsource(getattr(sci, fn_name))
        for ident in banned:
            assert ident not in src.lower(), (
                f"{fn_name} references SUT identifier {ident!r}"
            )
