"""Tests for nuclei_template_update.

Hermetic — `_locate_nuclei_binary` and `_run_nuclei` are
monkeypatched. No real subprocess invocation. Tests cover:

- Output parsing (version, template count, no-update vs update-applied)
- Binary missing → graceful failure
- Throttle window: re-run within window returns throttled, force=True
  overrides
- First run → updates and writes meta
- Update applied → finding mentions new version
- Already current → finding says "already current"
- Subprocess timeout → graceful failure
- Subprocess hard error → graceful failure
- Primary args fail → falls back to legacy args
- Returncode != 0 but version parsed → still success
- Returncode != 0 AND no parseable output → failure
- Single info finding emitted with description_plain + recommended_action
- check.completed events
- Result schema integrity
- Meta file persisted across runs
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety


import strix.tools.nuclei_templates.nuclei_template_update  # noqa: F401

nu_module = sys.modules["strix.tools.nuclei_templates.nuclei_template_update"]
nuclei_template_update = nu_module.nuclei_template_update


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    monkeypatch.delenv("STRIX_NUCLEI_BIN", raising=False)
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("nu-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_binary(monkeypatch, path: str | None) -> None:
    monkeypatch.setattr(nu_module, "_locate_nuclei_binary", lambda: path)


def _patch_run(monkeypatch, responder):
    """Install a fake `_run_nuclei`. responder(binary, args, timeout) → dict."""
    log: list[dict[str, Any]] = []

    def fake(binary, args, timeout):
        kwargs = {"binary": binary, "args": tuple(args), "timeout": timeout}
        log.append(kwargs)
        return responder(binary, tuple(args), timeout)

    monkeypatch.setattr(nu_module, "_run_nuclei", fake)
    return log


def _success_run(*, version: str = "10.1.2", count: int = 9876, no_update: bool = False, applied: bool = False) -> dict[str, Any]:
    out_lines = []
    if version:
        out_lines.append(f"templates v{version}")
    if count:
        out_lines.append(f"loaded {count} templates")
    if no_update:
        out_lines.append("Already up-to-date")
    if applied:
        out_lines.append(f"Successfully updated to v{version}")
    return {
        "returncode": 0,
        "stdout": "\n".join(out_lines),
        "stderr": "",
        "duration_seconds": 1.23,
    }


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


def test_parse_version_extracted() -> None:
    out = nu_module._parse_nuclei_output("templates v10.1.2 loaded", "")
    assert out["version"] == "10.1.2"


def test_parse_version_with_v_prefix_optional() -> None:
    out = nu_module._parse_nuclei_output("Nuclei templates 10.1.2 ready", "")
    assert out["version"] == "10.1.2"


def test_parse_template_count() -> None:
    out = nu_module._parse_nuclei_output("loaded 9876 templates from disk", "")
    assert out["template_count"] == 9876


def test_parse_no_update_needed() -> None:
    out = nu_module._parse_nuclei_output("templates v10.1.2 already up-to-date", "")
    assert out["no_update_needed"] is True
    assert out["update_applied"] is False


def test_parse_update_applied() -> None:
    out = nu_module._parse_nuclei_output("Successfully updated to v10.1.3", "")
    assert out["update_applied"] is True


def test_parse_combined_stdout_stderr() -> None:
    """Parser should look at merged stdout+stderr."""
    out = nu_module._parse_nuclei_output("", "templates v10.1.2 loaded 1234 templates")
    assert out["version"] == "10.1.2"
    assert out["template_count"] == 1234


def test_parse_empty_input() -> None:
    out = nu_module._parse_nuclei_output("", "")
    assert out["version"] is None
    assert out["template_count"] is None
    assert out["no_update_needed"] is False
    assert out["update_applied"] is False


# ---------------------------------------------------------------------------
# Binary missing
# ---------------------------------------------------------------------------


def test_binary_missing_returns_failure(monkeypatch) -> None:
    _patch_binary(monkeypatch, None)
    log = _patch_run(monkeypatch, lambda *a, **k: pytest.fail("subprocess should not run"))
    out = nuclei_template_update()
    assert out["success"] is False
    assert "not found" in out["error"]
    assert log == []


# ---------------------------------------------------------------------------
# Throttle window
# ---------------------------------------------------------------------------


def test_throttle_skips_recent_run(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    log = _patch_run(monkeypatch, lambda *a, **k: pytest.fail("should be throttled"))

    # Pre-populate meta with a very recent run.
    nu_module._write_meta({
        "last_run_at": int(time.time()) - 10,  # 10s ago
        "last_version": "10.1.2",
        "last_template_count": 9876,
    })
    out = nuclei_template_update()
    assert out["throttled"] is True
    assert out["ran"] is False
    assert out["version_after"] == "10.1.2"
    assert log == []


def test_force_overrides_throttle(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.3", count=10000, applied=True),
    )

    nu_module._write_meta({
        "last_run_at": int(time.time()) - 10,
        "last_version": "10.1.2",
    })
    out = nuclei_template_update(force=True)
    assert out["throttled"] is False
    assert out["ran"] is True
    assert out["updated"] is True


def test_throttle_expired_runs(monkeypatch) -> None:
    """Last run > 30 min ago → run again."""
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.3", count=10000, applied=True),
    )
    nu_module._write_meta({
        "last_run_at": int(time.time()) - 3600,  # 1 hour ago
        "last_version": "10.1.2",
    })
    out = nuclei_template_update()
    assert out["throttled"] is False
    assert out["ran"] is True


# ---------------------------------------------------------------------------
# First run + update applied
# ---------------------------------------------------------------------------


def test_first_run_update_applied(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.3", count=10000, applied=True),
    )
    out = nuclei_template_update()
    assert out["success"] is True
    assert out["ran"] is True
    assert out["throttled"] is False
    assert out["updated"] is True
    assert out["version_after"] == "10.1.3"
    assert out["template_count_after"] == 10000
    assert out["binary_path"] == "/usr/local/bin/nuclei"

    # Meta file written.
    meta = nu_module._read_meta()
    assert meta["last_version"] == "10.1.3"
    assert meta["last_template_count"] == 10000


def test_first_run_emits_info_finding_with_new_version(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.3", count=10000, applied=True),
    )
    nuclei_template_update()
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    r = reports[0]
    assert r["severity"] == "info"
    assert r["category"] == "info_disclosure"
    assert "10.1.3" in r["title"] or "10.1.3" in r["description"]
    assert r.get("description_plain")
    assert r.get("recommended_action")


# ---------------------------------------------------------------------------
# Already current
# ---------------------------------------------------------------------------


def test_already_current_no_update(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.2", count=9876, no_update=True),
    )
    out = nuclei_template_update()
    assert out["success"] is True
    assert out["updated"] is False
    assert out["version_after"] == "10.1.2"


def test_already_current_emits_info_finding(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.2", count=9876, no_update=True),
    )
    nuclei_template_update()
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    assert "current" in reports[0]["title"].lower() or "already" in reports[0]["title"].lower()


# ---------------------------------------------------------------------------
# Subprocess errors
# ---------------------------------------------------------------------------


def test_subprocess_timeout_graceful(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(monkeypatch, lambda b, a, t: {
        "returncode": -1, "stdout": "", "stderr": "",
        "duration_seconds": float(t), "error": f"nuclei update timed out after {t}s",
    })
    out = nuclei_template_update(timeout=10)
    assert out["success"] is False
    assert "timed out" in out["error"]
    assert out["ran"] is True


def test_subprocess_oserror_graceful(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(monkeypatch, lambda b, a, t: {
        "returncode": -1, "stdout": "", "stderr": "",
        "duration_seconds": 0.1,
        "error": "nuclei subprocess failed: PermissionError: [Errno 13]",
    })
    out = nuclei_template_update()
    assert out["success"] is False
    assert "PermissionError" in out["error"]


# ---------------------------------------------------------------------------
# Args fallback (modern → legacy)
# ---------------------------------------------------------------------------


def test_legacy_args_fallback(monkeypatch) -> None:
    """Modern -ut returns nonzero with empty output → fallback to
    -update-templates."""
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    call_count = [0]

    def responder(binary, args, timeout):
        call_count[0] += 1
        if args == ("-ut", "-silent"):
            return {
                "returncode": 1,  # primary fails
                "stdout": "",
                "stderr": "Unknown flag: -ut",
                "duration_seconds": 0.1,
            }
        # Legacy succeeds.
        return _success_run(version="10.1.3", count=9999, applied=True)

    _patch_run(monkeypatch, responder)
    out = nuclei_template_update()
    assert out["success"] is True
    assert out["args_used"] == ["-update-templates", "-silent"]
    assert out["updated"] is True
    assert call_count[0] == 2


def test_no_fallback_when_primary_succeeds(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    log = _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.3", count=9999, applied=True),
    )
    nuclei_template_update()
    assert len(log) == 1  # primary args succeeded; no fallback
    assert log[0]["args"] == ("-ut", "-silent")


# ---------------------------------------------------------------------------
# Returncode handling
# ---------------------------------------------------------------------------


def test_nonzero_returncode_with_parseable_output_succeeds(monkeypatch) -> None:
    """Nuclei sometimes returns non-zero on 'no update needed' depending
    on the build; if we can still parse version/count, treat as success."""
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(monkeypatch, lambda b, a, t: {
        "returncode": 1,
        "stdout": "templates v10.1.2 loaded 9876 templates",
        "stderr": "",
        "duration_seconds": 0.5,
    })
    out = nuclei_template_update()
    # The version was successfully parsed → tool should consider this
    # a success (after potential fallback). Either primary or fallback
    # returns version, so result is success.
    assert out["success"] is True
    assert out["version_after"] == "10.1.2"


def test_returncode_nonzero_no_parseable_output_fails(monkeypatch) -> None:
    """Returncode != 0 AND no parseable output → both primary and
    fallback fail; surface as failure."""
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(monkeypatch, lambda b, a, t: {
        "returncode": 2,
        "stdout": "",
        "stderr": "fatal: panic",
        "duration_seconds": 0.5,
    })
    out = nuclei_template_update()
    assert out["success"] is False
    assert out["returncode"] == 2


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------


def test_huge_output_truncated() -> None:
    big = "x" * (nu_module._MAX_OUTPUT_BYTES + 100)
    out = nu_module._truncate(big)
    assert out.endswith("[output truncated]")
    assert len(out) <= nu_module._MAX_OUTPUT_BYTES + 50


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.2", count=9876, no_update=True),
    )
    nuclei_template_update()
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "nuclei_template_update" in summary["by_category"]
    assert summary["by_category"]["nuclei_template_update"]["not_vulnerable"] == 1


def test_check_event_inconclusive_when_binary_missing(monkeypatch) -> None:
    _patch_binary(monkeypatch, None)
    nuclei_template_update()
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["by_category"]["nuclei_template_update"]["inconclusive"] == 1


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema_keys(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.3", applied=True),
    )
    out = nuclei_template_update()
    for k in ("success", "ran", "throttled", "updated", "binary_path",
              "args_used", "version_before", "version_after",
              "template_count_after", "duration_seconds", "stdout",
              "stderr", "returncode", "findings_emitted"):
        assert k in out


# ---------------------------------------------------------------------------
# Meta persistence
# ---------------------------------------------------------------------------


def test_meta_persists_across_runs(monkeypatch) -> None:
    """Run once → meta written. Force run again → version_before reads meta."""
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")

    versions = ["10.1.2", "10.1.3"]
    counts = [9876, 9999]
    call_index = [0]

    def responder(b, a, t):
        i = min(call_index[0], len(versions) - 1)
        result = _success_run(version=versions[i], count=counts[i], applied=True)
        call_index[0] += 1
        return result

    _patch_run(monkeypatch, responder)
    out1 = nuclei_template_update()
    assert out1["version_after"] == "10.1.2"
    assert out1["version_before"] is None  # no prior meta

    out2 = nuclei_template_update(force=True)
    assert out2["version_before"] == "10.1.2"  # carried over from prior run
    assert out2["version_after"] == "10.1.3"
    assert out2["updated"] is True


def test_throttle_zero_seconds_disables(monkeypatch) -> None:
    """throttle_seconds=0 → never throttled."""
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    log = _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.2", count=9876, no_update=True),
    )
    nuclei_template_update()
    pre = len(log)
    nuclei_template_update(throttle_seconds=0)
    assert len(log) > pre


# ---------------------------------------------------------------------------
# §11 UX
# ---------------------------------------------------------------------------


def test_finding_carries_plain_and_action(monkeypatch) -> None:
    _patch_binary(monkeypatch, "/usr/local/bin/nuclei")
    _patch_run(
        monkeypatch,
        lambda b, a, t: _success_run(version="10.1.3", count=10000, applied=True),
    )
    nuclei_template_update()
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) == 1
    r = reports[0]
    assert r.get("description_plain")
    assert r.get("recommended_action")
    assert r["category"] == "info_disclosure"
    assert r["cwe"] == "CWE-200"
    assert r.get("verification_status") == "verified"
