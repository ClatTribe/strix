"""Tests for the LLM-facing scan_nuclei_templates specialist."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from strix.tools.nuclei_runner.nuclei_runner import scan_nuclei_templates


_FIXTURES = Path(__file__).parent / "fixtures" / "templates"


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path) -> None:
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-nuclei-runner"))
    yield


@pytest.fixture(autouse=True)
def _reset_security_context() -> None:
    from strix.agents.security_context import reset_security_context
    reset_security_context()
    yield
    reset_security_context()


@pytest.fixture
def fixture_corpus(monkeypatch):
    """Point the runner at the test-fixture corpus."""
    monkeypatch.setenv("STRIX_NUCLEI_TEMPLATES_DIR", str(_FIXTURES))
    yield _FIXTURES


@pytest.fixture
def fake_proxy(monkeypatch):
    state = {"fn": lambda *a, **kw: {"status_code": 200, "body": "", "headers": {}}}

    def setter(fn):
        state["fn"] = fn

    fake = MagicMock()
    fake.send_simple_request = MagicMock(
        side_effect=lambda method, url, headers, body, timeout: state["fn"](
            method, url, headers, body, timeout,
        )
    )
    monkeypatch.setattr(
        "strix.tools.proxy.proxy_manager.get_proxy_manager", lambda: fake,
    )
    return setter


# ---------------------------------------------------------------------------
# Defensive
# ---------------------------------------------------------------------------


def test_empty_url_returns_error() -> None:
    out = scan_nuclei_templates(url="")
    assert out["status"] == "error"


def test_corpus_missing_returns_partial(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("STRIX_NUCLEI_TEMPLATES_DIR", str(tmp_path / "nope"))
    out = scan_nuclei_templates(url="http://target.test/")
    assert out["status"] == "partial"
    assert "refresh" in out["error"].lower()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_apache_flink_template_fires(fixture_corpus, fake_proxy) -> None:
    """Server returns Apache Flink dashboard at /jobmanager/logs →
    template fires, finding emitted."""
    def fake(method, url, headers, body, timeout):
        if "/jobmanager/logs" in url:
            return {
                "status_code": 200,
                "body": "Apache Flink Dashboard",
                "headers": {},
            }
        return {"status_code": 404, "body": "", "headers": {}}

    fake_proxy(fake)
    out = scan_nuclei_templates(
        url="http://flink.test/",
        template_ids=["apache-flink-unauth-fixture"],
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["category"] == "nuclei"
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-552"
    assert "Apache Flink" in f["title"]


def test_filter_by_tags_narrows_run(fixture_corpus, fake_proxy) -> None:
    """tags=['jenkins'] → only the jenkins template is run."""
    fake_proxy(lambda *a, **kw: {
        "status_code": 200,
        "body": "Jenkins 2.387.1",
        "headers": {},
    })
    out = scan_nuclei_templates(
        url="http://target.test/",
        tags=["jenkins"],
    )
    assert out["tool_metadata"]["templates_run"] == 1
    # The jenkins fixture has both regex + status (AND condition);
    # response matches both → finding emitted.
    assert any(f["category"] == "nuclei" for f in out["findings"])


def test_filter_by_severity(fixture_corpus, fake_proxy) -> None:
    fake_proxy(lambda *a, **kw: {"status_code": 404, "body": "", "headers": {}})
    out = scan_nuclei_templates(
        url="http://target.test/",
        severity=["critical"],
    )
    # Only the critical-severity templates run (apache-flink + log4shell).
    assert out["tool_metadata"]["templates_run"] >= 1


def test_max_templates_caps_run(fixture_corpus, fake_proxy) -> None:
    fake_proxy(lambda *a, **kw: {"status_code": 404, "body": "", "headers": {}})
    out = scan_nuclei_templates(
        url="http://target.test/",
        max_templates=1,
    )
    assert out["tool_metadata"]["templates_run"] == 1


def test_no_templates_match_no_findings(fixture_corpus, fake_proxy) -> None:
    """Server returns 500 across the board → all status-200 matchers
    fail → no findings."""
    fake_proxy(lambda *a, **kw: {
        "status_code": 500,
        "body": "Internal Server Error",
        "headers": {},
    })
    # Use a single non-log4shell template so the OR-condition negative
    # matcher in log4shell's fixture doesn't trip on the 500.
    out = scan_nuclei_templates(
        url="http://target.test/",
        template_ids=["apache-flink-unauth-fixture"],
    )
    assert out["status"] == "ok"
    assert len(out["findings"]) == 0


# ---------------------------------------------------------------------------
# Auth auto-injection
# ---------------------------------------------------------------------------


def test_auth_state_bearer_auto_forwarded(fixture_corpus, fake_proxy) -> None:
    captured: list[dict] = []
    def fake(method, url, headers, body, timeout):
        captured.append(dict(headers or {}))
        return {"status_code": 200, "body": "", "headers": {}}
    fake_proxy(fake)

    from strix.agents.security_context import record_auth_state
    record_auth_state(label="lead", bearer="ntok")

    scan_nuclei_templates(
        url="http://target.test/",
        template_ids=["apache-flink-unauth-fixture"],
    )
    assert any(
        h.get("Authorization") == "Bearer ntok" for h in captured
    )


# ---------------------------------------------------------------------------
# SecurityContext + decision_log
# ---------------------------------------------------------------------------


def test_records_endpoint_probed_for_nuclei_runner(
    fixture_corpus, fake_proxy,
) -> None:
    fake_proxy(lambda *a, **kw: {"status_code": 404, "body": "", "headers": {}})
    scan_nuclei_templates(url="http://target.test/")
    from strix.agents.security_context import list_endpoints
    eps = list_endpoints()
    assert any("nuclei_runner" in (e.probed_for or []) for e in eps)


def test_records_decision_log_entry(
    fixture_corpus, fake_proxy,
) -> None:
    from strix.agents.decision_log import (
        list_decisions, reset_decision_log,
    )
    reset_decision_log()
    fake_proxy(lambda *a, **kw: {"status_code": 404, "body": "", "headers": {}})
    scan_nuclei_templates(url="http://target.test/")
    decisions = list_decisions()
    assert any(
        d.kind == "specialist_invocation"
        and d.actor.get("tool_name") == "scan_nuclei_templates"
        for d in decisions
    )


# ---------------------------------------------------------------------------
# Registry / catalog wiring
# ---------------------------------------------------------------------------


def test_scan_nuclei_templates_registered() -> None:
    from strix.tools.specialist.registry import get_specialist_descriptor
    desc = get_specialist_descriptor("scan_nuclei_templates")
    assert desc is not None
    assert desc.llm is False
    assert desc.category == "nuclei-runner"


def test_scan_nuclei_templates_in_lead_web_application_catalog() -> None:
    from strix.agents.lead_agent.tool_catalog import get_lead_tool_catalog
    catalog = get_lead_tool_catalog(target_types=["web_application"])
    assert "scan_nuclei_templates" in catalog
