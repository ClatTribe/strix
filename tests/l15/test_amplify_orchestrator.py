"""Tests for iter-26.5 + 26.6 — amplify orchestrator."""

from __future__ import annotations

import asyncio

import pytest

from strix.l15.amplify_orchestrator import (
    _AmplifyLedger,
    amplify_calls_so_far,
    clear_amplify_ledger,
    drain_amplify_queue_async,
)


def _run(coro):
    """Drive a coroutine to completion on a fresh event loop."""
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _clean():
    clear_amplify_ledger()
    yield
    clear_amplify_ledger()


@pytest.fixture
def mock_execute_tool(monkeypatch):
    """Patch the tool executor to return controllable outcomes."""
    invocations: list[tuple[str, dict]] = []

    async def _fake(tool_name, agent_state=None, **kwargs):
        invocations.append((tool_name, kwargs))
        if tool_name in (
            "scan_sqli_sqlmap", "scan_xss_dalfox",
            "scan_path_traversal", "scan_cmd_injection",
            "scan_ssrf", "scan_ssti",
        ):
            return {
                "status": "ok",
                "total_findings": 1,
                "findings": [{"severity": "high"}],
            }
        return {"status": "ok", "total_found": 5}

    monkeypatch.setattr(
        "strix.tools.executor.execute_tool",
        _fake,
    )

    def _fake_get(name):
        def _stub(target=None, target_url=None, **kw):
            return {"status": "ok"}
        return _stub

    monkeypatch.setattr(
        "strix.tools.registry.get_tool_by_name",
        _fake_get,
    )
    return invocations


# --------------------------------------------------------------------
# Pending confirmations
# --------------------------------------------------------------------

def test_confirmation_fires_and_marks_confirmed(mock_execute_tool):
    finding = {
        "id": "vuln-0001",
        "severity": "medium",
        "title": "Potential SQLi (SAST)",
        "cwe": "CWE-89",
        "rule_id": "semgrep-sqli",
        "pending_confirmations": [{
            "tool": "scan_sqli_sqlmap",
            "target_url": "https://e.com/api/search",
            "param": "q",
        }],
    }
    results = _run(drain_amplify_queue_async([finding]))
    fired = [r for r in results if r.status == "fired"]
    assert len(fired) == 1
    assert finding["severity"] == "high"  # medium → high
    assert finding["confirmed_by_dast"] is True
    assert finding["dast_confirmer"] == "scan_sqli_sqlmap"


def test_confirmation_with_no_findings_demotes_source(monkeypatch):
    async def _no_findings(tool_name, agent_state=None, **kw):
        return {"status": "ok", "total_findings": 0, "findings": []}

    monkeypatch.setattr(
        "strix.tools.executor.execute_tool", _no_findings,
    )
    monkeypatch.setattr(
        "strix.tools.registry.get_tool_by_name",
        lambda n: (lambda **k: None),
    )

    finding = {
        "id": "vuln-0001",
        "severity": "medium",
        "cwe": "CWE-89",
        "verification_status": "inconclusive",
        "pending_confirmations": [{
            "tool": "scan_sqli_sqlmap",
            "target_url": "https://e.com/api/search",
            "param": "q",
        }],
    }
    results = _run(drain_amplify_queue_async([finding]))
    assert results[0].status == "fired"
    assert finding["severity"] == "info"
    assert finding["noise"] is True
    assert finding["confirmed_by_dast"] is False


def test_exploited_finding_not_demoted_on_zero_confirm(monkeypatch):
    async def _no_findings(tool_name, agent_state=None, **kw):
        return {"status": "ok", "total_findings": 0, "findings": []}

    monkeypatch.setattr(
        "strix.tools.executor.execute_tool", _no_findings,
    )
    monkeypatch.setattr(
        "strix.tools.registry.get_tool_by_name",
        lambda n: (lambda **k: None),
    )

    finding = {
        "id": "vuln-0001",
        "severity": "critical",
        "cwe": "CWE-89",
        "verification_status": "exploited",
        "pending_confirmations": [{
            "tool": "scan_sqli_sqlmap",
            "target_url": "https://e.com/api/search",
        }],
    }
    _run(drain_amplify_queue_async([finding]))
    assert finding["severity"] == "critical"
    assert finding.get("noise") is not True


# --------------------------------------------------------------------
# Probe bundles
# --------------------------------------------------------------------

def test_bundle_step_fires_and_records_result(mock_execute_tool):
    finding = {
        "id": "vuln-0002",
        "endpoint": "https://e.com/admin",
        "triggered_probes": [
            {"tool": "scan_auth_flow",
             "args": {"target": "https://e.com/admin"},
             "rationale": "default creds",
             "stealth": False},
            {"tool": "discover_paths_feroxbuster",
             "args": {"target_url": "https://e.com/admin",
                      "wordlist": "admin-backups"},
             "rationale": "backup paths",
             "stealth": False},
        ],
    }
    results = _run(drain_amplify_queue_async([finding]))
    fired = [r for r in results if r.status == "fired"]
    assert len(fired) == 2
    assert len(finding["bundle_results"]) == 2


# --------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------

def test_same_request_only_fires_once(mock_execute_tool):
    finding = {
        "id": "vuln-0001",
        "cwe": "CWE-89",
        "pending_confirmations": [{
            "tool": "scan_sqli_sqlmap",
            "target_url": "https://e.com/x",
        }],
    }
    r1 = _run(drain_amplify_queue_async([finding]))
    r2 = _run(drain_amplify_queue_async([finding]))
    assert r1[0].status == "fired"
    assert r2[0].status == "skipped"
    assert "idempotent" in r2[0].reason


# --------------------------------------------------------------------
# Global cap
# --------------------------------------------------------------------

def test_global_cap_short_circuits(monkeypatch, mock_execute_tool):
    monkeypatch.setattr(
        "strix.l15.amplify_orchestrator._GLOBAL_AMPLIFY_CAP", 2,
    )
    findings = [
        {
            "id": f"vuln-{i:04d}",
            "cwe": "CWE-89",
            "pending_confirmations": [{
                "tool": "scan_sqli_sqlmap",
                "target_url": f"https://e.com/x{i}",
            }],
        }
        for i in range(5)
    ]
    results = _run(drain_amplify_queue_async(findings))
    fired = [r for r in results if r.status == "fired"]
    cap = [r for r in results if r.status == "cap_exceeded"]
    assert len(fired) == 2
    assert len(cap) >= 1


# --------------------------------------------------------------------
# Tool / target missing
# --------------------------------------------------------------------

def test_missing_tool_returns_error():
    finding = {
        "id": "vuln-0001",
        "pending_confirmations": [{"tool": "", "target_url": "https://e.com/"}],
    }
    results = _run(drain_amplify_queue_async([finding]))
    assert results[0].status == "error"
    assert "tool name missing" in results[0].reason


# --------------------------------------------------------------------
# Independent ledger
# --------------------------------------------------------------------

def test_independent_ledger():
    led = _AmplifyLedger()
    assert led.calls == 0
    led.mark_fired("v1", "tool", "tgt")
    assert led.calls == 1
    assert led.has_fired("v1", "tool", "tgt")
    led.clear()
    assert led.calls == 0


def test_amplify_calls_so_far_singleton():
    clear_amplify_ledger()
    assert amplify_calls_so_far() == 0


# --------------------------------------------------------------------
# Drain tool registration
# --------------------------------------------------------------------

def test_drain_amplify_queue_registered():
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name
    assert callable(get_tool_by_name("drain_amplify_queue"))


def test_drain_amplify_queue_in_lead_core_tools():
    from strix.agents.lead_agent.tool_catalog import _CORE_TOOLS
    assert "drain_amplify_queue" in _CORE_TOOLS


# --------------------------------------------------------------------
# iter-26-fix correctness regression — agent_state plumbing
# --------------------------------------------------------------------

def test_agent_state_plumbed_to_executor(monkeypatch):
    """iter-26-fix regression: drain_amplify_queue must pass its
    framework-injected `agent_state` through to `execute_tool`,
    otherwise sandbox-resident specialists (sqlmap, dalfox,
    feroxbuster, ...) error with 'Agent state with a valid
    sandbox_id is required'.

    The original Wave 3 implementation passed `agent_state=None`,
    which meant every auto-confirmation against a sandbox tool
    silently errored — the mock-based tests didn't catch it because
    they mocked execute_tool itself.
    """
    seen_agent_states: list = []

    async def _capture_agent_state(tool_name, agent_state=None, **kwargs):
        seen_agent_states.append(agent_state)
        return {"status": "ok", "total_findings": 0, "findings": []}

    monkeypatch.setattr(
        "strix.tools.executor.execute_tool", _capture_agent_state,
    )
    monkeypatch.setattr(
        "strix.tools.registry.get_tool_by_name",
        lambda n: (lambda **k: None),
    )

    finding = {
        "id": "vuln-0001",
        "cwe": "CWE-89",
        "pending_confirmations": [{
            "tool": "scan_sqli_sqlmap",
            "target_url": "https://e.com/x",
        }],
    }
    # Pass a sentinel agent_state through and assert it reaches the executor
    fake_state = type("S", (), {"sandbox_id": "abc", "sandbox_token": "tok"})()
    _run(drain_amplify_queue_async([finding], agent_state=fake_state))
    assert seen_agent_states == [fake_state]
