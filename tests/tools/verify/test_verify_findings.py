"""Tests for verify_findings (roadmap §8.2 row 3 — Verifier agent).

Hermetic — each underlying probe tool's `*_check` function is
monkeypatched. Tests cover:

- update_finding_verification (tracer method)
- verify_findings: eligibility filter (status / category / endpoint)
- verify_findings: per-strategy dispatch
- verify_findings: ok=True → verified
- verify_findings: ok=False → could_not_verify
- verify_findings: per-finding probe exception → skipped, not crashed
- verify_findings: max_findings cap
- verify_findings: finding_ids filter
- verify_findings: categories filter
- verify_findings: already-verified findings skipped
- finding.verification_attempted event emitted
- update_finding_verification rejects non-canonical statuses
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("vf-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "web_application", "value": "https://app.example.com"}]}
    )
    yield


def _emit(tracer: Tracer, **overrides: Any) -> str:
    """Helper to emit a canonical finding via the tracer."""
    base = {
        "title": "Test finding",
        "severity": "medium",
        "category": "information_disclosure",
        "endpoint": "https://app.example.com/api",
        "verification_status": "needs_review",
        "description_plain": "p",
        "recommended_action": "a",
        "cwe": "CWE-200",
    }
    base.update(overrides)
    return tracer.add_vulnerability_report(**base)


def _stub_probe_modules(monkeypatch, *, fires: bool = True) -> dict[str, int]:
    """Stub each underlying probe tool to return findings_emitted=N
    based on the `fires` flag. Returns a counter dict for asserting
    call counts."""
    calls: dict[str, int] = {
        "debug_endpoint_check": 0,
        "cors_deep_check": 0,
        "open_redirect_check": 0,
        "method_tamper_check": 0,
        "host_header_check": 0,
    }

    def make_stub(name: str):
        def stub(**kwargs):
            calls[name] += 1
            return {"success": True, "findings_emitted": 1 if fires else 0}
        return stub

    # Force-import each module so sys.modules has it.
    import strix.tools.debug_endpoint.debug_endpoint_check  # noqa: F401
    import strix.tools.cors_check.cors_deep_check  # noqa: F401
    import strix.tools.open_redirect.open_redirect_check  # noqa: F401
    import strix.tools.method_tamper.method_tamper_check  # noqa: F401
    import strix.tools.host_header.host_header_check  # noqa: F401

    monkeypatch.setattr(
        sys.modules["strix.tools.debug_endpoint.debug_endpoint_check"],
        "debug_endpoint_check", make_stub("debug_endpoint_check"),
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.cors_check.cors_deep_check"],
        "cors_deep_check", make_stub("cors_deep_check"),
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.open_redirect.open_redirect_check"],
        "open_redirect_check", make_stub("open_redirect_check"),
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.method_tamper.method_tamper_check"],
        "method_tamper_check", make_stub("method_tamper_check"),
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.host_header.host_header_check"],
        "host_header_check", make_stub("host_header_check"),
    )
    return calls


def _verify_findings():
    from strix.tools.verify.verify_findings import verify_findings
    return verify_findings


# ---------------------------------------------------------------------------
# update_finding_verification (tracer method)
# ---------------------------------------------------------------------------


def test_update_finding_verification_sets_status() -> None:
    tracer = tracer_module.get_global_tracer()
    rid = _emit(tracer)
    ok = tracer.update_finding_verification(
        report_id=rid, new_status="verified",
        evidence="re-probe still fires",
    )
    assert ok is True
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "verified"
    assert findings[0]["verification_evidence"] == "re-probe still fires"


def test_update_finding_verification_unknown_id_returns_false() -> None:
    tracer = tracer_module.get_global_tracer()
    ok = tracer.update_finding_verification(
        report_id="vuln-9999", new_status="verified",
    )
    assert ok is False


def test_update_finding_verification_rejects_non_canonical_status() -> None:
    tracer = tracer_module.get_global_tracer()
    rid = _emit(tracer)
    ok = tracer.update_finding_verification(
        report_id=rid, new_status="bogus_status",
    )
    assert ok is False
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] != "bogus_status"


def test_update_finding_verification_emits_event(tmp_path) -> None:
    tracer = tracer_module.get_global_tracer()
    rid = _emit(tracer)
    tracer.update_finding_verification(
        report_id=rid, new_status="could_not_verify",
        evidence="re-probe didn't fire",
    )
    events_file = tracer.get_run_dir() / "events.jsonl"
    events = [
        json.loads(l) for l in events_file.read_text().splitlines() if l.strip()
    ]
    verif_events = [
        e for e in events
        if (e.get("event_type") or e.get("event")) == "finding.verification_attempted"
    ]
    assert len(verif_events) == 1
    payload = verif_events[0].get("payload") or {}
    assert payload["new_status"] == "could_not_verify"
    assert payload["report_id"] == rid


# ---------------------------------------------------------------------------
# verify_findings — basic flow
# ---------------------------------------------------------------------------


def test_verifier_no_findings_returns_empty() -> None:
    out = _verify_findings()()
    assert out["success"] is True
    assert out["eligible_count"] == 0
    assert out["verified"] == []
    assert out["could_not_verify"] == []


def test_verifier_re_probe_fires_marks_verified(monkeypatch) -> None:
    tracer = tracer_module.get_global_tracer()
    rid = _emit(tracer, category="information_disclosure")
    _stub_probe_modules(monkeypatch, fires=True)

    out = _verify_findings()()
    assert out["success"] is True
    assert out["processed_count"] == 1
    assert any(v["report_id"] == rid for v in out["verified"])

    # Finding's verification_status was updated.
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "verified"


def test_verifier_re_probe_silent_marks_could_not_verify(monkeypatch) -> None:
    tracer = tracer_module.get_global_tracer()
    rid = _emit(tracer, category="information_disclosure")
    _stub_probe_modules(monkeypatch, fires=False)

    out = _verify_findings()()
    assert out["processed_count"] == 1
    assert any(v["report_id"] == rid for v in out["could_not_verify"])

    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "could_not_verify"


# ---------------------------------------------------------------------------
# Eligibility filters
# ---------------------------------------------------------------------------


def test_verifier_skips_already_verified(monkeypatch) -> None:
    tracer = tracer_module.get_global_tracer()
    rid = _emit(tracer, verification_status="verified")
    _stub_probe_modules(monkeypatch, fires=True)

    out = _verify_findings()()
    assert any(s["reason"] == "already_verified" for s in out["skipped"])
    assert out["processed_count"] == 0


def test_verifier_skips_categories_without_strategy(monkeypatch) -> None:
    tracer = tracer_module.get_global_tracer()
    rid = _emit(tracer, category="weak_session_id")  # no strategy
    _stub_probe_modules(monkeypatch, fires=True)

    out = _verify_findings()()
    assert any(s["reason"].startswith("no_strategy") for s in out["skipped"])
    assert out["processed_count"] == 0


def test_verifier_skips_findings_without_endpoint(monkeypatch) -> None:
    """No endpoint → skipped early. Use code_locations for locatability
    so the canonical contract still passes."""
    tracer = tracer_module.get_global_tracer()
    rid = tracer.add_vulnerability_report(
        title="Dependency CVE",
        severity="medium",
        category="information_disclosure",  # in strategy table
        cwe="CWE-200",
        verification_status="needs_review",
        description_plain="p", recommended_action="a",
        code_locations=[{"file": "x.py", "line": 1}],  # locatable, but no endpoint
    )
    _stub_probe_modules(monkeypatch, fires=True)

    out = _verify_findings()()
    skips = [s for s in out["skipped"] if s["report_id"] == rid]
    assert any(s["reason"] == "missing_endpoint" for s in skips)


# ---------------------------------------------------------------------------
# Per-strategy dispatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("category,expected_call", [
    ("information_disclosure", "debug_endpoint_check"),
    ("cors_misconfiguration", "cors_deep_check"),
    ("open_redirect", "open_redirect_check"),
    ("method_disclosure", "method_tamper_check"),
    ("xst", "method_tamper_check"),
    ("webdav_exposure", "method_tamper_check"),
    ("host_header_injection", "host_header_check"),
    ("cache_poisoning", "host_header_check"),
])
def test_verifier_dispatches_per_category(monkeypatch, category, expected_call) -> None:
    tracer = tracer_module.get_global_tracer()
    _emit(tracer, category=category)
    calls = _stub_probe_modules(monkeypatch, fires=True)

    _verify_findings()()
    # Matching probe was called.
    assert calls[expected_call] >= 1


# ---------------------------------------------------------------------------
# Caps + filters
# ---------------------------------------------------------------------------


def test_verifier_max_findings_cap(monkeypatch) -> None:
    tracer = tracer_module.get_global_tracer()
    for i in range(5):
        _emit(tracer, title=f"T{i}", endpoint=f"https://app.example.com/{i}")
    _stub_probe_modules(monkeypatch, fires=True)

    out = _verify_findings()(max_findings=2)
    assert out["eligible_count"] == 5
    assert out["processed_count"] == 2


def test_verifier_finding_ids_filter(monkeypatch) -> None:
    tracer = tracer_module.get_global_tracer()
    rid_a = _emit(tracer, title="A")
    rid_b = _emit(tracer, title="B")
    _stub_probe_modules(monkeypatch, fires=True)

    out = _verify_findings()(finding_ids=rid_a)
    assert out["processed_count"] == 1
    assert any(v["report_id"] == rid_a for v in out["verified"])
    # The other finding wasn't touched.
    findings = tracer.get_existing_vulnerabilities()
    other = [f for f in findings if f.get("id") == rid_b][0]
    assert other["verification_status"] == "needs_review"


def test_verifier_categories_filter(monkeypatch) -> None:
    tracer = tracer_module.get_global_tracer()
    _emit(tracer, category="information_disclosure", endpoint="https://x/a")
    _emit(tracer, category="cors_misconfiguration", endpoint="https://x/b")
    _stub_probe_modules(monkeypatch, fires=True)

    out = _verify_findings()(categories="cors_misconfiguration")
    # Only the CORS finding processed.
    assert out["processed_count"] == 1
    cats = {v["category"] for v in out["verified"]}
    assert cats == {"cors_misconfiguration"}


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_verifier_per_finding_exception_swallowed(monkeypatch) -> None:
    tracer = tracer_module.get_global_tracer()
    _emit(tracer, category="information_disclosure", endpoint="https://x/1")
    _emit(tracer, category="cors_misconfiguration", endpoint="https://x/2")

    # Force-import + patch.
    import strix.tools.debug_endpoint.debug_endpoint_check  # noqa: F401
    import strix.tools.cors_check.cors_deep_check  # noqa: F401

    def boom(**kw):
        raise RuntimeError("debug_endpoint_check broke")

    def good(**kw):
        return {"success": True, "findings_emitted": 1}

    monkeypatch.setattr(
        sys.modules["strix.tools.debug_endpoint.debug_endpoint_check"],
        "debug_endpoint_check", boom,
    )
    monkeypatch.setattr(
        sys.modules["strix.tools.cors_check.cors_deep_check"],
        "cors_deep_check", good,
    )

    out = _verify_findings()()
    # Both processed; debug_endpoint failed → could_not_verify with
    # verifier_error in evidence.
    assert out["processed_count"] == 2
    fail = [v for v in out["could_not_verify"] if "verifier_error" in v.get("evidence", "")]
    assert len(fail) == 1


def test_verifier_returns_well_shaped_result_when_no_tracer(monkeypatch) -> None:
    """When the global tracer isn't set, the tool returns a clear error
    rather than crashing."""
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    out = _verify_findings()()
    assert out["success"] is False
    assert "tracer" in out.get("error", "").lower()


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("verify_findings")
    assert "T1190" in techniques


# ---------------------------------------------------------------------------
# §8.1 row 4 — code-target re-verification strategies
# ---------------------------------------------------------------------------


def test_taint_flow_strategy_dispatched(monkeypatch) -> None:
    """taint_flow → re-runs taint_analysis."""
    tracer = tracer_module.get_global_tracer()
    rid = tracer.add_vulnerability_report(
        title="Taint flow",
        severity="high",
        category="taint_flow",
        cwe="CWE-20",
        endpoint="app.py:42",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
        code_locations=[{"file": "app.py", "line": 42}],
    )

    # Stub taint_analysis to return a flow at line 42 (matching).
    import strix.tools.taint.taint_analysis  # noqa: F401
    captured = {"calls": []}

    def fake_taint(repo_path, **kw):
        captured["calls"].append(repo_path)
        return {
            "success": True,
            "flows": [{"file": "app.py", "lineno": 42, "sink_label": "eval"}],
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.taint.taint_analysis"],
        "taint_analysis", fake_taint,
    )

    # Create the file so the verifier finds it (it tries Path.cwd() / file).
    from pathlib import Path
    Path("app.py").write_text("# stub")

    out = _verify_findings()()
    assert out["processed_count"] == 1
    assert any(v["report_id"] == rid for v in out["verified"])
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "verified"


def test_taint_flow_line_mismatch_marks_could_not_verify(monkeypatch) -> None:
    """Same file but different line → could_not_verify."""
    tracer = tracer_module.get_global_tracer()
    rid = tracer.add_vulnerability_report(
        title="Taint flow",
        severity="high",
        category="taint_flow",
        cwe="CWE-20",
        endpoint="app.py:42",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
        code_locations=[{"file": "app.py", "line": 42}],
    )

    import strix.tools.taint.taint_analysis  # noqa: F401

    def fake_taint(repo_path, **kw):
        # Returns a flow but at a different line
        return {
            "success": True,
            "flows": [{"file": "app.py", "lineno": 99}],
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.taint.taint_analysis"],
        "taint_analysis", fake_taint,
    )

    from pathlib import Path
    Path("app.py").write_text("# stub")

    out = _verify_findings()()
    assert any(v["report_id"] == rid for v in out["could_not_verify"])
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "could_not_verify"


def test_taint_flow_file_missing_marks_could_not_verify(monkeypatch) -> None:
    """File no longer exists → could_not_verify."""
    tracer = tracer_module.get_global_tracer()
    tracer.add_vulnerability_report(
        title="Taint flow",
        severity="high",
        category="taint_flow",
        cwe="CWE-20",
        endpoint="nonexistent_file.py:42",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
        code_locations=[{"file": "nonexistent_file.py", "line": 42}],
    )

    out = _verify_findings()()
    # Either could_not_verify (file-missing branch) or verifier_error.
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "could_not_verify"


def test_vulnerable_dependency_strategy_dispatched(monkeypatch) -> None:
    """vulnerable_dependency → re-runs cve_lookup."""
    tracer = tracer_module.get_global_tracer()
    rid = tracer.add_vulnerability_report(
        title="lodash CVE-2021-23337",
        severity="high",
        category="vulnerable_dependency",
        cwe="CWE-77",
        cve="CVE-2021-23337",
        endpoint="npm://lodash@4.17.20",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
    )

    import strix.tools.cve_lookup.cve_lookup  # noqa: F401
    captured = {"calls": []}

    def fake_cve_lookup(package_name, package_version, ecosystem=None, **kw):
        captured["calls"].append({
            "name": package_name, "version": package_version, "ecosystem": ecosystem,
        })
        return {
            "success": True,
            "vulnerabilities": [{"id": "CVE-2021-23337"}],
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.cve_lookup.cve_lookup"],
        "cve_lookup", fake_cve_lookup,
    )

    out = _verify_findings()()
    assert out["processed_count"] == 1
    assert any(v["report_id"] == rid for v in out["verified"])
    # cve_lookup got the right args.
    assert captured["calls"][0]["name"] == "lodash"
    assert captured["calls"][0]["version"] == "4.17.20"
    assert captured["calls"][0]["ecosystem"] == "npm"


def test_vulnerable_dependency_cve_no_longer_present(monkeypatch) -> None:
    """cve_lookup re-run returns CVEs but not the original one →
    could_not_verify (vendor patched it)."""
    tracer = tracer_module.get_global_tracer()
    tracer.add_vulnerability_report(
        title="lodash CVE-2021-23337",
        severity="high",
        category="vulnerable_dependency",
        cwe="CWE-77",
        cve="CVE-2021-23337",
        endpoint="npm://lodash@4.17.21",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
    )

    import strix.tools.cve_lookup.cve_lookup  # noqa: F401

    def fake_cve_lookup(package_name, package_version, ecosystem=None, **kw):
        # Returns a different CVE — the patched version
        return {
            "success": True,
            "vulnerabilities": [{"id": "CVE-2099-99999"}],
        }

    monkeypatch.setattr(
        sys.modules["strix.tools.cve_lookup.cve_lookup"],
        "cve_lookup", fake_cve_lookup,
    )

    out = _verify_findings()()
    assert out["processed_count"] == 1
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "could_not_verify"


def test_vulnerable_dependency_no_cves_returned(monkeypatch) -> None:
    """cve_lookup returns no CVEs → could_not_verify."""
    tracer = tracer_module.get_global_tracer()
    tracer.add_vulnerability_report(
        title="package CVE",
        severity="high",
        category="vulnerable_dependency",
        cwe="CWE-77",
        endpoint="pypi://requests@2.31.0",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
    )

    import strix.tools.cve_lookup.cve_lookup  # noqa: F401

    def fake_cve_lookup(**kw):
        return {"success": True, "vulnerabilities": []}

    monkeypatch.setattr(
        sys.modules["strix.tools.cve_lookup.cve_lookup"],
        "cve_lookup", fake_cve_lookup,
    )

    out = _verify_findings()()
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "could_not_verify"


def test_vulnerable_dependency_malformed_endpoint(monkeypatch) -> None:
    """Endpoint without ://...@ shape → graceful could_not_verify."""
    tracer = tracer_module.get_global_tracer()
    tracer.add_vulnerability_report(
        title="bad endpoint",
        severity="high",
        category="vulnerable_dependency",
        cwe="CWE-77",
        endpoint="just-a-string",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
    )
    out = _verify_findings()()
    assert out["processed_count"] == 1
    findings = tracer.get_existing_vulnerabilities()
    assert findings[0]["verification_status"] == "could_not_verify"


def test_scoped_npm_package_parsed_correctly(monkeypatch) -> None:
    """`@scope/pkg@1.2.3` rsplit('@', 1) gives correct (name, version)."""
    tracer = tracer_module.get_global_tracer()
    tracer.add_vulnerability_report(
        title="scoped pkg",
        severity="medium",
        category="vulnerable_dependency",
        cwe="CWE-77",
        cve="CVE-2024-99999",
        endpoint="npm://@scope/pkg@1.2.3",
        verification_status="pattern_match",
        description_plain="p", recommended_action="a",
    )

    import strix.tools.cve_lookup.cve_lookup  # noqa: F401
    captured = {"calls": []}

    def fake_cve_lookup(package_name, package_version, ecosystem=None, **kw):
        captured["calls"].append({"name": package_name, "version": package_version})
        return {"success": True, "vulnerabilities": [{"id": "CVE-2024-99999"}]}

    monkeypatch.setattr(
        sys.modules["strix.tools.cve_lookup.cve_lookup"],
        "cve_lookup", fake_cve_lookup,
    )

    _verify_findings()()
    assert captured["calls"][0]["name"] == "@scope/pkg"
    assert captured["calls"][0]["version"] == "1.2.3"


def test_taint_flow_and_dependency_in_verifiable_categories() -> None:
    """The two new categories are in the verifiable allow-list."""
    from strix.tools.verify.verify_findings import _VERIFIABLE_CATEGORIES
    assert "taint_flow" in _VERIFIABLE_CATEGORIES
    assert "vulnerable_dependency" in _VERIFIABLE_CATEGORIES
