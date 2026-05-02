"""Tests for run.test_plan event + build_test_plan builder.

Roadmap §1. Pre-finding visibility into what a scan is going to do.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.test_plan import (
    _CATEGORIES_BY_TARGET_TYPE,
    _DNS_ONLY_PRUNED,
    build_test_plan,
)
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
    monkeypatch.delenv("STRIX_DNS_ONLY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    yield


def _events_for(run_name: str, tmp_path) -> list[dict[str, Any]]:
    p = tmp_path / "strix_runs" / run_name / "events.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line]


# ---------------------------------------------------------------------------
# build_test_plan — data shape
# ---------------------------------------------------------------------------


def test_empty_config_returns_well_formed_payload() -> None:
    plan = build_test_plan(None)
    assert plan["schema_version"] == 1
    assert plan["targets"] == []
    assert "no targets" in plan["summary_text"]


def test_domain_target_full_category_set() -> None:
    plan = build_test_plan({"targets": [{"type": "domain", "value": "example.com"}]})
    assert len(plan["targets"]) == 1
    target = plan["targets"][0]
    cat_names = [c["name"] for c in target["planned_categories"]]
    # Should include the headline domain-recon checks.
    assert "dns_security" in cat_names
    assert "email_security" in cat_names
    assert "subdomain_takeover" in cat_names
    assert "subdomain_enum" in cat_names
    assert target["skipped_categories"] == []


def test_web_application_target_categories() -> None:
    plan = build_test_plan({"targets": [
        {"type": "web_application", "value": "https://example.com"}
    ]})
    cat_names = [c["name"] for c in plan["targets"][0]["planned_categories"]]
    assert "xss" in cat_names
    assert "sql_injection" in cat_names
    assert "authentication" in cat_names
    assert "ssrf" in cat_names


def test_ip_address_target_categories() -> None:
    plan = build_test_plan({"targets": [{"type": "ip_address", "value": "1.2.3.4"}]})
    cat_names = [c["name"] for c in plan["targets"][0]["planned_categories"]]
    assert "port_scan" in cat_names
    assert "service_fingerprint" in cat_names
    assert "cve_correlation" in cat_names


def test_repository_and_local_code_share_categories() -> None:
    plan = build_test_plan({"targets": [
        {"type": "repository", "value": "https://github.com/x/y"},
        {"type": "local_code", "value": "/tmp/code"},
    ]})
    repo_cats = {c["name"] for c in plan["targets"][0]["planned_categories"]}
    code_cats = {c["name"] for c in plan["targets"][1]["planned_categories"]}
    assert repo_cats == code_cats
    assert "secret_scan" in repo_cats
    assert "dependency_scan" in repo_cats


def test_unknown_target_type_keeps_target_with_empty_categories() -> None:
    """Don't drop the target — emit it with empty lists so consumers see it."""
    plan = build_test_plan({"targets": [{"type": "saas_account", "value": "acct-1"}]})
    assert len(plan["targets"]) == 1
    assert plan["targets"][0]["planned_categories"] == []
    assert plan["targets"][0]["skipped_categories"] == []


def test_target_id_is_stable_per_position() -> None:
    plan = build_test_plan({"targets": [
        {"type": "domain", "value": "a.example.com"},
        {"type": "domain", "value": "b.example.com"},
    ]})
    ids = [t["target_id"] for t in plan["targets"]]
    assert ids == ["target-0001", "target-0002"]


def test_unusable_targets_skipped() -> None:
    """Targets without a usable value are dropped from the plan
    (consistent with target.started behavior)."""
    plan = build_test_plan({"targets": [
        {"type": "domain", "value": "example.com"},
        {"type": "domain"},  # no value
        "raw-string.com",
    ]})
    values = [t["value"] for t in plan["targets"]]
    assert values == ["example.com", "raw-string.com"]


# ---------------------------------------------------------------------------
# dns_only mode — pruning
# ---------------------------------------------------------------------------


def test_dns_only_prunes_active_probe_categories_for_domain() -> None:
    plan = build_test_plan(
        {"targets": [{"type": "domain", "value": "example.com"}]},
        dns_only=True,
    )
    target = plan["targets"][0]
    planned_names = {c["name"] for c in target["planned_categories"]}
    skipped_names = {c["name"] for c in target["skipped_categories"]}
    # Pruned categories shouldn't appear in planned.
    assert _DNS_ONLY_PRUNED.isdisjoint(planned_names)
    # And they should appear in skipped with a reason.
    assert _DNS_ONLY_PRUNED <= skipped_names
    for entry in target["skipped_categories"]:
        assert entry.get("reason") == "dns-only mode active"


def test_dns_only_does_not_affect_web_application() -> None:
    """dns_only is a domain-only mode; web_application targets keep their full set."""
    plan = build_test_plan(
        {"targets": [{"type": "web_application", "value": "https://example.com"}]},
        dns_only=True,
    )
    assert plan["targets"][0]["skipped_categories"] == []


def test_dns_only_flag_in_payload() -> None:
    plan = build_test_plan({"targets": []}, dns_only=True)
    assert plan["dns_only"] is True
    plan2 = build_test_plan({"targets": []}, dns_only=False)
    assert plan2["dns_only"] is False


# ---------------------------------------------------------------------------
# summary_text
# ---------------------------------------------------------------------------


def test_summary_text_single_target() -> None:
    plan = build_test_plan({"targets": [{"type": "domain", "value": "example.com"}]})
    text = plan["summary_text"]
    assert "1 domain target" in text
    assert "example.com" in text
    # Number of categories should appear.
    n = len(_CATEGORIES_BY_TARGET_TYPE["domain"])
    assert str(n) in text


def test_summary_text_multi_target() -> None:
    plan = build_test_plan({"targets": [
        {"type": "domain", "value": "a.example.com"},
        {"type": "domain", "value": "b.example.com"},
        {"type": "ip_address", "value": "1.2.3.4"},
    ]})
    text = plan["summary_text"]
    assert "3 target(s)" in text
    assert "domain" in text
    assert "ip_address" in text


def test_summary_text_no_targets() -> None:
    text = build_test_plan({"targets": []})["summary_text"]
    assert "no targets" in text


# ---------------------------------------------------------------------------
# Event emission via Tracer.set_scan_config
# ---------------------------------------------------------------------------


def test_set_scan_config_emits_run_test_plan(tmp_path) -> None:
    t = Tracer("plan-evt")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    events = _events_for("plan-evt", tmp_path)
    plan_events = [e for e in events if e["event_type"] == "run.test_plan"]
    assert len(plan_events) == 1
    payload = plan_events[0]["payload"]
    assert payload["schema_version"] == 1
    assert len(payload["targets"]) == 1
    assert payload["targets"][0]["value"] == "example.com"


def test_run_test_plan_after_target_started(tmp_path) -> None:
    """run.test_plan should land after target.started events. Consumers
    reading in order know the targets first, then what's planned for them."""
    t = Tracer("order-run")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    events = _events_for("order-run", tmp_path)
    types = [e["event_type"] for e in events]
    started_idx = types.index("target.started")
    plan_idx = types.index("run.test_plan")
    assert started_idx < plan_idx


def test_run_test_plan_picks_up_dns_only_env(tmp_path, monkeypatch) -> None:
    """STRIX_DNS_ONLY=1 in the environment should mark the plan dns_only=True."""
    monkeypatch.setenv("STRIX_DNS_ONLY", "1")
    t = Tracer("dns-only-evt")
    set_global_tracer(t)
    t.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    events = _events_for("dns-only-evt", tmp_path)
    plan = next(e["payload"] for e in events if e["event_type"] == "run.test_plan")
    assert plan["dns_only"] is True
    # Pruned categories should be in skipped, not planned.
    target = plan["targets"][0]
    planned_names = {c["name"] for c in target["planned_categories"]}
    assert "subdomain_takeover" not in planned_names
    assert any(c["name"] == "subdomain_takeover" for c in target["skipped_categories"])


def test_run_test_plan_picks_up_dns_only_in_config(tmp_path) -> None:
    """dns_only=True in the scan_config dict also activates the mode."""
    t = Tracer("dns-cfg")
    set_global_tracer(t)
    t.set_scan_config({
        "targets": [{"type": "domain", "value": "example.com"}],
        "dns_only": True,
    })
    events = _events_for("dns-cfg", tmp_path)
    plan = next(e["payload"] for e in events if e["event_type"] == "run.test_plan")
    assert plan["dns_only"] is True


def test_no_test_plan_when_no_targets(tmp_path) -> None:
    """Empty target list should still emit a plan event (with empty targets array)
    so consumers know the scan was configured but had nothing to do."""
    t = Tracer("empty-cfg")
    set_global_tracer(t)
    t.set_scan_config({"targets": []})
    events = _events_for("empty-cfg", tmp_path)
    plans = [e for e in events if e["event_type"] == "run.test_plan"]
    assert len(plans) == 1
    assert plans[0]["payload"]["targets"] == []
