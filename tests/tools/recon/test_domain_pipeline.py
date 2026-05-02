"""Tests for domain_recon_pipeline.

Hermetic — every underlying tool is mocked. We're testing the orchestration
shape (phase events, surface_map.json, deep/shallow/skip triage, next_steps),
not the underlying tool behaviour (those have their own test modules).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import domain_pipeline as dp


def _load_events(events_path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in events_path.read_text().splitlines() if line]


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
    tracer = Tracer("dp-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_underlying(
    monkeypatch,
    *,
    org_result: dict[str, Any] | None = None,
    dns_result: dict[str, Any] | None = None,
    passive_result: dict[str, Any] | None = None,
    takeover_result: dict[str, Any] | None = None,
    cloud_result: dict[str, Any] | None = None,
    subfinder_subs: list[str] | None = None,
    triage_responses: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Patch every tool the pipeline composes, plus subdomain enumeration
    and the per-host triage probe."""
    from strix.tools.recon import (
        cloud_assets,
        dns_hygiene,
        org_recon,
        passive_dns,
        takeover,
    )

    monkeypatch.setattr(
        org_recon, "org_fingerprint",
        lambda domain, **kw: org_result or {"success": True, "domain": domain},
    )
    monkeypatch.setattr(
        dns_hygiene, "dns_hygiene_check",
        lambda domain, **kw: dns_result or {"success": True, "results": []},
    )
    monkeypatch.setattr(
        passive_dns, "passive_dns_history",
        lambda domain, **kw: passive_result or {"success": False},
    )
    monkeypatch.setattr(
        takeover, "subdomain_takeover_check",
        lambda **kw: takeover_result or {"success": True, "candidates": 0, "results": []},
    )
    monkeypatch.setattr(
        cloud_assets, "discover_cloud_assets",
        lambda **kw: cloud_result or {"success": True, "hit_count": 0, "hits": []},
    )

    # Pipeline now delegates to strix.tools.recon.subdomain_enum_tool.subdomain_enum.
    # Mock the public function on the module the pipeline imports.
    from strix.tools.recon import subdomain_enum_tool as _subdomain_enum_mod

    enum_subs_list = subfinder_subs or []  # legacy parameter name; treats as enum result

    def fake_subdomain_enum(domain, **kw):
        return {
            "success": True,
            "domain": domain,
            "subdomains": enum_subs_list,
            "per_source_counts": {"subfinder": len(enum_subs_list)},
            "sources_run": ["subfinder"],
            "total_unique": len(enum_subs_list),
        }

    monkeypatch.setattr(_subdomain_enum_mod, "subdomain_enum", fake_subdomain_enum)

    triage_map = triage_responses or {}

    def fake_triage(host: str) -> dict[str, Any]:
        return triage_map.get(
            host,
            {"host": host, "ip": None, "live": False, "triage": "skip", "evidence": "no A record"},
        )

    monkeypatch.setattr(dp, "_triage_subdomain", fake_triage)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_invalid_domain_rejected() -> None:
    out = dp.domain_recon_pipeline("not a domain")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Phase events
# ---------------------------------------------------------------------------


def test_pipeline_brackets_recon_phase(monkeypatch, tmp_path) -> None:
    _patch_underlying(monkeypatch)
    out = dp.domain_recon_pipeline("example.com")
    assert out["success"] is True

    events = _load_events(tmp_path / "strix_runs" / "dp-test" / "events.jsonl")
    entered = [e for e in events if e["event_type"] == "phase.entered"]
    completed = [e for e in events if e["event_type"] == "phase.completed"]
    assert len(entered) == 1
    assert len(completed) == 1
    assert entered[0]["payload"]["phase"] == "recon"
    assert entered[0]["payload"]["focus"] == "domain:example.com"
    assert completed[0]["payload"]["phase_id"] == entered[0]["payload"]["phase_id"]


def test_pipeline_completes_phase_even_on_underlying_failure(monkeypatch, tmp_path) -> None:
    """A raised exception in one of the underlying tools should NOT leave the
    phase open — the orchestrator's `finally` block must close it."""
    from strix.tools.recon import org_recon

    monkeypatch.setattr(
        org_recon, "org_fingerprint",
        lambda domain, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    _patch_underlying(monkeypatch)  # patch the rest after; org keeps the raise
    monkeypatch.setattr(
        org_recon, "org_fingerprint",
        lambda domain, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(RuntimeError):
        dp.domain_recon_pipeline("example.com")

    events = _load_events(tmp_path / "strix_runs" / "dp-test" / "events.jsonl")
    # Phase still gets a completed event despite the inner error.
    assert any(e["event_type"] == "phase.completed" for e in events)


# ---------------------------------------------------------------------------
# Surface map structure
# ---------------------------------------------------------------------------


def test_surface_map_contains_required_keys(monkeypatch, tmp_path) -> None:
    _patch_underlying(monkeypatch)
    out = dp.domain_recon_pipeline("example.com")
    sm = out["surface_map"]
    assert sm["schema_version"] == 1
    assert sm["domain"] == "example.com"
    assert "phase_id" in sm
    assert "summary" in sm
    assert "subdomain_triage" in sm
    assert "deep_targets" in sm
    assert "shallow_targets" in sm
    assert "subdomain_enum" in sm


def test_surface_map_persisted_to_disk(monkeypatch, tmp_path) -> None:
    _patch_underlying(monkeypatch, subfinder_subs=["api.example.com"])
    out = dp.domain_recon_pipeline("example.com")

    path = tmp_path / "strix_runs" / "dp-test" / "surface_map.json"
    assert path.exists()
    on_disk = json.loads(path.read_text())
    assert on_disk["domain"] == "example.com"
    assert on_disk["schema_version"] == 1
    assert "api.example.com" in on_disk["subdomain_enum"]["subdomains"]


# ---------------------------------------------------------------------------
# Subdomain merging
# ---------------------------------------------------------------------------


def test_subdomains_merge_subfinder_and_passive_dns(monkeypatch, tmp_path) -> None:
    _patch_underlying(
        monkeypatch,
        subfinder_subs=["api.example.com", "blog.example.com"],
        passive_result={
            "success": True,
            "merged_subdomains": ["api.example.com", "old.example.com"],  # api dups
        },
    )
    out = dp.domain_recon_pipeline("example.com")
    subs = out["surface_map"]["subdomain_enum"]["subdomains"]
    # Apex + www always added; subfinder + passive DNS merged + deduped.
    assert "api.example.com" in subs
    assert "blog.example.com" in subs
    assert "old.example.com" in subs
    assert "example.com" in subs
    assert "www.example.com" in subs
    # Dedup verified — api.example.com appears once.
    assert subs.count("api.example.com") == 1


def test_subdomain_max_caps_count(monkeypatch, tmp_path) -> None:
    _patch_underlying(
        monkeypatch,
        subfinder_subs=[f"sub{i}.example.com" for i in range(60)],
    )
    out = dp.domain_recon_pipeline("example.com", subdomain_max=10)
    assert len(out["surface_map"]["subdomain_enum"]["subdomains"]) == 10


# ---------------------------------------------------------------------------
# Triage classification
# ---------------------------------------------------------------------------


def test_triage_classifies_deep_shallow_skip(monkeypatch, tmp_path) -> None:
    triage = {
        "api.example.com": {"host": "api.example.com", "ip": "1.1.1.1", "live": True, "triage": "deep", "evidence": "200 application/json"},
        "static.example.com": {"host": "static.example.com", "ip": "2.2.2.2", "live": True, "triage": "shallow", "evidence": "200 text/plain"},
        "dead.example.com": {"host": "dead.example.com", "ip": None, "live": False, "triage": "skip", "evidence": "no A record"},
    }
    _patch_underlying(
        monkeypatch,
        subfinder_subs=list(triage.keys()),
        triage_responses=triage,
    )
    out = dp.domain_recon_pipeline("example.com")
    sm = out["surface_map"]
    assert "api.example.com" in sm["deep_targets"]
    assert "static.example.com" in sm["shallow_targets"]
    assert "dead.example.com" not in sm["deep_targets"]
    assert "dead.example.com" not in sm["shallow_targets"]
    assert sm["summary"]["deep_targets"] == 1
    assert sm["summary"]["shallow_targets"] == 1


def test_triage_skipped_when_disabled(monkeypatch, tmp_path) -> None:
    _patch_underlying(monkeypatch, subfinder_subs=["api.example.com"])
    out = dp.domain_recon_pipeline("example.com", triage_subdomains=False)
    assert out["surface_map"]["subdomain_triage"] == []


# ---------------------------------------------------------------------------
# Conditional sub-tool invocation
# ---------------------------------------------------------------------------


def test_passive_dns_skipped_when_disabled(monkeypatch, tmp_path) -> None:
    called = {"passive_dns": False}
    from strix.tools.recon import passive_dns

    def fake_passive(domain, **kw):
        called["passive_dns"] = True
        return {"success": True, "merged_subdomains": []}

    monkeypatch.setattr(passive_dns, "passive_dns_history", fake_passive)
    _patch_underlying(monkeypatch)  # other tools mocked too

    dp.domain_recon_pipeline("example.com", enable_passive_dns=False)
    assert called["passive_dns"] is False


def test_cloud_assets_skipped_when_disabled(monkeypatch, tmp_path) -> None:
    called = {"cloud": False}
    from strix.tools.recon import cloud_assets

    def fake_cloud(**kw):
        called["cloud"] = True
        return {"success": True, "hits": [], "hit_count": 0}

    monkeypatch.setattr(cloud_assets, "discover_cloud_assets", fake_cloud)
    _patch_underlying(monkeypatch)  # other tools mocked too

    dp.domain_recon_pipeline("example.com", enable_cloud_assets=False)
    assert called["cloud"] is False


# ---------------------------------------------------------------------------
# dns_only mode
# ---------------------------------------------------------------------------


def _track_called(monkeypatch) -> dict[str, bool]:
    """Patch every active-probing step and record whether it ran."""
    called = {"takeover": False, "cloud": False, "triage": False}
    from strix.tools.recon import cloud_assets, takeover

    def fake_cloud(**kw):
        called["cloud"] = True
        return {"success": True, "hits": [], "hit_count": 0}

    def fake_takeover(**kw):
        called["takeover"] = True
        return {"success": True, "candidates": 0, "results": []}

    def fake_triage(host: str):
        called["triage"] = True
        return {"host": host, "ip": "1.2.3.4", "live": True, "triage": "deep", "evidence": ""}

    monkeypatch.setattr(cloud_assets, "discover_cloud_assets", fake_cloud)
    monkeypatch.setattr(takeover, "subdomain_takeover_check", fake_takeover)
    monkeypatch.setattr(dp, "_triage_subdomain", fake_triage)
    return called


def test_dns_only_skips_takeover_cloud_assets_triage(monkeypatch, tmp_path) -> None:
    """All three active-probing steps should be skipped under dns_only."""
    called = _track_called(monkeypatch)
    _patch_underlying(monkeypatch, subfinder_subs=["api.example.com"])
    # _patch_underlying re-patches the same functions, so re-apply our trackers
    # last to win.
    called = _track_called(monkeypatch)

    out = dp.domain_recon_pipeline("example.com", dns_only=True)
    assert out["success"] is True
    assert out["surface_map"]["dns_only"] is True
    assert called["takeover"] is False
    assert called["cloud"] is False
    assert called["triage"] is False


def test_dns_only_keeps_passive_steps(monkeypatch, tmp_path) -> None:
    """org_fingerprint, dns_hygiene, passive_dns, subdomain_enum all still run."""
    called: dict[str, bool] = {
        "org": False, "dns": False, "passive_dns": False, "enum": False,
    }
    from strix.tools.recon import (
        cloud_assets,
        dns_hygiene,
        org_recon,
        passive_dns,
        takeover,
    )

    def fake_org(domain, **kw):
        called["org"] = True
        return {"success": True}

    def fake_dns(domain, **kw):
        called["dns"] = True
        return {"success": True, "results": []}

    def fake_passive(domain, **kw):
        called["passive_dns"] = True
        return {"success": False}  # no key configured — fail-open path

    monkeypatch.setattr(org_recon, "org_fingerprint", fake_org)
    monkeypatch.setattr(dns_hygiene, "dns_hygiene_check", fake_dns)
    monkeypatch.setattr(passive_dns, "passive_dns_history", fake_passive)
    monkeypatch.setattr(cloud_assets, "discover_cloud_assets", lambda **kw: {"success": True, "hits": [], "hit_count": 0})
    monkeypatch.setattr(takeover, "subdomain_takeover_check", lambda **kw: {"success": True, "candidates": 0, "results": []})

    from strix.tools.recon import subdomain_enum_tool as _sub

    def fake_sub(domain, **kw):
        called["enum"] = True
        return {"success": True, "domain": domain, "subdomains": [], "per_source_counts": {}, "sources_run": [], "total_unique": 0}

    monkeypatch.setattr(_sub, "subdomain_enum", fake_sub)
    monkeypatch.setattr(dp, "_triage_subdomain", lambda h: {"host": h, "live": False, "triage": "skip", "evidence": ""})

    dp.domain_recon_pipeline("example.com", dns_only=True)
    assert called["org"] is True
    assert called["dns"] is True
    assert called["passive_dns"] is True
    assert called["enum"] is True


def test_dns_only_via_env_var(monkeypatch, tmp_path) -> None:
    """STRIX_DNS_ONLY=1 forces dns_only mode regardless of the call arg."""
    monkeypatch.setenv("STRIX_DNS_ONLY", "1")
    _patch_underlying(monkeypatch, subfinder_subs=["api.example.com"])
    called = _track_called(monkeypatch)

    out = dp.domain_recon_pipeline("example.com")  # no explicit dns_only kwarg
    assert out["surface_map"]["dns_only"] is True
    assert called["takeover"] is False
    assert called["cloud"] is False
    assert called["triage"] is False


def test_dns_only_env_var_other_values_dont_trigger(monkeypatch, tmp_path) -> None:
    """STRIX_DNS_ONLY must equal exactly '1' to enable — '0' / 'true' / etc.
    don't activate the mode (avoid surprising bool coercion)."""
    monkeypatch.setenv("STRIX_DNS_ONLY", "0")
    _patch_underlying(monkeypatch, subfinder_subs=["api.example.com"])
    called = _track_called(monkeypatch)

    dp.domain_recon_pipeline("example.com")
    assert called["takeover"] is True  # mode NOT activated


def test_normal_mode_runs_active_probes(monkeypatch, tmp_path) -> None:
    """Sanity: without dns_only, takeover/cloud/triage all run."""
    _patch_underlying(monkeypatch, subfinder_subs=["api.example.com"])
    called = _track_called(monkeypatch)

    dp.domain_recon_pipeline("example.com")
    assert called["takeover"] is True
    assert called["cloud"] is True
    assert called["triage"] is True


# ---------------------------------------------------------------------------
# next_steps
# ---------------------------------------------------------------------------


def test_next_steps_mentions_deep_targets(monkeypatch, tmp_path) -> None:
    _patch_underlying(
        monkeypatch,
        subfinder_subs=["api.example.com"],
        triage_responses={
            "api.example.com": {"host": "api.example.com", "ip": "1.1.1.1", "live": True, "triage": "deep", "evidence": "200 html"}
        },
    )
    out = dp.domain_recon_pipeline("example.com")
    assert any("deep target" in step for step in out["next_steps"])


def test_next_steps_mentions_takeover_when_present(monkeypatch, tmp_path) -> None:
    _patch_underlying(
        monkeypatch,
        takeover_result={"success": True, "candidates": 2, "results": []},
    )
    out = dp.domain_recon_pipeline("example.com")
    assert any("takeover" in step for step in out["next_steps"])


def test_next_steps_falls_back_when_nothing_interesting(monkeypatch, tmp_path) -> None:
    _patch_underlying(monkeypatch)
    out = dp.domain_recon_pipeline("example.com")
    assert any("No deep targets" in step for step in out["next_steps"])


# ---------------------------------------------------------------------------
# Triage classifier (the inner _triage_subdomain helper)
# ---------------------------------------------------------------------------


def test_triage_classifier_skip_when_no_dns(monkeypatch) -> None:
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "")
    result = dp._triage_subdomain("nonexistent.example.com")
    assert result["live"] is False
    assert result["triage"] == "skip"


def test_triage_classifier_deep_for_html_200(monkeypatch) -> None:
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "1.2.3.4")
    monkeypatch.setattr(
        dp, "http_head",
        lambda url, **kw: (200, {"content-type": "text/html; charset=utf-8", "server": "nginx"}),
    )
    result = dp._triage_subdomain("api.example.com")
    assert result["live"] is True
    assert result["triage"] == "deep"


def test_triage_classifier_deep_for_401(monkeypatch) -> None:
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "1.2.3.4")
    monkeypatch.setattr(dp, "http_head", lambda url, **kw: (401, {}))
    result = dp._triage_subdomain("admin.example.com")
    assert result["triage"] == "deep"


def test_triage_classifier_skip_for_5xx(monkeypatch) -> None:
    monkeypatch.setattr(dp, "dig", lambda *a, **kw: "1.2.3.4")
    monkeypatch.setattr(dp, "http_head", lambda url, **kw: (502, {}))
    result = dp._triage_subdomain("broken.example.com")
    assert result["triage"] == "skip"
