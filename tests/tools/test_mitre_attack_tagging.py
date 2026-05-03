"""Tests for the MITRE ATT&CK technique-tagging plumbing (roadmap §10).

Validates:
- `register_tool(mitre_techniques=...)` stores the techniques on the
  registry entry.
- `_normalize_mitre_techniques` validates IDs against the canonical
  `T<digits>(.<digits>)?` shape and dedupes.
- `get_tool_mitre_techniques(name)` returns the registered list.
- `Tracer.log_tool_execution_start` surfaces the techniques on the
  `tool.execution.started` event under `actor.mitre_techniques`.
- Backward compatibility: tools without an annotation still work and
  emit an empty `mitre_techniques: []` field for schema stability.
- The §10 security-relevant tools shipped in this PR carry sensible
  technique IDs (smoke check that the annotation didn't get lost in
  refactors).
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools import registry as tool_registry
from strix.tools.proxy import http_safety

# Import the security-relevant tool modules so they register on the
# `tools` list. The smoke test below queries the registry for the
# canonical names, which only works after each module has been
# imported (the @register_tool decorator runs at import time).
import strix.tools.attack_surface_intel.attack_surface_intel  # noqa: F401
import strix.tools.authz_matrix.authz_matrix  # noqa: F401
import strix.tools.cache_deception.cache_deception_check  # noqa: F401
import strix.tools.cve_lookup.cve_lookup  # noqa: F401
import strix.tools.domain_reputation.domain_reputation  # noqa: F401
import strix.tools.exploit_refs.exploit_refs  # noqa: F401
import strix.tools.file_upload.file_upload_abuse_check  # noqa: F401
import strix.tools.graphql.graphql  # noqa: F401
import strix.tools.hibp_breach.hibp_breach_check  # noqa: F401
import strix.tools.host_header.host_header_check  # noqa: F401
import strix.tools.http_headers.http_headers  # noqa: F401
import strix.tools.m365_recon.m365_recon  # noqa: F401
import strix.tools.method_tamper.method_tamper_check  # noqa: F401
import strix.tools.open_redirect.open_redirect_check  # noqa: F401
import strix.tools.recon.cloud_assets  # noqa: F401
import strix.tools.recon.code_search  # noqa: F401
import strix.tools.recon.dns_hygiene  # noqa: F401
import strix.tools.recon.domain_pipeline  # noqa: F401
import strix.tools.recon.mail_recon  # noqa: F401
import strix.tools.recon.org_recon  # noqa: F401
import strix.tools.recon.passive_dns  # noqa: F401
import strix.tools.recon.reverse_ip  # noqa: F401
import strix.tools.recon.saas_leaks  # noqa: F401
import strix.tools.recon.subdomain_enum_tool  # noqa: F401
import strix.tools.recon.takeover  # noqa: F401
import strix.tools.request_smuggling.request_smuggling_check  # noqa: F401
import strix.tools.source_maps.source_maps  # noqa: F401
import strix.tools.tls_audit.tls_audit  # noqa: F401
import strix.tools.web_crawler.crawler  # noqa: F401
import strix.tools.well_known.well_known  # noqa: F401


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    for k in (
        "STRIX_AUTH_COOKIE", "STRIX_AUTH_BEARER", "STRIX_AUTH_BASIC",
        "STRIX_HEADERS", "STRIX_EXCLUDE_PATHS", "STRIX_RATE_LIMIT",
    ):
        monkeypatch.delenv(k, raising=False)
    http_safety.reset_rate_limiter_for_testing()
    tracer = Tracer("mitre-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


# ---------------------------------------------------------------------------
# Normalization helper
# ---------------------------------------------------------------------------


def test_normalize_accepts_canonical_ids() -> None:
    out = tool_registry._normalize_mitre_techniques(["T1190", "T1592.002"])
    assert out == ["T1190", "T1592.002"]


def test_normalize_uppercases() -> None:
    out = tool_registry._normalize_mitre_techniques(["t1190", "t1592.002"])
    assert out == ["T1190", "T1592.002"]


def test_normalize_dedups() -> None:
    out = tool_registry._normalize_mitre_techniques(["T1190", "T1190", "T1190"])
    assert out == ["T1190"]


def test_normalize_drops_malformed() -> None:
    out = tool_registry._normalize_mitre_techniques([
        "T1190",       # ok
        "T119",        # too short
        "T11900",      # too long (5 digits)
        "T1190.0002",  # sub-technique too long
        "1190",        # missing T
        "TXXXX",       # not numeric
        "",            # empty
        None,          # not a string
        "T1190.002",   # ok
    ])
    assert out == ["T1190", "T1190.002"]


def test_normalize_handles_none() -> None:
    assert tool_registry._normalize_mitre_techniques(None) == []
    assert tool_registry._normalize_mitre_techniques([]) == []


# ---------------------------------------------------------------------------
# Registry lookup
# ---------------------------------------------------------------------------


def test_existing_tool_has_techniques() -> None:
    """Smoke check — a tool annotated in this PR has the expected ID."""
    techs = tool_registry.get_tool_mitre_techniques("tls_audit")
    assert "T1592.002" in techs


def test_unknown_tool_returns_empty_list() -> None:
    assert tool_registry.get_tool_mitre_techniques("does_not_exist") == []


def test_canonical_tool_techniques_smoke() -> None:
    """Each annotated security tool returns at least one technique ID
    of the canonical shape."""
    canonical = (
        "tls_audit",
        "subdomain_enum",
        "dns_hygiene_check",
        "well_known_harvest",
        "m365_tenant_recon",
        "org_fingerprint",
        "passive_dns_history",
        "mx_fingerprint",
        "code_search_for_domain",
        "reverse_ip_discovery",
        "saas_leak_discovery",
        "subdomain_takeover_check",
        "discover_cloud_assets",
        "bfs_crawl",
        "source_map_probe",
        "http_security_headers_audit",
        "request_smuggling_check",
        "host_header_check",
        "cache_deception_check",
        "file_upload_abuse_check",
        "open_redirect_check",
        "method_tamper_check",
        "authz_matrix_check",
        "graphql_specialist_check",
        "cve_lookup",
        "exploit_refs",
        "domain_reputation",
        "hibp_breach_check",
        "attack_surface_intel",
        "domain_recon_pipeline",
    )
    for name in canonical:
        techs = tool_registry.get_tool_mitre_techniques(name)
        assert techs, f"tool {name!r} has no MITRE techniques"
        assert all(
            tool_registry._MITRE_TECHNIQUE_RE.match(t)
            for t in techs
        ), f"tool {name!r} has non-canonical IDs: {techs}"


# ---------------------------------------------------------------------------
# Decorator integration (live registration)
# ---------------------------------------------------------------------------


def test_register_tool_stores_normalized_techniques(monkeypatch) -> None:
    """Registering a fresh tool with mitre_techniques records it on the
    registry entry. Uses a unique name to avoid collisions."""
    @tool_registry.register_tool(
        sandbox_execution=False,
        mitre_techniques=["t1190", "T1190", "TXXXX", "T1592.002"],
    )
    def _strix_test_tool_canonical(target: str) -> dict[str, Any]:
        return {"ok": True}

    techs = tool_registry.get_tool_mitre_techniques("_strix_test_tool_canonical")
    assert techs == ["T1190", "T1592.002"]


def test_register_tool_default_empty_techniques() -> None:
    """Tool registered without mitre_techniques → empty list."""
    @tool_registry.register_tool(sandbox_execution=False)
    def _strix_test_tool_no_techniques(target: str) -> dict[str, Any]:
        return {"ok": True}

    techs = tool_registry.get_tool_mitre_techniques("_strix_test_tool_no_techniques")
    assert techs == []


# ---------------------------------------------------------------------------
# Tracer event integration
# ---------------------------------------------------------------------------


def _capture_events(monkeypatch) -> list[dict[str, Any]]:
    """Capture the records emitted via `_append_event_record` (the
    tracer writes to JSONL on disk; we patch the append to also stash
    in-memory for assertion convenience)."""
    captured: list[dict[str, Any]] = []
    tracer = tracer_module.get_global_tracer()
    assert tracer is not None
    real = tracer._append_event_record

    def fake(record: dict[str, Any]) -> None:
        captured.append(dict(record))
        real(record)

    monkeypatch.setattr(tracer, "_append_event_record", fake)
    return captured


def test_tool_execution_event_carries_techniques(monkeypatch) -> None:
    captured = _capture_events(monkeypatch)
    tracer = tracer_module.get_global_tracer()
    assert tracer is not None
    execution_id = tracer.log_tool_execution_start(
        agent_id="strix-test",
        tool_name="tls_audit",
        args={"target": "example.com"},
    )
    events = [e for e in captured if e.get("event_type") == "tool.execution.started"]
    assert events, [e.get("event_type") for e in captured]
    actor = events[-1].get("actor") or {}
    assert "mitre_techniques" in actor
    assert "T1592.002" in actor["mitre_techniques"]
    assert isinstance(execution_id, int)


def test_tool_execution_event_empty_for_unannotated(monkeypatch) -> None:
    """An unknown / unannotated tool name → empty list (field still
    present for schema stability)."""
    captured = _capture_events(monkeypatch)
    tracer = tracer_module.get_global_tracer()
    assert tracer is not None
    tracer.log_tool_execution_start(
        agent_id="strix-test",
        tool_name="does_not_exist_xyz",
        args={},
    )
    events = [e for e in captured if e.get("event_type") == "tool.execution.started"]
    assert events
    actor = events[-1].get("actor") or {}
    assert actor.get("mitre_techniques") == []


def test_tool_execution_event_actor_keys_stable(monkeypatch) -> None:
    """Actor dict carries the existing keys plus mitre_techniques."""
    captured = _capture_events(monkeypatch)
    tracer = tracer_module.get_global_tracer()
    assert tracer is not None
    tracer.log_tool_execution_start(
        agent_id="strix-test",
        tool_name="tls_audit",
        args={"target": "example.com"},
    )
    events = [e for e in captured if e.get("event_type") == "tool.execution.started"]
    actor = events[-1].get("actor") or {}
    # All four keys present.
    assert "agent_id" in actor
    assert "tool_name" in actor
    assert "execution_id" in actor
    assert "mitre_techniques" in actor


# ---------------------------------------------------------------------------
# Backward compatibility — schema didn't change, just new field
# ---------------------------------------------------------------------------


def test_field_present_even_when_lookup_fails(monkeypatch) -> None:
    """If the registry lookup raises, the event still has the field
    (empty list) so consumers don't see schema variance."""
    captured = _capture_events(monkeypatch)

    def boom(_name: str) -> list[str]:
        raise RuntimeError("simulated registry crash")

    monkeypatch.setattr(tool_registry, "get_tool_mitre_techniques", boom)
    monkeypatch.setattr(
        "strix.tools.registry.get_tool_mitre_techniques", boom,
    )
    tracer = tracer_module.get_global_tracer()
    assert tracer is not None
    tracer.log_tool_execution_start(
        agent_id="strix-test",
        tool_name="tls_audit",
        args={},
    )
    events = [e for e in captured if e.get("event_type") == "tool.execution.started"]
    actor = events[-1].get("actor") or {}
    assert actor.get("mitre_techniques") == []
