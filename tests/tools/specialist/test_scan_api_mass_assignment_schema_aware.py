"""Tests for the schema-aware mass-assignment extension.

Covers:
  * `_extract_schema_aware_probes` derives the right probe set
    from a request body schema (readOnly + name patterns)
  * Dedup against the canonical field set
  * End-to-end: scan_api_mass_assignment derives + fires
    schema-aware probes alongside canonical ones
  * Defensive: missing schema, malformed schema, empty properties

Note: pairs with the openapi_spec_ingest schema-extraction tests
(`test_openapi_spec_ingest.py`) — schema extraction tested there,
probe-derivation tested here, end-to-end tested here.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.specialist.scan_api_mass_assignment import (
    _SERVER_MANAGED_NAME_PATTERNS,
    _choose_probe_value_for_type,
    _extract_schema_aware_probes,
    scan_api_mass_assignment,
)


# ---------------------------------------------------------------------------
# Test scaffolding — copied from test_scan_api_mass_assignment.py
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_tracer(monkeypatch, tmp_path):
    from strix.telemetry import tracer as tracer_mod
    from strix.telemetry.tracer import Tracer, set_global_tracer

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_mod, "_global_tracer", None)
    monkeypatch.setattr(tracer_mod, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_mod, "_OTEL_REMOTE_ENABLED", False)
    monkeypatch.setenv("STRIX_TELEMETRY", "0")
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    set_global_tracer(Tracer("test-mass-assignment-schema"))
    yield


def _seed_user_a():
    from strix.agents.security_context import (
        get_security_context,
        AuthState,
    )
    ctx = get_security_context()
    ctx.auth_states["user-a"] = AuthState(
        label="user-a", bearer="user-a-token",
    )


def _endpoint(
    *, url: str = "https://api/v1/users",
    method: str = "POST",
    request_body_schema: dict[str, Any] | None = None,
    params: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "url": url, "method": method, "auth_required": True,
        "params": params or [
            {"name": "name", "in": "body", "required": True},
        ],
        "request_body_schema": request_body_schema,
    }


def _schema(
    *,
    properties: dict[str, dict[str, Any]] | None = None,
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "properties": properties or {},
        "required": required or [],
        "additional_properties": True,
        "source": "openapi3",
    }


# ---------------------------------------------------------------------------
# _extract_schema_aware_probes — derivation logic
# ---------------------------------------------------------------------------


def test_readonly_field_derives_probe() -> None:
    """Schema declares `readOnly: true` → field becomes a probe
    candidate. This is the strongest signal: the server itself
    says the client shouldn't set this field."""
    schema = _schema(properties={
        "amount": {"type": "number", "read_only": False, "description": ""},
        "commission_rate": {
            "type": "number", "read_only": True,
            "description": "Server-managed",
        },
    })
    probes = _extract_schema_aware_probes(schema, canonical_field_names=set())
    names = [n for n, _ in probes]
    assert "commission_rate" in names
    assert "amount" not in names  # not readOnly, not server-managed name


def test_server_managed_name_pattern_derives_probe() -> None:
    """Field name matches `_SERVER_MANAGED_NAME_PATTERNS` →
    probe candidate, even when readOnly isn't declared. Most
    real-world APIs forget the readOnly annotation."""
    schema = _schema(properties={
        "amount": {"type": "number", "read_only": False},
        "id": {"type": "string", "read_only": False},  # name match
        "created_at": {"type": "string", "read_only": False},  # name match
        "etag": {"type": "string", "read_only": False},  # name match
    })
    probes = _extract_schema_aware_probes(schema, canonical_field_names=set())
    names = {n for n, _ in probes}
    assert "id" in names
    assert "created_at" in names
    assert "etag" in names
    assert "amount" not in names


def test_dedup_against_canonical_set() -> None:
    """Schema-declared `is_admin` is ALSO in the canonical authz
    set. The schema-aware path must skip it to avoid double-probing."""
    schema = _schema(properties={
        "is_admin": {"type": "boolean", "read_only": True},
        "custom_role": {"type": "string", "read_only": True},
    })
    probes = _extract_schema_aware_probes(
        schema,
        canonical_field_names={"is_admin", "isAdmin", "admin"},
    )
    names = {n for n, _ in probes}
    assert "is_admin" not in names  # deduped
    assert "custom_role" in names  # not in canonical


def test_dedup_is_literal_case_insensitive() -> None:
    """Dedup is literal-lowercase match — `IS_ADMIN` matches
    `is_admin` (same field, ALLCAPS variant). Does NOT bridge
    casing conventions (`IsAdmin` vs `is_admin` are DIFFERENT
    JSON keys, both must be in the canonical set explicitly).
    The shipped `_AUTHZ_FIELDS` covers snake_case, camelCase,
    AND bare variants for every field — case-insensitive dedup
    is enough."""
    schema = _schema(properties={
        "IS_ADMIN": {"type": "boolean", "read_only": True},
    })
    probes = _extract_schema_aware_probes(
        schema,
        canonical_field_names={"is_admin"},
    )
    assert probes == []


# ---------------------------------------------------------------------------
# _choose_probe_value_for_type — sentinel selection
# ---------------------------------------------------------------------------


def test_probe_value_boolean_privilege_marker() -> None:
    """Field name with `admin` / `superuser` / etc. → probe value
    is True regardless of schema type."""
    assert _choose_probe_value_for_type("is_admin", "boolean") is True
    assert _choose_probe_value_for_type("isSuperuser", "boolean") is True
    assert _choose_probe_value_for_type("is_root", None) is True


def test_probe_value_typed_defaults() -> None:
    """Non-privilege fields get type-led defaults."""
    assert _choose_probe_value_for_type("flag", "boolean") is True
    assert _choose_probe_value_for_type("count", "integer") == 1
    assert _choose_probe_value_for_type("price", "number") == 1
    assert _choose_probe_value_for_type("tags", "array") == ["strix-probe"]
    assert _choose_probe_value_for_type("metadata", "object") == {"strix-probe": True}


def test_probe_value_string_carries_field_name() -> None:
    """String probes embed the field name as a sentinel — makes
    echo-based detection unambiguous about which probe fired."""
    v = _choose_probe_value_for_type("commission_rate", "string")
    assert "commission_rate" in v
    assert "STRIX" in v


# ---------------------------------------------------------------------------
# Defensive — malformed schema
# ---------------------------------------------------------------------------


def test_no_schema_returns_empty_probes() -> None:
    assert _extract_schema_aware_probes(None, canonical_field_names=set()) == []


def test_empty_properties_returns_empty_probes() -> None:
    schema = _schema(properties={})
    assert _extract_schema_aware_probes(schema, canonical_field_names=set()) == []


def test_malformed_property_skipped() -> None:
    """Property value isn't a dict → skip gracefully."""
    schema = _schema(properties={
        "good_field": {"type": "string", "read_only": True},
        "bad_field": "not a dict",  # type: ignore[dict-item]
    })
    probes = _extract_schema_aware_probes(schema, canonical_field_names=set())
    names = [n for n, _ in probes]
    assert "good_field" in names
    assert "bad_field" not in names


def test_non_string_property_name_skipped() -> None:
    schema = _schema()
    schema["properties"] = {
        "good": {"type": "string", "read_only": True},
        42: {"type": "string", "read_only": True},  # type: ignore[dict-item]
    }
    probes = _extract_schema_aware_probes(schema, canonical_field_names=set())
    names = [n for n, _ in probes]
    assert "good" in names


def test_non_dict_schema_returns_empty() -> None:
    """Top-level schema not a dict — caller probably passed garbage."""
    assert _extract_schema_aware_probes(
        "not a schema", canonical_field_names=set(),  # type: ignore[arg-type]
    ) == []


# ---------------------------------------------------------------------------
# End-to-end — scan_api_mass_assignment with schema-aware probes
# ---------------------------------------------------------------------------


def test_end_to_end_schema_aware_finds_custom_server_managed_field() -> None:
    """Schema declares `commission_rate` as readOnly (customer-
    specific Akto-grade case). The probe fires it; the server
    accepts; finding emits. Without schema-aware path, this would
    be silently missed because `commission_rate` isn't in the
    canonical 22."""
    _seed_user_a()

    def fetcher(*, url, method, headers, json_body, timeout):
        # Server accepts whatever; echoes back.
        if json_body and "commission_rate" in json_body:
            return 200, (
                '{"id": "p_1", "amount": 100, '
                '"commission_rate": 1, "ok": true}'
            )
        return 200, '{"id": "p_1", "amount": 100, "ok": true}'

    schema = _schema(properties={
        "amount": {"type": "number", "read_only": False},
        "commission_rate": {"type": "number", "read_only": True},
    })

    result = scan_api_mass_assignment(
        endpoints=[_endpoint(
            url="https://api/v1/payments",
            request_body_schema=schema,
            params=[{"name": "amount", "in": "body", "required": True}],
        )],
        auth_label="user-a", confirm_mutation=True,
        probe_authz_fields=False, probe_id_fields=False,
        probe_schema_aware=True,
        _fetcher=fetcher,
    )
    assert result["status"] == "ok"
    findings = result["findings"]
    assert len(findings) == 1
    assert "commission_rate" in findings[0]["title"]
    # Metadata surfaces the schema-aware activity.
    assert result["tool_metadata"]["schema_aware_probes_total"] >= 1


def test_end_to_end_schema_aware_off_misses_custom_field() -> None:
    """Same setup as the above, but with schema_aware off — the
    `commission_rate` field MUST NOT be probed. This is the
    contrast that proves the schema-aware path is what catches
    customer-specific fields."""
    _seed_user_a()

    def fetcher(*, url, method, headers, json_body, timeout):
        if json_body and "commission_rate" in json_body:
            return 200, '{"commission_rate": 1, "ok": true}'
        return 200, '{"ok": true}'

    schema = _schema(properties={
        "amount": {"type": "number"},
        "commission_rate": {"type": "number", "read_only": True},
    })
    result = scan_api_mass_assignment(
        endpoints=[_endpoint(
            url="https://api/v1/payments",
            request_body_schema=schema,
            params=[{"name": "amount", "in": "body", "required": True}],
        )],
        auth_label="user-a", confirm_mutation=True,
        probe_authz_fields=True, probe_id_fields=False,
        probe_schema_aware=False,  # OFF
        _fetcher=fetcher,
    )
    # The canonical 22 fields ARE probed (probe_authz_fields=True)
    # — but none of them match. commission_rate is never probed.
    # Result: no finding.
    assert result["status"] == "ok"
    assert len(result["findings"]) == 0


def test_end_to_end_canonical_plus_schema_aware_complements() -> None:
    """When both canonical AND schema-aware probes are enabled
    (the default), each catches what the other can't.

    Canonical: `is_admin` → admin escalation.
    Schema-aware: `account_balance` (customer-specific readOnly).

    Both findings should emit when both fields are accepted."""
    _seed_user_a()

    accept_log: list[str] = []

    def fetcher(*, url, method, headers, json_body, timeout):
        if not json_body:
            return 200, '{"ok": true}'
        if "is_admin" in json_body:
            accept_log.append("is_admin")
            return 200, '{"is_admin": true, "ok": true}'
        if "account_balance" in json_body:
            accept_log.append("account_balance")
            return 200, '{"account_balance": 1, "ok": true}'
        return 200, '{"ok": true}'

    schema = _schema(properties={
        "amount": {"type": "number"},
        "account_balance": {"type": "integer", "read_only": True},
    })
    result = scan_api_mass_assignment(
        endpoints=[_endpoint(
            url="https://api/v1/users",
            request_body_schema=schema,
            params=[{"name": "amount", "in": "body", "required": True}],
        )],
        auth_label="user-a", confirm_mutation=True,
        probe_authz_fields=True,
        probe_schema_aware=True,
        _fetcher=fetcher,
    )
    # First accepted field wins (single-finding-per-endpoint rule).
    # The iteration order is canonical-first → is_admin lands
    # before account_balance. Either is acceptable evidence the
    # combined probe set works; assert at least one fires.
    assert len(result["findings"]) == 1
    assert accept_log  # at least one probe accepted


def test_end_to_end_no_schema_falls_back_to_canonical() -> None:
    """Endpoint without `request_body_schema` → schema-aware path
    derives no probes; canonical set still runs. Backwards-
    compatible with pre-schema-aware behaviour."""
    _seed_user_a()

    def fetcher(*, url, method, headers, json_body, timeout):
        if json_body and "is_admin" in json_body:
            return 200, '{"is_admin": true, "ok": true}'
        return 200, '{"ok": true}'

    result = scan_api_mass_assignment(
        endpoints=[_endpoint(
            url="https://api/v1/users",
            request_body_schema=None,  # explicitly no schema
        )],
        auth_label="user-a", confirm_mutation=True,
        probe_authz_fields=True,
        probe_schema_aware=True,
        _fetcher=fetcher,
    )
    assert result["status"] == "ok"
    assert len(result["findings"]) == 1
    assert "is_admin" in result["findings"][0]["title"]


def test_metadata_reports_schema_aware_count() -> None:
    """tool_metadata.schema_aware_probes_total counts schema-
    derived probes across all endpoints — for telemetry."""
    _seed_user_a()

    def fetcher(*, url, method, headers, json_body, timeout):
        return 200, '{"ok": true}'  # nothing accepted

    schema = _schema(properties={
        "amount": {"type": "number"},
        "commission_rate": {"type": "number", "read_only": True},
        "etag": {"type": "string"},  # name pattern match
    })
    result = scan_api_mass_assignment(
        endpoints=[_endpoint(
            url="https://api/v1/x",
            request_body_schema=schema,
        )],
        auth_label="user-a", confirm_mutation=True,
        probe_authz_fields=False,
        probe_schema_aware=True,
        _fetcher=fetcher,
    )
    assert result["tool_metadata"]["schema_aware_probes_total"] == 2


# ---------------------------------------------------------------------------
# Sanity — server-managed name patterns cover the obvious cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("expected_pattern", [
    "id", "uuid", "created_at", "updated_at", "deleted_at",
    "version", "etag", "tenant_id", "owner_id",
])
def test_canonical_server_managed_names_present(expected_pattern: str) -> None:
    assert expected_pattern in _SERVER_MANAGED_NAME_PATTERNS
