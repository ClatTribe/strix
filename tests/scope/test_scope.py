"""Tests for the §7 engagement scope module.

Covers:
  * YAML parsing happy path
  * Each validation rule produces a ScopeValidationError with all
    failures collected (not just the first)
  * Defaults populate when fields are omitted
  * `EngagementScope` is frozen / immutable
  * Render block has the expected structure
  * Render NEVER echoes resolved credentials — only `env:VAR` source
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.scope import (
    AuthConfig,
    EngagementScope,
    ScopeTarget,
    ScopeValidationError,
    load_scope_file,
    parse_scope_yaml,
    render_for_prompt,
)


# ---------------------------------------------------------------------------
# Parser — happy paths
# ---------------------------------------------------------------------------


def test_minimal_scope_parses() -> None:
    """Only `targets` is required."""
    yaml_text = """
targets:
  - type: web_application
    value: https://app.example.com
"""
    scope = parse_scope_yaml(yaml_text)
    assert len(scope.targets) == 1
    assert scope.targets[0].type == "web_application"
    assert scope.targets[0].value == "https://app.example.com"
    # Defaults
    assert scope.opsec_level == "standard"
    assert scope.rate_limit_rps is None
    assert scope.auth.method == "none"
    assert scope.exclusion_paths == ()
    assert scope.exclusion_hosts == ()


def test_full_scope_parses() -> None:
    yaml_text = """
targets:
  - type: web_application
    value: https://app.example.com
  - type: api
    value: https://api.example.com
exclusions:
  paths:
    - /admin/destructive-export
    - /webhooks/*
  hosts:
    - prod-payments.example.com
opsec_level: quiet
rate_limit_rps: 5
auth:
  method: bearer
  inject_from: env:STRIX_BEARER
acceptance_criteria:
  - "All OWASP A0X covered"
  - "Authz matrix on all role pairs"
escalation_contact: secops@example.com
"""
    scope = parse_scope_yaml(yaml_text)
    assert len(scope.targets) == 2
    assert scope.opsec_level == "quiet"
    assert scope.rate_limit_rps == 5
    assert scope.auth.method == "bearer"
    assert scope.auth.inject_from == "env:STRIX_BEARER"
    assert scope.exclusion_paths == ("/admin/destructive-export", "/webhooks/*")
    assert scope.exclusion_hosts == ("prod-payments.example.com",)
    assert len(scope.acceptance_criteria) == 2
    assert scope.escalation_contact == "secops@example.com"


def test_load_scope_file_round_trip(tmp_path: Path) -> None:
    p = tmp_path / "strix.scope.yml"
    p.write_text(
        "targets:\n  - type: api\n    value: https://api.example.com\n",
        encoding="utf-8",
    )
    scope = load_scope_file(p)
    assert scope.targets[0].type == "api"


def test_load_scope_file_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_scope_file(tmp_path / "does_not_exist.yml")


# ---------------------------------------------------------------------------
# Parser — validation
# ---------------------------------------------------------------------------


def test_empty_yaml_fails() -> None:
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml("")
    assert any("empty" in e for e in exc.value.errors)


def test_non_mapping_top_level_fails() -> None:
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml("- not\n- a\n- mapping")
    assert any("mapping" in e for e in exc.value.errors)


def test_targets_required() -> None:
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml("opsec_level: quiet")
    assert any("targets" in e for e in exc.value.errors)


def test_targets_must_be_list() -> None:
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml("targets: not_a_list")
    assert any("targets" in e and "list" in e for e in exc.value.errors)


def test_unknown_target_type_fails() -> None:
    yaml_text = """
targets:
  - type: smartwatch
    value: foo
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml_text)
    assert any("type" in e for e in exc.value.errors)


def test_empty_target_value_fails() -> None:
    yaml_text = """
targets:
  - type: api
    value: ""
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml_text)
    assert any("value" in e for e in exc.value.errors)


def test_unknown_opsec_level_fails() -> None:
    yaml_text = """
targets:
  - type: api
    value: x
opsec_level: AGGRESSIVE
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml_text)
    assert any("opsec" in e.lower() for e in exc.value.errors)


def test_rate_limit_must_be_positive_int() -> None:
    yaml_text = """
targets:
  - type: api
    value: x
rate_limit_rps: -1
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml_text)
    assert any("rate_limit_rps" in e for e in exc.value.errors)


def test_unknown_auth_method_fails() -> None:
    yaml_text = """
targets:
  - type: api
    value: x
auth:
  method: oauth2
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml_text)
    assert any("method" in e for e in exc.value.errors)


def test_invalid_inject_from_fails() -> None:
    yaml_text = """
targets:
  - type: api
    value: x
auth:
  method: bearer
  inject_from: not_a_valid_source
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml_text)
    assert any("inject_from" in e for e in exc.value.errors)


def test_inject_from_env_is_valid() -> None:
    yaml_text = """
targets:
  - type: api
    value: x
auth:
  method: bearer
  inject_from: env:STRIX_BEARER
"""
    scope = parse_scope_yaml(yaml_text)
    assert scope.auth.inject_from == "env:STRIX_BEARER"


def test_inject_from_file_is_valid() -> None:
    yaml_text = """
targets:
  - type: api
    value: x
auth:
  method: bearer
  inject_from: file:/var/run/secrets/token
"""
    scope = parse_scope_yaml(yaml_text)
    assert scope.auth.inject_from == "file:/var/run/secrets/token"


def test_multiple_errors_collected() -> None:
    """One error per failure — caller sees the full picture, not just
    the first one."""
    yaml_text = """
targets:
  - type: smartwatch
    value: x
opsec_level: AGGRESSIVE
rate_limit_rps: 0
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml_text)
    # Three distinct validation failures: bad type, bad opsec, bad rate.
    assert len(exc.value.errors) >= 3


def test_malformed_yaml_reports_parse_error() -> None:
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml("targets: [\n  - type:")
    assert any("parse" in e.lower() for e in exc.value.errors)


# ---------------------------------------------------------------------------
# EngagementScope — immutability + helpers
# ---------------------------------------------------------------------------


def test_scope_is_frozen() -> None:
    scope = EngagementScope(
        targets=(ScopeTarget(type="api", value="x"),),
    )
    with pytest.raises((AttributeError, Exception)):
        scope.opsec_level = "loud"  # type: ignore[misc]


def test_target_values_helper() -> None:
    scope = EngagementScope(
        targets=(
            ScopeTarget(type="api", value="https://api.example.com"),
            ScopeTarget(type="web_application", value="https://app.example.com"),
        ),
    )
    assert scope.target_values() == [
        "https://api.example.com",
        "https://app.example.com",
    ]


def test_has_exclusions_helper() -> None:
    s1 = EngagementScope(targets=(ScopeTarget(type="api", value="x"),))
    assert not s1.has_exclusions()

    s2 = EngagementScope(
        targets=(ScopeTarget(type="api", value="x"),),
        exclusion_paths=("/admin",),
    )
    assert s2.has_exclusions()


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


def test_render_minimal() -> None:
    scope = EngagementScope(
        targets=(ScopeTarget(type="api", value="https://api.example.com"),),
    )
    out = render_for_prompt(scope)
    assert "ENGAGEMENT SCOPE" in out
    assert "api: https://api.example.com" in out
    assert "OpSec level: standard" in out
    assert "Auth:" not in out  # method=none → omitted


def test_render_full() -> None:
    scope = EngagementScope(
        targets=(
            ScopeTarget(type="web_application", value="https://app.example.com"),
        ),
        exclusion_paths=("/admin/destructive-export",),
        exclusion_hosts=("prod-payments.example.com",),
        opsec_level="quiet",
        rate_limit_rps=5,
        auth=AuthConfig(method="bearer", inject_from="env:STRIX_BEARER"),
        acceptance_criteria=("All OWASP A0X covered",),
        escalation_contact="secops@example.com",
    )
    out = render_for_prompt(scope)
    assert "Exclusions" in out
    assert "/admin/destructive-export" in out
    assert "prod-payments.example.com" in out
    assert "OpSec level: quiet" in out
    assert "Rate limit: 5 req/sec" in out
    assert "method=bearer" in out
    assert "env:STRIX_BEARER" in out
    assert "secops@example.com" in out


def test_render_never_echoes_resolved_credential() -> None:
    """`inject_from: env:STRIX_BEARER` renders as the SOURCE descriptor
    only — never as the resolved env value. This guards against the
    secret-scanning hit that comes from echoing credentials into the
    prompt."""
    import os
    os.environ["STRIX_BEARER"] = "secret-value-must-not-leak"
    try:
        scope = EngagementScope(
            targets=(ScopeTarget(type="api", value="x"),),
            auth=AuthConfig(method="bearer", inject_from="env:STRIX_BEARER"),
        )
        out = render_for_prompt(scope)
        assert "secret-value-must-not-leak" not in out
        assert "env:STRIX_BEARER" in out
    finally:
        os.environ.pop("STRIX_BEARER", None)


def test_render_enforcement_directive_present() -> None:
    scope = EngagementScope(
        targets=(ScopeTarget(type="api", value="x"),),
    )
    out = render_for_prompt(scope)
    # The agent gets a sentence telling it the scope is authoritative.
    assert "Enforce this scope" in out
    assert "authoritative" in out
