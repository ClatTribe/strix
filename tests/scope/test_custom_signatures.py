"""Tests for iter-24.2 — strix.scope.yml `custom_signatures` block.

Covers loader validation + compile-into-cache flow.
"""

from __future__ import annotations

import importlib

import pytest

from strix.scope import (
    CustomDockerfileRules,
    CustomSecretRule,
    CustomSignatures,
    ScopeValidationError,
    parse_scope_yaml,
)


_MIN_YAML = """\
targets:
  - type: web_application
    value: https://app.example.com
"""


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("STRIX_RULES_CACHE_DIR", str(tmp_path / "rules"))
    from strix.tools.rule_updates import _common
    importlib.reload(_common)
    yield tmp_path / "rules"


# =============================================================================
# Loader parsing
# =============================================================================

def test_omitted_custom_signatures_defaults_empty():
    s = parse_scope_yaml(_MIN_YAML)
    assert s.custom_signatures.is_empty()


def test_secrets_rules_parsed():
    yaml = _MIN_YAML + """
custom_signatures:
  secrets:
    - id: INTERNAL-DEV-KEY
      regex: 'env_key_[a-zA-Z0-9]{32}'
      description: "Internal dev creds"
    - id: PAYMENT-TOKEN
      regex: 'pay_(test|live)_[A-Za-z0-9]{20,40}'
"""
    s = parse_scope_yaml(yaml)
    assert len(s.custom_signatures.secrets) == 2
    ids = {r.id for r in s.custom_signatures.secrets}
    assert ids == {"INTERNAL-DEV-KEY", "PAYMENT-TOKEN"}
    internal = next(
        r for r in s.custom_signatures.secrets if r.id == "INTERNAL-DEV-KEY"
    )
    assert internal.description == "Internal dev creds"


def test_dockerfile_overrides_parsed():
    yaml = _MIN_YAML + """
custom_signatures:
  dockerfile:
    exclude_rules: [DL3008, DL3015]
    severity_overrides:
      DL3000: warning
      DL4006: error
"""
    s = parse_scope_yaml(yaml)
    df = s.custom_signatures.dockerfile
    assert "DL3008" in df.exclude_rules
    assert "DL3015" in df.exclude_rules
    sev_map = dict(df.severity_overrides)
    assert sev_map["DL3000"] == "warning"
    assert sev_map["DL4006"] == "error"


def test_bad_regex_rejected():
    yaml = _MIN_YAML + """
custom_signatures:
  secrets:
    - id: BAD
      regex: '['
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml)
    assert any("regex" in e and "invalid" in e for e in exc.value.errors)


def test_duplicate_secret_id_rejected():
    yaml = _MIN_YAML + """
custom_signatures:
  secrets:
    - id: DUP
      regex: 'foo'
    - id: DUP
      regex: 'bar'
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml)
    assert any("duplicate" in e.lower() for e in exc.value.errors)


def test_bad_severity_rejected():
    yaml = _MIN_YAML + """
custom_signatures:
  dockerfile:
    severity_overrides:
      DL3000: shouting
"""
    with pytest.raises(ScopeValidationError) as exc:
        parse_scope_yaml(yaml)
    assert any("severity_overrides" in e for e in exc.value.errors)


def test_secrets_not_a_list_rejected():
    yaml = _MIN_YAML + """
custom_signatures:
  secrets:
    id: NOT-A-LIST
    regex: '.*'
"""
    with pytest.raises(ScopeValidationError):
        parse_scope_yaml(yaml)


def test_custom_signatures_not_a_mapping_rejected():
    yaml = _MIN_YAML + """
custom_signatures: not-a-mapping
"""
    with pytest.raises(ScopeValidationError):
        parse_scope_yaml(yaml)


# =============================================================================
# Compiler
# =============================================================================

def test_compile_gitleaks_appends_rules(_isolated_cache):
    from strix.tools.rule_updates._compile import compile_gitleaks_config
    from strix.tools.rule_updates._common import cached_path
    # seed cache
    base = cached_path("gitleaks.toml")
    base.write_text("# baseline rules\n[[rules]]\nid = \"aws-key\"\n")

    sigs = CustomSignatures(secrets=(
        CustomSecretRule(
            id="INTERNAL", regex=r"env_[a-z0-9]{20}",
            description="dev",
        ),
        CustomSecretRule(id="PAY", regex=r"pay_live_\w+"),
    ))
    out = compile_gitleaks_config(sigs)
    assert out is not None
    text = out.read_text()
    # baseline still there
    assert "aws-key" in text
    # custom rules appended
    assert 'id          = "INTERNAL"' in text
    assert "env_[a-z0-9]{20}" in text
    assert 'id          = "PAY"' in text


def test_compile_gitleaks_skips_when_no_secrets():
    from strix.tools.rule_updates._compile import compile_gitleaks_config
    assert compile_gitleaks_config(CustomSignatures()) is None


def test_compile_gitleaks_skips_when_base_missing():
    from strix.tools.rule_updates._compile import compile_gitleaks_config
    sigs = CustomSignatures(secrets=(
        CustomSecretRule(id="X", regex="."),
    ))
    # No base file → returns None
    assert compile_gitleaks_config(sigs) is None


def test_compile_hadolint_merges_ignored_and_override(_isolated_cache):
    from strix.tools.rule_updates._compile import compile_hadolint_config
    from strix.tools.rule_updates._common import cached_path
    base = cached_path("hadolint.yaml")
    base.write_text(
        "ignored:\n  - DL3001\noverride:\n  warning: [DL3002]\n",
    )
    sigs = CustomSignatures(dockerfile=CustomDockerfileRules(
        exclude_rules=("DL3008", "DL3001"),  # DL3001 already there → no dup
        severity_overrides=(("DL3000", "warning"), ("DL4006", "error")),
    ))
    out = compile_hadolint_config(sigs)
    assert out is not None

    import yaml
    data = yaml.safe_load(out.read_text())
    # ignored union, no dup
    assert sorted(data["ignored"]) == ["DL3001", "DL3008"]
    # warning bucket contains existing DL3002 + new DL3000
    assert sorted(data["override"]["warning"]) == ["DL3000", "DL3002"]
    assert data["override"]["error"] == ["DL4006"]


def test_compile_hadolint_skips_when_empty():
    from strix.tools.rule_updates._compile import compile_hadolint_config
    assert compile_hadolint_config(CustomSignatures()) is None


def test_compile_all_returns_dict(_isolated_cache):
    from strix.tools.rule_updates._compile import compile_all
    from strix.tools.rule_updates._common import cached_path
    cached_path("gitleaks.toml").write_text("# base\n")
    cached_path("hadolint.yaml").write_text("ignored: []\n")
    sigs = CustomSignatures(
        secrets=(CustomSecretRule(id="X", regex="."),),
        dockerfile=CustomDockerfileRules(exclude_rules=("DL3008",)),
    )
    out = compile_all(sigs)
    assert set(out.keys()) == {"gitleaks", "hadolint"}
