"""E2E Phase E (L0 chain) — ruleset cache + custom_signatures injection.

Per `docs/E2E-test-proposal.md` §3.1. Each test exercises the full L0
chain end-to-end:

    cached file on disk  →  (optional) scope.yml custom_signatures
    →  compile_all()    →  scan_<tool> subprocess argv includes the
    compiled config

Mocks `subprocess.run` to capture argv (we don't actually shell out to
gitleaks/hadolint here — we verify the wiring), and `urllib.request.
urlopen` for refresh-failure tests.
"""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Point cache_root() at a tmpdir so tests don't touch ~/.strix."""
    cache_root_dir = tmp_path / "rules"
    cache_root_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("STRIX_RULES_CACHE_DIR", str(cache_root_dir))
    # Reload _common so the env var takes effect.
    import importlib
    from strix.tools.rule_updates import _common
    importlib.reload(_common)
    yield cache_root_dir


# =========================================================================
# E2E-L0-1 — cached gitleaks.toml picked up by secrets_scan
# =========================================================================

def test_l0_cached_gitleaks_config_used_by_secrets_scan(
    tmp_path, monkeypatch, _isolated_cache,
):
    """When `~/.strix/cache/rules/gitleaks.toml` exists, secrets_scan
    invokes gitleaks with `--config <cached>`."""
    # Plant a cached config file
    cfg = _isolated_cache / "gitleaks.toml"
    cfg.write_text("# fake gitleaks rules")

    # Stub binary lookup
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/gitleaks" if b == "gitleaks" else None,
    )

    captured = {}
    import subprocess

    def _capture(cmd, **kw):
        captured["cmd"] = cmd
        m = MagicMock()
        m.returncode = 0
        m.stdout = "[]"
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _capture)

    # Call gitleaks runner via the module path so it picks up the
    # cache lookup
    import sys
    import strix.tools.secrets_scan.secrets_scan  # noqa: F401
    ss_mod = sys.modules["strix.tools.secrets_scan.secrets_scan"]
    ss_mod._run_gitleaks(tmp_path, scan_git_history=False)

    cmd = captured["cmd"]
    assert "--config" in cmd
    assert str(cfg) in cmd, (
        f"gitleaks argv should reference cached config "
        f"{cfg}; got {cmd}"
    )


# =========================================================================
# E2E-L0-2 — scope.yml custom_signatures.secrets compiled + used
# =========================================================================

def test_l0_scope_custom_signatures_compiled_and_used_by_gitleaks(
    tmp_path, monkeypatch, _isolated_cache,
):
    """scope.yml carries `custom_signatures.secrets: [...]` → compile
    writes `gitleaks.toml.compiled` → secrets_scan picks the
    compiled variant over the base cached file."""
    # Plant a base cached gitleaks.toml
    base = _isolated_cache / "gitleaks.toml"
    base.write_text("# baseline rules\n[[rules]]\nid = \"aws-key\"\n")

    # Compile the scope.yml custom_signatures
    from strix.scope.spec import (
        CustomSecretRule,
        CustomSignatures,
    )
    from strix.tools.rule_updates._compile import compile_gitleaks_config

    sigs = CustomSignatures(secrets=(
        CustomSecretRule(
            id="INTERNAL-DEV-KEY",
            regex=r"env_key_[a-zA-Z0-9]{32}",
            description="Internal team dev creds",
        ),
    ))
    compiled_path = compile_gitleaks_config(sigs)
    assert compiled_path is not None
    assert compiled_path.exists()

    # Sanity-check the compiled file: contains baseline AND custom rule
    text = compiled_path.read_text()
    assert "aws-key" in text          # baseline preserved
    assert "INTERNAL-DEV-KEY" in text  # custom rule appended
    assert "env_key_" in text          # the regex text

    # Now exercise secrets_scan — it should prefer the compiled
    # variant over the base file
    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/gitleaks" if b == "gitleaks" else None,
    )
    captured = {}

    def _capture(cmd, **kw):
        captured["cmd"] = cmd
        m = MagicMock()
        m.returncode = 0
        m.stdout = "[]"
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _capture)

    import sys
    import strix.tools.secrets_scan.secrets_scan  # noqa: F401
    ss_mod = sys.modules["strix.tools.secrets_scan.secrets_scan"]
    ss_mod._run_gitleaks(tmp_path, scan_git_history=False)

    cmd = captured["cmd"]
    assert "--config" in cmd
    # Crucial assertion: compiled wins over base
    config_arg = cmd[cmd.index("--config") + 1]
    assert config_arg.endswith("gitleaks.toml.compiled"), (
        f"secrets_scan should use the compiled variant; got {config_arg}"
    )


# =========================================================================
# E2E-L0-3 — hadolint custom severity overrides propagate
# =========================================================================

def test_l0_hadolint_severity_overrides_compiled_and_used(
    tmp_path, monkeypatch, _isolated_cache,
):
    """`custom_signatures.dockerfile.severity_overrides` → compiled
    hadolint.yaml.compiled → scan_dockerfile_hadolint argv includes
    it."""
    # Plant a base cached hadolint.yaml
    base = _isolated_cache / "hadolint.yaml"
    base.write_text("ignored: []\noverride: {}\n")

    from strix.scope.spec import (
        CustomDockerfileRules,
        CustomSignatures,
    )
    from strix.tools.rule_updates._compile import compile_hadolint_config

    sigs = CustomSignatures(dockerfile=CustomDockerfileRules(
        exclude_rules=("DL3008",),
        severity_overrides=(
            ("DL3000", "warning"),
            ("DL4006", "error"),
        ),
    ))
    compiled = compile_hadolint_config(sigs)
    assert compiled is not None
    assert compiled.exists()

    # Verify compiled yaml has the merged content
    import yaml
    data = yaml.safe_load(compiled.read_text())
    assert "DL3008" in data["ignored"]
    assert "DL3000" in data["override"]["warning"]
    assert "DL4006" in data["override"]["error"]

    # Now exercise scan_dockerfile_hadolint
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3\n")

    import shutil
    import subprocess
    monkeypatch.setattr(
        shutil, "which",
        lambda b: "/usr/local/bin/hadolint" if b == "hadolint" else None,
    )
    captured = {}

    def _capture(cmd, **kw):
        captured["cmd"] = cmd
        m = MagicMock()
        m.returncode = 0
        m.stdout = "[]"
        m.stderr = ""
        return m

    monkeypatch.setattr(subprocess, "run", _capture)

    from strix.tools.hadolint_runner.scan_dockerfile_hadolint import (
        scan_dockerfile_hadolint,
    )
    scan_dockerfile_hadolint(str(df))

    cmd = captured["cmd"]
    assert "--config" in cmd
    config_arg = cmd[cmd.index("--config") + 1]
    assert config_arg.endswith("hadolint.yaml.compiled"), (
        f"hadolint should use compiled variant; got {config_arg}"
    )


# =========================================================================
# E2E-L0-4 — update failure falls back to baked seed
# =========================================================================

def test_l0_update_failure_preserves_existing_cache(
    monkeypatch, _isolated_cache,
):
    """`update_gitleaks_rules` with network error → status=partial →
    existing cache file untouched. Per docs/L1-optimization.md §5.1
    "fails-safe back to build-time static seed"."""
    # Plant an existing cache (pretend the build-time seed wrote it)
    cfg = _isolated_cache / "gitleaks.toml"
    cfg.write_text("# build-time baked seed v1.0")

    # Make the urlopen raise URLError (network down)
    import urllib.request

    def _network_down(*a, **k):
        raise urllib.error.URLError("network unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", _network_down)

    from strix.tools.rule_updates import update_gitleaks_rules

    result = update_gitleaks_rules(force=True)
    assert result["status"] == "partial", (
        f"expected partial status on network failure; got {result['status']}"
    )
    assert "network unreachable" in result.get("reason", "")

    # Existing cache MUST be untouched
    assert cfg.exists()
    assert cfg.read_text() == "# build-time baked seed v1.0", (
        "existing cache must NOT be modified on network failure"
    )
