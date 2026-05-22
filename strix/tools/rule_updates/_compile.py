"""iter-24.2 — compile cached rule files + scope.yml custom_signatures
into final configs that gitleaks / hadolint consume.

Why a separate compile step (vs. just passing both files):
  * gitleaks only accepts a single ``--config`` path; we have to merge
    the base TOML with user-injected ``[[rules]]`` ourselves.
  * hadolint's ``.hadolint.yaml`` supports ``ignored:`` + ``override:``
    but the canonical base file is auto-generated upstream, so it's
    safer to read it, mutate the dict, and write the merged version
    than to try to feed two configs.

Compiled outputs live next to the cached base under ``<name>.compiled``
so the wiring code in secrets_scan / scan_dockerfile_hadolint can
look for the compiled variant first and fall back to the raw cached
file when no custom_signatures are present.
"""

from __future__ import annotations

import logging
from pathlib import Path

from strix.scope.spec import CustomSignatures
from strix.tools.rule_updates._common import cached_path


logger = logging.getLogger(__name__)


def compile_gitleaks_config(sigs: CustomSignatures) -> Path | None:
    """Merge ``custom_signatures.secrets`` into the cached
    ``gitleaks.toml`` and write the result to ``gitleaks.toml.compiled``.

    Returns the compiled path on success, ``None`` if the base cache
    isn't present (caller falls back to gitleaks defaults) or if the
    scope contains no custom secret rules.

    The injection is purely additive: we append new ``[[rules]]``
    blocks. No existing rules are mutated, so an upstream refresh of
    ``gitleaks.toml`` followed by a recompile always produces a
    superset.
    """
    if not sigs.secrets:
        return None
    base = cached_path("gitleaks.toml")
    if not base.is_file() or base.stat().st_size == 0:
        logger.debug(
            "gitleaks.toml cache missing — cannot compile custom rules",
        )
        return None

    base_text = base.read_text(encoding="utf-8")
    custom_blocks: list[str] = []
    for rule in sigs.secrets:
        # gitleaks TOML rule shape:
        #   [[rules]]
        #   id          = "..."
        #   description = "..."
        #   regex       = '''...'''
        custom_blocks.append(
            "\n\n[[rules]]\n"
            f'id          = "{_esc_toml(rule.id)}"\n'
            f'description = "{_esc_toml(rule.description or rule.id)}"\n'
            f"regex       = '''{rule.regex}'''\n"
        )

    out_path = cached_path("gitleaks.toml.compiled")
    out_path.write_text(
        base_text.rstrip() + "\n"
        + "\n# === iter-24.2: strix.scope.yml custom_signatures.secrets ===\n"
        + "".join(custom_blocks),
        encoding="utf-8",
    )
    return out_path


def compile_hadolint_config(sigs: CustomSignatures) -> Path | None:
    """Merge ``custom_signatures.dockerfile`` into the cached
    ``hadolint.yaml`` and write the result to ``hadolint.yaml.compiled``.

    Hadolint config keys we touch:
        ignored: [DL3008, ...]            — appended to existing list
        override:
          warning: [DL3000, ...]          — per-severity buckets
          error:   [DL4006, ...]
          info:    [...]
          style:   [...]

    Returns the compiled path on success, ``None`` if the base cache
    isn't present or scope contains no dockerfile customizations.
    """
    df = sigs.dockerfile
    if not df.exclude_rules and not df.severity_overrides:
        return None

    import yaml  # noqa: PLC0415  (delay import; yaml might not be on minimal stacks)

    base = cached_path("hadolint.yaml")
    base_data: dict = {}
    if base.is_file() and base.stat().st_size > 0:
        try:
            loaded = yaml.safe_load(base.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                base_data = loaded
        except yaml.YAMLError as e:
            logger.debug("hadolint.yaml cache unparseable: %s", e)
            base_data = {}

    # Merge ignored
    ignored = list(base_data.get("ignored") or [])
    for rid in df.exclude_rules:
        if rid not in ignored:
            ignored.append(rid)
    if ignored:
        base_data["ignored"] = ignored

    # Merge severity overrides
    override = dict(base_data.get("override") or {})
    for rid, sev in df.severity_overrides:
        bucket = list(override.get(sev) or [])
        if rid not in bucket:
            bucket.append(rid)
        override[sev] = bucket
        # Strip rid from any other severity bucket if it was previously listed
        for other_sev, items in list(override.items()):
            if other_sev == sev:
                continue
            override[other_sev] = [x for x in items if x != rid]
    if override:
        # Drop empty buckets
        override = {k: v for k, v in override.items() if v}
        base_data["override"] = override

    out_path = cached_path("hadolint.yaml.compiled")
    out_path.write_text(
        "# === iter-24.2: compiled from cached hadolint.yaml + "
        "strix.scope.yml custom_signatures.dockerfile ===\n"
        + yaml.safe_dump(base_data, sort_keys=True),
        encoding="utf-8",
    )
    return out_path


def compile_all(sigs: CustomSignatures) -> dict[str, Path]:
    """Compile every applicable config; return ``{kind: out_path}``."""
    out: dict[str, Path] = {}
    g = compile_gitleaks_config(sigs)
    if g is not None:
        out["gitleaks"] = g
    h = compile_hadolint_config(sigs)
    if h is not None:
        out["hadolint"] = h
    return out


def _esc_toml(s: str) -> str:
    """Minimal escape for inline TOML double-quoted strings."""
    return s.replace("\\", "\\\\").replace('"', '\\"')
