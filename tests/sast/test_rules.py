"""Tests for the bundled vibe-coded rule corpus.

Each rule must:
  * Be valid YAML.
  * Have an `id` starting with `strix-`.
  * Have a `severity` from {ERROR, WARNING, INFO}.
  * Declare at least one language.
  * Declare a CWE in `metadata.cwe` that's present in
    `_CWE_TO_CATEGORY` (so findings get the right cross-asset
    category for routing).
  * Set `metadata.vibe_pattern: true` so we can filter the corpus
    from non-AI-generated patterns at scoring time.
"""

from __future__ import annotations

import pytest

yaml = pytest.importorskip("yaml")

from strix.sast.semgrep_runner import (
    _CWE_TO_CATEGORY,
    VIBE_CODED_RULES_DIR,
)


_VALID_SEVERITIES = {"ERROR", "WARNING", "INFO"}


def _load_rules():
    """Yield (filename, rule_dict) for every rule in every YAML
    file in the bundled corpus."""
    for yml in VIBE_CODED_RULES_DIR.glob("*.yml"):
        doc = yaml.safe_load(yml.read_text(encoding="utf-8"))
        rules = doc.get("rules") if isinstance(doc, dict) else None
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if isinstance(rule, dict):
                yield yml.name, rule


def test_corpus_has_at_least_eight_rules() -> None:
    """v1 ships 9 anchors per the README. Don't accept fewer."""
    rules = list(_load_rules())
    assert len(rules) >= 8, [n for n, _ in rules]


def test_corpus_grew_to_at_least_30_rules() -> None:
    """Phase 7.2 corpus expansion — went from 9 anchors to 30+
    rules covering Express / Python / React-Next.js / LLM /
    crypto / file handling. Anti-rot: if someone deletes a swathe
    of rule files, this catches it before the regression hits
    customers."""
    rules = list(_load_rules())
    assert len(rules) >= 30, (
        f"corpus has shrunk to {len(rules)} rules; expected >=30 "
        f"after Phase 7.2 expansion"
    )


def test_rule_ids_are_unique() -> None:
    """Duplicate IDs cause Semgrep to silently drop one of the
    rules. Pin uniqueness across the whole corpus."""
    seen: dict[str, str] = {}
    for filename, rule in _load_rules():
        rid = rule.get("id")
        assert isinstance(rid, str), filename
        assert rid not in seen, (
            f"duplicate rule id `{rid}` in {filename} (also seen in "
            f"{seen[rid]})"
        )
        seen[rid] = filename


def test_rule_ids_use_strix_prefix() -> None:
    for filename, rule in _load_rules():
        rid = rule["id"]
        assert rid.startswith("strix-"), (
            f"{filename}: rule id `{rid}` should start with `strix-` "
            f"to namespace away from registry rules"
        )


def test_rule_severity_is_valid() -> None:
    for filename, rule in _load_rules():
        sev = rule.get("severity")
        assert sev in _VALID_SEVERITIES, (
            f"{filename}: severity `{sev}` not in {_VALID_SEVERITIES}"
        )


def test_rule_declares_languages() -> None:
    for filename, rule in _load_rules():
        langs = rule.get("languages")
        assert isinstance(langs, list) and langs, (
            f"{filename}: missing or empty `languages` list"
        )


def test_rule_has_cwe_in_category_map() -> None:
    """A rule whose CWE isn't in `_CWE_TO_CATEGORY` won't have a
    semantic category — the lead's cross-asset routing breaks."""
    for filename, rule in _load_rules():
        cwe = (rule.get("metadata") or {}).get("cwe")
        assert cwe, f"{filename}: missing metadata.cwe"
        # CWE is a single string in our YAML; ensure it's in the map.
        if isinstance(cwe, list):
            cwe_str = str(cwe[0])
        else:
            cwe_str = str(cwe)
        assert cwe_str in _CWE_TO_CATEGORY, (
            f"{filename}: CWE `{cwe_str}` not in _CWE_TO_CATEGORY — "
            f"add to the map in semgrep_runner.py or change the rule's CWE"
        )


def test_rule_marked_as_vibe_pattern() -> None:
    """Filterable from non-AI patterns at scoring time."""
    for filename, rule in _load_rules():
        meta = rule.get("metadata") or {}
        assert meta.get("vibe_pattern") is True, (
            f"{filename}: must set metadata.vibe_pattern: true"
        )


def test_each_rule_has_message() -> None:
    """Every rule needs a human-readable message; it becomes the
    finding description."""
    for filename, rule in _load_rules():
        msg = rule.get("message", "")
        assert isinstance(msg, str) and len(msg) > 30, (
            f"{filename}: message is too short to be useful "
            f"(have len={len(msg)})"
        )
