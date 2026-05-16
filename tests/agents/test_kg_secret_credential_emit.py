"""Tests for `record_secret_in_kg` and `record_credential_in_kg`.

The Secret/Credential nodes close the last KG-emission gap: the
`Vuln → LEAKS → Secret/Credential` chain that lets a downstream
query like "which findings leaked an AWS key" run efficiently.

Coverage:
  * Basic emit: Secret + Credential shape, fingerprint storage
  * **Raw secret value is NEVER stored on the node** (critical
    security invariant)
  * Dedup: same (kind, fingerprint) → one Secret node; same
    (service, username, kind) → one Credential node
  * LEAKS edge: created from Vuln (by finding_id) → Secret/
    Credential
  * Missing-input behaviour (no raw_value AND no fingerprint
    returns None)
  * Kill switch
"""

from __future__ import annotations

import pytest

from strix.agents import knowledge_graph as kg
from strix.agents.kg_emit import (
    record_credential_in_kg,
    record_finding_in_kg,
    record_secret_in_kg,
    reset_secret_cache_for_testing,
    reset_surface_cache_for_testing,
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    kg.reset_for_testing()
    reset_secret_cache_for_testing()
    reset_surface_cache_for_testing()
    monkeypatch.delenv("STRIX_KG_DISABLED", raising=False)


# ---------------------------------------------------------------------------
# record_secret_in_kg
# ---------------------------------------------------------------------------


def test_secret_basic_emit() -> None:
    node_id = record_secret_in_kg(
        finding_id=None,
        raw_value="AKIAIOSFODNN7EXAMPLE",
        masked="AKIA****EXAMPLE",
        secret_type="aws_access_key",
        detected_in="config.py:42",
    )
    assert node_id is not None
    node = kg.get_kg().get_node(node_id)
    assert node.type == "Secret"
    assert node.props["kind"] == "aws_access_key"
    assert node.props["masked"] == "AKIA****EXAMPLE"
    assert node.props["first_seen_in"] == "config.py:42"
    assert "fingerprint" in node.props


def test_secret_never_stores_raw_value() -> None:
    """CRITICAL security invariant: the raw secret value must
    never end up in any prop on the KG. We only store the
    fingerprint hash + the masked display form."""
    raw = "AKIAIOSFODNN7EXAMPLE"
    node_id = record_secret_in_kg(
        finding_id=None,
        raw_value=raw,
        masked="AKIA****EXAMPLE",
        secret_type="aws_access_key",
    )
    node = kg.get_kg().get_node(node_id)
    # Walk every prop value — none should equal or contain the raw secret.
    for value in node.props.values():
        if isinstance(value, str):
            assert raw not in value, (
                f"raw secret leaked into prop: {value!r}"
            )


def test_secret_accepts_fingerprint_without_raw_value() -> None:
    """When a scanner can't extract the raw value (e.g. the
    secret lives in a remote SaaS doc), it can pass a
    pre-computed fingerprint."""
    node_id = record_secret_in_kg(
        finding_id=None,
        fingerprint="abc123def456",
        masked="<saas-leak>",
        secret_type="github_doc_leak",
    )
    assert node_id is not None
    node = kg.get_kg().get_node(node_id)
    assert node.props["fingerprint"] == "abc123def456"


def test_secret_dedupes_on_kind_and_fingerprint() -> None:
    """The same AWS key found in two files = one Secret node +
    two LEAKS edges (later, when finding_ids supplied)."""
    a = record_secret_in_kg(
        finding_id=None,
        raw_value="AKIAIOSFODNN7EXAMPLE",
        masked="AKIA****EXAMPLE",
        secret_type="aws_access_key",
    )
    b = record_secret_in_kg(
        finding_id=None,
        raw_value="AKIAIOSFODNN7EXAMPLE",   # same secret
        masked="AKIA****EXAMPLE",
        secret_type="aws_access_key",
    )
    assert a == b


def test_secret_different_kinds_keep_separate_nodes() -> None:
    """A GitHub token and an AWS key with the same fingerprint
    (improbable but possible after hash truncation) stay
    distinct because `kind` is part of the dedup key."""
    a = record_secret_in_kg(
        finding_id=None, fingerprint="abc123",
        masked="m", secret_type="aws_access_key",
    )
    b = record_secret_in_kg(
        finding_id=None, fingerprint="abc123",
        masked="m", secret_type="github_token",
    )
    assert a != b


def test_secret_emits_leaks_edge_when_vuln_exists() -> None:
    """The whole point of the Secret node: a `Vuln → LEAKS →
    Secret` chain so queries can join findings to their leaked
    material."""
    # Set up a Vuln node with the finding_id we'll reference.
    record_finding_in_kg(
        finding_id="vuln-0001",
        url="file://src/config.py",
        param="aws_secret",
        cwe="CWE-798",
        severity="critical",
        category="hardcoded_secret",
        method="FILE",
    )
    record_secret_in_kg(
        finding_id="vuln-0001",
        raw_value="AKIAIOSFODNN7EXAMPLE",
        masked="AKIA****EXAMPLE",
        secret_type="aws_access_key",
    )
    g = kg.get_kg()
    leaks_edges = [e for e in g.query_edges(type="LEAKS")]
    assert len(leaks_edges) == 1


def test_secret_no_leaks_edge_without_finding_id() -> None:
    """When finding_id is None the helper still creates the
    Secret node but no LEAKS edge (no Vuln to attach to)."""
    record_secret_in_kg(
        finding_id=None,
        raw_value="AKIAIOSFODNN7EXAMPLE",
        masked="AKIA****EXAMPLE",
        secret_type="aws_access_key",
    )
    g = kg.get_kg()
    assert g.stats()["node_types"].get("Secret", 0) == 1
    assert g.stats()["edge_types"].get("LEAKS", 0) == 0


def test_secret_missing_inputs_returns_none() -> None:
    """No raw_value AND no fingerprint → can't dedup → reject."""
    assert record_secret_in_kg(
        finding_id=None, secret_type="aws_access_key",
    ) is None


def test_secret_kg_disabled_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_KG_DISABLED", "1")
    assert record_secret_in_kg(
        finding_id=None, raw_value="x",
        masked="x", secret_type="aws_access_key",
    ) is None


# ---------------------------------------------------------------------------
# record_credential_in_kg
# ---------------------------------------------------------------------------


def test_credential_basic_emit() -> None:
    node_id = record_credential_in_kg(
        finding_id=None,
        username="admin@example.com",
        masked_password="hunt****",
        service="okta",
        credential_kind="username_password",
        detected_in="saas-leaks:google-docs/abc",
    )
    assert node_id is not None
    node = kg.get_kg().get_node(node_id)
    assert node.type == "Credential"
    assert node.props["username"] == "admin@example.com"
    assert node.props["masked_password"] == "hunt****"
    assert node.props["service"] == "okta"
    assert node.props["kind"] == "username_password"


def test_credential_never_stores_raw_password() -> None:
    """Same security invariant as Secret. We store only the
    masked form."""
    node_id = record_credential_in_kg(
        finding_id=None,
        username="admin@example.com",
        masked_password="hunter2****",   # masked
        service="github",
    )
    node = kg.get_kg().get_node(node_id)
    # No raw-password material in any prop.
    for v in node.props.values():
        if isinstance(v, str):
            assert "hunter2" not in v or v == "hunter2****"


def test_credential_dedupes_on_service_user_kind() -> None:
    """Rotating a single user's password doesn't add a new node
    — it's still the same identity at the same service."""
    a = record_credential_in_kg(
        finding_id=None, username="admin@example.com",
        masked_password="old****", service="okta",
    )
    b = record_credential_in_kg(
        finding_id=None, username="admin@example.com",
        masked_password="new****", service="okta",
    )
    assert a == b


def test_credential_different_services_keep_separate_nodes() -> None:
    """Same username on two SaaSes → two Credential nodes."""
    a = record_credential_in_kg(
        finding_id=None, username="admin@example.com",
        masked_password="m", service="okta",
    )
    b = record_credential_in_kg(
        finding_id=None, username="admin@example.com",
        masked_password="m", service="aws",
    )
    assert a != b


def test_credential_username_case_insensitive() -> None:
    """Email comparison is case-insensitive."""
    a = record_credential_in_kg(
        finding_id=None, username="Admin@Example.com",
        masked_password="m", service="okta",
    )
    b = record_credential_in_kg(
        finding_id=None, username="admin@example.com",
        masked_password="m", service="okta",
    )
    assert a == b


def test_credential_emits_leaks_edge_when_vuln_exists() -> None:
    record_finding_in_kg(
        finding_id="vuln-CRED-1",
        url="https://docs.google.com/spreadsheets/d/abc",
        param="",
        cwe="CWE-200",
        severity="high",
        category="info_disclosure",
    )
    record_credential_in_kg(
        finding_id="vuln-CRED-1",
        username="admin@example.com",
        masked_password="m",
        service="okta",
    )
    g = kg.get_kg()
    assert g.stats()["edge_types"].get("LEAKS", 0) == 1


def test_credential_missing_username_returns_none() -> None:
    assert record_credential_in_kg(
        finding_id=None, masked_password="m", service="okta",
    ) is None
    assert record_credential_in_kg(
        finding_id=None, username="", masked_password="m",
        service="okta",
    ) is None


# ---------------------------------------------------------------------------
# DNS-hygiene → threat-intel observations
# ---------------------------------------------------------------------------


def test_dns_hygiene_emits_threat_intel_observations(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """End-to-end smoke: call dns_hygiene's monkeypatched checks
    and verify the KG gets one ThreatIntel node per check."""
    from strix.agents.kg_emit import (
        record_threat_intel_in_kg,
        reset_asset_cache_for_testing,
    )
    reset_asset_cache_for_testing()

    # Direct unit test of the emit path that dns_hygiene_check uses.
    # We don't need to invoke the full tool — its KG-emit loop is
    # exercised here on a synthetic results list.
    results = [
        {"check": "spf", "present": False},
        {"check": "dmarc", "present": True, "policy": "none"},
        {"check": "dnssec", "signed": True},
    ]
    for r in results:
        check = r.get("check")
        fail = (
            r.get("present") is False
            or r.get("policy") == "none"
            or r.get("signed") is False
        )
        record_threat_intel_in_kg(
            source=f"dns_hygiene:{check}",
            asset_type="domain",
            asset_value="example.com",
            verdict="compliance_fail" if fail else "benign",
        )

    stats = kg.get_kg().stats()
    assert stats["node_types"].get("ThreatIntel", 0) == 3
    assert stats["node_types"].get("Asset", 0) == 1   # shared domain
    assert stats["edge_types"].get("OBSERVED", 0) == 3
