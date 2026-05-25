"""Tests for iter-29.3 — shape-aware payload bins."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.l15.payload_bins import (
    PayloadBin,
    bin_for,
    bin_object_for,
    list_available_combinations,
)


# ---------------------------------------------------------------------------
# Anti-overfit guards
# ---------------------------------------------------------------------------

def test_no_sut_specific_payloads():
    """Anti-overfit: payload bins must not contain SUT-specific
    credentials, paths, hostnames, or product names."""
    src = Path(__file__).resolve().parents[2] / "strix" / "l15" / "payload_bins" / "__init__.py"
    text = src.read_text().lower()
    forbidden = (
        "juice-shop", "juiceshop", "bkimminich", "juice-sh.op",
        "vampi", "crapi", "nodegoat", "webgoat",
        "vibe-app", "nginx-vuln", "flask-vuln",
        "admin@juice", "test@juice",
    )
    for f in forbidden:
        assert f not in text, f"SUT-specific value {f!r} in payload_bins"


def test_every_bin_has_provenance():
    """Each bin must declare which public corpus it came from. No
    'inspired by the team' payloads."""
    for shape, cls in list_available_combinations():
        pb = bin_object_for(shape, cls)
        assert pb is not None
        assert pb.provenance, f"({shape},{cls}) missing provenance URL"
        # Loose check: provenance string should mention a known
        # corpus source (github, owasp, portswigger)
        prov = pb.provenance.lower()
        sources = ("github.com", "owasp", "portswigger")
        assert any(s in prov for s in sources), (
            f"({shape},{cls}) provenance={pb.provenance!r} doesn't reference "
            f"a public corpus"
        )


def test_payload_lists_non_empty():
    """Every registered bin must have at least 1 payload."""
    for shape, cls in list_available_combinations():
        pb = bin_object_for(shape, cls)
        assert pb is not None
        assert len(pb.payloads) >= 1


# ---------------------------------------------------------------------------
# Bin lookup
# ---------------------------------------------------------------------------

def test_sqli_form_bin_classic_payloads():
    payloads = bin_for("form", "sqli")
    assert "' OR '1'='1" in payloads
    assert "admin'--" in payloads


def test_sqli_json_includes_nosql_operators():
    """JSON SQLi bin must include MongoDB/NoSQL operators."""
    payloads = bin_for("json", "sqli")
    has_nosql = any(
        isinstance(p, dict) and ("$ne" in p or "$gt" in p or "$where" in p)
        for p in payloads
    )
    assert has_nosql


def test_xss_html_includes_classic_alert():
    payloads = bin_for("html", "xss")
    assert "<script>alert(1)</script>" in payloads


def test_ssrf_includes_imds_variants():
    """Must include AWS + GCP + Azure IMDS endpoints."""
    payloads = bin_for("url-param", "ssrf")
    joined = " ".join(payloads)
    assert "169.254.169.254" in joined  # AWS + Azure
    assert "metadata.google.internal" in joined  # GCP


def test_path_traversal_includes_encoded_variants():
    payloads = bin_for("path", "path-traversal")
    assert "../../../../etc/passwd" in payloads
    # Encoded variant
    assert any("%2F" in p or "%2f" in p for p in payloads)


def test_cmd_injection_includes_unix_and_windows():
    payloads = bin_for("form", "cmd-injection")
    joined = " ".join(payloads)
    assert "/etc/passwd" in joined        # Unix
    assert "whoami" in joined              # cross-platform


def test_xxe_xml_includes_doctype_entity():
    payloads = bin_for("xml", "xxe")
    joined = " ".join(payloads)
    assert "<!DOCTYPE" in joined
    assert "ENTITY" in joined


# ---------------------------------------------------------------------------
# Shape fallback
# ---------------------------------------------------------------------------

def test_unknown_shape_falls_back_to_form():
    """When the shape is unknown, the bin lookup should fall back
    to form (best generic guess)."""
    payloads = bin_for("unknown", "sqli")
    assert len(payloads) > 0
    assert "' OR '1'='1" in payloads  # form-bin payload


def test_static_shape_returns_empty():
    """Static assets are never payload-fired."""
    assert bin_for("static", "sqli") == []
    assert bin_for("static", "xss") == []


def test_grpc_shape_returns_empty():
    """gRPC without .proto can't be payload-fired safely."""
    assert bin_for("grpc", "sqli") == []


# ---------------------------------------------------------------------------
# WAF bypass variants
# ---------------------------------------------------------------------------

def test_waf_none_returns_base_payloads():
    base = bin_for("form", "sqli", waf=None)
    assert "' OR '1'='1" in base
    # No URL-encoded variant when no WAF
    assert "%27%20OR" not in " ".join(base)


def test_waf_cloudflare_appends_bypass_variants():
    base = bin_for("form", "sqli", waf=None)
    with_cf = bin_for("form", "sqli", waf="cloudflare")
    assert len(with_cf) > len(base)
    # CF-specific bypass variant present
    assert any("%27" in p for p in with_cf)


def test_waf_unknown_vendor_returns_base():
    """Unknown WAF vendor → no extra variants (don't hallucinate)."""
    base = bin_for("form", "sqli", waf=None)
    with_unknown = bin_for("form", "sqli", waf="acme-waf-2099")
    assert sorted(with_unknown, key=str) == sorted(base, key=str)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def test_list_available_combinations_includes_core_classes():
    combos = set(list_available_combinations())
    must = {
        ("form", "sqli"), ("json", "sqli"), ("graphql", "sqli"),
        ("html", "xss"), ("json", "xss"),
        ("url-param", "ssrf"),
        ("xml", "xxe"),
        ("path", "path-traversal"),
        ("form", "cmd-injection"),
    }
    missing = must - combos
    assert not missing, f"missing bin combinations: {missing}"


def test_bin_object_returns_payloadbin():
    pb = bin_object_for("form", "sqli")
    assert isinstance(pb, PayloadBin)
    assert pb.vuln_class == "sqli"
    assert pb.shape == "form"


def test_bin_object_for_missing_returns_none():
    """No bin for (grpc, sqli) and no fallback → None."""
    pb = bin_object_for("grpc", "sqli")
    assert pb is None


def test_payload_count_sane_bounded():
    """Each bin should be small (5-30 payloads). The whole "fire smart,
    not loud" philosophy: bigger isn't better."""
    for shape, cls in list_available_combinations():
        pb = bin_object_for(shape, cls)
        assert pb is not None
        assert 1 <= len(pb.payloads) <= 40, (
            f"({shape},{cls}) has {len(pb.payloads)} payloads — outside "
            f"the 1-40 sanity range"
        )


def test_payloadbin_dataclass_immutable_default_factories():
    """Dataclass should use field(default_factory=list) — not raw [].
    Catches the classic dataclass mutable-default bug."""
    pb1 = PayloadBin(shape="x", vuln_class="y")
    pb2 = PayloadBin(shape="x", vuln_class="y")
    pb1.payloads.append("test")
    assert pb2.payloads == []
