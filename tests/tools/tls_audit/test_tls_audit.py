"""Tests for the TLS audit tool.

Hermetic — `_probe_protocol`, `_probe_weak_cipher`, and `_fetch_certificate`
are monkeypatched so no real sockets are opened. Tests cover:

- Target normalization (hostname / host:port / URL / scheme stripping)
- Hostname match logic (exact + wildcard)
- TLS 1.0 / 1.1 accepted → medium finding (CWE-326)
- TLS 1.2 / 1.3 accepted → no finding (info only)
- Weak cipher accepted (RC4 / 3DES / NULL / EXPORT) → high finding (CWE-327)
- Certificate expired → high finding (CWE-298)
- Certificate expiring soon → low finding (CWE-298)
- Self-signed certificate → medium finding (CWE-295)
- Hostname mismatch → high finding (CWE-297)
- Modern, healthy cert → no findings
- Cipher probes are skipped when no protocol version is up
- description_plain + recommended_action populated on every finding
- Check event emitted with category=tls_audit
- SANs surfaced on the result for downstream subdomain enumeration
"""

from __future__ import annotations

import ssl
from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.proxy import http_safety
# The package re-exports `tls_audit` (the function) at
# `strix.tools.tls_audit.tls_audit`, shadowing the submodule of the same
# name in the package namespace. Pull the actual module out of sys.modules.
import sys

import strix.tools.tls_audit.tls_audit  # noqa: F401  # ensure submodule is imported

tls_module = sys.modules["strix.tools.tls_audit.tls_audit"]
tls_audit = tls_module.tls_audit


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
    tracer = Tracer("tls-audit-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _patch_probes(
    monkeypatch,
    *,
    protocols_accepted: dict[str, bool] | None = None,
    weak_ciphers_accepted: dict[str, bool] | None = None,
    certificate: dict[str, Any] | None = None,
) -> dict[str, list[Any]]:
    """Wire up fake probe functions. Returns call logs by probe type."""
    log: dict[str, list[Any]] = {"protocol": [], "cipher": [], "cert": []}
    protocols_accepted = protocols_accepted or {}
    weak_ciphers_accepted = weak_ciphers_accepted or {}

    # Map ssl.TLSVersion → label (matches _PROTOCOL_PROBES table)
    version_to_label = {
        ssl.TLSVersion.TLSv1: "TLS 1.0",
        ssl.TLSVersion.TLSv1_1: "TLS 1.1",
        ssl.TLSVersion.TLSv1_2: "TLS 1.2",
        ssl.TLSVersion.TLSv1_3: "TLS 1.3",
    }

    def fake_protocol(host, port, version, timeout):
        label = version_to_label.get(version, str(version))
        log["protocol"].append((host, port, label))
        accepted = protocols_accepted.get(label, False)
        return {"accepted": accepted, "error": None if accepted else "fake refused"}

    def fake_cipher(host, port, cipher_string, timeout):
        log["cipher"].append((host, port, cipher_string))
        accepted = weak_ciphers_accepted.get(cipher_string, False)
        if accepted:
            return {
                "accepted": True,
                "error": None,
                "negotiated_cipher": f"FAKE-{cipher_string}",
                "negotiated_protocol": "TLSv1.2",
                "client_capable": True,
            }
        return {"accepted": False, "error": "fake refused", "client_capable": True}

    def fake_cert(host, port, timeout):
        log["cert"].append((host, port))
        return certificate if certificate is not None else {"present": False, "error": "no cert"}

    monkeypatch.setattr(tls_module, "_probe_protocol", fake_protocol)
    monkeypatch.setattr(tls_module, "_probe_weak_cipher", fake_cipher)
    monkeypatch.setattr(tls_module, "_fetch_certificate", fake_cert)
    return log


def _good_cert(
    *,
    host: str = "example.com",
    sans: list[str] | None = None,
    expired: bool = False,
    days_until_expiry: int = 365,
    self_signed: bool = False,
    hostname_match: bool = True,
) -> dict[str, Any]:
    if sans is None:
        sans = [host, f"www.{host}"]
    return {
        "present": True,
        "subject_cn": host,
        "issuer_cn": "DigiCert TLS RSA SHA256 2020 CA1",
        "issuer_o": "DigiCert Inc",
        "self_signed": self_signed,
        "sans": sans,
        "not_before": "2025-01-01T00:00:00+00:00",
        "not_after": "2026-01-01T00:00:00+00:00",
        "days_until_expiry": days_until_expiry,
        "expired": expired,
        "not_yet_valid": False,
        "hostname_match": hostname_match,
        "fingerprint_sha256": "deadbeef" * 8,
        "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
        "negotiated_protocol": "TLSv1.3",
    }


# ---------------------------------------------------------------------------
# Target normalization
# ---------------------------------------------------------------------------


def test_normalize_bare_hostname() -> None:
    assert tls_module._normalize_target("example.com") == ("example.com", 443)


def test_normalize_host_port() -> None:
    assert tls_module._normalize_target("api.example.com:8443") == ("api.example.com", 8443)


def test_normalize_https_url() -> None:
    assert tls_module._normalize_target("https://example.com/some/path") == ("example.com", 443)


def test_normalize_https_url_with_port() -> None:
    assert tls_module._normalize_target("https://example.com:9443/x") == ("example.com", 9443)


def test_normalize_uppercase_host_lowered() -> None:
    assert tls_module._normalize_target("Example.COM") == ("example.com", 443)


def test_normalize_empty_returns_none() -> None:
    assert tls_module._normalize_target("") is None
    assert tls_module._normalize_target("   ") is None
    assert tls_module._normalize_target(None) is None  # type: ignore[arg-type]


def test_normalize_invalid_port_returns_none() -> None:
    assert tls_module._normalize_target("example.com:not-a-port") is None


def test_invalid_target_returns_failure() -> None:
    out = tls_module.tls_audit("")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Hostname matcher (RFC 6125 wildcard semantics)
# ---------------------------------------------------------------------------


def test_hostname_exact_match() -> None:
    assert tls_module._hostname_matches("example.com", "example.com") is True


def test_hostname_case_insensitive() -> None:
    assert tls_module._hostname_matches("Example.COM", "example.com") is True


def test_hostname_trailing_dot_ignored() -> None:
    assert tls_module._hostname_matches("example.com.", "example.com") is True


def test_hostname_wildcard_matches_one_label() -> None:
    assert tls_module._hostname_matches("foo.example.com", "*.example.com") is True


def test_hostname_wildcard_does_not_match_apex() -> None:
    assert tls_module._hostname_matches("example.com", "*.example.com") is False


def test_hostname_wildcard_does_not_match_two_labels() -> None:
    assert tls_module._hostname_matches("a.b.example.com", "*.example.com") is False


def test_hostname_no_match() -> None:
    assert tls_module._hostname_matches("foo.com", "bar.com") is False


# ---------------------------------------------------------------------------
# Protocol probes — findings
# ---------------------------------------------------------------------------


def test_tls_10_accepted_emits_medium_finding(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.0": True, "TLS 1.2": True, "TLS 1.3": True},
        certificate=_good_cert(),
    )
    out = tls_module.tls_audit("example.com")
    assert out["success"] is True
    assert out["protocols"]["TLS 1.0"]["accepted"] is True
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    titles = [r["title"] for r in reports]
    assert any("TLS 1.0" in t for t in titles)
    tls10 = next(r for r in reports if "TLS 1.0" in r["title"])
    assert tls10["severity"] == "medium"
    assert tls10["cwe"] == "CWE-326"
    assert tls10["category"] == "tls_misconfig"


def test_tls_11_accepted_emits_medium_finding(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.1": True, "TLS 1.2": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert any("TLS 1.1" in r["title"] for r in reports)


def test_tls_12_only_no_finding(monkeypatch) -> None:
    """Modern config — TLS 1.2 + 1.3 only, healthy cert → zero findings."""
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True, "TLS 1.3": True},
        certificate=_good_cert(),
    )
    out = tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []
    assert out["findings_emitted"] == 0


def test_tls_13_accepted_no_finding(monkeypatch) -> None:
    """TLS 1.3 alone is a `info` probe — no finding."""
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.3": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


# ---------------------------------------------------------------------------
# Weak cipher probes
# ---------------------------------------------------------------------------


def test_rc4_accepted_emits_high_finding(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        weak_ciphers_accepted={"RC4": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    rc4 = next((r for r in reports if "RC4" in r["title"]), None)
    assert rc4 is not None
    assert rc4["severity"] == "high"
    assert rc4["cwe"] == "CWE-327"


def test_3des_accepted_emits_high_finding(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        weak_ciphers_accepted={"3DES:DES-CBC3-SHA": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    threedes = next((r for r in reports if "3DES" in r["title"]), None)
    assert threedes is not None
    assert threedes["severity"] == "high"


def test_null_cipher_accepted_emits_high_finding(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        weak_ciphers_accepted={"NULL": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    nullf = next((r for r in reports if "NULL" in r["title"]), None)
    assert nullf is not None
    assert nullf["severity"] == "high"


def test_export_cipher_accepted_emits_high_finding(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        weak_ciphers_accepted={"EXPORT": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    expf = next((r for r in reports if "EXPORT" in r["title"]), None)
    assert expf is not None


def test_no_weak_ciphers_no_findings(monkeypatch) -> None:
    """Modern cipher suite — none of the weak cohorts accepted."""
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True, "TLS 1.3": True},
        weak_ciphers_accepted={},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_cipher_probes_skipped_when_no_protocol_up(monkeypatch) -> None:
    """No TLS version handshakes at all → cipher probes don't run."""
    log = _patch_probes(
        monkeypatch,
        protocols_accepted={},
        weak_ciphers_accepted={"RC4": True},  # would fire but probe not called
        certificate={"present": False, "error": "host unreachable"},
    )
    out = tls_module.tls_audit("example.com")
    assert log["cipher"] == []
    assert "_skipped" in out["weak_ciphers"]
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


# ---------------------------------------------------------------------------
# Certificate findings
# ---------------------------------------------------------------------------


def test_expired_cert_emits_high_finding(monkeypatch) -> None:
    cert = _good_cert(expired=True, days_until_expiry=-30)
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        certificate=cert,
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    expired = next((r for r in reports if "Expired" in r["title"]), None)
    assert expired is not None
    assert expired["severity"] == "high"
    assert expired["cwe"] == "CWE-298"


def test_expiring_soon_cert_emits_low_finding(monkeypatch) -> None:
    cert = _good_cert(days_until_expiry=10)
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        certificate=cert,
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    soon = next((r for r in reports if "expiring soon" in r["title"]), None)
    assert soon is not None
    assert soon["severity"] == "low"


def test_self_signed_cert_emits_medium_finding(monkeypatch) -> None:
    cert = _good_cert(self_signed=True)
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        certificate=cert,
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    selfsigned = next((r for r in reports if "Self-signed" in r["title"]), None)
    assert selfsigned is not None
    assert selfsigned["severity"] == "medium"
    assert selfsigned["cwe"] == "CWE-295"


def test_hostname_mismatch_emits_high_finding(monkeypatch) -> None:
    cert = _good_cert(hostname_match=False, sans=["other.example.com"])
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        certificate=cert,
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    mismatch = next((r for r in reports if "hostname mismatch" in r["title"]), None)
    assert mismatch is not None
    assert mismatch["severity"] == "high"
    assert mismatch["cwe"] == "CWE-297"


def test_healthy_cert_no_findings(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True, "TLS 1.3": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_cert_absent_no_cert_findings(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        certificate={"present": False, "error": "no cert"},
    )
    out = tls_module.tls_audit("example.com")
    assert out["certificate"]["present"] is False
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    # Cert findings should not fire when no cert was retrievable.
    cert_titles = [r["title"] for r in reports if "ert" in r["title"]]
    assert cert_titles == []


# ---------------------------------------------------------------------------
# Multiple findings + result shape
# ---------------------------------------------------------------------------


def test_multi_issue_target(monkeypatch) -> None:
    """Realistic legacy-server scenario: TLS 1.0 + RC4 + expired cert."""
    cert = _good_cert(expired=True, days_until_expiry=-5, self_signed=True)
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.0": True, "TLS 1.1": True, "TLS 1.2": True},
        weak_ciphers_accepted={"RC4": True, "3DES:DES-CBC3-SHA": True},
        certificate=cert,
    )
    out = tls_module.tls_audit("legacy.example.com")
    assert out["findings_emitted"] >= 5  # 1.0, 1.1, RC4, 3DES, expired, self-signed
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    severities = {r["severity"] for r in reports}
    assert "medium" in severities
    assert "high" in severities


def test_sans_returned_for_subdomain_pivoting(monkeypatch) -> None:
    """Cert SANs should propagate to the result for downstream subdomain enum."""
    cert = _good_cert(sans=["example.com", "www.example.com", "api.example.com", "staging.example.com"])
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        certificate=cert,
    )
    out = tls_module.tls_audit("example.com")
    assert out["certificate"]["sans"] == [
        "example.com", "www.example.com", "api.example.com", "staging.example.com",
    ]


# ---------------------------------------------------------------------------
# Wrapper UX baseline (§11)
# ---------------------------------------------------------------------------


def test_every_finding_has_plain_and_action(monkeypatch) -> None:
    """Per the §11 non-tech UX baseline: every finding must carry both
    description_plain and recommended_action."""
    cert = _good_cert(expired=True, self_signed=True, hostname_match=False, sans=["other.com"])
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.0": True, "TLS 1.1": True, "TLS 1.2": True},
        weak_ciphers_accepted={"RC4": True, "NULL": True},
        certificate=cert,
    )
    tls_module.tls_audit("example.com")
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert len(reports) >= 6
    for r in reports:
        assert r.get("description_plain"), f"missing description_plain on: {r['title']}"
        assert r.get("recommended_action"), f"missing recommended_action on: {r['title']}"
        assert r["category"] == "tls_misconfig"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_check_event_emitted_clean(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True, "TLS 1.3": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "tls_audit" in summary["by_category"]


def test_check_event_emitted_vulnerable(monkeypatch) -> None:
    _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.0": True, "TLS 1.2": True},
        certificate=_good_cert(),
    )
    tls_module.tls_audit("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    # By category
    cat = summary["by_category"]["tls_audit"]
    assert cat["vulnerable"] == 1


# ---------------------------------------------------------------------------
# URL/port handling end-to-end
# ---------------------------------------------------------------------------


def test_url_input_strips_path(monkeypatch) -> None:
    log = _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        certificate=_good_cert(),
    )
    out = tls_module.tls_audit("https://example.com/some/long/path?q=1")
    assert out["host"] == "example.com"
    assert out["port"] == 443
    # Probes used the bare host, not the URL.
    assert all(host == "example.com" for host, _, _ in log["protocol"])


def test_host_port_input_used_verbatim(monkeypatch) -> None:
    log = _patch_probes(
        monkeypatch,
        protocols_accepted={"TLS 1.2": True},
        certificate=_good_cert(),
    )
    out = tls_module.tls_audit("api.example.com:8443")
    assert out["host"] == "api.example.com"
    assert out["port"] == 8443
    assert all(port == 8443 for _, port, _ in log["protocol"])
