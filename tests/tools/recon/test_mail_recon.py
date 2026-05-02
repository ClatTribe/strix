"""Tests for mx_fingerprint.

Hermetic — `dig` and `_smtp_banner` are monkey-patched. No real network.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.recon import mail_recon as mr


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    tracer = Tracer("mx-test")
    set_global_tracer(tracer)
    tracer.set_scan_config({"targets": [{"type": "domain", "value": "example.com"}]})
    yield


def _stub_banner(host: str, *, banner: str = "", ehlo: str = "", error: str | None = None):
    """Build a fake _smtp_banner return."""
    if error:
        return {
            "success": False,
            "host": host,
            "port": 25,
            "banner": "",
            "ehlo_response": "",
            "error": error,
        }
    return {
        "success": True,
        "host": host,
        "port": 25,
        "banner": banner,
        "ehlo_response": ehlo,
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_invalid_domain_rejected() -> None:
    out = mr.mx_fingerprint("not a domain")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# MX resolution
# ---------------------------------------------------------------------------


def test_no_mx_records_returns_empty_results(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="unreachable"))
    out = mr.mx_fingerprint("example.com")
    assert out["success"] is True
    assert out["mx_records"] == []
    assert out["mx_results"] == []


def test_mx_records_sorted_by_preference(monkeypatch) -> None:
    monkeypatch.setattr(
        mr,
        "dig",
        lambda *a, **kw: "20 mx2.example.com.\n10 mx1.example.com.\n30 mx3.example.com.",
    )
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    out = mr.mx_fingerprint("example.com")
    hosts = [r["host"] for r in out["mx_records"]]
    assert hosts == ["mx1.example.com", "mx2.example.com", "mx3.example.com"]


def test_max_mx_hosts_cap(monkeypatch) -> None:
    """Only the first _MAX_MX_HOSTS records are queried."""
    records = "\n".join(f"{i*10} mx{i}.example.com." for i in range(1, 10))
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: records)
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    out = mr.mx_fingerprint("example.com")
    assert len(out["mx_records"]) == mr._MAX_MX_HOSTS


# ---------------------------------------------------------------------------
# Banner parsing & version disclosure finding
# ---------------------------------------------------------------------------


def test_banner_with_software_version_emits_info_finding(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "10 mx.example.com.")
    monkeypatch.setattr(
        mr,
        "_smtp_banner",
        lambda h, **kw: _stub_banner(
            h, banner="220 mx.example.com ESMTP Postfix (Debian/GNU)"
        ),
    )
    out = mr.mx_fingerprint("example.com")
    assert out["mx_results"][0]["software"] == "Postfix"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    info_findings = [r for r in reports if r["severity"] == "info"]
    assert len(info_findings) == 1
    assert "Postfix" in info_findings[0]["title"]


def test_banner_without_software_no_finding(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "10 mx.example.com.")
    monkeypatch.setattr(
        mr,
        "_smtp_banner",
        lambda h, **kw: _stub_banner(h, banner="220 mx.example.com Hello"),
    )
    out = mr.mx_fingerprint("example.com")
    assert out["mx_results"][0]["software"] is None
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    assert reports == []


def test_unreachable_mx_no_finding_no_crash(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "10 mx.example.com.")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="timeout"))
    out = mr.mx_fingerprint("example.com")
    assert out["success"] is True
    assert out["mx_results"][0]["success"] is False
    assert out["mx_results"][0]["error"] == "timeout"
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


# ---------------------------------------------------------------------------
# Stale-MTA flagging
# ---------------------------------------------------------------------------


def test_sendmail_emits_medium_finding(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "10 mx.example.com.")
    monkeypatch.setattr(
        mr,
        "_smtp_banner",
        lambda h, **kw: _stub_banner(
            h, banner="220 mx.example.com ESMTP Sendmail 8.15.2/8.15.2"
        ),
    )
    out = mr.mx_fingerprint("example.com")
    flags = out["mx_results"][0]["flags"]
    assert any(f["severity"] == "medium" for f in flags)
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    medium = [r for r in reports if r["severity"] == "medium"]
    assert len(medium) >= 1
    assert any(r["category"] == "vulnerable_dependency" for r in medium)


def test_old_exim_emits_medium_finding(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "10 mx.example.com.")
    monkeypatch.setattr(
        mr,
        "_smtp_banner",
        lambda h, **kw: _stub_banner(
            h, banner="220 mx.example.com ESMTP Exim 4.92 ready"
        ),
    )
    out = mr.mx_fingerprint("example.com")
    flags = out["mx_results"][0]["flags"]
    assert any("Exim" in f["label"] for f in flags)


def test_modern_postfix_no_stale_flag(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "10 mx.example.com.")
    monkeypatch.setattr(
        mr,
        "_smtp_banner",
        lambda h, **kw: _stub_banner(
            h, banner="220 mx.example.com ESMTP Postfix 3.7.4"
        ),
    )
    out = mr.mx_fingerprint("example.com")
    flags = out["mx_results"][0]["flags"]
    # Postfix 3.x should not match the 1.x/2.x stale flag.
    assert flags == []


# ---------------------------------------------------------------------------
# Sample-mail Authentication-Results parsing
# ---------------------------------------------------------------------------


def _write_eml(tmp_path, *, ar_header: str | None = None, from_addr: str = "alice@example.com") -> str:
    """Build a minimal .eml file and return its path."""
    headers = [
        f"From: Alice <{from_addr}>",
        "To: bob@elsewhere.com",
        "Subject: hello",
    ]
    if ar_header is not None:
        headers.append(f"Authentication-Results: {ar_header}")
    eml = ("\n".join(headers) + "\n\nbody\n").encode()
    p = tmp_path / "sample.eml"
    p.write_bytes(eml)
    return str(p)


def test_sample_mail_all_pass_no_finding(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    eml = _write_eml(
        tmp_path,
        ar_header="example.com; spf=pass smtp.mailfrom=alice@example.com; "
        "dkim=pass header.d=example.com; dmarc=pass action=none header.from=example.com",
    )
    out = mr.mx_fingerprint("example.com", sample_email_path=eml)
    sm = out["sample_mail"]
    assert sm["headers_present"] is True
    assert sm["spf"] == "pass"
    assert sm["dkim"] == "pass"
    assert sm["dmarc"] == "pass"
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_sample_mail_dmarc_fail_emits_medium(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    eml = _write_eml(
        tmp_path,
        ar_header="example.com; spf=pass; dkim=pass; dmarc=fail action=quarantine",
    )
    out = mr.mx_fingerprint("example.com", sample_email_path=eml)
    assert out["sample_mail"]["dmarc"] == "fail"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    findings = [r for r in reports if r["category"] == "authentication_bypass"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "medium"
    assert "dmarc=fail" in findings[0]["title"]


def test_sample_mail_softfail_emits_finding(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    eml = _write_eml(
        tmp_path,
        ar_header="example.com; spf=softfail; dkim=pass; dmarc=pass",
    )
    out = mr.mx_fingerprint("example.com", sample_email_path=eml)
    assert out["sample_mail"]["spf"] == "softfail"
    reports = tracer_module.get_global_tracer().get_existing_vulnerabilities()
    findings = [r for r in reports if r["category"] == "authentication_bypass"]
    assert len(findings) == 1


def test_sample_mail_no_ar_header_no_finding(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    eml = _write_eml(tmp_path, ar_header=None)
    out = mr.mx_fingerprint("example.com", sample_email_path=eml)
    assert out["sample_mail"]["headers_present"] is False
    assert tracer_module.get_global_tracer().get_existing_vulnerabilities() == []


def test_sample_mail_missing_file(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    out = mr.mx_fingerprint("example.com", sample_email_path="/nonexistent.eml")
    assert out["sample_mail"]["success"] is False
    assert out["sample_mail"]["error"] == "file_not_found"


def test_sample_mail_extracts_from_domain(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    eml = _write_eml(
        tmp_path, ar_header="example.com; spf=pass", from_addr="bob@subdomain.example.com"
    )
    out = mr.mx_fingerprint("example.com", sample_email_path=eml)
    assert out["sample_mail"]["from_domain"] == "subdomain.example.com"


# ---------------------------------------------------------------------------
# Check events
# ---------------------------------------------------------------------------


def test_emits_one_check_per_call(monkeypatch) -> None:
    monkeypatch.setattr(mr, "dig", lambda *a, **kw: "10 mx.example.com.")
    monkeypatch.setattr(mr, "_smtp_banner", lambda h, **kw: _stub_banner(h, error="t"))
    mr.mx_fingerprint("example.com")
    summary = tracer_module.get_global_tracer().get_check_summary()
    assert summary["total"] == 1
    assert "mx_recon" in summary["by_category"]
