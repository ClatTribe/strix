"""Tests for iter-25.4 — defensive-posture awareness."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from strix.l15.posture import (
    SecurityPosture,
    _check_waf_via_headers,
    clear_cache,
    get_posture,
    probe_defensive_posture,
    rate_limit_cap,
    set_posture,
    stealth_required,
)


@pytest.fixture(autouse=True)
def _clean_cache(monkeypatch):
    clear_cache()
    # Force wafw00f path off by default — tests opt-in
    monkeypatch.setenv("STRIX_WAFW00F_DISABLED", "1")
    yield
    clear_cache()


# --------------------------------------------------------------------
# Header-based WAF detection
# --------------------------------------------------------------------

def test_cloudflare_via_cf_ray_header():
    waf, vendor, cdn = _check_waf_via_headers({"cf-ray": "abc-DFW"})
    assert waf
    assert vendor == "cloudflare"
    assert cdn


def test_akamai_via_x_akamai_transformed():
    waf, vendor, cdn = _check_waf_via_headers(
        {"X-Akamai-Transformed": "9 25"},
    )
    assert waf
    assert vendor == "akamai"
    assert cdn


def test_no_waf_in_plain_headers():
    waf, vendor, cdn = _check_waf_via_headers(
        {"server": "nginx/1.18.0", "content-type": "text/html"},
    )
    assert not waf
    assert vendor is None
    assert not cdn


def test_aws_waf_via_action_header():
    waf, vendor, _ = _check_waf_via_headers(
        {"x-amzn-waf-action": "BLOCK"},
    )
    assert waf
    assert vendor == "aws_waf"


# --------------------------------------------------------------------
# probe_defensive_posture — happy path
# --------------------------------------------------------------------

def test_probe_returns_dataclass(monkeypatch):
    """Mock httpx so probe doesn't hit the network."""
    mock_resp = MagicMock()
    mock_resp.headers = {"cf-ray": "abc-DFW"}
    mock_resp.status_code = 200
    mock_client = MagicMock()
    mock_client.head.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None
    monkeypatch.setattr(
        "httpx.Client", lambda **kwargs: mock_client,
    )
    posture = probe_defensive_posture("https://e.com")
    assert isinstance(posture, SecurityPosture)
    assert posture.waf_detected
    assert posture.waf_vendor == "cloudflare"
    assert posture.cdn_detected
    assert posture.stealth_mode_required  # WAF detected → stealth


def test_probe_no_waf(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.headers = {"server": "nginx/1.18.0"}
    mock_resp.status_code = 200
    mock_client = MagicMock()
    mock_client.head.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None
    monkeypatch.setattr("httpx.Client", lambda **kwargs: mock_client)
    posture = probe_defensive_posture("https://plain.example.com")
    assert not posture.waf_detected
    assert not posture.cdn_detected


# --------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------

def test_get_posture_returns_none_when_not_probed():
    assert get_posture("https://never-probed.example.com") is None


def test_set_posture_then_get():
    p = SecurityPosture(target="https://x.com", waf_detected=True)
    set_posture(p)
    got = get_posture("https://x.com")
    assert got is p


def test_stealth_required_helper():
    set_posture(SecurityPosture(
        target="https://stealth.com",
        waf_detected=True, stealth_mode_required=True,
    ))
    set_posture(SecurityPosture(
        target="https://normal.com",
        waf_detected=False, stealth_mode_required=False,
    ))
    assert stealth_required("https://stealth.com") is True
    assert stealth_required("https://normal.com") is False
    assert stealth_required("https://unknown.com") is False


def test_rate_limit_cap_default_when_unprobed():
    assert rate_limit_cap("https://unprobed.com", default=20) == 20


def test_rate_limit_cap_uses_half_of_measured_rps():
    set_posture(SecurityPosture(
        target="https://x.com", rate_limit_rps=100,
    ))
    # cap = max(1, 100 // 2) = 50
    assert rate_limit_cap("https://x.com") == 50


def test_rate_limit_cap_floor_at_1():
    set_posture(SecurityPosture(
        target="https://x.com", rate_limit_rps=1,
    ))
    assert rate_limit_cap("https://x.com") == 1


# --------------------------------------------------------------------
# Robustness — invalid input
# --------------------------------------------------------------------

def test_empty_target_returns_safe_default():
    posture = probe_defensive_posture("")
    assert posture.target == ""
    assert posture.measurement_error == "empty target"


def test_conservative_flag_when_empty_target():
    posture = probe_defensive_posture("", conservative=True)
    assert posture.stealth_mode_required is True


def test_bare_host_gets_normalised(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.headers = {"server": "nginx"}
    mock_resp.status_code = 200
    mock_client = MagicMock()
    mock_client.head.return_value = mock_resp
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = None
    monkeypatch.setattr("httpx.Client", lambda **kwargs: mock_client)
    posture = probe_defensive_posture("example.com")
    # Should be normalised to http://example.com
    assert posture.target.startswith("http://")
