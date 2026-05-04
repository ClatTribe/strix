"""Tests for CIDR / IP-range target support (roadmap §3 / PR #124).

Validates that infer_target_type correctly classifies CIDR forms
(`192.168.1.0/24`, `10.0.0.0/16`) as ip_address targets with
is_cidr=True and the documented safety cap on range size.
"""

from __future__ import annotations

import pytest

from strix.interface.utils import infer_target_type


# ---------------------------------------------------------------------------
# Single IP — unchanged behaviour
# ---------------------------------------------------------------------------


def test_single_ipv4_address() -> None:
    target_type, details = infer_target_type("192.168.1.10")
    assert target_type == "ip_address"
    assert details["target_ip"] == "192.168.1.10"
    assert "is_cidr" not in details


def test_single_ipv6_address() -> None:
    target_type, details = infer_target_type("2001:db8::1")
    assert target_type == "ip_address"
    assert details["target_ip"] == "2001:db8::1"


# ---------------------------------------------------------------------------
# CIDR / network forms
# ---------------------------------------------------------------------------


def test_cidr_24_classified() -> None:
    target_type, details = infer_target_type("192.168.1.0/24")
    assert target_type == "ip_address"
    assert details["is_cidr"] is True
    assert details["num_hosts"] == 256
    assert details["target_ip"] == "192.168.1.0/24"


def test_cidr_28_classified() -> None:
    target_type, details = infer_target_type("10.0.0.0/28")
    assert target_type == "ip_address"
    assert details["is_cidr"] is True
    assert details["num_hosts"] == 16


def test_cidr_with_host_bits_set_normalised() -> None:
    """`192.168.1.10/24` has host bits set; ip_network(strict=False)
    silently rounds down to 192.168.1.0/24."""
    target_type, details = infer_target_type("192.168.1.10/24")
    assert target_type == "ip_address"
    assert details["target_ip"] == "192.168.1.0/24"


def test_cidr_single_host_32_classified() -> None:
    """`/32` is a single host — still classified as CIDR for
    consistency in the agent's pipeline."""
    target_type, details = infer_target_type("192.168.1.10/32")
    assert target_type == "ip_address"
    assert details["is_cidr"] is True
    assert details["num_hosts"] == 1


# ---------------------------------------------------------------------------
# Safety cap
# ---------------------------------------------------------------------------


def test_cidr_above_safety_cap_rejected() -> None:
    """`/16` = 65536 hosts — exceeds the 4096 cap. Reject with
    a clear error."""
    with pytest.raises(ValueError) as exc:
        infer_target_type("10.0.0.0/16")
    assert "4096" in str(exc.value)
    assert "65536" in str(exc.value)


def test_cidr_at_cap_boundary_accepted() -> None:
    """`/20` = 4096 hosts — exactly at the cap, accepted."""
    target_type, details = infer_target_type("10.0.0.0/20")
    assert target_type == "ip_address"
    assert details["num_hosts"] == 4096


def test_cidr_just_above_cap_rejected() -> None:
    """`/19` = 8192 hosts — just over the cap, rejected."""
    with pytest.raises(ValueError):
        infer_target_type("10.0.0.0/19")


def test_cidr_8_rejected() -> None:
    """The classic /8 footgun — should never be accepted."""
    with pytest.raises(ValueError):
        infer_target_type("10.0.0.0/8")


# ---------------------------------------------------------------------------
# Disambiguation — domain/path with `/` shouldn't trip the CIDR path
# ---------------------------------------------------------------------------


def test_domain_with_path_not_classified_as_cidr() -> None:
    """`example.com/admin` is a web_application target, not CIDR."""
    target_type, details = infer_target_type("example.com/admin")
    assert target_type == "web_application"


def test_repo_url_not_classified_as_cidr() -> None:
    """A repository URL with `/` in the path isn't CIDR."""
    target_type, details = infer_target_type("https://github.com/owner/repo")
    # Either repository or web_application depending on _is_http_git_repo;
    # either way, NOT ip_address.
    assert target_type != "ip_address"


def test_invalid_cidr_string_rejected() -> None:
    """Garbage that LOOKS like CIDR but isn't a valid network."""
    with pytest.raises(ValueError):
        infer_target_type("not-a-network/24")
