"""Tests for the SSRF probe library — Phase 4 cohort expansion.

Pins the probe inventory, the family taxonomy, and the fingerprint
regexes. End-to-end probe behaviour (via scan_ssrf against a mock
HTTP server) is in `test_scan_ssrf.py`.
"""

from __future__ import annotations

import re

import pytest

from strix.tools.specialist.ssrf_probes import (
    FAMILIES,
    PROBES,
    SsrfProbe,
    get_probes,
    get_probes_by_family,
)


# ---------------------------------------------------------------------------
# Inventory — pin probe count + family distribution
# ---------------------------------------------------------------------------


def test_probe_count_meets_cohort_expansion_target() -> None:
    """Pre-expansion: 6 probes. Post-expansion target: 25+
    probes across the named families. The exact number is
    allowed to drift upward as we add probes; the floor is the
    contract."""
    assert len(PROBES) >= 25


def test_get_probes_returns_full_library() -> None:
    assert get_probes() is PROBES
    assert len(get_probes()) == len(PROBES)


def test_every_family_has_at_least_one_probe() -> None:
    """If a family appears in `FAMILIES` it MUST have at least one
    probe — otherwise the family label is dead documentation."""
    families_in_probes = {p.family for p in PROBES}
    for family in FAMILIES:
        assert family in families_in_probes, (
            f"family {family!r} declared in FAMILIES but has no "
            f"probes — either add probes or remove the family"
        )


def test_no_probe_uses_undeclared_family() -> None:
    """Reverse check: no probe carries a `family` not in `FAMILIES`."""
    declared = frozenset(FAMILIES)
    for p in PROBES:
        assert p.family in declared, (
            f"probe {p.label!r} uses undeclared family {p.family!r}"
        )


def test_probe_labels_are_unique() -> None:
    """Labels appear in finding titles and audit logs. Duplicates
    would produce ambiguous emissions."""
    labels = [p.label for p in PROBES]
    assert len(labels) == len(set(labels)), (
        f"duplicate labels: "
        f"{[l for l in labels if labels.count(l) > 1]}"
    )


# ---------------------------------------------------------------------------
# Per-family coverage — pin the cohort shape
# ---------------------------------------------------------------------------


def test_cloud_metadata_family_covers_major_providers() -> None:
    """Multi-cloud coverage is the headline value of cohort
    expansion. AWS / GCP / Azure are non-negotiable; Oracle /
    DigitalOcean / Alibaba are differentiation."""
    cloud = {p.label for p in get_probes_by_family("cloud_metadata")}
    assert "aws_metadata" in cloud
    assert "gcp_metadata" in cloud
    assert "azure_metadata" in cloud
    assert "oracle_metadata" in cloud
    assert "digitalocean_metadata" in cloud
    assert "alibaba_metadata" in cloud


def test_ip_encoding_family_covers_aws_and_loopback() -> None:
    """Both 169.254.169.254 AND 127.0.0.1 need the full
    decimal / hex / octal encoding bypass set — different
    targets, same filter-evasion technique."""
    ip = {p.label for p in get_probes_by_family("ip_encoding")}
    # AWS metadata via IP encoding
    assert "aws_decimal" in ip
    assert any("aws_hex" in label for label in ip)
    assert "aws_octal" in ip
    # Loopback via IP encoding
    assert "loopback_decimal" in ip
    assert any("loopback_hex" in label for label in ip)
    assert "loopback_octal" in ip
    # IPv6 variants for loopback
    assert "ipv6_loopback" in ip
    assert "ipv6_mapped_loopback" in ip


def test_dns_rebinding_family_uses_real_wildcard_providers() -> None:
    """`localtest.me` and `nip.io` are the two most-deployed
    wildcard-DNS-resolves-to-internal-IP providers. Both should
    be represented."""
    dns = {p.target for p in get_probes_by_family("dns_rebinding")}
    assert any("localtest.me" in t for t in dns)
    assert any("nip.io" in t for t in dns)


def test_alt_scheme_family_covers_gopher_and_dict() -> None:
    """SSRF-to-RCE on Redis depends on `gopher://` OR `dict://`
    being accepted by the consuming HTTP client."""
    schemes = {p.target.split("://")[0] for p in get_probes_by_family("alt_scheme")}
    assert "gopher" in schemes
    assert "dict" in schemes


def test_file_scheme_family_covers_etc_passwd() -> None:
    """`file:///etc/passwd` is the canonical local-file-read probe.
    Must be in the file_scheme family."""
    files = {p.target for p in get_probes_by_family("file_scheme")}
    assert "file:///etc/passwd" in files


def test_url_parser_bypass_family_has_at_bypass() -> None:
    """The `user@target` URL-parser bypass is the single most-
    common parser-vs-client divergence exploit. Must be present."""
    bypasses = {p.target for p in get_probes_by_family("url_parser_bypass")}
    assert any("@169.254.169.254" in t for t in bypasses)


# ---------------------------------------------------------------------------
# Severity calibration — critical vs high
# ---------------------------------------------------------------------------


def test_cloud_metadata_probes_are_critical() -> None:
    """Cloud metadata = IAM credential theft = direct compromise.
    All cloud_metadata probes MUST be severity=critical."""
    for p in get_probes_by_family("cloud_metadata"):
        assert p.severity == "critical", (
            f"probe {p.label!r} (cloud_metadata) is "
            f"{p.severity}, must be critical"
        )


def test_ip_encoding_aws_probes_critical_loopback_high() -> None:
    """An IP-encoded path to AWS metadata is STILL cloud
    credential theft → critical. An IP-encoded path to loopback
    is internal-service reach → high. The encoding doesn't
    change the impact class."""
    for p in get_probes_by_family("ip_encoding"):
        if p.target.endswith("/meta-data/"):
            assert p.severity == "critical", (
                f"AWS-metadata-via-{p.label!r} is {p.severity}, must be critical"
            )
        else:
            assert p.severity == "high"


def test_etc_passwd_is_critical() -> None:
    """Local file read of /etc/passwd is canonical
    information-disclosure-with-uid:0-shape → critical."""
    passwd = next(
        p for p in PROBES if p.label == "file_etc_passwd"
    )
    assert passwd.severity == "critical"


# ---------------------------------------------------------------------------
# Fingerprint regex compiles + matches expected payloads
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("probe", PROBES, ids=lambda p: p.label)
def test_every_fingerprint_regex_compiles(probe: SsrfProbe) -> None:
    """A bad regex would silently fail to detect SSRF. Compile each
    one to surface syntax errors at test time."""
    re.compile(probe.fingerprint_regex, re.IGNORECASE | re.MULTILINE)


def test_aws_imds_fingerprint_matches_real_response_shape() -> None:
    """Real AWS IMDS index response carries `ami-id`,
    `instance-id`, `iam/`, `security-credentials`, etc. The
    fingerprint must match at least one."""
    aws_probe = next(p for p in PROBES if p.label == "aws_metadata")
    sample_response = (
        "ami-id\n"
        "ami-launch-index\n"
        "ami-manifest-path\n"
        "instance-id\n"
        "iam/info\n"
        "iam/security-credentials/myrole\n"
        "placement/availability-zone\n"
    )
    assert re.search(
        aws_probe.fingerprint_regex, sample_response,
        re.IGNORECASE | re.MULTILINE,
    ) is not None


def test_etc_passwd_fingerprint_matches_uid_zero() -> None:
    """The /etc/passwd fingerprint must catch the uid:0:0 root
    line shape. uid != 0 lines should NOT match."""
    probe = next(p for p in PROBES if p.label == "file_etc_passwd")
    assert re.search(
        probe.fingerprint_regex,
        "root:x:0:0:root:/root:/bin/bash",
        re.IGNORECASE | re.MULTILINE,
    ) is not None
    # Non-root user must NOT match.
    assert re.search(
        probe.fingerprint_regex,
        "alice:x:1000:1000:alice:/home/alice:/bin/bash",
        re.IGNORECASE | re.MULTILINE,
    ) is None


def test_redis_fingerprint_matches_real_info_response() -> None:
    """Real Redis `INFO` response carries `redis_version:`,
    `tcp_port:`, `process_id:`. At least one must match."""
    probe = next(p for p in PROBES if p.label == "gopher_redis")
    sample = (
        "# Server\nredis_version:7.2.0\nredis_git_sha1:00000000\n"
        "tcp_port:6379\nprocess_id:42\nos:Linux 5.10.0 x86_64\n"
    )
    assert re.search(
        probe.fingerprint_regex, sample,
        re.IGNORECASE | re.MULTILINE,
    ) is not None


# ---------------------------------------------------------------------------
# get_probes_by_family filter semantics
# ---------------------------------------------------------------------------


def test_filter_by_single_family() -> None:
    cloud = get_probes_by_family("cloud_metadata")
    assert len(cloud) >= 6
    assert all(p.family == "cloud_metadata" for p in cloud)


def test_filter_by_multiple_families() -> None:
    out = get_probes_by_family("file_scheme", "alt_scheme")
    families = {p.family for p in out}
    assert families == {"file_scheme", "alt_scheme"}


def test_filter_by_empty_returns_empty() -> None:
    """Empty filter ≠ full library — empty filter means 'none'."""
    assert get_probes_by_family() == ()


def test_filter_by_unknown_family_returns_empty() -> None:
    assert get_probes_by_family("nonexistent_family") == ()


def test_filter_mixing_known_and_unknown_returns_only_known() -> None:
    out = get_probes_by_family("cloud_metadata", "nonexistent")
    assert len(out) >= 6
    assert all(p.family == "cloud_metadata" for p in out)


# ---------------------------------------------------------------------------
# IP encoding correctness — encoded forms must resolve to expected IP
# ---------------------------------------------------------------------------


def test_aws_decimal_encodes_169_254_169_254() -> None:
    """169.254.169.254 = 2852039166 decimal. Use ipaddress to
    confirm the encoded form decodes to the AWS metadata IP."""
    import ipaddress

    aws_probe = next(p for p in PROBES if p.label == "aws_decimal")
    # Extract the host portion: http://<DECIMAL>/path
    host = aws_probe.target.replace("http://", "").split("/")[0]
    decoded = ipaddress.ip_address(int(host))
    assert str(decoded) == "169.254.169.254"


def test_aws_hex_flat_encodes_169_254_169_254() -> None:
    """0xa9fea9fe = 169.254.169.254."""
    import ipaddress

    probe = next(p for p in PROBES if p.label == "aws_hex_flat")
    host = probe.target.replace("http://", "").split("/")[0]
    decoded = ipaddress.ip_address(int(host, 16))
    assert str(decoded) == "169.254.169.254"


def test_loopback_decimal_encodes_127_0_0_1() -> None:
    """127.0.0.1 = 2130706433 decimal."""
    import ipaddress

    probe = next(p for p in PROBES if p.label == "loopback_decimal")
    host = probe.target.replace("http://", "").split("/")[0]
    decoded = ipaddress.ip_address(int(host))
    assert str(decoded) == "127.0.0.1"


def test_loopback_hex_flat_encodes_127_0_0_1() -> None:
    """0x7f000001 = 127.0.0.1."""
    import ipaddress

    probe = next(p for p in PROBES if p.label == "loopback_hex_flat")
    host = probe.target.replace("http://", "").split("/")[0]
    decoded = ipaddress.ip_address(int(host, 16))
    assert str(decoded) == "127.0.0.1"
