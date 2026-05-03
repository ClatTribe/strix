"""TLS / SSL configuration audit.

Per-host probe of TLS posture: protocol versions, cipher suites,
certificate validity, SAN extraction. Each detected weakness emits a
finding with severity tuned to real-world impact.

Implementation note: uses Python's `ssl` module + `cryptography` for
cert parsing rather than shelling out to `openssl s_client`. Cleaner,
no subprocess overhead, full Python error handling, and the sandbox
already has both libraries.

Findings:
- **High** (CWE-327, weak_crypto) — weak cipher accepted (RC4 / 3DES /
  NULL / EXPORT / anonymous / DES).
- **High** (CWE-297, cert_invalid) — hostname mismatch on the
  presented certificate.
- **High** (CWE-298, cert_expired) — certificate already expired.
- **Medium** (CWE-326, weak_protocol) — TLS 1.0 or TLS 1.1 accepted
  (deprecated by RFC 8996 / PCI-DSS / NIST 800-52r2).
- **Medium** (CWE-295, cert_self_signed) — self-signed certificate
  (issuer == subject).
- **Low** (CWE-298, cert_expiring_soon) — cert expires within 30 days.

Composes with cluster-A safety: rate-limit applies to each connection
attempt; exclude-path doesn't quite fit (TLS audit operates on the
host:port, not a path) so it's a no-op for this tool.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "tls_audit"
_DEFAULT_TIMEOUT = 6.0
_DEFAULT_PORT = 443
_EXPIRY_WARN_DAYS = 30


# Protocol versions to probe. Each probe returns success/failure independently
# of the others. Old versions (TLS 1.0 / 1.1) accepted = finding.
_PROTOCOL_PROBES: tuple[tuple[str, ssl.TLSVersion, str, str, str | None], ...] = (
    # (label, ssl.TLSVersion, severity_when_accepted, message_when_accepted, cwe)
    ("TLS 1.0", ssl.TLSVersion.TLSv1, "medium",
     "TLS 1.0 accepted — deprecated by RFC 8996, PCI-DSS, and NIST 800-52r2.",
     "CWE-326"),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1, "medium",
     "TLS 1.1 accepted — deprecated by RFC 8996 and disallowed by modern compliance frameworks.",
     "CWE-326"),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2, "info",
     "TLS 1.2 supported (good — current minimum).",
     None),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3, "info",
     "TLS 1.3 supported (good — current best practice).",
     None),
)


# Weak-cipher cohorts. We probe each cohort with an explicit OpenSSL cipher
# string + low security level. If the handshake completes, the server accepts
# at least one cipher in that cohort.
_WEAK_CIPHER_PROBES: tuple[tuple[str, str, str, str, str], ...] = (
    # (label, openssl_cipher_string, severity, message, cwe)
    ("NULL ciphers", "NULL", "high",
     "NULL ciphers accepted — traffic is authenticated but not encrypted at all.",
     "CWE-327"),
    ("anonymous DH (aNULL)", "aNULL", "high",
     "Anonymous Diffie-Hellman accepted — no server authentication; trivial MITM.",
     "CWE-327"),
    ("EXPORT-grade ciphers", "EXPORT", "high",
     "EXPORT-grade ciphers accepted (40/56-bit). Trivially decrypted; FREAK / Logjam-class risk.",
     "CWE-327"),
    ("RC4", "RC4", "high",
     "RC4 stream cipher accepted. Disallowed by RFC 7465 and trivially decrypted given enough samples.",
     "CWE-327"),
    ("3DES (DES-CBC3)", "3DES:DES-CBC3-SHA", "high",
     "3DES (Triple DES) accepted. Sweet32 birthday attack against 64-bit block ciphers; deprecated by NIST.",
     "CWE-327"),
    ("DES (single)", "DES:!3DES", "high",
     "Single-DES accepted. 56-bit keys, trivially brute-forceable today.",
     "CWE-327"),
)


def _normalize_target(target: str) -> tuple[str, int] | None:
    """Accept hostname / hostname:port / https://host[:port]/path → (host, port)."""
    if not target or not isinstance(target, str):
        return None
    target = target.strip()
    if not target:
        return None
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme not in ("https", "http", "tls"):
            return None
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme in ("https", "tls") else 80)
        if not host:
            return None
        return host.lower(), int(port)
    # Bare hostname or hostname:port
    if ":" in target and target.count(":") == 1:
        host, _, port_str = target.partition(":")
        try:
            port = int(port_str)
        except ValueError:
            return None
        return host.lower(), port
    return target.lower(), _DEFAULT_PORT


def _probe_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> dict[str, Any]:
    """Try to handshake against a specific TLS version.

    Returns {accepted: bool, error: str | None}. Cipher / cert verification
    is intentionally relaxed so the protocol-version question is answered
    cleanly — separate probes handle the cert + cipher checks.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    except (ssl.SSLError, ValueError, AttributeError) as e:
        # Older OpenSSL builds may reject TLSv1 / TLSv1_1 outright; treat
        # that as the protocol being unavailable client-side, not as a
        # server miss.
        return {"accepted": False, "error": f"protocol unavailable on this OpenSSL: {e}"}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                # Successful handshake.
                _ = ssock.version()
                return {"accepted": True, "error": None}
    except ssl.SSLError as e:
        return {"accepted": False, "error": f"SSLError: {e}"}
    except (OSError, socket.timeout) as e:
        return {"accepted": False, "error": f"OSError: {e}"}


def _probe_weak_cipher(host: str, port: int, cipher_string: str, timeout: float) -> dict[str, Any]:
    """Try to negotiate any cipher in the weak cohort.

    Uses `@SECLEVEL=0` to defeat OpenSSL's default minimum security level
    so the test isn't refused client-side. Many builds still won't accept
    NULL / EXPORT even with SECLEVEL=0 — those return an SSLError without
    the server ever seeing the ClientHello, which is recorded as
    "client cannot test" rather than "server rejected".
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Lower the security level + apply the explicit cipher list.
        try:
            ctx.set_ciphers(f"{cipher_string}:@SECLEVEL=0")
        except ssl.SSLError:
            # Some OpenSSL builds reject @SECLEVEL=0 in the cipher list.
            # Try without — accept failure if the cipher is also rejected.
            try:
                ctx.set_ciphers(cipher_string)
            except ssl.SSLError as e:
                return {"accepted": False, "error": f"client refused cipher: {e}", "client_capable": False}
        # Allow any TLS version so the cipher cohort isn't blocked by the
        # protocol-min-version check (some weak ciphers only exist on TLS 1.0).
        try:
            ctx.minimum_version = ssl.TLSVersion.SSLv3
        except (ValueError, AttributeError):
            pass
    except ssl.SSLError as e:
        return {"accepted": False, "error": f"context setup: {e}", "client_capable": False}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                return {
                    "accepted": True,
                    "error": None,
                    "negotiated_cipher": cipher[0] if cipher else None,
                    "negotiated_protocol": ssock.version(),
                    "client_capable": True,
                }
    except ssl.SSLError as e:
        # Server rejected the cipher cohort — desired outcome.
        return {"accepted": False, "error": f"SSLError: {e}", "client_capable": True}
    except (OSError, socket.timeout) as e:
        return {"accepted": False, "error": f"OSError: {e}", "client_capable": True}


def _fetch_certificate(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Connect with verification disabled so even invalid certs are
    retrievable; parse the leaf cert with `cryptography`."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    except (ssl.SSLError, AttributeError) as e:
        return {"present": False, "error": f"SSL context setup: {e}"}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return {"present": False, "error": "no certificate presented"}
                cipher = ssock.cipher()
                version = ssock.version()
    except (ssl.SSLError, OSError, socket.timeout) as e:
        return {"present": False, "error": f"connection failed: {e}"}

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:  # noqa: BLE001
        return {"present": True, "error": f"cert parse failed: {e}"}

    subject = _name_to_dict(cert.subject)
    issuer = _name_to_dict(cert.issuer)
    self_signed = subject == issuer

    # SANs — feed back into the subdomain pool.
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(str(name.value).lower())
    except x509.ExtensionNotFound:
        pass
    except Exception:  # noqa: BLE001
        logger.debug("SAN extraction failed", exc_info=True)

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(UTC)
    days_until_expiry = (not_after - now).days
    expired = now > not_after
    not_yet_valid = now < not_before

    # Hostname validation — separate from cert-fetch since we disabled it
    # to allow retrieval of bad certs.
    hostname_match = _check_hostname_match(host, cert)

    try:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:  # noqa: BLE001
        fingerprint = ""

    return {
        "present": True,
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "issuer_o": issuer.get("organizationName"),
        "self_signed": self_signed,
        "sans": sans,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "expired": expired,
        "not_yet_valid": not_yet_valid,
        "hostname_match": hostname_match,
        "fingerprint_sha256": fingerprint,
        "negotiated_cipher": cipher[0] if cipher else None,
        "negotiated_protocol": version,
    }


def _name_to_dict(x509_name) -> dict[str, str]:  # type: ignore[no-untyped-def]
    """Convert an X.509 Name to a flat dict (e.g. {'commonName': 'x',
    'organizationName': 'y'})."""
    out: dict[str, str] = {}
    try:
        from cryptography.x509 import oid

        # NameOID maps OIDs to human-readable strings; we want the most
        # commonly-asked fields with friendly keys.
        wanted = {
            oid.NameOID.COMMON_NAME: "commonName",
            oid.NameOID.ORGANIZATION_NAME: "organizationName",
            oid.NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnit",
            oid.NameOID.COUNTRY_NAME: "country",
        }
        for attr in x509_name:
            key = wanted.get(attr.oid)
            if key:
                out[key] = str(attr.value)
    except Exception:  # noqa: BLE001
        pass
    return out


def _check_hostname_match(host: str, cert) -> bool:  # type: ignore[no-untyped-def]
    """Match the hostname against the cert's CN + SANs (RFC 6125-ish)."""
    try:
        from cryptography import x509

        # SAN list (RFC 6125 says SANs supersede CN).
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName) and _hostname_matches(host, str(name.value)):
                    return True
        except x509.ExtensionNotFound:
            pass

        # Fall back to CN.
        subject = _name_to_dict(cert.subject)
        cn = subject.get("commonName")
        if cn and _hostname_matches(host, cn):
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _hostname_matches(host: str, pattern: str) -> bool:
    """Wildcard-aware match: `*.example.com` matches `foo.example.com` but
    not `example.com` or `bar.foo.example.com`."""
    host_lower = host.lower().rstrip(".")
    pattern_lower = pattern.lower().rstrip(".")
    if host_lower == pattern_lower:
        return True
    if pattern_lower.startswith("*."):
        suffix = pattern_lower[1:]  # `.example.com`
        # Must match exactly one label to the left of the suffix.
        if host_lower.endswith(suffix):
            left = host_lower[: -len(suffix)]
            if left and "." not in left:
                return True
    return False


def _emit_finding(
    *,
    title: str,
    severity: str,
    cwe: str,
    target: str,
    endpoint: str,
    description: str,
    description_plain: str,
    recommended_action: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return
    tracer.add_vulnerability_report(
        title=title,
        severity=severity,
        category="tls_misconfig",
        cwe=cwe,
        target=target,
        endpoint=endpoint,
        description=description,
        impact=(
            "Weak TLS configurations enable passive eavesdropping "
            "(weak ciphers / old protocols), active MITM (anonymous DH / "
            "expired or self-signed certs), and certificate-pinning "
            "bypass for downstream clients. Modern compliance regimes "
            "(PCI-DSS, FedRAMP, SOC 2) require TLS 1.2+ with strong "
            "ciphers and a valid chain; this is also a common audit-fail "
            "trigger."
        ),
        remediation_steps=recommended_action,
        description_plain=description_plain,
        recommended_action=recommended_action,
        verification_status="verified",
    )


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592.002", "T1595.002"],  # Software fingerprinting + Vulnerability Scanning
)
def tls_audit(
    target: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Audit TLS configuration on a target host.

    Args:
        target: hostname / hostname:port / URL. Default port 443.
        timeout: per-probe timeout in seconds (default 6).

    Probes:
    - TLS 1.0 / 1.1 / 1.2 / 1.3 acceptance (one connection each).
    - Weak cipher cohorts: NULL, anonymous DH, EXPORT, RC4, 3DES, DES.
    - Certificate retrieval + parse: subject CN, issuer, SANs, expiry,
      self-signed detection, hostname-match check.

    Returns:
        {
          success, target, host, port,
          protocols: {"TLS 1.0": {accepted, error}, ...},
          weak_ciphers: {"RC4": {accepted, ...}, ...},
          certificate: {present, subject_cn, sans, expired, ...},
          findings_emitted: int
        }

    Findings:
        - **High** weak cipher / hostname mismatch / expired cert
        - **Medium** TLS 1.0 or 1.1 / self-signed
        - **Low** cert expiring within 30 days
    """
    parsed = _normalize_target(target)
    if not parsed:
        return {"success": False, "error": f"invalid target: {target!r}"}
    host, port = parsed

    cev = _start_check("tls_audit", host)

    findings_emitted = 0

    # ---- Protocol probes ----
    protocols: dict[str, dict[str, Any]] = {}
    for label, version, severity, message, cwe in _PROTOCOL_PROBES:
        result = _probe_protocol(host, port, version, timeout)
        protocols[label] = result
        if result["accepted"] and severity != "info":
            assert cwe is not None
            _emit_finding(
                title=f"{label} accepted on {host}:{port}",
                severity=severity,
                cwe=cwe,
                target=host,
                endpoint=f"https://{host}:{port}",
                description=message,
                description_plain=(
                    f"Your server still accepts {label}, which is an old "
                    "encryption protocol that has known weaknesses. Modern "
                    "browsers and compliance standards require TLS 1.2 or 1.3."
                ),
                recommended_action=(
                    f"Disable {label} in your TLS configuration. For nginx: "
                    "set `ssl_protocols TLSv1.2 TLSv1.3;`. For Apache: "
                    "`SSLProtocol -all +TLSv1.2 +TLSv1.3`. For cloud "
                    "load-balancers, choose a 'TLS 1.2+' security policy."
                ),
            )
            findings_emitted += 1

    # ---- Cert retrieval + parse ----
    cert = _fetch_certificate(host, port, timeout)
    if cert.get("present"):
        if cert.get("expired"):
            _emit_finding(
                title=f"Expired certificate on {host}:{port}",
                severity="high",
                cwe="CWE-298",
                target=host,
                endpoint=f"https://{host}:{port}",
                description=(
                    f"Certificate expired on {cert.get('not_after')}. "
                    f"Issuer: {cert.get('issuer_cn')}; subject: "
                    f"{cert.get('subject_cn')}."
                ),
                description_plain=(
                    "Your TLS certificate has expired. Browsers refuse to "
                    "load the site at all, and any client that does connect "
                    "is wide open to man-in-the-middle attacks."
                ),
                recommended_action=(
                    "Renew the certificate immediately. If using Let's "
                    "Encrypt, ensure your auto-renewal cron / systemd timer "
                    "is actually running (`certbot renew --dry-run`)."
                ),
            )
            findings_emitted += 1
        elif cert.get("days_until_expiry", 9999) <= _EXPIRY_WARN_DAYS:
            days = cert["days_until_expiry"]
            _emit_finding(
                title=f"Certificate expiring soon on {host}:{port} ({days} days)",
                severity="low",
                cwe="CWE-298",
                target=host,
                endpoint=f"https://{host}:{port}",
                description=f"Certificate expires in {days} day(s) on {cert.get('not_after')}.",
                description_plain=(
                    f"Your TLS certificate expires in {days} day(s). Renew it "
                    "soon to avoid an outage."
                ),
                recommended_action=(
                    "Renew the certificate before the expiry date. Verify "
                    "auto-renewal is functioning."
                ),
            )
            findings_emitted += 1

        if cert.get("self_signed"):
            _emit_finding(
                title=f"Self-signed certificate on {host}:{port}",
                severity="medium",
                cwe="CWE-295",
                target=host,
                endpoint=f"https://{host}:{port}",
                description=(
                    f"Certificate is self-signed (issuer == subject = "
                    f"{cert.get('subject_cn')}). No CA chain to validate "
                    "trust."
                ),
                description_plain=(
                    "Your TLS certificate is self-signed — not issued by a "
                    "trusted Certificate Authority. Browsers will warn users; "
                    "any attacker can impersonate the server because there's "
                    "nothing to verify the cert against."
                ),
                recommended_action=(
                    "Replace with a CA-signed certificate. Free option: "
                    "Let's Encrypt (`certbot --nginx -d <host>`). Don't ship "
                    "self-signed certs to anything other than internal-only "
                    "infra protected by other access controls."
                ),
            )
            findings_emitted += 1

        if not cert.get("hostname_match"):
            _emit_finding(
                title=f"Certificate hostname mismatch on {host}:{port}",
                severity="high",
                cwe="CWE-297",
                target=host,
                endpoint=f"https://{host}:{port}",
                description=(
                    f"Cert subject CN = {cert.get('subject_cn')!r}; SANs = "
                    f"{cert.get('sans', [])[:5]}. Hostname {host!r} does not "
                    "match either."
                ),
                description_plain=(
                    "Your TLS certificate is valid, but it was issued for a "
                    "different hostname. Browsers will refuse the connection; "
                    "any attacker holding a valid cert for a similar hostname "
                    "could intercept traffic."
                ),
                recommended_action=(
                    f"Reissue the certificate with `{host}` (or a wildcard "
                    "covering it) in the Subject Alternative Names. Confirm "
                    "with `openssl s_client -connect <host>:443 -servername "
                    "<host>`."
                ),
            )
            findings_emitted += 1

    # ---- Weak cipher probes ----
    # Only run when at least one TLS version was accepted — otherwise the
    # cipher probes burn time on a port that can't TLS-handshake at all.
    weak_ciphers: dict[str, dict[str, Any]] = {}
    any_protocol_up = any(p["accepted"] for p in protocols.values())
    if any_protocol_up:
        for label, cipher_string, severity, message, cwe in _WEAK_CIPHER_PROBES:
            result = _probe_weak_cipher(host, port, cipher_string, timeout)
            weak_ciphers[label] = result
            if result.get("accepted"):
                _emit_finding(
                    title=f"Weak cipher accepted ({label}) on {host}:{port}",
                    severity=severity,
                    cwe=cwe,
                    target=host,
                    endpoint=f"https://{host}:{port}",
                    description=(
                        f"{message} Negotiated cipher: "
                        f"{result.get('negotiated_cipher')}; protocol: "
                        f"{result.get('negotiated_protocol')}."
                    ),
                    description_plain=(
                        f"Your server accepts {label} encryption — these are "
                        "old, broken algorithms. An attacker recording the "
                        "traffic can decrypt it without much effort."
                    ),
                    recommended_action=(
                        "Restrict your cipher suite to modern AEAD ciphers "
                        "(AES-GCM, ChaCha20-Poly1305). For nginx: "
                        "`ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:"
                        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
                        "ECDHE-RSA-CHACHA20-POLY1305;` plus "
                        "`ssl_prefer_server_ciphers on;`."
                    ),
                )
                findings_emitted += 1
    else:
        weak_ciphers["_skipped"] = {"reason": "no TLS version accepted; cipher probes skipped"}

    issues = findings_emitted
    _complete_check(
        cev,
        result="vulnerable" if issues else "not_vulnerable",
        evidence=f"{issues} TLS issue(s) on {host}:{port}",
    )

    return {
        "success": True,
        "target": target,
        "host": host,
        "port": port,
        "protocols": protocols,
        "weak_ciphers": weak_ciphers,
        "certificate": cert,
        "findings_emitted": findings_emitted,
    }
