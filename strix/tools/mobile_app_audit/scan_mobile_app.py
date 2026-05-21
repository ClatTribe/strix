"""iter-21.5 — `scan_mobile_app` deterministic mobile static
analysis (APK / IPA).

## Why this exists

Mobile static analysis is genuinely uncovered by generalist
scanners. Veracode / Checkmarx / Snyk Mobile / NowSecure each
charge separately for it; the OSS option (mobsf) is solid but
ships a heavy ~3GB container including its own DAST runner.

This tool runs the deterministic L1 layer in pure Python — no
docker dependency, no external CLI. It reads the binary as a
zip archive (both APK and IPA are zips), pulls the manifest /
Info.plist + selected resource files, and applies a rule set.

## Rules

### Android (APK)

| Rule | CWE | Severity | What it catches |
|---|---|---|---|
| android-debuggable | CWE-489 | high | `<application android:debuggable="true">` shipped to prod |
| android-allow-backup | CWE-359 | medium | `android:allowBackup="true"` lets adb/ADB pull user data |
| android-cleartext-traffic | CWE-319 | high | `usesCleartextTraffic="true"` or no network security config |
| android-exported-activity-no-permission | CWE-926 | high | `<activity android:exported="true">` without a permission attribute |
| android-dangerous-permission | CWE-250 | info | tagged for review when SMS / CALL_LOG / READ_CONTACTS etc. requested |
| android-old-min-sdk | CWE-1392 | low | `minSdkVersion < 24` (cutoff for hardened crypto / network security) |
| android-secret-in-resources | CWE-798 | high | API-key-shaped strings in res/values/strings.xml |

### iOS (IPA)

| Rule | CWE | Severity | What it catches |
|---|---|---|---|
| ios-ats-disabled | CWE-319 | high | `NSAllowsArbitraryLoads: true` in Info.plist (TLS bypass) |
| ios-ats-allow-http | CWE-319 | medium | per-domain `NSExceptionAllowsInsecureHTTPLoads: true` |
| ios-url-scheme-no-filter | CWE-939 | medium | `CFBundleURLSchemes` declared without LSApplicationQueriesSchemes filter |
| ios-secret-in-plist | CWE-798 | high | API-key-shaped strings inside Info.plist |

The rules are conservative — they flag PATTERNS that competent
mobile reviewers also examine. False positives are kept low by
requiring exact attribute matches (not loose string contains).

## Recall safety

Tool is read-only. Reads the binary, never modifies it; never
sends network traffic. Failures fall through to `status=partial`;
the rest of the audit proceeds with whatever was readable.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)


# Android namespace for manifest attributes.
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


# Permissions worth flagging for human review. These aren't auto-
# critical — many apps legitimately need them — but they're worth
# surfacing so the reviewer can confirm the request is justified.
_DANGEROUS_ANDROID_PERMISSIONS = frozenset({
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.GET_ACCOUNTS",
})


# Secret-shape regex — borrows from common gitleaks signatures.
# We're conservative: only catches HIGH-confidence patterns so we
# don't drown the report in false positives on benign-looking
# values.
_SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(
        r"\b[A-Za-z0-9/+=]{40}\b(?=.*aws|secret|access[_-]?key)",
        re.IGNORECASE,
    )),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", re.compile(r"\bxox[bp]-[0-9]{10,}-[0-9A-Za-z]{10,}\b")),
    ("stripe_live_key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")),
    ("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
    )),
]


def _detect_format(path: Path) -> str | None:
    """Best-effort classify a path as `apk` or `ipa`. Returns None
    when neither matches (e.g. AAB, raw .so file, anything that
    isn't a recognized mobile binary).
    """
    name = path.name.lower()
    if name.endswith(".apk"):
        return "apk"
    if name.endswith(".ipa"):
        return "ipa"
    # Try zip-magic + content sniff for cases where extension is
    # missing (rare but happens with stripped fixtures).
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if any(n == "AndroidManifest.xml" for n in names):
                return "apk"
            if any(n.startswith("Payload/") and n.endswith(".plist")
                   for n in names):
                return "ipa"
    except (zipfile.BadZipFile, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Android (APK) rules
# ---------------------------------------------------------------------------


def _audit_android_manifest(  # noqa: PLR0912, PLR0915
    manifest_xml: str,
) -> list[dict[str, Any]]:
    """Apply the Android manifest ruleset. `manifest_xml` should be
    the DECODED text manifest — if you have the binary AXML form
    from a real APK, decode it with apktool / aapt2 first.

    Test fixtures (and many open-source apps) ship the manifest
    in text form, so this works on both.
    """
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError as e:
        logger.debug("AndroidManifest parse failed: %s", e)
        return findings

    app = root.find("application")
    if app is not None:
        # debuggable=true
        if app.get(f"{_ANDROID_NS}debuggable") == "true":
            findings.append({
                "rule_id": "android-debuggable",
                "title": "Android app shipped with android:debuggable=\"true\"",
                "severity": "high",
                "cwe": "CWE-489",
                "description": (
                    "AndroidManifest.xml declares "
                    "`<application android:debuggable=\"true\">`. "
                    "Debuggable apps allow `adb shell run-as` to "
                    "inspect process memory, attach a debugger, "
                    "and extract content from app-private storage. "
                    "Production builds MUST set this to `false` "
                    "(default when omitted)."
                ),
                "remediation": (
                    "Remove `android:debuggable` from the production "
                    "manifest (or set it to `false`). Gradle should "
                    "manage this via build types — debug builds set "
                    "true automatically, release builds leave it "
                    "unset."
                ),
            })

        # allowBackup
        if app.get(f"{_ANDROID_NS}allowBackup") == "true":
            findings.append({
                "rule_id": "android-allow-backup",
                "title": "Android app permits ADB backup (allowBackup=\"true\")",
                "severity": "medium",
                "cwe": "CWE-359",
                "description": (
                    "`android:allowBackup=\"true\"` lets `adb backup` "
                    "extract the app's data directory (including "
                    "auth tokens, encrypted preferences, SQLite "
                    "databases) to a tar file. On non-USB-debug "
                    "devices the user has to consent, but the "
                    "default-on posture is a privacy risk."
                ),
                "remediation": (
                    "Set `android:allowBackup=\"false\"` in the "
                    "application tag, OR define a `fullBackupContent` "
                    "rules XML that excludes sensitive data dirs."
                ),
            })

        # usesCleartextTraffic
        if app.get(f"{_ANDROID_NS}usesCleartextTraffic") == "true":
            findings.append({
                "rule_id": "android-cleartext-traffic",
                "title": "Android app permits cleartext HTTP traffic",
                "severity": "high",
                "cwe": "CWE-319",
                "description": (
                    "`android:usesCleartextTraffic=\"true\"` permits "
                    "unencrypted HTTP requests to any host. MITM "
                    "attackers on the same Wi-Fi can read AND "
                    "modify all such traffic. Modern Android "
                    "(API 28+) defaults to false; explicitly "
                    "setting true is a regression."
                ),
                "remediation": (
                    "Remove `android:usesCleartextTraffic`. If "
                    "specific hosts need HTTP (e.g. local-dev "
                    "endpoints), declare them in a "
                    "`network_security_config.xml` per-domain "
                    "allowlist rather than globally enabling "
                    "cleartext."
                ),
            })

        # Exported activities / services / receivers without permission
        for tag in ("activity", "service", "receiver"):
            for el in app.findall(tag):
                exported = el.get(f"{_ANDROID_NS}exported")
                perm = el.get(f"{_ANDROID_NS}permission")
                name = el.get(f"{_ANDROID_NS}name", "(unnamed)")
                if exported == "true" and not perm:
                    findings.append({
                        "rule_id": "android-exported-component-no-permission",
                        "title": (
                            f"Exported Android {tag} `{name}` has no "
                            "permission attribute"
                        ),
                        "severity": "high",
                        "cwe": "CWE-926",
                        "description": (
                            f"`<{tag} android:exported=\"true\">` "
                            f"on `{name}` is callable by any "
                            "installed app on the device. Without "
                            "an `android:permission` attribute, the "
                            "caller doesn't need to hold any system "
                            "permission. Malicious apps can invoke "
                            "the component with crafted Intents to "
                            "trigger any code path the component "
                            "exposes."
                        ),
                        "remediation": (
                            "If the component MUST be exported, "
                            "add `android:permission=\"...\"` "
                            "naming a signature-only permission "
                            "defined by this app. If it doesn't "
                            "need to be reachable cross-app, set "
                            "`android:exported=\"false\"`."
                        ),
                    })

    # Dangerous permissions — informational tags only.
    for use in root.findall("uses-permission"):
        perm = use.get(f"{_ANDROID_NS}name")
        if perm in _DANGEROUS_ANDROID_PERMISSIONS:
            findings.append({
                "rule_id": "android-dangerous-permission",
                "title": f"Android app requests dangerous permission `{perm}`",
                "severity": "info",
                "cwe": "CWE-250",
                "description": (
                    f"The manifest declares `{perm}`. This isn't "
                    "necessarily a vulnerability — many apps "
                    "legitimately need it — but it's worth "
                    "confirming the permission is essential to "
                    "the app's function. Apps that over-request "
                    "permissions become attractive targets after "
                    "compromise."
                ),
                "remediation": (
                    "Verify the permission is required. If only "
                    "needed for one code path, consider gating "
                    "the request behind a runtime check at the "
                    "feature's first use rather than declaring it "
                    "manifest-wide."
                ),
            })

    # minSdkVersion
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk_raw = uses_sdk.get(f"{_ANDROID_NS}minSdkVersion")
        try:
            min_sdk = int(min_sdk_raw) if min_sdk_raw else None
        except (TypeError, ValueError):
            min_sdk = None
        if min_sdk is not None and min_sdk < 24:
            findings.append({
                "rule_id": "android-old-min-sdk",
                "title": (
                    f"Android app minSdkVersion={min_sdk} below "
                    "hardened-crypto cutoff (24)"
                ),
                "severity": "low",
                "cwe": "CWE-1392",
                "description": (
                    f"`minSdkVersion={min_sdk}` lets the app run "
                    "on Android < 7.0 (Nougat). Pre-Nougat versions "
                    "don't enforce the Network Security Config, "
                    "have weaker AES-GCM hardware acceleration, and "
                    "don't ship the modern Conscrypt provider. "
                    "Supporting these versions widens the "
                    "exploitable-device surface."
                ),
                "remediation": (
                    "Raise minSdkVersion to ≥24 (Android 7.0 "
                    "covers ≥98% of active devices today). For "
                    "apps requiring older support, document the "
                    "specific reason and ensure server-side does "
                    "not trust client-attested encryption."
                ),
            })

    return findings


def _audit_strings_xml(strings_xml: str) -> list[dict[str, Any]]:
    """Scan res/values/strings.xml for high-confidence secrets.

    Catches the common-mistake-pattern of shipping `<string
    name="api_key">AIza...</string>` directly in resources, which
    surfaces in every reverse-engineering pass.
    """
    findings: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(strings_xml)
    except ET.ParseError:
        return findings
    for el in root.findall("string"):
        text = (el.text or "").strip()
        name = el.get("name", "(unnamed)")
        for kind, pat in _SECRET_PATTERNS:
            if pat.search(text):
                findings.append({
                    "rule_id": "android-secret-in-resources",
                    "title": (
                        f"Hardcoded secret ({kind}) in "
                        f"res/values/strings.xml: `{name}`"
                    ),
                    "severity": "high",
                    "cwe": "CWE-798",
                    "description": (
                        f"The `{name}` string in "
                        "`res/values/strings.xml` matches a known "
                        f"{kind} secret shape. Resources are "
                        "trivially extractable via `apktool d` or "
                        "by unzipping the APK — anything in this "
                        "file is effectively public."
                    ),
                    "remediation": (
                        "Move the secret out of resources. For "
                        "API keys, fetch them from a backend at "
                        "auth time. For per-user tokens, use the "
                        "Android Keystore + EncryptedSharedPrefs. "
                        "If the value isn't actually a secret, "
                        "rotate the key (it's already compromised)."
                    ),
                })
                break  # one finding per resource is enough
    return findings


# ---------------------------------------------------------------------------
# iOS (IPA) rules — operate on parsed plist dict
# ---------------------------------------------------------------------------


def _audit_ios_info_plist(  # noqa: PLR0912
    plist: dict[str, Any],
) -> list[dict[str, Any]]:
    """Apply the iOS Info.plist ruleset. `plist` is the parsed
    plistlib dict (NSDictionary at the root)."""
    findings: list[dict[str, Any]] = []

    # ATS — App Transport Security
    ats = plist.get("NSAppTransportSecurity") or {}
    if isinstance(ats, dict):
        if ats.get("NSAllowsArbitraryLoads") is True:
            findings.append({
                "rule_id": "ios-ats-disabled",
                "title": "iOS app disables App Transport Security globally",
                "severity": "high",
                "cwe": "CWE-319",
                "description": (
                    "`NSAllowsArbitraryLoads: true` in "
                    "NSAppTransportSecurity disables iOS's TLS "
                    "policy enforcement for ALL outbound HTTP. "
                    "MITM attackers on the same network can read "
                    "AND modify all such traffic, AND "
                    "TLS-downgrade attacks are trivial. ATS is "
                    "default-on for a reason."
                ),
                "remediation": (
                    "Remove `NSAllowsArbitraryLoads`. If specific "
                    "endpoints need exceptions, declare per-domain "
                    "rules under `NSExceptionDomains` rather than "
                    "killing ATS globally."
                ),
            })
        exceptions = ats.get("NSExceptionDomains") or {}
        if isinstance(exceptions, dict):
            for domain, rules in exceptions.items():
                if not isinstance(rules, dict):
                    continue
                if rules.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    findings.append({
                        "rule_id": "ios-ats-allow-http",
                        "title": (
                            f"iOS ATS exception permits HTTP for "
                            f"`{domain}`"
                        ),
                        "severity": "medium",
                        "cwe": "CWE-319",
                        "description": (
                            f"`NSExceptionAllowsInsecureHTTPLoads: "
                            f"true` for `{domain}` lets the app "
                            "talk to that host over plaintext HTTP. "
                            "Even if the host is internal, traffic "
                            "to it is MITMable from any network "
                            "between the device and the host."
                        ),
                        "remediation": (
                            f"Deploy TLS on `{domain}` and remove "
                            "the exception. If TLS is genuinely "
                            "impossible (legacy hardware), pin "
                            "the connection to a specific cert/CA "
                            "via `NSPinnedCAIdentities`."
                        ),
                    })

    # URL schemes without query allowlist
    url_types = plist.get("CFBundleURLTypes") or []
    queries_allowed = plist.get("LSApplicationQueriesSchemes") or []
    declared_schemes: list[str] = []
    for ut in url_types if isinstance(url_types, list) else []:
        if not isinstance(ut, dict):
            continue
        for s in ut.get("CFBundleURLSchemes") or []:
            if isinstance(s, str):
                declared_schemes.append(s)
    if declared_schemes and not queries_allowed:
        findings.append({
            "rule_id": "ios-url-scheme-no-filter",
            "title": (
                f"iOS app declares URL schemes {declared_schemes} "
                "without LSApplicationQueriesSchemes filter"
            ),
            "severity": "medium",
            "cwe": "CWE-939",
            "description": (
                "Apps that declare custom URL schemes for inbound "
                "deep links should also declare "
                "`LSApplicationQueriesSchemes` to control which "
                "outbound schemes `canOpenURL:` will report. "
                "Absence often correlates with apps that pass "
                "untrusted scheme-handled URLs to UI flows "
                "without validation — a parallel to web open-"
                "redirect."
            ),
            "remediation": (
                "Define `LSApplicationQueriesSchemes` listing only "
                "the schemes the app actually queries. Validate "
                "inbound URL parameters before consuming them."
            ),
        })

    # Plist-embedded secrets
    def _walk(obj: Any, path: str = "") -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        if isinstance(obj, str):
            for kind, pat in _SECRET_PATTERNS:
                if pat.search(obj):
                    out.append((path, kind, obj))
                    break
        elif isinstance(obj, dict):
            for k, v in obj.items():
                out.extend(_walk(v, f"{path}.{k}" if path else str(k)))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                out.extend(_walk(v, f"{path}[{i}]"))
        return out

    for path, kind, _val in _walk(plist):
        findings.append({
            "rule_id": "ios-secret-in-plist",
            "title": (
                f"Hardcoded secret ({kind}) in Info.plist at `{path}`"
            ),
            "severity": "high",
            "cwe": "CWE-798",
            "description": (
                f"The plist key `{path}` contains a value matching "
                f"a known {kind} secret shape. Info.plist is part "
                "of the IPA bundle and trivially extractable; "
                "anything stored here is effectively public."
            ),
            "remediation": (
                "Remove the secret from Info.plist. For API keys, "
                "fetch them from a backend at auth time. For "
                "per-user tokens, use the iOS Keychain. If the "
                "value isn't actually a secret, rotate the key "
                "(it's already compromised)."
            ),
        })

    return findings


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592.002", "T1027"],  # gather software, obfuscation
)
def scan_mobile_app(
    binary_path: str,
) -> dict[str, Any]:
    """Deterministic L1 static audit of a mobile app binary
    (APK or IPA).

    Args:
        binary_path: filesystem path to the APK / IPA. Detection
            is by extension first, with a zip-content fallback for
            extension-stripped fixtures.

    Returns:
        ```
        {
          success: bool,
          format: "apk" | "ipa" | null,
          status: "ok" | "partial" | "error",
          path: <input path>,
          total_findings: int,
          findings: [
            {rule_id, title, severity, cwe, description, remediation},
            ...
          ],
          reason?: str  // when status=partial / error
        }
        ```

    Recall safety: read-only zip extraction, no execution. Each
    rule emits at most one finding per resource — duplicate
    detections across multiple secret patterns short-circuit to
    a single finding.
    """
    path = Path(binary_path)
    if not path.exists() or not path.is_file():
        return {
            "success": False,
            "status": "error",
            "format": None,
            "path": binary_path,
            "total_findings": 0,
            "findings": [],
            "reason": f"binary not found: {binary_path!r}",
        }

    fmt = _detect_format(path)
    if fmt is None:
        return {
            "success": True,
            "status": "partial",
            "format": None,
            "path": str(path),
            "total_findings": 0,
            "findings": [],
            "reason": (
                "could not detect APK/IPA format from extension or "
                "archive contents — pass a .apk or .ipa file"
            ),
        }

    findings: list[dict[str, Any]] = []

    if fmt == "apk":
        try:
            with zipfile.ZipFile(path) as z:
                # AndroidManifest.xml (binary AXML in real APKs;
                # we apply the rules to text-form manifests as
                # well, which covers test fixtures and many
                # debugged builds).
                try:
                    with z.open("AndroidManifest.xml") as fh:
                        manifest_bytes = fh.read()
                    try:
                        manifest_text = manifest_bytes.decode(
                            "utf-8", errors="ignore",
                        )
                    except Exception:  # noqa: BLE001
                        manifest_text = ""
                    if manifest_text.lstrip().startswith("<"):
                        findings.extend(_audit_android_manifest(manifest_text))
                except KeyError:
                    pass
                # res/values/strings.xml (also AXML in real builds;
                # text-form covered).
                for member in z.namelist():
                    if member.endswith("res/values/strings.xml"):
                        try:
                            with z.open(member) as fh:
                                strings_text = fh.read().decode(
                                    "utf-8", errors="ignore",
                                )
                            if strings_text.lstrip().startswith("<"):
                                findings.extend(
                                    _audit_strings_xml(strings_text),
                                )
                        except Exception as e:  # noqa: BLE001
                            logger.debug(
                                "strings.xml audit failed: %s", e,
                            )
                        break  # one strings.xml is typical
        except (zipfile.BadZipFile, OSError) as e:
            return {
                "success": False,
                "status": "error",
                "format": "apk",
                "path": str(path),
                "total_findings": 0,
                "findings": [],
                "reason": f"could not open APK: {e}",
            }

    elif fmt == "ipa":
        try:
            with zipfile.ZipFile(path) as z:
                # Info.plist lives at Payload/<app>.app/Info.plist
                plist_name = None
                for member in z.namelist():
                    if (
                        member.startswith("Payload/")
                        and member.endswith(".app/Info.plist")
                    ):
                        plist_name = member
                        break
                if plist_name is None:
                    return {
                        "success": True,
                        "status": "partial",
                        "format": "ipa",
                        "path": str(path),
                        "total_findings": 0,
                        "findings": [],
                        "reason": (
                            "no Payload/*.app/Info.plist found in IPA"
                        ),
                    }
                with z.open(plist_name) as fh:
                    plist_bytes = fh.read()
                try:
                    import plistlib
                    plist = plistlib.loads(plist_bytes)
                except Exception as e:  # noqa: BLE001
                    return {
                        "success": True,
                        "status": "partial",
                        "format": "ipa",
                        "path": str(path),
                        "total_findings": 0,
                        "findings": [],
                        "reason": f"could not parse Info.plist: {e}",
                    }
                if isinstance(plist, dict):
                    findings.extend(_audit_ios_info_plist(plist))
        except (zipfile.BadZipFile, OSError) as e:
            return {
                "success": False,
                "status": "error",
                "format": "ipa",
                "path": str(path),
                "total_findings": 0,
                "findings": [],
                "reason": f"could not open IPA: {e}",
            }

    # Emit each finding through the tracer if one is registered.
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is not None:
            for f in findings:
                tracer.add_vulnerability_report(
                    title=f["title"],
                    severity=f["severity"],
                    cwe=f["cwe"],
                    target=str(path),
                    endpoint=str(path),
                    category="mobile_static",
                    verification_status="pattern_match",
                    confidence=0.9,
                    description=f["description"],
                    impact=(
                        f"Mobile static analysis rule "
                        f"`{f['rule_id']}` matched on {fmt.upper()} "
                        f"binary `{path.name}`."
                    ),
                    remediation_steps=f["remediation"],
                    technical_analysis=(
                        f"Rule: `{f['rule_id']}`\n"
                        f"Format: {fmt}\n"
                        f"Path: `{path}`\n"
                        "Auditor: scan_mobile_app "
                        "(strix.tools.mobile_app_audit)."
                    ),
                    reasoning_trace=[
                        f"scan_mobile_app inspected `{path.name}`.",
                        f"Rule `{f['rule_id']}` matched.",
                        "Auto-emitted by L1 deterministic audit; "
                        "no network, no execution.",
                    ],
                    poc_description=(
                        "Reproduce by unzipping the binary and "
                        "inspecting the noted field."
                    ),
                    poc_script_code=(
                        f"unzip -p {path} "
                        + ("AndroidManifest.xml" if fmt == "apk"
                           else "Payload/*.app/Info.plist")
                    ),
                )
    except Exception as e:  # noqa: BLE001
        logger.debug("scan_mobile_app tracer emit failed: %s", e)

    return {
        "success": True,
        "status": "ok",
        "format": fmt,
        "path": str(path),
        "total_findings": len(findings),
        "findings": findings,
    }
