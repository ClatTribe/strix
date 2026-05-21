"""Tests for iter-21.5 — `scan_mobile_app` deterministic mobile
static analysis (APK / IPA).

We build synthetic APK/IPA fixtures via Python's zipfile so the
test suite is hermetic (no real binaries in-tree). The fixtures
ship text-form AndroidManifest.xml / Info.plist, which works
with our parser; real APKs have binary AXML manifests that
require apktool decoding — that's a runtime concern, not a
unit-test one.
"""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from strix.tools.mobile_app_audit.scan_mobile_app import (
    _audit_android_manifest,
    _audit_ios_info_plist,
    _audit_strings_xml,
    _detect_format,
    scan_mobile_app,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


def _build_apk(
    tmp_path: Path,
    *,
    manifest: str | None = None,
    strings: str | None = None,
    name: str = "test.apk",
) -> Path:
    """Build a minimal APK at `tmp_path / name` containing the
    provided manifest + strings.xml."""
    apk_path = tmp_path / name
    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as z:
        if manifest is not None:
            z.writestr("AndroidManifest.xml", manifest)
        if strings is not None:
            z.writestr("res/values/strings.xml", strings)
    return apk_path


def _build_ipa(
    tmp_path: Path,
    *,
    plist: dict | None = None,
    name: str = "test.ipa",
) -> Path:
    """Build a minimal IPA at `tmp_path / name` containing the
    provided Info.plist."""
    ipa_path = tmp_path / name
    with zipfile.ZipFile(ipa_path, "w", zipfile.ZIP_DEFLATED) as z:
        if plist is not None:
            z.writestr(
                "Payload/Test.app/Info.plist",
                plistlib.dumps(plist),
            )
        else:
            # Marker file so _detect_format sees it as an IPA.
            z.writestr("Payload/Test.app/.gitkeep", "")
    return ipa_path


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def test_detect_apk_by_extension(tmp_path: Path) -> None:
    p = _build_apk(tmp_path, manifest="<manifest/>")
    assert _detect_format(p) == "apk"


def test_detect_ipa_by_extension(tmp_path: Path) -> None:
    p = _build_ipa(tmp_path, plist={"CFBundleIdentifier": "com.x"})
    assert _detect_format(p) == "ipa"


def test_detect_apk_by_content_when_extension_missing(
    tmp_path: Path,
) -> None:
    """Strip the .apk extension; content-sniff should still classify."""
    p = _build_apk(tmp_path, manifest="<manifest/>", name="apk-no-ext")
    assert _detect_format(p) == "apk"


def test_detect_unknown_returns_none(tmp_path: Path) -> None:
    p = tmp_path / "blank.txt"
    p.write_text("not a zip")
    assert _detect_format(p) is None


# ---------------------------------------------------------------------------
# Android manifest rules
# ---------------------------------------------------------------------------


_MANIFEST_DEBUGGABLE = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:debuggable="true"/>
</manifest>"""


_MANIFEST_ALLOWBACKUP = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="true"/>
</manifest>"""


_MANIFEST_CLEARTEXT = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:usesCleartextTraffic="true"/>
</manifest>"""


_MANIFEST_EXPORTED_NO_PERM = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <activity android:name=".SignInActivity" android:exported="true"/>
  </application>
</manifest>"""


_MANIFEST_EXPORTED_WITH_PERM = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <activity android:name=".SignInActivity" android:exported="true"
              android:permission="com.x.PERM"/>
  </application>
</manifest>"""


_MANIFEST_DANGEROUS_PERM = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.READ_SMS"/>
  <application/>
</manifest>"""


_MANIFEST_OLD_SDK = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:minSdkVersion="19"/>
  <application/>
</manifest>"""


_MANIFEST_HEALTHY = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:minSdkVersion="28"/>
  <application android:allowBackup="false">
    <activity android:name=".SafeActivity" android:exported="false"/>
  </application>
</manifest>"""


def test_debuggable_emits_high() -> None:
    findings = _audit_android_manifest(_MANIFEST_DEBUGGABLE)
    assert "android-debuggable" in _rule_ids(findings)
    f = next(x for x in findings if x["rule_id"] == "android-debuggable")
    assert f["severity"] == "high"
    assert f["cwe"] == "CWE-489"


def test_allow_backup_emits_medium() -> None:
    findings = _audit_android_manifest(_MANIFEST_ALLOWBACKUP)
    assert "android-allow-backup" in _rule_ids(findings)


def test_cleartext_traffic_emits_high() -> None:
    findings = _audit_android_manifest(_MANIFEST_CLEARTEXT)
    assert "android-cleartext-traffic" in _rule_ids(findings)


def test_exported_no_permission_emits_high() -> None:
    findings = _audit_android_manifest(_MANIFEST_EXPORTED_NO_PERM)
    assert "android-exported-component-no-permission" in _rule_ids(findings)


def test_exported_with_permission_no_finding() -> None:
    findings = _audit_android_manifest(_MANIFEST_EXPORTED_WITH_PERM)
    assert "android-exported-component-no-permission" not in _rule_ids(findings)


def test_dangerous_permission_emits_info() -> None:
    findings = _audit_android_manifest(_MANIFEST_DANGEROUS_PERM)
    assert "android-dangerous-permission" in _rule_ids(findings)
    f = next(x for x in findings if x["rule_id"] == "android-dangerous-permission")
    assert f["severity"] == "info"


def test_old_min_sdk_emits_low() -> None:
    findings = _audit_android_manifest(_MANIFEST_OLD_SDK)
    assert "android-old-min-sdk" in _rule_ids(findings)


def test_healthy_manifest_emits_no_findings() -> None:
    findings = _audit_android_manifest(_MANIFEST_HEALTHY)
    assert findings == []


def test_garbage_manifest_doesnt_raise() -> None:
    """Defence-in-depth: malformed XML must not crash the auditor."""
    findings = _audit_android_manifest("<not-valid-xml")
    assert findings == []


# ---------------------------------------------------------------------------
# strings.xml secret scan
# ---------------------------------------------------------------------------


_STRINGS_WITH_AWS = """<resources>
  <string name="api_key">AKIAIOSFODNN7EXAMPLE</string>
  <string name="app_name">Test</string>
</resources>"""


_STRINGS_WITH_GOOGLE = """<resources>
  <string name="gmaps_key">AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI</string>
</resources>"""


_STRINGS_CLEAN = """<resources>
  <string name="app_name">Test</string>
  <string name="welcome">Welcome to Test</string>
</resources>"""


def test_strings_aws_key_emits_finding() -> None:
    findings = _audit_strings_xml(_STRINGS_WITH_AWS)
    assert "android-secret-in-resources" in _rule_ids(findings)
    f = findings[0]
    assert "aws_access_key_id" in f["title"]
    assert f["severity"] == "high"


def test_strings_google_key_emits_finding() -> None:
    findings = _audit_strings_xml(_STRINGS_WITH_GOOGLE)
    assert "android-secret-in-resources" in _rule_ids(findings)


def test_strings_clean_no_findings() -> None:
    assert _audit_strings_xml(_STRINGS_CLEAN) == []


def test_strings_garbage_doesnt_raise() -> None:
    assert _audit_strings_xml("<not xml") == []


# ---------------------------------------------------------------------------
# iOS Info.plist rules
# ---------------------------------------------------------------------------


def test_ats_disabled_emits_high() -> None:
    plist = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    findings = _audit_ios_info_plist(plist)
    assert "ios-ats-disabled" in _rule_ids(findings)


def test_ats_per_domain_http_emits_medium() -> None:
    plist = {
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {
                "internal-api.example.com": {
                    "NSExceptionAllowsInsecureHTTPLoads": True,
                },
            },
        },
    }
    findings = _audit_ios_info_plist(plist)
    assert "ios-ats-allow-http" in _rule_ids(findings)


def test_ats_strict_no_finding() -> None:
    plist = {
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {
                "x.example.com": {
                    "NSExceptionRequiresForwardSecrecy": True,
                },
            },
        },
    }
    findings = _audit_ios_info_plist(plist)
    assert "ios-ats-disabled" not in _rule_ids(findings)
    assert "ios-ats-allow-http" not in _rule_ids(findings)


def test_url_scheme_no_filter_emits_medium() -> None:
    plist = {
        "CFBundleURLTypes": [
            {"CFBundleURLSchemes": ["myapp"]},
        ],
        # NO LSApplicationQueriesSchemes
    }
    findings = _audit_ios_info_plist(plist)
    assert "ios-url-scheme-no-filter" in _rule_ids(findings)


def test_url_scheme_with_filter_no_finding() -> None:
    plist = {
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}],
        "LSApplicationQueriesSchemes": ["mail", "tel"],
    }
    findings = _audit_ios_info_plist(plist)
    assert "ios-url-scheme-no-filter" not in _rule_ids(findings)


def test_plist_aws_secret_in_nested_dict() -> None:
    plist = {
        "FirebaseConfig": {
            "API_KEY": "AKIAIOSFODNN7EXAMPLE",
        },
    }
    findings = _audit_ios_info_plist(plist)
    assert "ios-secret-in-plist" in _rule_ids(findings)


def test_plist_clean_no_secret_finding() -> None:
    plist = {
        "CFBundleIdentifier": "com.example.test",
        "CFBundleVersion": "1.0",
    }
    findings = _audit_ios_info_plist(plist)
    assert "ios-secret-in-plist" not in _rule_ids(findings)


# ---------------------------------------------------------------------------
# scan_mobile_app — end-to-end
# ---------------------------------------------------------------------------


def test_scan_apk_end_to_end(tmp_path: Path) -> None:
    apk = _build_apk(
        tmp_path,
        manifest=_MANIFEST_DEBUGGABLE,
        strings=_STRINGS_WITH_GOOGLE,
    )
    result = scan_mobile_app(str(apk))
    assert result["success"] is True
    assert result["status"] == "ok"
    assert result["format"] == "apk"
    rids = _rule_ids(result["findings"])
    assert "android-debuggable" in rids
    assert "android-secret-in-resources" in rids


def test_scan_ipa_end_to_end(tmp_path: Path) -> None:
    ipa = _build_ipa(
        tmp_path,
        plist={"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}},
    )
    result = scan_mobile_app(str(ipa))
    assert result["success"] is True
    assert result["status"] == "ok"
    assert result["format"] == "ipa"
    assert "ios-ats-disabled" in _rule_ids(result["findings"])


def test_scan_missing_file_returns_error() -> None:
    result = scan_mobile_app("/nonexistent/path.apk")
    assert result["success"] is False
    assert result["status"] == "error"
    assert "not found" in (result.get("reason") or "")


def test_scan_unknown_format_returns_partial(tmp_path: Path) -> None:
    p = tmp_path / "not-a-mobile.txt"
    p.write_text("hello")
    result = scan_mobile_app(str(p))
    assert result["success"] is True
    assert result["status"] == "partial"
    assert result["format"] is None


def test_scan_apk_with_clean_manifest_returns_zero_findings(
    tmp_path: Path,
) -> None:
    apk = _build_apk(
        tmp_path,
        manifest=_MANIFEST_HEALTHY,
        strings=_STRINGS_CLEAN,
    )
    result = scan_mobile_app(str(apk))
    assert result["success"] is True
    assert result["total_findings"] == 0


def test_scan_corrupted_apk_returns_error(tmp_path: Path) -> None:
    p = tmp_path / "corrupted.apk"
    p.write_bytes(b"not a real zip")
    result = scan_mobile_app(str(p))
    # _detect_format returns None on bad zip -> partial
    assert result["status"] in ("partial", "error")


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def test_scan_mobile_app_registered() -> None:
    import strix.tools  # noqa: F401  side-effect imports
    from strix.tools.registry import get_tool_by_name, get_tool_names

    assert "scan_mobile_app" in get_tool_names()
    fn = get_tool_by_name("scan_mobile_app")
    assert callable(fn)


def test_mobile_app_asset_type_not_wired_yet() -> None:
    """iter-21.5 followup: `mobile_app` asset_type was added to
    the anchor prepass dict but the rest of the strix pipeline
    (CLI, preflight, target detection, runner) doesn't recognize
    it — the anchor would never have fired. We removed the dead
    entry; this test pins that it stays removed until the
    upstream plumbing exists, so a future eager refactor doesn't
    re-introduce dead code.

    When the full pipeline lands (CLI flag, preflight, fixture,
    routing), DELETE this test and re-add the asset_type
    `mobile_app` entry pointing at a single-tool `_ANCHORS_MOBILE`
    list — the tool itself stays callable by agents in the
    meantime.
    """
    from strix.agents.lead_agent.anchor_prepass import (
        _ANCHORS_BY_TARGET_TYPE,
    )
    assert "mobile_app" not in _ANCHORS_BY_TARGET_TYPE
