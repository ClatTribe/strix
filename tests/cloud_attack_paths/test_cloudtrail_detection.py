"""Tests for the CloudTrail-based CDR rule engine."""

from __future__ import annotations

import json
from datetime import datetime, time, timezone
from typing import Any

import pytest

from strix.cloud_attack_paths import cloudtrail_detection as cdr
from strix.cloud_attack_paths import tools as tools_module
from strix.cloud_attack_paths.cloudtrail_detection import (
    BUILTIN_RULES,
    CloudTrailFinding,
    _event_principal,
    _event_time,
    _is_after_hours,
    detect,
    load_events_from_file,
    summarise,
)
from strix.cloud_attack_paths.tools import scan_cloud_attack_paths


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------


def test_event_principal_extracts_arn() -> None:
    ev = {"userIdentity": {"arn": "arn:aws:iam::1:user/alice"}}
    assert _event_principal(ev) == "arn:aws:iam::1:user/alice"


def test_event_principal_root_synthesised() -> None:
    ev = {"userIdentity": {"type": "Root", "accountId": "1"}}
    assert _event_principal(ev) == "arn:aws:iam::1:root"


def test_event_principal_none_when_missing() -> None:
    assert _event_principal({}) is None


def test_event_time_parses_iso8601_z() -> None:
    ev = {"eventTime": "2026-01-15T03:00:00Z"}
    dt = _event_time(ev)
    assert dt is not None
    assert dt.tzinfo is not None


def test_event_time_returns_none_when_missing() -> None:
    assert _event_time({}) is None


def test_is_after_hours_outside_business_window() -> None:
    """3am UTC is outside 13:00-23:00 UTC."""
    dt = datetime(2026, 1, 15, 3, 0, tzinfo=timezone.utc)
    assert _is_after_hours(dt, business_hours=(time(13, 0), time(23, 0))) is True


def test_is_after_hours_inside_business_window() -> None:
    """4pm UTC is inside 13:00-23:00 UTC."""
    dt = datetime(2026, 1, 15, 16, 0, tzinfo=timezone.utc)
    assert _is_after_hours(dt, business_hours=(time(13, 0), time(23, 0))) is False


def test_is_after_hours_wrap_around_window() -> None:
    """22:00-06:00 wrap-around night-shift window."""
    night_window = (time(22, 0), time(6, 0))
    # 3am — inside night shift, so NOT after-hours under that
    # window (after_hours = outside window).
    assert _is_after_hours(
        datetime(2026, 1, 15, 3, 0, tzinfo=timezone.utc),
        business_hours=night_window,
    ) is False


# ---------------------------------------------------------------------------
# Rule: root account used
# ---------------------------------------------------------------------------


def test_root_account_event_fires_critical() -> None:
    events = [{
        "eventName": "PutBucketPolicy",
        "eventTime": "2026-01-15T03:00:00Z",
        "userIdentity": {"type": "Root", "accountId": "111"},
        "sourceIPAddress": "1.2.3.4",
        "awsRegion": "us-east-1",
    }]
    findings = detect(events, rules=["cdr_root_account_used"])
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].rule_id == "cdr_root_account_used"


def test_iam_user_event_does_not_fire_root_rule() -> None:
    events = [{
        "eventName": "PutBucketPolicy",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::1:user/alice",
        },
    }]
    assert detect(events, rules=["cdr_root_account_used"]) == []


# ---------------------------------------------------------------------------
# Rule: console login without MFA
# ---------------------------------------------------------------------------


def test_console_login_without_mfa_fires() -> None:
    events = [{
        "eventName": "ConsoleLogin",
        "eventTime": "2026-01-15T16:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/bob"},
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
        "sourceIPAddress": "1.2.3.4",
    }]
    findings = detect(events, rules=["cdr_console_login_without_mfa"])
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_console_login_with_mfa_does_not_fire() -> None:
    events = [{
        "eventName": "ConsoleLogin",
        "userIdentity": {"arn": "arn:aws:iam::1:user/bob"},
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "Yes"},
    }]
    assert detect(events, rules=["cdr_console_login_without_mfa"]) == []


def test_failed_console_login_does_not_fire() -> None:
    events = [{
        "eventName": "ConsoleLogin",
        "userIdentity": {"arn": "arn:aws:iam::1:user/bob"},
        "responseElements": {"ConsoleLogin": "Failure"},
        "additionalEventData": {"MFAUsed": "No"},
    }]
    assert detect(events, rules=["cdr_console_login_without_mfa"]) == []


# ---------------------------------------------------------------------------
# Rule: IAM change after hours
# ---------------------------------------------------------------------------


def test_after_hours_iam_change_fires() -> None:
    events = [{
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "eventTime": "2026-01-15T03:00:00Z",   # 3am UTC, after-hours
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
    }]
    findings = detect(events, rules=["cdr_iam_change_after_hours"])
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_business_hours_iam_change_does_not_fire() -> None:
    events = [{
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "eventTime": "2026-01-15T16:00:00Z",  # 4pm UTC, business hours
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
    }]
    assert detect(events, rules=["cdr_iam_change_after_hours"]) == []


def test_non_iam_event_does_not_fire_iam_change_rule() -> None:
    events = [{
        "eventName": "PutObject",
        "eventSource": "s3.amazonaws.com",
        "eventTime": "2026-01-15T03:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
    }]
    assert detect(events, rules=["cdr_iam_change_after_hours"]) == []


def test_iam_describe_event_does_not_fire_iam_change_rule() -> None:
    """Read-only IAM (Get / List / Describe) shouldn't fire even
    after-hours."""
    events = [{
        "eventName": "GetUser",
        "eventSource": "iam.amazonaws.com",
        "eventTime": "2026-01-15T03:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
    }]
    assert detect(events, rules=["cdr_iam_change_after_hours"]) == []


def test_custom_business_hours_override() -> None:
    """Operator in IST sets business_hours=(03:30, 13:30) UTC
    (9am-7pm IST). 16:00 UTC is now after-hours."""
    events = [{
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "eventTime": "2026-01-15T16:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
    }]
    findings = detect(
        events,
        rules=["cdr_iam_change_after_hours"],
        business_hours=(time(3, 30), time(13, 30)),
    )
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Rule: CloudTrail logging stopped
# ---------------------------------------------------------------------------


def test_stop_logging_fires() -> None:
    events = [{
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventTime": "2026-01-15T16:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/attacker"},
    }]
    findings = detect(events, rules=["cdr_cloudtrail_logging_stopped"])
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_non_stop_logging_event_does_not_fire() -> None:
    events = [{
        "eventName": "StartLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "userIdentity": {"arn": "arn:aws:iam::1:user/admin"},
    }]
    assert detect(events, rules=["cdr_cloudtrail_logging_stopped"]) == []


# ---------------------------------------------------------------------------
# Rule: bulk S3 GetObject
# ---------------------------------------------------------------------------


def _s3_get(arn: str, t: str) -> dict[str, Any]:
    return {
        "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com",
        "eventTime": t,
        "userIdentity": {"arn": arn},
        "sourceIPAddress": "1.2.3.4",
    }


def test_bulk_s3_get_threshold_crossed_fires() -> None:
    """5 calls within a 1m window with threshold=3 → fires."""
    arn = "arn:aws:iam::1:user/eve"
    events = [
        _s3_get(arn, f"2026-01-15T16:00:{i:02d}Z") for i in range(5)
    ]
    findings = detect(
        events,
        rules=["cdr_bulk_s3_get_in_window"],
        bulk_s3_threshold=3,
        bulk_s3_window_minutes=1,
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].event_count >= 3


def test_bulk_s3_below_threshold_does_not_fire() -> None:
    arn = "arn:aws:iam::1:user/eve"
    events = [
        _s3_get(arn, f"2026-01-15T16:00:{i:02d}Z") for i in range(2)
    ]
    findings = detect(
        events,
        rules=["cdr_bulk_s3_get_in_window"],
        bulk_s3_threshold=3,
        bulk_s3_window_minutes=1,
    )
    assert findings == []


def test_bulk_s3_outside_window_does_not_fire() -> None:
    """5 calls spread over 30 minutes with a 1-minute window →
    no window ever crosses the threshold."""
    arn = "arn:aws:iam::1:user/eve"
    events = [
        _s3_get(arn, f"2026-01-15T16:{i*6:02d}:00Z") for i in range(5)
    ]
    findings = detect(
        events,
        rules=["cdr_bulk_s3_get_in_window"],
        bulk_s3_threshold=3,
        bulk_s3_window_minutes=1,
    )
    assert findings == []


def test_bulk_s3_one_finding_per_principal() -> None:
    """Two principals each cross the threshold → two findings,
    not 10."""
    e1 = [_s3_get("arn:aws:iam::1:user/a", f"2026-01-15T16:00:{i:02d}Z")
          for i in range(5)]
    e2 = [_s3_get("arn:aws:iam::1:user/b", f"2026-01-15T16:00:{i:02d}Z")
          for i in range(5)]
    findings = detect(
        e1 + e2,
        rules=["cdr_bulk_s3_get_in_window"],
        bulk_s3_threshold=3,
        bulk_s3_window_minutes=1,
    )
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Rule: security group egress to world
# ---------------------------------------------------------------------------


def test_sg_egress_0_0_0_0_fires() -> None:
    events = [{
        "eventName": "AuthorizeSecurityGroupEgress",
        "eventSource": "ec2.amazonaws.com",
        "eventTime": "2026-01-15T16:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
        "requestParameters": {
            "ipPermissions": {
                "items": [{
                    "ipRanges": {
                        "items": [{"cidrIp": "0.0.0.0/0"}],
                    },
                }],
            },
        },
    }]
    findings = detect(events, rules=["cdr_security_group_egress_to_world"])
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_sg_egress_specific_cidr_does_not_fire() -> None:
    events = [{
        "eventName": "AuthorizeSecurityGroupEgress",
        "eventSource": "ec2.amazonaws.com",
        "requestParameters": {
            "ipPermissions": {
                "items": [{
                    "ipRanges": {
                        "items": [{"cidrIp": "10.0.0.0/16"}],
                    },
                }],
            },
        },
    }]
    assert detect(events, rules=["cdr_security_group_egress_to_world"]) == []


# ---------------------------------------------------------------------------
# detect — registry hygiene + sorting
# ---------------------------------------------------------------------------


def test_detect_default_runs_all_rules() -> None:
    """`rules=None` runs every built-in rule."""
    events = [{
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
    }, {
        "eventName": "ConsoleLogin",
        "userIdentity": {"arn": "arn:aws:iam::1:user/bob"},
        "responseElements": {"ConsoleLogin": "Success"},
        "additionalEventData": {"MFAUsed": "No"},
    }]
    findings = detect(events)
    assert len(findings) == 2


def test_detect_sorts_critical_first() -> None:
    events = [
        # medium
        {
            "eventName": "AuthorizeSecurityGroupEgress",
            "eventSource": "ec2.amazonaws.com",
            "requestParameters": {
                "ipPermissions": {
                    "items": [{"ipRanges":
                              {"items": [{"cidrIp": "0.0.0.0/0"}]}}],
                },
            },
        },
        # critical
        {
            "eventName": "StopLogging",
            "eventSource": "cloudtrail.amazonaws.com",
            "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
        },
    ]
    findings = detect(events)
    assert findings[0].severity == "critical"
    assert findings[-1].severity == "medium"


def test_rule_count_at_least_six() -> None:
    assert len(BUILTIN_RULES) >= 6


def test_detect_handles_empty_events() -> None:
    assert detect([]) == []


def test_failing_rule_does_not_crash_run(monkeypatch) -> None:
    """Rule exceptions are caught + logged; rest of rules still
    run. Pin so a buggy contributor rule doesn't blank the
    output."""

    def _broken(events, **_):
        raise RuntimeError("synthetic")

    BUILTIN_RULES["cdr_test_broken"] = _broken
    try:
        events = [{
            "eventName": "StopLogging",
            "eventSource": "cloudtrail.amazonaws.com",
            "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
        }]
        findings = detect(events)
        assert any(
            f.rule_id == "cdr_cloudtrail_logging_stopped"
            for f in findings
        )
    finally:
        BUILTIN_RULES.pop("cdr_test_broken", None)


# ---------------------------------------------------------------------------
# load_events_from_file
# ---------------------------------------------------------------------------


def test_load_events_from_jsonlines_file(tmp_path) -> None:
    p = tmp_path / "events.jsonl"
    p.write_text(
        json.dumps({"eventName": "GetUser", "userIdentity": {}}) + "\n" +
        json.dumps({"eventName": "PutUser", "userIdentity": {}}) + "\n",
    )
    events = load_events_from_file(p)
    assert len(events) == 2


def test_load_events_from_bundle_file(tmp_path) -> None:
    """`{"Records": [...]}` format — AWS's canonical CloudTrail
    export shape."""
    p = tmp_path / "events.json"
    p.write_text(json.dumps({
        "Records": [
            {"eventName": "GetUser", "userIdentity": {}},
            {"eventName": "PutUser", "userIdentity": {}},
        ],
    }))
    events = load_events_from_file(p)
    assert len(events) == 2


def test_load_events_missing_file_returns_empty(tmp_path) -> None:
    assert load_events_from_file(tmp_path / "missing.json") == []


def test_load_events_malformed_returns_empty(tmp_path) -> None:
    p = tmp_path / "events.json"
    p.write_text("not json at all")
    # Malformed JSON-lines: each line tried independently; all
    # fail → empty.
    assert load_events_from_file(p) == []


# ---------------------------------------------------------------------------
# CspmFinding adaptation
# ---------------------------------------------------------------------------


def test_to_cspm_finding_carries_canonical_shape() -> None:
    cf = CloudTrailFinding(
        rule_id="cdr_root_account_used",
        severity="critical",
        message="root used",
        narrative="root activity",
        principal="arn:aws:iam::1:root",
        event_name="PutBucketPolicy",
        event_time="2026-01-15T03:00:00Z",
        source_ip="1.2.3.4",
        aws_region="us-east-1",
        account_id="1",
        evidence_events=[{"eventName": "PutBucketPolicy"}],
        mitre_techniques=["T1078.004"],
    )
    cspm = cf.to_cspm_finding()
    assert cspm.rule_id == "cdr_root_account_used"
    assert cspm.severity == "critical"
    assert cspm.category == "cdr_detection"
    assert cspm.cwe == "CWE-778"
    assert cspm.resource_arn == "arn:aws:iam::1:root"
    assert cspm.metadata["event_name"] == "PutBucketPolicy"
    assert cspm.metadata["mitre_techniques"] == ["T1078.004"]


# ---------------------------------------------------------------------------
# summarise
# ---------------------------------------------------------------------------


def test_summarise_counts_severities_and_rules() -> None:
    findings = [
        CloudTrailFinding(
            rule_id="cdr_root_account_used",
            severity="critical",
            message="m", narrative="n",
        ),
        CloudTrailFinding(
            rule_id="cdr_iam_change_after_hours",
            severity="high",
            message="m", narrative="n",
        ),
    ]
    s = summarise(findings)
    assert s["total_findings"] == 2
    assert s["severity_breakdown"]["critical"] == 1
    assert s["severity_breakdown"]["high"] == 1
    assert s["per_rule"]["cdr_root_account_used"] == 1


# ---------------------------------------------------------------------------
# Specialist integration
# ---------------------------------------------------------------------------


class _StubAwsReport:
    findings: list = []
    errors: list = []
    account_id = "1"
    regions_scanned = ["us-east-1"]
    findings_by_service = {}


def test_specialist_threads_cloudtrail_events(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    events = [{
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventTime": "2026-01-15T16:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
    }]

    result = scan_cloud_attack_paths(
        provider="aws",
        cloudtrail_events=events,
        auto_discover_assets=False,
    )
    assert result["status"] == "ok"
    assert "cdr_summary" in result["tool_metadata"]
    summary = result["tool_metadata"]["cdr_summary"]
    assert summary["total_findings"] == 1
    assert summary["severity_breakdown"]["critical"] == 1


def test_specialist_loads_cloudtrail_events_from_path(
    monkeypatch, tmp_path,
) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    p = tmp_path / "events.jsonl"
    p.write_text(json.dumps({
        "eventName": "StopLogging",
        "eventSource": "cloudtrail.amazonaws.com",
        "eventTime": "2026-01-15T16:00:00Z",
        "userIdentity": {"arn": "arn:aws:iam::1:user/eve"},
    }) + "\n")

    result = scan_cloud_attack_paths(
        provider="aws",
        cloudtrail_events_path=str(p),
        auto_discover_assets=False,
    )
    assert "cdr_summary" in result["tool_metadata"]
    assert result["tool_metadata"]["cdr_summary"]["total_findings"] == 1


def test_specialist_no_cdr_kwargs_keeps_legacy(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: False)
    monkeypatch.setattr(tools_module, "scan_aws_account",
                        lambda **_: _StubAwsReport())

    result = scan_cloud_attack_paths(
        provider="aws", auto_discover_assets=False,
    )
    assert "cdr_summary" not in result["tool_metadata"]


def test_specialist_cdr_only_runs_on_aws(monkeypatch) -> None:
    monkeypatch.setattr(tools_module, "is_prowler_available",
                        lambda: True)
    from strix.cspm.prowler import ProwlerScanResult
    monkeypatch.setattr(
        tools_module, "run_prowler",
        lambda **_: ProwlerScanResult(provider="azure", findings=[]),
    )

    result = scan_cloud_attack_paths(
        provider="azure",
        cloudtrail_events=[{"eventName": "StopLogging"}],
        auto_discover_assets=False,
    )
    assert "cdr_summary" not in result["tool_metadata"]
