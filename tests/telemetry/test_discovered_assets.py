"""Tests for engine-wishlist §4 `assets.discovered.jsonl` emission.

Hermetic — pure dataclass + dict transformations + a single
filesystem write to tmp_path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from strix.telemetry.discovered_assets import (
    DiscoveredAsset,
    _KIND_TO_TARGET_TYPE,
    emit_discovered_assets,
    from_cloud_asset,
    from_cloud_assets,
)


# ---------------------------------------------------------------------------
# DiscoveredAsset dataclass — validation
# ---------------------------------------------------------------------------


def test_dataclass_rejects_unknown_type() -> None:
    with pytest.raises(ValueError, match="type="):
        DiscoveredAsset(
            type="nope-not-a-real-type",
            canonical_id="x",
            display_name="x",
            discovered_by="test",
        )


def test_dataclass_rejects_unknown_confidence() -> None:
    with pytest.raises(ValueError, match="confidence="):
        DiscoveredAsset(
            type="web_application",
            canonical_id="x",
            display_name="x",
            discovered_by="test",
            confidence="ultra-high",
        )


def test_dataclass_to_dict_round_trip() -> None:
    a = DiscoveredAsset(
        type="web_application",
        canonical_id="aws:111/alb/x",
        display_name="x (us-east-1)",
        discovered_by="cspm.aws.elbv2",
        attributes={"is_public": True, "tags": ["prod"]},
        suggested_config={"scan_mode": "standard"},
        confidence="high",
    )
    d = a.to_dict()
    assert d["type"] == "web_application"
    assert d["canonical_id"] == "aws:111/alb/x"
    assert d["confidence"] == "high"
    assert d["attributes"]["is_public"] is True


# ---------------------------------------------------------------------------
# from_cloud_asset — kind → target_type mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,expected_type",
    [
        ("s3_bucket", "cloud_account"),
        ("elbv2", "web_application"),
        ("api_gateway", "api"),
        ("lambda_function_url", "api"),
        ("ec2_instance", "ip_address"),
        ("ecr_repository", "container_registry"),
        ("azure_storage_account", "cloud_account"),
        ("azure_app_service", "web_application"),
        ("azure_function_app", "api"),
        ("azure_container_registry", "container_registry"),
        ("gcs_bucket", "cloud_account"),
        ("gcp_cloud_function", "api"),
        ("gcp_cloud_run_service", "api"),
        ("gcp_artifact_repository", "container_registry"),
    ],
)
def test_kind_maps_to_expected_target_type(kind, expected_type) -> None:
    asset = {"kind": kind, "arn": "arn:aws:test:::x/name", "name": "x"}
    result = from_cloud_asset(asset, discovered_by="test")
    assert result is not None
    assert result.type == expected_type


def test_unknown_kind_defaults_to_cloud_account() -> None:
    """Unknown kinds shouldn't break emission — default to
    `cloud_account` (the bulk catch-all wrapper-side)."""
    asset = {"kind": "future_unknown_kind", "arn": "arn:aws:x:::y/z"}
    result = from_cloud_asset(asset, discovered_by="test")
    assert result is not None
    assert result.type == "cloud_account"


def test_asset_without_kind_or_arn_is_dropped() -> None:
    assert from_cloud_asset({"name": "no-id"}, discovered_by="test") is None


# ---------------------------------------------------------------------------
# Confidence ladder
# ---------------------------------------------------------------------------


def test_public_asset_is_high_confidence() -> None:
    asset = {
        "kind": "s3_bucket",
        "arn": "arn:aws:s3:::public-bucket",
        "name": "public-bucket",
        "is_public": True,
    }
    result = from_cloud_asset(asset, discovered_by="test")
    assert result.confidence == "high"
    # `suggested_config.scan_frequency` derives from confidence.
    assert result.suggested_config["scan_frequency"] == "daily"


def test_named_with_region_is_medium_confidence() -> None:
    asset = {
        "kind": "s3_bucket",
        "arn": "arn:aws:s3:::priv",
        "name": "priv",
        "region": "us-east-1",
        "is_public": False,
    }
    result = from_cloud_asset(asset, discovered_by="test")
    assert result.confidence == "medium"
    assert result.suggested_config["scan_frequency"] == "weekly"


def test_bare_arn_only_is_low_confidence() -> None:
    asset = {"kind": "iam_role", "arn": "arn:aws:iam::111:role/r"}
    result = from_cloud_asset(asset, discovered_by="test")
    assert result.confidence == "low"
    assert result.suggested_config["scan_frequency"] == "monthly"


# ---------------------------------------------------------------------------
# canonical_id encoding
# ---------------------------------------------------------------------------


def test_aws_canonical_id_encodes_account_service() -> None:
    asset = {
        "kind": "s3_bucket",
        "arn": "arn:aws:s3:::my-bucket",
        "name": "my-bucket",
    }
    result = from_cloud_asset(asset, discovered_by="test")
    # account is empty for global-service ARNs, but service + name encode.
    assert result.canonical_id.startswith("aws:")
    assert "s3" in result.canonical_id
    assert "my-bucket" in result.canonical_id


def test_aws_canonical_id_includes_account() -> None:
    asset = {
        "kind": "iam_role",
        "arn": "arn:aws:iam::123456789012:role/admin",
    }
    result = from_cloud_asset(asset, discovered_by="test")
    assert "123456789012" in result.canonical_id
    assert "iam" in result.canonical_id


def test_gcp_canonical_id_prefixed() -> None:
    asset = {
        "kind": "gcs_bucket",
        "arn": "//storage.googleapis.com/projects/_/buckets/x",
        "name": "x",
    }
    result = from_cloud_asset(asset, discovered_by="test")
    assert result.canonical_id.startswith("gcp:")


def test_azure_canonical_id_prefixed() -> None:
    asset = {
        "kind": "azure_storage_account",
        "arn": "/subscriptions/sub-x/storage/sa1",
        "name": "sa1",
    }
    result = from_cloud_asset(asset, discovered_by="test")
    assert result.canonical_id.startswith("azure:")


# ---------------------------------------------------------------------------
# Attribute pass-through + drop list
# ---------------------------------------------------------------------------


def test_engine_internal_keys_stripped_from_attributes() -> None:
    """The wrapper's reader doesn't want engine-internal `kind` /
    `arn` — they're encoded into `type` / `canonical_id`
    respectively."""
    asset = {
        "kind": "s3_bucket",
        "arn": "arn:aws:s3:::x",
        "name": "x",
        "is_public": True,
        "tags": ["prod"],
        "discovered_via": "s3:ListBuckets",
    }
    result = from_cloud_asset(asset, discovered_by="test")
    assert "kind" not in result.attributes
    assert "arn" not in result.attributes
    assert "discovered_via" not in result.attributes
    # Provenance preserved as a private key (the wrapper can
    # render it without surfacing the underscore).
    assert result.attributes["_engine_discovered_via"] == "s3:ListBuckets"
    assert result.attributes["is_public"] is True
    assert result.attributes["tags"] == ["prod"]


# ---------------------------------------------------------------------------
# Bulk converter
# ---------------------------------------------------------------------------


def test_from_cloud_assets_drops_invalid_silently() -> None:
    assets = [
        {"kind": "s3_bucket", "arn": "arn:aws:s3:::x", "name": "x"},
        {"name": "no-id"},  # dropped
        {"kind": "elbv2", "arn": "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/y/abc", "name": "y"},
    ]
    out = from_cloud_assets(assets, discovered_by="test")
    assert len(out) == 2


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def test_emit_writes_one_object_per_line(tmp_path) -> None:
    assets = [
        DiscoveredAsset(
            type="web_application",
            canonical_id="aws:1/alb/a",
            display_name="a",
            discovered_by="test",
        ),
        DiscoveredAsset(
            type="api",
            canonical_id="aws:1/lambda/b",
            display_name="b",
            discovered_by="test",
        ),
    ]
    out = emit_discovered_assets(tmp_path, assets)
    assert out == tmp_path / "assets.discovered.jsonl"
    lines = out.read_text().strip().split("\n")
    assert len(lines) == 2
    for line in lines:
        obj = json.loads(line)
        assert "type" in obj
        assert "canonical_id" in obj


def test_emit_skips_when_no_assets(tmp_path) -> None:
    """Per the wishlist contract — empty list emits nothing
    (no zero-byte file forced)."""
    out = emit_discovered_assets(tmp_path, [])
    assert out is None
    assert not (tmp_path / "assets.discovered.jsonl").exists()


# ---------------------------------------------------------------------------
# Wrapper-schema compatibility — sanity check the row shape
# ---------------------------------------------------------------------------


def test_emitted_row_has_required_wrapper_fields(tmp_path) -> None:
    """The wrapper's `DiscoveredAsset` type has six required keys;
    every row we emit must have all six."""
    required = {
        "type", "canonical_id", "display_name",
        "attributes", "suggested_config", "confidence",
        "discovered_by",
    }
    asset = {
        "kind": "s3_bucket",
        "arn": "arn:aws:s3:::test",
        "name": "test",
        "is_public": False,
        "region": "us-east-1",
    }
    discovered = from_cloud_asset(asset, discovered_by="cspm.aws.s3")
    emit_discovered_assets(tmp_path, [discovered])
    lines = (tmp_path / "assets.discovered.jsonl").read_text().strip().split("\n")
    row = json.loads(lines[0])
    assert required.issubset(row.keys())
