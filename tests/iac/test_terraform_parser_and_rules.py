"""Tests for Terraform parser + rule set (Phase 11.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.iac.parsers.base import PLATFORM_TERRAFORM
from strix.iac.parsers.terraform import (
    _extract_balanced_body,
    _parse_terraform,
    parse_terraform,
)
from strix.iac.rules import run_rules
from strix.iac.rules.terraform_rules import (
    tf_aws_ebs_no_encryption,
    tf_aws_iam_wildcard_policy,
    tf_aws_rds_no_encryption,
    tf_aws_s3_no_versioning,
    tf_aws_s3_public_acl,
    tf_aws_sg_open_ingress,
    tf_hardcoded_secret,
)


def _tmp_tf(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "test.tf"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_parser_extracts_resource_blocks() -> None:
    blocks = _parse_terraform("""
resource "aws_s3_bucket" "data" {
  bucket = "x"
}

resource "aws_db_instance" "db" {
  engine = "postgres"
}
""")
    assert len(blocks) == 2
    assert blocks[0]["type"] == "resource"
    assert blocks[0]["label1"] == "aws_s3_bucket"
    assert blocks[0]["label2"] == "data"
    assert blocks[1]["label1"] == "aws_db_instance"


def test_parser_handles_nested_braces() -> None:
    """Nested braces in a body must not confuse the block extractor."""
    blocks = _parse_terraform("""
resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port   = 22
  }
  egress {
    from_port = 0
  }
}
""")
    assert len(blocks) == 1
    assert "ingress" in blocks[0]["body"]
    assert "egress" in blocks[0]["body"]


def test_parser_handles_strings_with_braces() -> None:
    """Braces inside string literals (heredocs / JSON policies) must
    not perturb the balanced-brace walker."""
    blocks = _parse_terraform("""
resource "aws_iam_role_policy" "x" {
  policy = "{\\"Statement\\": [{\\"Action\\": \\"*\\"}]}"
}
""")
    assert len(blocks) == 1
    assert "Statement" in blocks[0]["body"]


def test_parser_skips_blocks_without_braces() -> None:
    """A keyword without an opening brace is not a block — skip."""
    blocks = _parse_terraform("""
# comment
provider
""")
    assert blocks == []


def test_parser_captures_provider_module_variable() -> None:
    blocks = _parse_terraform("""
provider "aws" { region = "us-east-1" }
variable "env" { default = "prod" }
module "vpc" { source = "./vpc" }
""")
    types = [b["type"] for b in blocks]
    assert types == ["provider", "variable", "module"]


def test_extract_balanced_body_simple() -> None:
    text = "x { a b } y"
    body, end = _extract_balanced_body(text, 2)
    assert body == " a b "
    assert text[end - 1] == "}"


def test_extract_balanced_body_nested() -> None:
    text = "x { { y } } z"
    body, _ = _extract_balanced_body(text, 2)
    assert body == " { y } "


def test_parse_terraform_returns_iacfile(tmp_path: Path) -> None:
    p = _tmp_tf(tmp_path, 'resource "aws_s3_bucket" "x" { bucket = "y" }')
    iac = parse_terraform(p)
    assert iac is not None
    assert iac.platform == PLATFORM_TERRAFORM
    assert len(iac.data) == 1


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def test_s3_public_acl_detected(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_s3_bucket" "data" {
  bucket = "x"
  acl    = "public-read"
}
"""))
    out = tf_aws_s3_public_acl(iac)
    assert len(out) == 1
    assert out[0].rule_id == "TF_AWS_S3_PUBLIC_ACL"
    assert out[0].severity == "high"


def test_s3_private_acl_not_flagged(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_s3_bucket" "data" {
  bucket = "x"
  acl    = "private"
}
"""))
    assert tf_aws_s3_public_acl(iac) == []


def test_sg_open_ssh_ingress_critical(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""))
    out = tf_aws_sg_open_ingress(iac)
    assert len(out) == 1
    assert out[0].severity == "critical"
    assert "SSH" in out[0].message


def test_sg_open_https_is_high_not_critical(tmp_path: Path) -> None:
    """443 to the world is normal for public services — high but
    not critical."""
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""))
    out = tf_aws_sg_open_ingress(iac)
    assert len(out) == 1
    assert out[0].severity == "high"


def test_sg_restricted_cidr_not_flagged(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["10.0.0.0/16"]
  }
}
"""))
    assert tf_aws_sg_open_ingress(iac) == []


def test_rds_unencrypted_detected(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_db_instance" "db" {
  engine = "postgres"
}
"""))
    out = tf_aws_rds_no_encryption(iac)
    assert len(out) == 1
    assert out[0].cwe == "CWE-311"


def test_rds_encrypted_not_flagged(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_db_instance" "db" {
  engine             = "postgres"
  storage_encrypted = true
}
"""))
    assert tf_aws_rds_no_encryption(iac) == []


def test_ebs_unencrypted_detected(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_ebs_volume" "data" {
  size = 100
}
"""))
    out = tf_aws_ebs_no_encryption(iac)
    assert len(out) == 1


def test_iam_wildcard_action_detected(tmp_path: Path) -> None:
    """Real-world Terraform uses heredoc for inline JSON policies —
    that's the shape rules need to match."""
    iac = parse_terraform(_tmp_tf(tmp_path, '''
resource "aws_iam_role_policy" "admin" {
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "x"}]
}
EOF
}
'''))
    out = tf_aws_iam_wildcard_policy(iac)
    assert len(out) == 1
    assert "Action" in out[0].message


def test_iam_specific_policy_not_flagged(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, '''
resource "aws_iam_role_policy" "admin" {
  policy = <<EOF
{
  "Statement": [{"Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*"}]
}
EOF
}
'''))
    assert tf_aws_iam_wildcard_policy(iac) == []


def test_hardcoded_aws_key_detected(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
variable "key" {
  default = "AKIAEXAMPLE12345678X"
}
"""))
    out = tf_hardcoded_secret(iac)
    assert len(out) == 1
    assert out[0].severity == "critical"
    assert out[0].cwe == "CWE-798"


def test_s3_no_versioning_detected(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_s3_bucket" "data" {
  bucket = "x"
}
"""))
    out = tf_aws_s3_no_versioning(iac)
    assert len(out) == 1


def test_s3_versioning_enabled_not_flagged(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_s3_bucket" "data" {
  bucket = "x"
  versioning {
    enabled = true
  }
}
"""))
    assert tf_aws_s3_no_versioning(iac) == []


# ---------------------------------------------------------------------------
# End-to-end via run_rules
# ---------------------------------------------------------------------------


def test_run_rules_dispatches_to_terraform_rules(tmp_path: Path) -> None:
    iac = parse_terraform(_tmp_tf(tmp_path, """
resource "aws_s3_bucket" "data" {
  bucket = "x"
  acl    = "public-read"
}
"""))
    findings = run_rules(iac)
    # Public ACL + missing versioning both fire.
    assert any(f.rule_id == "TF_AWS_S3_PUBLIC_ACL" for f in findings)
    assert any(f.rule_id == "TF_AWS_S3_NO_VERSIONING" for f in findings)
    for f in findings:
        assert f.platform == PLATFORM_TERRAFORM
