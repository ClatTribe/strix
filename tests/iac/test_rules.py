"""Unit tests for IaC rules across all platforms — Phase 11."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Side-effect imports to register parsers + rules.
import strix.iac.parsers  # noqa: F401
import strix.iac.rules  # noqa: F401
from strix.iac.parsers.base import (
    PLATFORM_CLOUDFLARE,
    PLATFORM_DOCKER,
    PLATFORM_DOCKER_COMPOSE,
    PLATFORM_NETLIFY,
    PLATFORM_VERCEL,
    IacFile,
)
from strix.iac.rules import run_rules


# ---------------------------------------------------------------------------
# Vercel rules
# ---------------------------------------------------------------------------


def _vercel(data: dict, *, raw: str = "") -> IacFile:
    return IacFile(
        platform=PLATFORM_VERCEL, path="/vercel.json",
        data=data, raw_text=raw or json.dumps(data, indent=2),
    )


def test_vercel_cors_wildcard_with_credentials_fires() -> None:
    iac = _vercel({
        "headers": [{
            "source": "/api/(.*)",
            "headers": [
                {"key": "Access-Control-Allow-Origin", "value": "*"},
                {"key": "Access-Control-Allow-Credentials", "value": "true"},
            ],
        }],
    })
    findings = run_rules(iac)
    rule_ids = {f.rule_id for f in findings}
    assert "vercel-cors-wildcard-with-credentials" in rule_ids


def test_vercel_cors_wildcard_without_credentials_clean() -> None:
    """`*` origin alone is not a finding — only the combo with
    credentials is flagged."""
    iac = _vercel({
        "headers": [{
            "source": "/api/(.*)",
            "headers": [
                {"key": "Access-Control-Allow-Origin", "value": "*"},
            ],
        }],
    })
    findings = run_rules(iac)
    cors_hits = [f for f in findings
                 if f.rule_id == "vercel-cors-wildcard-with-credentials"]
    assert cors_hits == []


def test_vercel_redirect_external_host_fires() -> None:
    iac = _vercel({
        "redirects": [{"source": "/go/:url", "destination": "https://:url"}],
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "vercel-redirect-external-host" for f in findings)


def test_vercel_cron_no_auth_marker_fires() -> None:
    iac = _vercel({
        "crons": [{"path": "/api/jobs/cleanup", "schedule": "0 0 * * *"}],
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "vercel-cron-no-auth-marker" for f in findings)


def test_vercel_env_hardcoded_secret_fires() -> None:
    iac = _vercel({
        "env": {"OPENAI_API_KEY": "sk-deadbeefDEADBEEF1234567890abcdef"},
    })
    findings = run_rules(iac)
    secret_hits = [f for f in findings
                   if f.rule_id == "vercel-env-hardcoded-secret"]
    assert len(secret_hits) == 1
    assert secret_hits[0].severity == "critical"


def test_vercel_env_non_secret_value_doesnt_fire() -> None:
    iac = _vercel({"env": {"NODE_ENV": "production"}})
    findings = run_rules(iac)
    assert not any(f.rule_id == "vercel-env-hardcoded-secret"
                   for f in findings)


def test_vercel_function_max_duration_fires() -> None:
    iac = _vercel({
        "functions": {"api/long-job.js": {"maxDuration": 600}},
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "vercel-function-overly-large-max-duration"
               for f in findings)


def test_vercel_function_safe_max_duration_doesnt_fire() -> None:
    iac = _vercel({
        "functions": {"api/normal.js": {"maxDuration": 60}},
    })
    findings = run_rules(iac)
    assert not any(f.rule_id == "vercel-function-overly-large-max-duration"
                   for f in findings)


# ---------------------------------------------------------------------------
# Netlify rules
# ---------------------------------------------------------------------------


def _netlify(data: dict, *, raw: str = "") -> IacFile:
    return IacFile(
        platform=PLATFORM_NETLIFY, path="/netlify.toml",
        data=data, raw_text=raw,
    )


def test_netlify_redirect_external_wildcard_fires() -> None:
    iac = _netlify({
        "redirects": [{"from": "/go/*", "to": "https://example.com/:splat"}],
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "netlify-redirect-external-wildcard"
               for f in findings)


def test_netlify_build_env_hardcoded_secret_fires() -> None:
    iac = _netlify({
        "build": {"environment": {
            "AWS_KEY": "AKIAIOSFODNN7EXAMPLE",
        }},
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "netlify-build-env-hardcoded-secret"
               for f in findings)


def test_netlify_csp_unsafe_inline_fires() -> None:
    iac = _netlify({
        "headers": [{
            "for": "/*",
            "values": {
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            },
        }],
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "netlify-csp-unsafe-inline-or-eval"
               for f in findings)


def test_netlify_cors_wildcard_with_credentials_fires() -> None:
    iac = _netlify({
        "headers": [{
            "for": "/api/*",
            "values": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        }],
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "netlify-cors-wildcard-with-credentials"
               for f in findings)


# ---------------------------------------------------------------------------
# Cloudflare rules
# ---------------------------------------------------------------------------


def _cloudflare(data: dict, *, raw: str = "") -> IacFile:
    return IacFile(
        platform=PLATFORM_CLOUDFLARE, path="/wrangler.toml",
        data=data, raw_text=raw,
    )


def test_cloudflare_vars_hardcoded_secret_fires() -> None:
    iac = _cloudflare({
        "vars": {"OPENAI_KEY": "sk-deadbeefdeadbeefdeadbeefdeadbeef"},
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "cloudflare-vars-hardcoded-secret"
               for f in findings)


def test_cloudflare_r2_public_binding_fires() -> None:
    iac = _cloudflare({
        "r2_buckets": [{"binding": "PUBLIC_ASSETS",
                         "bucket_name": "my-public-cdn"}],
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "cloudflare-r2-public-binding"
               for f in findings)


def test_cloudflare_r2_normal_binding_doesnt_fire() -> None:
    iac = _cloudflare({
        "r2_buckets": [{"binding": "USER_AVATARS", "bucket_name": "uploads"}],
    })
    findings = run_rules(iac)
    assert not any(f.rule_id == "cloudflare-r2-public-binding"
                   for f in findings)


def test_cloudflare_route_global_wildcard_fires_high() -> None:
    iac = _cloudflare({"routes": ["*/*"]})
    findings = run_rules(iac)
    hits = [f for f in findings
            if f.rule_id == "cloudflare-route-overly-broad"]
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_cloudflare_kv_no_preview_id_fires() -> None:
    iac = _cloudflare({
        "kv_namespaces": [{"binding": "CACHE", "id": "abc123"}],
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "cloudflare-kv-no-preview-id"
               for f in findings)


def test_cloudflare_kv_with_preview_id_doesnt_fire() -> None:
    iac = _cloudflare({
        "kv_namespaces": [{"binding": "CACHE", "id": "abc",
                            "preview_id": "def"}],
    })
    findings = run_rules(iac)
    assert not any(f.rule_id == "cloudflare-kv-no-preview-id"
                   for f in findings)


# ---------------------------------------------------------------------------
# Dockerfile rules
# ---------------------------------------------------------------------------


def _dockerfile(directives: list[dict], *, raw: str = "") -> IacFile:
    return IacFile(
        platform=PLATFORM_DOCKER, path="/Dockerfile",
        data=directives, raw_text=raw,
    )


def test_dockerfile_no_user_directive_fires() -> None:
    iac = _dockerfile([
        {"directive": "FROM", "args": "node:18-alpine", "line": 1},
        {"directive": "RUN", "args": "npm install", "line": 2},
    ])
    findings = run_rules(iac)
    assert any(f.rule_id == "dockerfile-no-user-directive"
               for f in findings)


def test_dockerfile_with_user_directive_doesnt_fire() -> None:
    iac = _dockerfile([
        {"directive": "FROM", "args": "node:18-alpine", "line": 1},
        {"directive": "USER", "args": "1001", "line": 2},
    ])
    findings = run_rules(iac)
    assert not any(f.rule_id == "dockerfile-no-user-directive"
                   for f in findings)


def test_dockerfile_user_root_fires() -> None:
    iac = _dockerfile([
        {"directive": "USER", "args": "root", "line": 5},
    ])
    findings = run_rules(iac)
    hits = [f for f in findings if f.rule_id == "dockerfile-user-root"]
    assert len(hits) == 1
    assert hits[0].line == 5


def test_dockerfile_latest_tag_fires_for_no_tag() -> None:
    iac = _dockerfile([
        {"directive": "FROM", "args": "alpine", "line": 1},
    ])
    findings = run_rules(iac)
    assert any(f.rule_id == "dockerfile-latest-tag" for f in findings)


def test_dockerfile_latest_tag_explicit_fires() -> None:
    iac = _dockerfile([
        {"directive": "FROM", "args": "node:latest", "line": 1},
    ])
    findings = run_rules(iac)
    assert any(f.rule_id == "dockerfile-latest-tag" for f in findings)


def test_dockerfile_pinned_version_doesnt_fire() -> None:
    iac = _dockerfile([
        {"directive": "FROM", "args": "node:18.19.0-alpine", "line": 1},
    ])
    findings = run_rules(iac)
    assert not any(f.rule_id == "dockerfile-latest-tag" for f in findings)


def test_dockerfile_digest_pinned_doesnt_fire() -> None:
    iac = _dockerfile([
        {"directive": "FROM",
         "args": "node@sha256:abc123def456", "line": 1},
    ])
    findings = run_rules(iac)
    assert not any(f.rule_id == "dockerfile-latest-tag" for f in findings)


def test_dockerfile_env_hardcoded_secret_fires() -> None:
    iac = _dockerfile([
        {"directive": "ENV",
         "args": "OPENAI_KEY=sk-deadbeefDEADBEEF1234567890abcdef",
         "line": 3},
    ])
    findings = run_rules(iac)
    hits = [f for f in findings
            if f.rule_id == "dockerfile-env-hardcoded-secret"]
    assert len(hits) == 1
    assert hits[0].severity == "critical"


def test_dockerfile_add_from_url_fires() -> None:
    iac = _dockerfile([
        {"directive": "ADD",
         "args": "https://example.com/install.sh /tmp/install.sh",
         "line": 4},
    ])
    findings = run_rules(iac)
    assert any(f.rule_id == "dockerfile-add-from-url" for f in findings)


def test_dockerfile_add_local_file_doesnt_fire() -> None:
    iac = _dockerfile([
        {"directive": "ADD", "args": "./local.tar.gz /opt/", "line": 4},
    ])
    findings = run_rules(iac)
    assert not any(f.rule_id == "dockerfile-add-from-url" for f in findings)


# ---------------------------------------------------------------------------
# docker-compose rules
# ---------------------------------------------------------------------------


def _compose(data: dict, *, raw: str = "") -> IacFile:
    return IacFile(
        platform=PLATFORM_DOCKER_COMPOSE, path="/docker-compose.yml",
        data=data, raw_text=raw,
    )


def test_compose_privileged_container_fires() -> None:
    iac = _compose({
        "services": {"db": {"image": "postgres", "privileged": True}},
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "compose-privileged-container" for f in findings)


def test_compose_host_network_mode_fires() -> None:
    iac = _compose({
        "services": {"app": {"image": "x", "network_mode": "host"}},
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "compose-host-network-mode" for f in findings)


def test_compose_docker_socket_mount_fires() -> None:
    iac = _compose({
        "services": {"watchtower": {
            "image": "containrrr/watchtower",
            "volumes": ["/var/run/docker.sock:/var/run/docker.sock"],
        }},
    })
    findings = run_rules(iac)
    hits = [f for f in findings
            if f.rule_id == "compose-docker-socket-mount"]
    assert len(hits) == 1
    assert hits[0].severity == "critical"


def test_compose_db_port_exposed_fires_for_postgres() -> None:
    iac = _compose({
        "services": {"db": {"image": "postgres",
                              "ports": ["5432:5432"]}},
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "compose-db-port-exposed" for f in findings)


def test_compose_db_port_exposed_fires_for_mysql() -> None:
    iac = _compose({
        "services": {"mysql": {"image": "mysql:8",
                                 "ports": ["3306:3306"]}},
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "compose-db-port-exposed" for f in findings)


def test_compose_app_port_doesnt_fire() -> None:
    """Port 80 / 3000 / 8080 — normal app ports — should NOT fire
    the DB-port rule."""
    iac = _compose({
        "services": {"web": {"image": "nginx", "ports": ["80:80"]}},
    })
    findings = run_rules(iac)
    assert not any(f.rule_id == "compose-db-port-exposed" for f in findings)


def test_compose_environment_hardcoded_secret_dict_form_fires() -> None:
    iac = _compose({
        "services": {"app": {
            "image": "x",
            "environment": {
                "OPENAI_KEY": "sk-deadbeefDEADBEEF1234567890abcdef",
            },
        }},
    })
    findings = run_rules(iac)
    hits = [f for f in findings
            if f.rule_id == "compose-environment-hardcoded-secret"]
    assert len(hits) == 1
    assert hits[0].severity == "critical"


def test_compose_environment_hardcoded_secret_list_form_fires() -> None:
    """`environment:` can be a list of `KEY=value` strings too."""
    iac = _compose({
        "services": {"app": {
            "image": "x",
            "environment": [
                "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
            ],
        }},
    })
    findings = run_rules(iac)
    assert any(f.rule_id == "compose-environment-hardcoded-secret"
               for f in findings)


def test_compose_environment_no_secret_doesnt_fire() -> None:
    iac = _compose({
        "services": {"app": {
            "image": "x",
            "environment": {"NODE_ENV": "production"},
        }},
    })
    findings = run_rules(iac)
    assert not any(f.rule_id == "compose-environment-hardcoded-secret"
                   for f in findings)
