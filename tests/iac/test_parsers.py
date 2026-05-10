"""Unit tests for IaC parsers — Phase 11."""

from __future__ import annotations

from pathlib import Path

import pytest

# Side-effect import registers parsers.
import strix.iac.parsers  # noqa: F401
from strix.iac.parsers.base import (
    PLATFORM_CLOUDFLARE,
    PLATFORM_DOCKER,
    PLATFORM_DOCKER_COMPOSE,
    PLATFORM_NETLIFY,
    PLATFORM_VERCEL,
    find_iac_files,
    parse_iac_file,
)
from strix.iac.parsers.docker import _parse_dockerfile_lines


# ---------------------------------------------------------------------------
# Vercel
# ---------------------------------------------------------------------------


def test_parse_vercel_basic(tmp_path: Path) -> None:
    f = tmp_path / "vercel.json"
    f.write_text(
        '{"headers": [{"source": "/(.*)", '
        '"headers": [{"key": "X-Frame-Options", "value": "DENY"}]}]}',
    )
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.platform == PLATFORM_VERCEL
    assert iac.data["headers"][0]["source"] == "/(.*)"


def test_parse_vercel_invalid_json_returns_parse_error(tmp_path: Path) -> None:
    f = tmp_path / "vercel.json"
    f.write_text("{not json")
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.parse_error is not None
    assert iac.data == {}


def test_parse_vercel_list_top_level_marks_error(tmp_path: Path) -> None:
    """Older / wrong format — vercel.json should be an object,
    not an array. Surface as parse_error."""
    f = tmp_path / "vercel.json"
    f.write_text("[]")
    iac = parse_iac_file(f)
    assert iac.parse_error == "vercel.json should be a JSON object"


# ---------------------------------------------------------------------------
# Netlify
# ---------------------------------------------------------------------------


def test_parse_netlify_basic(tmp_path: Path) -> None:
    f = tmp_path / "netlify.toml"
    f.write_text(
        '[build]\n'
        '  command = "npm run build"\n'
        '\n'
        '[[redirects]]\n'
        '  from = "/old"\n'
        '  to = "/new"\n'
        '  status = 301\n'
    )
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.platform == PLATFORM_NETLIFY
    assert iac.data["build"]["command"] == "npm run build"
    assert len(iac.data["redirects"]) == 1


def test_parse_netlify_invalid_toml_returns_parse_error(tmp_path: Path) -> None:
    f = tmp_path / "netlify.toml"
    f.write_text("[build\nbroken")
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.parse_error is not None


# ---------------------------------------------------------------------------
# Cloudflare wrangler
# ---------------------------------------------------------------------------


def test_parse_wrangler_basic(tmp_path: Path) -> None:
    f = tmp_path / "wrangler.toml"
    f.write_text(
        'name = "my-worker"\n'
        'main = "src/index.ts"\n'
        '\n'
        '[vars]\n'
        'API_BASE = "https://api.example.com"\n'
        '\n'
        '[[r2_buckets]]\n'
        'binding = "MY_BUCKET"\n'
        'bucket_name = "prod-uploads"\n'
    )
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.platform == PLATFORM_CLOUDFLARE
    assert iac.data["name"] == "my-worker"
    assert iac.data["vars"]["API_BASE"] == "https://api.example.com"


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------


def test_parse_dockerfile_directives() -> None:
    text = (
        "FROM node:18-alpine\n"
        "USER 1001:1001\n"
        "RUN apk add --no-cache curl\n"
        "EXPOSE 3000\n"
        'CMD ["node", "app.js"]\n'
    )
    out = _parse_dockerfile_lines(text)
    directives = [d["directive"] for d in out]
    assert directives == ["FROM", "USER", "RUN", "EXPOSE", "CMD"]
    # Lines are 1-based.
    assert out[0]["line"] == 1
    assert out[4]["line"] == 5
    # USER args preserved.
    assert out[1]["args"] == "1001:1001"


def test_parse_dockerfile_handles_continuations() -> None:
    """A `RUN` with trailing `\\` should join the continuation."""
    text = (
        "RUN apt-get update && \\\n"
        "    apt-get install -y curl\n"
    )
    out = _parse_dockerfile_lines(text)
    assert len(out) == 1
    assert out[0]["directive"] == "RUN"
    assert "curl" in out[0]["args"]


def test_parse_dockerfile_skips_comments() -> None:
    text = (
        "# this is a comment\n"
        "FROM node:18\n"
        "# another comment\n"
        "USER 1001\n"
    )
    out = _parse_dockerfile_lines(text)
    directives = [d["directive"] for d in out]
    assert directives == ["FROM", "USER"]


def test_parse_dockerfile_via_dispatch(tmp_path: Path) -> None:
    f = tmp_path / "Dockerfile"
    f.write_text("FROM alpine\nUSER 1001\n")
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.platform == PLATFORM_DOCKER
    assert isinstance(iac.data, list)


def test_parse_dockerfile_dev_variant(tmp_path: Path) -> None:
    """`Dockerfile.dev` should match the pattern-based registration."""
    f = tmp_path / "Dockerfile.dev"
    f.write_text("FROM alpine\n")
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.platform == PLATFORM_DOCKER


# ---------------------------------------------------------------------------
# docker-compose
# ---------------------------------------------------------------------------


def test_parse_docker_compose_basic(tmp_path: Path) -> None:
    f = tmp_path / "docker-compose.yml"
    f.write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "    ports:\n"
        "      - '80:80'\n"
    )
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.platform == PLATFORM_DOCKER_COMPOSE
    assert "web" in iac.data["services"]


def test_parse_docker_compose_yaml_variant(tmp_path: Path) -> None:
    """Both `.yml` and `.yaml` and `compose.yml` should be picked up."""
    f = tmp_path / "compose.yaml"
    f.write_text("services: {web: {image: nginx}}\n")
    iac = parse_iac_file(f)
    assert iac is not None
    assert iac.platform == PLATFORM_DOCKER_COMPOSE


# ---------------------------------------------------------------------------
# find_iac_files
# ---------------------------------------------------------------------------


def test_find_iac_files_walks_repo(tmp_path: Path) -> None:
    (tmp_path / "vercel.json").write_text("{}")
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    sub = tmp_path / "infra"
    sub.mkdir()
    (sub / "docker-compose.yml").write_text("services: {}")
    out = {p.name for p in find_iac_files(tmp_path)}
    assert "vercel.json" in out
    assert "Dockerfile" in out
    assert "docker-compose.yml" in out


def test_find_iac_files_skips_node_modules(tmp_path: Path) -> None:
    (tmp_path / "vercel.json").write_text("{}")
    nm = tmp_path / "node_modules" / "x"
    nm.mkdir(parents=True)
    (nm / "vercel.json").write_text("{}")
    out = list(find_iac_files(tmp_path))
    # Only the root vercel.json — the node_modules one is skipped.
    assert len(out) == 1


def test_find_iac_files_caps_at_max() -> None:
    # Cap should bound work; smoke-test with a small max.
    out = find_iac_files("/tmp/this-doesnt-exist", max_files=10)
    assert out == []
