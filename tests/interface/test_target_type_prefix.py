"""Tests for the `<type>:<value>` target-type prefix on `--target`.

PR #267 added the `api` target type to the lead-agent tool catalog
but the CLI inference only ever produced `web_application` for
URL-shaped values. The prefix syntax lets wrappers (webappsec/)
disambiguate without relying on Strix's URL-shape heuristics.

The contract:
  * Allowed prefixes: web_application, api, repository, local_code,
    ip_address (same set as `_TOOLS_BY_TARGET_TYPE`).
  * `api:` is deterministic — bypasses the git-repo HTTP probe so
    classification doesn't depend on network reachability.
  * Other prefixes are strict — they're honoured iff inference
    on the inner value yields a matching type; otherwise error.
  * Empty value (`api:`) is rejected.
  * Bare URLs without a prefix continue to classify exactly as
    before (no behaviour change for existing callers).
"""

from __future__ import annotations

import pytest

from strix.interface.utils import infer_target_type


# ---------------------------------------------------------------------------
# api: — the motivating case
# ---------------------------------------------------------------------------


def test_api_prefix_https_url() -> None:
    target_type, details = infer_target_type("api:https://api.example.com")
    assert target_type == "api"
    assert details == {"target_url": "https://api.example.com"}


def test_api_prefix_http_url() -> None:
    target_type, details = infer_target_type("api:http://internal-api.example.com:8080")
    assert target_type == "api"
    assert details == {"target_url": "http://internal-api.example.com:8080"}


def test_api_prefix_bare_host_coerced_to_https() -> None:
    target_type, details = infer_target_type("api:api.example.com")
    assert target_type == "api"
    assert details == {"target_url": "https://api.example.com"}


def test_api_prefix_bare_host_with_path() -> None:
    target_type, details = infer_target_type("api:example.com/v1")
    assert target_type == "api"
    assert details == {"target_url": "https://example.com/v1"}


def test_api_prefix_url_with_path_and_query() -> None:
    target_type, details = infer_target_type("api:https://api.example.com/v2?tenant=foo")
    assert target_type == "api"
    assert details["target_url"] == "https://api.example.com/v2?tenant=foo"


def test_api_prefix_rejects_local_path(tmp_path) -> None:
    with pytest.raises(ValueError) as exc:
        infer_target_type(f"api:{tmp_path}")
    assert "URL-shaped" in str(exc.value)


def test_api_prefix_rejects_empty_value() -> None:
    with pytest.raises(ValueError) as exc:
        infer_target_type("api:")
    assert "requires a target value" in str(exc.value)


def test_api_prefix_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        infer_target_type("api:not a url")


def test_api_prefix_does_not_probe_git_url() -> None:
    """`api:https://github.com/owner/repo` would normally trigger
    the `_is_http_git_repo` HTTP probe and could classify as
    `repository`. The api branch bypasses that probe so the
    classification is deterministic and offline-safe."""
    target_type, details = infer_target_type("api:https://github.com/owner/repo")
    assert target_type == "api"
    assert details == {"target_url": "https://github.com/owner/repo"}


def test_api_prefix_case_insensitive() -> None:
    target_type, details = infer_target_type("API:https://api.example.com")
    assert target_type == "api"
    assert details["target_url"] == "https://api.example.com"


# ---------------------------------------------------------------------------
# Other prefixes — strict inference match
# ---------------------------------------------------------------------------


def test_web_application_prefix_url() -> None:
    target_type, details = infer_target_type("web_application:https://example.com")
    assert target_type == "web_application"
    assert details == {"target_url": "https://example.com"}


def test_web_application_prefix_rejects_path(tmp_path) -> None:
    with pytest.raises(ValueError) as exc:
        infer_target_type(f"web_application:{tmp_path}")
    assert "web_application" in str(exc.value)


def test_local_code_prefix_existing_dir(tmp_path) -> None:
    target_type, details = infer_target_type(f"local_code:{tmp_path}")
    assert target_type == "local_code"
    assert details["target_path"] == str(tmp_path.resolve())


def test_local_code_prefix_rejects_url() -> None:
    with pytest.raises(ValueError) as exc:
        infer_target_type("local_code:https://example.com")
    assert "local_code" in str(exc.value)
    assert "web_application" in str(exc.value)


def test_ip_address_prefix_ipv4() -> None:
    target_type, details = infer_target_type("ip_address:192.168.1.10")
    assert target_type == "ip_address"
    assert details["target_ip"] == "192.168.1.10"


def test_ip_address_prefix_rejects_url() -> None:
    with pytest.raises(ValueError):
        infer_target_type("ip_address:https://example.com")


def test_repository_prefix_git_ssh() -> None:
    target_type, details = infer_target_type("repository:git@github.com:owner/repo.git")
    assert target_type == "repository"
    assert details["target_repo"] == "git@github.com:owner/repo.git"


def test_repository_prefix_dot_git_url() -> None:
    target_type, details = infer_target_type("repository:https://github.com/owner/repo.git")
    assert target_type == "repository"
    assert details["target_repo"] == "https://github.com/owner/repo.git"


# ---------------------------------------------------------------------------
# No prefix — backwards-compatibility: bare inputs classify exactly as before
# ---------------------------------------------------------------------------


def test_no_prefix_url_is_web_application() -> None:
    target_type, details = infer_target_type("https://example.com")
    assert target_type == "web_application"


def test_no_prefix_ip_is_ip_address() -> None:
    target_type, details = infer_target_type("10.0.0.1")
    assert target_type == "ip_address"


def test_no_prefix_git_ssh_is_repository() -> None:
    target_type, details = infer_target_type("git@github.com:foo/bar.git")
    assert target_type == "repository"


# ---------------------------------------------------------------------------
# Disambiguation — values that contain `:` but no allowlisted prefix
# ---------------------------------------------------------------------------


def test_url_scheme_not_mistaken_for_prefix() -> None:
    """`https://...` partitions to ("https", ":", "//...") — `https` is
    not in the allowlist so the whole string falls through to inference."""
    target_type, details = infer_target_type("https://example.com:8080/path")
    assert target_type == "web_application"
    assert details["target_url"] == "https://example.com:8080/path"


def test_git_ssh_path_not_mistaken_for_prefix() -> None:
    """`git@github.com:org/repo` partitions to
    ("git@github.com", ":", "org/repo") — `git@github.com` is not in
    the allowlist so the bare-input repository path triggers."""
    target_type, details = infer_target_type("git@github.com:org/repo")
    assert target_type == "repository"


def test_unknown_prefix_left_alone() -> None:
    """A leading token that looks like `foo:` but isn't in the
    allowlist must NOT be treated as a prefix. The whole string
    passes to the heuristic inference path unmodified. The
    bareword-domain heuristic accepts `domain:example.com` as
    a (malformed) bare host — what matters here is that the
    `domain:` segment wasn't stripped."""
    target_type, details = infer_target_type("domain:example.com")
    assert target_type == "web_application"
    # The prefix was NOT stripped — the inferred URL still contains it.
    assert "domain:example.com" in details["target_url"]


# ---------------------------------------------------------------------------
# Integration — downstream-shape sanity
# ---------------------------------------------------------------------------


def test_api_prefix_dict_uses_target_url_key() -> None:
    """The StrixAgent dispatch reads `target_url` for both
    `web_application` and `api` (see
    strix/agents/StrixAgent/strix_agent.py). The api prefix MUST
    emit `target_url` as the canonical key."""
    _, details = infer_target_type("api:https://api.example.com")
    assert "target_url" in details
    assert "target_repo" not in details
    assert "target_path" not in details
    assert "target_ip" not in details
