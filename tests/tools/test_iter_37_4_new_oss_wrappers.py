"""Tests for iter-37.4 — 5 new OSS-anchored wrappers.

Per docs/tool-catalog-rationalization.md §C, this iter adds:
  * `probe_default_creds_hydra` — hydra-backed credential brute-force
  * `scan_fuzz_ffuf`            — ffuf web fuzzer
  * `scan_api_schemathesis`     — OpenAPI property-based fuzzer
  * `scan_smuggling_smuggler`   — HTTP request smuggling detector
  * `scan_mobile_mobsfscan`     — mobile-app static analysis

(The 6th planned wrapper, `scan_saml_xsw`, was dropped — SAML Raider
is a Burp extension without a usable CLI, and the existing in-house
`strix/tools/specialist/scan_saml_xsw.py` already implements the
canonical 8 XSW variants.)

Each wrapper follows the sqlmap_runner pattern:
  * `subprocess.run` the OSS binary
  * Parse stdout/file output into the canonical finding dict shape
  * Return `{success, status, target, total_findings, findings}`
  * Graceful-degrade to `status="partial"` + descriptive `reason`
    when the binary isn't on PATH
  * Register with `@register_tool(sandbox_execution=True)`
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


_WRAPPER_REGISTRATIONS = [
    # (tool_name, env_var_to_disable, install_hint_fragment)
    (
        "probe_default_creds_hydra",
        "STRIX_HYDRA_DISABLED",
        "hydra",
    ),
    (
        "scan_fuzz_ffuf",
        "STRIX_FFUF_DISABLED",
        "ffuf",
    ),
    (
        "scan_api_schemathesis",
        "STRIX_SCHEMATHESIS_DISABLED",
        "schemathesis",
    ),
    (
        "scan_smuggling_smuggler",
        "STRIX_SMUGGLER_DISABLED",
        "smuggler",
    ),
    (
        "scan_mobile_mobsfscan",
        "STRIX_MOBSFSCAN_DISABLED",
        "mobsfscan",
    ),
]


# ---------------------------------------------------------------------------
# Registry + sandbox-routing contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name", [t[0] for t in _WRAPPER_REGISTRATIONS],
)
def test_wrapper_is_registered(tool_name: str) -> None:
    """Every iter-37.4 wrapper must be discoverable via the tool
    registry. Without this, `execute_tool` can't dispatch."""
    import strix.tools  # noqa: F401 — trigger decorators
    from strix.tools.registry import get_tool_names

    assert tool_name in get_tool_names(), (
        f"{tool_name} is not registered. Check that the runner "
        f"module is imported by `strix/tools/__init__.py`."
    )


@pytest.mark.parametrize(
    "tool_name", [t[0] for t in _WRAPPER_REGISTRATIONS],
)
def test_wrapper_routes_to_sandbox(tool_name: str) -> None:
    """Every OSS-anchored wrapper must execute inside the sandbox
    container per CLAUDE.md §3. Host-side execution would break the
    iter-35 sandbox-only invariant."""
    import strix.tools  # noqa: F401
    from strix.tools.executor import should_execute_in_sandbox

    assert should_execute_in_sandbox(tool_name), (
        f"{tool_name} must route to sandbox. The whole iter-37 "
        f"premise is OSS tools run in the sandbox container — "
        f"host-side execution leaks the target's network reach into "
        f"the host process (CLAUDE.md §3 violation)."
    )


# ---------------------------------------------------------------------------
# Graceful-degrade contract — missing binary → status=partial
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tool_name,env_var,install_hint", _WRAPPER_REGISTRATIONS,
)
def test_missing_binary_returns_partial(
    monkeypatch, tool_name: str, env_var: str, install_hint: str,
) -> None:
    """When the OSS binary isn't on PATH, the wrapper must return
    `status="partial"` with a `reason` mentioning the install hint —
    not raise. The env-var-disabled path forces this branch
    deterministically (no PATH dependency in CI)."""
    import strix.tools  # noqa: F401
    from strix.tools.registry import get_tool_by_name

    monkeypatch.setenv(env_var, "1")
    tool_func = get_tool_by_name(tool_name)
    assert tool_func is not None

    # Each wrapper takes a different kwarg shape — pass a minimal
    # valid target for each.
    if tool_name == "probe_default_creds_hydra":
        result = tool_func(target_url="http://example.com/login")
    elif tool_name == "scan_fuzz_ffuf":
        result = tool_func(target_url="http://example.com/FUZZ")
    elif tool_name == "scan_api_schemathesis":
        result = tool_func(schema_url="http://example.com/openapi.json")
    elif tool_name == "scan_smuggling_smuggler":
        result = tool_func(target_url="https://example.com/")
    elif tool_name == "scan_mobile_mobsfscan":
        # Need an existing path — use /tmp which always exists.
        result = tool_func(target_path="/tmp")
    else:
        pytest.skip(f"unhandled tool: {tool_name}")

    assert isinstance(result, dict)
    assert result.get("status") == "partial", (
        f"{tool_name}: expected status=partial when binary missing; "
        f"got {result.get('status')!r}. Full result: {result}"
    )
    assert result.get("success") is True, (
        f"{tool_name}: missing binary must not fail the scan — it's "
        f"a graceful coverage gap, not an error."
    )
    assert result.get("findings") == []
    assert install_hint in (result.get("reason") or "").lower(), (
        f"{tool_name}: reason should mention `{install_hint}` install "
        f"hint; got {result.get('reason')!r}"
    )


# ---------------------------------------------------------------------------
# Input-validation contract — invalid target → status=error
# ---------------------------------------------------------------------------


def test_hydra_rejects_empty_target() -> None:
    from strix.tools.hydra_runner.probe_default_creds_hydra import (
        probe_default_creds_hydra,
    )
    result = probe_default_creds_hydra(target_url="")
    assert result["success"] is False
    assert result["status"] == "error"
    assert "target_url required" in result["reason"]


def test_ffuf_rejects_empty_target() -> None:
    from strix.tools.ffuf_runner.scan_fuzz_ffuf import scan_fuzz_ffuf
    result = scan_fuzz_ffuf(target_url="")
    assert result["success"] is False
    assert result["status"] == "error"


def test_ffuf_rejects_target_without_fuzz_token_in_param_mode() -> None:
    """For param/vhost modes, the URL must carry the FUZZ token
    explicitly (auto-injection only fires for content_discovery)."""
    from strix.tools.ffuf_runner.scan_fuzz_ffuf import scan_fuzz_ffuf
    result = scan_fuzz_ffuf(
        target_url="http://example.com/api",
        mode="param_discovery",
    )
    assert result["success"] is False
    assert result["status"] == "error"
    assert "FUZZ" in result["reason"]


def test_schemathesis_rejects_empty_schema_url() -> None:
    from strix.tools.schemathesis_runner.scan_api_schemathesis import (
        scan_api_schemathesis,
    )
    result = scan_api_schemathesis(schema_url="")
    assert result["success"] is False
    assert result["status"] == "error"


def test_smuggler_rejects_empty_target() -> None:
    from strix.tools.smuggler_runner.scan_smuggling_smuggler import (
        scan_smuggling_smuggler,
    )
    result = scan_smuggling_smuggler(target_url="")
    assert result["success"] is False
    assert result["status"] == "error"


def test_mobsfscan_rejects_nonexistent_path() -> None:
    from strix.tools.mobsf_runner.scan_mobile_mobsfscan import (
        scan_mobile_mobsfscan,
    )
    result = scan_mobile_mobsfscan(
        target_path="/this/path/does/not/exist/12345",
    )
    assert result["success"] is False
    assert result["status"] == "error"
    assert "does not exist" in result["reason"]


# ---------------------------------------------------------------------------
# Parser unit tests — stdout/JSON → canonical finding shape
# ---------------------------------------------------------------------------


def test_hydra_parser_extracts_login_password():
    """hydra prints `[80][http-post-form] host: X login: Y password: Z`
    on each found credential."""
    from strix.tools.hydra_runner.probe_default_creds_hydra import (
        _parse_findings,
    )
    stdout = (
        "Hydra v9.4 (c) 2022 by van Hauser/THC\n"
        "[DATA] attacking http-post-form://target/login\n"
        "[80][http-post-form] host: example.com  "
        "login: admin  password: admin123\n"
        "1 of 1 target successfully completed, 1 valid password found\n"
    )
    findings = _parse_findings(stdout, "http://example.com/login")
    assert len(findings) == 1
    f = findings[0]
    assert f["credential_login"] == "admin"
    assert f["credential_password"] == "admin123"
    assert f["category"] == "auth"
    assert f["cwe"] == "CWE-521"
    assert f["severity"] == "high"


def test_smuggler_parser_extracts_technique_and_mutation():
    """smuggler.py prints `[+] Issue Found / Target: X / Technique: Y /
    Mutation: Z` on each detected vector."""
    from strix.tools.smuggler_runner.scan_smuggling_smuggler import (
        _parse_findings,
    )
    stdout = (
        "[+] Loading 35 mutations\n"
        "[+] Issue Found \n"
        "    Target: https://example.com:443/\n"
        "    Technique: cl.te\n"
        "    Mutation: nameprefix1\n"
        "    Payload: GET / HTTP/1.1\\r\\n\n"
    )
    findings = _parse_findings(stdout, "https://example.com/")
    assert len(findings) == 1
    f = findings[0]
    assert f["smuggler_technique"] == "cl.te"
    assert f["smuggler_mutation"] == "nameprefix1"
    assert f["cwe"] == "CWE-444"
    assert f["severity"] == "critical"


def test_ffuf_parser_emits_finding_for_interesting_status():
    """ffuf -o foo.json writes {results: [{input: {FUZZ: ...},
    status: ..., url: ..., length: ...}]}. Hits with status in the
    interesting set (200/201/301/302/401/403) become findings."""
    import json
    import tempfile
    from strix.tools.ffuf_runner.scan_fuzz_ffuf import _parse_findings

    with tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", suffix=".json", delete=False,
    ) as f:
        json.dump({
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "status": 200,
                    "url": "http://example.com/admin",
                    "length": 1234,
                    "words": 100,
                },
                {
                    "input": {"FUZZ": "uninteresting"},
                    "status": 999,  # filtered out
                    "url": "http://example.com/uninteresting",
                    "length": 0,
                    "words": 0,
                },
            ],
        }, f)
        json_path = f.name

    findings = _parse_findings(
        json_path, "http://example.com/", "content_discovery",
    )
    # Only the 200 admin hit is emitted; 999 is filtered.
    assert len(findings) == 1
    f0 = findings[0]
    assert f0["ffuf_input"] == "admin"
    assert f0["ffuf_status"] == 200
    # `admin` keyword + 200 → high severity per the category map.
    assert f0["severity"] == "high"


def test_mobsfscan_parser_extracts_rule_id_and_files():
    """mobsfscan --json output: {results: {<rule_id>: {metadata: {...},
    files: [{file_path, match_lines, match_string}]}}}."""
    import json
    import tempfile
    from strix.tools.mobsf_runner.scan_mobile_mobsfscan import _parse_findings

    with tempfile.NamedTemporaryFile(  # noqa: SIM115
        mode="w", suffix=".json", delete=False,
    ) as fh:
        json.dump({
            "results": {
                "android_hardcoded_api_key": {
                    "metadata": {
                        "severity": "ERROR",
                        "description": "Hardcoded API key detected",
                        "cwe": "CWE-798: Use of Hard-coded Credentials",
                        "owasp-mobile": "M5: Insufficient Cryptography",
                    },
                    "files": [{
                        "file_path": "/app/src/main/java/Constants.java",
                        "match_lines": [42, 42],
                        "match_string": (
                            "private static final String API_KEY = "
                            "\"sk_live_REDACTED\";"
                        ),
                    }],
                },
            },
        }, fh)
        json_path = fh.name

    findings = _parse_findings(json_path, "/app/src")
    assert len(findings) == 1
    f0 = findings[0]
    assert f0["cwe"].startswith("CWE-798")
    assert f0["severity"] == "high"
    assert f0["mobsfscan_rule_id"] == "android_hardcoded_api_key"
    assert f0["code_locations"][0]["file"].endswith("Constants.java")
    assert f0["code_locations"][0]["line"] == 42
