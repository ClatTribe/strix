"""Tests for `strix/llm/fp_filter.py` — the deterministic FP
pre-filter (workflow phase 6, step 1 of the v2 cost-optimization
plan).

Discipline:
  * Each rule has a positive test (rule fires on canonical noise)
    AND a negative test (rule does NOT fire on a legitimate
    finding shape).
  * The aggregate `evaluate()` is tested for DROP-wins-over-
    DOWNGRADE and DOWNGRADE-takes-the-lowest-severity semantics.
  * The kill switch (`STRIX_FP_FILTER_DISABLED=1`) must
    short-circuit every rule.
  * No test depends on the LLM dedupe path — that's covered in
    `tests/llm/test_dedupe*.py`.

Recall-safety contract: if any of these tests starts failing
because a *real* must_find finding shape now matches a DROP
rule, the rule is broken and reverts — DO NOT loosen the test
to make the rule pass.
"""

from __future__ import annotations

import pytest

from strix.llm import fp_filter as fp


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("STRIX_FP_FILTER_DISABLED", raising=False)


# Canonical *good* finding — should ALLOW from every rule. Reused
# as the base for negative tests; each negative test mutates only
# the fields relevant to its rule.
def _good_finding() -> dict:
    return {
        "title": "SQL injection on POST /api/login username field",
        "description": "Unauthenticated SQLi via the username field allows arbitrary database read.",
        "impact": "Full database read; user credential dump.",
        "target": "https://vampi.local/api/login",
        "endpoint": "/api/login",
        "method": "POST",
        "technical_analysis": "Union-based SQLi; payload reflected in response with data from sqlite_master.",
        "poc_description": "Send POST with username=' UNION SELECT 1,2,3-- and observe response.",
        "poc_script_code": (
            "curl -X POST https://vampi.local/api/login "
            "-d 'username=admin\\' UNION SELECT 1,2,3-- &password=x'"
        ),
        "cwe": "CWE-89",
    }


# ---------------------------------------------------------------------------
# R1 — empty PoC
# ---------------------------------------------------------------------------


def test_R1_empty_poc_fires_when_poc_missing() -> None:
    f = _good_finding()
    f["poc_script_code"] = ""
    r = fp.rule_empty_poc(f)
    assert r.verdict == "DROP"
    assert r.rule == "R1_empty_poc"


def test_R1_empty_poc_fires_on_whitespace_only() -> None:
    f = _good_finding()
    f["poc_script_code"] = "   \n  "
    r = fp.rule_empty_poc(f)
    assert r.verdict == "DROP"


def test_R1_empty_poc_allows_real_poc() -> None:
    r = fp.rule_empty_poc(_good_finding())
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# R2 — speculation title + trivial PoC
# ---------------------------------------------------------------------------


def test_R2_speculation_with_trivial_poc_fires() -> None:
    f = _good_finding()
    f["title"] = "Potential SSRF on webhook handler"
    f["poc_script_code"] = "curl /webhook"
    r = fp.rule_speculation_title(f)
    assert r.verdict == "DROP"


def test_R2_speculation_with_real_poc_allows() -> None:
    """A hedging title but a substantial PoC means the agent
    confirmed it after writing the title — let it through."""
    f = _good_finding()
    f["title"] = "Potential SSRF on webhook handler"
    # PoC is real (the _good_finding default has a 60+ char PoC)
    r = fp.rule_speculation_title(f)
    assert r.verdict == "ALLOW"


def test_R2_concrete_title_with_short_poc_allows() -> None:
    """No hedging language — rule should not fire even if the
    PoC happens to be short. Trivial-PoC alone is R1's job."""
    f = _good_finding()
    f["poc_script_code"] = "x"  # short but no hedging title
    r = fp.rule_speculation_title(f)
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# R3 — out-of-scope target
# ---------------------------------------------------------------------------


def test_R3_out_of_scope_fires_on_unrelated_host() -> None:
    f = _good_finding()
    f["target"] = "https://attacker.example.com/leak"
    f["endpoint"] = "https://attacker.example.com/leak"
    r = fp.rule_out_of_scope(f, scope_hosts={"vampi.local"})
    assert r.verdict == "DROP"


def test_R3_out_of_scope_allows_in_scope_host() -> None:
    r = fp.rule_out_of_scope(_good_finding(), scope_hosts={"vampi.local"})
    assert r.verdict == "ALLOW"


def test_R3_out_of_scope_allows_subdomain_of_scope() -> None:
    f = _good_finding()
    f["target"] = "https://api.vampi.local/foo"
    f["endpoint"] = "https://api.vampi.local/foo"
    r = fp.rule_out_of_scope(f, scope_hosts={"vampi.local"})
    assert r.verdict == "ALLOW"


def test_R3_out_of_scope_allows_when_scope_unknown() -> None:
    """No scope information → can't gate; ALLOW (conservative)."""
    r = fp.rule_out_of_scope(_good_finding(), scope_hosts=set())
    assert r.verdict == "ALLOW"


def test_R3_out_of_scope_allows_non_url_target() -> None:
    """Target is a code path, not a URL (local_code/repository
    target type) → don't gate by host."""
    f = _good_finding()
    f["target"] = "src/app/auth.py:142"
    f["endpoint"] = ""
    r = fp.rule_out_of_scope(f, scope_hosts={"vampi.local"})
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# R4 — vague target (no endpoint + no HTTP-shape PoC)
# ---------------------------------------------------------------------------


def test_R4_vague_target_fires_with_no_endpoint_and_prose_poc() -> None:
    f = _good_finding()
    f["endpoint"] = ""
    f["poc_script_code"] = "Look at the login flow and observe the response."
    r = fp.rule_vague_target(f)
    assert r.verdict == "DROP"


def test_R4_vague_target_allows_with_endpoint() -> None:
    r = fp.rule_vague_target(_good_finding())
    assert r.verdict == "ALLOW"


def test_R4_vague_target_allows_when_poc_has_http_shape() -> None:
    """No `endpoint` field but the PoC itself includes an HTTP
    request — that's specific enough; ALLOW."""
    f = _good_finding()
    f["endpoint"] = ""
    # poc_script_code has curl + https://... → has_http_shape=True
    r = fp.rule_vague_target(f)
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# R5 — duplicate request signature
# ---------------------------------------------------------------------------


def test_R5_duplicate_request_signature_fires_on_identical_emission() -> None:
    f = _good_finding()
    existing_sig = fp._request_signature(f)
    r = fp.rule_duplicate_request_signature(
        f, existing_signatures={existing_sig},
    )
    assert r.verdict == "DROP"


def test_R5_duplicate_request_signature_allows_different_endpoint() -> None:
    f = _good_finding()
    existing_sig = fp._request_signature(f)
    f2 = _good_finding()
    f2["endpoint"] = "/api/different"
    r = fp.rule_duplicate_request_signature(
        f2, existing_signatures={existing_sig},
    )
    assert r.verdict == "ALLOW"


def test_R5_duplicate_request_signature_allows_when_no_history() -> None:
    r = fp.rule_duplicate_request_signature(
        _good_finding(), existing_signatures=set(),
    )
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# R6 — severity / CWE-200 mismatch
# ---------------------------------------------------------------------------


def test_R6_severity_cwe_mismatch_downgrades_banner_grab_with_cwe200() -> None:
    f = _good_finding()
    f["title"] = "Server header reveals nginx 1.18.0"
    f["cwe"] = "CWE-200"
    f["poc_script_code"] = "curl -I https://vampi.local/ | grep Server: nginx/1.18.0"
    f["technical_analysis"] = "Server: nginx/1.18.0 in response headers."
    r = fp.rule_severity_cwe_mismatch(f, severity="critical")
    assert r.verdict == "DOWNGRADE"
    assert r.new_severity == "low"


def test_R6_severity_cwe_mismatch_allows_real_critical() -> None:
    """Real critical SQLi (CWE-89, no banner-grab pattern) →
    don't touch."""
    r = fp.rule_severity_cwe_mismatch(_good_finding(), severity="critical")
    assert r.verdict == "ALLOW"


def test_R6_severity_cwe_mismatch_allows_low_severity_info_disclosure() -> None:
    """When severity is already low, the rule's job is done by
    the agent — ALLOW unchanged."""
    f = _good_finding()
    f["cwe"] = "CWE-200"
    f["poc_script_code"] = "curl -I / | grep Server:"
    r = fp.rule_severity_cwe_mismatch(f, severity="low")
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# R7 — banner-grab tagged high-tier (no CWE required)
# ---------------------------------------------------------------------------


def test_R7_banner_grab_high_tier_downgrades_critical_banner() -> None:
    """Pure banner-grab finding (no exploit signals in any field)
    tagged critical → DOWNGRADE to low."""
    f = {
        "title": "Tech stack disclosure",
        "description": "Server banner is exposed in response headers.",
        "impact": "Attackers can fingerprint the stack.",
        "target": "https://vampi.local/",
        "endpoint": "/",
        "method": "GET",
        "technical_analysis": (
            "Response includes Server: nginx/1.18.0 and "
            "X-Powered-By: PHP/7.4 on every endpoint."
        ),
        "poc_description": "Curl the root and inspect headers.",
        "poc_script_code": "curl -sI https://vampi.local/",
        "cwe": "",
    }
    r = fp.rule_banner_grab_high_tier(f, severity="high")
    assert r.verdict == "DOWNGRADE"
    assert r.new_severity == "low"


def test_R7_banner_grab_allows_when_exploit_signals_present() -> None:
    """A banner-grab pattern is incidental if the PoC also contains
    a real exploit signal (e.g. SQLi payload). Don't downgrade —
    let the LLM verifier judge."""
    f = _good_finding()
    f["technical_analysis"] = (
        "Server: nginx; ' OR '1'='1 worked on the login form."
    )
    r = fp.rule_banner_grab_high_tier(f, severity="high")
    assert r.verdict == "ALLOW"


def test_R7_banner_grab_allows_medium_severity() -> None:
    f = _good_finding()
    f["technical_analysis"] = "Server: nginx in response headers."
    r = fp.rule_banner_grab_high_tier(f, severity="medium")
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# R8 — directory listing without traversal
# ---------------------------------------------------------------------------


def test_R8_directory_listing_only_downgrades_when_no_traversal() -> None:
    f = _good_finding()
    f["title"] = "Directory listing exposed on /uploads/"
    f["poc_script_code"] = "curl https://vampi.local/uploads/"
    f["technical_analysis"] = "Apache directory index enabled for /uploads/."
    f["poc_description"] = "Browse to /uploads/ and observe the listing."
    r = fp.rule_directory_listing_only(f, severity="high")
    assert r.verdict == "DOWNGRADE"
    assert r.new_severity == "low"


def test_R8_directory_listing_allows_with_traversal_payload() -> None:
    """Listing + actual traversal payload → real severity is
    justified; ALLOW unchanged."""
    f = _good_finding()
    f["title"] = "Directory listing leads to LFI on /uploads/"
    f["poc_script_code"] = "curl https://vampi.local/uploads/../../../etc/passwd"
    r = fp.rule_directory_listing_only(f, severity="high")
    assert r.verdict == "ALLOW"


def test_R8_directory_listing_allows_non_listing_title() -> None:
    r = fp.rule_directory_listing_only(_good_finding(), severity="high")
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# Aggregate evaluate() — verdict precedence + telemetry
# ---------------------------------------------------------------------------


def test_evaluate_returns_allow_for_clean_finding() -> None:
    r = fp.evaluate(
        _good_finding(),
        severity="critical",
        scope_targets=[{"original": "https://vampi.local/"}],
        existing_findings=[],
    )
    assert r.verdict == "ALLOW"


def test_evaluate_drop_wins_over_downgrade() -> None:
    """A finding that triggers both R1 (DROP) and R7 (DOWNGRADE)
    should be DROPPED — DROP takes precedence."""
    f = _good_finding()
    f["poc_script_code"] = ""  # triggers R1 DROP
    f["technical_analysis"] = "Server: nginx"  # would trigger R7 DOWNGRADE
    r = fp.evaluate(
        f, severity="critical", scope_targets=None, existing_findings=None,
    )
    assert r.verdict == "DROP"
    assert r.rule == "R1_empty_poc"


def test_evaluate_aggregates_downgrades_to_lowest_severity() -> None:
    f = _good_finding()
    f["title"] = "Directory listing exposed and server banner revealed"
    f["cwe"] = "CWE-200"
    f["poc_script_code"] = "curl -I https://vampi.local/uploads/"
    f["technical_analysis"] = "Server: nginx/1.18.0; directory index enabled"
    f["poc_description"] = "Curl with -I shows the Server header"
    r = fp.evaluate(
        f, severity="critical",
        scope_targets=[{"original": "https://vampi.local"}],
        existing_findings=[],
    )
    assert r.verdict == "DOWNGRADE"
    assert r.new_severity == "low"


def test_evaluate_kill_switch_disables_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("STRIX_FP_FILTER_DISABLED", "1")
    f = _good_finding()
    f["poc_script_code"] = ""  # would normally R1 DROP
    r = fp.evaluate(
        f, severity="critical", scope_targets=None, existing_findings=None,
    )
    assert r.verdict == "ALLOW"
    assert r.rule == "filter_disabled"


def test_evaluate_rule_exception_falls_through_to_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A buggy rule must NEVER block a finding. Force one rule to
    raise; the aggregate should still ALLOW the clean finding."""
    def boom(finding):
        raise RuntimeError("forced rule failure")

    monkeypatch.setattr(fp, "rule_empty_poc", boom)
    r = fp.evaluate(
        _good_finding(),
        severity="critical",
        scope_targets=[{"original": "https://vampi.local"}],
        existing_findings=[],
    )
    assert r.verdict == "ALLOW"


# ---------------------------------------------------------------------------
# Recall-safety canary — the must_find fixtures must survive the filter
# ---------------------------------------------------------------------------


def test_recall_canary_sqli_must_find_shape_passes() -> None:
    """Canonical SQLi finding shape (from vampi/flask-vuln
    fixtures) must pass the filter cleanly."""
    f = {
        "title": "SQL injection in books/v2/search via search parameter",
        "description": "User input passed to a raw SQL query.",
        "impact": "Read arbitrary rows from the books table.",
        "target": "http://vampi.local:5001/books/v2/search",
        "endpoint": "/books/v2/search",
        "method": "GET",
        "technical_analysis": "Boolean-based blind SQLi; payload `' OR 1=1--` returns full table.",
        "poc_description": "GET /books/v2/search?title=' OR 1=1-- ",
        "poc_script_code": "curl 'http://vampi.local:5001/books/v2/search?title=%27%20OR%201=1--'",
        "cwe": "CWE-89",
    }
    r = fp.evaluate(
        f, severity="high",
        scope_targets=[{"original": "http://vampi.local:5001"}],
        existing_findings=[],
    )
    assert r.verdict == "ALLOW", (
        f"recall canary: SQLi must_find shape was rejected: "
        f"{r.rule} — {r.reason}"
    )


def test_recall_canary_idor_must_find_shape_passes() -> None:
    """IDOR finding shape must pass — these are the highest-value
    findings (no deterministic scanner finds them)."""
    f = {
        "title": "BOLA — cross-tenant order access via order_id",
        "description": "User A can fetch user B's order by guessing the order_id.",
        "impact": "Cross-tenant data exposure including PII and order contents.",
        "target": "https://crapi.local/api/orders/{id}",
        "endpoint": "/api/orders/12345",
        "method": "GET",
        "technical_analysis": (
            "Endpoint trusts the order_id without verifying the JWT "
            "subject matches the order owner. User A's token + user B's "
            "order_id returns user B's order JSON."
        ),
        "poc_description": "Get user A's token, request /api/orders/<user-B-order-id>",
        "poc_script_code": (
            "curl -H 'Authorization: Bearer <userA-token>' "
            "https://crapi.local/api/orders/12345"
        ),
        "cwe": "CWE-639",
    }
    r = fp.evaluate(
        f, severity="high",
        scope_targets=[{"original": "https://crapi.local"}],
        existing_findings=[],
    )
    assert r.verdict == "ALLOW", (
        f"recall canary: IDOR must_find shape was rejected: "
        f"{r.rule} — {r.reason}"
    )


def test_recall_canary_mass_assignment_must_find_shape_passes() -> None:
    """Mass assignment finding shape — another reasoning-bound
    category that scanners miss."""
    f = {
        "title": "Mass assignment — privilege escalation via profile update",
        "description": "Profile update accepts is_admin=true from client.",
        "impact": "Any user can promote themselves to admin.",
        "target": "https://crapi.local/api/profile",
        "endpoint": "/api/profile",
        "method": "PUT",
        "technical_analysis": (
            "PUT /api/profile body trusts every JSON key. Submitting "
            "is_admin=true persists the flag without server-side filter."
        ),
        "poc_description": "PUT /api/profile with {is_admin: true}",
        "poc_script_code": (
            "curl -X PUT -H 'Authorization: Bearer <token>' "
            "-d '{\"is_admin\": true}' https://crapi.local/api/profile"
        ),
        "cwe": "CWE-915",
    }
    r = fp.evaluate(
        f, severity="critical",
        scope_targets=[{"original": "https://crapi.local"}],
        existing_findings=[],
    )
    assert r.verdict == "ALLOW", (
        f"recall canary: mass-assignment must_find shape was rejected: "
        f"{r.rule} — {r.reason}"
    )
