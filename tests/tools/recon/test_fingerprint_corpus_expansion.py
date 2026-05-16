"""Tests for the fingerprint corpus expansion driven by MOAK Phase A dogfood.

Adds detections for 14 high-version-reliability products that
`fingerprint_tech_stack` didn't previously surface but the MOAK
`image_resolver` already covers. The dogfood finding was that the
binding constraint on Phase A's effectiveness was the fingerprint
corpus, not the resolver table.

Each test pins:
  * Detection of the product from realistic HTTP responses
  * Version extraction (when the product exposes one)
  * Technology name alignment with NVD CPE / image_resolver keys

The latter matters because the downstream pipeline is:
  fingerprint_tech_stack
    → record_dependency_in_kg(name=technology, version=version)
      → cve_relevance.get_asset_inventory_from_kg()  (reads KG)
        → feed_trigger.relevance_match (CPE intersect)
          → MOAK pipeline (when CVE fires)
            → image_resolver.resolve_from_dossier  (CPE → image)

If the technology name we emit isn't recognised by cve_relevance's
CPE matcher OR by image_resolver's product map, the whole chain
breaks. Each test asserts the emitted name matches the canonical
NVD product string for that product.
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.recon import fingerprint


# ---------------------------------------------------------------------------
# Test scaffolding — same fakes as test_fingerprint.py
# ---------------------------------------------------------------------------


class _FakeLLM:
    def __init__(self) -> None:
        self.added: list[str] = []

    def add_skills(self, names: list[str]) -> list[str]:
        new = [n for n in names if n not in self.added]
        self.added.extend(new)
        return new


class _FakeAgentInstance:
    def __init__(self) -> None:
        self.llm = _FakeLLM()


class _FakeAgentState:
    def __init__(self, agent_id: str = "agent-1") -> None:
        self.agent_id = agent_id
        self.context: dict[str, Any] = {}

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value


@pytest.fixture
def fake_agent_state(monkeypatch) -> _FakeAgentState:
    state = _FakeAgentState("test-agent")
    instance = _FakeAgentInstance()
    monkeypatch.setattr(
        "strix.tools.agents_graph.agents_graph_actions._agent_instances",
        {state.agent_id: instance},
    )
    state._fake_instance = instance  # type: ignore[attr-defined]
    return state


def _patch_probe(monkeypatch, status: int, headers: dict[str, str], body: str) -> None:
    monkeypatch.setattr(
        fingerprint, "_probe_http", lambda url: (status, headers, body)
    )


def _run(monkeypatch, fake_agent_state, *, headers=None, body="") -> dict[str, Any]:
    _patch_probe(monkeypatch, 200, headers or {}, body)
    return fingerprint.fingerprint_tech_stack(
        fake_agent_state, "https://example.com/",
    )


def _tech(out: dict[str, Any], name: str) -> dict[str, Any] | None:
    for t in out["technologies"]:
        if t["technology"] == name:
            return t
    return None


# ---------------------------------------------------------------------------
# Header-based: Jenkins
# ---------------------------------------------------------------------------


def test_jenkins_detected_with_version(monkeypatch, fake_agent_state) -> None:
    """`X-Jenkins: <version>` is the canonical Jenkins version header.
    Detection + version both required for downstream MOAK
    image_resolver to construct `jenkins/jenkins:<v>`."""
    out = _run(monkeypatch, fake_agent_state, headers={"x-jenkins": "2.426.1"})
    j = _tech(out, "jenkins")
    assert j is not None
    assert j["version"] == "2.426.1"
    assert j["confidence"] == "high"


def test_jenkins_invalid_version_dropped(monkeypatch, fake_agent_state) -> None:
    """When `X-Jenkins` value doesn't look like a version (e.g.
    pre-release marker or build label), detection still fires but
    `version` stays empty rather than emitting garbage."""
    out = _run(monkeypatch, fake_agent_state, headers={"x-jenkins": "garbage"})
    j = _tech(out, "jenkins")
    assert j is not None
    assert "version" not in j  # empty version not serialised


# ---------------------------------------------------------------------------
# Header-based: Jetty (via Server header)
# ---------------------------------------------------------------------------


def test_jetty_via_server_header(monkeypatch, fake_agent_state) -> None:
    out = _run(
        monkeypatch, fake_agent_state,
        headers={"server": "Jetty(11.0.17)"},
    )
    j = _tech(out, "jetty")
    assert j is not None
    assert j["version"] == "11.0.17"
    assert j["confidence"] == "high"


def test_jetty_ee_variant(monkeypatch, fake_agent_state) -> None:
    """`Jetty(EE10-11.0.18)` — the EE-prefixed form newer Jetty
    builds use. Version extraction must still pull the numeric part."""
    out = _run(
        monkeypatch, fake_agent_state,
        headers={"server": "Jetty(EE10-11.0.18)"},
    )
    j = _tech(out, "jetty")
    assert j is not None
    assert j["version"] == "11.0.18"


# ---------------------------------------------------------------------------
# Header-based: Kibana
# ---------------------------------------------------------------------------


def test_kibana_via_kbn_version_header(monkeypatch, fake_agent_state) -> None:
    out = _run(
        monkeypatch, fake_agent_state,
        headers={"kbn-version": "8.10.0", "kbn-name": "kibana-prod-01"},
    )
    k = _tech(out, "kibana")
    assert k is not None
    assert k["version"] == "8.10.0"


# ---------------------------------------------------------------------------
# Header-based: Microsoft Exchange Server
# ---------------------------------------------------------------------------


def test_exchange_server_via_owa_version(monkeypatch, fake_agent_state) -> None:
    out = _run(
        monkeypatch, fake_agent_state,
        headers={"x-owa-version": "15.2.1118.7"},
    )
    e = _tech(out, "exchange_server")
    assert e is not None
    assert e["version"] == "15.2.1118.7"


# ---------------------------------------------------------------------------
# Header-based: Tomcat (version-less)
# ---------------------------------------------------------------------------


def test_tomcat_via_apache_coyote(monkeypatch, fake_agent_state) -> None:
    """Coyote header reveals Tomcat but the connector version isn't
    a reliable proxy for Tomcat version. Detection without version
    is still useful for cve_relevance product-match filtering."""
    out = _run(
        monkeypatch, fake_agent_state,
        headers={"server": "Apache-Coyote/1.1"},
    )
    t = _tech(out, "tomcat")
    assert t is not None
    assert t["confidence"] == "medium"
    # Coyote version != Tomcat version → no `version` key serialised.
    assert "version" not in t


# ---------------------------------------------------------------------------
# Body-based: Atlassian stack (Confluence / Jira / Bitbucket)
# ---------------------------------------------------------------------------


def test_confluence_detected_with_version(monkeypatch, fake_agent_state) -> None:
    body = (
        '<html><head>'
        '<meta name="application-name" content="Confluence">'
        '<meta name="ajs-version-number" content="8.5.0">'
        '</head></html>'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    c = _tech(out, "confluence_server")
    assert c is not None
    assert c["version"] == "8.5.0"


def test_jira_software_detected_with_version(monkeypatch, fake_agent_state) -> None:
    body = (
        '<html><head>'
        '<meta name="application-name" content="JIRA">'
        '<meta name="ajs-version-number" content="9.12.0">'
        '</head></html>'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    j = _tech(out, "jira_software")
    assert j is not None
    assert j["version"] == "9.12.0"


def test_jira_via_ajs_app_title_alt_marker(monkeypatch, fake_agent_state) -> None:
    """Some Jira deployments use `ajs-app-title` instead of
    `application-name` to identify the product."""
    body = (
        '<meta name="ajs-app-title" content="JIRA">'
        '<meta name="ajs-version-number" content="9.12.0">'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    assert _tech(out, "jira_software") is not None


def test_bitbucket_server_detected_with_version(monkeypatch, fake_agent_state) -> None:
    body = (
        '<meta name="application-name" content="Bitbucket">'
        '<meta name="application-version" content="8.16.0">'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    b = _tech(out, "bitbucket_server")
    assert b is not None
    assert b["version"] == "8.16.0"


def test_bitbucket_via_legacy_stash_name(monkeypatch, fake_agent_state) -> None:
    """Older Bitbucket installs (pre-rebrand) still carry the `Stash`
    product name. Detection must catch both."""
    body = (
        '<meta name="application-name" content="Stash">'
        '<meta name="application-version" content="6.5.0">'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    b = _tech(out, "bitbucket_server")
    assert b is not None
    assert b["version"] == "6.5.0"


# ---------------------------------------------------------------------------
# Body-based: GitLab + Gitea
# ---------------------------------------------------------------------------


def test_gitlab_via_gon_version(monkeypatch, fake_agent_state) -> None:
    body = (
        '<script>gon.gitlab_version = "16.4.1";</script>'
        '<title>GitLab</title>'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    g = _tech(out, "gitlab")
    assert g is not None
    assert g["version"] == "16.4.1"


def test_gitlab_via_meta_tag(monkeypatch, fake_agent_state) -> None:
    body = (
        '<meta name="gitlab-version" content="16.5.0">'
        '<title>GitLab Self-Hosted</title>'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    g = _tech(out, "gitlab")
    assert g is not None
    assert g["version"] == "16.5.0"


def test_gitea_via_powered_by_footer(monkeypatch, fake_agent_state) -> None:
    body = (
        '<meta name="generator" content="Gitea"/>'
        '<p>Powered by Gitea Version: <a href="/">1.21.0</a></p>'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    g = _tech(out, "gitea")
    assert g is not None
    assert g["version"] == "1.21.0"


# ---------------------------------------------------------------------------
# Body-based: SonarQube + Nexus
# ---------------------------------------------------------------------------


def test_sonarqube_detected_with_version(monkeypatch, fake_agent_state) -> None:
    body = (
        '<title>SonarQube</title>'
        '<script>window.sonarqube = {"version":"10.2.1"}</script>'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    s = _tech(out, "sonarqube")
    assert s is not None
    assert s["version"] == "10.2.1"


def test_nexus_repository_manager_detected_with_version(
    monkeypatch, fake_agent_state,
) -> None:
    body = '<title>Nexus Repository Manager 3.61.0</title>'
    out = _run(monkeypatch, fake_agent_state, body=body)
    n = _tech(out, "nexus_repository_manager")
    assert n is not None
    assert n["version"] == "3.61.0"


# ---------------------------------------------------------------------------
# Body-based: Grafana
# ---------------------------------------------------------------------------


def test_grafana_via_meta_version(monkeypatch, fake_agent_state) -> None:
    body = '<meta name="grafana-version" content="10.1.0">'
    out = _run(monkeypatch, fake_agent_state, body=body)
    g = _tech(out, "grafana")
    assert g is not None
    assert g["version"] == "10.1.0"


def test_grafana_via_bootdata_no_version(monkeypatch, fake_agent_state) -> None:
    """Grafana installs that don't expose the meta tag still expose
    the boot-data global. Detection fires but version stays empty
    (the boot-data JSON is too large to parse reliably from the
    32 KB body probe)."""
    body = '<script>window.grafanaBootData = {settings: {...}};</script>'
    out = _run(monkeypatch, fake_agent_state, body=body)
    g = _tech(out, "grafana")
    assert g is not None
    assert "version" not in g


# ---------------------------------------------------------------------------
# Body-based: Elasticsearch (JSON root)
# ---------------------------------------------------------------------------


def test_elasticsearch_root_json_detection(monkeypatch, fake_agent_state) -> None:
    body = (
        '{"name":"node-1","cluster_name":"prod",'
        '"version":{"number":"8.10.0","build_type":"docker"},'
        '"tagline":"You Know, for Search"}'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    e = _tech(out, "elasticsearch")
    assert e is not None
    assert e["version"] == "8.10.0"


def test_elasticsearch_oss_version_suffix(monkeypatch, fake_agent_state) -> None:
    """ES OSS builds carry a `-SNAPSHOT` or `-oss` suffix on the
    version. The version regex must accept the suffix form."""
    body = (
        '{"tagline":"You Know, for Search",'
        '"version":{"number":"7.17.4-oss"}}'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    e = _tech(out, "elasticsearch")
    assert e is not None
    assert e["version"] == "7.17.4-oss"


# ---------------------------------------------------------------------------
# Body-based: Ghost CMS
# ---------------------------------------------------------------------------


def test_ghost_cms_detected_with_version(monkeypatch, fake_agent_state) -> None:
    body = '<meta name="generator" content="Ghost 5.71">'
    out = _run(monkeypatch, fake_agent_state, body=body)
    g = _tech(out, "ghost")
    assert g is not None
    assert g["version"] == "5.71"


# ---------------------------------------------------------------------------
# WordPress + Drupal — versioned detection beats existing version-less
# ---------------------------------------------------------------------------


def test_wordpress_version_extracted(monkeypatch, fake_agent_state) -> None:
    """The legacy `_BODY_SIGNALS` entry detected WordPress but
    didn't extract a version. The versioned signal runs FIRST so the
    version slot is filled when the meta-generator tag is present."""
    body = (
        '<meta name="generator" content="WordPress 6.3.2"/>'
        '<link href="/wp-content/themes/x.css">'
    )
    out = _run(monkeypatch, fake_agent_state, body=body)
    w = _tech(out, "wordpress")
    assert w is not None
    assert w["version"] == "6.3.2"


def test_wordpress_hardened_no_meta_still_detected(
    monkeypatch, fake_agent_state,
) -> None:
    """Hardened WP installs strip the `<meta generator>` tag. The
    versioned signal still fires via `/wp-content/` path detection
    but `version` stays empty."""
    body = '<link href="/wp-content/themes/x.css">'
    out = _run(monkeypatch, fake_agent_state, body=body)
    w = _tech(out, "wordpress")
    assert w is not None
    assert "version" not in w


def test_drupal_version_extracted(monkeypatch, fake_agent_state) -> None:
    body = '<meta name="Generator" content="Drupal 10.1.0">'
    out = _run(monkeypatch, fake_agent_state, body=body)
    d = _tech(out, "drupal")
    assert d is not None
    assert d["version"] == "10.1.0"


# ---------------------------------------------------------------------------
# Multi-product co-detection (real customer environments mix products)
# ---------------------------------------------------------------------------


def test_multi_product_atlassian_stack(monkeypatch, fake_agent_state) -> None:
    """Real Atlassian deployment exposing Confluence behind nginx.
    Both detect cleanly."""
    body = (
        '<meta name="application-name" content="Confluence">'
        '<meta name="ajs-version-number" content="8.5.5">'
    )
    out = _run(
        monkeypatch, fake_agent_state,
        headers={"server": "nginx/1.25.0"},
        body=body,
    )
    techs = {t["technology"] for t in out["technologies"]}
    assert "confluence_server" in techs
    assert "webserver_disclosure" in techs


def test_jenkins_behind_jetty_both_detected(
    monkeypatch, fake_agent_state,
) -> None:
    """Jenkins is shipped on top of Jetty by default — `X-Jenkins`
    AND `Server: Jetty(...)` both present. The lead should see both
    so CVE-relevance fires against either."""
    out = _run(
        monkeypatch, fake_agent_state,
        headers={"x-jenkins": "2.426.1", "server": "Jetty(10.0.18)"},
    )
    techs = {t["technology"] for t in out["technologies"]}
    assert "jenkins" in techs
    assert "jetty" in techs


# ---------------------------------------------------------------------------
# Pipeline alignment — emitted names must match MOAK image_resolver
# ---------------------------------------------------------------------------


def test_emitted_names_match_moak_image_resolver(
    monkeypatch, fake_agent_state,
) -> None:
    """Every product this PR adds must emit a `technology` string
    that the MOAK `image_resolver` recognises (either directly or
    via CPE alias). Without this alignment the downstream pipeline
    can't construct an image ref for the fingerprinted product."""
    import os
    os.environ["STRIX_MOAK_FINGERPRINTED_PRODUCTS"] = "1"
    from strix.agents.exploit_builder.image_resolver import resolve_image_ref

    # (test-case, expected-product-emission, version-for-resolver-check)
    cases = [
        ({"headers": {"x-jenkins": "2.426.1"}}, "jenkins", "2.426.1"),
        ({"headers": {"server": "Jetty(11.0.17)"}}, "jetty", "11.0.17"),
        ({"headers": {"kbn-version": "8.10.0"}}, "kibana", "8.10.0"),
        ({"headers": {"x-owa-version": "15.2.1118.7"}}, "exchange_server", "15.2.1118.7"),
        ({"headers": {"server": "Apache-Coyote/1.1"}}, "tomcat", "10.1.13"),
        (
            {"body": '<meta name="application-name" content="Confluence">'
                     '<meta name="ajs-version-number" content="8.5.0">'},
            "confluence_server", "8.5.0",
        ),
        (
            {"body": '<meta name="application-name" content="JIRA">'
                     '<meta name="ajs-version-number" content="9.12.0">'},
            "jira_software", "9.12.0",
        ),
        (
            {"body": '<meta name="application-name" content="Bitbucket">'
                     '<meta name="application-version" content="8.16.0">'},
            "bitbucket_server", "8.16.0",
        ),
        (
            {"body": '<script>gon.gitlab_version = "16.4.1";</script>'
                     '<title>GitLab</title>'},
            "gitlab", "16.4.1",
        ),
        (
            {"body": '<meta name="generator" content="Gitea"/>'
                     'Powered by Gitea Version: <a>1.21.0</a>'},
            "gitea", "1.21.0",
        ),
        (
            {"body": '<title>SonarQube</title>"version":"10.2.1"'},
            "sonarqube", "10.2.1",
        ),
        (
            {"body": '<title>Nexus Repository Manager 3.61.0</title>'},
            "nexus_repository_manager", "3.61.0",
        ),
        (
            {"body": '<meta name="grafana-version" content="10.1.0">'},
            "grafana", "10.1.0",
        ),
        (
            {"body": '{"tagline":"You Know, for Search",'
                     '"version":{"number":"8.10.0"}}'},
            "elasticsearch", "8.10.0",
        ),
        (
            {"body": '<meta name="generator" content="Ghost 5.71">'},
            "ghost", "5.71",
        ),
    ]
    for probe, expected_tech, version in cases:
        out = _run(
            monkeypatch, fake_agent_state,
            headers=probe.get("headers"),
            body=probe.get("body", ""),
        )
        emitted = _tech(out, expected_tech)
        assert emitted is not None, (
            f"product {expected_tech!r} not detected for probe {probe}"
        )
        # And the resolver must accept the emitted technology name.
        resolved = resolve_image_ref(expected_tech, version)
        assert resolved is not None, (
            f"image_resolver doesn't recognise emitted technology "
            f"{expected_tech!r} — pipeline alignment broken"
        )
