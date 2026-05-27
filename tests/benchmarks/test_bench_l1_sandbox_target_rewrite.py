"""iter-Q5.21 — sandbox-aware target rewriting in bench_l1_only.

When `bench_l1_only.py` runs with `--with-sandbox`, the L1 anchor
prepass executes inside the strix-sandbox container. From in there,
`127.0.0.1 / localhost` mean the sandbox itself, not the host
machine — so probes against fixture-exposed ports fail (ip/
vulnerable-services regressed from recall=1.0 to 0.0 when we flipped
the prepass to sandbox-routed).

The fix (PR for iter-Q5.21):
  * The sandbox is already spawned with
    `extra_hosts={"host.docker.internal": "host-gateway"}` (see
    `strix/runtime/docker_runtime.py:188`).
  * The bench's `resolve_target / resolve_all_targets` now take an
    `in_sandbox: bool` parameter. When True, host-local refs in the
    manifest's `target` field are rewritten to `host.docker.internal`
    so sandbox-side tools reach the host's docker-compose ports.
  * Without `--with-sandbox`, the historic `host.docker.internal →
    localhost` rewrite is preserved (host-side execution).

These tests pin the bidirectional rewrite for every network
target_type the bench supports.
"""

from __future__ import annotations

import sys
from pathlib import Path


# Add the bench module dir to path; it isn't packaged.
BENCH_DIR = Path(__file__).resolve().parents[2] / "benchmarks" / "per_target"
sys.path.insert(0, str(BENCH_DIR))

from bench_l1_only import (  # noqa: E402
    _rewrite_host_for_context,
    resolve_all_targets,
    resolve_target,
)


# ---------------------------------------------------------------------------
# _rewrite_host_for_context — the bidirectional rewrite primitive
# ---------------------------------------------------------------------------


def test_rewrite_host_side_collapses_docker_alias_to_localhost() -> None:
    """Host-side bench keeps the pre-iter-Q5.21 behavior:
    host.docker.internal → localhost so host-side python can reach the
    fixture's exposed ports directly."""
    got = _rewrite_host_for_context(
        "http://host.docker.internal:5001",
        in_sandbox=False,
    )
    assert got == "http://localhost:5001"


def test_rewrite_host_side_preserves_127_0_0_1() -> None:
    """Host-side leaves explicit 127.0.0.1 alone — it already works
    against host-exposed docker-compose ports."""
    got = _rewrite_host_for_context("127.0.0.1", in_sandbox=False)
    assert got == "127.0.0.1"


def test_rewrite_sandbox_side_flips_localhost_to_docker_alias() -> None:
    """Sandbox-side: `localhost` → `host.docker.internal` so the
    sandbox's host-gateway alias reaches the host's docker-compose
    ports. ip/vulnerable-services regression cure."""
    got = _rewrite_host_for_context(
        "http://localhost:8080",
        in_sandbox=True,
    )
    assert got == "http://host.docker.internal:8080"


def test_rewrite_sandbox_side_flips_127_0_0_1_to_docker_alias() -> None:
    """Same for the IP form — ip/vulnerable-services manifest uses
    the literal `127.0.0.1` target."""
    got = _rewrite_host_for_context("127.0.0.1", in_sandbox=True)
    assert got == "host.docker.internal"


def test_rewrite_sandbox_side_is_idempotent() -> None:
    """If a fixture already uses host.docker.internal (juiceshop /
    vampi / crapi), sandbox-side rewrite is a no-op — the target is
    already sandbox-reachable."""
    got = _rewrite_host_for_context(
        "http://host.docker.internal:3001",
        in_sandbox=True,
    )
    assert got == "http://host.docker.internal:3001"


def test_rewrite_empty_string_passthrough() -> None:
    """Defensive: empty / None targets pass through unchanged in both
    contexts (caller handles fallback)."""
    assert _rewrite_host_for_context("", in_sandbox=True) == ""
    assert _rewrite_host_for_context("", in_sandbox=False) == ""


# ---------------------------------------------------------------------------
# resolve_target — manifest → (type, value) with context-aware rewrite
# ---------------------------------------------------------------------------


def test_resolve_target_ip_address_sandbox_rewrites_127() -> None:
    """ip/vulnerable-services fixture: target=127.0.0.1, sandbox-routed
    bench needs host.docker.internal to reach host-exposed ports."""
    manifest = {"target_type": "ip_address", "target": "127.0.0.1"}
    tt, tv = resolve_target(Path("/tmp"), manifest, in_sandbox=True)
    assert tt == "ip_address"
    assert tv == "host.docker.internal"


def test_resolve_target_ip_address_host_keeps_127() -> None:
    """Without --with-sandbox, the host-side bench still talks to
    127.0.0.1 directly (no rewrite needed)."""
    manifest = {"target_type": "ip_address", "target": "127.0.0.1"}
    tt, tv = resolve_target(Path("/tmp"), manifest, in_sandbox=False)
    assert tt == "ip_address"
    assert tv == "127.0.0.1"


def test_resolve_target_web_application_sandbox_keeps_docker_alias() -> None:
    """juiceshop fixture: target=http://host.docker.internal:3001.
    Sandbox-routed bench should keep that form intact (idempotent)."""
    manifest = {
        "target_type": "web_application",
        "target": "http://host.docker.internal:3001",
    }
    tt, tv = resolve_target(Path("/tmp"), manifest, in_sandbox=True)
    assert tt == "web_application"
    assert tv == "http://host.docker.internal:3001"


def test_resolve_target_web_application_host_collapses_to_localhost() -> None:
    """Host-side bench: same juiceshop fixture, but localhost form so
    the host-side prepass can reach the port."""
    manifest = {
        "target_type": "web_application",
        "target": "http://host.docker.internal:3001",
    }
    tt, tv = resolve_target(Path("/tmp"), manifest, in_sandbox=False)
    assert tt == "web_application"
    assert tv == "http://localhost:3001"


def test_resolve_target_web_application_sandbox_flips_localhost() -> None:
    """vibe-app fixture uses target=http://localhost:3030; sandbox-routed
    bench needs the docker-alias form."""
    manifest = {
        "target_type": "web_application",
        "target": "http://localhost:3030",
    }
    tt, tv = resolve_target(Path("/tmp"), manifest, in_sandbox=True)
    assert tt == "web_application"
    assert tv == "http://host.docker.internal:3030"


def test_resolve_target_api_sandbox_keeps_docker_alias() -> None:
    """vampi fixture: target=http://host.docker.internal:5001 — already
    sandbox-reachable."""
    manifest = {
        "target_type": "api",
        "target": "http://host.docker.internal:5001",
    }
    tt, tv = resolve_target(Path("/tmp"), manifest, in_sandbox=True)
    assert tt == "api"
    assert tv == "http://host.docker.internal:5001"


def test_resolve_target_local_code_unaffected_by_in_sandbox() -> None:
    """Code targets are filesystem paths; the in_sandbox flag must not
    touch them (the bench separately mounts source into the sandbox
    workspace)."""
    fix_dir = Path("/tmp/fixture")
    manifest = {"target_type": "local_code", "target": "src"}
    tt_host, tv_host = resolve_target(fix_dir, manifest, in_sandbox=False)
    tt_sb, tv_sb = resolve_target(fix_dir, manifest, in_sandbox=True)
    assert tt_host == tt_sb == "local_code"
    assert tv_host == tv_sb == str((fix_dir / "src").resolve())


def test_resolve_target_container_image_unaffected_by_in_sandbox() -> None:
    """container_image targets are docker image refs (e.g. nginx:1.18)
    — no host rewrite ever applies."""
    manifest = {"target_type": "container_image", "target": "nginx:1.18"}
    _, tv_host = resolve_target(Path("/tmp"), manifest, in_sandbox=False)
    _, tv_sb = resolve_target(Path("/tmp"), manifest, in_sandbox=True)
    assert tv_host == tv_sb == "nginx:1.18"


# ---------------------------------------------------------------------------
# resolve_all_targets — multi-target manifests (paired-asset fixtures)
# ---------------------------------------------------------------------------


def test_resolve_all_targets_sandbox_rewrites_primary_and_additional() -> None:
    """Paired-asset fixture (e.g. vibe-app) — primary web target +
    additional local_code. Sandbox routing must rewrite the URL and
    leave the code path intact."""
    fix_dir = Path("/tmp/vibe-app")
    manifest = {
        "target_type": "web_application",
        "target": "http://localhost:3030",
        "additional_targets": [
            {"type": "local_code", "target": "src"},
        ],
    }
    out = resolve_all_targets(fix_dir, manifest, in_sandbox=True)
    assert len(out) == 2
    assert out[0] == ("web_application", "http://host.docker.internal:3030")
    assert out[1] == ("local_code", str((fix_dir / "src").resolve()))


def test_resolve_all_targets_sandbox_rewrites_additional_network_targets() -> None:
    """If a fixture lists multiple network targets, every one needs
    the sandbox-side rewrite — not just the primary."""
    manifest = {
        "target_type": "web_application",
        "target": "http://localhost:8000",
        "additional_targets": [
            {"type": "api", "target": "http://127.0.0.1:8001"},
            {"type": "ip_address", "target": "localhost"},
        ],
    }
    out = resolve_all_targets(Path("/tmp"), manifest, in_sandbox=True)
    assert ("web_application", "http://host.docker.internal:8000") in out
    assert ("api", "http://host.docker.internal:8001") in out
    assert ("ip_address", "host.docker.internal") in out


def test_resolve_all_targets_host_side_default_unchanged() -> None:
    """Regression guard: without in_sandbox=True, the historic
    behavior (collapse host.docker.internal → localhost) is preserved
    for the no-sandbox lower-bound bench."""
    manifest = {
        "target_type": "api",
        "target": "http://host.docker.internal:5001",
    }
    out = resolve_all_targets(Path("/tmp"), manifest)
    assert out == [("api", "http://localhost:5001")]
