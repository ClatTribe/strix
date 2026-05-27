"""L1-only benchmark harness — measures the OSS-anchor prepass
directly against each fixture, no LLM cost.

## Why this exists

The full per-target bench (runner.py) shells to strix CLI which uses
the LLM for the lead loop. That makes the bench's measurement
unreliable on LLM providers with tight per-minute RPM caps (Gemini
free tier — observed 2026-05-20: each fixture after the first
fails fast on 429 because the previous fixture's tail exhausted the
quota).

L1 alone is deterministic — it's strix's OSS anchor pre-pass
(`strix.agents.lead_agent.anchor_prepass.run_oss_anchor_prepass`),
no LLM cost.

**Sandbox vs bench gap (post PR #384):** every L1 anchor specialist
now runs inside the strix-sandbox container in production. The
bench harness here has NO sandbox — tools with
`sandbox_execution=True` error cleanly with "Agent state with a
valid sandbox_id is required" and contribute 0 findings.

That's by design: the bench measures the LOWER BOUND of L1 (what
runs without the sandbox infrastructure). Production sees the full
anchor coverage including jwt_audit, webapp_recon_pipeline,
http_security_headers_audit, tls_audit, cors_deep_check,
csrf_check, dom_xss_static_probe, scan_cache_deception,
scan_websocket_auth, scan_prototype_pollution, scan_container_image,
scan_sast, scan_sca_lockfiles, scan_iac, secrets_scan, etc.

The bench's job is to validate L1's NON-sandbox-resident probes +
the orchestration logic. Sandbox-resident specialists are
validated separately (unit tests + production runs).

## What this measures

For each fixture:
  1. Parse expected.yaml (must_finds + categories + per-finding
     location metadata).
  2. Resolve `target_value` from the manifest (same logic as runner.py).
  3. Bring up docker compose if `docker.compose_file` is set + wait for
     the health URL.
  4. Run `run_oss_anchor_prepass(target_type, target_value, ...)` —
     this is the L1 detection layer ONLY.
  5. Map prepass findings to the strix canonical Found shape (category,
     file, line, endpoint, etc.).
  6. Score against expected.yaml using the same scoring layer that
     runner.py uses.
  7. Emit per-fixture L1 recall + precision.
  8. Tear down docker compose.

## What this does NOT measure

  * LLM lead-loop reasoning (L2)
  * Specialist dispatch (L3)
  * Cross-tool dedupe / FP demotion
  * Attack-path chain construction

Those layers are tested by runner.py with a real LLM. Use this
harness when you need a deterministic L1-only number per fixture
(e.g. when iterating on the anchor sequence, kwarg builders, or
ruleset coverage in semgrep/nuclei/trivy/grype).

## Usage

  $ python benchmarks/per_target/bench_l1_only.py
  $ python benchmarks/per_target/bench_l1_only.py --fixture flask-vuln
  $ python benchmarks/per_target/bench_l1_only.py --output /tmp/l1.md

Defaults to running the 5 representative fixtures from the per-asset-
type bench (flask-vuln / vampi / vibe-app / ip-vulnerable / juiceshop).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


# Import the scoring + expected-yaml parser from runner.py's sibling
# scoring module. Reuse means our L1-only numbers are directly
# comparable to runner.py's full-pipeline numbers.
sys.path.insert(0, str(Path(__file__).parent))
from scoring import Expected, Found, score  # noqa: E402

# Import the L1 prepass.
sys.path.insert(0, str(Path(__file__).parents[2]))
from strix.agents.lead_agent.anchor_prepass import run_oss_anchor_prepass  # noqa: E402


REPO_ROOT = Path(__file__).parents[2]


def _require_yaml():
    import yaml
    return yaml


class _FakeAgentState:
    """Minimal agent_state for the prepass — has the attrs the
    tool registry checks but no real sandbox. Tools with
    sandbox_execution=True will error out cleanly. The bench
    captures the LOWER BOUND of L1 recall (what runs without
    sandbox infrastructure); production sees the full anchor
    coverage. Use `--with-sandbox` to provision a real sandbox
    container and measure full production-equivalent recall."""
    sandbox_id = None
    sandbox_token = None
    sandbox_info: dict = {}
    agent_id = "l1-bench"
    findings: list = []


class _SandboxAgentState:
    """agent_state populated with a real strix-sandbox container's
    workspace_id + tool_server_port. iter-19: makes the bench run
    every L1 anchor specialist (semgrep, trivy, nuclei, jwt_audit,
    webapp_recon_pipeline, etc.) inside the strix-sandbox:local
    container — measures production-equivalent L1 recall, not the
    no-sandbox lower bound."""

    def __init__(self, sandbox_info: dict) -> None:
        self.sandbox_info = sandbox_info
        self.sandbox_id = sandbox_info.get("workspace_id")
        self.sandbox_token = sandbox_info.get("auth_token")
        self.agent_id = sandbox_info.get("agent_id") or "l1-bench"
        self.findings: list = []


async def _provision_sandbox(image: str | None = None) -> tuple[Any, Any]:
    """Spin up the strix-sandbox container and return (runtime,
    sandbox_info). Image defaults to whatever Config.strix_image
    resolves to (env STRIX_IMAGE → default ghcr.io/usestrix/strix-
    sandbox:0.1.13). The bench typically wants `strix-sandbox:local`
    which is the locally-built image with the iter-15+ tools.

    iter-19 also pip-installs `opentelemetry-api`+`opentelemetry-sdk`
    into the running container if missing — PRs #386/#387 slimmed
    these out of the sandbox image but strix's tracer.py imports
    them unconditionally. pyproject.toml's sandbox extras have been
    updated to include them for the next image rebuild; this
    docker-exec workaround keeps existing locally-built images
    usable without rebuild.
    """
    if image:
        os.environ["STRIX_IMAGE"] = image
    # iter-20 (2026-05-21): skip the entrypoint's lazy-init fetches
    # (nuclei templates + trivy DB + grype DB, ~2-3min). Without this,
    # `_wait_for_tool_server`'s max budget (~5min in theory, ~2-3min
    # in practice with httpx connection-refused short-circuits) trips
    # the lazy-init deadline and the bench raises
    # `SandboxInitializationError: Tool server failed to start`.
    # Caches are warmed below via `docker exec` AFTER tool server is
    # healthy, so per-tool invocations either see warm data or fall
    # back to the tool's own DB-fetch path (trivy without
    # `--skip-db-update`, nuclei with the `~/nuclei-templates`
    # fallback in `templates_dir()`).
    os.environ["STRIX_SKIP_CACHE_INIT"] = "1"
    from strix.runtime import get_runtime  # late-import: needs STRIX_IMAGE set first
    runtime = get_runtime()
    info = await runtime.create_sandbox(
        agent_id="l1-bench-" + os.urandom(4).hex(),
    )
    # The tool server in the sandbox runs as `sudo -u pentester ...`
    # which strips PATH to sudo's secure_path (no /opt/pipx/bin,
    # no /home/pentester/go/bin, etc.). `shutil.which("semgrep")`
    # then returns None inside scan_sast and the tool errors with
    # "semgrep CLI not installed". Symlink the L1 anchor tools into
    # /usr/local/bin (which IS on sudo's secure_path) so the tool
    # server can find them. iter-19 measurement-infrastructure fix;
    # the proper sandbox-image fix is to add
    # `Defaults env_keep += "PATH"` to /etc/sudoers OR pass
    # `sudo --preserve-env=PATH`. Both need an image rebuild.
    try:
        container_id = info.get("workspace_id")
        if container_id:
            tools_to_link = [
                "/opt/pipx/bin/semgrep",
                "/opt/pipx/bin/checkov",
                "/opt/pipx/bin/bandit",
                "/opt/pipx/bin/trufflehog",
                "/usr/local/bin/trivy",      # if already symlinked, no-op
                "/usr/local/bin/grype",
                "/usr/local/bin/osv-scanner",
                "/usr/local/bin/gitleaks",
                "/usr/local/bin/nuclei",
                "/usr/local/bin/katana",
            ]
            symlink_script = (
                " && ".join(
                    f"[ -e {p} ] && ln -sf {p} /usr/local/bin/$(basename {p}) || true"
                    for p in tools_to_link
                )
                + " ; echo done"
            )
            subprocess.run(
                ["docker", "exec", "--user", "root", container_id,
                 "sh", "-c", symlink_script],
                capture_output=True, timeout=15,
            )
    except Exception as e:  # noqa: BLE001
        print(f"[bench] tool-path symlinks failed (continuing): {e}",
              flush=True)

    # Verify + uv-pip-install opentelemetry into the sandbox's
    # /app/.venv if missing. The sandbox runs strix from a uv-managed
    # virtualenv at /app/.venv; system `pip install` doesn't reach
    # that venv. Use `uv pip install --python /app/.venv/bin/python3`
    # to target it specifically.
    try:
        container_id = info.get("workspace_id")
        if container_id:
            check = subprocess.run(
                ["docker", "exec", container_id,
                 "/app/.venv/bin/python3", "-c", "import opentelemetry"],
                capture_output=True, timeout=15,
            )
            if check.returncode != 0:
                print(
                    "[bench] sandbox venv missing opentelemetry — uv-pip-installing...",
                    flush=True,
                )
                install = subprocess.run(
                    ["docker", "exec", "--workdir", "/app", container_id,
                     "uv", "pip", "install", "--python",
                     "/app/.venv/bin/python3",
                     "opentelemetry-api>=1.20",
                     "opentelemetry-sdk>=1.20"],
                    capture_output=True, timeout=180, text=True,
                )
                if install.returncode != 0:
                    print(
                        f"[bench] uv pip install failed: "
                        f"{install.stderr[:200]}",
                        flush=True,
                    )
                else:
                    print(
                        "[bench] opentelemetry installed in sandbox venv.",
                        flush=True,
                    )
    except Exception as e:  # noqa: BLE001
        print(f"[bench] opentelemetry shim failed (continuing): {e}", flush=True)

    # iter-20 (2026-05-21): warm the scanner-data caches now that the
    # tool server is up. These would normally be fetched by the
    # entrypoint's lazy-init, but we skipped it with
    # `STRIX_SKIP_CACHE_INIT=1` so the tool server starts in seconds
    # rather than minutes.
    #
    # Each warmup is best-effort + concurrent (kick all three in
    # background then wait, capped at 120s total). The first per-tool
    # invocation that needs the data will block until ready; warming
    # here just shifts the cost out of the per-tool wall-time budget.
    try:
        container_id = info.get("workspace_id")
        if container_id:
            # Kick off all three concurrently — they share no state.
            # Output redirected to a log inside the container; check
            # the process status before the bench's first tool call.
            warmup_script = (
                "nohup nuclei -update-templates -silent "
                ">/tmp/warmup_nuclei.log 2>&1 & "
                "nohup trivy image --download-db-only --quiet "
                ">/tmp/warmup_trivy.log 2>&1 & "
                "nohup grype db update "
                ">/tmp/warmup_grype.log 2>&1 & "
                "echo started_warmup"
            )
            subprocess.run(
                ["docker", "exec", container_id, "sh", "-c", warmup_script],
                capture_output=True, timeout=15,
            )
            print(
                "[bench] cache warmup (nuclei/trivy/grype) running in "
                "background inside sandbox; per-tool invocations will "
                "block on cache readiness as needed.",
                flush=True,
            )
    except Exception as e:  # noqa: BLE001
        print(f"[bench] cache warmup kickoff failed (continuing): {e}",
              flush=True)

    return runtime, info


def _copy_source_into_sandbox(
    sandbox_info: dict, host_path: str,
) -> str:
    """Tar the host source dir + put it at /workspace/<basename> inside
    the sandbox. Returns the in-sandbox workspace_path that scan_sast /
    scan_sca_lockfiles / scan_iac / secrets_scan should read.

    iter-19: needed because the L1 bench was previously running every
    code-target tool on the host (sandbox_execution=False semantics).
    Post-PR #384, those tools execute in the sandbox — the host path
    `/Users/...` doesn't exist inside the container, so we need to
    copy + remap.

    Best-effort: failure returns empty string, prepass falls back to
    host path → tool errors → finding count 0 for that target. Logged
    by the caller via the bench's per-tool error captures.
    """
    import tarfile
    from io import BytesIO
    container_id = sandbox_info.get("workspace_id")
    if not container_id:
        return ""
    host_path_obj = Path(host_path).resolve()
    if not host_path_obj.exists() or not host_path_obj.is_dir():
        return ""
    target_name = host_path_obj.name
    workspace_path = f"/workspace/{target_name}"
    try:
        # Build a tarball of the source dir.
        tar_buffer = BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
            for item in host_path_obj.rglob("*"):
                if item.is_file():
                    rel = item.relative_to(host_path_obj)
                    tar.add(item, arcname=str(Path(target_name) / rel))
        tar_buffer.seek(0)
        # Stream the tarball into the container at /workspace.
        proc = subprocess.run(
            ["docker", "cp", "-", f"{container_id}:/workspace"],
            input=tar_buffer.getvalue(),
            capture_output=True, timeout=60,
        )
        if proc.returncode != 0:
            return ""
        # Chown so the pentester user can read the files.
        subprocess.run(
            ["docker", "exec", "--user", "root", container_id, "sh", "-c",
             f"chown -R pentester:pentester /workspace/{target_name} && "
             f"chmod -R 755 /workspace/{target_name}"],
            capture_output=True, timeout=30,
        )
    except Exception:  # noqa: BLE001
        return ""
    return workspace_path


async def _destroy_sandbox(runtime: Any, sandbox_info: dict) -> None:
    """Best-effort sandbox teardown."""
    try:
        wid = sandbox_info.get("workspace_id")
        if wid:
            await runtime.destroy_sandbox(wid)
    except Exception:  # noqa: BLE001
        pass
    try:
        runtime.cleanup()
    except Exception:  # noqa: BLE001
        pass


def _ensure_tracer() -> None:
    """Set up a minimal global tracer so tools that emit via
    `get_global_tracer()` (scan_container_image, scan_sast, etc.)
    can actually persist findings.

    Without this, scan_container_image silently no-ops on the L1
    bench harness — trivy finds 400+ CVEs in nginx:1.18 but
    `_emit_image_finding` returns None because tracer is None,
    so 0 findings make it into the result dict.

    The tracer writes events to a tempdir; not used by the bench
    but required by the emission layer.
    """
    try:
        from strix.telemetry import tracer as tracer_module
        if getattr(tracer_module, "_global_tracer", None) is not None:
            return
        from strix.telemetry.tracer import Tracer, set_global_tracer
        t = Tracer("l1-bench")
        set_global_tracer(t)
    except Exception:  # noqa: BLE001
        # Don't crash the bench on tracer setup failure — some tools
        # still emit findings without a tracer.
        pass


def parse_expected(fixture_dir: Path) -> tuple[dict[str, Any], list[Expected]]:
    yaml = _require_yaml()
    manifest = yaml.safe_load((fixture_dir / "expected.yaml").read_text())
    raw = manifest.get("expected_findings", []) or []
    expected = [
        Expected(
            id=e["id"],
            category=e.get("category", ""),
            cwe=e.get("cwe"),
            file=e.get("file"),
            line=e.get("line"),
            endpoint=e.get("endpoint"),
            port=e.get("port"),
            severity=e.get("severity"),
            description=e.get("description", ""),
            must_find=bool(e.get("must_find", True)),
        )
        for e in raw
    ]
    return manifest, expected


def _rewrite_host_for_context(target: str, *, in_sandbox: bool) -> str:
    """Rewrite host references based on the bench's execution context
    (iter-Q5.21).

    Two contexts:

    - **Host execution** (`in_sandbox=False`, the default / no-sandbox
      bench): rewrite `host.docker.internal` → `localhost` so the
      host-side Python prepass can reach the fixture's exposed ports.
      This is the historic behavior, preserved for the lower-bound
      measurement.

    - **Sandbox execution** (`in_sandbox=True`, `--with-sandbox`): the
      prepass tools execute *inside* the strix-sandbox container. From
      in there, `127.0.0.1` / `localhost` mean the sandbox itself, not
      the host machine. Rewrite both to `host.docker.internal` so the
      sandbox's host-gateway alias (added by
      `strix/runtime/docker_runtime.py:188` via
      `extra_hosts={"host.docker.internal": "host-gateway"}`) reaches
      the host's exposed ports.

    Without this guard the ip/vulnerable-services fixture went from
    recall=1.0 (host-side) to recall=0.0 (sandbox-routed) because the
    sandbox-side `probe_open_tcp_ports` was scanning the sandbox itself
    rather than the host's docker-compose ports.
    """
    if not target:
        return target
    if in_sandbox:
        # Sandbox side: rewrite host-local refs to the docker-host alias.
        # Order: rewrite 127.0.0.1 first (more specific) then localhost,
        # then leave host.docker.internal as a no-op.
        return (
            target
            .replace("127.0.0.1", "host.docker.internal")
            .replace("localhost", "host.docker.internal")
        )
    # Host side: collapse host.docker.internal → localhost. Same as
    # pre-Q5.21 behavior.
    return target.replace("host.docker.internal", "localhost")


def resolve_all_targets(
    fixture_dir: Path,
    manifest: dict[str, Any],
    *,
    in_sandbox: bool = False,
) -> list[tuple[str, str]]:
    """Returns a list of (target_type, target_value) the prepass
    should scan. Handles primary + `additional_targets` (paired-asset
    fixtures like vibe-app where the same app is scanned as web URL
    AND local source tree).

    The primary target comes first; additional targets follow in
    manifest order. Each target gets its own prepass invocation; the
    bench unions the findings across all targets before scoring.

    `in_sandbox=True` (iter-Q5.21) flips the host-name rewrite from
    `host.docker.internal → localhost` to `localhost / 127.0.0.1 →
    host.docker.internal` so sandbox-routed tools can reach
    host-exposed ports via the docker host-gateway alias.
    """
    out: list[tuple[str, str]] = []
    # Primary target via the single-target resolver.
    primary = resolve_target(fixture_dir, manifest, in_sandbox=in_sandbox)
    if primary[0] and primary[1]:
        out.append(primary)

    # Additional targets: each has its own {type, target} pair.
    for entry in (manifest.get("additional_targets") or []):
        if not isinstance(entry, dict):
            continue
        tt = (entry.get("type") or "").strip()
        tg = entry.get("target")
        if not tt or tg is None:
            continue
        if tt in ("local_code", "repository"):
            full = (fixture_dir / tg).resolve()
            out.append((tt, str(full)))
        elif tt in ("web_application", "api", "ip_address"):
            # Apply the same context-aware host rewrite as the primary.
            out.append((tt, _rewrite_host_for_context(str(tg), in_sandbox=in_sandbox)))
        else:
            out.append((tt, str(tg)))
    return out


def resolve_target(
    fixture_dir: Path,
    manifest: dict[str, Any],
    *,
    in_sandbox: bool = False,
) -> tuple[str, str]:
    """Pick (target_type, target_value) the prepass should scan.

    For network targets (api / web_application / ip_address) the
    fixture's `target` field is rewritten according to the bench's
    execution context (see `_rewrite_host_for_context`):

    - Host side (default): `host.docker.internal → localhost`.
    - Sandbox side (`in_sandbox=True`, set by --with-sandbox path):
      `localhost / 127.0.0.1 → host.docker.internal` so sandbox tools
      reach the host's docker-compose ports via the host-gateway alias
      (iter-Q5.21).
    """
    target_type = manifest.get("target_type", "")
    if target_type in ("local_code", "repository"):
        rel = manifest.get("target", "")
        full = (fixture_dir / rel).resolve()
        return target_type, str(full)
    if target_type in ("web_application", "api"):
        # Prefer the manifest's `target` field (with context-aware host
        # rewrite). Fall back to wait_url if no target.
        #
        # We deliberately DON'T use docker.wait_url as the primary —
        # wait_url is a health-check endpoint that may point deep into
        # the app (juiceshop's wait_url is /rest/admin/application-version,
        # not the app root). Probes appended to that URL would all go to
        # the wrong place.
        target = manifest.get("target", "")
        target = _rewrite_host_for_context(target or "", in_sandbox=in_sandbox)
        if target:
            return target_type, target.rstrip("/")
        # Last-ditch: take scheme://netloc from wait_url (strip the path).
        docker_cfg = manifest.get("docker") or {}
        wait_url = docker_cfg.get("wait_url")
        if isinstance(wait_url, str) and wait_url:
            try:
                from urllib.parse import urlparse
                rewritten = _rewrite_host_for_context(wait_url, in_sandbox=in_sandbox)
                p = urlparse(rewritten)
                if p.scheme and p.netloc:
                    return target_type, f"{p.scheme}://{p.netloc}"
            except Exception:  # noqa: BLE001
                pass
            return target_type, _rewrite_host_for_context(
                wait_url, in_sandbox=in_sandbox
            ).rstrip("/")
        return target_type, ""
    if target_type == "ip_address":
        # Same context-aware host rewrite.
        target = manifest.get("target", "")
        target = _rewrite_host_for_context(target or "", in_sandbox=in_sandbox)
        return target_type, target
    if target_type == "container_image":
        return target_type, manifest.get("target", "")
    return target_type, manifest.get("target", "")


def docker_up(fixture_dir: Path, manifest: dict[str, Any]) -> bool:
    """Bring up docker compose if specified; wait for health URL."""
    docker_cfg = manifest.get("docker") or {}
    compose_file = docker_cfg.get("compose_file")
    if not compose_file:
        return False
    compose_path = fixture_dir / compose_file
    if not compose_path.exists():
        return False
    print(f"  [docker] up -f {compose_path.relative_to(REPO_ROOT)}", flush=True)
    subprocess.run(
        ["docker", "compose", "-f", str(compose_path), "up", "-d"],
        check=False, capture_output=True,
    )
    wait_url = docker_cfg.get("wait_url")
    if wait_url:
        deadline = time.time() + int(docker_cfg.get("wait_timeout_seconds", 60))
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(wait_url, timeout=2):
                    print(f"  [docker] {wait_url} healthy", flush=True)
                    return True
            except Exception:  # noqa: BLE001
                time.sleep(2)
        print(f"  [docker] WARN: {wait_url} never became healthy", flush=True)
    return True


def docker_down(fixture_dir: Path, manifest: dict[str, Any]) -> None:
    docker_cfg = manifest.get("docker") or {}
    compose_file = docker_cfg.get("compose_file")
    if not compose_file:
        return
    compose_path = fixture_dir / compose_file
    subprocess.run(
        ["docker", "compose", "-f", str(compose_path), "down"],
        check=False, capture_output=True,
    )


def _finding_to_found(raw: dict[str, Any]) -> Found:
    """Map a prepass-tool finding dict to the canonical Found shape.

    Tool-emitted findings vary in field names; we extract the common
    ones the scoring layer needs (category, cwe, file, line, endpoint).
    """
    if not isinstance(raw, dict):
        return Found(title=str(raw)[:80])
    title = (
        raw.get("title")
        or raw.get("name")
        or raw.get("description", "")[:120]
        or raw.get("rule_id", "")
        or "unnamed"
    )
    location = raw.get("location") or {}
    if isinstance(location, dict):
        file_ = location.get("file") or location.get("path")
        line = location.get("line") or location.get("line_start")
    else:
        file_ = None
        line = None
    return Found(
        title=str(title)[:200],
        category=raw.get("category"),
        cwe=raw.get("cwe"),
        file=raw.get("file") or file_,
        line=raw.get("line") or line,
        endpoint=raw.get("endpoint") or raw.get("url"),
        port=raw.get("port"),
        severity=raw.get("severity"),
        raw=raw,
    )


async def run_one_fixture(
    fixture_dir: Path,
    *,
    skip_docker: bool = False,
    agent_state: Any | None = None,
) -> dict[str, Any]:
    """Run L1 prepass against one fixture; return scored result dict.

    If `agent_state` is supplied (e.g. a `_SandboxAgentState` from
    `--with-sandbox` provisioning), it's used for the prepass —
    enabling sandbox-routed tools to actually run. Otherwise falls
    back to the no-sandbox `_FakeAgentState` (bench lower bound).
    """
    manifest, expected = parse_expected(fixture_dir)
    # iter-Q5.21: when the prepass routes through a real sandbox
    # (agent_state carries a sandbox_id), the L1 tools execute *inside*
    # the strix-sandbox container. Resolve targets in that context so
    # `127.0.0.1 / localhost` get rewritten to `host.docker.internal`
    # (which the sandbox can reach via the host-gateway alias added in
    # strix/runtime/docker_runtime.py:188). Without this rewrite,
    # ip/vulnerable-services scans the sandbox itself instead of the
    # host's docker-compose ports and recall collapses to 0.
    _in_sandbox = bool(getattr(agent_state, "sandbox_id", None))
    targets = resolve_all_targets(fixture_dir, manifest, in_sandbox=_in_sandbox)
    rel = fixture_dir.relative_to(REPO_ROOT) if str(fixture_dir).startswith(str(REPO_ROOT)) else fixture_dir
    primary_type, primary_value = targets[0] if targets else ("", "")
    print(f"\n=== {rel} ({primary_type}) ===", flush=True)
    for tt, tv in targets:
        print(f"  target: [{tt}] {tv}", flush=True)

    docker_up_ok = False
    try:
        if not skip_docker:
            docker_up_ok = docker_up(fixture_dir, manifest)
        if agent_state is None:
            agent_state = _FakeAgentState()

        # Run the L1 prepass against EACH target and union findings.
        # Paired-asset fixtures (vibe-app) need this so SCA / SAST
        # against the source tree run alongside DAST against the
        # web URL.
        start = time.monotonic()
        all_findings: list[Found] = []
        merged_tool_results: list[dict[str, Any]] = []
        total_tools_run = 0
        total_tools_succeeded = 0
        total_tools_failed = 0
        for tt, tv in targets:
            # iter-19: for local_code/repository targets under
            # --with-sandbox, copy the source dir into the sandbox
            # at /workspace/<basename> and pass workspace_path so the
            # in-sandbox scan_sast / scan_sca_lockfiles / scan_iac /
            # secrets_scan find the right path. Non-code targets pass
            # workspace_path=""; the prepass uses target_value (URL).
            ws_path = ""
            if (
                tt in ("local_code", "repository")
                and hasattr(agent_state, "sandbox_info")
                and agent_state.sandbox_info
            ):
                ws_path = _copy_source_into_sandbox(
                    agent_state.sandbox_info, tv,
                )
                if ws_path:
                    print(
                        f"  copied {tv} → sandbox {ws_path}",
                        flush=True,
                    )
            summary = await run_oss_anchor_prepass(
                target_type=tt,
                target_value=tv,
                workspace_path=ws_path,
                agent_state=agent_state,
            )
            for r in summary.tool_results:
                raw = r.raw_result
                if isinstance(raw, dict):
                    for f in (raw.get("findings") or raw.get("vulnerabilities") or []):
                        if isinstance(f, dict):
                            all_findings.append(_finding_to_found(f))
                merged_tool_results.append({
                    "tool": f"[{tt}] {r.tool_name}",
                    "status": r.status,
                    "findings": r.findings_count,
                    "note": (r.error_reason or "")[:120],
                })
            total_tools_run += len(summary.tools_run)
            total_tools_succeeded += len(summary.tools_succeeded)
            total_tools_failed += len(summary.tools_failed)
        wall = time.monotonic() - start

        score_result = score(expected, all_findings)

        result = {
            "fixture": str(rel),
            "target_type": primary_type,
            "target_value": primary_value,
            "wall_seconds": round(wall, 2),
            "expected_count": score_result.expected_count,
            "found_count": score_result.found_count,
            "matched_count": score_result.matched_count,
            "recall": score_result.recall,
            "precision": score_result.precision,
            "matched": list(score_result.matches),
            "missed": list(score_result.missed),
            "tools_run": total_tools_run,
            "tools_succeeded": total_tools_succeeded,
            "tools_failed": total_tools_failed,
            "tool_breakdown": merged_tool_results,
        }
        print(
            f"  recall={result['recall']:.3f} ({result['matched_count']}/{result['expected_count']}) "
            f"found={result['found_count']} wall={result['wall_seconds']:.1f}s",
            flush=True,
        )
        return result
    finally:
        if docker_up_ok and not skip_docker:
            docker_down(fixture_dir, manifest)


# Default fixture list. Two tiers:
#   * _FAST_FIXTURES — original 6 used during iter-11..iter-15
#     iteration. ~10 min total wall, one fixture per asset type.
#   * _ALL_FIXTURES  — every fixture under fixtures/ that has an
#     expected.yaml. Triggered via `--full`.
#
# Why two tiers (caught 2026-05-21): iter-15 surfaced that 5+
# fixtures with expected.yaml had NEVER been measured because they
# weren't in the default list (code/sast-vibe, code/iac-vibe,
# code/sca-*, api/crapi). The selection bias meant new probes /
# rules were tuned to the 6, not to the breadth. `--full` makes
# "forgot to measure a fixture" structurally impossible.
_FAST_FIXTURES = [
    "code/flask-vuln",
    "api/vampi",
    "web+code/vibe-app",
    "ip/vulnerable-services",
    "web/juiceshop",
    "container/nginx-vuln",
]

# Heavy; ~30-45 min when all containers come up cleanly. Order is
# asset-type-grouped so a partial run still gives you per-type signal.
_ALL_FIXTURES = [
    # code / repository targets — host execution, fastest
    "code/flask-vuln",
    "code/sast-vibe",
    "code/iac-vibe",
    "code/sca-vuln-deps",
    "code/sca-reachability",
    "code/sca-supply-chain",
    # api targets
    "api/vampi",
    "api/crapi",
    # web_application targets (some heavy)
    "web+code/vibe-app",
    "web/juiceshop",
    "web/webgoat",
    "web/apache-cve-2021-41773",
    # ip_address
    "ip/vulnerable-services",
    # container_image
    "container/nginx-vuln",
]

# Backwards-compatible name for any caller that referenced this
# directly. Fast set is still the default for `python -m
# benchmarks.per_target.bench_l1_only` with no flags.
_DEFAULT_FIXTURES = _FAST_FIXTURES


async def amain(args: argparse.Namespace) -> int:
    _ensure_tracer()
    fixtures_root = REPO_ROOT / "benchmarks" / "per_target" / "fixtures"
    if args.fixture:
        targets = [fixtures_root / args.fixture]
    elif args.full:
        targets = [fixtures_root / f for f in _ALL_FIXTURES]
    else:
        targets = [fixtures_root / f for f in _FAST_FIXTURES]

    # iter-19: optional sandbox provisioning. With `--with-sandbox`,
    # the bench spins up a strix-sandbox container ONCE and reuses it
    # across every fixture. The fixture's docker compose (the target
    # under test) runs alongside the sandbox; the sandbox reaches the
    # target via host.docker.internal (HOST_GATEWAY).
    sandbox_runtime = None
    sandbox_info: dict | None = None
    if args.with_sandbox:
        print(
            f"[bench] provisioning strix-sandbox container "
            f"(image={args.sandbox_image or '$STRIX_IMAGE'})...",
            flush=True,
        )
        sandbox_runtime, sandbox_info = await _provision_sandbox(
            image=args.sandbox_image,
        )
        print(
            f"[bench] sandbox ready: workspace_id="
            f"{sandbox_info['workspace_id'][:12]}... "
            f"tool_server_port={sandbox_info['tool_server_port']}",
            flush=True,
        )

    results: list[dict[str, Any]] = []
    try:
        for fx in targets:
            if not (fx / "expected.yaml").exists():
                print(f"  [skip] {fx.name}: no expected.yaml", flush=True)
                continue
            try:
                # Build a fresh per-fixture agent_state. When the
                # sandbox is shared, each fixture gets a state object
                # pointing at the same sandbox_info — fine because the
                # prepass doesn't mutate sandbox_info, only reads it.
                if sandbox_info is not None:
                    agent_state = _SandboxAgentState(sandbox_info)
                else:
                    agent_state = None  # falls back to _FakeAgentState
                results.append(await run_one_fixture(
                    fx,
                    skip_docker=args.skip_docker,
                    agent_state=agent_state,
                ))
            except Exception as e:  # noqa: BLE001
                import traceback
                traceback.print_exc()
                results.append({
                    "fixture": str(fx.relative_to(REPO_ROOT)),
                    "error": f"{type(e).__name__}: {e}",
                })
    finally:
        if sandbox_runtime is not None and sandbox_info is not None:
            print("[bench] tearing down sandbox...", flush=True)
            await _destroy_sandbox(sandbox_runtime, sandbox_info)

    # Emit markdown summary.
    ts = time.strftime("%Y%m%d_%H%M%S")
    out_path = args.output or f"benchmarks/per_target/baseline/l1_only_{ts}.md"
    lines = [
        f"# L1-only baseline @ {ts}",
        "",
        "Pure prepass measurement — no LLM cost. Tools that need a real",
        "sandbox (`sandbox_execution=True`) fail in this harness; they",
        "work in the full bench via runner.py.",
        "",
        "| Fixture | target_type | recall | precision | matched | found | wall |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        if "error" in r:
            lines.append(
                f"| {r['fixture']} | — | — | — | — | — | ERROR: {r['error']} |"
            )
            continue
        lines.append(
            f"| {r['fixture']} | {r['target_type']} | "
            f"{r['recall']:.3f} | {r['precision']:.3f} | "
            f"{r['matched_count']}/{r['expected_count']} | "
            f"{r['found_count']} | {r['wall_seconds']:.1f}s |"
        )
    lines.append("")
    # Append per-fixture tool breakdowns for diagnostics.
    for r in results:
        if "error" in r:
            continue
        lines.append(f"## {r['fixture']} — tool breakdown")
        lines.append("")
        lines.append(f"- matched: {r['matched']}")
        lines.append(f"- missed: {r['missed']}")
        lines.append("")
        lines.append("| Tool | Status | Findings | Note |")
        lines.append("|---|---|---:|---|")
        for t in r["tool_breakdown"]:
            note = (t["note"] or "").replace("|", "\\|")
            lines.append(
                f"| {t['tool']} | {t['status']} | {t['findings']} | {note} |"
            )
        lines.append("")

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text("\n".join(lines))
    print(f"\nDONE. Wrote {out_path}", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--fixture", default=None,
        help="single fixture relative path (e.g. 'code/flask-vuln'). "
             "Default: runs the FAST tier (6 fixtures, ~10 min). Use "
             "`--full` for every fixture with an expected.yaml.",
    )
    parser.add_argument(
        "--full", action="store_true",
        help="run the full fixture set instead of the fast tier. ~30-45 min "
             "when all containers come up cleanly. Covers every fixture under "
             "fixtures/ that has an expected.yaml — added 2026-05-21 after "
             "iter-15 surfaced that the fast tier had been silently missing "
             "5+ measurable fixtures (sast-vibe, iac-vibe, sca-*, crapi).",
    )
    parser.add_argument(
        "--output", default=None,
        help="path to markdown summary (default: timestamped under baseline/)",
    )
    parser.add_argument(
        "--skip-docker", action="store_true",
        help="don't bring up docker compose (assume target is already up)",
    )
    parser.add_argument(
        "--with-sandbox", action="store_true",
        help="provision a real strix-sandbox container and route every "
             "L1 anchor tool through it. Without this flag the bench "
             "shows the no-sandbox LOWER BOUND (semgrep/trivy/nuclei/"
             "etc. error cleanly). With it, the bench measures "
             "production-equivalent L1 recall.",
    )
    parser.add_argument(
        "--sandbox-image", default=None,
        help="override the sandbox image (sets STRIX_IMAGE). Default: "
             "whatever STRIX_IMAGE env or Config.strix_image resolves "
             "to. Typically `strix-sandbox:local` for a locally-built "
             "image.",
    )
    args = parser.parse_args()
    return asyncio.run(amain(args))


if __name__ == "__main__":
    sys.exit(main())
