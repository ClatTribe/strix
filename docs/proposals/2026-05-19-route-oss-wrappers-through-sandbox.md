# Proposal: Route `scan_sast` / `scan_sca_lockfiles` / `scan_iac` / `scan_nuclei_templates` through the sandbox container

**Date:** 2026-05-19
**Status:** Draft — needs review before implementation
**Driver:** Customer-deployable architecture — strix must not depend on host-installed OSS scanners

## Problem

The deterministic-specialist wrappers that strix uses for signature-driven detection currently shell to OSS binaries via `subprocess.run` on the **host where strix is running**, not inside the strix-sandbox container.

```python
# strix/sast/tools.py
@register_specialist_tool(
    category="sast",
    sandbox_execution=False,   # <-- runs on host
    ...
)
def scan_sast(...):
    if not is_semgrep_available():  # shutil.which("semgrep") on host
        return {"status": "partial", "reason": "semgrep not on PATH"}
    result = run_semgrep(...)       # subprocess.run on host
```

Same pattern in:

- `strix/sast/tools.py` → `scan_sast` (semgrep)
- `strix/sca/tools.py` → `scan_sca_lockfiles` (osv-scanner + GHSA)
- `strix/iac/tools.py` → `scan_iac` (checkov + tfsec)
- `strix/tools/container_image/scan_container_image.py` → `scan_container_image` (trivy)
- `strix/tools/nuclei_runner/nuclei_runner.py` → `scan_nuclei_templates` (nuclei)

### Why it's a problem

1. **Customer surface area mismatch.** Strix is marketed as "agentic
   security with just Docker." A customer who follows our install
   docs does `pip install strix` + `docker pull strix-sandbox` and
   expects everything to work. They do NOT also run `brew install
   semgrep trivy grype osv-scanner checkov nuclei`. When `scan_sast`
   silently returns `status="partial"`, the customer's recall craters
   without a clear signal — they think strix is broken, not their
   install.

2. **Live measurement showed exactly this failure mode.** R1
   (2026-05-19, benchmarks/per_target/baseline/COMPETITIVE_ASSESSMENT_2026-05-19.md):
   the full per_target quick-mode baseline ran with every OSS scanner
   missing from PATH on the host. `scan_sast` returned partial on
   every call. Result: 13% aggregate recall against must_find
   canaries, indistinguishable from a real low-recall run.

3. **The sandbox image already has the binaries** — confirmed in
   `containers/Dockerfile`: nuclei + templates, semgrep + bandit,
   trivy, sqlmap, gitleaks, trufflehog, zaproxy, wapiti, plus (added
   in PR #359 extensions): grype, osv-scanner, checkov. We're shipping
   the toolkit but not using it from the wrappers.

4. **Air-gap and signature-staleness wins.** When OSS tools run inside
   the sandbox, signature DBs are baked at image-build time. Customers
   on locked-down corporate networks (no outbound from CI runner)
   get a working scanner. When tools run on host, customers have to
   solve `nuclei -update-templates` connectivity themselves.

## Proposal

Flip `sandbox_execution=True` on the five wrappers and route their
binary invocations through the existing DockerRuntime layer. The
sandbox already mounts the target source at `/workspace` (for code
fixtures) or has network access to the target (for web/API fixtures),
so the target reachability surface doesn't change.

### Wrapper interface change

```python
# Before (current — host subprocess)
@register_specialist_tool(category="sast", sandbox_execution=False, ...)
def scan_sast(target_path: str, ...) -> SpecialistResult:
    if not is_semgrep_available():
        return {"status": "partial", "reason": "semgrep not on PATH"}
    return _run_semgrep_host(target_path, ...)

# After (proposed — sandbox routed)
@register_specialist_tool(category="sast", sandbox_execution=True, ...)
def scan_sast(target_path: str, ...) -> SpecialistResult:
    # The sandbox always has semgrep installed (baked at image build).
    # Path translation happens at the DockerRuntime boundary —
    # target_path resolves to /workspace/<relpath> inside container.
    return _run_semgrep_sandbox(target_path, ...)
```

### DockerRuntime integration

`strix/runtime/docker_runtime.py` already exposes `exec_in_container`
which `terminal_execute` uses. The five OSS-wrapper functions need a
small `_run_via_sandbox(cmd: list[str], cwd: str | None,
timeout: int) -> CompletedProcess` helper that wraps
`exec_in_container` with the same stdout/stderr/returncode contract as
`subprocess.run` returns, so the existing parsing logic in
`semgrep_runner.py` / trivy decorators / etc. doesn't need to change.

### Backwards compatibility

Two failure modes to handle:

1. **Customer runs strix natively (no docker)**, e.g. in a CI runner
   where Docker-in-Docker isn't available. Keep host-subprocess as a
   fallback when `STRIX_SANDBOX_MODE=false` is set OR when the
   DockerRuntime fails to start the sandbox. Surface in the result
   payload's `engine_routing` field which path was taken
   (`"sandbox"` vs `"host"`) so customers can audit reliability.

2. **Bench harness uses host-installed scanners deliberately.**
   `benchmarks/per_target/runner.py` already computes `oss_floor`
   via host-side `shutil.which()` for the *floor measurement*, not
   the *production scan path*. Keep that separation — `oss_floor`
   stays host-side (it's a benchmark-harness helper), the
   `scan_*` wrappers route through sandbox.

## Out of scope (separate PRs)

- **Wrapper config validation in CI.** Add an integration test that
  spins up strix-sandbox, runs `scan_sast` against a known-vuln
  fixture inside the container, and asserts the expected finding lands
  in the result. The current `tests/sast/test_semgrep_runner.py` only
  tests the host path with a mocked subprocess.
- **Signature-DB refresh policy.** Image-build-time bake is the
  simplest, but signatures go stale within weeks. Sketch a sidecar
  `strix-sandbox-refresher` cron that pulls new template / DB
  versions on a daily schedule and either commits an updated image
  or warms a sidecar volume.

## Acceptance criteria

- [ ] `scan_sast`, `scan_sca_lockfiles`, `scan_iac`,
      `scan_container_image`, `scan_nuclei_templates` all route through
      the sandbox container when `STRIX_SANDBOX_MODE=true` (default).
- [ ] Per-finding `engine_routing` recorded (`"sandbox"` / `"host"` /
      `"unavailable"`).
- [ ] No host install required: a fresh macOS / Linux box with only
      `docker` + `strix` (no `brew install …`) runs the full
      per_target benchmark suite and recovers ≥ the `oss_floor`
      `naive_sum` on each code fixture.
- [ ] `STRIX_SANDBOX_MODE=false` continues to work as a host-subprocess
      fallback (CI runners without Docker-in-Docker).
- [ ] `tests/runtime/test_sandbox_oss_routing.py` covers the path-
      translation + stdout-capture contract end-to-end.

## Risks

- **Path translation bugs.** `scan_sast(target_path="/Users/foo/repo")`
  on host needs to become `semgrep /workspace/repo` inside the
  container. The DockerRuntime mount config is the source of truth;
  must thread the mount-prefix info through the wrapper.
- **Performance.** Container-exec adds ~100-300ms per scan. For
  scan_sast (typically 5-60s wall) this is negligible. For tight
  loops, batching multiple wrapper calls into one exec might be
  worth it.
- **Sandbox-image binary drift.** When the Dockerfile bumps semgrep /
  trivy versions, the wrapper version-detection code in
  `semgrep_runner.py` (which currently runs `semgrep --version` on
  host) needs to be sandbox-routed too. Keep this in mind when
  staging the change.
