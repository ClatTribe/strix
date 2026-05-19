# Proposal: strix-sandbox image size reduction

**Date:** 2026-05-19
**Status:** Draft — Tier 1 ready to land in a follow-up PR
**Driver:** PR #359 brought the image to 19.5 GB. That's too large for K8s image-pull limits, CI runner disks, and customer first-pull experience.

## Current state (post PR #359)

`strix-sandbox:fork-recall-bar`, image ID `ad055180165e`, **19.5 GB** (multi-arch, BuildKit attestation manifest included).

Approximate breakdown:

| Layer / component | Size | Notes |
|---|---:|---|
| kalilinux/kali-rolling base + apt packages | ~3-4 GB | Kali ships pre-installed pen-testing arsenal (~1-2 GB) we don't use |
| ZAP (zaproxy via apt) | ~1.5 GB | Java runtime + JAR |
| Python venv (uv sync — litellm, openai, playwright, langchain, …) | ~2-3 GB | |
| **Trivy DB (vuln + java)** | **~3.8 GB** | Pre-populated at build time |
| **Grype DB** | **~1.6 GB** | Pre-populated at build time |
| pipx tools (semgrep, bandit, checkov, arjun, dirsearch, wafw00f) | ~700 MB | |
| Node global packages (retire, eslint, ast-grep, tree-sitter-cli, jshint, js-beautify) | ~800 MB | |
| Tree-sitter parsers (8 languages, full git clones) | ~500 MB | |
| Go binaries (httpx, katana, vulnx, gospider, interactsh) | ~300 MB | Built with `go install` |
| Playwright Chromium browser | ~170 MB | |
| Caido CLI | ~50 MB | |
| Nuclei templates | ~50 MB | 13,060 YAMLs |
| build-essential, gcc, golang-go, libc6-dev, pkg-config | ~1 GB | Only needed at *build* time |
| Image metadata + multi-arch attestation manifest | ~1 GB | BuildKit dual-arch artifacts |

## Reduction tiers

### Tier 1 — easy wins (target: ~14 GB, **~5 GB savings**)

No architectural change. Same tool set, just packaged more efficiently.

1. **Switch base from `kalilinux/kali-rolling:latest` → `debian:bookworm-slim`** (~1.5 GB savings).
   - Kali's pre-installed `nuclei`/`subfinder`/`naabu`/`sqlmap`/`ffuf` packages are useful, but Debian-slim + explicit apt installs gets us the same tools without Kali's other 1.5 GB of pen-testing kitchen-sink.
   - Risk: some kali-specific paths (e.g. `/usr/share/wordlists/`) won't exist; we'd need to install `seclists` explicitly. The Dockerfile already creates `/home/pentester/wordlists` so this is straightforward.

2. **Multi-stage build for Go binaries** (~500 MB savings).
   - Use `golang:1.22-alpine` builder stage to `go install` the projectdiscovery tools.
   - `COPY --from=builder /go/bin/{httpx,katana,vulnx,gospider,interactsh-client} /usr/local/bin/` into final stage.
   - Drop `golang-go` from the runtime image (only needed for compilation).

3. **Multi-stage for compile-only build deps** (~300-500 MB savings).
   - `build-essential`, `gcc`, `libc6-dev`, `pkg-config` only needed when compiling things at build time.
   - Move installation into a builder stage; final stage only has runtime libs.

4. **Drop redundant tools** (~200-300 MB savings, no recall loss):
   - `bandit` — every rule it ships is covered by `semgrep --config p/python` and the `r2c-ci` ruleset. Strix's `scan_sast` already uses semgrep; bandit is dead weight.
   - `wapiti` — overlaps 100% with ZAP baseline. We use ZAP via `terminal_execute`; wapiti is never invoked.
   - `jshint` — eslint+ast-grep cover JS linting better; jshint is unreferenced in any strix tool.

5. **Drop multi-arch attestation manifest from build artifacts** (~500 MB savings, single-arch).
   - Current build emits multi-arch (linux/amd64 + linux/arm64) attestations. Publish per-arch images via `docker buildx --platform linux/amd64 -t strix-sandbox:fork-arm64-X.Y …` and let customers pull only their arch.

**Target after Tier 1**: ~14-15 GB.

### Tier 2 — medium effort (target: ~10 GB, **~5 GB more savings**)

Trade-off: breaks the "single image, fully air-gap-ready out of the box" promise unless we re-engineer deployment.

6. **Move signature DBs to a sidecar volume** (~5 GB savings).
   - Don't bake trivy + grype DBs into the image.
   - Mount a named volume `strix-sandbox-db` at `/home/pentester/.cache/`.
   - First scan downloads DBs (slow but cached); subsequent scans reuse.
   - For air-gap customers: `docker run --rm -v strix-sandbox-db:/db strix-sandbox-db-seeder` populates the volume from a pre-built tarball.
   - Adds one step to air-gap deployment docs (the seeder run); makes the image MUCH smaller (~14 GB → ~10 GB).

7. **Final stage on distroless** (~2-3 GB savings).
   - Multi-stage with `gcr.io/distroless/python3-debian12` (or `chainguard/python:latest`) as the final stage.
   - COPY just `/app`, `/usr/local/bin/{nuclei,trivy,grype,osv-scanner,sqlmap,gitleaks,trufflehog}`, `/home/pentester/.local/...`, the strix package.
   - Tricky: ZAP needs a Java runtime; would need `gcr.io/distroless/java-debian12` as a sidecar OR drop ZAP from the sandbox (covered by nuclei + the deterministic DAST specialists).

**Target after Tier 2**: ~9-10 GB.

### Tier 3 — architectural split (target: ~6-8 GB per image)

8. **Split sandbox into two coordinated images**:
   - **`strix-sandbox-scanner`** (~6 GB): L1 OSS scanners only — nuclei + semgrep + trivy + grype + osv-scanner + checkov + sqlmap + gitleaks + trufflehog + their DBs. No Python venv, no browser, no recon tools.
   - **`strix-sandbox-agent`** (~8 GB): strix Python venv + browser (playwright) + recon Go binaries + caido. Calls into the scanner image via gRPC or shared mount.
   - Each image scales independently in K8s; can be cached separately; scanner image refreshes more often (signature DBs); agent image refreshes less often (Python deps).

**Target after Tier 3**: ~6 GB scanner + ~8 GB agent, ~14 GB total but in two independently-scalable units.

## Recommendation

**Land Tier 1 in a follow-up PR after PR #359 merges.**

Tier 1 is straightforward, doesn't change customer deployment, gets us a 25% size reduction with low risk. Defer Tier 2/3 until a customer surfaces a specific pain point (K8s image-pull-secret quota, CI runner disk pressure, registry cost).

## Acceptance criteria for Tier 1 PR

- [ ] `docker build -f containers/Dockerfile -t strix-sandbox:fork-tier1 .` succeeds.
- [ ] Image size ≤ 15 GB (vs current 19.5 GB).
- [ ] All existing OSS tool smoke tests pass:
  - `nuclei`, `semgrep`, `trivy`, `grype`, `osv-scanner`, `checkov`, `sqlmap`, `gitleaks`, `trufflehog`, ZAP
  - Recon: `httpx`, `katana`, `subfinder`, `naabu`, `ffuf`, `gospider`, `nmap`
  - DBs accessible to `pentester` user at `~/.cache/{trivy,grype}/` and `~/.local/nuclei-templates/`
- [ ] No regression in `strix-runner/docker-compose.yml` example startup time.
- [ ] CI workflow `.github/workflows/benchmarks.yml` updates to use the new image tag.

## Risks

- **Debian-slim missing kali-specific paths.** Strix tools that hardcode `/usr/share/wordlists/` or similar would break. Audit + grep before flipping the base.
- **Multi-stage COPY paths drift.** When the Dockerfile bumps Go or Python versions, the multi-stage source paths need to stay in sync. Add an integration test in CI that verifies all expected binaries are on PATH inside the final image.
- **ZAP retention.** Tier 2 considers dropping ZAP. Verify before doing so that no strix tool (`scan_xss`, `cors_deep_check`, `cookie_jwt_scoping_check`) actually shells to `zap-cli` or `zap-baseline.py`. If they do, keep ZAP.
