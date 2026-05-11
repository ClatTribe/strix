# Wrapper integration contract

Authoritative reference for how a wrapper / SaaS layer (e.g.
[ClatTribe webappsec]) invokes strix as a unit of compute.

This doc is the contract: env vars strix reads, CLI flags it
accepts, output artefacts it emits, caches it touches. If you
change any of these surfaces in code, update this doc in the
same PR.

For a runnable starter that implements the contract, see
[`examples/strix-runner/`](../examples/strix-runner/).

---

## TL;DR

Strix is a one-shot CLI process. The wrapper's job is to spawn it
in an isolated environment, pass the right env vars, and consume
the structured artefacts it writes to disk on exit.

| Concern | Surface |
|---|---|
| What to scan | `-t / --target` (repeatable) |
| How aggressively | `-m / --scan-mode {quick,standard,deep}` (default `deep`) |
| Stop the agent looping | `--max-cost USD` (env `STRIX_MAX_COST_USD`), exits **code 3** on breach |
| Where output lands | `cwd/strix_runs/<run_id>/` (chdir per scan; **not** a flag) |
| Threat-intel cache | `STRIX_THREAT_INTEL_CACHE` env var (shared SQLite) |
| LLM provider | `STRIX_LLM` (model name) + `LLM_API_KEY` |
| Inner sandbox | Default ON via Docker-in-Docker; opt out with `STRIX_SANDBOX_MODE=false` |
| Headless / non-interactive | `-n / --non-interactive` |
| Per-tenant isolation | Wrapper's job — one process per scan, per-tenant API key, per-tenant output prefix |

---

## 1. CLI contract

Entry point: `strix` (defined in `pyproject.toml` →
`strix.interface.main:main`). The full argparse parser lives at
[`strix/interface/main.py`](../strix/interface/main.py).

### Required

| Flag | Type | Notes |
|---|---|---|
| `-t / --target` | repeatable | URL, IP, domain, or local path. `action="append"` — pass `-t a -t b` for paired-asset scans (web + code, IP + service). |
| `STRIX_LLM` (env) | required | litellm-format model name, e.g. `anthropic/claude-opus-4`, `openai/gpt-5.4`. Strix exits at startup if unset. |

### Headless / wrapper-friendly

| Flag | Purpose |
|---|---|
| `-n / --non-interactive` | No TTY prompts; required for background workers. Implied by `--quiet`. |
| `--quiet` | Sets `STRIX_QUIET=1` + forces `-n`. Pipes-only logs (stdout JSONL). |
| `--config <path>` | Override `~/.strix/cli-config.json` for per-tenant config bundles. |

### Scan scope / depth

| Flag | Default | Notes |
|---|---|---|
| `-m / --scan-mode` | `deep` | `quick` (~5 min, <$0.50), `standard` (~15 min, <$2), `deep` (~30 min, <$5). Wrapper should expose this as a plan-tier knob. |
| `--scope-mode` | `auto` | `auto` / `diff` / `full`. `diff` triggers Phase 7.3 diff-aware SAST. |
| `--diff-base` | — | Git ref to diff against (e.g. `origin/main`). Used with `--scope-mode diff`. |
| `--branch` | — | Repo clone ref for `repository` targets. |
| `--exclude-path` | repeatable | Glob to skip (e.g. `--exclude-path 'node_modules/**'`). Forwarded as `STRIX_EXCLUDE_PATHS`. |
| `--rate-limit <qps>` | — | Outbound QPS cap. Forwarded as `STRIX_RATE_LIMIT`. |

### Cost / budget (the wrapper-critical knob)

Both flags enforce hard caps; strix exits **code 3**
(`EXIT_BUDGET_EXCEEDED`) on breach. Findings written up to the
breach remain in `vulnerabilities.json`.

| Flag | Env equivalent | Effect |
|---|---|---|
| `--max-cost <USD>` | `STRIX_MAX_COST_USD` | LLM spend cap. `0` / unset = unlimited. |
| `--max-input-tokens <N>` | `STRIX_MAX_INPUT_TOKENS_RUN` | Total input-token cap. |

Wrapper recipe: set both per scan based on the tenant's plan
tier. E.g.

```bash
strix -n -t https://example.com -m standard \
  --max-cost 2.50 \
  --max-input-tokens 1500000
```

Implementation: [`strix/llm/run_budget.py`](../strix/llm/run_budget.py).
Caps are re-read every LLM call; the agent is interrupted on
breach.

### Auth pass-through (DAST targets behind login)

| Flag | Env | Forwarded by | Notes |
|---|---|---|---|
| `--auth-cookie 'k=v; k2=v2'` | `STRIX_AUTH_COOKIE` | HTTP safety proxy | Never logged. |
| `--auth-bearer <token>` | `STRIX_AUTH_BEARER` | same | Never logged. |
| `--auth-basic 'user:pass'` | `STRIX_AUTH_BASIC` | same | Never logged. |
| `--header 'Name: Value'` | `STRIX_HEADERS` | same | Repeatable, joined with `\n`. |

### Crawl seeds

| Flag | Env | Notes |
|---|---|---|
| `--seed-url` | `STRIX_SEED_URLS` | Repeatable; pre-seed the crawler. |
| `--openapi <URL>` | `STRIX_OPENAPI_URL` | Pull an OpenAPI/Swagger doc; expand into endpoints. |

### Compliance export

| Flag | Notes |
|---|---|
| `--export-format <p>` | Repeatable. `{vanta, drata, hyperproof, secureframe, servicenow, generic}`. Writes `grc_export_<platform>.json` next to `vulnerabilities.json`. |
| `--compliance-pack <dir>` | Drop a full signed compliance pack at `<dir>/<run_id>/`. |
| `--feedback-from <path>` | Sets `STRIX_FEEDBACK_FROM`; supervised-FP feedback corpus for severity calibration. |

### Modes that change the engine surface

| Flag | Env | Meaning |
|---|---|---|
| `--dns-only` | `STRIX_DNS_ONLY=1` | Domain target → DNS-only (no HTTP probes). |
| `--surface-map-only` | `STRIX_SURFACE_MAP_ONLY=1` | Recon + surface-map only; no specialist scans. |
| `--vendor-mode` | `STRIX_VENDOR_MODE=1` | Black-box vendor-risk assessment scope. |
| `--preflight / --no-preflight` | — | Reachability + auth probe before the agent loop. Default on. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed (findings may or may not exist). |
| `1` | Configuration error (bad flags, missing `STRIX_LLM`, target unresolvable). |
| `2` | Argparse error (malformed CLI). |
| `3` | **`EXIT_BUDGET_EXCEEDED`** — hit `--max-cost` or `--max-input-tokens`. Partial findings written. |
| `>3` | Unexpected runtime error. Inspect `strix_runs/<run_id>/events.jsonl` for the trail. |

The wrapper should treat **code 3 as a non-error** (capped successfully, partial results valid) and surface the cap-breach in the UI rather than retrying.

---

## 2. Environment variables (the full table)

### LLM / model selection (required)

| Var | Required | Default | Read at |
|---|---|---|---|
| `STRIX_LLM` | **yes** | — | `strix/config/config.py` |
| `LLM_API_KEY` | yes (provider-dependent) | — | Read by litellm via strix Config |
| `ANTHROPIC_API_KEY` | **for Anthropic models** | — | litellm fallback (see below) |
| `OPENAI_API_KEY` | **for OpenAI models** | — | litellm fallback (see below) |
| `GEMINI_API_KEY` | **for Google AI Studio models (`gemini/…`)** | — | litellm fallback (see below) |
| `GOOGLE_API_KEY` | Vertex AI / alternate Gemini path | — | litellm fallback |
| `GOOGLE_APPLICATION_CREDENTIALS` | for Vertex AI (`vertex_ai/…`) | — | service-account JSON path |
| `LLM_API_BASE` / `OPENAI_API_BASE` / `LITELLM_BASE_URL` / `OLLAMA_API_BASE` | no | — | Proxy / self-hosted LLM endpoints |
| `STRIX_REASONING_EFFORT` | no | — | Anthropic reasoning-effort hint |
| `STRIX_LLM_MAX_RETRIES` | no | — | Per-call retry cap |
| `STRIX_LLM_FAILOVER` | no | — | Comma-separated fallback model list |
| `STRIX_TOOL_CALL_FORMAT` | no | `xml` | `xml` or `native` |
| `LLM_TIMEOUT` | no | — | Per-call timeout seconds |

> **Set BOTH `LLM_API_KEY` AND the provider-specific env var.**
> Strix's Config layer reads `LLM_API_KEY`, but litellm's
> per-provider adapters also fall back to their own canonical env
> var directly when the configured key isn't threaded through the
> call path. Empirically seen: `LLM_API_KEY` alone fails with
> `litellm.AuthenticationError: Missing <Provider> API Key`.
> Safest pattern is to set both to the same value.
>
> Provider → env-var mapping:
>
> | Provider / model prefix | Provider env var |
> |---|---|
> | `anthropic/claude-…`            | `ANTHROPIC_API_KEY` |
> | `openai/gpt-…` / Azure          | `OPENAI_API_KEY` |
> | `gemini/gemini-…` (AI Studio)   | `GEMINI_API_KEY` |
> | `vertex_ai/gemini-…` (Vertex)   | `GOOGLE_APPLICATION_CREDENTIALS` (service-account JSON) |
> | `bedrock/…`                     | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_REGION_NAME` |
> | `ollama/…`                      | none (set `OLLAMA_API_BASE`) |
>
> Example for Gemini 2.5 Flash via Google AI Studio:
>
> ```bash
> STRIX_LLM=gemini/gemini-2.5-flash
> LLM_API_KEY=<your-google-ai-studio-key>
> GEMINI_API_KEY=<your-google-ai-studio-key>   # same value
> ```
>
> Example for Anthropic:
>
> ```bash
> STRIX_LLM=anthropic/claude-opus-4
> LLM_API_KEY=<sk-ant-…>
> ANTHROPIC_API_KEY=<sk-ant-…>   # same value
> ```

### Cost / budget

| Var | Default | Effect |
|---|---|---|
| `STRIX_MAX_COST_USD` | unlimited | Run-level LLM spend cap. Breach → exit 3. |
| `STRIX_MAX_INPUT_TOKENS_RUN` | unlimited | Run-level input-token cap. Breach → exit 3. |

### Output paths

| Var | Default | Notes |
|---|---|---|
| `STRIX_RUN_DIR` | derived from `cwd/strix_runs/<run_id>/` | Override the run-dir inside the sandbox. Wrapper rarely needs to set this — chdir is the idiomatic approach. |

### Threat-intel cache

| Var | Default | Notes |
|---|---|---|
| `STRIX_THREAT_INTEL_CACHE` | `~/.cache/strix/threat_intel.db` | SQLite path. **Single most important wrapper knob** — mount a shared read-only path so every scan worker hits the same pre-seeded cache. |

### Sandbox / runtime

| Var | Default | Notes |
|---|---|---|
| `STRIX_SANDBOX_MODE` | `true` (DinD) | `false` to disable inner Docker sandbox — strix runs in-process. See §6. |
| `STRIX_IMAGE` | `ghcr.io/usestrix/strix-sandbox:0.1.13` | Override the inner-sandbox image. **Use this for fork-built images** (e.g. `strix-sandbox:fork-<sha>`). See §6 "Fork-built sandbox images". |
| `STRIX_RUNTIME_BACKEND` | `docker` | Runtime driver. `docker` today; other backends are reserved. |
| `STRIX_SANDBOX_EXECUTION_TIMEOUT` | `120` | Seconds — inner-sandbox per-command timeout. |
| `STRIX_SANDBOX_CONNECT_TIMEOUT` | `10` | Seconds — inner-sandbox bring-up timeout. |
| `STRIX_PARALLEL_TOOL_DISPATCH` | `1` | Specialists run concurrently. Set to `0` for serial debugging. |
| `STRIX_AGENT_ARCHITECTURE` | — | `single_lead` to opt into the single-lead architecture (per proposal doc). |
| `STRIX_INHERIT_CONTEXT_DEFAULT` | — | Sub-agent context inheritance default. |
| `STRIX_DISABLE_BROWSER` | — | Skip the Chrome / playwright tool surface. |
| `DOCKER_HOST` | — | Standard Docker env. Used when sandbox spawns its inner container. |

### Crawl / scope (set by CLI flags)

| Var | Set by | Notes |
|---|---|---|
| `STRIX_DNS_ONLY` | `--dns-only` | — |
| `STRIX_SURFACE_MAP_ONLY` | `--surface-map-only` | — |
| `STRIX_VENDOR_MODE` | `--vendor-mode` | — |
| `STRIX_QUIET` | `--quiet` | — |
| `STRIX_AUTH_COOKIE` / `_BEARER` / `_BASIC` / `_HEADERS` | `--auth-*` / `--header` | Never logged. |
| `STRIX_EXCLUDE_PATHS` | `--exclude-path` | Newline-separated glob list. |
| `STRIX_RATE_LIMIT` | `--rate-limit` | QPS cap. |
| `STRIX_SEED_URLS` | `--seed-url` | Newline-separated URL list. |
| `STRIX_OPENAPI_URL` | `--openapi` | — |
| `STRIX_FEEDBACK_FROM` | `--feedback-from` | — |

### Telemetry / signing

| Var | Default | Notes |
|---|---|---|
| `STRIX_SIGNING_KEY` | — | Path to PEM private key for run-signature. Empty = no signing. |
| `STRIX_SIGNING_CMD` | — | Alternative: shell command that produces a signature on stdin. |
| `STRIX_AUDIT_LOG_RETENTION_DAYS` | `90` | Compliance window. |
| `STRIX_SCAN_CADENCE_DAYS` | `90` | Compliance attestation cadence. |
| `STRIX_COVERAGE_MATRIX_PATH` | — | Override path to the bundled coverage matrix. |
| `STRIX_EVENT_STREAM_MAX` | `10000` | Ring buffer size for `event_stream.jsonl`. |
| `STRIX_SANITIZER_DISABLED` | — | Disable output sanitisation (debugging only). |
| `STRIX_TELEMETRY` / `_OTEL_TELEMETRY` / `_POSTHOG_TELEMETRY` | — | Opt-in telemetry sinks. |
| `TRACELOOP_BASE_URL` / `_API_KEY` / `_HEADERS` | — | OTEL collector endpoint. |

### Threat-intel feeds (background refresher)

The refresher (`python -m strix.threat_intel.refresh`) is a
**separate** invocation from scan runs. Run it on a cron / sidecar
schedule (every 1–6 h) and let scan workers consume the resulting
SQLite via `STRIX_THREAT_INTEL_CACHE`.

| Var | Required for | Default |
|---|---|---|
| `GITHUB_TOKEN` | GHSA feed (60 req/h unauth → useless) | — |
| `NVD_API_KEY` | NVD feed (higher rate limit) | — |
| `STRIX_KEV_URL` | KEV catalog URL override | CISA default |
| `STRIX_KEV_DISABLED` | Disable KEV polling | — |

### Per-tool API keys (all optional, graceful-degrade)

Tools that hit third-party intelligence APIs degrade gracefully if
their key is missing. Wrappers offering "premium intel" tiers set
these per-tenant.

| Var | Tool surface |
|---|---|
| `STRIX_VT_KEY` | VirusTotal |
| `STRIX_GSB_KEY` | Google Safe Browsing |
| `STRIX_ABUSEIPDB_KEY` | AbuseIPDB |
| `STRIX_OTX_KEY` | AlienVault OTX |
| `STRIX_GREYNOISE_KEY` | GreyNoise |
| `STRIX_SHODAN_KEY` | Shodan |
| `STRIX_CENSYS_API_ID` / `_API_SECRET` | Censys |
| `STRIX_SECURITYTRAILS_KEY` | SecurityTrails |
| `STRIX_VIRUSTOTAL_KEY` | (alternate VT path) |
| `STRIX_BING_KEY` | Bing search |
| `STRIX_VIEWDNS_KEY` | ViewDNS recon |
| `STRIX_NVD_KEY` | NVD tool-side |
| `STRIX_GITHUB_TOKEN` | Code-search / sigma-lookup tools |
| `STRIX_GITLAB_TOKEN` | GitLab recon |
| `PERPLEXITY_API_KEY` | Web-search tool |
| `CAIDO_API_TOKEN` | Caido proxy integration |

### OOB infrastructure (blind-SSRF / OOB callbacks)

Required only if running specialists that need OOB callbacks
(`scan_blind_ssrf`, OOB-based XSS probes).

| Var | Default | Notes |
|---|---|---|
| `STRIX_OOB_BACKEND` | — | `local` or `interactsh` |
| `STRIX_OOB_LOCAL_HOST` | `127.0.0.1:8443` | Local OOB listener |
| `STRIX_OOB_PUBLIC_HOST` | — | Public DNS pointing to the listener |
| `STRIX_OOB_INTERACTSH_SERVER` | — | Self-hosted interactsh |
| `STRIX_OOB_REBIND_HOST` | — | DNS-rebinding test host |

For a wrapper running scans in a private K8s cluster, you'll
typically run a single shared interactsh server in the cluster
and point all workers at it.

---

## 3. Output artefacts

Strix writes everything to `<cwd>/strix_runs/<run_id>/`. The
**`<cwd>`** is the wrapper's choice — chdir per scan to a
tenant-scoped scratch directory before invoking strix.

### Canonical layout

```
strix_runs/<run_id>/
├── events.jsonl                    append-only agent-loop event stream
├── trajectory.jsonl                RLHF trajectory (training data shape)
├── run_meta.json                   ALWAYS — run metadata, compliance posture, vendor-risk
├── run_summary.json                end-of-run summary (counts, cost, duration)
├── run.signature.json              when STRIX_SIGNING_KEY is set
├── checks_summary.json             per-specialist pass/fail
├── coverage.json                   methodology coverage matrix
├── coverage_attestation.json       signed coverage claim
├── penetration_test_report.md      human-readable PT report
│
├── vulnerabilities.json            ★ primary findings artefact
├── vulnerabilities.csv             ★ findings index (wrapper-friendly)
├── vulnerabilities/<id>.md         ★ one markdown per finding
│
├── finding_chains.json             §4a v2 — cross-category chains
├── compliance_evidence.json        §4b — SOC 2 / ISO / PCI / ASVS evidence
├── behavioural_baselines.jsonl     Phase 9.2 — per-endpoint baselines
├── event_stream.jsonl              Phase 9.1 — threat-intel ring buffer
│
├── surface_map.json                domain / IP recon output
├── webapp_surface_map.json         web-app endpoint inventory
│
├── grc_export_<platform>.json      one per --export-format value
└── *.sarif                         when scan_sast(sarif_output_path=...) used
```

### What the wrapper should ingest

| Artefact | Wrapper UI surface |
|---|---|
| `vulnerabilities.json` | Findings inbox (Phase B) |
| `vulnerabilities.csv` | Bulk export, BI tooling |
| `finding_chains.json` | Chain-card UI (Phase B) |
| `compliance_evidence.json` | Compliance tab (Phase C) |
| `event_stream.jsonl` | Real-time KEV banner / behavioural tab (Phase B/F) |
| `behavioural_baselines.jsonl` | Endpoint reference panel (Phase B) |
| `*.sarif` | GitHub Code Scanning integration (Phase A PR-bot) |
| `grc_export_*.json` | GRC tab — pipe straight to Vanta/Drata/etc. |
| `run_meta.json` + `run_summary.json` | Scan-history table |
| `penetration_test_report.md` | "Download report" button |

The wrapper should treat `vulnerabilities.json` as the source of
truth and the per-finding `.md` files as render-time helpers.

### Stable schema

Every JSON artefact carries a top-level `schema_version` integer.
Wrappers should gate on it — increment in strix when fields are
removed or renamed (additions are non-breaking by convention).

Current schemas:

- `vulnerabilities.json` → schema v1
- `finding_chains.json` → schema v1
- `compliance_evidence.json` → schema v1

---

## 4. Caches (what to mount, what to scope per-tenant)

### Shared, read-only — mount the same path into every scan worker

| Path | Override env | What lives there | TTL |
|---|---|---|---|
| `~/.cache/strix/threat_intel.db` | `STRIX_THREAT_INTEL_CACHE` | KEV / GHSA / EPSS / NVD / OSSF / popular-package corpus | refresh on cron, scans read snapshot |
| `~/.cache/strix/nuclei_templates/` | `STRIX_NUCLEI_TEMPLATES_DIR` | Nuclei template bundle | 24 h |

Pattern: a separate refresher job (`python -m
strix.threat_intel.refresh`) runs every 1–6 h, writes the SQLite
to a shared volume / S3-blob. Per-scan workers mount it
**read-only**. All tenants benefit from the same seed without
each one paying the GHSA rate-limit toll.

### Per-tenant, write-through — scope by mounting tenant-specific paths

| Path | What lives there | Sensitivity |
|---|---|---|
| `~/.strix/cli-config.json` | User-supplied CLI config defaults | Tenant config — per-tenant mount |
| `~/.strix/{tool}_cache/` (~12 dirs) | Per-tool intel cache (VT / NVD / OTX / etc.) | Tenant-scoped — keys differ per tenant |
| `~/.strix/feedback.jsonl` | FP-feedback corpus for severity calibration | Tenant-scoped — different tenant = different ground truth |
| `~/.strix/kev_cache.json` + `kev_diff_snapshot.json` | KEV poll snapshots | Can be shared (public data) |

For the per-tool caches, the simplest pattern is an
emptyDir-per-pod that gets discarded when the scan exits. Cost:
each scan re-fetches its own intel. Benefit: zero risk of one
tenant's API-key results bleeding into another's.

For high-traffic tenants, mount a tenant-scoped persistent volume
at `~/.strix/` (or set per-tool env vars that point caches at
S3-backed FUSE / EFS / similar).

---

## 5. External dependencies the runner image needs

### Required on the host (no graceful degrade)

| Dependency | Why | Where strix expects it |
|---|---|---|
| **Docker CLI** | Spawn the inner sandbox (`STRIX_SANDBOX_MODE=true`) | `shutil.which("docker")` at startup |
| **`ghcr.io/usestrix/strix-sandbox:0.1.13`** image | The inner sandbox runtime image | Auto-pulled at scan start |
| **Git** | Clone `repository` targets, compute diffs for `--scope-mode diff` | `subprocess.run(["git", …])` |

The Docker requirement is the single biggest wrapper-side
architecture decision. See §6.

### Optional (graceful degrade)

| Dependency | Used by | Effect when missing |
|---|---|---|
| **Semgrep** | `scan_sast` | Returns `engine_available: false`, 0 findings. Scan still completes. |
| **Nuclei** | `nuclei_runner` | Skipped; `success=False` returned. |
| **Gitleaks** | `secrets_scan` | Skipped. |
| **interactsh-client** | OOB specialists | Skipped; OOB tests no-op. |

**Recommended baseline runner image:** `python:3.12-slim` +
`pip install strix-agent semgrep` + system packages
`git docker-cli` (or `docker.io` on Debian). That covers SCA /
SAST / IaC / DAST without OOB infrastructure. Nuclei + interactsh
are opt-in.

---

## 6. The sandbox-mode decision

Strix's default execution model is **Docker-in-Docker (DinD)**:

1. Wrapper invokes `strix -n -t <target>` in a pod/container.
2. Strix at startup pulls `ghcr.io/usestrix/strix-sandbox:0.1.13`.
3. Strix spawns the sandbox container, executes the agent loop
   inside it, propagates results back to the outer cwd.

This protects the **outer** runtime from anything the agent loop
does — file writes, shell-outs, network calls — all happen inside
the inner sandbox.

For a multi-tenant wrapper running in K8s, this is awkward
because DinD requires either:

### Option A — Mount host Docker socket into each pod

```yaml
volumeMounts:
  - name: docker-sock
    mountPath: /var/run/docker.sock
volumes:
  - name: docker-sock
    hostPath: { path: /var/run/docker.sock }
```

**Pros:** simplest, no nested-runtime overhead.
**Cons:** mounting `/var/run/docker.sock` is effectively
giving the pod root on the host. A compromised scan pod
can spawn arbitrary containers. **Not multi-tenant-safe.**

### Option B — Disable inner sandbox

Set `STRIX_SANDBOX_MODE=false`. Strix executes the agent loop
directly in the outer container, with no inner Docker layer.

```yaml
env:
  - name: STRIX_SANDBOX_MODE
    value: "false"
```

**Pros:** no Docker socket, no nesting, simpler IAM.
**Cons:** the outer pod's filesystem / network is exposed to
the agent loop. You're trusting the **outer container's**
sandboxing (K8s pod-security-standards, seccomp, network
policy) to be your only layer of defense.

**This is the right choice for most multi-tenant wrappers.**
The agent loop is bounded by the cost cap (§1) and the
specialists already run with strict tool-surface restrictions.
The wrapper's K8s pod is a perfectly fine outer boundary.

### Option C — Nested-isolation runtime (gVisor / Kata / sysbox / Firecracker)

Use a runtime that supports nested containers without exposing
the host. `sysbox` is the most operationally simple — it lets
DinD work safely inside an unprivileged container.

```yaml
spec:
  runtimeClassName: sysbox-runc
  # ... no docker-sock mount needed, DinD just works
```

**Pros:** strix's default sandbox model works as designed; clean
nested isolation.
**Cons:** sysbox / Kata / Firecracker require cluster-level
infrastructure investment. Most teams don't have it on day 1.

### Recommendation table

| Stage | Recommendation |
|---|---|
| Local dev / `docker-compose` demo | DinD via host socket (Option A). Single tenant, no real concern. |
| First production deploy, single-tenant or trusted-multi-tenant | `STRIX_SANDBOX_MODE=false` (Option B). Lean on K8s pod boundaries. |
| Real multi-tenant / untrusted DAST targets | sysbox runtimeClass (Option C), or Firecracker if you need VM-grade isolation. |

The example in [`examples/strix-runner/`](../examples/strix-runner/)
ships with **two profiles**: the default uses Option B (no
inner sandbox); a `--profile sandbox` variant wires Option A
(DinD + custom `STRIX_IMAGE`). Switching between them is one
env-var flip.

### Fork-built sandbox images

Production deployments typically build their own sandbox image
rather than pulling `ghcr.io/usestrix/strix-sandbox:0.1.13`
directly — pinned-fork builds, additional toolchain, internal
registry, etc. The override knob is **`STRIX_IMAGE`**.

Naming convention used in our internal builds:

```
strix-sandbox:fork-<short-sha-of-fork-tip>
strix-sandbox:fork-latest                  # mutable alias
```

Wrapper-side usage:

```yaml
# K8s Pod spec
env:
  - name: STRIX_SANDBOX_MODE
    value: "true"
  - name: STRIX_IMAGE
    value: "registry.internal/strix-sandbox:fork-4f3f93c"
  # Mount Docker socket OR run with sysbox runtime class
volumes:
  - name: docker-sock
    hostPath: { path: /var/run/docker.sock }
volumeMounts:
  - name: docker-sock
    mountPath: /var/run/docker.sock
```

```bash
# docker-compose
STRIX_IMAGE=strix-sandbox:fork-4f3f93c \
  docker compose --profile sandbox \
  -f examples/strix-runner/docker-compose.yml up
```

Two pre-conditions for it to work:

1. The image is available where the worker can `docker pull` it
   (or it's already local — `docker images` shows the tag).
2. The wrapper has Docker socket access (Option A) or is running
   under a nested-isolation runtime (Option C). Plain
   `STRIX_SANDBOX_MODE=true` without one of those will fail at
   sandbox spawn.

Pinning the fork SHA into the tag (rather than `:latest`) gives
the wrapper a reproducible scan environment — re-running an old
scan against the same fork-image tag produces the same agent
behaviour modulo external feed drift.

---

## 7. Scaling pattern (multi-tenant K8s)

Once Option B / C is the runtime, the scaling pattern is the
standard "job queue + autoscaled worker pool":

```
wrapper API ──POST /scans──> queue ──> worker pool ──> strix CLI
                              │
                              ├── per-tenant FIFO (fair-share)
                              └── per-tenant concurrency cap
```

| Concern | Wrapper-side mechanism |
|---|---|
| Fair-share across tenants | SQS per-tenant queues, or Temporal task queue routing |
| Concurrency cap per tenant | Token-bucket in the orchestrator; reject `POST /scans` over cap |
| Cost cap per scan | Wrapper passes `--max-cost USD` per scan based on tenant plan |
| Cost accounting per tenant | Each scan uses a tenant-scoped `LLM_API_KEY` (BYOK), or wrapper aggregates strix's `run_summary.json` cost numbers |
| Output isolation | Per-scan pod's cwd is `s3://strix-artifacts/<tenant_id>/<scan_id>/` (FUSE-mounted) or a node-local emptyDir uploaded post-scan |
| Threat-intel sharing | One refresher CronJob writes to a shared RO volume; all scan pods mount it |

### One-tenant docker-compose starter

Spin up the minimum-viable version locally:

```bash
cd examples/strix-runner
docker compose up --build
# in another terminal:
curl -X POST localhost:8080/scans \
  -H "content-type: application/json" \
  -d '{"target":"https://demo.testfire.net","scan_mode":"quick"}'
```

This implements: one Redis broker, one Celery worker invoking
strix as a subprocess, a FastAPI front-end with `POST /scans` +
`GET /scans/{id}`. Single tenant, no per-tenant isolation —
exactly the floor to build up from.

To grow toward multi-tenant K8s:

1. **Replace Celery with K8s Jobs.** Each `POST /scans` creates
   a tenant-prefixed K8s Job; worker pool becomes the cluster's
   autoscaler.
2. **Replace local volume with S3 (or EFS) for outputs.**
   Tenant-prefix the bucket key.
3. **Add per-tenant LLM API keys** as K8s Secrets injected per
   Job; cost accounting falls out of the LLM provider's
   per-key usage API.
4. **Mount the shared threat-intel SQLite as RO** in every Job.
5. **Run the threat-intel refresher** as a separate K8s
   CronJob, writing to the same shared volume.

---

## 8. Failure modes & their wrapper-side mitigations

| Failure | Symptom | Wrapper-side handling |
|---|---|---|
| `STRIX_LLM` unset | Exits **1** at startup | Reject `POST /scans` at the API layer if no tenant LLM is configured |
| Bad / expired `LLM_API_KEY` | Exits **1** after a few retries | Surface "API key invalid for tenant X" in the wrapper inbox |
| Hit `--max-cost` | Exits **3** with partial findings in `vulnerabilities.json` | Display "scan capped at $X — N findings collected" in UI; **don't auto-retry** |
| Sandbox image pull fails (Option A/C) | Exits non-zero at startup | Pre-pull the sandbox image at worker boot; circuit-break |
| Semgrep missing | Scan continues, `engine_available: false` in tool_metadata | Show "Install Semgrep" CTA in SAST tab |
| Target unreachable | Exits 1 if preflight enabled, otherwise specialists report `unreachable` | Display "target not reachable from scanner network — check firewall rules" |
| Worker pod dies mid-scan | Outer K8s sees Job failure | Wrapper retries with a NEW scan_id; partial outputs from the dead pod are discarded (no resumable scans today) |
| Run dir collision | Strix appends timestamp suffix to run_id; doesn't overwrite | n/a — handled by strix |

---

## 9. Versioning & breaking-change policy

This doc + strix's CLI / env / artefact surface are **versioned
together with strix itself.** Bumping any of:

- A schema_version on an artefact
- Renaming or removing an env var
- Renaming or removing a CLI flag

requires:

1. Bumping the engine version
2. Updating this doc in the same PR
3. Calling out the change in `AISecurityEngineerUX.md` §13a
   (the wrapper change-log)

Adding new flags / env vars / artefact fields is non-breaking
(wrappers should ignore unknown fields).

---

## 10. Open contract gaps (track here)

Items where the engine doesn't yet expose what wrappers need.
Each should be a tracked issue.

| Gap | Wrapper workaround today |
|---|---|
| No `--output-dir` flag (run dir is `cwd/strix_runs/...`) | chdir to tenant-scratch before invoking |
| No `--tenant-id` flag for log/event tagging | Wrap strix in a log-prefixer subprocess |
| No resumable scans | Re-run on worker failure with new run_id |
| `~/.strix/` caches are global per UID | Run each scan as a unique UID, or mount `~/.strix` as a per-scan emptyDir |
| Run-signature key (`STRIX_SIGNING_KEY`) is a path — no in-memory mode | Mount as a tmpfs secret |

When you close one of these gaps in code, delete the row.
