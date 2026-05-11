# strix-runner — example wrapper integration

A minimal, runnable reference for invoking strix as a unit of
compute behind a small HTTP control plane. **Single tenant, no
real isolation.** Designed to be the smallest scaffolding a real
wrapper (e.g. ClatTribe webappsec) builds up from.

The full integration contract lives at
[`docs/wrapper-integration.md`](../../docs/wrapper-integration.md).
Read that first if you're wiring strix into a real system. This
example is the implementation-flavoured companion.

## What's here

```
examples/strix-runner/
├── Dockerfile             python:3.12-slim + strix + semgrep + celery + fastapi
├── docker-compose.yml     redis + worker + api + refresher (profile)
├── worker.py              Celery task that invokes `strix` CLI
├── api.py                 FastAPI POST /scans + GET /scans/{id}
└── README.md              this file
```

## Quickstart

Requires Docker + Docker Compose v2. From the **repo root** (not
this directory — the build context is `../..`):

```bash
# 1. (Optional but recommended) set your LLM key in .env. Pick ONE
#    provider block below. **Set BOTH `LLM_API_KEY` and the
#    provider-specific env var** to the same value — litellm's
#    per-provider adapter falls back to its own canonical name,
#    and strix's `LLM_API_KEY` alone isn't always threaded through.
#    See docs/wrapper-integration.md §2 for the full provider table.

# --- Anthropic ---
cat > .env <<'EOF'
STRIX_LLM=anthropic/claude-opus-4-5
LLM_API_KEY=sk-ant-...
ANTHROPIC_API_KEY=sk-ant-...
GITHUB_TOKEN=ghp_...     # for the threat-intel refresher
EOF

# --- Google AI Studio (Gemini) ---
# cat > .env <<'EOF'
# STRIX_LLM=gemini/gemini-2.5-flash
# LLM_API_KEY=<your-google-ai-studio-key>
# GEMINI_API_KEY=<your-google-ai-studio-key>
# GITHUB_TOKEN=ghp_...
# EOF

# --- OpenAI ---
# cat > .env <<'EOF'
# STRIX_LLM=openai/gpt-4o
# LLM_API_KEY=sk-...
# OPENAI_API_KEY=sk-...
# GITHUB_TOKEN=ghp_...
# EOF

# 2. Seed the threat-intel cache (one-shot; ~5–15 min)
docker compose --profile refresh -f examples/strix-runner/docker-compose.yml up refresher

# 3. Bring up the worker pool + API
docker compose -f examples/strix-runner/docker-compose.yml up --build -d

# 4. Submit a scan
curl -X POST localhost:8080/scans \
  -H "content-type: application/json" \
  -d '{"target":"https://demo.testfire.net","scan_mode":"quick"}'
# → {"scan_id":"abc-123","status":"queued"}

# 5. Poll until ready
watch -n 5 'curl -s localhost:8080/scans/abc-123 | jq .state'

# 6. Read the structured findings
curl -s localhost:8080/scans/abc-123/artefacts/vulnerabilities.json | jq
```

## How it implements the contract

| Contract surface (per `docs/wrapper-integration.md`) | Implementation |
|---|---|
| CLI flags: `-n`, `--quiet`, `-t`, `-m`, `--max-cost`, `--max-input-tokens` | `worker.py:run_scan` builds the command line |
| `STRIX_LLM` + `LLM_API_KEY` | docker-compose env, read from your `.env` |
| `STRIX_THREAT_INTEL_CACHE` | Set on every service to `/home/strix/cache/threat_intel.db` |
| Shared RO threat-intel cache | `threat-intel-cache` named volume, mounted `:ro` into workers |
| Per-scan run dir is `cwd/strix_runs/<run_id>/` | Worker `chdir`s to `<RUN_STORAGE>/<tenant_id>/<scan_id>/` before invoking strix |
| Exit code 3 = budget capped (not a real error) | `worker._classify_exit` returns `"budget_capped"`, not `"error"` |
| `STRIX_SANDBOX_MODE=false` (Option B from §6) | Set in the Dockerfile + compose env |
| Structured artefact ingest | `worker._index_artefacts` builds a flat manifest the wrapper can persist |

## Production migration path

This compose file is a single-tenant demo. Here's what changes
when you move to a real multi-tenant K8s deployment.

### Replace Celery + Redis with K8s Jobs

```
POST /scans
   │
   ▼
   Wrapper API (FastAPI)
   │
   ▼
   1. Auth → tenant_id
   2. Check tenant quota / concurrency
   3. Allocate from per-tenant cost budget
   4. kubectl create -f <generated Job spec>
       │
       ▼
       K8s Job
       │
       ├── runs the strix-runner image
       ├── one Pod per scan
       └── outputs uploaded post-scan or via FUSE mount
```

The `worker.py` Celery task becomes a K8s Job template. Most of
the logic (cmd construction, env mapping, artefact indexing)
ports directly — replace `subprocess.run` with a Job that has
strix as its `command:` and let K8s manage the lifecycle.

### Per-tenant LLM key

In the compose example, the worker uses a single global
`LLM_API_KEY`. In production:

```yaml
env:
  - name: LLM_API_KEY
    valueFrom:
      secretKeyRef:
        name: tenant-{{tenant_id}}-llm-key
        key: api-key
```

Cost accounting falls out of the LLM provider's per-key usage API
(Anthropic console, OpenAI dashboard, etc.).

### Per-tenant output storage

The `run-artifacts` volume becomes an S3 bucket with tenant
prefixing:

```python
# In a real wrapper, after the scan completes:
s3.upload_file(
    Filename=f"{run_dir}/vulnerabilities.json",
    Bucket="strix-artefacts",
    Key=f"{tenant_id}/{scan_id}/vulnerabilities.json",
    ExtraArgs={"ServerSideEncryption": "aws:kms",
               "SSEKMSKeyId": f"alias/tenant-{tenant_id}"},
)
```

Or mount S3 directly into the scan pod (s3fs / Mountpoint for S3 /
GCS FUSE) and point `STRIX_RUN_STORAGE` at the mount. Then the
artefacts hit S3 as they're written.

### Per-tenant concurrency cap

Add a counting semaphore in Redis (or the auth-context DB):

```python
# Pseudocode in api.py
async def submit_scan(req, current_tenant):
    in_flight = redis.incr(f"scans:in_flight:{current_tenant.id}")
    if in_flight > current_tenant.plan.max_concurrent_scans:
        redis.decr(f"scans:in_flight:{current_tenant.id}")
        raise HTTPException(429, "concurrency cap exceeded")
    # … submit job, decrement when it completes …
```

For real fair-share scheduling under load, use Temporal's
task-queue routing or SQS's per-tenant queues.

### Threat-intel refresher → K8s CronJob

The `refresher` service in `docker-compose.yml` becomes:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: strix-threat-intel-refresh
spec:
  schedule: "0 */6 * * *"   # every 6 h
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: refresh
              image: strix-runner:latest
              command: [python, -m, strix.threat_intel.refresh,
                        --only, kev,ghsa,nvd,popular,ossf-malicious,
                        --ghsa-days, "30",
                        --popular-top-n, "1000"]
              env:
                - name: STRIX_THREAT_INTEL_CACHE
                  value: /shared-cache/threat_intel.db
                - name: GITHUB_TOKEN
                  valueFrom: { secretKeyRef: { name: gh-token, key: token } }
              volumeMounts:
                - name: shared-cache
                  mountPath: /shared-cache
          volumes:
            - name: shared-cache
              persistentVolumeClaim:
                claimName: strix-threat-intel
```

Scan workers mount the same PVC `:readOnly`.

### Sandbox-mode escalation

This example **defaults to** `STRIX_SANDBOX_MODE=false` for
simplicity (no DinD, no privileged pods). To switch to inner-
sandbox mode with a fork-built image (Option A in
`docs/wrapper-integration.md` §6), the compose file ships a
`sandbox` profile:

```bash
# Build your fork sandbox image first (in the strix repo root).
# See docs/wrapper-integration.md §6 "Fork-built sandbox images".

STRIX_SANDBOX_MODE=true \
STRIX_IMAGE=strix-sandbox:fork-4f3f93c \
docker compose --profile sandbox \
  -f examples/strix-runner/docker-compose.yml \
  up worker-sandbox api redis
```

The `worker-sandbox` service:
- Sets `STRIX_SANDBOX_MODE=true` + `STRIX_IMAGE=$STRIX_IMAGE`
- Mounts `/var/run/docker.sock` so strix can spawn the inner
  sandbox container on the host Docker daemon
- Runs at `--concurrency=1` (DinD overhead is real)

**The Docker socket mount is the security trade-off.** This pod
can now drive the host Docker daemon — fine for local dev /
trusted single-tenant, not OK for multi-tenant production. The
production fix is to drop the socket mount and use a
nested-isolation runtime class (sysbox / Kata) so plain DinD
just works.

For production multi-tenant, see `docs/wrapper-integration.md` §6:

- **Trust the K8s pod boundary** (this example default) — viable
  for trusted-multi-tenant or single-tenant deployments.
- **sysbox runtime class** — clean nested isolation; strix's
  default sandbox mode "just works" inside the outer pod, no
  socket mount needed.
- **Firecracker microVM** (KubeVirt / Kata) — VM-grade isolation
  for high-risk DAST workloads.

## What this example does NOT do

- **AuthN / AuthZ** — every request is "tenant=default"
- **Cost accounting** — no per-tenant ledger; cost only enforced
  via per-scan caps
- **Persistence beyond the scan-result Redis backend** — no DB,
  no scan history, no audit log
- **Concurrency limits** — Celery worker concurrency is fixed at
  2; no per-tenant fair share
- **Webhook callbacks** — clients have to poll `GET /scans/{id}`
- **TLS termination** — uvicorn HTTP only
- **Pre-pull of the strix sandbox image** — the `sandbox` profile
  expects the image to be locally available (built or pulled
  ahead of time). For multi-tenant K8s, pull during the
  worker pod's init-container.
- **Streaming `event_stream.jsonl`** — only post-completion
  artefact reads

Each item above is a deliberate omission to keep the example
small. Adding any of them shouldn't change the shape of the
worker → strix invocation; they're all wrapper-layer concerns.

## Sanity-check the image without running a scan

If you just want to verify the image builds and the strix CLI is
wired up correctly:

```bash
docker compose -f examples/strix-runner/docker-compose.yml build worker
docker compose -f examples/strix-runner/docker-compose.yml run --rm \
  worker strix --version
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `strix: command not found` | Image build skipped the `pip install /strix-src` step | `docker compose build --no-cache worker` |
| Scan exits with code 1 immediately | `STRIX_LLM` unset, or `LLM_API_KEY` invalid | Check `.env` is being loaded; `docker compose config` |
| Scan exits with code 3 with partial findings | Hit `--max-cost` — **not an error** | Increase `max_cost_usd` in the request, or accept the cap |
| `vulnerable_dependency` findings empty | Threat-intel cache not seeded | Run the `refresher` profile once with `GITHUB_TOKEN` set |
| Scan hangs > 35 minutes | Celery time limit reached | Bump `task_time_limit` in `worker.py` if your scans legitimately run longer |
