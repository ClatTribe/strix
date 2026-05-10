# iac-vibe — Phase 11 IaC benchmark

Plants a vibe-coded SaaS deploy config across all 4 supported
platforms. Every file has at least one intentional misconfig
the bundled rule pack should catch.

## Layout

```
iac-vibe/
├── README.md
├── expected.yaml
└── src/
    ├── vercel.json          5 misconfigs planted
    ├── wrangler.toml        4 misconfigs (Cloudflare)
    ├── Dockerfile           4 misconfigs
    └── docker-compose.yml   4 misconfigs
```

## Running

```bash
python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/code/iac-vibe \
    --scan-mode standard
```

No external dependency setup required — IaC scanning is pure-
Python in v1.

## What's planted (15 must-find + 2 soft)

**Vercel (`vercel.json`):**
- CORS origin=`*` + credentials=true (high)
- Redirect with external-host wildcard (open redirect, medium)
- Cron path without auth marker (medium)
- Hardcoded OpenAI key in env (critical)
- maxDuration=600s (low; soft)

**Cloudflare (`wrangler.toml`):**
- Anthropic key in `[vars]` (critical)
- R2 binding named `PUBLIC_CDN` (medium)
- Worker route `*/*` global catch-all (high)
- KV namespace without preview_id (low; soft)

**Dockerfile:**
- No USER directive (high)
- `:latest` tag (implicit, since `node` has no tag) (low)
- Hardcoded Stripe key in ENV (critical)
- ADD from external URL (medium)

**docker-compose.yml:**
- privileged: true container (high)
- /var/run/docker.sock bind-mount (critical)
- Postgres port 5432 exposed to host (high)
- Hardcoded OpenAI key in environment: (critical)

## What this isn't

Not a full IaC suite. Phase 11 v1 covers the deploy surface for
vibe-coded SaaS. Terraform / Pulumi / k8s manifests / cloud APIs
(AWS / GCP / Azure) are deferred to Phase 11.x follow-ups (full
spec in AISecurityEngineer.md §10).
