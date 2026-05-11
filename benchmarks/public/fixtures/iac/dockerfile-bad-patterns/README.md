# dockerfile-bad-patterns — synthetic IaC recall benchmark

Synthetic deliberately-bad Dockerfile + docker-compose.yml,
planted to trigger every rule in strix's Docker IaC pack
(`strix/iac/rules/docker_rules.py`).

## Why synthetic, not a clone

There isn't a widely-published IaC public benchmark that covers
strix's current platforms (Vercel / Netlify / Cloudflare / Docker
— Terraform / k8s are deferred to Phase 11.3). The well-known
IaC benchmarks are:

| Public benchmark | Coverage | Strix support today |
|---|---|---|
| [TerraGoat](https://github.com/bridgecrewio/terragoat) | Terraform | ❌ Phase 11.3 deferred |
| [KICS test-repository](https://github.com/Checkmarx/kics/tree/master/test) | Terraform / k8s / CloudFormation / Helm | ❌ |
| Checkov test fixtures | Terraform / k8s / Dockerfile / GitHub Actions | Partial — Dockerfile only |
| OWASP DSVW | Docker (single Dockerfile) | ✅ — but only one rule fires |

Once **Phase 11.2** lands Checkov integration as the heavy-rules
engine, this directory should add a TerraGoat fixture (the
IaC equivalent of NodeGoat). Until then this synthetic fixture
covers strix's current rule pack.

## What's in `src/`

| File | Bad patterns planted |
|---|---|
| `Dockerfile` | `FROM node:latest`, `ADD https://…/setup.sh`, `ENV AWS_ACCESS_KEY_ID=AKIA…`, `USER root` |
| `docker-compose.yml` | `privileged: true`, `network_mode: host`, `/var/run/docker.sock` bind-mount, `AWS_ACCESS_KEY_ID: AKIA…` in env, postgres port `5432:5432` published |

All "secrets" are well-known synthetic test values (e.g.
`AKIAIOSFODNN7EXAMPLE`) — pattern shape only, not real
credentials.

## Run

```bash
python benchmarks/public/run_iac_benchmark.py \
  benchmarks/public/fixtures/iac/dockerfile-bad-patterns \
  -o benchmarks/public/fixtures/iac/dockerfile-bad-patterns/baseline/run_$(date +%Y%m%d_%H%M).json
```

Takes ~1 s (pure-Python rule pack, no external binary).

## First captured baseline (CEILING)

| Metric | Value |
|---|---|
| recall_must_find | 100% (9/9) |
| total findings | 9 |
| duration | 0.96 s |
| files scanned | 2 (1 Dockerfile + 1 docker-compose.yml) |
| critical / high / medium / low | 2 / 3 / 3 / 1 |

## Comparison to Checkov

Once Phase 11.2 lands Checkov as an engine, this fixture should
also be runnable through Checkov for a direct head-to-head:

| Rule (strix) | Checkov equivalent | Triggered |
|---|---|---|
| dockerfile-latest-tag | CKV_DOCKER_7 | ✅ |
| dockerfile-add-from-url | CKV_DOCKER_4 | ✅ |
| dockerfile-env-hardcoded-secret | (no exact equivalent; Checkov uses TruffleHog) | ✅ in strix |
| dockerfile-user-root | CKV_DOCKER_8 | ✅ |
| compose-privileged-container | CKV_DOCKER_*(privileged) | ✅ |
| compose-host-network-mode | (no exact equivalent in Checkov core) | ✅ in strix |
| compose-docker-socket-mount | CKV_DOCKER_(socket mount) | ✅ |
| compose-environment-hardcoded-secret | (TruffleHog overlay) | ✅ in strix |
| compose-db-port-exposed | (no direct rule; KICS has it) | ✅ in strix |

Strix's rule pack is narrower than Checkov's (Checkov ships ~1500
rules); the planned Phase 11.2 integration is what closes that
gap. This benchmark is the regression-detection floor for the
core rules strix ships today.
