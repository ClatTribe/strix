# crAPI — OWASP API Top 10 benchmark fixture

Target: [OWASP crAPI](https://github.com/OWASP/crAPI) — the canonical
OWASP API Top 10 (2023) demonstration application.

Pin: `crapi/*:0.7.0`. The fixture's `expected.yaml` aligns to this
specific tag; bumping requires re-baselining.

## Why this fixture exists

Strix's `api` target type has 6 API-specific specialists (BOLA / BFLA /
mass-assignment / rate-limit / GraphQL deep / gRPC reflection), plus
the shared web DAST surface. None of them have a public benchmark
number. **Akto publishes ~85% recall on OWASP API Top 10** against
their internal benchmark suite; this fixture lets Strix produce a
comparable public number against the same vuln catalog.

The 11 expected findings map 1:1 to the OWASP API Top 10 (2023) where
crAPI has a clean planted example. Each finding's `must_find` flag is
set conservatively — items requiring stateful flows (auth, paired
sessions, race conditions) are marked optional so the benchmark fails
loudly on the core deterministic class but doesn't punish edge cases.

## How to run

```bash
# From repo root, with strix venv activated:
cd benchmarks/per_target

# Bring up crAPI (one-time; takes ~3-5 min first-pull)
docker compose -f fixtures/api/crapi/docker-compose.yml up -d

# Wait for health check
curl --fail --silent --retry 30 --retry-delay 5 \
  http://127.0.0.1:8888/identity/health-check

# Run the benchmark (specify scan_mode + model)
python runner.py fixtures/api/crapi/ \
  --scan-mode standard \
  --output baseline/crapi_$(date +%Y%m%d)_standard.json

# Tear down
docker compose -f fixtures/api/crapi/docker-compose.yml down -v
```

Expected wall time per run: 15-45 minutes on `STRIX_LLM=anthropic/claude-sonnet-4-6`,
`--scan-mode standard`. `--scan-mode deep` extends to 60-90 min.

## Scoring rubric

- `recall_must_find` — % of `must_find: true` items detected. **Headline metric.**
- `recall_total` — % of all items detected (incl. `must_find: false`).
- `precision` — % of emitted findings that match an expected one.
- `cost_usd` — LLM spend (from `run_summary.json`).
- `wall_seconds` — runtime.

## Target comparison

| Tool | Published recall | Source |
|---|---|---|
| Akto (proprietary) | ~85% | Akto blog (self-reported) |
| 42Crunch | ~70-80% | Vendor case studies |
| Burp + manual | ~95% (depends on tester) | Industry-anecdotal |
| **Strix** | TBD (run this benchmark) | — |

## Recording results

Drop result JSON into `baseline/` with filename:
`crapi_<YYYYMMDD>_<scan_mode>_<llm_provider>.json`

The runner emits a result document with the contract pinned in
`scoring.py`. Aggregate trends are tracked in
`benchmarks/per_target/baseline/README.md`.

## Troubleshooting

- **crAPI healthcheck times out**: bump `wait_timeout_seconds` in
  `expected.yaml`; first-pull on slow links can hit the 180 s ceiling.
- **MongoDB / Postgres fail to start**: `docker volume prune` between
  runs — stale data corrupts crAPI's bootstrap.
- **Strix's lead loses session mid-scan**: crAPI's JWTs are
  short-TTL (24 h baseline); the benchmark target is the auth tier
  itself, so this is expected for some flows. Re-auth is part of
  the test.
- **`host.docker.internal` not resolvable**: on Linux you may need
  `--add-host=host.docker.internal:host-gateway` on the strix
  sandbox container, OR replace with `172.17.0.1` (the docker0 bridge IP).

## Adding more findings

crAPI has more documented vulns than the 11 listed here. To extend:
1. Pull the crAPI walkthrough from upstream
2. Add a planted vuln entry to `expected_findings` following the schema in `runner.py`
3. Re-baseline; document the addition in `baseline/README.md`
