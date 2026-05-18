# VAmPI — Vulnerable API smoke benchmark

Target: [erev0s/VAmPI](https://github.com/erev0s/VAmPI) — single-container
Flask API designed for OWASP API Top 10 demonstration.

Pin: `erev0s/vampi:0.4.3`.

## Why this fixture exists

crAPI is the **comprehensive** API benchmark (~30 documented vulns,
7-container deploy, 15-45 min runtime). VAmPI is the **smoke** —
single container, 8 expected findings, 5-15 min runtime. Run it
on every commit; run crAPI weekly.

VAmPI exists in two modes via the `vulnerable` env var:
- `vulnerable=1` (default) — every documented issue is present
- `vulnerable=0` — same endpoints but with fixes applied

The negative control (mode 0) is useful for **false-positive
suppression validation** — confirming the harness emits zero false
positives against properly-defended code.

## How to run

```bash
# From repo root, with strix venv:
cd benchmarks/per_target

# Bring up VAmPI in vulnerable mode (default)
docker compose -f fixtures/api/vampi/docker-compose.yml up -d

# Wait for ready
curl --fail --silent --retry 12 --retry-delay 5 http://127.0.0.1:5001/

# Run
python runner.py fixtures/api/vampi/ \
  --scan-mode standard \
  --output baseline/vampi_$(date +%Y%m%d)_standard.json

# Negative-control: rerun against vulnerable=0 by replacing the env
# in docker-compose.yml then a different expected.yaml-style manifest
# (TODO: vampi-mitigated fixture as a sibling)

docker compose -f fixtures/api/vampi/docker-compose.yml down -v
```

Expected runtime: 5-15 min per `standard` scan; ~30 min on `deep`.

## Scoring rubric

Same as crAPI:
- `recall_must_find` — % of `must_find: true` items detected
- `precision` — % of emitted findings matching expected
- `cost_usd`, `wall_seconds`

## Target

Strix should land at ≥ 85% `recall_must_find` on VAmPI. The deterministic
classes (SQLi, mass-assignment, JWT-alg=none, debug-endpoint exposure,
OpenAPI spec exposure) are all within scope of shipped specialists.

The harder classes (rate-limit detection, BFLA when role enforcement
is partial) depend on multi-request reasoning + objective continuity.

## Comparison reference

VAmPI's own README links to community-published recall numbers:
| Tool | Recall (community-reported) |
|---|---|
| OWASP ZAP active scan | ~40% (covers SQLi + open-redirect; misses API-specific) |
| Burp Suite Pro active scan | ~60% (with custom auth + macro recording) |
| Akto (with crAPI training corpus) | ~85% |
| **Strix** | TBD |

The community numbers are anecdotal — VAmPI doesn't publish formal
benchmark methodology. Strix's number, recorded reproducibly via this
fixture, becomes the first methodologically clean public score.
