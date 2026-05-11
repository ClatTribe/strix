# DAST public benchmark — pointer

DAST runs against a **live** web app, not a static artefact. The
right harness for DAST is the **agentic** runner
(`benchmarks/per_target/runner.py`) — it spawns the full `strix`
CLI, lets the lead agent drive a scan over HTTP, and parses
markdown findings. A direct-tool runner makes no sense here
because the scan _is_ an agent loop.

So this directory deliberately doesn't ship its own fixture. The
DAST public benchmark is:

| Fixture | Where | Public dataset | Cost / runtime |
|---|---|---|---|
| **OWASP Juice Shop** | `benchmarks/per_target/fixtures/web/juiceshop/` | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — docker-compose, 100+ planted vulnerabilities, ~OWASP Top 10 + extras | ~30 min, ~$1–3 per scan depending on scan mode |
| **XBEN** _(upstream)_ | [`usestrix/benchmarks`](https://github.com/usestrix/benchmarks) | XBOW's 104-challenge web CTF — published as the externally-comparable headline number | ~19 min average per challenge, ~$337 total for v0.4.0 |

## How to run Juice Shop

```bash
cd benchmarks/per_target/fixtures/web/juiceshop
# Bring up the Juice Shop docker-compose
docker compose up -d
# Run strix against it (agentic)
python ../../runner.py . --scan-mode standard \
  --output ../../baseline/juiceshop_$(date +%Y%m%d_%H%M).json
docker compose down
```

The recent juiceshop baseline JSONs in `benchmarks/per_target/baseline/`
are previous runs — compare new runs against those to detect
regression.

## Why no DVWA / WebGoat fixture here

DVWA, WebGoat, bWAPP, Mutillidae are all candidate DAST fixtures.
None of them have published cross-tool comparison numbers
(Snyk doesn't run on DVWA, Burp doesn't publish a DVWA scorecard).
Adding them to `per_target/fixtures/web/` would be useful for
regression-detection but wouldn't unlock the "comparable to
commercial" story.

The actually-comparable DAST number is **XBEN**, which is already
published upstream at `usestrix/benchmarks` (96% / 100-of-104 for
v0.4.0).

## Roadmap

| Lane | Status | Next |
|---|---|---|
| Juice Shop | ✅ Wired (agentic, per_target) | Refresh baseline after each lead-agent change |
| XBEN | ✅ Published upstream | Re-run on next major lead-agent rev |
| DVWA  | Not planned (no comparable commercial scorecard) | — |
| WebGoat | Not planned | — |
