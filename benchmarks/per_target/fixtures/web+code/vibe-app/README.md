# vibe-app — paired-asset benchmark (web + code)

Validates the **single-lead asset-aware planning + cross-asset
correlation** work formalised in `AISecurityEngineer.md` §4a. The
gap that motivated this fixture: every per-target benchmark before
it (`code/flask-vuln`, `code/sca-vuln-deps`, `web/juiceshop`) hit
exactly one `target_type`. Cross-asset chains literally couldn't
fire on a single-target fixture, so "single-lead correlates SCA
with DAST" was an architectural assertion measurable only in
production telemetry. Now it's measurable here.

## What's in the box

A tiny Express app with two **paired** vulnerabilities:

| Package          | CVE             | DAST endpoint | Class                |
|------------------|-----------------|---------------|----------------------|
| lodash@4.17.20   | CVE-2020-8203   | POST /api/merge + GET /api/check | Prototype pollution |
| ejs@3.1.6        | CVE-2022-29078  | GET /api/render?tmpl= | Template injection / RCE |

Plus a hardcoded Stripe live key in `app.js` for secret-scan
coverage.

The whole point: the **same vulnerability is reachable through two
assets**. SCA on the repo finds the package version; DAST on the
URL confirms the runtime is exploitable. Single-lead routing has
to surface both AND mention them in the same finding chain.

## Layout

```
vibe-app/
├── README.md            this file
├── expected.yaml        manifest with additional_targets[] list
├── Dockerfile           node:18-alpine, npm install, run app.js
├── docker-compose.yml   exposes :3030
└── src/
    ├── package.json
    ├── package-lock.json   (lodash@4.17.20, ejs@3.1.6, express@4.16.0)
    └── app.js              4 vulnerable endpoints + 1 hardcoded secret
```

## Running

```bash
# Refresh the threat-intel cache so GHSA / NVD have the dep CVEs.
python -m strix.threat_intel.refresh --feeds kev,epss,nvd,ghsa

# Run the paired benchmark (the runner will docker compose up the app
# AND pass both -t URL and -t local_code/path to strix in one
# invocation — see runner.py::resolve_targets).
python benchmarks/per_target/runner.py \
    benchmarks/per_target/fixtures/web+code/vibe-app \
    --scan-mode standard
```

The runner brings up the docker service, runs strix with **both**
`-t http://localhost:3030` and `-t .../src/`, scores findings against
`expected.yaml`, then tears the service down.

## What "passing" looks like

The five `must_find: true` entries split as:

* **Pure SCA** (2 — lockfile-only): lodash + ejs CVEs.
* **Pure SAST / secret**: hardcoded Stripe key.
* **Cross-asset DAST** (2 — `cross_asset: true`): live exploits of
  the merge + render endpoints.

A clean run finds all five. A run that finds the SCA pair but
misses the DAST pair (or vice versa) shows the routing fired but
the correlation didn't. A run that finds DAST but misses SCA shows
the lead picked the wrong anchor (started with browser probing
instead of `scan_sca_lockfiles`).

## What this isn't

Not a synthetic OWASP enum like `flask-vuln`. The whole point is
that **two real CVEs** are deliberately exposed via two asset
classes so you can tell when single-lead correlation breaks.

If a future regression makes the lead skip SCA on web targets, or
miss the DAST follow-up after an SCA hit, this benchmark catches
it without requiring production telemetry.
