# juiceshop — web-application benchmark fixture

OWASP Juice Shop running in a local Docker container, scanned by Strix as
a `web_application` target. Used to baseline black-box web coverage.

> Juice Shop is the canonical "deliberately vulnerable web app". It has
> 100+ documented challenges; this fixture's manifest covers a curated
> subset chosen for category breadth, not full coverage of every challenge.

## Running

```bash
# from repo root — docker must be available
python benchmarks/per_target/runner.py benchmarks/per_target/fixtures/web/juiceshop \
    --scan-mode standard \
    --output benchmarks/per_target/baseline/juiceshop_standard.json
```

The runner brings the container up via `docker compose`, waits for the
healthcheck, runs Strix against `http://localhost:3000`, then tears down.
Use `--keep-up` if you want to inspect the running app after the scan.

## What's covered in the manifest

10 findings spanning: SQLi (incl. NoSQLi), XSS, IDOR, broken access
control, path traversal, JWT weaknesses, deprecated/XXE endpoints, SSRF
(authenticated, marked `must_find: false`), open redirect.

The full Juice Shop challenge list is much larger; intentionally not
included here are challenges that depend on specific UI interactions, on
solving a previous challenge first, or on time-of-day. Those are
better-suited to the upstream XBEN-style benchmark.

## Known limitations of today's Strix on this fixture

- **Authenticated findings under-recall.** Strix without proper auth
  (roadmap §2 `--auth-cookie/-bearer`) can't reliably maintain a session
  across many requests. The SSRF-via-profile-image is `must_find: false`
  for this reason.
- **Stateful challenges miss.** Findings that require multi-step exploit
  chains across pages (e.g., XSS that fires only after a specific cart
  manipulation) often miss because the agent loses state.
- **JWT findings are sensitive to the agent's testing path.** It needs to
  capture a real token first, then mutate it; without a structured Auth
  agent (§8.2) it's hit-or-miss.

These are all expected gaps and motivate roadmap items — that's the
point of having the baseline.

## Bumping the Juice Shop version

`docker-compose.yml` pins `v17.2.0`. Newer versions add/remove challenges
and rework endpoints. If you bump:

1. Re-run the fixture and review the resulting findings.
2. Update `expected.yaml` for any endpoint changes.
3. Save a fresh baseline before merging.
