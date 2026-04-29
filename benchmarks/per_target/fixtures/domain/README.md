# domain — methodology (no runnable fixture)

Domain-target benchmarks need a **real test domain** you control with
DNS authority. There's no honest way to ship a runnable fixture — DNS
isn't dockerizable in a useful way, and pointing at a public test
domain makes findings non-deterministic (its records change without
notice).

This README is the methodology for building your own domain fixture.

## What to plant

For a useful domain-target baseline, plant at least one of each:

| # | Category | What to set up |
|---|---|---|
| 1 | Subdomain takeover | Create CNAME pointing to an unclaimed third-party (e.g. `bench-takeover.<your-domain>` → `nonexistent-app.herokuapp.com`). Use a provider on `can-i-take-over-xyz`'s "exploitable" list. |
| 2 | Missing DMARC / SPF / DKIM | Don't publish a DMARC record on `<your-domain>`; or publish `v=DMARC1; p=none` (audit-only, no enforcement). |
| 3 | Public AXFR | Configure your authoritative NS to allow zone transfer from any source (`allow-transfer { any; };` in BIND). |
| 4 | Wildcard DNS | Add `*.<your-domain>` → some IP. The recon agent should detect this and mark non-existent subdomains as unsafe-to-trust. |
| 5 | Stale subdomain | Old `legacy.<your-domain>` → an IP that hasn't been used in months / years. Passive DNS history may reveal it. |
| 6 | Cloud asset discovery | Create a public S3 bucket named `<your-org>-prod-uploads` or similar predictable pattern. The cloud-asset agent (roadmap §7.3) should find it via wordlist permutation. |
| 7 | Dangling NS | Delegate a subdomain to a nameserver that no longer exists. |

## Manifest schema

Once you have a test domain, create your own `expected.yaml` (do not
commit if it identifies a real domain you own):

```yaml
target_type: domain
target: bench.your-domain.com
description: Private benchmark domain with planted issues.

expected_findings:
  - id: takeover-bench-takeover
    category: subdomain_takeover
    cwe: CWE-1390
    severity: high
    must_find: true
    description: bench-takeover.<domain> CNAMEs to unclaimed Heroku app.

  - id: missing-dmarc
    category: misconfig
    cwe: CWE-1278
    severity: medium
    must_find: true
    description: Domain has no DMARC record.

  # ... etc.
```

## Running

```bash
# Set the test domain at runtime (don't bake it into a committed file)
export TEST_DOMAIN=bench.your-domain.com

# Override the target via --strix-arg
python benchmarks/per_target/runner.py benchmarks/per_target/fixtures/domain \
    --scan-mode standard
```

(The runner reads `target` from `expected.yaml`; for domain fixtures, you
maintain that file locally with your domain in it.)

## Why no shared fixture

- Public test domains drift unpredictably.
- Hosting a shared test domain costs DNS infrastructure + monitoring.
- Subdomain takeover candidates are time-sensitive — a setup that's
  exploitable today may not be tomorrow if the third-party provider
  changes policy.

When the recon team lands (roadmap §8.3), this section can be revisited
— a recon-only mode (`--surface-map-only`, §7.0) makes domain testing
much more deterministic, since the surface map is the artifact under
test rather than the exploit outcomes.
