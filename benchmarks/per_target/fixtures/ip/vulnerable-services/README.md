# vulnerable-services — IP-target benchmark fixture

Three deliberately-misconfigured services on `127.0.0.1`, scanned by
Strix as an `ip_address` target. Used to baseline network-target
coverage — port scanning, service detection, service-specific
weaknesses.

| Port | Service | Planted issue |
|---|---|---|
| 6379 | Redis 6.0 | No authentication required |
| 8080 | nginx 1.18 | Directory listing on `/uploads/` + version disclosure |
| 21 | vsftpd | Weak guest credentials, cleartext protocol |
| 21100–21110 | vsftpd PASV | Cleartext data channel |

> Don't run on a host that's reachable from anywhere you don't trust.
> All ports are bound to `127.0.0.1` only by the compose file, but
> Docker Desktop's defaults can vary — double-check before you start.

## Running

```bash
# from repo root
python benchmarks/per_target/runner.py benchmarks/per_target/fixtures/ip/vulnerable-services \
    --scan-mode standard \
    --output benchmarks/per_target/baseline/vulnerable-services_standard.json
```

The runner brings up all three services, waits 8 seconds, runs Strix
against `127.0.0.1`, then tears down.

## What "good" looks like

Today's Strix should:
- **Reliably:** Find unauthenticated Redis on 6379. Probably catch nginx
  autoindex on 8080 (in top-1000 default ports). Often catch the version
  disclosure.
- **Inconsistently:** Find FTP weaknesses. The agent doesn't run a
  service-specific FTP playbook (roadmap §7.4); recall on FTP findings
  is the canonical signal of "did we improve service-specialist depth?"
- **Today: rarely:** CVE-correlation findings (nginx 1.18 has known
  CVEs). Flips to `must_find: true` once roadmap §10 CVE/OSV lookup
  ships.

## Bumping versions / adding services

Adding a service:

1. Add it to `docker-compose.yml` with `127.0.0.1:` binding.
2. Add at least one expected finding in `expected.yaml` with the port
   and CWE.
3. Note the addition in the table above.

When Strix's coverage genuinely improves (e.g., new service-specialist
skill packs land), flip the relevant `must_find` flags from `false` to
`true` and re-baseline.
