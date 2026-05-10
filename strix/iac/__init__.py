"""IaC / cloud-posture scanning (roadmap §10 / Phase 11).

Targets the actual deploy surface for vibe-coded SaaS: Vercel,
Netlify, Cloudflare Workers, Docker / docker-compose. Skips
Terraform / Pulumi / Kubernetes for v1 — those are enterprise
patterns; vibe-coded apps deploy via the edge-platform UIs and
hand-write `vercel.json` / `netlify.toml` / `wrangler.toml`.

What v1 ships
-------------

  parsers/  — vercel.json, netlify.toml, wrangler.toml,
              Dockerfile, docker-compose.yml
  rules/    — ~20 starter rules covering CORS-with-credentials,
              hardcoded secrets in env, exposed sensitive ports,
              :latest tag, USER root, privileged containers,
              wildcard redirects, public storage bindings, etc.
  scanner   — walk repo, parse IaC files, run rules, emit findings
  tools     — `scan_iac` LLM-facing specialist

What's deferred
---------------

  * 11.2 Checkov integration (heavy external dep, separate PR)
  * 11.4 Cloud API integration (AWS/GCP/Azure read-only) —
    needs customer credentials, distinct workflow
  * 11.5 Container image scanning (trivy / grype) — separate
    engine concern
  * Terraform / Pulumi / Kubernetes parsers (enterprise scope)

Cross-asset chain (per §4a)
---------------------------

IaC misconfig ↔ DAST probe is the primary chain:
  * `vercel.json` CORS:* + credentials:true → DAST sends
    cross-origin request; if it succeeds, the misconfig is
    proven exploitable rather than just present.
  * Dockerfile EXPOSE 3306 + docker-compose binds container
    to host → DAST probes localhost:3306; if it answers,
    the DB is exposed beyond the container.
"""

from strix.iac.parsers.base import (  # noqa: F401
    IacFile,
    find_iac_files,
    parse_iac_file,
)
from strix.iac.rules import IacFinding  # noqa: F401
from strix.iac.scanner import IacReport, scan_iac_repo  # noqa: F401
from strix.iac.tools import scan_iac  # noqa: F401
