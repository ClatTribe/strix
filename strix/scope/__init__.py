"""Engagement scope (§7 of strixredteam.md).

Structured replacement for `--instruction-file` free-text. A
`strix.scope.yml` file declares:

  * In-scope targets (incl. type — `web_application`, `api`,
    `repository`, etc.)
  * Path / host exclusions
  * OpSec level (`quiet` | `standard` | `loud`)
  * Rate-limit cap (rps)
  * Auth method + injection source
  * Acceptance criteria (free-form list)
  * Escalation contact

The scope object is loaded once at scan start, validated, and
injected as a structured block into every agent's system prompt
(see `render_for_prompt`). The agent enforces every probe against
this scope rather than re-parsing free-form instructions on each
spawn.

## Why this is value-add even when CLI flags already exist

The CLI already has `--exclude-path`, `--rate-limit`, `--auth-*`
flags etc. — the scope file's value isn't *new fields*, it's:

  1. **Version control** — `strix.scope.yml` lives next to the
     `.github/workflows/strix.yml` that invokes scans, so the
     exact scope a finding was produced under is reproducible.
  2. **Onboarding** — one doc to point new team members at vs.
     CLI flag spelunking.
  3. **Single source of truth for the agent** — instead of free-form
     instructions, the agent sees a structured block it can reason
     about: "Is this path in `exclusions.paths`?" is a yes/no, not a
     natural-language reading task.

## File shape

```yaml
targets:
  - type: web_application
    value: https://app.example.com
  - type: api
    value: https://api.example.com
exclusions:
  paths:
    - /admin/destructive-export
    - /webhooks/*
  hosts:
    - prod-payments.example.com
opsec_level: standard            # quiet | standard | loud
rate_limit_rps: 10
auth:
  method: bearer                 # bearer | basic | cookie | none
  inject_from: env:STRIX_BEARER  # env:VAR_NAME | file:/path | literal
acceptance_criteria:
  - "All OWASP A0X covered"
  - "Authz matrix on all role pairs"
escalation_contact: secops@example.com
```

Only `targets` is required. Everything else has a safe default.
"""

from strix.scope.loader import (
    ScopeValidationError,
    load_scope_file,
    parse_scope_yaml,
)
from strix.scope.render import render_for_prompt
from strix.scope.spec import (
    AuthConfig,
    EngagementScope,
    OpSecLevel,
    ScopeTarget,
    TargetType,
)


__all__ = [
    "AuthConfig",
    "EngagementScope",
    "OpSecLevel",
    "ScopeTarget",
    "ScopeValidationError",
    "TargetType",
    "load_scope_file",
    "parse_scope_yaml",
    "render_for_prompt",
]
