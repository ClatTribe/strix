"""Cross-subdomain cookie / JWT scoping checks (roadmap §7.2).

When multiple subdomains of the same org are in scope, this tool
probes for:

- Session cookies with `Domain=.<parent>` that leak across sister
  subdomains.
- Inconsistent `SameSite` settings across subdomains (one weak
  subdomain weakens the cohort).
- `SameSite=None` without `Secure` (browser silently downgrades
  in modern browsers).
- JWT cross-acceptance — a token issued by subdomain A accepted
  by subdomain B (broken audience binding).
- JWT `aud` claim too broadly scoped (parent domain instead of
  the specific subdomain).

Pivots between sister subdomains are a real-world attack class
that single-target scans miss entirely.
"""

from .cookie_scoping_check import cookie_jwt_scoping_check


__all__ = ["cookie_jwt_scoping_check"]
