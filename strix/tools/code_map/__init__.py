"""Code-Map agent (roadmap §8.1 row 1).

Walks a repository, extracts the structural artifacts every downstream
code-target specialist reads — HTTP routes, ORM models, DB queries,
external HTTP calls, auth boundaries — and emits `code_map.json`.

This is the §8.1 equivalent of `webapp_recon_pipeline`'s
`webapp_surface_map.json` (§8.2 row 1) and `domain_recon_pipeline`'s
`surface_map.json` (§7.3): the Observe → Decide handoff for the
code-target team.

Pure regex / pattern catalogue (no AST yet). Languages covered v1:
Python (Flask / Django / FastAPI / SQLAlchemy / requests / httpx),
JavaScript / TypeScript (Express / fetch / axios / Mongoose), and
generic SQL string detection across all languages.
"""

from .code_map import build_code_map


__all__ = ["build_code_map"]
