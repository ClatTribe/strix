"""Roadmap §8.5 Phase 1 — specialist-tool primitive.

Wires the registry decorator + result schema + first deterministic
(`llm=False`) specialist (`scan_misconfig`) into the existing tool
catalog. Importing this package registers `scan_misconfig` so the
agent can call it normally.

Background patterns this implements:
  * B.1 — primitive (no LLM) vs Agent-pattern (delegates to sub-LLM).
  * B.2 — bounded input at every tool boundary.
  * B.8 — tool-result schema discipline (`SpecialistResult`).

See [`single-agent.md §2.2`](../../single-agent.md) for the full
specification.
"""

# `__all__` is explicitly empty so `from .specialist import *` from
# `strix/tools/__init__.py` does NOT propagate the `registry` /
# `result` / `scan_misconfig` submodules into `strix.tools.*`. The
# `registry` submodule name in particular would otherwise shadow
# `strix.tools.registry` — broke `tests/tools/test_mitre_attack_
# tagging.py` and `tests/tools/test_tool_registration_modes.py` post-
# Phase-1 sweep. Side-effect import below still registers the tool.
__all__: list[str] = []

# Import side-effects register tools.
from strix.tools.specialist import async_dispatch as _async_dispatch  # noqa: F401
from strix.tools.specialist import scan_misconfig as _scan_misconfig  # noqa: F401
from strix.tools.specialist import scan_sqli as _scan_sqli  # noqa: F401  # Phase 3b
from strix.tools.specialist import scan_xss as _scan_xss  # noqa: F401  # Phase 3b
from strix.tools.specialist import scan_xxe as _scan_xxe  # noqa: F401  # Phase 6
from strix.tools.specialist import scan_auth_flow as _scan_auth_flow  # noqa: F401  # Phase 6
from strix.tools.specialist import scan_ssti as _scan_ssti  # noqa: F401  # Phase 2.3
from strix.tools.specialist import scan_path_traversal as _scan_path_traversal  # noqa: F401  # Phase 2.2
from strix.tools.specialist import scan_ssrf as _scan_ssrf  # noqa: F401  # Phase 2.1
