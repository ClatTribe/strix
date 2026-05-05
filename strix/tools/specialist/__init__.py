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

# Import side-effects register tools.
from strix.tools.specialist import scan_misconfig as _scan_misconfig  # noqa: F401
