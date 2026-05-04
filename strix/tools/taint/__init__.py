"""Taint agent (roadmap §8.1 row 3).

Python AST-based source→sink data-flow analysis. Walks the
codebase, finds calls that read from a known taint **source**
(request.args.get, request.json, sys.argv, os.environ.get,
flask.request.form, etc.), tracks the variable through assignments,
and flags it when it reaches a known **sink** (raw cursor.execute,
os.system, subprocess.run with shell=True, eval, exec,
template.render with the var as direct-input, etc.).

Lightweight v1 (Python only via `ast` stdlib). Full CodeQL / Joern
integration is the L-effort §17.1 follow-up. This implementation is
the deterministic candidate-finding emitter the LLM-side Taint
agent (per §8.1 diagram) triages for relevance + false-positive
likelihood.

Each detection becomes a finding with:
- `category="taint_flow"`
- `severity="medium"` (default; bumped to high when sink is `eval`/
  `exec`/`os.system`/`shell=True`)
- `verification_status="pattern_match"` (re-flow analysis isn't
  exploit-execution; the future Validator §17.1 will try the actual
  exploit)
- evidence: source `file:line` + sink `file:line` + the variable
  chain in between
"""

from .taint_analysis import taint_analysis


__all__ = ["taint_analysis"]
