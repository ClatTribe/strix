"""Roadmap §8.5 Phase 5 — finding-mutation primitives.

Today only `add_vulnerability_report` (single-write) exists. This
package adds `update_finding` (mutation) so eager-emission +
review-then-emit (B.10) can compose: emit early at
`verification_status='pattern_match'`, then promote / refute /
attach PoC after follow-up evidence.
"""

# `__all__` empty — same rationale as `strix/tools/specialist/__init__.py`:
# prevents `from .findings import *` from propagating submodule names
# that could shadow other top-level `strix.tools.*` modules.
__all__: list[str] = []

# Import side-effects register tools.
from strix.tools.findings import check_budget as _check_budget  # noqa: F401
from strix.tools.findings import update_finding as _update_finding  # noqa: F401
