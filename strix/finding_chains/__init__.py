"""Cross-category finding-chain artifact (roadmap §4a v2).

Today every category emits findings independently:

  * `vulnerable_dependency`       (SCA)
  * `sast`                         (SAST)
  * `sqli` / `xss` / `idor` / etc. (DAST specialists)
  * `misconfig` / `open_redirect`  (IaC, also DAST)
  * `anomaly`                      (Phase 9)
  * `info_disclosure`              (secrets / SAST hardcoded-*)

These findings often relate. A vulnerable lodash in `package-
lock.json` (SCA), an `eval(req.body)` SAST hit, and a `cmd_
injection` DAST exploit on `/api/calc` may all be ONE bug —
not three. Without correlation, the wrapper has to render N
disconnected reports; reviewers triage the same bug N times.

This module post-processes the emitted-findings set and groups
them into `FindingChain` entries via deterministic linkers
(no LLM). Each chain has a stable `chain_id` + a one-line
summary + the constituent finding IDs + a max-severity rollup.

Output: `finding_chains.json` artifact next to the existing
`vulnerabilities.json`. Wrapper consumes the chain artifact to
render "this is one exploit chain across 3 categories" instead
of three disconnected findings.

Strategic position (per §4a):
  * §4a "single-lead asset-aware planning" tells the LEAD
    to correlate findings AT INVOCATION time via prompt
    chains.
  * This module is the OUTPUT-time correlator that runs after
    the lead finishes, exhausts its work, and we have the
    full finding set to operate on.

Both layers complement each other: the lead's prompt-time
chain reduces wasted probes; this module's output-time chain
gives the wrapper a clean rendering shape.

Heuristics, not LLM. The linkers are deterministic — same
input, same chains. Adding LLM-driven correlation is a
follow-up; it'd produce richer narratives but break the
"replayable telemetry" property.
"""

from strix.finding_chains.chain import (  # noqa: F401
    ChainLink,
    Finding,
    FindingChain,
)
from strix.finding_chains.correlator import (  # noqa: F401
    build_chains,
    write_finding_chains,
)
from strix.finding_chains.links import (  # noqa: F401
    LINKER_REGISTRY,
    LinkType,
)
from strix.finding_chains.normalise import (  # noqa: F401
    normalise_finding,
    normalise_findings,
)
from strix.finding_chains.tools import correlate_findings  # noqa: F401
