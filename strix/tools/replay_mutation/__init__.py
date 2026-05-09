"""Replay-with-mutation testing (workitem.md Phase 5.5).

Orchestration layer: ingest a HAR / Burp file → for each captured
request, auto-replay with a mutation matrix per param (SQLi, XSS,
NoSQLi, path traversal, SSRF, command injection, SSTI, XPath, LDAP,
IDOR, secrets) using existing specialists.

Mostly pure dispatch on top of the Phase 2-4 specialist library;
emits the same findings as direct specialist invocations would
(via `tracer.add_vulnerability_report`), plus a per-call telemetry
event courtesy of the registry hook.

Public API
----------

  * `replay_mutation_on_endpoints(endpoints, families=None,
    max_endpoints=200, extra_headers=None)` — pure dispatch
    over an endpoints list (the output shape of
    `ingest_har_file` / `ingest_burp_file`).

  * `replay_mutation_from_har_file(path, ...)` — convenience that
    invokes `ingest_har_file` then `replay_mutation_on_endpoints`.

  * `replay_mutation_from_burp_file(path, ...)` — same for Burp.

Design choices
--------------

  * **No new specialists.** Phase 5.5 is orchestration. Adding a
    new attack here would dilute the per-class specialist contract.
  * **Family-shaped param routing.** A param named "id" doesn't
    deserve a SSTI probe; a param named "redirect" doesn't deserve
    SQLi. The mutation matrix is conditioned on the param-name
    lexicon each specialist already uses.
  * **Bounded.** `max_endpoints` caps fan-out; the lead is
    expected to subset the inventory before calling this.
  * **Best-effort.** Specialist failures are logged in
    `result.evidence` but never abort the replay.
"""

from strix.tools.replay_mutation.replay_mutation import (  # noqa: F401
    replay_mutation_on_endpoints,
)
