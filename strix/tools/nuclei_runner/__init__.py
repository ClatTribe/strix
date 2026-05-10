"""Nuclei template runner — community-maintained payload corpus.

Pure-Python interpreter for ProjectDiscovery's nuclei-templates
[1], a 9,000+ template MIT-licensed corpus that's daily-updated by
the community. Each template is a self-contained "send X, expect
Y" probe — directly compatible with our specialist contract.

Why this matters
----------------

Strix's other 17 specialists are static signature engines: I write
the payload list, ship it, and the corpus only grows when I push
new code. The nuclei corpus updates daily without us touching
anything. Adding this single specialist is roughly 100× the
detection breadth of any individual hand-written specialist.

Coverage we get for free
------------------------

  * **CVEs** — `~/.cache/strix/nuclei_templates/http/cves/` — every
    publicly-disclosed CVE with a network-detectable signature.
    Updates daily as new CVEs land.
  * **Exposed panels** — admin dashboards, monitoring UIs (Grafana,
    Kibana, Jenkins, etc.).
  * **Default credentials** — pre-baked login attempts for popular
    apps.
  * **Misconfiguration** — open admin endpoints, debug routes,
    info-disclosure files.
  * **Technologies** — fingerprint detection (often used to chain
    into CVE templates).

What's supported (this module)
------------------------------

We interpret the dominant HTTP template shape natively:
  * `http:` requests with `method`, `path[]`, `headers`, `body`
  * `{{BaseURL}}` substitution
  * Matchers: `word`, `regex`, `status`, `size`, `binary`
  * `matchers-condition: and|or` (default: or)
  * `stop-at-first-match` semantics (default: true on first match)
  * `info.severity`, `info.classification.cve-id`, `info.tags`

What's deferred
---------------

The complex template shapes are skipped (logged + counted) — they
need a full DSL evaluator + workflow engine. Future work:
  * `dsl` matchers (expression language)
  * Workflow templates (chained probes with extracted variables)
  * Network / DNS / file / code templates

Even without these, the HTTP subset covers ~80% of templates.

Refresh
-------

`python -m strix.tools.nuclei_runner.refresh` pulls / updates the
corpus into `~/.cache/strix/nuclei_templates/` (or
`STRIX_NUCLEI_TEMPLATES_DIR` env override).

[1] https://github.com/projectdiscovery/nuclei-templates  (MIT)
"""

from strix.tools.nuclei_runner.nuclei_runner import (  # noqa: F401
    scan_nuclei_templates,
)
