"""Agent-callable tool for emitting `finding.dismissed` events
(roadmap §12 — continuous learning).

When the agent investigates something that LOOKED vulnerable and
confirms it ISN'T, it should emit a structured event with the
surface, the hypothesis, the evidence, and the dismissal reason.

This is DISTINCT from `check.completed {result: not_vulnerable}`
(those are categories, not investigations). Where check.completed
says "I ran the SQL-injection probe family on this endpoint and
nothing fired," `finding.dismissed` says "I noticed
`/api/users/123` reflects user input into the response, formed
the hypothesis 'this might be reflected XSS', tested with
`<script>alert(1)</script>` and the response HTML-encodes it
correctly — so this is NOT a finding."

Why we want these events
------------------------

* **RL training data**: positive-only training data is biased.
  RL needs the "interesting-but-safe" examples — surfaces that
  looked suspicious but weren't.
* **Wrapper transparency**: "what did the agent investigate but
  rule out?" is a common operator question. Today it's buried
  in the agent's prose; the event surfaces it.
* **Cost rationality**: spending tokens on dismissals is
  legitimate work; surfacing it lets cost-dashboards show the
  WHY behind the spend.
"""

from .finding_dismissed import dismiss_finding


__all__ = ["dismiss_finding"]
