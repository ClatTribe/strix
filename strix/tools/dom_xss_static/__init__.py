"""DOM-XSS source→sink static probe (roadmap §7.2).

Single-pass static analysis on harvested JS bundles for direct
source→sink DOM-XSS patterns:

  * `location.hash` → `innerHTML`
  * `document.URL` → `eval`
  * `window.name` → `document.write`
  * `document.referrer` → `Function()`
  * …

Zero-FP-by-construction: only reports DIRECT source-in-sink
expressions on a single line. Variable-propagation chains are
deliberately out of scope (would need a real JS AST + dataflow,
which is the L-effort §17.1 follow-up). The Validator agent
(roadmap §8.2) handles the multi-step cases.
"""

from .dom_xss_static import dom_xss_static_probe


__all__ = ["dom_xss_static_probe"]
