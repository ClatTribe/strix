"""Subresource Integrity (SRI) audit (roadmap §7.2 / §7.3).

For each `<script src="...">` and `<link rel="stylesheet" href="...">`
that loads from an EXTERNAL host (CDN), check whether the tag has
an `integrity=` attribute. Missing SRI on external assets = supply-
chain risk (see the polyfill.io incident).

Pure binary check. The HTML literally has the attribute or it
doesn't. Zero false positives.
"""

from .sri_audit import sri_audit


__all__ = ["sri_audit"]
