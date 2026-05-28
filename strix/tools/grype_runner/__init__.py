"""grype CVE detection specialist.

Importing the submodule triggers `@register_tool` at package-load
time so the lead-agent tool catalog sees it.
"""

from strix.tools.grype_runner.scan_image_grype import scan_image_grype


__all__ = ("scan_image_grype",)
