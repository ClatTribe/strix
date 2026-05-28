"""syft SBOM extraction specialist.

Importing the submodule triggers `@register_tool` at package-load
time so the lead-agent tool catalog sees it.
"""

from strix.tools.syft_runner.extract_sbom_syft import extract_sbom_syft


__all__ = ("extract_sbom_syft",)
