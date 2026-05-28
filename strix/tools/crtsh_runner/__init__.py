"""crt.sh certificate-transparency subdomain mining specialist.

Importing the submodule triggers `@register_tool` at package-load
time so the lead-agent tool catalog sees it.
"""

from strix.tools.crtsh_runner.enumerate_subdomains_crtsh import (
    enumerate_subdomains_crtsh,
)


__all__ = ("enumerate_subdomains_crtsh",)
