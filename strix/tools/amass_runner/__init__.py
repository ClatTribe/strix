"""amass subdomain enumeration specialist.

Importing the submodule triggers `@register_tool` at package-load
time so the lead-agent tool catalog sees it.
"""

from strix.tools.amass_runner.enumerate_subdomains_amass import (
    enumerate_subdomains_amass,
)


__all__ = ("enumerate_subdomains_amass",)
