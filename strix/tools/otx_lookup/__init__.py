"""AlienVault OTX (Open Threat Exchange) IoC lookup.

Roadmap §10 expert-pentester gap audit (🟡 important). Different
signal from VirusTotal (#71): OTX gives **attribution context**
(which threat actor / campaign tagged this IoC) rather than
**multi-engine consensus** (how many AV vendors flagged it). Free
key required at otx.alienvault.com.
"""

from .otx_lookup import otx_lookup


__all__ = ["otx_lookup"]
