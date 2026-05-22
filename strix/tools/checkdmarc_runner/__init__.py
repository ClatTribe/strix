"""iter-22.4 — checkdmarc DNS/email-hygiene wrapper.

`docs/L1-optimization.md §3.4` calls for the pure-Python
`checkdmarc` library (https://github.com/domainaware/checkdmarc).
It audits a domain's SPF / DKIM / DMARC / MX records + CAA + BIMI
+ MTA-STS, returning structured JSON.

This is a pure-Python lib — no subprocess. We import lazily so
the strix runtime doesn't take a hard dep when the lib isn't
installed.
"""

from __future__ import annotations

from strix.tools.checkdmarc_runner.scan_dns_hygiene_checkdmarc import (  # noqa: F401
    scan_dns_hygiene_checkdmarc,
)


__all__ = ["scan_dns_hygiene_checkdmarc"]
