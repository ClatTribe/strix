"""iter-22.4 — Dockle container-image CIS-bench wrapper.

`docs/L1-optimization.md §3.10` calls for Dockle (Goodwith-Tech)
to complement Trivy. Where Trivy is vuln+secret-focused, Dockle
covers CIS Docker Benchmark + image-build best practices:

  * CIS-DI-0001: USER set to root (high)
  * CIS-DI-0005: enable Content trust (medium)
  * CIS-DI-0006: HEALTHCHECK defined (info)
  * CIS-DI-0008: removed setuid/setgid bits (medium)
  * DKL-DI-0001..0007: image labels, exposed creds, etc.

Different category than scan_container_image (Trivy) — runs as a
complement, not replacement.
"""

from __future__ import annotations

from strix.tools.dockle_runner.scan_image_dockle import (  # noqa: F401
    scan_image_dockle,
)


__all__ = ["scan_image_dockle"]
