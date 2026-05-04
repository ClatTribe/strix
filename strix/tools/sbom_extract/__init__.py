"""SBOM extraction from web targets (roadmap §16 / PR #131).

Black-box-derived CycloneDX 1.5 SBOM. Parses HTTP responses + JS
bundle URLs to identify:

  * Frameworks via response headers / HTML markers
    (React / Vue / Next.js / Django / Rails / Laravel / Express)
  * NPM packages from CDN-served bundle URLs
    (`/cdn.jsdelivr.net/npm/<pkg>@<version>/...`,
     `/unpkg.com/<pkg>@<version>/...`,
     `/cdnjs.cloudflare.com/ajax/libs/<pkg>/<version>/...`)
  * Backend frameworks from `Server` / `X-Powered-By` headers

Cross-references the detected SBOM against the existing CVE/KEV
enrichment so vulnerable-component findings emit alongside the
SBOM artifact.
"""

from .sbom_extract import sbom_extract


__all__ = ["sbom_extract"]
