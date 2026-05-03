"""Source-map (`*.js.map`) exposure probe.

Roadmap §7.3 expert-pentester gap audit. Production builds frequently leak
source maps — `app.js.map` reveals full TypeScript source including
baked-in constants, internal API shapes, and sometimes secrets. This tool
probes the standard bundle-name set + extracts script srcs from the
target HTML, attempts each `.map` URL, parses the result, and emits a
medium-severity finding per accessible map (escalates to high when
secret-indicator tokens appear in the sourcesContent).
"""

from .source_maps import source_map_probe


__all__ = ["source_map_probe"]
