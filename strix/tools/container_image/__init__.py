"""Container-image scanning specialist.

Imports the specialist to trigger `@register_specialist_tool` at
package-load time so the lead-agent tool catalog sees it.
"""

from strix.tools.container_image.scan_container_image import (
    scan_container_image,
)


__all__ = ("scan_container_image",)
