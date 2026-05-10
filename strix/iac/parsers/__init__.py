"""IaC parser registry — side-effect imports register parsers."""

from strix.iac.parsers import cloudflare as _cloudflare  # noqa: F401
from strix.iac.parsers import docker as _docker  # noqa: F401
from strix.iac.parsers import netlify as _netlify  # noqa: F401
from strix.iac.parsers import vercel as _vercel  # noqa: F401
