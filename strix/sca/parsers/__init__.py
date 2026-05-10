"""Per-ecosystem lockfile parsers."""

from strix.sca.parsers.base import (  # noqa: F401
    Package,
    parse_lockfile,
    register_parser,
)

# Side-effect imports register parsers.
from strix.sca.parsers import npm as _npm  # noqa: F401
from strix.sca.parsers import python as _python  # noqa: F401
from strix.sca.parsers import ruby as _ruby  # noqa: F401
from strix.sca.parsers import cargo as _cargo  # noqa: F401
from strix.sca.parsers import composer as _composer  # noqa: F401
from strix.sca.parsers import go as _go  # noqa: F401
