"""iter-28.6 — Default-credentials probe (pure-python, no hydra).

Universal L1 primitive: against any discovered login form, try the
top default credentials (SecLists-curated). Pure-python — does NOT
require hydra/medusa in the docker image.
"""

from .probe_default_creds import probe_default_creds


__all__ = ["probe_default_creds"]
