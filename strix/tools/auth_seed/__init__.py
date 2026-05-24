"""iter-28.4 — Shape-driven auth seed primitive.

Discovers any registration endpoint by SHAPE (POST taking
email+password, returning a session credential), submits a randomized
test account, and exports the captured JWT/cookie/Bearer via
`STRIX_AUTH_BEARER` / `STRIX_AUTH_COOKIE` for downstream specialists.

Universal — works against Django, Rails, Express, FastAPI, Spring,
Flask, Supabase, Auth0, and any hand-rolled signup that follows the
standard email+password POST convention. NOT Juice Shop-specific.
"""

from .seed_auth import seed_auth


__all__ = ["seed_auth"]
