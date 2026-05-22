"""iter-25.7 — surface priority labels (Gap 9 in docs/L2-optimization.md).

Real engineers time-box: "30 min on auth, 10 min on the rest." Strix
today gives every URL surface the same depth. This module labels each
surface at the start of L2 so `dispatch_specialist` can scale per-
specialist depth budgets accordingly.

Labels derive from IMMUTABLE signal only:
  * URL path prefix (`/admin/*`, `/api/*/auth*`, `/api/*/payment*`)
  * OpenAPI `x-internal: true` or `x-strix-priority: critical`
  * SAST taint paths into known-sensitive models (Users / Payment /
    Secret / PII)

Never response-header derived — otherwise an attacker controlling
`Host:` or `X-Internal-Auth:` could downgrade the scan to
`low_priority` to avoid detection.

The label drives `depth_multiplier`:

  | label    | multiplier |
  | :------- | ---------: |
  | critical | 3.0        |
  | high     | 2.0        |
  | normal   | 1.0        |
  | low      | 0.3        |

Composes with `hygiene_ledger.compute().depth_multiplier`; the
combined multiplier is the per-surface depth budget the dispatcher
applies. Wave 4 wires the combination.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


SurfaceLabel = Literal["critical", "high", "normal", "low"]


_DEPTH_MULTIPLIER: dict[str, float] = {
    "critical": 3.0,
    "high": 2.0,
    "normal": 1.0,
    "low": 0.3,
}


# URL prefix rules — matched against the path segment (lowercased).
_CRITICAL_PATH_RE = re.compile(
    r"""(?ix) ^/?(
          admin/?
        | api/(?:v\d+/)?(?:auth|authn|authz|login|logout|signin|signout
                          |password|passwd|account|session|sso|saml|oauth)
        | api/(?:v\d+/)?(?:payment|billing|invoice|charge|subscription
                          |refund|payout|bank|card)
        | api/(?:v\d+/)?(?:secret|vault|kms|keys|credential|token)
        | api/(?:v\d+/)?internal
        | internal/?
        | private/?
        | manage
        | sudo
        | root
        | rootless
        | grafana/admin
        | wp-admin
        | phpmyadmin
        | actuator/?  # Spring Boot actuator
        | console/?   # Apache Tomcat console
    )(/.*)?$
    """,
)

_HIGH_PATH_RE = re.compile(
    r"""(?ix) ^/?(
          api/(?:v\d+/)?(?:user|users|profile|account|me|orders?|cart|checkout)
        | api/(?:v\d+/)?(?:upload|download|attachment|file|files)
        | oauth/(?:authorize|token|callback)
        | callback
        | webhook(?:s)?
        | api/(?:v\d+/)?(?:admin|admins)/?$  # /api/.../admin without subpath
        | reset[-_]?password
        | forgot[-_]?password
        | verify[-_]?email
    )(/.*)?$
    """,
)

_LOW_PATH_RE = re.compile(
    r"""(?ix) ^/?(
          static/?
        | assets/?
        | images?/?
        | img/?
        | css/?
        | js/?
        | fonts?/?
        | favicon\.ico
        | robots\.txt
        | sitemap(\.\w+)?$
        | health(?:check)?/?
        | ready/?
        | live(?:ness)?/?
        | metrics/?$
        | docs?/?
        | swagger\.json
        | openapi\.(?:json|yaml|yml)
        | (?:[^?]*?\.(?:png|jpg|jpeg|gif|svg|ico|woff2?|ttf|css|js|map))
    )(/.*)?$
    """,
)


@dataclass(frozen=True)
class SurfaceClassification:
    """Per-surface priority decision."""
    surface: str
    label: SurfaceLabel
    depth_multiplier: float
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface": self.surface,
            "label": self.label,
            "depth_multiplier": self.depth_multiplier,
            "rationale": self.rationale,
        }


def _path_of(surface: str) -> str:
    """Extract a normalised lowercase path from a URL or bare path."""
    s = surface.strip()
    if not s:
        return ""
    if "://" in s:
        try:
            p = urlparse(s).path or "/"
            return p.lower()
        except Exception:  # noqa: BLE001
            pass
    if s.startswith("/"):
        return s.lower()
    return ("/" + s).lower()


def classify_surface(
    surface: str,
    *,
    openapi_metadata: dict[str, Any] | None = None,
    sast_taints_sensitive: bool = False,
) -> SurfaceClassification:
    """Decide priority for a surface based on immutable signal.

    Args:
        surface: URL (any scheme) or bare path. We extract the path.
        openapi_metadata: optional dict pulled from the OpenAPI spec
            for this path. Honoured fields:
              * `x-internal: true`           → critical
              * `x-strix-priority: <label>`  → label
        sast_taints_sensitive: True if SAST taint analysis reports
            the path's handler touches a sensitive model. Forces
            label up to at least `high`.
    """
    try:
        path = _path_of(surface)

        # 1) OpenAPI hints win (operator-controlled signal).
        if isinstance(openapi_metadata, dict):
            if openapi_metadata.get("x-internal") is True:
                return SurfaceClassification(
                    surface=surface, label="critical",
                    depth_multiplier=_DEPTH_MULTIPLIER["critical"],
                    rationale="OpenAPI x-internal=true",
                )
            xp = openapi_metadata.get("x-strix-priority")
            if isinstance(xp, str):
                lbl = xp.strip().lower()
                if lbl in _DEPTH_MULTIPLIER:
                    return SurfaceClassification(
                        surface=surface, label=lbl,  # type: ignore[arg-type]
                        depth_multiplier=_DEPTH_MULTIPLIER[lbl],
                        rationale=f"OpenAPI x-strix-priority={lbl}",
                    )

        # 2) Critical paths.
        if _CRITICAL_PATH_RE.search(path):
            return SurfaceClassification(
                surface=surface, label="critical",
                depth_multiplier=_DEPTH_MULTIPLIER["critical"],
                rationale=f"path matches critical prefix ({path})",
            )

        # 3) Low paths (static / health / docs) — but SAST sensitive
        #    overrides.
        if _LOW_PATH_RE.search(path) and not sast_taints_sensitive:
            return SurfaceClassification(
                surface=surface, label="low",
                depth_multiplier=_DEPTH_MULTIPLIER["low"],
                rationale=f"path is static/health/docs ({path})",
            )

        # 4) High paths.
        if _HIGH_PATH_RE.search(path):
            return SurfaceClassification(
                surface=surface, label="high",
                depth_multiplier=_DEPTH_MULTIPLIER["high"],
                rationale=f"path matches high prefix ({path})",
            )

        # 5) SAST taint into sensitive models — promote to high
        #    regardless of path shape.
        if sast_taints_sensitive:
            return SurfaceClassification(
                surface=surface, label="high",
                depth_multiplier=_DEPTH_MULTIPLIER["high"],
                rationale="SAST taint reaches sensitive model",
            )

        # 6) Default — normal.
        return SurfaceClassification(
            surface=surface, label="normal",
            depth_multiplier=_DEPTH_MULTIPLIER["normal"],
            rationale="no priority signal",
        )
    except Exception as e:  # noqa: BLE001
        logger.debug("classify_surface failed for %r: %s", surface, e)
        return SurfaceClassification(
            surface=surface, label="normal",
            depth_multiplier=_DEPTH_MULTIPLIER["normal"],
            rationale=f"classification error: {type(e).__name__}",
        )


def depth_multiplier_for(
    surface: str, **kwargs: Any,
) -> float:
    """Convenience: return just the depth multiplier for a surface."""
    return classify_surface(surface, **kwargs).depth_multiplier
