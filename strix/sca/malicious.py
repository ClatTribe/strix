"""Malicious-package heuristics (roadmap §6.6 / Socket.dev angle).

Phase 6 ships KNOWN-vulnerable detection (CVE matching against the
threat-intel cache). This module covers UNKNOWN-malicious — packages
that aren't in any CVE feed yet but exhibit patterns associated with
supply-chain attacks:

  1. **Typosquats** — installed package name is 1–2 character edits
     from a high-popularity package name. The classic dependency-
     confusion / typosquat vector (`reqeusts` for `requests`,
     `lodahs` for `lodash`).
  2. **Install scripts on direct deps** — npm packages that run
     code during `npm install` via `postinstall` / `preinstall` /
     `install`. Not malicious by itself (legitimate native modules
     use these), but every public supply-chain attack of the last
     5 years used one. Flag for human review.
  3. **No license field** — distributors with no SPDX license
     metadata. Suspicious by absence; legitimate published packages
     declare a license. Lower-severity finding by itself, useful
     when correlated with other signals.

Out of scope for v1 (would need npm registry / pypi API):
  * Recently-published-with-high-downloads detection.
  * Maintainer-history checks (no GitHub repo / one-commit history).
  * Network-call patterns at install time.

Each finding emits as `category="malicious_dependency"` with a
`subtype` field telling the wrapper which heuristic fired. KEV /
EPSS-style overrides don't apply here — these are pattern-match
findings, not advisory matches; severity is fixed per heuristic.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

from strix.sca.parsers.base import Package


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Popular package corpus (curated; small, high-confidence list)
# ---------------------------------------------------------------------------
#
# Source: top-N download lists from npm + pypi, intersected with
# packages that are common typosquat targets in published incident
# reports. Deliberately small — maintaining a comprehensive list
# would require a daily-refreshed corpus (deferred to a separate
# threat-intel feed).
#
# Adding to either list:
#   * Names should be lowercased.
#   * Don't add packages with names < 4 chars — too many false
#     positives at edit distance ≤ 2 against arbitrary 4-char
#     strings (e.g. `is`, `nan`, `ws`, `bs4`).
#   * Don't add scoped names — typosquatters can't claim someone
#     else's `@scope/`, so the scope itself is the protection.

_POPULAR_NPM_PACKAGES: frozenset[str] = frozenset({
    # Top runtime deps (typosquat targets in published reports).
    "express", "react", "lodash", "axios", "moment", "request",
    "underscore", "bluebird", "minimist", "yargs", "chalk",
    "commander", "debug", "dotenv", "ejs", "fs-extra", "glob",
    "graphql", "jquery", "knex", "lru-cache", "mongoose",
    "node-fetch", "nodemailer", "passport", "pg", "ramda",
    "redis", "rxjs", "semver", "socket.io", "uuid", "ws",
    "zod", "yup", "joi", "jsonwebtoken", "bcrypt", "bcryptjs",
    "cors", "helmet", "morgan", "multer", "winston", "pino",
    "vue", "angular", "next", "nuxt", "svelte", "preact",
    "tailwindcss", "postcss", "autoprefixer", "webpack", "vite",
    "rollup", "babel", "typescript", "eslint", "prettier",
    "jest", "mocha", "chai", "sinon", "supertest", "playwright",
    "puppeteer", "cypress", "vitest", "lodash.merge", "lodash.set",
    "lodash.get", "react-dom", "react-router", "redux", "vuex",
    "pinia", "cheerio", "axios", "got", "ky", "ohash",
    "fastify", "koa", "hapi", "nest", "@nestjs/core", "ioredis",
    "sequelize", "typeorm", "prisma", "mysql2", "sqlite3",
    "stripe", "twilio", "@sendgrid/mail", "aws-sdk",
    "@aws-sdk/client-s3", "googleapis", "openai", "anthropic",
    "@anthropic-ai/sdk", "langchain",
})


_POPULAR_PYPI_PACKAGES: frozenset[str] = frozenset({
    # Top runtime + framework + common typosquat targets.
    "requests", "urllib3", "django", "flask", "fastapi",
    "starlette", "sqlalchemy", "pydantic", "numpy", "pandas",
    "scipy", "scikit-learn", "tensorflow", "torch", "transformers",
    "openai", "anthropic", "langchain", "boto3", "botocore",
    "pyjwt", "cryptography", "bcrypt", "passlib", "celery",
    "redis", "psycopg2", "psycopg2-binary", "pymongo", "pymysql",
    "asyncio", "aiohttp", "httpx", "tornado", "twisted",
    "pyyaml", "jinja2", "markupsafe", "click", "typer",
    "rich", "loguru", "structlog", "tenacity", "retry",
    "matplotlib", "seaborn", "plotly", "bokeh", "dash",
    "pillow", "opencv-python", "imageio", "beautifulsoup4",
    "lxml", "html5lib", "selenium", "playwright", "pytest",
    "unittest2", "tox", "nox", "coverage", "mypy", "pylint",
    "flake8", "black", "ruff", "isort", "pre-commit", "bandit",
    "fastapi-users", "alembic", "marshmallow", "uvicorn",
    "gunicorn", "hypercorn", "daphne", "channels",
    "django-rest-framework", "djangorestframework", "graphene",
    "strawberry-graphql", "celery", "flower", "kombu",
    "stripe", "twilio", "sendgrid",
})


# ---------------------------------------------------------------------------
# Indicator + result records
# ---------------------------------------------------------------------------


# Heuristic identifiers. Stable strings — wrappers can map them to
# UI badges; tests pin them to catch silent renames.
INDICATOR_TYPOSQUAT = "typosquat"
INDICATOR_INSTALL_SCRIPT = "install_script"
INDICATOR_NO_LICENSE = "no_license"


@dataclass
class MaliciousIndicator:
    """One heuristic hit on one Package."""
    indicator: str            # one of INDICATOR_* constants
    severity: str             # info / low / medium / high
    rationale: str            # human-readable WHY for the finding writeup
    confidence: float = 0.7   # heuristic-only; bump in cross-correlation
    extra: dict = field(default_factory=dict)


@dataclass
class PackageMaliciousReport:
    """All indicator hits for one Package."""
    package: Package
    indicators: list[MaliciousIndicator] = field(default_factory=list)

    @property
    def severity_max(self) -> str:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if not self.indicators:
            return "info"
        return max(
            (i.severity for i in self.indicators),
            key=lambda s: order.get((s or "").lower(), 0),
        )


# ---------------------------------------------------------------------------
# Levenshtein (small + fast; classical 2-row DP)
# ---------------------------------------------------------------------------


def _levenshtein(a: str, b: str, *, max_d: int = 2) -> int:
    """Return Levenshtein edit distance between `a` and `b`. Caps
    at `max_d + 1` for early termination — typosquat detection
    only cares about distance ≤ 2.

    For names that differ in length by more than `max_d`, returns
    `max_d + 1` immediately."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_d:
        return max_d + 1
    if len(a) > len(b):
        a, b = b, a
    # Now len(a) <= len(b).
    prev = list(range(len(a) + 1))
    for i, cb in enumerate(b, start=1):
        cur = [i] + [0] * len(a)
        for j, ca in enumerate(a, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(
                prev[j] + 1,        # deletion
                cur[j - 1] + 1,     # insertion
                prev[j - 1] + cost, # substitution
            )
        # Early bail when minimum across the row exceeds max_d.
        if min(cur) > max_d:
            return max_d + 1
        prev = cur
    return prev[-1]


# ---------------------------------------------------------------------------
# Per-heuristic detectors
# ---------------------------------------------------------------------------


def _detect_typosquat(pkg: Package) -> MaliciousIndicator | None:
    """Flag a package whose name is 1–2 edits from a popular
    package's name (and isn't itself a popular package).

    Edge-case guards:
      * Skip packages with name < 4 chars (false-positive heavy).
      * Skip scoped names (`@scope/x`) — the scope is the
        protection; an attacker can't squat `@vercel/foo`.
      * Skip names that contain the popular name as a substring
        (e.g. `lodash-extra` is a legit pattern, not a squat).
      * Distance 0 (i.e. it IS the popular package) → no hit.
    """
    name = (pkg.name or "").lower().strip()
    if not name or len(name) < 4 or name.startswith("@"):
        return None
    eco = (pkg.ecosystem or "").lower()
    if eco == "npm":
        corpus = _POPULAR_NPM_PACKAGES
    elif eco == "pypi":
        corpus = _POPULAR_PYPI_PACKAGES
    else:
        return None
    # If name IS popular, no squat (it's the real package).
    if name in corpus:
        return None
    # If name contains a popular name as substring, treat as
    # legitimate variant rather than squat (e.g. `lodash-fp`,
    # `react-router`).
    for popular in corpus:
        if popular in name and len(popular) >= 5:
            return None

    closest: tuple[str, int] | None = None
    for popular in corpus:
        # Skip very short popular names — distance ≤ 2 from a
        # 3-char popular name produces too much noise.
        if len(popular) < 4:
            continue
        d = _levenshtein(name, popular, max_d=2)
        if d <= 2 and (closest is None or d < closest[1]):
            closest = (popular, d)
            if d == 1:
                break  # can't get closer; bail.
    if closest is None:
        return None
    target, dist = closest
    # Distance 1 is a high-confidence squat; distance 2 is medium.
    sev = "high" if dist == 1 else "medium"
    conf = 0.85 if dist == 1 else 0.6
    return MaliciousIndicator(
        indicator=INDICATOR_TYPOSQUAT,
        severity=sev,
        confidence=conf,
        rationale=(
            f"Package `{name}` is {dist} character edit"
            f"{'s' if dist != 1 else ''} away from the popular "
            f"`{target}` package. Typosquatting is a known "
            f"supply-chain attack vector — verify this is the "
            f"package you intended to install."
        ),
        extra={"typosquat_target": target, "edit_distance": dist},
    )


def _detect_install_script(pkg: Package) -> MaliciousIndicator | None:
    """Flag npm packages with `hasInstallScript=True` in the lockfile.

    Surfaces as `medium` for direct deps (developer added it on
    purpose; should know) and `high` for transitive deps (the dev
    didn't pick it; could be a confused-deputy install of an
    unexpected build tool).

    Not malicious by itself — many legitimate native-binding
    packages use install scripts (sharp, bcrypt, sqlite3, ...).
    The wrapper's UI should explain: "this package will run code
    during `npm install`; review it before deploying to CI."
    """
    if (pkg.ecosystem or "").lower() != "npm":
        return None
    if not pkg.metadata.get("has_install_script"):
        return None
    sev = "medium" if pkg.direct else "high"
    return MaliciousIndicator(
        indicator=INDICATOR_INSTALL_SCRIPT,
        severity=sev,
        confidence=0.5,
        rationale=(
            f"Package `{pkg.name}@{pkg.version}` runs an install "
            f"script (postinstall/preinstall) during `npm install`. "
            f"This is a common but high-risk vector for supply-chain "
            f"attacks — the script executes with the install user's "
            f"permissions. "
            + (
                "This is a transitive dependency — you didn't "
                "request it directly, so the code that runs at "
                "install time was chosen by another package's "
                "maintainer."
                if not pkg.direct else
                "This is a direct dependency you added, so likely "
                "intentional — verify the package's reputation "
                "before pinning it in CI."
            )
        ),
    )


def _detect_no_license(pkg: Package) -> MaliciousIndicator | None:
    """Flag packages with no license metadata.

    Conservative: only flagged for ecosystems where the parser
    captures license info (npm + composer; pypi via poetry/uv when
    present). When license is genuinely missing — empty string,
    None, or `[]` — the absence is suspicious-by-pattern, not
    malicious-by-evidence; severity is `low`.
    """
    eco = (pkg.ecosystem or "").lower()
    if eco not in ("npm", "composer", "pypi"):
        return None
    if "license" not in pkg.metadata:
        # Parser doesn't surface license for this ecosystem — no
        # signal, no finding. (Better than a false positive.)
        return None
    lic = pkg.metadata.get("license")
    if lic is None or lic == "" or lic == [] or lic == ():
        return MaliciousIndicator(
            indicator=INDICATOR_NO_LICENSE,
            severity="low",
            confidence=0.4,
            rationale=(
                f"Package `{pkg.name}@{pkg.version}` has no license "
                f"declared in its lockfile metadata. Legitimate "
                f"published packages typically declare an SPDX "
                f"license; absence is not malicious by itself but "
                f"is one signal — combined with typosquat or "
                f"install-script flags, it raises the case for "
                f"human review."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


_DETECTORS = [
    _detect_typosquat,
    _detect_install_script,
    _detect_no_license,
]


def analyse_package(pkg: Package) -> PackageMaliciousReport:
    """Run every heuristic against `pkg`. Returns a report with
    zero or more `MaliciousIndicator` entries."""
    report = PackageMaliciousReport(package=pkg)
    for detector in _DETECTORS:
        try:
            ind = detector(pkg)
            if ind is not None:
                report.indicators.append(ind)
        except Exception as e:  # noqa: BLE001
            logger.debug("malicious detector %s failed: %s",
                         detector.__name__, e, exc_info=True)
    return report


def analyse_packages(
    packages: Iterable[Package],
) -> list[PackageMaliciousReport]:
    """Bulk variant. Returns one report per Package, including
    packages with zero indicators (caller filters)."""
    return [analyse_package(p) for p in packages]
