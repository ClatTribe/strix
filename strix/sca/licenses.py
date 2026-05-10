"""License compliance — Phase 6.7.

Walks `Package` records, classifies each package's license into
one of {permissive, copyleft, weak_copyleft, commercial_restricted,
unknown}, and emits findings for any package that violates a
configurable policy (default: flag copyleft + weak_copyleft +
unknown when the customer's project is "proprietary").

Why this matters: a vibe-coded SaaS company using a GPL-licensed
package without complying with the GPL terms (publishing modified
source + downstream license) is a litigation risk. SOC 2 OPS-3
(ongoing third-party risk monitoring) requires a documented
license inventory.

## License families

  * **permissive** — MIT, BSD (2/3-clause), Apache-2.0, ISC, 0BSD,
    Unlicense, MIT-0. Safe for any commercial use.
  * **weak_copyleft** — LGPL-2.1, LGPL-3.0, MPL-2.0, EPL.
    Generally safe for SaaS (link-only); risk is in distribution.
  * **copyleft** — GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0.
    AGPL is the SaaS killer (network use = distribution).
  * **commercial_restricted** — proprietary, custom, "see LICENSE",
    BUSL (Business Source License).
  * **unknown** — empty / None / unparseable.

SPDX identifiers are matched case-insensitively. Compound
expressions (`(MIT OR Apache-2.0)`, `MIT AND CC0-1.0`) take the
**most-restrictive** family seen in the expression — a package
licensed `(MIT OR GPL-3.0)` is treated as copyleft because the
choice belongs to the licensee, but the conservative engineering
default is "assume worst case".

## Policy

Default policy treats the project as proprietary commercial:

  * permissive → ok
  * weak_copyleft → ok (linked dynamically; SaaS doesn't distribute)
  * copyleft → flag (incompatible with proprietary distribution)
  * commercial_restricted → flag (need explicit license review)
  * unknown → flag (can't verify compliance)

Two override knobs on `find_license_violations`:
  * `allow_copyleft=True` — for OSS / GPL-licensed projects.
  * `allow_unknown=True` — for projects where the license corpus
    is genuinely incomplete (rarely the right call).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable

from strix.sca.parsers.base import Package


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# License family classification
# ---------------------------------------------------------------------------


FAMILY_PERMISSIVE = "permissive"
FAMILY_WEAK_COPYLEFT = "weak_copyleft"
FAMILY_COPYLEFT = "copyleft"
FAMILY_COMMERCIAL_RESTRICTED = "commercial_restricted"
FAMILY_UNKNOWN = "unknown"


# Severity (ordered most-restrictive first) — used to pick the
# "worst-case" family in compound `(A OR B)` expressions.
_FAMILY_RESTRICTIVENESS: dict[str, int] = {
    FAMILY_COMMERCIAL_RESTRICTED: 4,
    FAMILY_COPYLEFT: 3,
    FAMILY_UNKNOWN: 2,
    FAMILY_WEAK_COPYLEFT: 1,
    FAMILY_PERMISSIVE: 0,
}


# Canonical SPDX → family. Lowercased keys for case-insensitive lookup.
_SPDX_FAMILY: dict[str, str] = {
    # Permissive
    "mit": FAMILY_PERMISSIVE,
    "mit-0": FAMILY_PERMISSIVE,
    "mit license": FAMILY_PERMISSIVE,
    "bsd": FAMILY_PERMISSIVE,
    "bsd-2-clause": FAMILY_PERMISSIVE,
    "bsd-3-clause": FAMILY_PERMISSIVE,
    "bsd-3-clause-clear": FAMILY_PERMISSIVE,
    "0bsd": FAMILY_PERMISSIVE,
    "apache": FAMILY_PERMISSIVE,
    "apache-2.0": FAMILY_PERMISSIVE,
    "apache 2.0": FAMILY_PERMISSIVE,
    "apache license 2.0": FAMILY_PERMISSIVE,
    "isc": FAMILY_PERMISSIVE,
    "unlicense": FAMILY_PERMISSIVE,
    "the unlicense": FAMILY_PERMISSIVE,
    "wtfpl": FAMILY_PERMISSIVE,
    "cc0-1.0": FAMILY_PERMISSIVE,
    "cc-by-4.0": FAMILY_PERMISSIVE,
    "zlib": FAMILY_PERMISSIVE,
    "boost": FAMILY_PERMISSIVE,
    "bsl-1.0": FAMILY_PERMISSIVE,
    "python-2.0": FAMILY_PERMISSIVE,
    "psf": FAMILY_PERMISSIVE,
    "psf-2.0": FAMILY_PERMISSIVE,
    "json": FAMILY_PERMISSIVE,
    # Weak copyleft (file-/library-scope; safe for SaaS link-only)
    "lgpl": FAMILY_WEAK_COPYLEFT,
    "lgpl-2.0": FAMILY_WEAK_COPYLEFT,
    "lgpl-2.1": FAMILY_WEAK_COPYLEFT,
    "lgpl-3.0": FAMILY_WEAK_COPYLEFT,
    "lgpl-3.0-only": FAMILY_WEAK_COPYLEFT,
    "lgpl-3.0-or-later": FAMILY_WEAK_COPYLEFT,
    "mpl": FAMILY_WEAK_COPYLEFT,
    "mpl-2.0": FAMILY_WEAK_COPYLEFT,
    "mpl-1.1": FAMILY_WEAK_COPYLEFT,
    "epl": FAMILY_WEAK_COPYLEFT,
    "epl-1.0": FAMILY_WEAK_COPYLEFT,
    "epl-2.0": FAMILY_WEAK_COPYLEFT,
    "cddl": FAMILY_WEAK_COPYLEFT,
    "cddl-1.0": FAMILY_WEAK_COPYLEFT,
    # Copyleft (project-scope; viral)
    "gpl": FAMILY_COPYLEFT,
    "gpl-2.0": FAMILY_COPYLEFT,
    "gpl-3.0": FAMILY_COPYLEFT,
    "gpl-3.0-only": FAMILY_COPYLEFT,
    "gpl-3.0-or-later": FAMILY_COPYLEFT,
    "agpl": FAMILY_COPYLEFT,
    "agpl-3.0": FAMILY_COPYLEFT,
    "agpl-3.0-only": FAMILY_COPYLEFT,
    "agpl-3.0-or-later": FAMILY_COPYLEFT,
    "sspl": FAMILY_COPYLEFT,
    "sspl-1.0": FAMILY_COPYLEFT,
    # Commercial / restricted
    "proprietary": FAMILY_COMMERCIAL_RESTRICTED,
    "see license": FAMILY_COMMERCIAL_RESTRICTED,
    "see license file": FAMILY_COMMERCIAL_RESTRICTED,
    "see-license-file": FAMILY_COMMERCIAL_RESTRICTED,
    "commercial": FAMILY_COMMERCIAL_RESTRICTED,
    "busl": FAMILY_COMMERCIAL_RESTRICTED,
    "busl-1.1": FAMILY_COMMERCIAL_RESTRICTED,
    "elastic": FAMILY_COMMERCIAL_RESTRICTED,
    "elastic-2.0": FAMILY_COMMERCIAL_RESTRICTED,
    "redis-source-available-license-2.0": FAMILY_COMMERCIAL_RESTRICTED,
    "rsal-2.0": FAMILY_COMMERCIAL_RESTRICTED,
    "fsl-1.1-mit": FAMILY_COMMERCIAL_RESTRICTED,
    "fsl-1.1-apache-2.0": FAMILY_COMMERCIAL_RESTRICTED,
}


# Compound-expression splitter: tokenise `(A OR B)`, `A AND B`,
# `A WITH C` into individual SPDX identifiers. Conservative — we
# don't try to parse SPDX expression grammar; we just extract
# identifiers.
_SPDX_TOKEN_SPLIT = re.compile(r"[\s()]+|\bAND\b|\bOR\b|\bWITH\b", re.IGNORECASE)


def _classify_one(s: str) -> str:
    """Classify one already-tokenised license identifier."""
    if not s:
        return FAMILY_UNKNOWN
    key = s.strip().lower().rstrip("+")
    if not key:
        return FAMILY_UNKNOWN
    if key in _SPDX_FAMILY:
        return _SPDX_FAMILY[key]
    # Prefix match — `gpl-2.0+` should hit `gpl-2.0`.
    for spdx_key, fam in _SPDX_FAMILY.items():
        if key.startswith(spdx_key + "-") or key.startswith(spdx_key + " "):
            return fam
    return FAMILY_UNKNOWN


def classify_license(value) -> str:
    """Classify a license field of arbitrary shape.

    Accepts:
      * `None` / `""` → `unknown`
      * SPDX string `"MIT"` / `"Apache-2.0"`
      * Compound SPDX `"(MIT OR Apache-2.0)"`, `"GPL-3.0 WITH Classpath-exception-2.0"`
      * List of strings (composer convention) `["MIT"]`
      * Object with `type` field (npm legacy) `{"type": "MIT"}`
      * List of objects (npm legacy multi-license) `[{"type":"MIT"}, ...]`

    Return the **most restrictive** family across all identifiers
    in the expression. The conservative engineering default —
    `(MIT OR GPL-3.0)` is reported as copyleft so the auditor
    sees the worst case before signing off.
    """
    if value is None or value == "":
        return FAMILY_UNKNOWN

    # Composer / npm-legacy: list shape.
    if isinstance(value, (list, tuple)):
        if not value:
            return FAMILY_UNKNOWN
        worst = FAMILY_PERMISSIVE
        seen_any = False
        for item in value:
            fam = classify_license(item)
            if fam == FAMILY_UNKNOWN:
                # Skip; one missing field shouldn't poison the
                # whole list classification when others resolve.
                continue
            seen_any = True
            if (_FAMILY_RESTRICTIVENESS.get(fam, 0)
                    > _FAMILY_RESTRICTIVENESS.get(worst, 0)):
                worst = fam
        return worst if seen_any else FAMILY_UNKNOWN

    # npm legacy: {"type": "MIT"} / {"type": "MIT", "url": "..."}
    if isinstance(value, dict):
        return classify_license(value.get("type") or value.get("name"))

    if not isinstance(value, str):
        return FAMILY_UNKNOWN

    # String: try direct first (covers `"MIT"`, `"Apache-2.0"`).
    direct_fam = _classify_one(value)
    if direct_fam != FAMILY_UNKNOWN:
        return direct_fam

    # Compound expression — tokenise and pick worst.
    tokens = [t for t in _SPDX_TOKEN_SPLIT.split(value) if t]
    if not tokens:
        return FAMILY_UNKNOWN
    worst = FAMILY_PERMISSIVE
    saw_known = False
    for tok in tokens:
        fam = _classify_one(tok)
        if fam == FAMILY_UNKNOWN:
            continue
        saw_known = True
        if (_FAMILY_RESTRICTIVENESS.get(fam, 0)
                > _FAMILY_RESTRICTIVENESS.get(worst, 0)):
            worst = fam
    return worst if saw_known else FAMILY_UNKNOWN


# ---------------------------------------------------------------------------
# Per-package + bulk APIs
# ---------------------------------------------------------------------------


@dataclass
class LicenseViolation:
    """One license-policy violation."""
    package: Package
    license_text: str            # the raw license value as parsed
    family: str                  # one of FAMILY_* constants
    severity: str                # info / low / medium / high
    rationale: str


def _severity_for_family(family: str) -> str:
    """Map license family → finding severity. Conservative —
    weak_copyleft is `low` because SaaS link-only is usually fine,
    full copyleft is `high` because AGPL-licensed deps in a
    proprietary SaaS is a clear license violation."""
    return {
        FAMILY_COPYLEFT: "high",
        FAMILY_COMMERCIAL_RESTRICTED: "high",
        FAMILY_UNKNOWN: "medium",
        FAMILY_WEAK_COPYLEFT: "low",
        FAMILY_PERMISSIVE: "info",
    }.get(family, "info")


def _license_to_text(value) -> str:
    """Stringify a license value of arbitrary shape for the
    finding writeup. Best-effort; doesn't invent."""
    if value is None:
        return "(none)"
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("type") or value.get("name") or str(value)
    if isinstance(value, (list, tuple)):
        parts = [_license_to_text(v) for v in value]
        return ", ".join(p for p in parts if p)
    return str(value)


def find_license_violations(
    packages: Iterable[Package],
    *,
    allow_copyleft: bool = False,
    allow_unknown: bool = False,
    allow_weak_copyleft: bool = True,
    skip_dev_only: bool = True,
) -> list[LicenseViolation]:
    """Walk `packages`, classify each license, emit violations
    per the policy.

    Args:
        packages: Package list (typically from
            `find_lockfiles` → `parse_lockfile`).
        allow_copyleft: when True, GPL/AGPL/SSPL packages don't
            emit violations. Use for OSS projects that ARE GPL.
        allow_unknown: when True, missing-license packages don't
            emit. Rarely the right call — unknown is the
            "everything else" bucket.
        allow_weak_copyleft: when True (default), LGPL/MPL/EPL
            don't emit. Safe for SaaS that links dynamically.
        skip_dev_only: don't flag dev-only deps (test runners,
            linters, build tools). Default True — these don't
            ship to production so license terms typically don't
            apply.

    Returns:
        list of `LicenseViolation` ordered by severity descending.
    """
    out: list[LicenseViolation] = []
    for pkg in packages:
        if skip_dev_only and pkg.dev_only:
            continue
        # Parser must have surfaced license — when it didn't (e.g.
        # cargo / go), there's nothing to classify, skip silently.
        if "license" not in pkg.metadata:
            continue
        lic_value = pkg.metadata.get("license")
        family = classify_license(lic_value)
        if family == FAMILY_PERMISSIVE:
            continue
        if family == FAMILY_WEAK_COPYLEFT and allow_weak_copyleft:
            continue
        if family == FAMILY_COPYLEFT and allow_copyleft:
            continue
        if family == FAMILY_UNKNOWN and allow_unknown:
            continue
        sev = _severity_for_family(family)
        rationale_lines = [
            f"Package `{pkg.ecosystem}:{pkg.name}@{pkg.version}` "
            f"declares license `{_license_to_text(lic_value)}`.",
        ]
        if family == FAMILY_COPYLEFT:
            rationale_lines.append(
                "This is a strong-copyleft license (GPL/AGPL/SSPL "
                "family) — using it in a proprietary SaaS without "
                "complying with the upstream license is a "
                "litigation risk. AGPL specifically treats network "
                "use as distribution; you cannot host an AGPL "
                "library and keep your service code closed."
            )
        elif family == FAMILY_COMMERCIAL_RESTRICTED:
            rationale_lines.append(
                "This is a commercial / restricted license (BUSL / "
                "Elastic / proprietary). Confirm you have explicit "
                "redistribution / use rights — these licenses "
                "often forbid SaaS hosting or impose paid tiers "
                "above usage thresholds."
            )
        elif family == FAMILY_WEAK_COPYLEFT:
            rationale_lines.append(
                "This is a weak-copyleft license (LGPL/MPL/EPL). "
                "Generally safe for SaaS link-only use, but "
                "re-distributing a modified version of the package "
                "requires releasing the modified source under the "
                "same terms."
            )
        elif family == FAMILY_UNKNOWN:
            rationale_lines.append(
                "License is missing or unparseable — without an "
                "SPDX identifier, you can't verify compliance. "
                "Either the package omitted license metadata "
                "(common with hand-rolled npm packages) or our "
                "classifier didn't recognise the SPDX expression."
            )
        out.append(LicenseViolation(
            package=pkg,
            license_text=_license_to_text(lic_value),
            family=family,
            severity=sev,
            rationale=" ".join(rationale_lines),
        ))
    # Severity-descending ordering — wrappers usually want highest
    # priority items first.
    sev_order = {"high": 3, "medium": 2, "low": 1, "info": 0}
    out.sort(key=lambda v: -sev_order.get(v.severity, 0))
    return out
