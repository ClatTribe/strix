"""iter-Q5.48 — `extract_sbom_syft` subprocess wrapper.

Syft (Anchore) is the de-facto-standard SBOM (Software Bill of
Materials) generator. Produces CycloneDX, SPDX, and syft-native JSON
formats for any container image, filesystem, or repository.

Why SBOM
--------

* **Compliance evidence** — SOC2 / PCI / FedRAMP require SBOM
  generation. The L1.5 compliance-evidence emitter folds the syft
  output into the final compliance artifact.
* **Dependency graph** — feeds the KG Dependency-node emitter so
  cross-asset chaining (image → app → lockfile) can correlate
  package versions across the asset graph.
* **Tool-input** — grype + trivy both accept syft JSON as input,
  cutting their re-discovery cost. Future iters may wire this
  pipeline.

trivy already emits inline SBOM data per its `--scanners` config;
syft produces a richer, format-canonical SBOM independent of CVE
matching. Both ship in parallel; the L1.5 SBOM-merger collapses
duplicate package records.

Recall safety: `status=partial` when the binary is missing.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess  # noqa: S404
from typing import Any


logger = logging.getLogger(__name__)


_SYFT_BIN = "syft"
_DEFAULT_TIMEOUT_SECONDS = 300

_VALID_FORMATS = {
    "syft-json", "cyclonedx-json", "cyclonedx-xml",
    "spdx-json", "spdx-tag-value", "table", "github-json",
}


def _syft_available() -> bool:
    """True iff `syft` is on PATH AND the kill switch isn't set."""
    if os.environ.get(
        "STRIX_SYFT_DISABLED", "",
    ).strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return shutil.which(_SYFT_BIN) is not None


from strix.tools.registry import register_tool  # noqa: E402


@register_tool(
    sandbox_execution=True,
    # T1592.002 Gather Victim Host Information: Software.
    mitre_techniques=["T1592.002"],
)
def extract_sbom_syft(
    image_ref: str,
    sbom_format: str = "cyclonedx-json",
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Generate an SBOM for a container image via syft.

    Args:
        image_ref: image reference (e.g. ``nginx:1.25``,
            ``registry.example.com/foo/bar:tag``,
            ``nginx@sha256:0123...abcd``). Required.
        sbom_format: output format. Default ``cyclonedx-json``
            (most-portable SBOM standard). Accepts: ``syft-json``,
            ``cyclonedx-json``, ``cyclonedx-xml``, ``spdx-json``,
            ``spdx-tag-value``, ``table``, ``github-json``.
            Env override: ``STRIX_SYFT_FORMAT``.
        timeout_seconds: syft invocation timeout. Default 300s.

    Returns:
        ```
        {success, status, image_ref, format,
         sbom: <parsed dict for JSON formats / str otherwise>,
         package_count: int, reason?}
        ```

    JSON formats are parsed into a dict and exposed under ``sbom``.
    Text formats are returned as the raw string. ``package_count`` is
    best-effort across formats so callers always have a quick metric.
    """
    if not isinstance(image_ref, str) or not image_ref.strip():
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "format": sbom_format,
            "sbom": None, "package_count": 0,
            "reason": "image_ref required",
        }
    if not _syft_available():
        return {
            "success": True, "status": "partial",
            "image_ref": image_ref, "format": sbom_format,
            "sbom": None, "package_count": 0,
            "reason": (
                "syft binary not on PATH (or STRIX_SYFT_DISABLED=1). "
                "Install via `curl -sSfL https://raw.githubusercontent."
                "com/anchore/syft/main/install.sh | sh -s -- -b "
                "/usr/local/bin`."
            ),
        }

    # Format env fallback.
    env_format = os.environ.get("STRIX_SYFT_FORMAT", "").strip()
    if env_format:
        sbom_format = env_format

    fmt = sbom_format.strip().lower()
    if fmt not in _VALID_FORMATS:
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "format": sbom_format,
            "sbom": None, "package_count": 0,
            "reason": (
                f"unsupported sbom_format {sbom_format!r}; "
                f"valid: {sorted(_VALID_FORMATS)}"
            ),
        }

    cmd = [_SYFT_BIN, image_ref.strip(), "-o", fmt, "-q"]

    try:
        result = subprocess.run(  # noqa: S603
            cmd, check=False, capture_output=True,
            timeout=timeout_seconds, text=True,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "format": fmt,
            "sbom": None, "package_count": 0,
            "reason": f"syft invocation failed: {type(e).__name__}: {e}",
        }

    if result.returncode != 0:
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "format": fmt,
            "sbom": None, "package_count": 0,
            "reason": (
                f"syft returned exit {result.returncode}: "
                f"{(result.stderr or '').strip()[:300]}"
            ),
        }
    if not (result.stdout or "").strip():
        return {
            "success": False, "status": "error",
            "image_ref": image_ref, "format": fmt,
            "sbom": None, "package_count": 0,
            "reason": "syft produced no output",
        }

    sbom_payload: dict[str, Any] | str
    package_count = 0
    if fmt.endswith("-json"):
        try:
            sbom_payload = json.loads(result.stdout)
            package_count = _count_packages(sbom_payload, fmt)
        except (ValueError, TypeError) as e:
            return {
                "success": False, "status": "error",
                "image_ref": image_ref, "format": fmt,
                "sbom": None, "package_count": 0,
                "reason": f"syft JSON output unparseable: {e}",
            }
    else:
        sbom_payload = result.stdout
        # Best-effort line count for table format.
        package_count = max(0, sum(1 for ln in result.stdout.splitlines() if ln.strip()) - 1)

    return {
        "success": True,
        "status": "ok",
        "image_ref": image_ref,
        "format": fmt,
        "sbom": sbom_payload,
        "package_count": package_count,
    }


def _count_packages(payload: Any, fmt: str) -> int:
    """Best-effort package count across syft JSON variants."""
    if not isinstance(payload, dict):
        return 0
    # CycloneDX
    components = payload.get("components")
    if isinstance(components, list):
        return len(components)
    # SPDX
    pkgs = payload.get("packages")
    if isinstance(pkgs, list):
        return len(pkgs)
    # syft-json
    artifacts = payload.get("artifacts")
    if isinstance(artifacts, list):
        return len(artifacts)
    return 0
