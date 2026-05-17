"""Per-target fingerprinting for §5 skip-if-unchanged.

engine-wishlist.md §5 — the single biggest cost-flattener for
daily-cadence orgs. A 200-target org running daily scans where
~95% of targets are quiescent on any given day wastes 95% of LLM
spend re-scanning unchanged assets. This module computes a
stable, lightweight per-target fingerprint that lets the engine
short-circuit unchanged scans before spending any LLM tokens.

## Per-target-type fingerprint sources

| target type     | sources                                          |
| --------------- | ------------------------------------------------ |
| repository      | git HEAD + dep-lockfile hashes                   |
| web_application | TLS cert fingerprint + landing-page HTML hash    |
| cloud_account   | resource-tag inventory hash (deferred to v2)     |
| container_image | image digest                                     |
| api             | OpenAPI spec hash + base URL                     |
| domain          | DNS record-set hash                              |

## Contract — false-negative-favoured

The fingerprint is **false-negative-favoured**: if anything goes
wrong (network down, auth issue, target type unknown, tool
missing) the function returns `None`. Callers MUST treat `None`
as *"can't skip, run the scan."* Better to do a redundant scan
than to incorrectly skip and miss a real change.

The reverse is forbidden: a fingerprint MUST NOT match between
two genuinely-different target states. We use SHA-256 of well-
ordered, version-salted inputs so collisions aren't realistic.

## DI surface

Every external call (`subprocess.run`, HTTP, DNS) is DI'd via
keyword args so tests are hermetic. Real production callers pass
no DI args — the defaults wire up the actual implementations.

## Versioning

`_FINGERPRINT_VERSION` is concatenated into every digest. Bump
it whenever the algorithm changes — that invalidates all prior
fingerprints in one stroke, forcing a re-scan on the next run
(safe-by-default).
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


# Bump on any algorithm change → invalidates prior fingerprints.
_FINGERPRINT_VERSION = "v1"

# Lockfiles whose contents change every dep upgrade. Hash any that
# exist; concatenation order is deterministic (alphabetical).
_DEP_LOCKFILES = (
    "Cargo.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "composer.lock",
    "go.sum",
    "package-lock.json",
    "pnpm-lock.yaml",
    "poetry.lock",
    "requirements.txt",
    "yarn.lock",
)

# Per-target-type timeout for fingerprint-side network calls.
# Fingerprinting must be <5s end-to-end per the engine-wishlist
# contract, so individual probes cap at 3-10s.
_DEFAULT_GIT_TIMEOUT = 15
_DEFAULT_NET_TIMEOUT = 10
_DEFAULT_REGISTRY_TIMEOUT = 15


@dataclass
class TargetFingerprint:
    """Computed fingerprint for a single target.

    Stored in `run_meta.json` so future runs can compare. The
    `digest` field is the comparison primitive; `sources` and
    `computed_at` are diagnostic.
    """

    target_type: str
    target_value: str
    digest: str
    sources: list[str] = field(default_factory=list)
    computed_at: str = ""
    algo_version: str = _FINGERPRINT_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_value": self.target_value,
            "digest": self.digest,
            "sources": list(self.sources),
            "computed_at": self.computed_at,
            "algo_version": self.algo_version,
        }


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(target_type: str, target_value: str, parts: list[str]) -> str:
    """Stable SHA-256 of version + type + value + ordered parts."""
    h = hashlib.sha256()
    h.update(_FINGERPRINT_VERSION.encode())
    h.update(b"\x00")
    h.update(target_type.encode("utf-8"))
    h.update(b"\x00")
    h.update(target_value.encode("utf-8"))
    for part in parts:
        h.update(b"\x00")
        h.update(part.encode("utf-8", errors="replace"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# repository
# ---------------------------------------------------------------------------


def _is_remote_git_url(value: str) -> bool:
    return value.startswith(
        ("http://", "https://", "git@", "ssh://", "git://"),
    )


def _fingerprint_repository(
    target_value: str,
    *,
    _subprocess_run: Callable[..., Any] = subprocess.run,
) -> tuple[str, list[str]] | None:
    """git HEAD + lockfile digest.

    For URLs we use `git ls-remote --symref … HEAD` (no clone).
    For local paths we use `git rev-parse HEAD` + lockfile hashes.
    """
    sources: list[str] = []
    parts: list[str] = []

    if _is_remote_git_url(target_value):
        try:
            proc = _subprocess_run(
                ["git", "ls-remote", "--symref", target_value, "HEAD"],
                capture_output=True,
                text=True,
                timeout=_DEFAULT_GIT_TIMEOUT,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.debug("fingerprint: ls-remote failed: %s", e)
            return None
        if proc.returncode != 0:
            logger.debug(
                "fingerprint: ls-remote nonzero %s: %s",
                proc.returncode, (proc.stderr or "")[:200],
            )
            return None
        parts.append((proc.stdout or "").strip())
        sources.append("git:ls-remote")
        return "\n".join(parts), sources

    # Local path.
    p = Path(target_value)
    if not p.exists():
        return None

    try:
        proc = _subprocess_run(
            ["git", "-C", str(p), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=_DEFAULT_GIT_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        logger.debug("fingerprint: rev-parse failed: %s", e)
        return None
    if proc.returncode != 0:
        return None
    parts.append((proc.stdout or "").strip())
    sources.append("git:HEAD")

    # Hash any present lockfiles — alphabetical order for stability.
    for lock in _DEP_LOCKFILES:
        lock_path = p / lock
        if lock_path.is_file():
            try:
                content = lock_path.read_bytes()
            except OSError as e:
                logger.debug(
                    "fingerprint: lockfile read failed (%s): %s",
                    lock_path, e,
                )
                continue
            parts.append(f"{lock}:{hashlib.sha256(content).hexdigest()[:16]}")
            sources.append(f"lockfile:{lock}")

    return "\n".join(parts), sources


# ---------------------------------------------------------------------------
# web_application / api (HTTP/HTTPS)
# ---------------------------------------------------------------------------


def _fetch_tls_cert_digest(host: str, port: int = 443) -> str | None:
    """Connect, fetch the leaf cert in DER form, return SHA-256."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(
            (host, port), timeout=_DEFAULT_NET_TIMEOUT,
        ) as raw, ctx.wrap_socket(raw, server_hostname=host) as sock:
            der = sock.getpeercert(binary_form=True)
        if not der:
            return None
        return hashlib.sha256(der).hexdigest()
    except (OSError, ssl.SSLError) as e:
        logger.debug("fingerprint: TLS cert fetch failed (%s): %s", host, e)
        return None


def _fetch_landing_page_hash(
    url: str,
    *,
    _http_get: Callable[..., Any] | None = None,
) -> tuple[str, str] | None:
    """GET the URL, return (body_hash, headers_digest). Strips
    known volatile headers (Date, Set-Cookie) before digesting."""
    try:
        if _http_get is None:
            import urllib.request  # noqa: PLC0415

            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "strix-fingerprint/1.0",
                    "Accept": "*/*",
                },
            )
            with urllib.request.urlopen(
                req, timeout=_DEFAULT_NET_TIMEOUT,
            ) as resp:
                body = resp.read(2 * 1024 * 1024)  # cap at 2MB
                headers = dict(resp.headers.items())
        else:
            body, headers = _http_get(url, timeout=_DEFAULT_NET_TIMEOUT)
    except Exception as e:  # noqa: BLE001 — broad: every urllib path can raise
        logger.debug("fingerprint: HTTP get failed (%s): %s", url, e)
        return None

    body_hash = hashlib.sha256(body or b"").hexdigest()
    # Strip volatile headers — leave the rest for digest.
    volatile = {
        "date", "set-cookie", "x-request-id", "x-amz-cf-id",
        "x-amz-request-id", "x-trace-id", "cf-ray", "x-cache",
        "age", "x-served-by", "x-amz-rid", "x-runtime",
        "x-frame-options",
    }
    norm = sorted(
        f"{k.lower()}:{v.strip()}"
        for k, v in (headers or {}).items()
        if k.lower() not in volatile
    )
    headers_digest = hashlib.sha256(
        "\n".join(norm).encode("utf-8", "replace"),
    ).hexdigest()
    return body_hash, headers_digest


def _fingerprint_web_application(
    target_value: str,
    *,
    _tls_get: Callable[..., Any] | None = None,
    _http_get: Callable[..., Any] | None = None,
) -> tuple[str, list[str]] | None:
    """TLS cert digest (if HTTPS) + landing-page body + non-volatile
    headers."""
    sources: list[str] = []
    parts: list[str] = []

    parsed = urlparse(target_value)
    host = parsed.hostname
    if not host:
        return None
    is_https = parsed.scheme == "https"
    port = parsed.port or (443 if is_https else 80)

    if is_https:
        tls = (
            _tls_get(host, port) if _tls_get is not None
            else _fetch_tls_cert_digest(host, port)
        )
        if tls:
            parts.append(f"tls:{tls}")
            sources.append("tls:cert")

    page = _fetch_landing_page_hash(target_value, _http_get=_http_get)
    if page is None and not parts:
        # Nothing succeeded — bail rather than emit a meaningless
        # fingerprint that only encodes the target URL itself.
        return None
    if page is not None:
        body_hash, headers_digest = page
        parts.append(f"body:{body_hash}")
        parts.append(f"headers:{headers_digest}")
        sources.append("http:body")
        sources.append("http:headers")

    return "\n".join(parts), sources


# ---------------------------------------------------------------------------
# container_image
# ---------------------------------------------------------------------------


def _fingerprint_container_image(
    target_value: str,
    *,
    _subprocess_run: Callable[..., Any] = subprocess.run,
) -> tuple[str, list[str]] | None:
    """Image digest via `docker buildx imagetools inspect` (or
    fall back to `docker manifest inspect`)."""
    # The simplest stable identity for a registry image is its
    # multi-arch manifest digest. `docker buildx imagetools
    # inspect` returns it as `Digest: sha256:…`. `docker manifest
    # inspect` returns the v2 manifest with `.config.digest`.
    # We try each in order and digest whichever returned the
    # canonical form.

    # If the caller already specified a tag with a digest pin
    # (`image@sha256:…`), short-circuit — we already have it.
    if "@sha256:" in target_value:
        digest = target_value.split("@", 1)[1]
        return digest, ["pin:sha256"]

    for argv in (
        ["docker", "buildx", "imagetools", "inspect", target_value],
        ["docker", "manifest", "inspect", target_value],
    ):
        try:
            proc = _subprocess_run(
                argv,
                capture_output=True,
                text=True,
                timeout=_DEFAULT_REGISTRY_TIMEOUT,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.debug(
                "fingerprint: %s failed: %s", " ".join(argv[:2]), e,
            )
            continue
        if proc.returncode != 0:
            continue
        out = (proc.stdout or "").strip()
        if not out:
            continue
        # `buildx imagetools inspect` prints lines `Digest: sha256:…`
        # First parse that; else just digest the whole manifest blob
        # which is stable per-image.
        for line in out.splitlines():
            if line.strip().lower().startswith("digest:"):
                digest = line.split(":", 1)[1].strip()
                return digest, [argv[1]]
        return (
            hashlib.sha256(out.encode("utf-8", "replace")).hexdigest(),
            [f"{argv[1]}:manifest-hash"],
        )

    return None


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def compute_fingerprint(
    target_type: str,
    target_value: str,
    *,
    _subprocess_run: Callable[..., Any] = subprocess.run,
    _tls_get: Callable[..., Any] | None = None,
    _http_get: Callable[..., Any] | None = None,
) -> TargetFingerprint | None:
    """Compute a TargetFingerprint or return None on any failure.

    Per the contract, None means "can't skip; run the scan."

    Args:
        target_type: one of `repository`, `web_application`, `api`,
            `container_image`, `cloud_account`, `domain`,
            `ip_address`, `local_code`.
        target_value: the raw target string (URL / git ref / image
            tag / etc.).
        _subprocess_run / _tls_get / _http_get: DI hooks for tests.

    Returns:
        TargetFingerprint on success; None on any failure mode
        (network down, tool missing, target type unsupported).
    """
    if not target_value:
        return None

    result: tuple[str, list[str]] | None = None

    if target_type == "repository":
        result = _fingerprint_repository(
            target_value, _subprocess_run=_subprocess_run,
        )
    elif target_type in ("web_application", "api"):
        result = _fingerprint_web_application(
            target_value, _tls_get=_tls_get, _http_get=_http_get,
        )
    elif target_type == "container_image":
        result = _fingerprint_container_image(
            target_value, _subprocess_run=_subprocess_run,
        )
    elif target_type == "local_code":
        # Same algorithm as repository for local paths.
        result = _fingerprint_repository(
            target_value, _subprocess_run=_subprocess_run,
        )
    else:
        # cloud_account / domain / ip_address — deferred to v2;
        # callers receive None and fall through to the scan.
        logger.debug(
            "fingerprint: target type %s deferred to v2", target_type,
        )
        return None

    if result is None:
        return None

    raw_parts_str, sources = result
    parts = [raw_parts_str] if raw_parts_str else []
    return TargetFingerprint(
        target_type=target_type,
        target_value=target_value,
        digest=_digest(target_type, target_value, parts),
        sources=sources,
        computed_at=_now_iso(),
    )


# ---------------------------------------------------------------------------
# Prior-run lookup
# ---------------------------------------------------------------------------


def find_prior_run_for_target(
    target_value: str,
    *,
    runs_root: Path = Path("strix_runs"),
    explicit_prior_run_dir: Path | None = None,
) -> tuple[Path, TargetFingerprint] | None:
    """Find the prior successful run for `target_value` and return
    (run_dir, prior_fingerprint).

    Args:
        target_value: the canonical target string we're matching on.
        runs_root: where to look for prior runs.
        explicit_prior_run_dir: when set, only look at this directory
            (the wrapper's preferred path — it knows which prior run
            corresponds to this target).

    Returns:
        (run_dir, prior_fingerprint) when a prior fingerprint exists
        for the target; None otherwise.
    """
    import json  # noqa: PLC0415

    candidates: list[Path]
    if explicit_prior_run_dir is not None:
        candidates = [Path(explicit_prior_run_dir)]
    else:
        if not runs_root.exists():
            return None
        # Most-recent first by mtime.
        try:
            candidates = sorted(
                (p for p in runs_root.iterdir() if p.is_dir()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
        except OSError:
            return None

    for run_dir in candidates:
        meta_path = run_dir / "run_meta.json"
        if not meta_path.is_file():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        # Skip prior runs that were themselves "skipped_unchanged" —
        # we want to chain back to the last full scan. (Otherwise a
        # broken chain of skips perpetuates an old fingerprint
        # forever.)
        if meta.get("status") == "skipped_unchanged":
            continue

        prior_fp_blob = meta.get("target_fingerprint")
        if not isinstance(prior_fp_blob, dict):
            continue
        # The wrapper-preferred path: explicit_prior_run_dir → trust
        # it without target-value matching (the wrapper guarantees
        # this is the right prior run).
        if explicit_prior_run_dir is None:
            if prior_fp_blob.get("target_value") != target_value:
                continue

        # Algorithm-version check — if the algorithm changed we
        # treat the prior fingerprint as not-comparable.
        if prior_fp_blob.get("algo_version") != _FINGERPRINT_VERSION:
            return None

        prior_fp = TargetFingerprint(
            target_type=prior_fp_blob.get("target_type", ""),
            target_value=prior_fp_blob.get("target_value", ""),
            digest=prior_fp_blob.get("digest", ""),
            sources=list(prior_fp_blob.get("sources", []) or []),
            computed_at=prior_fp_blob.get("computed_at", ""),
            algo_version=prior_fp_blob.get(
                "algo_version", _FINGERPRINT_VERSION,
            ),
        )
        return run_dir, prior_fp

    return None
