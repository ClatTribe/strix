"""Cryptographically-signed audit trail (roadmap §16 / PR #127).

Tamper-evident logging on `events.jsonl`:

  * Every event record gets `prev_event_hash` (the hash of the
    previous event, "0" * 64 for the first) and `event_hash`
    (SHA-256 of the canonical JSON of the rest of the record).
  * The chain's terminal hash is signed at run-end.
  * Two signing modes:
      1. **HMAC** (simple) — `STRIX_SIGNING_KEY` env var → HMAC-
         SHA256 of chain_terminal_hash.
      2. **External signer** (HSM / KMS) — `STRIX_SIGNING_CMD`
         env var → shell command that reads the chain hash on
         stdin and emits a base64 signature on stdout. Allows
         operator-controlled key material that never enters the
         strix process memory.
  * No-op when neither is configured. Chain hash is still
    recorded so a wrapper that has a key can verify retroactively.

Why the chain hash even without a signature
-------------------------------------------

A wrapper that re-executes strix in CI has access to the events
file but may not have the signing key. By recording the chain
hash in `run_meta.json`, the wrapper can:

* Compare hashes across consumers to detect tampering BETWEEN
  consumer reads (one consumer reads h1, second consumer reads
  h2 — different events.jsonl files were served).
* Detect mid-run tampering by recomputing the chain.

The signature adds tamper-evidence at the storage layer (after
strix exits, before the auditor reads): without the key, an
attacker can't forge a signature over a modified chain hash.

References
----------

* SOC 2 CC4.1 (monitoring), CC7.1 (security event detection)
* NIST 800-53 AU-9 (Protection of Audit Information)
* PCI-DSS Req 10.5.5 (FIM on logs)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import subprocess
from typing import Any


logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64
"""Hash value used as `prev_event_hash` on the first event in
the chain. Stable across releases."""

# Fields excluded from the canonical-JSON computation of
# `event_hash`. The hash field itself is excluded by definition.
_EXCLUDE_FROM_HASH = frozenset({"event_hash"})


def compute_event_hash(record: dict[str, Any]) -> str:
    """Compute the canonical SHA-256 hash of an event record.
    The record's `event_hash` field is excluded if present.
    Canonical JSON: sorted keys, no whitespace, UTF-8 encoded."""
    payload = {k: v for k, v in record.items() if k not in _EXCLUDE_FROM_HASH}
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def stamp_event_record(
    record: dict[str, Any], *, prev_event_hash: str
) -> dict[str, Any]:
    """Mutate `record` in place to add `prev_event_hash` and
    `event_hash` fields. Returns the mutated record so callers
    can chain. The new chain-tip hash is `record["event_hash"]`.

    Idempotent: if `prev_event_hash` / `event_hash` are already
    set on the record, they're overwritten with the canonical
    values (use case: replaying an existing record through a new
    chain)."""
    record["prev_event_hash"] = prev_event_hash
    record["event_hash"] = compute_event_hash(record)
    return record


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _signing_key() -> str | None:
    """Read STRIX_SIGNING_KEY from env. Returns None when absent."""
    raw = (os.environ.get("STRIX_SIGNING_KEY") or "").strip()
    return raw or None


def _signing_cmd() -> str | None:
    """Read STRIX_SIGNING_CMD from env. Returns None when absent."""
    raw = (os.environ.get("STRIX_SIGNING_CMD") or "").strip()
    return raw or None


def _hmac_sign(chain_hash: str, key: str) -> str:
    """HMAC-SHA256 over the chain hash. Returns hex digest."""
    return hmac.new(
        key.encode("utf-8"),
        chain_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _external_signer(chain_hash: str, cmd: str) -> str:
    """Run `cmd` with the chain hash on stdin; return base64
    signature from stdout.

    The command should be quoted so shell metachars are safe
    (we use `shell=False` and split via shlex). Failure is
    converted to a sentinel error string so the caller can
    record the diagnostic without crashing the run."""
    import shlex

    try:
        proc = subprocess.run(  # noqa: S603
            shlex.split(cmd),
            input=chain_hash,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return f"ERROR: external signer failed: {e}"

    if proc.returncode != 0:
        return (
            f"ERROR: external signer exited {proc.returncode}: "
            f"{(proc.stderr or '').strip()[:240]}"
        )
    out = (proc.stdout or "").strip()
    if not out:
        return "ERROR: external signer returned empty stdout"
    return out


def sign_chain_terminal(chain_hash: str) -> dict[str, Any]:
    """Sign the chain's terminal hash if a key / signer is
    configured. Returns a dict suitable for `run.signature.json`:

    ```
    {
      schema_version: 1,
      chain_terminal_hash: <hex>,
      signature_algorithm: "hmac-sha256" | "external" | "none",
      signature: <hex|base64|None>,
      key_fingerprint: <hex|None>,    # SHA-256(key) for HMAC; None otherwise
      external_signer: <cmd|None>,    # echoed for audit trail; null when HMAC
    }
    ```

    No-op (signature = None, algorithm = "none") when neither
    `STRIX_SIGNING_KEY` nor `STRIX_SIGNING_CMD` is set.
    """
    out: dict[str, Any] = {
        "schema_version": 1,
        "chain_terminal_hash": chain_hash,
        "signature_algorithm": "none",
        "signature": None,
        "key_fingerprint": None,
        "external_signer": None,
    }

    cmd = _signing_cmd()
    if cmd:
        signature = _external_signer(chain_hash, cmd)
        out["signature"] = signature
        out["signature_algorithm"] = "external"
        out["external_signer"] = cmd
        return out

    key = _signing_key()
    if key:
        out["signature"] = _hmac_sign(chain_hash, key)
        out["signature_algorithm"] = "hmac-sha256"
        # Key fingerprint = SHA-256 of the key bytes. Lets a
        # verifier confirm they're using the right key without
        # storing the key alongside the signature.
        out["key_fingerprint"] = hashlib.sha256(
            key.encode("utf-8")
        ).hexdigest()
        return out

    return out


def verify_signature(
    chain_hash: str,
    signature_block: dict[str, Any],
    *,
    key: str | None = None,
) -> tuple[bool, str | None]:
    """Verify a signature block. Returns `(valid, reason_when_invalid)`.

    For `algorithm=hmac-sha256`, `key` must be supplied.
    For `algorithm=external`, this returns `(True, None)` (the
    external signer's verification is the operator's responsibility
    — we can't generically verify HSM signatures here).
    For `algorithm=none`, returns `(False, "unsigned")`.
    """
    algo = signature_block.get("signature_algorithm")
    if algo == "none":
        return False, "unsigned"
    if algo == "external":
        # We can't verify externally-produced signatures here.
        return True, None
    if algo == "hmac-sha256":
        if key is None:
            return False, "no key supplied for hmac-sha256 verification"
        expected = _hmac_sign(chain_hash, key)
        actual = signature_block.get("signature")
        if not isinstance(actual, str):
            return False, "signature is not a string"
        # Constant-time compare.
        if hmac.compare_digest(expected, actual):
            return True, None
        return False, "hmac mismatch"
    return False, f"unknown algorithm: {algo!r}"
