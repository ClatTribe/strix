"""Response-shape clustering — Phase 9.6.

Group probe responses by their (status × length-bucket ×
content-type × body-key-hash) fingerprint. Outliers — clusters
of size 1 across a corpus of probes that should be returning
similar shapes — signal novel behaviour worth investigating.

Pairs with the mutation fuzzer (Phase 13.5) — when the fuzzer
sends 100 mutations of the same payload, 99 should produce the
same fingerprint; the 1 outlier is the interesting one.

Used by `scan_response_anomaly` as a complementary signal to
the per-baseline diff: a probe might not flag any individual
diff classes, but if its fingerprint is unique across a
corpus, that's still a "different" signal worth surfacing.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


# Body length bucketing — log-scale, so a 100-byte response and
# a 200-byte response collapse to the same bucket but a 100-byte
# vs 5000-byte don't. Stable enough for fingerprinting.
_LENGTH_BUCKETS = [
    (0, "empty"),
    (100, "tiny"),
    (1024, "small"),
    (10_240, "medium"),
    (102_400, "large"),
]


def _length_bucket(length: int) -> str:
    last = "huge"
    for threshold, label in _LENGTH_BUCKETS:
        if length <= threshold:
            return label
    return last


def _body_key_hash(body: str, content_type: str) -> str:
    """For JSON: hash of the sorted top-level key set. Identical
    JSON shapes produce identical hashes regardless of value
    differences. For non-JSON: hash of the first 512 bytes
    (catches templated HTML; ignores per-request data)."""
    ct = (content_type or "").lower()
    if "json" in ct:
        try:
            doc = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return _short_hash(body[:512])
        if isinstance(doc, dict):
            keys = sorted(str(k) for k in doc.keys())
            return _short_hash("|".join(keys))
        if isinstance(doc, list) and doc and isinstance(doc[0], dict):
            keys = sorted(str(k) for k in doc[0].keys())
            return _short_hash("[]|" + "|".join(keys))
        return "json:other"
    return _short_hash(body[:512])


def _short_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="replace")).hexdigest()[:12]


def fingerprint_response(response: dict[str, Any]) -> str:
    """Return a fingerprint string `status|length-bucket|ct|body-key-hash`.

    Two responses with the same fingerprint are
    behaviourally-equivalent for our purposes; one outlier in a
    corpus of identical fingerprints is suspicious.
    """
    if not isinstance(response, dict):
        return "invalid"
    status = response.get("status", 0)
    body = response.get("body") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    headers = response.get("headers") or {}
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = str(v).split(";", 1)[0].strip().lower()
            break
    return (
        f"{status}|{_length_bucket(len(body))}|{ct or '?'}"
        f"|{_body_key_hash(body, ct)}"
    )


@dataclass
class ShapeOutlier:
    """One probe response that has a unique fingerprint across
    the corpus."""
    response_index: int
    fingerprint: str
    cluster_size: int       # always 1 for true outliers
    response: dict


def find_shape_outliers(
    responses: list[dict[str, Any]],
    *,
    min_corpus_size: int = 5,
    outlier_max_cluster_size: int = 1,
) -> list[ShapeOutlier]:
    """Return responses whose fingerprint is unique (or nearly
    so) across the corpus.

    Args:
        responses: list of probe responses (caller's order).
        min_corpus_size: don't classify outliers when the
            corpus is too small; with 3 probes any one is
            "rare". Default 5.
        outlier_max_cluster_size: a cluster of size <= this is
            an outlier. Default 1 (truly unique).

    Returns:
        list of `ShapeOutlier` with the original response index
        preserved so the caller can correlate back to the probe
        that produced it.
    """
    if len(responses) < min_corpus_size:
        return []
    clusters: dict[str, list[int]] = {}
    fingerprints: list[str] = []
    for i, r in enumerate(responses):
        fp = fingerprint_response(r)
        fingerprints.append(fp)
        clusters.setdefault(fp, []).append(i)

    out: list[ShapeOutlier] = []
    for i, fp in enumerate(fingerprints):
        sz = len(clusters[fp])
        if sz <= outlier_max_cluster_size:
            out.append(ShapeOutlier(
                response_index=i,
                fingerprint=fp,
                cluster_size=sz,
                response=responses[i],
            ))
    return out
