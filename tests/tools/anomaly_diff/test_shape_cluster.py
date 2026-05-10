"""Unit tests for `strix.tools.anomaly_diff.shape_cluster`."""

from __future__ import annotations

from strix.tools.anomaly_diff.shape_cluster import (
    fingerprint_response,
    find_shape_outliers,
)


def _resp(status: int = 200, body: str = '{"id":1}',
          ct: str = "application/json") -> dict:
    return {"status": status, "body": body,
            "headers": {"Content-Type": ct}}


def test_fingerprint_identical_responses_match() -> None:
    a = _resp()
    b = _resp()
    assert fingerprint_response(a) == fingerprint_response(b)


def test_fingerprint_different_status_doesnt_match() -> None:
    assert fingerprint_response(_resp(status=200)) \
        != fingerprint_response(_resp(status=500))


def test_fingerprint_different_content_type_doesnt_match() -> None:
    assert fingerprint_response(_resp(ct="application/json")) \
        != fingerprint_response(_resp(ct="text/html"))


def test_fingerprint_same_keys_different_values_match() -> None:
    """Two JSON responses with the same shape but different
    values should fingerprint identically — the body-key-hash
    only considers keys, not values."""
    a = _resp(body='{"id":1, "name":"alice"}')
    b = _resp(body='{"id":2, "name":"bob"}')
    assert fingerprint_response(a) == fingerprint_response(b)


def test_fingerprint_different_keys_dont_match() -> None:
    a = _resp(body='{"id":1}')
    b = _resp(body='{"id":1, "secret":"x"}')
    assert fingerprint_response(a) != fingerprint_response(b)


def test_fingerprint_invalid_response_returns_invalid() -> None:
    assert fingerprint_response(None) == "invalid"
    assert fingerprint_response("not a dict") == "invalid"


# ---------------------------------------------------------------------------
# find_shape_outliers
# ---------------------------------------------------------------------------


def test_find_outliers_in_corpus_with_one_unique() -> None:
    """5 identical responses + 1 different → the different one
    is the outlier."""
    corpus = [_resp() for _ in range(5)] + [_resp(status=500, body="ERR")]
    outliers = find_shape_outliers(corpus, min_corpus_size=5)
    assert len(outliers) == 1
    assert outliers[0].response_index == 5
    assert outliers[0].cluster_size == 1


def test_find_outliers_below_min_corpus_size_returns_empty() -> None:
    """A corpus too small to be meaningful — every entry would
    be 'rare'. Return empty rather than false-positive everything."""
    corpus = [_resp(), _resp(status=500)]
    outliers = find_shape_outliers(corpus, min_corpus_size=5)
    assert outliers == []


def test_find_outliers_in_uniform_corpus_returns_empty() -> None:
    """All identical → no outliers."""
    corpus = [_resp() for _ in range(10)]
    outliers = find_shape_outliers(corpus)
    assert outliers == []


def test_find_outliers_preserves_response_index() -> None:
    """The returned outlier should reference the original
    corpus index so the caller can correlate back."""
    corpus = [_resp() for _ in range(5)]
    corpus[2] = _resp(status=500, body="ERR")  # outlier at index 2
    outliers = find_shape_outliers(corpus, min_corpus_size=5)
    assert len(outliers) == 1
    assert outliers[0].response_index == 2


def test_find_outliers_max_cluster_size_threshold() -> None:
    """outlier_max_cluster_size=2 — a cluster of 2 is also an
    outlier (rare-ish vs the rest)."""
    corpus = [_resp() for _ in range(10)] + [
        _resp(status=500), _resp(status=500),
    ]
    outliers = find_shape_outliers(
        corpus, min_corpus_size=5, outlier_max_cluster_size=2,
    )
    # The two 500-responses form a cluster of size 2 → both
    # flagged as outliers under this threshold.
    assert len(outliers) == 2
