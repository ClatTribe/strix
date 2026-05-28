"""Tests for iter-Q7.2 — WAVSEP fixture smoke gate.

The gate HEADs a sample of expected URLs from `expected-cases.csv`
and refuses to run the bench when fewer than `_SMOKE_MIN_HIT_RATE`
return 2xx/3xx. Catches the `zaproxy/wavsep:latest`-style "empty
webapp" failure mode where the landing page is mounted in but the
JSP test cases aren't deployed — that scenario previously wasted
53 minutes of wall time and produced 98 pattern-match false
positives on Tomcat's encoded error pages.
"""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock, patch

import pytest

bench = importlib.import_module("benchmarks.per_target.bench_wavsep")


class _Expectation:
    """Minimal stand-in for `WavsepExpectation` — only `.url_path` is read."""

    def __init__(self, url_path: str):
        self.url_path = url_path


@pytest.fixture
def _reset_env(monkeypatch):
    monkeypatch.delenv(bench._SMOKE_DISABLE_ENV, raising=False)
    yield


def _mock_urlopen_with_codes(monkeypatch, codes: list[int | str]):
    """Stub urllib.request.urlopen so each successive call returns
    the next code from `codes`. String codes simulate exceptions
    ("err" → URLError; "http400" → HTTPError 400)."""
    import urllib.error
    import urllib.request

    iter_codes = iter(codes)

    class _Resp:
        def __init__(self, status):
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    def _fake_urlopen(req, timeout=None):  # noqa: ARG001
        code = next(iter_codes)
        if isinstance(code, str):
            if code.startswith("http"):
                http_code = int(code.removeprefix("http"))
                raise urllib.error.HTTPError(
                    req.full_url, http_code, "fixture failure", {}, None,  # type: ignore[arg-type]
                )
            raise urllib.error.URLError(f"simulated {code}")
        return _Resp(code)

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)


# ----------------------------------------------------------------------
# Hit-rate behaviour
# ----------------------------------------------------------------------

class TestSmokeGate:
    def test_all_200_passes(self, monkeypatch, _reset_env):
        _mock_urlopen_with_codes(monkeypatch, [200] * 10)
        with patch.object(bench, "_compose_down"):
            bench._smoke_test_expected_cases(
                "http://localhost:8098",
                [_Expectation(f"/wavsep/a/case{i}.jsp") for i in range(10)],
            )

    def test_all_404_raises(self, monkeypatch, _reset_env):
        """The original failure mode — every expected URL 404s."""
        _mock_urlopen_with_codes(monkeypatch, ["http404"] * 10)
        with patch.object(bench, "_compose_down") as mock_down:
            with pytest.raises(RuntimeError, match="smoke test failed"):
                bench._smoke_test_expected_cases(
                    "http://localhost:8098",
                    [_Expectation(f"/wavsep/a/case{i}.jsp") for i in range(10)],
                )
            # Bench tore down the broken compose stack on failure.
            mock_down.assert_called_once()

    def test_threshold_boundary_50_percent_passes(self, monkeypatch, _reset_env):
        """5 hits + 5 misses = 50% — exactly at threshold, no raise."""
        _mock_urlopen_with_codes(monkeypatch, [200] * 5 + ["http404"] * 5)
        with patch.object(bench, "_compose_down"):
            bench._smoke_test_expected_cases(
                "http://localhost:8098",
                [_Expectation(f"/wavsep/a/case{i}.jsp") for i in range(10)],
            )

    def test_threshold_boundary_40_percent_fails(self, monkeypatch, _reset_env):
        """4 hits + 6 misses = 40% — below threshold, raise."""
        _mock_urlopen_with_codes(monkeypatch, [200] * 4 + ["http404"] * 6)
        with patch.object(bench, "_compose_down"):
            with pytest.raises(RuntimeError):
                bench._smoke_test_expected_cases(
                    "http://localhost:8098",
                    [_Expectation(f"/wavsep/a/case{i}.jsp") for i in range(10)],
                )

    def test_redirects_count_as_hits(self, monkeypatch, _reset_env):
        """3xx is acceptable — some WAVSEP cases redirect by design."""
        _mock_urlopen_with_codes(monkeypatch, [301, 302, 303, 307, 308] + [200] * 5)
        with patch.object(bench, "_compose_down"):
            bench._smoke_test_expected_cases(
                "http://localhost:8098",
                [_Expectation(f"/wavsep/a/case{i}.jsp") for i in range(10)],
            )

    def test_500_counts_as_miss(self, monkeypatch, _reset_env):
        """5xx is a server failure, NOT a deployed-case signal."""
        _mock_urlopen_with_codes(
            monkeypatch, [200] * 2 + ["http500"] * 8,
        )
        with patch.object(bench, "_compose_down"):
            with pytest.raises(RuntimeError):
                bench._smoke_test_expected_cases(
                    "http://localhost:8098",
                    [_Expectation(f"/wavsep/a/case{i}.jsp") for i in range(10)],
                )

    def test_connection_errors_count_as_misses(self, monkeypatch, _reset_env):
        """Network failures = miss. Catches the case where the compose
        stack came up but isn't actually listening on the port."""
        _mock_urlopen_with_codes(monkeypatch, ["err"] * 10)
        with patch.object(bench, "_compose_down"):
            with pytest.raises(RuntimeError):
                bench._smoke_test_expected_cases(
                    "http://localhost:8098",
                    [_Expectation(f"/wavsep/a/case{i}.jsp") for i in range(10)],
                )


# ----------------------------------------------------------------------
# Sampling — even spread across categories
# ----------------------------------------------------------------------

class TestSmokeSampling:
    def test_samples_evenly_spread(self, monkeypatch, _reset_env):
        """With 1000 expectations and probe_count=10, we should sample
        every 100th — not just the first 10 (which would all be the
        same WAVSEP category)."""
        captured: list[str] = []

        class _Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): return None

        def _fake_urlopen(req, timeout=None):  # noqa: ARG001
            captured.append(req.full_url)
            return _Resp()

        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

        with patch.object(bench, "_compose_down"):
            bench._smoke_test_expected_cases(
                "http://localhost:8098",
                [_Expectation(f"/case-{i:04d}.jsp") for i in range(1000)],
            )
        assert len(captured) == bench._SMOKE_PROBE_COUNT
        # Step is 1000 // 10 = 100; first probed URL is `case-0000`,
        # last is `case-0900`.
        assert "/case-0000.jsp" in captured[0]
        assert "/case-0900.jsp" in captured[-1]

    def test_small_corpus_doesnt_oversample(self, monkeypatch, _reset_env):
        """If there are only 3 expectations, we probe 3 (not 10)."""
        _mock_urlopen_with_codes(monkeypatch, [200, 200, 200])
        with patch.object(bench, "_compose_down"):
            bench._smoke_test_expected_cases(
                "http://localhost:8098",
                [_Expectation(f"/c{i}.jsp") for i in range(3)],
            )


# ----------------------------------------------------------------------
# Escape hatch + edge cases
# ----------------------------------------------------------------------

class TestSmokeEscapeHatches:
    def test_disable_env_skips_smoke(self, monkeypatch):
        monkeypatch.setenv(bench._SMOKE_DISABLE_ENV, "1")
        # Even with no expectations + no mocked urlopen, this must not
        # raise — the gate is fully bypassed.
        bench._smoke_test_expected_cases(
            "http://localhost:8098",
            [_Expectation(f"/case{i}.jsp") for i in range(10)],
        )

    @pytest.mark.parametrize("v", ["1", "true", "yes", "on", "TRUE"])
    def test_disable_env_truthy_variants(self, monkeypatch, v):
        monkeypatch.setenv(bench._SMOKE_DISABLE_ENV, v)
        bench._smoke_test_expected_cases(
            "http://localhost:8098",
            [_Expectation("/case.jsp")] * 10,
        )

    def test_empty_expectations_warns_but_passes(self, monkeypatch, _reset_env):
        """No expectations to probe → no gate to fail. Bench can still
        run (e.g., for `--findings-json` post-hoc scoring runs)."""
        bench._smoke_test_expected_cases("http://localhost:8098", [])

    def test_url_path_without_leading_slash_handled(self, monkeypatch, _reset_env):
        """expected-cases.csv may emit `url_path` with or without `/`."""
        captured: list[str] = []

        class _Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): return None

        def _fake_urlopen(req, timeout=None):  # noqa: ARG001
            captured.append(req.full_url)
            return _Resp()

        import urllib.request
        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
        with patch.object(bench, "_compose_down"):
            bench._smoke_test_expected_cases(
                "http://localhost:8098",
                [_Expectation("wavsep/no-leading-slash.jsp")] * 10,
            )
        # Single canonical `/` between host and path — no `//`.
        assert all("//wavsep" not in u or u.startswith("http://") for u in captured)


# ----------------------------------------------------------------------
# Anti-overfit
# ----------------------------------------------------------------------

def test_no_fixture_identifiers_in_q7_2_impl():
    import inspect
    src = inspect.getsource(bench._smoke_test_expected_cases).lower()
    # The gate is generic — must not name a specific fixture / category
    # in code. (Comments are allowed to reference zaproxy/wavsep as
    # the canonical failure-mode example.)
    banned = {"juice-shop", "bkimminich", "vampi", "crapi", "getedunext"}
    for ident in banned:
        assert ident not in src, (
            f"_smoke_test_expected_cases references SUT identifier {ident!r}"
        )
