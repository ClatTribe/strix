"""Tests for iter-Q5.42 — container_image base-layer skip + multi-arch.

Covers:
  * `_resolve_pkg_types` accepts os / library / os,library, rejects junk
  * `_resolve_ignore_unfixed` reads the env flag
  * `_resolve_platform` reads the env var
  * `_run_trivy_scan` emits `--pkg-types`, `--ignore-unfixed`, `--platform`
    only when the corresponding resolved value is truthy
  * Defaults remain OFF (no flags emitted) so we don't silently reduce
    finding count vs pre-Q5.42 behaviour (CLAUDE.md: "we don't want to
    reduce finding vulnerability")
  * `scan_container_image` kwargs flow through to `_run_trivy_scan`
  * Prepass `_container_kwargs` picks up env vars
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

import importlib
# `sci` MUST be the MODULE not the function. The package
# `strix.tools.container_image.__init__` re-exports the
# `scan_container_image` callable from inside the same-named
# submodule, and the rebinding wins under `import x.y.z as sci` on
# CPython 3.14 — `sci` resolves to the function, not the module.
# `importlib.import_module` returns the module unambiguously.
sci = importlib.import_module(
    "strix.tools.container_image.scan_container_image",
)
sci_fn = sci.scan_container_image  # the @register_specialist_tool callable


class TestResolvePkgTypes:
    def test_none_returns_none(self) -> None:
        assert sci._resolve_pkg_types(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert sci._resolve_pkg_types("") is None

    def test_library_accepted(self) -> None:
        assert sci._resolve_pkg_types("library") == "library"

    def test_os_accepted(self) -> None:
        assert sci._resolve_pkg_types("os") == "os"

    def test_combined_accepted(self) -> None:
        assert sci._resolve_pkg_types("os,library") == "os,library"

    def test_case_insensitive(self) -> None:
        assert sci._resolve_pkg_types("Library") == "library"
        assert sci._resolve_pkg_types("OS,LIBRARY") == "os,library"

    def test_whitespace_stripped(self) -> None:
        assert sci._resolve_pkg_types(" os , library ") == "os,library"

    def test_garbage_rejected(self) -> None:
        assert sci._resolve_pkg_types("garbage") is None
        assert sci._resolve_pkg_types("os,foo") is None

    def test_env_fallback(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_PKG_TYPES": "library"}, clear=False):
            assert sci._resolve_pkg_types(None) == "library"

    def test_arg_wins_over_env(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_PKG_TYPES": "library"}, clear=False):
            assert sci._resolve_pkg_types("os") == "os"

    def test_garbage_env_returns_none(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_PKG_TYPES": "junk"}, clear=False):
            assert sci._resolve_pkg_types(None) is None


class TestResolveIgnoreUnfixed:
    def test_none_default_false(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            assert sci._resolve_ignore_unfixed(None) is False

    def test_true_kwarg(self) -> None:
        assert sci._resolve_ignore_unfixed(True) is True

    def test_false_kwarg(self) -> None:
        assert sci._resolve_ignore_unfixed(False) is False

    def test_env_1(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_IGNORE_UNFIXED": "1"}, clear=False):
            assert sci._resolve_ignore_unfixed(None) is True

    def test_env_true(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_IGNORE_UNFIXED": "true"}, clear=False):
            assert sci._resolve_ignore_unfixed(None) is True

    def test_env_yes(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_IGNORE_UNFIXED": "yes"}, clear=False):
            assert sci._resolve_ignore_unfixed(None) is True

    def test_env_garbage_treated_false(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_IGNORE_UNFIXED": "maybe"}, clear=False):
            assert sci._resolve_ignore_unfixed(None) is False

    def test_arg_false_wins_over_env_true(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_IGNORE_UNFIXED": "1"}, clear=False):
            assert sci._resolve_ignore_unfixed(False) is False


class TestResolvePlatform:
    def test_none_returns_none(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            assert sci._resolve_platform(None) is None

    def test_empty_string_returns_none(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            assert sci._resolve_platform("") is None

    def test_arg_returned(self) -> None:
        assert sci._resolve_platform("linux/amd64") == "linux/amd64"

    def test_env_returned(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_PLATFORM": "linux/arm64"}, clear=False):
            assert sci._resolve_platform(None) == "linux/arm64"

    def test_arg_wins_over_env(self) -> None:
        with patch.dict(os.environ, {"STRIX_TRIVY_PLATFORM": "linux/arm64"}, clear=False):
            assert sci._resolve_platform("linux/amd64") == "linux/amd64"

    def test_whitespace_stripped(self) -> None:
        assert sci._resolve_platform("  linux/amd64  ") == "linux/amd64"


class TestRunTrivyScanCmdConstruction:
    """Verify _run_trivy_scan builds the correct argv for each flag combination.

    We can't run trivy in tests, so we patch subprocess.run and inspect
    the cmd argument.
    """

    def _capture_cmd(self, **kwargs: object) -> list[str]:
        captured: list[list[str]] = []

        class _FakeResult:
            returncode = 0
            stdout = '{"Results": []}'
            stderr = ""

        def _fake_run(cmd: list[str], **_: object) -> _FakeResult:
            captured.append(list(cmd))
            return _FakeResult()

        with patch.object(sci, "subprocess") as mock_sub:
            mock_sub.run = _fake_run
            mock_sub.TimeoutExpired = sci.subprocess.TimeoutExpired
            sci._run_trivy_scan("nginx:1.25", **kwargs)  # type: ignore[arg-type]

        assert len(captured) == 1, "expected exactly one trivy invocation"
        return captured[0]

    def test_defaults_omit_optional_flags(self) -> None:
        """No --pkg-types / --ignore-unfixed / --platform when all are unset.

        Critical regression guard: a default-mode scan must NOT silently
        drop OS-package CVEs.
        """
        cmd = self._capture_cmd()
        assert "--pkg-types" not in cmd
        assert "--ignore-unfixed" not in cmd
        assert "--platform" not in cmd
        # Sanity: the image_ref is the final positional.
        assert cmd[-1] == "nginx:1.25"

    def test_pkg_types_library_emits_flag(self) -> None:
        cmd = self._capture_cmd(pkg_types="library")
        idx = cmd.index("--pkg-types")
        assert cmd[idx + 1] == "library"

    def test_pkg_types_none_omits_flag(self) -> None:
        cmd = self._capture_cmd(pkg_types=None)
        assert "--pkg-types" not in cmd

    def test_ignore_unfixed_emits_flag(self) -> None:
        cmd = self._capture_cmd(ignore_unfixed=True)
        assert "--ignore-unfixed" in cmd

    def test_ignore_unfixed_false_omits_flag(self) -> None:
        cmd = self._capture_cmd(ignore_unfixed=False)
        assert "--ignore-unfixed" not in cmd

    def test_platform_emits_flag(self) -> None:
        cmd = self._capture_cmd(platform="linux/amd64")
        idx = cmd.index("--platform")
        assert cmd[idx + 1] == "linux/amd64"

    def test_all_three_combined(self) -> None:
        cmd = self._capture_cmd(
            pkg_types="library",
            ignore_unfixed=True,
            platform="linux/arm64",
        )
        assert "--pkg-types" in cmd and cmd[cmd.index("--pkg-types") + 1] == "library"
        assert "--ignore-unfixed" in cmd
        assert "--platform" in cmd and cmd[cmd.index("--platform") + 1] == "linux/arm64"
        # Image ref must still be the final positional even with all flags.
        assert cmd[-1] == "nginx:1.25"

    def test_severity_band_preserved(self) -> None:
        """Q5.42 must not silently narrow the LOW,MEDIUM,HIGH,CRITICAL band."""
        cmd = self._capture_cmd(pkg_types="library", ignore_unfixed=True)
        idx = cmd.index("--severity")
        assert cmd[idx + 1] == "LOW,MEDIUM,HIGH,CRITICAL"

    def test_scanners_preserved(self) -> None:
        """Q5.42 must not silently narrow the default scanner set."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("STRIX_TRIVY_SCANNERS", None)
            cmd = self._capture_cmd(pkg_types="library")
        idx = cmd.index("--scanners")
        assert cmd[idx + 1] == "vuln,misconfig,secret"


class TestContainerKwargsPrepassWiring:
    """_container_kwargs in anchor_prepass forwards env vars."""

    def test_defaults_only_image_ref(self) -> None:
        from strix.agents.lead_agent.anchor_prepass import _container_kwargs

        with patch.dict(os.environ, {}, clear=True):
            kwargs = _container_kwargs("nginx:1.25", "/tmp", "scan_container_image")
        assert kwargs == {"image_ref": "nginx:1.25"}

    def test_pkg_types_env_forwarded(self) -> None:
        from strix.agents.lead_agent.anchor_prepass import _container_kwargs

        with patch.dict(os.environ, {"STRIX_TRIVY_PKG_TYPES": "library"}, clear=False):
            kwargs = _container_kwargs("nginx:1.25", "/tmp", "scan_container_image")
        assert kwargs["pkg_types"] == "library"

    def test_ignore_unfixed_env_forwarded(self) -> None:
        from strix.agents.lead_agent.anchor_prepass import _container_kwargs

        with patch.dict(os.environ, {"STRIX_TRIVY_IGNORE_UNFIXED": "1"}, clear=False):
            kwargs = _container_kwargs("nginx:1.25", "/tmp", "scan_container_image")
        assert kwargs.get("ignore_unfixed") is True

    def test_platform_env_forwarded(self) -> None:
        from strix.agents.lead_agent.anchor_prepass import _container_kwargs

        with patch.dict(
            os.environ, {"STRIX_TRIVY_PLATFORM": "linux/arm64"}, clear=False,
        ):
            kwargs = _container_kwargs("nginx:1.25", "/tmp", "scan_container_image")
        assert kwargs["platform"] == "linux/arm64"

    def test_empty_env_does_not_inject_keys(self) -> None:
        """Empty env strings should not poison the kwargs dict."""
        from strix.agents.lead_agent.anchor_prepass import _container_kwargs

        with patch.dict(
            os.environ,
            {
                "STRIX_TRIVY_PKG_TYPES": "",
                "STRIX_TRIVY_IGNORE_UNFIXED": "",
                "STRIX_TRIVY_PLATFORM": "",
            },
            clear=False,
        ):
            kwargs = _container_kwargs("nginx:1.25", "/tmp", "scan_container_image")
        assert "pkg_types" not in kwargs
        assert "ignore_unfixed" not in kwargs
        assert "platform" not in kwargs


class TestScanContainerImageKwargFlowthrough:
    """`scan_container_image(pkg_types=..., ignore_unfixed=..., platform=...)`
    must thread the values down to `_run_trivy_scan`.
    """

    def test_kwargs_reach_run_trivy(self) -> None:
        captured: dict[str, object] = {}

        def _fake_run_trivy(image_ref: str, **kw: object) -> tuple[dict, None]:
            captured.update(kw)
            captured["image_ref"] = image_ref
            return {"Results": []}, None

        with patch.object(sci, "_trivy_available", return_value=True), \
             patch.object(sci, "_run_trivy_scan", side_effect=_fake_run_trivy):
            sci.scan_container_image(
                image_ref="nginx:1.25",
                pkg_types="library",
                ignore_unfixed=True,
                platform="linux/amd64",
            )

        assert captured["pkg_types"] == "library"
        assert captured["ignore_unfixed"] is True
        assert captured["platform"] == "linux/amd64"
        assert captured["image_ref"] == "nginx:1.25"

    def test_env_pkg_types_consumed_when_kwarg_none(self) -> None:
        captured: dict[str, object] = {}

        def _fake_run_trivy(image_ref: str, **kw: object) -> tuple[dict, None]:
            captured.update(kw)
            return {"Results": []}, None

        with patch.object(sci, "_trivy_available", return_value=True), \
             patch.object(sci, "_run_trivy_scan", side_effect=_fake_run_trivy), \
             patch.dict(os.environ, {"STRIX_TRIVY_PKG_TYPES": "library"}, clear=False):
            sci.scan_container_image(image_ref="nginx:1.25")

        assert captured["pkg_types"] == "library"

    def test_all_none_keeps_default_behaviour(self) -> None:
        """Regression guard: zero new kwargs + zero env vars = pre-Q5.42 behaviour."""
        captured: dict[str, object] = {}

        def _fake_run_trivy(image_ref: str, **kw: object) -> tuple[dict, None]:
            captured.update(kw)
            return {"Results": []}, None

        with patch.dict(os.environ, {}, clear=True), \
             patch.object(sci, "_trivy_available", return_value=True), \
             patch.object(sci, "_run_trivy_scan", side_effect=_fake_run_trivy):
            sci.scan_container_image(image_ref="nginx:1.25")

        assert captured.get("pkg_types") is None
        assert captured.get("ignore_unfixed") is False
        assert captured.get("platform") is None


# ----------------------------------------------------------------------
# iter-Q5.42 anti-overfit guard
# ----------------------------------------------------------------------
# This test file (and the Q5.42 implementation) must NOT reference any
# specific image / CVE / vendor identifier. The base-layer skip is a
# generic filter — tuning it to a particular fixture (e.g. `nginx-vuln`)
# would be overfit.
# ----------------------------------------------------------------------

def test_no_fixture_identifiers_in_q5_42_impl() -> None:
    """Source-grep: the resolver helpers don't reference SUT identifiers."""
    import inspect

    src = inspect.getsource(sci)
    banned = {
        "nginx-vuln", "alpine-vuln", "node-vuln", "python-vuln",
        "juice-shop", "vampi", "crapi", "wavsep",
    }
    # We DO reference "nginx:1.25" in docstring examples — that's a real
    # public image used as an example, not a fixture identifier. Skip
    # those by checking the helper functions specifically.
    for fn_name in ("_resolve_pkg_types", "_resolve_ignore_unfixed", "_resolve_platform"):
        fn_src = inspect.getsource(getattr(sci, fn_name))
        for ident in banned:
            assert ident not in fn_src.lower(), (
                f"{fn_name} references SUT identifier {ident!r}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
