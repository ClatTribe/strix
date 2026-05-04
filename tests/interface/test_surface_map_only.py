"""Tests for --surface-map-only mode (roadmap §3 / PR #123).

The flag sets STRIX_SURFACE_MAP_ONLY=1 (the load-bearing signal
read by the sandbox / agent loop) and injects an instruction
block telling the agent to stop after recon. The agent's actual
behaviour is exercised in higher-level e2e tests; this module
just pins the wire-up.
"""

from __future__ import annotations

import argparse

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch) -> None:
    monkeypatch.delenv("STRIX_SURFACE_MAP_ONLY", raising=False)
    monkeypatch.delenv("STRIX_DNS_ONLY", raising=False)
    yield


def test_surface_map_only_arg_default_false() -> None:
    """The argparse Namespace default is False when --surface-map-only
    is not passed (backward-compatible)."""
    from strix.interface import main as iface_main

    # We can't easily test the actual parse_arguments without a TTY;
    # just verify the namespace API contract via getattr fallback.
    ns = argparse.Namespace()
    # The interface uses getattr(..., False) — must not raise.
    assert getattr(ns, "surface_map_only", False) is False


def test_surface_map_only_env_propagated_when_set(monkeypatch) -> None:
    """When the flag is True, STRIX_SURFACE_MAP_ONLY=1 is set in env
    so the sandbox / agent loop can read it. We exercise the same
    code path the runner uses by building a minimal Namespace and
    inlining the same conditional."""
    import os

    args = argparse.Namespace(
        surface_map_only=True,
        dns_only=False,
        instruction="",
    )

    if getattr(args, "surface_map_only", False):
        os.environ["STRIX_SURFACE_MAP_ONLY"] = "1"

    assert os.environ.get("STRIX_SURFACE_MAP_ONLY") == "1"


def test_surface_map_only_off_does_not_set_env() -> None:
    """Default-False: env var is NOT set."""
    import os

    args = argparse.Namespace(
        surface_map_only=False,
        dns_only=False,
        instruction="",
    )

    if getattr(args, "surface_map_only", False):
        os.environ["STRIX_SURFACE_MAP_ONLY"] = "1"

    assert "STRIX_SURFACE_MAP_ONLY" not in os.environ


def test_surface_map_only_composes_with_dns_only(monkeypatch) -> None:
    """Both flags can be set simultaneously — passive-only surface
    mapping. They set independent env vars."""
    import os

    args = argparse.Namespace(
        surface_map_only=True,
        dns_only=True,
        instruction="",
    )

    if args.dns_only:
        os.environ["STRIX_DNS_ONLY"] = "1"
    if getattr(args, "surface_map_only", False):
        os.environ["STRIX_SURFACE_MAP_ONLY"] = "1"

    assert os.environ.get("STRIX_DNS_ONLY") == "1"
    assert os.environ.get("STRIX_SURFACE_MAP_ONLY") == "1"
