"""Tests for iter-27.5 — tool-server timeout default."""

from __future__ import annotations

import re
from pathlib import Path


def test_tool_server_default_timeout_300_seconds():
    """The tool-server's default `--timeout` argument must be at
    least 300 seconds. The original 120s default caused
    nginx-vuln container_image bench fixture (and every other
    heavy scan: trivy with DB init, sqlmap --batch --level 3,
    full nuclei template fan-out, dalfox payload set) to time out
    on every run.

    iter-27.5 bumped the default to 300s. This is a regression test
    against accidentally reverting it.
    """
    src = Path(__file__).resolve().parents[2] / "strix" / "runtime" / "tool_server.py"
    text = src.read_text()
    # Find the default in the `--timeout` argparse arg
    m = re.search(
        r"--timeout[^)]*?default\s*=\s*(\d+)",
        text,
        re.DOTALL,
    )
    assert m is not None, "could not locate --timeout default in tool_server.py"
    default_value = int(m.group(1))
    assert default_value >= 300, (
        f"tool_server.py --timeout default must be ≥ 300s; "
        f"got {default_value}"
    )


def test_config_default_timeout_300_seconds():
    """iter-27.9 — the host-side Config default also needs to be
    ≥ 300s. The bench harness and any host process importing
    `strix.tools.executor` reads
    `Config.get('strix_sandbox_execution_timeout')` at module load
    to set the client-side request timeout. Without this, the
    client times out at 120s even though the sandbox-side tool
    server is at 300s. Caught during iter-27.8 nginx-vuln re-bench
    where the bench reported `Tool timed out after 120s` despite
    the sandbox having the iter-27.5 entrypoint fix."""
    from strix.config.config import Config
    default = int(Config.strix_sandbox_execution_timeout)
    assert default >= 300, (
        f"Config.strix_sandbox_execution_timeout default must be "
        f">= 300s; got {default}"
    )


def test_docker_entrypoint_default_timeout_300_seconds():
    """The docker entrypoint's STRIX_SANDBOX_EXECUTION_TIMEOUT
    fallback must also default to at least 300s. The shell-side
    default + the python-side default must stay in sync."""
    src = (
        Path(__file__).resolve().parents[2]
        / "containers" / "docker-entrypoint.sh"
    )
    text = src.read_text()
    m = re.search(
        r"STRIX_SANDBOX_EXECUTION_TIMEOUT:-(\d+)",
        text,
    )
    assert m is not None, (
        "could not locate STRIX_SANDBOX_EXECUTION_TIMEOUT fallback in "
        "docker-entrypoint.sh"
    )
    default_value = int(m.group(1))
    assert default_value >= 300, (
        f"docker-entrypoint.sh STRIX_SANDBOX_EXECUTION_TIMEOUT "
        f"fallback must be ≥ 300s; got {default_value}"
    )
