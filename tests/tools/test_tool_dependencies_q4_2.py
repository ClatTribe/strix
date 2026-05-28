"""Tests for iter-Q4.2 — the dependency classifier safety guard.

`partition_independent_calls` layers a turn's tool batch into
dependency-ordered waves: calls in one wave run concurrently, waves
run strictly in order. The load-bearing property is that a tool which
reads another tool's side-effect (e.g. `scan_idor` reading the session
`seed_auth` captured) lands in a LATER wave than its prerequisite —
even when the model emits the dependent call first.

These tests pin the partition contract directly (no executor / agent
loop needed). The executor wiring is exercised by the existing
process_tool_invocations tests; here we pin the algorithm.
"""

from __future__ import annotations

import importlib

import pytest


# Import the module (not symbols) to avoid the package-shadowing gotcha
# where `from strix.tools.tool_dependencies import X` can resolve to a
# function rather than the module.
td = importlib.import_module("strix.tools.tool_dependencies")


def _inv(tool_name: str) -> dict:
    return {"toolName": tool_name, "args": {}}


def _wave_of(waves: list[list[int]], idx: int) -> int:
    for w, layer in enumerate(waves):
        if idx in layer:
            return w
    raise AssertionError(f"index {idx} not present in any wave: {waves}")


# ----------------------------------------------------------------------
# _invocation_tool_name
# ----------------------------------------------------------------------

class TestInvocationToolName:
    def test_dict_toolname(self):
        assert td._invocation_tool_name({"toolName": "scan_idor"}) == "scan_idor"

    def test_dict_aliases(self):
        assert td._invocation_tool_name({"tool_name": "seed_auth"}) == "seed_auth"
        assert td._invocation_tool_name({"name": "scan_auth_flow"}) == "scan_auth_flow"

    def test_unknown_is_empty_string(self):
        # Empty string never matches a dependency → treated as independent.
        assert td._invocation_tool_name({}) == ""
        assert td._invocation_tool_name(object()) == ""


# ----------------------------------------------------------------------
# partition_independent_calls — degenerate inputs
# ----------------------------------------------------------------------

class TestPartitionDegenerate:
    def test_empty(self):
        assert td.partition_independent_calls([]) == []

    def test_single(self):
        assert td.partition_independent_calls([_inv("scan_idor")]) == [[0]]


# ----------------------------------------------------------------------
# partition_independent_calls — independent batches collapse to 1 wave
# ----------------------------------------------------------------------

class TestPartitionIndependent:
    def test_all_independent_single_wave(self):
        """N fan-out scans across distinct endpoints with no encoded
        dependency → ONE wave (identical to the pre-Q4.2 full gather)."""
        invs = [_inv("scan_sqli_sqlmap"), _inv("scan_xss_dalfox"), _inv("scan_fuzz_ffuf")]
        waves = td.partition_independent_calls(invs)
        assert waves == [[0, 1, 2]]

    def test_unknown_tools_are_independent(self):
        invs = [_inv("totally_unknown_a"), _inv("totally_unknown_b")]
        assert td.partition_independent_calls(invs) == [[0, 1]]

    def test_duplicate_independent_tool_same_wave(self):
        # Two scans of the same kind on different endpoints still parallel.
        invs = [_inv("scan_sqli_sqlmap"), _inv("scan_sqli_sqlmap")]
        assert td.partition_independent_calls(invs) == [[0, 1]]


# ----------------------------------------------------------------------
# partition_independent_calls — the auth-state hazard (the whole point)
# ----------------------------------------------------------------------

class TestAuthDependency:
    def test_seed_auth_before_scan_idor(self):
        """seed_auth (writer) must land in an EARLIER wave than
        scan_idor (reader) — emitted writer-first."""
        invs = [_inv("seed_auth"), _inv("scan_idor")]
        waves = td.partition_independent_calls(invs)
        assert _wave_of(waves, 0) < _wave_of(waves, 1)

    def test_dependency_respected_regardless_of_emission_order(self):
        """The model lists scan_idor FIRST, seed_auth second. The guard
        must STILL run seed_auth's wave before scan_idor's — order of
        emission does not weaken the dependency."""
        invs = [_inv("scan_idor"), _inv("seed_auth")]
        waves = td.partition_independent_calls(invs)
        idx_scan_idor, idx_seed_auth = 0, 1
        assert _wave_of(waves, idx_seed_auth) < _wave_of(waves, idx_scan_idor)

    def test_scan_auth_flow_before_dispatch_l2_probe(self):
        invs = [_inv("scan_auth_flow"), _inv("dispatch_l2_probe")]
        waves = td.partition_independent_calls(invs)
        assert _wave_of(waves, 0) < _wave_of(waves, 1)

    def test_independent_scan_parallel_with_dependent_chain(self):
        """A mixed batch: [scan_xss_dalfox, seed_auth, scan_idor].
        scan_xss is independent (wave 0), seed_auth is independent
        (wave 0), scan_idor depends on seed_auth (wave 1). So wave 0
        runs {xss, seed_auth} concurrently, wave 1 runs scan_idor."""
        invs = [_inv("scan_xss_dalfox"), _inv("seed_auth"), _inv("scan_idor")]
        waves = td.partition_independent_calls(invs)
        assert _wave_of(waves, 0) == 0
        assert _wave_of(waves, 1) == 0
        assert _wave_of(waves, 2) == 1
        # The two wave-0 calls share a wave (run concurrently).
        assert sorted(waves[0]) == [0, 1]


# ----------------------------------------------------------------------
# partition_independent_calls — verifier-after-detector
# ----------------------------------------------------------------------

class TestVerifierDependency:
    def test_verify_finding_after_producer(self):
        invs = [_inv("create_vulnerability_report"), _inv("verify_finding")]
        waves = td.partition_independent_calls(invs)
        assert _wave_of(waves, 0) < _wave_of(waves, 1)

    def test_verify_finding_alone_is_single_wave(self):
        # No producer in the batch → no constraint → runs immediately.
        invs = [_inv("verify_finding"), _inv("scan_fuzz_ffuf")]
        assert td.partition_independent_calls(invs) == [[0, 1]]


# ----------------------------------------------------------------------
# partition_independent_calls — index/order properties + robustness
# ----------------------------------------------------------------------

class TestPartitionProperties:
    def test_indices_within_wave_are_ascending(self):
        invs = [_inv("scan_sqli_sqlmap"), _inv("scan_xss_dalfox"), _inv("scan_fuzz_ffuf")]
        for layer in td.partition_independent_calls(invs):
            assert layer == sorted(layer)

    def test_every_index_appears_exactly_once(self):
        invs = [
            _inv("scan_xss_dalfox"),
            _inv("seed_auth"),
            _inv("scan_idor"),
            _inv("scan_auth_flow"),
            _inv("dispatch_l2_probe"),
        ]
        waves = td.partition_independent_calls(invs)
        flat = [i for layer in waves for i in layer]
        assert sorted(flat) == list(range(len(invs)))

    def test_chain_of_three_serialises(self):
        """seed_auth → scan_idor, and verify_finding depends on
        scan_idor → a 3-deep chain becomes 3 ordered waves."""
        invs = [_inv("seed_auth"), _inv("scan_idor"), _inv("verify_finding")]
        waves = td.partition_independent_calls(invs)
        assert _wave_of(waves, 0) < _wave_of(waves, 1) < _wave_of(waves, 2)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
