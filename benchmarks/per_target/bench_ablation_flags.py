"""iter-Q1.4 — per-layer ablation flags for bench attribution.

Per docs/proposals/2026-05-27-benchmark-suite-strategy.md: every
headline bench number must be reportable with and without each
layer, so contributions can be attributed cleanly:

  * `STRIX_L15_DISABLED=1` — skip the L1.5 hook chain (FP filter,
    surface_priority, exploitability, corroborator, post_emit_
    verifier, threat_intel.enrich). Findings flow through to the
    tracer without enrichment.

  * `STRIX_L2_DISABLED=1` — skip the L2 LLM lead loop. Run only the
    deterministic anchor prepass + shape-aware dispatcher. The
    output is "what L1 finds without the LLM driving anything."

The bench harnesses don't toggle these themselves; they're set in
the environment by the multi-trial driver (`bench_multi_trial.py`)
or by hand:

    STRIX_L15_DISABLED=1 python -m benchmarks.per_target.bench_owasp_benchmark
    STRIX_L2_DISABLED=1 python -m benchmarks.per_target.bench_l2_juiceshop_full

The strix runtime checks these flags at the relevant decision points:

  * `strix/telemetry/tracer.py:add_vulnerability_report` — when
    L15_DISABLED, skip the hook chain entirely; append-and-emit only.

  * `strix/agents/strix_agent.py:execute_scan` — when L2_DISABLED,
    return immediately after the prepass without spawning the lead
    agent loop.
"""

from __future__ import annotations

import os


# ---------------------------------------------------------------------------
# Env-flag accessors — single source of truth.
# ---------------------------------------------------------------------------


def is_l15_disabled() -> bool:
    """L1.5 hook chain skip-flag.

    When set, `tracer.add_vulnerability_report` appends to the
    reports list WITHOUT firing fp_filter / surface_priority /
    exploitability / corroborator / post_emit_verifier /
    threat_intel hooks. Findings are emitted raw.

    Used by ablation benches to compute the L1.5 layer's value:
    `value_l15 = score_with_l15 − score_without_l15`.
    """
    return os.environ.get(
        "STRIX_L15_DISABLED", "",
    ).strip().lower() in ("1", "true", "yes", "on")


def is_l2_disabled() -> bool:
    """L2 LLM lead loop skip-flag.

    When set, `StrixAgent.execute_scan` returns after the
    anchor_prepass + shape_aware_dispatcher run, without spawning
    the lead agent loop. The output is the pure L1 detection set.

    Used by ablation benches to compute the L2 layer's value:
    `value_l2 = score_with_l2 − score_without_l2`.
    """
    return os.environ.get(
        "STRIX_L2_DISABLED", "",
    ).strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Documentation helpers — used by bench reports
# ---------------------------------------------------------------------------


def active_layers_label() -> str:
    """Short string describing the active layer stack — used in
    bench-report headlines."""
    parts = ["L1"]
    if not is_l15_disabled():
        parts.append("L1.5")
    if not is_l2_disabled():
        parts.append("L2")
    return "+".join(parts)


def ablation_metadata() -> dict[str, bool | str]:
    """Bundled ablation state — added to every bench report's
    metadata block so operators can tell at a glance which layers
    were active."""
    return {
        "l15_disabled": is_l15_disabled(),
        "l2_disabled": is_l2_disabled(),
        "active_layers": active_layers_label(),
    }
