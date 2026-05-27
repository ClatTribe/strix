"""iter-Q2.2 — compaction transcript artifact.

Per docs/proposals/2026-05-27-token-reduction-v2-stratified-compaction.md.

When the stratified compactor (iter-Q2.1) drops COLD-stratum turns
from the conversation, the LLM still needs to know "what happened
back there" to make informed decisions. The compaction transcript
is the deterministic summary of that history.

## Key design choice: NO LLM call

Existing `MemoryCompressor.compress_history` makes an LLM call to
summarize old turns. That:
  * Adds cost (~$0.10 per compaction event)
  * Adds variance (different summaries on re-runs)
  * Adds latency (~5-10s per compaction)
  * Could mis-summarize and drop a critical finding

This module avoids all of those. The transcript is built
deterministically from L1.5-enriched data structures that the
upstream pipeline already populates:

  * `tracer.vulnerability_reports` — every emitted finding
  * `workflow_state.snapshot()` — phase + counters + tool_results
  * `SecurityContext` — auth states + tech stack + endpoints

The compactor never has to *decide* what's important — upstream
already did via the L1.5 enrichment chain. The transcript just
renders those structures into a markdown block that fits in
~10K tokens (vs ~500K for the raw COLD-stratum turns it replaces).

## Lifecycle

  1. First compaction event (any COLD-stratum messages exist) →
     write `<run_dir>/compaction_transcript.md` + return the
     content as a system-prompt block.
  2. Every K=10 subsequent turns OR when COLD stratum grows >50% →
     re-render + overwrite.
  3. On `finish_scan` → final render with the full scan summary.

## Lifespan

The transcript persists for the run lifetime — `vulnerabilities.json`
and `run_summary.json` are the canonical scan outputs; this
transcript is the **conversation-state mirror** that gets folded
back into the system prompt.

## Opt-out

`STRIX_COMPACTION_TRANSCRIPT_DISABLED=1` — skip the artifact
generation. Stratified compactor still runs (per Q2.1).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


# Default cap on findings rendered in the transcript. Above this,
# only the top-N by surface_priority × exploitability are kept.
DEFAULT_MAX_FINDINGS_IN_TRANSCRIPT = 50


def is_transcript_disabled() -> bool:
    return os.environ.get(
        "STRIX_COMPACTION_TRANSCRIPT_DISABLED", "",
    ).strip().lower() in ("1", "true", "yes", "on")


def _run_dir() -> Path | None:
    rd = os.environ.get("STRIX_RUN_DIR")
    return Path(rd) if rd else None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TranscriptSection:
    """One markdown section of the transcript."""
    heading: str
    body: str

    def render(self) -> str:
        return f"## {self.heading}\n\n{self.body}\n"


# ---------------------------------------------------------------------------
# Section builders — each pulls from one upstream data source
# ---------------------------------------------------------------------------


def _build_what_we_know_section(
    workflow_snapshot: dict[str, Any] | None,
    security_context: dict[str, Any] | None,
) -> TranscriptSection:
    """What's the current scan state? Pulls from workflow_state +
    SecurityContext."""
    lines: list[str] = []
    if workflow_snapshot:
        phase = workflow_snapshot.get("current_phase") or "?"
        endpoints = workflow_snapshot.get("endpoints_discovered_count", 0)
        login = workflow_snapshot.get("login_forms_found") or []
        findings = workflow_snapshot.get("findings_emitted", 0)
        chains = workflow_snapshot.get("chains_emitted", 0)
        lines.append(f"- **Workflow phase**: `{phase}`")
        lines.append(f"- **Endpoints discovered**: {endpoints}")
        lines.append(f"- **Login forms found**: {len(login) if isinstance(login, list) else 0}")
        lines.append(f"- **Findings emitted**: {findings}")
        if chains:
            lines.append(f"- **Chains promoted**: {chains}")

    if security_context:
        tech = security_context.get("tech_stack") or {}
        # Render the few load-bearing fields.
        tech_summary_parts = []
        for k in ("server", "framework", "database", "language", "cms"):
            v = tech.get(k)
            if v:
                tech_summary_parts.append(f"{k}={v}")
        if tech_summary_parts:
            lines.append(
                "- **Tech stack**: " + ", ".join(tech_summary_parts),
            )

        auth_states = security_context.get("auth_states") or {}
        if auth_states:
            lines.append(
                f"- **Auth states captured**: "
                + ", ".join(f"`{label}`" for label in sorted(auth_states))
            )

    body = "\n".join(lines) if lines else "_no state recorded yet_"
    return TranscriptSection(heading="What we know so far", body=body)


def _build_what_weve_tried_section(
    workflow_snapshot: dict[str, Any] | None,
) -> TranscriptSection:
    """What tools have we already invoked? Pulls from
    workflow_state.tool_results."""
    if not workflow_snapshot:
        return TranscriptSection(
            heading="What we've tried", body="_no tool calls recorded_",
        )
    tools_run = workflow_snapshot.get("tools_run") or []
    tools_succeeded = workflow_snapshot.get("tools_succeeded") or []
    tools_failed = workflow_snapshot.get("tools_failed") or []
    lines: list[str] = []
    if tools_run:
        # Dedup + count.
        from collections import Counter
        counts = Counter(tools_run)
        lines.append("**Tools attempted** (count):")
        for tool, count in sorted(
            counts.items(), key=lambda kv: (-kv[1], kv[0]),
        ):
            ok = (
                "✓" if tool in tools_succeeded
                else "✗" if tool in tools_failed
                else "?"
            )
            lines.append(f"- [{ok}] `{tool}` ({count}×)")
    body = "\n".join(lines) if lines else "_no tool calls recorded_"
    return TranscriptSection(heading="What we've tried", body=body)


def _build_findings_section(
    vulnerability_reports: list[dict[str, Any]] | None,
    max_findings: int = DEFAULT_MAX_FINDINGS_IN_TRANSCRIPT,
) -> TranscriptSection:
    """Every emitted finding with L1.5 enrichment summary.

    This is the bench-recall-defining section: every finding listed
    here was emitted by L1 + ran through the L1.5 hook chain. If a
    finding is here, the scan formally caught it."""
    reports = list(vulnerability_reports or [])
    if not reports:
        return TranscriptSection(
            heading="Findings emitted so far", body="_no findings yet_",
        )

    # Rank by surface_priority × confidence proxy (defaults applied).
    def _rank_key(r: dict[str, Any]) -> tuple[int, float]:
        sp = r.get("surface_priority") or "low"
        sp_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(sp, 0)
        conf = r.get("confidence") or 0.5
        return (-sp_rank, -float(conf))

    sorted_reports = sorted(reports, key=_rank_key)[:max_findings]

    lines = [
        f"**Total**: {len(reports)} "
        + (f"(showing top {len(sorted_reports)} by L1.5-ranked priority)"
           if len(reports) > max_findings else "")
    ]
    lines.append("")
    lines.append(
        "| # | Severity | CWE | Endpoint | Title | "
        "Surface | Exploitability | Corroborated |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    for i, r in enumerate(sorted_reports, start=1):
        sev = (r.get("severity") or "?")[:8]
        cwe = (r.get("cwe") or "")[:10]
        endpoint = (r.get("endpoint") or r.get("target") or "")[:60]
        title = (r.get("title") or "")[:60]
        surf = (r.get("surface_priority") or "")[:8]
        # exploitability could be a dict OR a scalar.
        exp_raw = r.get("exploitability")
        if isinstance(exp_raw, dict):
            exp = (exp_raw.get("score") or exp_raw.get("level") or "")
            exp = str(exp)[:10]
        else:
            exp = str(exp_raw or "")[:10]
        corrob_raw = r.get("corroborated_by") or []
        corrob = f"{len(corrob_raw)}" if isinstance(corrob_raw, list) else ""
        lines.append(
            f"| {i} | {sev} | {cwe} | `{endpoint}` | {title} | "
            f"{surf} | {exp} | {corrob} |"
        )
    body = "\n".join(lines)
    return TranscriptSection(heading="Findings emitted so far", body=body)


def _build_open_questions_section(
    workflow_snapshot: dict[str, Any] | None,
    security_context: dict[str, Any] | None,
) -> TranscriptSection:
    """What's actionable but unresolved? Heuristic; surfaces:
      * partial_signals (unconfirmed observations from L1.5)
      * Login forms found but no auth state captured (auth retry candidate)
      * High-priority findings without `chain_summary` attached
    """
    lines: list[str] = []
    if security_context:
        signals = security_context.get("partial_signals") or []
        if signals:
            lines.append("**Unresolved partial signals**:")
            for sig in signals[:10]:
                if isinstance(sig, dict):
                    surf = sig.get("surface", "?")
                    obs = sig.get("signal", "?")
                    nxt = sig.get("next_probe", "")
                    lines.append(
                        f"- `{surf}` → {obs}" + (f" → next: {nxt}" if nxt else "")
                    )

    if workflow_snapshot:
        login_forms = workflow_snapshot.get("login_forms_found") or []
        auth_captured = workflow_snapshot.get("auth_state_captured", False)
        if login_forms and not auth_captured:
            lines.append("")
            lines.append(
                f"**Auth retry candidate**: {len(login_forms)} login form(s) "
                f"discovered but no auth state captured. Consider re-running "
                f"`scan_auth_flow` with `try_register=True`."
            )

    body = "\n".join(lines) if lines else "_no open questions identified_"
    return TranscriptSection(heading="Open questions", body=body)


# ---------------------------------------------------------------------------
# Top-level renderer
# ---------------------------------------------------------------------------


@dataclass
class CompactionTranscript:
    """Rendered transcript with metadata."""
    markdown: str
    section_count: int
    finding_count: int
    char_count: int

    @property
    def estimated_tokens(self) -> int:
        """Rough estimate; the LLM module's accurate counter takes
        ~10ms per call which would dominate this fast-path."""
        return self.char_count // 4

    def to_dict(self) -> dict[str, Any]:
        return {
            "section_count": self.section_count,
            "finding_count": self.finding_count,
            "char_count": self.char_count,
            "estimated_tokens": self.estimated_tokens,
        }


def render_transcript(
    *,
    vulnerability_reports: list[dict[str, Any]] | None = None,
    workflow_snapshot: dict[str, Any] | None = None,
    security_context: dict[str, Any] | None = None,
    max_findings: int = DEFAULT_MAX_FINDINGS_IN_TRANSCRIPT,
) -> CompactionTranscript:
    """Render the compaction transcript markdown.

    Pure function: deterministic, no I/O. The harness side
    (`build_and_persist_transcript`) handles disk I/O.
    """
    sections = [
        _build_what_we_know_section(workflow_snapshot, security_context),
        _build_what_weve_tried_section(workflow_snapshot),
        _build_findings_section(vulnerability_reports, max_findings),
        _build_open_questions_section(workflow_snapshot, security_context),
    ]
    header = (
        "# Scan compaction transcript\n\n"
        "_Auto-generated summary of conversation history that was "
        "dropped from the LLM's context window. Findings remain "
        "queryable via `list_pending_findings`; tool outputs via "
        "`read_tool_output(id)` (when available)._\n\n"
    )
    body = header + "\n".join(s.render() for s in sections)
    return CompactionTranscript(
        markdown=body,
        section_count=len(sections),
        finding_count=len(list(vulnerability_reports or [])),
        char_count=len(body),
    )


def build_and_persist_transcript(
    *,
    vulnerability_reports: list[dict[str, Any]] | None = None,
    workflow_snapshot: dict[str, Any] | None = None,
    security_context: dict[str, Any] | None = None,
    max_findings: int = DEFAULT_MAX_FINDINGS_IN_TRANSCRIPT,
) -> CompactionTranscript | None:
    """Render + persist to `<run_dir>/compaction_transcript.md`.

    Returns the transcript on success; None when disabled or on any
    persistence failure (best-effort — never blocks the scan)."""
    if is_transcript_disabled():
        return None
    tr = render_transcript(
        vulnerability_reports=vulnerability_reports,
        workflow_snapshot=workflow_snapshot,
        security_context=security_context,
        max_findings=max_findings,
    )
    rd = _run_dir()
    if rd:
        try:
            rd.mkdir(parents=True, exist_ok=True)
            (rd / "compaction_transcript.md").write_text(
                tr.markdown, encoding="utf-8",
            )
        except Exception:  # noqa: BLE001
            logger.debug(
                "compaction_transcript persist failed", exc_info=True,
            )
    return tr


def render_transcript_from_singletons() -> CompactionTranscript | None:
    """Convenience entry: pull from the live tracer / workflow_state
    / security_context singletons. Returns None when any source is
    missing (defensive)."""
    if is_transcript_disabled():
        return None
    try:
        from strix.telemetry.tracer import get_global_tracer
        from strix.agents.workflow_state import snapshot as ws_snapshot
        from strix.agents.security_context import get_security_context
    except Exception:  # noqa: BLE001
        return None
    try:
        tracer = get_global_tracer()
        reports = (
            list(tracer.vulnerability_reports)
            if tracer else []
        )
    except Exception:  # noqa: BLE001
        reports = []
    try:
        ws = ws_snapshot()
    except Exception:  # noqa: BLE001
        ws = None
    try:
        sc_obj = get_security_context()
        sc = sc_obj.to_dict() if sc_obj else None
    except Exception:  # noqa: BLE001
        sc = None
    return build_and_persist_transcript(
        vulnerability_reports=reports,
        workflow_snapshot=ws,
        security_context=sc,
    )
