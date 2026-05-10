"""LLM-facing finding-correlation specialist.

`correlate_findings` reads emitted findings (from
`vulnerabilities.json` or a caller-supplied list), runs every
linker in `LINKER_REGISTRY`, builds chains via union-find,
and writes `finding_chains.json` next to the input.

The tool is meant to run AT THE END of a scan — after every
specialist has emitted whatever findings it's going to emit.
The lead-agent should invoke it as part of `finish_scan` /
just before reporting.

Cost: pure Python, deterministic, no LLM call. ~milliseconds
on typical finding volumes (under 1000).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from strix.finding_chains.correlator import (
    build_chains,
    write_finding_chains,
)
from strix.finding_chains.normalise import normalise_findings
from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import (
    FindingDraft,
    SpecialistResult,
)


logger = logging.getLogger(__name__)


def _default_findings_path() -> Path:
    """Where the production tracer writes `vulnerabilities.json`.

    Honours `STRIX_RUN_DIR` like the other artefacts; falls back
    to `cwd / vulnerabilities.json` if that env var isn't set.
    """
    run_dir = os.environ.get("STRIX_RUN_DIR")
    if run_dir:
        return Path(run_dir) / "vulnerabilities.json"
    return Path.cwd() / "vulnerabilities.json"


def _default_output_path(findings_path: Path) -> Path:
    """Co-locate the chain artifact next to the findings."""
    return findings_path.parent / "finding_chains.json"


def _load_findings(findings_path: Path) -> list:
    """Read `vulnerabilities.json`. Tolerates two shapes:

      * `[{...}, {...}]` — raw list of finding dicts (the
        most common production shape).
      * `{"findings": [...]}` — wrapped in a top-level object.
    """
    if not findings_path.exists():
        return []
    try:
        doc = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("finding_chains: load failed for %s: %s",
                     findings_path, e)
        return []
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        if isinstance(doc.get("findings"), list):
            return doc["findings"]
        if isinstance(doc.get("vulnerabilities"), list):
            return doc["vulnerabilities"]
    return []


@register_specialist_tool(
    category="correlation-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 30},
    sandbox_execution=False,
    provenance="framework",
)
def correlate_findings(
    *,
    findings_path: str | None = None,
    output_path: str | None = None,
    min_chain_size: int = 2,
) -> SpecialistResult:
    """Read emitted findings, build cross-category chains,
    write `finding_chains.json`.

    Args:
        findings_path: path to `vulnerabilities.json` or similar.
            Default: `STRIX_RUN_DIR/vulnerabilities.json` (or
            `cwd/vulnerabilities.json`).
        output_path: where to write `finding_chains.json`.
            Default: same dir as `findings_path`.
        min_chain_size: minimum findings per chain (default 2).
            Singletons are filtered out — they're already in
            the source artifact.

    Returns:
        SpecialistResult with one FindingDraft per emitted chain
        (so the lead-agent can see the chain set in its
        result-handling loop) + tool_metadata pinning the
        output-file path + counts.
    """
    in_path = (
        Path(findings_path).expanduser() if findings_path
        else _default_findings_path()
    )
    out_path = (
        Path(output_path).expanduser() if output_path
        else _default_output_path(in_path)
    )

    raw = _load_findings(in_path)
    if not raw:
        return SpecialistResult(
            status="partial",
            error=(
                f"no findings to correlate — `{in_path}` either "
                f"doesn't exist or is empty. Run other "
                f"specialists first; `correlate_findings` is a "
                f"post-scan step."
            ),
            tool_metadata={
                "findings_path": str(in_path),
                "findings_loaded": 0,
                "chains_built": 0,
            },
        )

    findings = normalise_findings(raw)
    chains = build_chains(findings, min_chain_size=min_chain_size)

    written_path: str | None = None
    if chains:
        try:
            written_path = str(write_finding_chains(chains, out_path))
        except OSError as e:
            logger.debug("finding_chains write failed: %s", e)

    drafts: list[FindingDraft] = []
    evidence: list[str] = []

    for c in chains:
        # Each chain becomes a "report" the wrapper can render.
        # Severity from the chain's max; category=`finding_chain`
        # so the wrapper can route it through chain-specific UI.
        cat_summary = ", ".join(c.categories[:5])
        title = (
            f"[chain:{c.chain_type}] {c.summary[:160]} "
            f"({c.size} findings; cats: {cat_summary})"
        )[:480]
        drafts.append(FindingDraft(
            title=title,
            severity=c.severity,
            cwe=None,
            endpoint="",
            category="finding_chain",
            verification_status="verified",
            confidence=0.9,
            description=(
                f"Cross-category chain `{c.chain_id}` covers "
                f"{c.size} findings across categories: "
                f"{', '.join(c.categories)}.\n\n"
                f"Constituent finding IDs: {c.finding_ids}.\n\n"
                f"Linkers fired: "
                f"{sorted({l.link_type for l in c.links})}.\n\n"
                f"Narrative: {c.summary}"
            )[:480],
        ))
        evidence.append(
            f"chain {c.chain_id}: {c.chain_type} ({c.size} findings, "
            f"sev={c.severity})"
        )

    return SpecialistResult(
        status="ok",
        findings=drafts,
        evidence=evidence[:50],
        next_probes_suggested=(
            [
                "review the highest-severity chains first — they "
                "have the strongest cross-category corroboration "
                "(SCA + DAST or SAST + DAST = real exploit path, "
                "not just a static pattern)",
                "for `sca_dast` chains, the SCA finding's package "
                "version + the DAST finding's exploit confirmation "
                "give end-to-end evidence — open the upgrade PR "
                "first",
                "for `iac_dast` chains, the IaC misconfig affects "
                "EVERY environment that shares the file (dev, "
                "staging, prod); fix the source-of-truth IaC "
                "rather than per-env runtime patches",
            ]
            if drafts else
            [
                "no cross-category chains found. Either the scan "
                "produced few findings, or the findings genuinely "
                "don't relate. Single-category triage applies.",
            ]
        ),
        tool_metadata={
            "findings_path": str(in_path),
            "findings_loaded": len(raw),
            "findings_normalised": len(findings),
            "chains_built": len(chains),
            "chains_path": written_path,
            "by_chain_type": {
                t: sum(1 for c in chains if c.chain_type == t)
                for t in set(c.chain_type for c in chains)
            },
            "by_severity": {
                s: sum(1 for c in chains if c.severity == s)
                for s in set(c.severity for c in chains)
            },
        },
    )
