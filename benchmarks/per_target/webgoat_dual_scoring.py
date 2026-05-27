"""iter-Q1.2 — WebGoat dual-mode scoring (detection ∧ completion).

OWASP WebGoat ships a lesson-completion tracker exposed at
`/WebGoat/service/lessonprogress.mvc`. Each lesson has a per-step
exploit checker; when strix's actions fire the right HTTP requests,
the lesson's `solved` flag flips.

This module scores strix in TWO modes against the SAME fixture:

  * **detection rate** — did strix emit a vulnerability finding for
    each must-find lesson? (matches the L1 OSS-detection benchmark
    methodology — `expected.yaml`'s must_find list is the recall
    denominator)

  * **completion rate** — did strix's actions trip WebGoat's
    internal lesson-checker? Polls `/lessonprogress.mvc` post-scan;
    counts lessons with `solved == true`.

  * **chain gap** = detection_rate − completion_rate. This is the
    exact L2-value measurement: "L1 found these vulns; L2 either
    exploited them (completion) or didn't (gap)."

Per `docs/proposals/2026-05-27-benchmark-suite-strategy.md`, this is
how we separate "the OSS tools found the bug" from "the LLM chained
the exploit to actually trip the lesson."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Curated WebGoat lesson set (the bench's must-find universe)
# ---------------------------------------------------------------------------
# WebGoat ships ~30 lessons across 12 categories. The full set isn't
# all useful for tool benching — some lessons require human
# interaction (drag-and-drop UI), some are pedagogical-only (no
# real vuln). This curated set is the bench's universe:
#
#   * Each entry has a stable lesson_id (matches WebGoat's path)
#   * CWE for the underlying vuln class
#   * `exploit_endpoint` — the URL strix must hit to trip the lesson
#     (used by completion-rate scorer to confirm WebGoat's lesson-
#     checker fired)
#
# This matches the OWASP WebGoat 2023.8 release.
WEBGOAT_BENCH_LESSONS: list[dict[str, str]] = [
    # Injection family
    {"lesson_id": "SqlInjection.lesson", "cwe": "CWE-89",
     "exploit_endpoint": "/WebGoat/SqlInjection/attack5a"},
    {"lesson_id": "SqlInjectionMitigations.lesson", "cwe": "CWE-89",
     "exploit_endpoint": "/WebGoat/SqlInjectionMitigations/servers"},
    {"lesson_id": "SqlInjectionAdvanced.lesson", "cwe": "CWE-89",
     "exploit_endpoint": "/WebGoat/SqlInjectionAdvanced/attack6a"},
    {"lesson_id": "PathTraversal.lesson", "cwe": "CWE-22",
     "exploit_endpoint": "/WebGoat/PathTraversal/profile-upload"},
    {"lesson_id": "CrossSiteScripting.lesson", "cwe": "CWE-79",
     "exploit_endpoint": "/WebGoat/CrossSiteScripting/attack5a"},
    # Auth family
    {"lesson_id": "AuthBypass.lesson", "cwe": "CWE-287",
     "exploit_endpoint": "/WebGoat/auth-bypass/verify-account"},
    {"lesson_id": "JWT.lesson", "cwe": "CWE-347",
     "exploit_endpoint": "/WebGoat/JWT/decode"},
    {"lesson_id": "Password Reset.lesson", "cwe": "CWE-640",
     "exploit_endpoint": "/WebGoat/PasswordReset/reset/login"},
    # CSRF / SSRF / IDOR
    {"lesson_id": "CSRF.lesson", "cwe": "CWE-352",
     "exploit_endpoint": "/WebGoat/csrf/basic-get-flag"},
    {"lesson_id": "SSRF.lesson", "cwe": "CWE-918",
     "exploit_endpoint": "/WebGoat/SSRF/task1"},
    {"lesson_id": "IDOR.lesson", "cwe": "CWE-639",
     "exploit_endpoint": "/WebGoat/IDOR/profile"},
    # XXE
    {"lesson_id": "XXE.lesson", "cwe": "CWE-611",
     "exploit_endpoint": "/WebGoat/xxe/simple"},
    # Misc
    {"lesson_id": "InsecureDeserialization.lesson", "cwe": "CWE-502",
     "exploit_endpoint": "/WebGoat/InsecureDeserialization/task"},
    {"lesson_id": "VulnerableComponents.lesson", "cwe": "CWE-1104",
     "exploit_endpoint": "/WebGoat/VulnerableComponents/attack1"},
    {"lesson_id": "MissingFunctionAC.lesson", "cwe": "CWE-862",
     "exploit_endpoint": "/WebGoat/access-control/users"},
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LessonExpectation:
    """One curated must-find lesson — the bench's recall unit."""
    lesson_id: str
    cwe: str
    exploit_endpoint: str


@dataclass
class DualScorecard:
    """Detection rate + completion rate + chain gap.

    Detection: strix emitted a finding for the lesson's CWE class
    AND the finding's endpoint hits the lesson's surface.

    Completion: WebGoat's internal lesson-checker flipped `solved=
    true` for the lesson (polled post-scan).

    Chain gap: detection_rate − completion_rate. Positive = L1
    is finding bugs L2 isn't chaining. Negative would be weird
    (strix completed lessons without emitting findings) — investigate.
    """
    lessons_total: int = 0
    lessons_detected: int = 0           # L1 found the vuln
    lessons_completed: int = 0          # WebGoat marked it solved
    lessons_both: int = 0               # detected ∧ completed
    lessons_detected_not_completed: int = 0  # the L2 chain gap

    detected_lesson_ids: list[str] = field(default_factory=list)
    completed_lesson_ids: list[str] = field(default_factory=list)
    chain_gap_lesson_ids: list[str] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return (
            self.lessons_detected / self.lessons_total
            if self.lessons_total else 0.0
        )

    @property
    def completion_rate(self) -> float:
        return (
            self.lessons_completed / self.lessons_total
            if self.lessons_total else 0.0
        )

    @property
    def chain_gap(self) -> float:
        """Detection rate − completion rate. Positive = L2 chain gap."""
        return self.detection_rate - self.completion_rate

    def to_dict(self) -> dict:
        return {
            "lessons_total": self.lessons_total,
            "lessons_detected": self.lessons_detected,
            "lessons_completed": self.lessons_completed,
            "lessons_both": self.lessons_both,
            "lessons_detected_not_completed": self.lessons_detected_not_completed,
            "detection_rate": round(self.detection_rate, 4),
            "completion_rate": round(self.completion_rate, 4),
            "chain_gap": round(self.chain_gap, 4),
            "detected_lesson_ids": sorted(self.detected_lesson_ids),
            "completed_lesson_ids": sorted(self.completed_lesson_ids),
            "chain_gap_lesson_ids": sorted(self.chain_gap_lesson_ids),
        }


# ---------------------------------------------------------------------------
# Detection scoring: strix finding → covered lesson
# ---------------------------------------------------------------------------


def _finding_covers_lesson(
    finding: dict, lesson: LessonExpectation,
) -> bool:
    """A strix finding covers a lesson when:
      * The finding's CWE matches the lesson's CWE class, AND
      * The finding's endpoint contains the lesson's exploit_endpoint
        path segment (so a finding on
        `/WebGoat/SqlInjection/attack5a` covers `SqlInjection.lesson`).
    """
    cwe = str(finding.get("cwe", "")).strip().upper()
    if cwe != lesson.cwe.upper():
        return False
    endpoint = str(
        finding.get("endpoint") or finding.get("target") or "",
    )
    # Strip leading scheme://host so the substring match works for
    # both fully-qualified and path-relative endpoints.
    if "://" in endpoint:
        endpoint = endpoint.split("://", 1)[1]
        endpoint = "/" + endpoint.split("/", 1)[1] if "/" in endpoint else ""
    return lesson.exploit_endpoint in endpoint


def score_detection(
    findings: Iterable[dict],
    lessons: Iterable[LessonExpectation],
) -> tuple[int, set[str]]:
    """Return (count_detected, detected_lesson_ids) — how many
    must-find lessons strix emitted a covering finding for."""
    findings_list = list(findings)
    detected: set[str] = set()
    for lesson in lessons:
        if any(_finding_covers_lesson(f, lesson) for f in findings_list):
            detected.add(lesson.lesson_id)
    return (len(detected), detected)


# ---------------------------------------------------------------------------
# Completion scoring: WebGoat's lesson-progress poll
# ---------------------------------------------------------------------------


def score_completion(
    webgoat_lesson_progress: dict,
    lessons: Iterable[LessonExpectation],
) -> tuple[int, set[str]]:
    """Score lesson-completion from WebGoat's `/lessonprogress.mvc`
    response.

    WebGoat's response shape:
        {
          "SqlInjection.lesson": {"solved": true, "lessonName": "..."},
          "JWT.lesson": {"solved": false, ...},
          ...
        }
    OR a list of `{lessonName: "...", solved: bool}` entries
    depending on version. We handle both shapes defensively."""
    completed: set[str] = set()
    lesson_ids = {l.lesson_id for l in lessons}

    if isinstance(webgoat_lesson_progress, dict):
        for key, val in webgoat_lesson_progress.items():
            if not isinstance(val, dict):
                continue
            name = val.get("lessonName") or key
            if name in lesson_ids and val.get("solved"):
                completed.add(name)
    elif isinstance(webgoat_lesson_progress, list):
        for entry in webgoat_lesson_progress:
            if not isinstance(entry, dict):
                continue
            name = entry.get("lessonName") or entry.get("lesson_id")
            if name in lesson_ids and entry.get("solved"):
                completed.add(name)

    return (len(completed), completed)


# ---------------------------------------------------------------------------
# Top-level score — combines detection + completion
# ---------------------------------------------------------------------------


def score_dual(
    findings: Iterable[dict],
    lesson_progress: dict,
    lessons: Iterable[LessonExpectation] | None = None,
) -> DualScorecard:
    """Score strix's run against WebGoat in both modes.

    Args:
        findings: strix's vulnerability_reports.
        lesson_progress: parsed JSON from
            `/WebGoat/service/lessonprogress.mvc`.
        lessons: lesson universe (default: WEBGOAT_BENCH_LESSONS).
    """
    if lessons is None:
        lessons = [
            LessonExpectation(
                lesson_id=l["lesson_id"],
                cwe=l["cwe"],
                exploit_endpoint=l["exploit_endpoint"],
            )
            for l in WEBGOAT_BENCH_LESSONS
        ]
    else:
        lessons = list(lessons)

    findings_list = list(findings)
    detected_count, detected_ids = score_detection(findings_list, lessons)
    completed_count, completed_ids = score_completion(lesson_progress, lessons)
    both = detected_ids & completed_ids
    chain_gap_ids = detected_ids - completed_ids

    return DualScorecard(
        lessons_total=len(lessons),
        lessons_detected=detected_count,
        lessons_completed=completed_count,
        lessons_both=len(both),
        lessons_detected_not_completed=len(chain_gap_ids),
        detected_lesson_ids=sorted(detected_ids),
        completed_lesson_ids=sorted(completed_ids),
        chain_gap_lesson_ids=sorted(chain_gap_ids),
    )


# ---------------------------------------------------------------------------
# Markdown report rendering
# ---------------------------------------------------------------------------


def render_report(
    scorecard: DualScorecard, *,
    run_id: str = "",
    wall_seconds: float | None = None,
    extra_metadata: dict | None = None,
) -> str:
    """Render the dual scorecard with the headline detection /
    completion / chain-gap numbers."""
    lines: list[str] = []
    lines.append(
        f"# WebGoat dual-mode — strix scorecard"
        + (f" ({run_id})" if run_id else "")
    )
    lines.append("")
    lines.append(
        f"- **Detection rate**: {scorecard.detection_rate:.2%} "
        f"({scorecard.lessons_detected}/{scorecard.lessons_total})"
    )
    lines.append(
        f"- **Completion rate**: {scorecard.completion_rate:.2%} "
        f"({scorecard.lessons_completed}/{scorecard.lessons_total})"
    )
    lines.append(
        f"- **L2 chain gap**: {scorecard.chain_gap:.2%} "
        f"(strix found {scorecard.lessons_detected_not_completed} "
        f"lessons L2 couldn't complete)"
    )
    if wall_seconds is not None:
        lines.append(f"- **Wall time**: {wall_seconds:.1f}s")
    lines.append("")

    lines.append("## Why this metric matters")
    lines.append("")
    lines.append(
        "Detection rate measures L1 (OSS-tool detection). Completion "
        "rate measures L1+L2 (LLM successfully chained the finding "
        "into the specific exploit that flips WebGoat's lesson "
        "tracker). The **gap is the exact L2 chain-execution value** "
        "— closing the gap is L2's job."
    )
    lines.append("")

    if scorecard.detected_lesson_ids:
        lines.append("## Detected lessons")
        lines.append("")
        for lid in scorecard.detected_lesson_ids:
            mark = "✓" if lid in scorecard.completed_lesson_ids else "✗"
            lines.append(f"- [{mark}] `{lid}`" + (
                "" if lid in scorecard.completed_lesson_ids
                else "  — L1 found, L2 didn't chain"
            ))
        lines.append("")

    if scorecard.completed_lesson_ids:
        unexpected = [
            lid for lid in scorecard.completed_lesson_ids
            if lid not in scorecard.detected_lesson_ids
        ]
        if unexpected:
            lines.append("## Completed without detection")
            lines.append("")
            lines.append(
                "These lessons WebGoat marked complete but strix "
                "didn't emit a finding for. Either strix's "
                "L1 missed the vuln but the LLM's actions tripped "
                "the lesson anyway (good — chain reasoning worked) "
                "OR WebGoat's lesson tracker flipped from baseline "
                "noise (investigate)."
            )
            lines.append("")
            for lid in unexpected:
                lines.append(f"- `{lid}`")
            lines.append("")

    if extra_metadata:
        lines.append("## Metadata")
        lines.append("")
        for k, v in sorted(extra_metadata.items()):
            lines.append(f"- **{k}**: {v}")
        lines.append("")

    return "\n".join(lines)
