"""Reachability scoring for code-target findings (roadmap §7.1).

For each existing finding with a `code_locations` entry, compute
a `reachability_score: 0.0-1.0` based on three deterministic
signals derived from `code_map.json` (#94):

1. **route-reachable**: the finding's file is referenced by ANY
   route handler's file (transitively up to depth 3 via simple
   import chain). 1.0 if directly reachable, lower for transitive.
2. **non-test reference**: ANY non-test file imports the finding's
   file. 0.5 contribution.
3. **auth-path adjacency**: the finding's file is the same as a
   file containing an auth-boundary marker. Bumps to fix-now.

The aggregate score:
- 0.0 = dead code (no signal hits) → severity bumped DOWN to `info`
- 0.5 = imported but not on a route → severity unchanged
- 0.8+ = route-reachable → severity unchanged
- 1.0 + auth-path → severity bumped UP one notch (auth-attached findings)

The score is attached to the finding as `reachability_score` plus
`reachability_evidence: {route_reachable, non_test_referenced,
auth_path_adjacent, route_files, importing_files}` so the wrapper
can render the full provenance.

Engine-side severity promotion / demotion:
- Score 0.0 (dead code): severity → `info`, original kept in
  `severity_demoted_from`.
- `auth_path_adjacent=True`: severity bumped one notch (low→medium,
  medium→high, high→critical), original kept in
  `severity_promoted_from_reachability`.

Both transitions emit `finding.reachability_scored` events for
audit + wrapper rendering.

Targets zero-false-positive: deterministic, explainable, attached
evidence. The wrapper renders the score badge + reachability
provenance ("found in dead code; not exploitable from any route
handler") so non-technical users see WHY a finding was demoted.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "score_reachability"

_TEST_DIR_RE = re.compile(
    r"(^|[/\\])(tests?|_tests?_?|spec[s]?|__tests__)([/\\]|$)",
    re.IGNORECASE,
)


_SEV_LADDER = ["info", "low", "medium", "high", "critical"]


def _is_test_file(path: str) -> bool:
    """Heuristic: paths under `tests/` / `__tests__/` / `spec/` /
    `_tests_/` etc. are test files."""
    if _TEST_DIR_RE.search(path):
        return True
    base = Path(path).name
    return base.startswith("test_") or base.endswith("_test.py") or base.endswith(".test.js")


# ---------------------------------------------------------------------------
# Import-graph extraction (regex-based, lightweight)
# ---------------------------------------------------------------------------


# Python: `from foo.bar import x` / `import foo.bar`
_PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import\b|import\s+([\w.,\s]+))",
    re.MULTILINE,
)
# JS/TS: `import x from 'foo'` / `require('foo')`
_JS_IMPORT_RE = re.compile(
    r"""(?:from|require\s*\(\s*)\s*['"]([^'"]+)['"]""",
)


def _extract_imports(text: str, language: str) -> list[str]:
    """Return module specifiers imported by this file."""
    out: list[str] = []
    if language == "python":
        for m in _PY_IMPORT_RE.finditer(text):
            from_part = m.group(1)
            import_part = m.group(2)
            if from_part:
                out.append(from_part)
            elif import_part:
                # `import a, b.c, d` → ["a", "b.c", "d"]
                for piece in import_part.split(","):
                    piece = piece.strip()
                    if piece:
                        # Strip "as alias"
                        piece = piece.split(" as ")[0].strip()
                        out.append(piece)
    elif language in ("javascript", "typescript"):
        for m in _JS_IMPORT_RE.finditer(text):
            out.append(m.group(1))
    return out


def _resolve_python_import(
    importer_file: str,
    module_spec: str,
    repo_files: set[str],
) -> str | None:
    """Best-effort resolve a Python import statement to a file path
    in `repo_files`. Tries common conventions:
    - `foo.bar` → `foo/bar.py`
    - `foo.bar` → `foo/bar/__init__.py`
    - relative import `.bar` (treated as same-package)
    """
    parts = module_spec.replace(".", "/").strip("/")
    candidates = [
        f"{parts}.py",
        f"{parts}/__init__.py",
    ]
    importer_dir = str(Path(importer_file).parent)
    if importer_dir and not module_spec.startswith("."):
        candidates.append(f"{importer_dir}/{parts}.py")
        candidates.append(f"{importer_dir}/{parts}/__init__.py")
    for c in candidates:
        # Match by suffix to handle absolute vs relative paths.
        for fp in repo_files:
            if fp.endswith(c) or fp == c:
                return fp
    return None


def _resolve_js_import(
    importer_file: str,
    module_spec: str,
    repo_files: set[str],
) -> str | None:
    """Resolve a JS/TS import. Only looks at relative paths;
    `node_modules` deps are out of scope."""
    if not module_spec.startswith((".", "/")):
        return None
    importer_dir = Path(importer_file).parent
    target = (importer_dir / module_spec).as_posix()
    candidates = [
        target,
        f"{target}.js", f"{target}.jsx", f"{target}.ts", f"{target}.tsx",
        f"{target}/index.js", f"{target}/index.ts",
    ]
    for c in candidates:
        for fp in repo_files:
            if fp == c or fp.endswith(c):
                return fp
    return None


def _build_import_graph(
    code_map: dict[str, Any], repo_root: Path,
) -> dict[str, set[str]]:
    """Build {file: set(imported_files)} for every file referenced
    in code_map's routes/models/queries/external_http/auth lists.

    The graph is a coarse approximation — we only resolve imports
    we can see in the local repo; cross-package / node_modules edges
    are dropped. Intent: show whether the finding's file is in the
    same dependency closure as a route handler.
    """
    files_in_map: set[str] = set()
    for arr_name in (
        "routes", "models", "db_queries", "external_http_calls", "auth_boundaries",
    ):
        for entry in (code_map.get(arr_name) or []):
            if isinstance(entry, dict) and entry.get("file"):
                files_in_map.add(str(entry["file"]))

    # If the repo root exists, also walk it to collect known files.
    repo_files: set[str] = set(files_in_map)
    if repo_root.exists() and repo_root.is_dir():
        for ext in (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            for fp in repo_root.rglob(f"*{ext}"):
                # Skip pruned dirs.
                rel = fp.relative_to(repo_root).as_posix()
                if any(
                    seg in {"node_modules", "venv", ".venv", "__pycache__",
                            "dist", "build", ".git"}
                    for seg in rel.split("/")
                ):
                    continue
                repo_files.add(rel)

    graph: dict[str, set[str]] = defaultdict(set)

    for fp in repo_files:
        full = repo_root / fp if repo_root.is_dir() else Path(fp)
        try:
            text = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        ext = Path(fp).suffix.lower()
        if ext in (".py", ".pyi"):
            for spec in _extract_imports(text, "python"):
                resolved = _resolve_python_import(fp, spec, repo_files)
                if resolved:
                    graph[fp].add(resolved)
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            for spec in _extract_imports(text, "javascript"):
                resolved = _resolve_js_import(fp, spec, repo_files)
                if resolved:
                    graph[fp].add(resolved)
    return graph


def _bfs_reachable_from(
    graph: dict[str, set[str]], roots: set[str], max_depth: int = 5,
) -> dict[str, int]:
    """Return {file: shortest_distance} for every file reachable
    from any root via the import edges."""
    distance: dict[str, int] = {r: 0 for r in roots}
    queue: deque[tuple[str, int]] = deque((r, 0) for r in roots)
    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for target in graph.get(current, set()):
            if target not in distance or distance[target] > depth + 1:
                distance[target] = depth + 1
                queue.append((target, depth + 1))
    return distance


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------


def _score_for_file(
    file_path: str,
    *,
    route_reachable_distance: int | None,
    non_test_referrers: set[str],
    auth_path_files: set[str],
) -> tuple[float, dict[str, Any]]:
    """Compute the score + evidence for a single file."""
    in_test = _is_test_file(file_path)
    auth_adjacent = file_path in auth_path_files

    # Route-reachable score component. Direct (distance 0 — file
    # IS a route file) → 1.0. Distance 1 → 0.85. Distance 2 → 0.7.
    # Distance N → max(0.5, 1 - 0.15*N). None → 0.
    route_score = 0.0
    if route_reachable_distance is not None:
        if route_reachable_distance == 0:
            route_score = 1.0
        else:
            route_score = max(0.5, 1.0 - 0.15 * route_reachable_distance)

    # Non-test reference component (0 or 0.5).
    non_test_score = 0.5 if non_test_referrers and not in_test else 0.0

    if in_test and route_score == 0.0:
        # Test-only code with no production reachability.
        score = 0.0
    elif route_score > 0:
        score = route_score
    elif non_test_score > 0:
        score = non_test_score
    else:
        score = 0.0

    if auth_adjacent and score < 1.0:
        # auth-path adjacency clamps the score to 1.0 even via
        # transitive reachability — auth code is fix-now.
        score = max(score, 1.0)

    evidence: dict[str, Any] = {
        "in_test_path": in_test,
        "route_reachable": route_reachable_distance is not None,
        "route_distance": route_reachable_distance,
        "non_test_referrers": sorted(non_test_referrers),
        "auth_path_adjacent": auth_adjacent,
        "score_components": {
            "route_score": route_score,
            "non_test_score": non_test_score,
            "auth_clamp": auth_adjacent,
        },
    }
    return (score, evidence)


# ---------------------------------------------------------------------------
# Severity adjustment helpers
# ---------------------------------------------------------------------------


def _bump_severity(s: str) -> str:
    try:
        idx = _SEV_LADDER.index(s.lower())
    except ValueError:
        return s
    return _SEV_LADDER[min(idx + 1, len(_SEV_LADDER) - 1)]


def _adjust_finding_severity(
    finding: dict[str, Any], score: float, auth_adjacent: bool,
) -> tuple[str | None, str | None]:
    """Return (new_severity, transition_field) — None when no change.

    Transitions:
    - score == 0.0 + not info already → demote to 'info';
      transition_field = 'severity_demoted_from'
    - auth_adjacent → bump one notch;
      transition_field = 'severity_promoted_from_reachability'
    """
    current = (finding.get("severity") or "info").lower()
    if score == 0.0 and current != "info":
        return ("info", "severity_demoted_from")
    if auth_adjacent and current in ("low", "medium", "high"):
        return (_bump_severity(current), "severity_promoted_from_reachability")
    return (None, None)


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_event(name: str, payload: dict[str, Any]) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    try:
        t._emit_event(
            name, payload=payload, status="info",
            source="strix.findings.reachability",
        )
    except Exception:  # noqa: BLE001
        logger.debug("event emit failed", exc_info=True)


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592"],
)
def score_reachability(
    code_map_path: str | None = None,
    repo_path: str | None = None,
    finding_ids: str | None = None,
) -> dict[str, Any]:
    """Score reachability for every code-target finding.

    For each finding with `code_locations`, attach a
    `reachability_score: 0.0-1.0` plus `reachability_evidence`,
    then adjust severity:
        - score=0 (dead code) → severity → info (demoted)
        - auth-path adjacent → severity bumped one notch

    Args:
        code_map_path: optional path to `code_map.json`. Default:
            auto-load from the run dir.
        repo_path: optional path to repo root. Default: read from
            code_map_path's `repo_path` field.
        finding_ids: optional comma-separated subset of finding IDs
            to score. Default: every finding with `code_locations`.

    Returns:
        {
          success, code_map_path,
          processed_count, scored: [{report_id, score, evidence,
                                      severity_change}, ...],
          skipped: [{report_id, reason}, ...]
        }
    """
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return {"success": False, "error": "tracer not available"}

    tracer = get_global_tracer()
    if tracer is None:
        return {"success": False, "error": "no global tracer"}

    # ---- Auto-load code map ----
    cm: dict[str, Any] | None = None
    cm_path: Path | None = None
    if code_map_path:
        cm_path = Path(code_map_path)
    else:
        try:
            run_dir = tracer.get_run_dir()
            candidate = run_dir / "code_map.json"
            if candidate.exists():
                cm_path = candidate
        except Exception:  # noqa: BLE001
            pass

    if cm_path is None or not cm_path.exists():
        return {"success": False, "error": "code_map.json not available"}

    try:
        with cm_path.open("r", encoding="utf-8") as f:
            cm = json.load(f)
    except (OSError, ValueError) as e:
        return {"success": False, "error": f"failed to read code_map.json: {e}"}

    if not isinstance(cm, dict):
        return {"success": False, "error": "code_map.json is not a dict"}

    # ---- Resolve repo root ----
    repo_root_str = repo_path or cm.get("repo_path") or "."
    repo_root = Path(repo_root_str)

    # ---- Compute the import graph + route-set + auth-set ----
    route_files: set[str] = set()
    for r in cm.get("routes") or []:
        if isinstance(r, dict) and r.get("file"):
            route_files.add(str(r["file"]))
    auth_files: set[str] = set()
    for a in cm.get("auth_boundaries") or []:
        if isinstance(a, dict) and a.get("file"):
            auth_files.add(str(a["file"]))

    import_graph = _build_import_graph(cm, repo_root)
    distances_from_routes = _bfs_reachable_from(import_graph, route_files)

    # Build set of non-test files that import each file.
    inverse_graph: dict[str, set[str]] = defaultdict(set)
    for src, tgts in import_graph.items():
        for tgt in tgts:
            inverse_graph[tgt].add(src)

    # ---- Iterate findings, attach scores, adjust severities ----
    requested_ids: set[str] | None = None
    if finding_ids:
        requested_ids = {i.strip() for i in finding_ids.split(",") if i.strip()}

    findings = tracer.get_existing_vulnerabilities()
    scored: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for f in findings:
        rid = f.get("id")
        if requested_ids is not None and rid not in requested_ids:
            continue

        locations = f.get("code_locations") or []
        if not (isinstance(locations, list) and locations):
            skipped.append({"report_id": rid, "reason": "no_code_locations"})
            continue

        loc = locations[0] if isinstance(locations[0], dict) else None
        if loc is None:
            skipped.append({"report_id": rid, "reason": "invalid_code_locations"})
            continue
        file_path = str(loc.get("file") or "")
        if not file_path:
            skipped.append({"report_id": rid, "reason": "missing_file"})
            continue

        # Match by suffix — code_locations may use repo-relative paths
        # while the import graph uses the same; routes/auth come from
        # code_map and use the same convention.
        match_distance: int | None = None
        if file_path in distances_from_routes:
            match_distance = distances_from_routes[file_path]
        else:
            for candidate, dist in distances_from_routes.items():
                if candidate.endswith(file_path) or file_path.endswith(candidate):
                    match_distance = dist
                    break

        non_test_referrers = {
            r for r in inverse_graph.get(file_path, set())
            if not _is_test_file(r)
        }
        # Inverse-graph lookup may have suffix mismatches; sweep:
        if not non_test_referrers:
            for candidate in inverse_graph:
                if candidate.endswith(file_path) or file_path.endswith(candidate):
                    non_test_referrers.update(
                        r for r in inverse_graph[candidate]
                        if not _is_test_file(r)
                    )

        auth_adjacent = file_path in auth_files or any(
            af.endswith(file_path) or file_path.endswith(af) for af in auth_files
        )

        score, evidence = _score_for_file(
            file_path,
            route_reachable_distance=match_distance,
            non_test_referrers=non_test_referrers,
            auth_path_files=auth_files if auth_adjacent else set(),
        )

        # Attach to the finding.
        f["reachability_score"] = round(score, 3)
        f["reachability_evidence"] = evidence

        # Adjust severity per the score.
        new_sev, transition_field = _adjust_finding_severity(
            f, score, auth_adjacent,
        )
        severity_change: dict[str, Any] | None = None
        if new_sev is not None and transition_field is not None:
            previous = f.get("severity")
            f["severity"] = new_sev
            f[transition_field] = previous
            severity_change = {
                "previous": previous,
                "new": new_sev,
                "transition": transition_field,
            }

        record = {
            "report_id": rid,
            "score": round(score, 3),
            "evidence": evidence,
            "severity_change": severity_change,
        }
        scored.append(record)

        _emit_event(
            "finding.reachability_scored",
            payload={
                "report_id": rid,
                "fingerprint": f.get("fingerprint"),
                "score": round(score, 3),
                "evidence": evidence,
                "severity_change": severity_change,
            },
        )

    # Save run data so on-disk artifact reflects changes.
    try:
        tracer.save_run_data()
    except Exception:  # noqa: BLE001
        pass

    return {
        "success": True,
        "code_map_path": str(cm_path),
        "processed_count": len(scored),
        "scored": scored,
        "skipped": skipped,
    }
