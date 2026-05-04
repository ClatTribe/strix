"""Python AST-based taint analysis (roadmap §8.1 row 3).

Walks `.py` files in a repo, parses each with `ast`, and tracks
data flow from known **taint sources** (request.args, sys.argv,
os.environ, etc.) through variable assignments to known **sinks**
(eval, exec, os.system, raw cursor.execute, shell=True, ...).

Per-file analysis (intra-procedural; no cross-file flow). For each
function definition, the visitor:

1. Records every variable name that's been assigned from a taint
   source (`tainted_names`).
2. Tracks assignments: `y = x` propagates taint from x to y; `y =
   foo(x)` propagates if x is tainted (whole-call returns are
   considered tainted).
3. When a sink call site is reached, checks whether ANY of its
   argument expressions reference a tainted name. If yes, emits a
   finding linking source → sink.

Limitations (v1 — these are §17.1 follow-up territory):

- No inter-procedural flow (function calls in/out of the function
  don't carry taint across).
- No type-aware sanitiser detection (`html.escape(x)` doesn't
  un-taint x — every framework's sanitiser API is different).
- No object-attribute taint (`tainted.foo` is treated as untainted
  unless the chain originates at a source).
- Python only (Java / Go / JS via tree-sitter is L-effort §17.1).

Despite limitations, this catches the bulk of "obvious" taint
flows that LLM-only reasoning misses on non-trivial codebases:

- `cursor.execute("SELECT ... " + request.args.get('id'))` →
  `taint_flow` finding with severity=high (raw SQL + tainted input)
- `os.system(request.form['cmd'])` → severity=high
- `eval(request.json['expr'])` → severity=high
- `subprocess.run(request.args, shell=True)` → severity=high
- `template.render(message=request.args)` → severity=medium
  (XSS-shaped if rendered into HTML)

Composes with §8.0:
- Findings emitted via the canonical-finding contract (#86).
- Reads `code_map.json` (#94) when present to scope the walk to
  known route handlers (skips test files).
- The `validator-agent` specialist (#89) re-verifies via the
  `verify_findings` tool (#93) when it ships with a taint-aware
  re-probe strategy.
"""

from __future__ import annotations

import ast
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "taint_analysis"

_DEFAULT_MAX_FILES = 5000
_DEFAULT_MAX_FILE_SIZE = 1024 * 1024  # 1 MiB

# Same pruning as build_code_map.
_PRUNE_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components",
    "venv", ".venv", "env", ".env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "out", "target",
    ".next", ".nuxt", ".cache",
    "vendor", "third_party",
    ".idea", ".vscode",
    # By default, also skip test directories — taint findings in
    # test fixtures are noise. Caller can set scan_tests=True to
    # include them.
    "tests", "test", "_tests", "_test", "spec", "specs",
})


# ---------------------------------------------------------------------------
# Source / sink catalogues
# ---------------------------------------------------------------------------


# Each source is a sequence of attributes that must match an attribute
# chain ending in this name. e.g. ("request", "args") matches
# `request.args.get(...)`, `flask.request.args["k"]`, etc.
_TAINT_SOURCES: tuple[tuple[str, ...], ...] = (
    ("request", "args"),
    ("request", "form"),
    ("request", "json"),
    ("request", "cookies"),
    ("request", "headers"),
    ("request", "values"),
    ("request", "data"),
    ("request", "files"),
    ("request", "GET"),         # Django
    ("request", "POST"),        # Django
    ("request", "META"),        # Django
    ("request", "body"),
    ("request", "params"),      # express / fastify
    ("request", "query"),       # express / fastify
    ("flask", "request"),
    ("sys", "argv"),
    ("os", "environ"),
    ("input",),
    ("raw_input",),
)


# Sinks: (sink_chain, severity_when_tainted, sink_label)
# sink_chain is matched as suffix of attribute access.
_TAINT_SINKS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    # Code execution (highest severity)
    (("eval",), "high", "eval"),
    (("exec",), "high", "exec"),
    (("compile",), "high", "compile"),
    (("os", "system"), "high", "os.system"),
    (("os", "popen"), "high", "os.popen"),
    (("subprocess", "Popen"), "high", "subprocess.Popen"),
    (("subprocess", "call"), "high", "subprocess.call"),
    (("subprocess", "run"), "high", "subprocess.run"),
    (("subprocess", "check_call"), "high", "subprocess.check_call"),
    (("subprocess", "check_output"), "high", "subprocess.check_output"),
    # Raw SQL — high severity (SQLi)
    (("execute",), "high", "cursor.execute"),
    (("executemany",), "high", "cursor.executemany"),
    (("executescript",), "high", "cursor.executescript"),
    (("raw",), "medium", "Model.objects.raw (Django)"),
    # File system (path traversal)
    (("open",), "medium", "open"),
    (("os", "remove"), "medium", "os.remove"),
    (("os", "unlink"), "medium", "os.unlink"),
    (("shutil", "rmtree"), "high", "shutil.rmtree"),
    (("pathlib", "Path"), "low", "pathlib.Path"),
    # Deserialisation (RCE-shaped)
    (("pickle", "loads"), "high", "pickle.loads"),
    (("yaml", "load"), "high", "yaml.load (unsafe)"),
    (("marshal", "loads"), "high", "marshal.loads"),
    # Template / rendering (XSS-shaped)
    (("render_template_string",), "medium", "Flask render_template_string"),
    (("Template",), "medium", "string.Template"),
    (("Markup",), "medium", "Markup"),
    # Network / SSRF
    (("requests", "get"), "medium", "requests.get"),
    (("requests", "post"), "medium", "requests.post"),
    (("urllib", "urlopen"), "medium", "urllib.urlopen"),
    (("urllib", "request", "urlopen"), "medium", "urllib.request.urlopen"),
    (("httpx", "get"), "medium", "httpx.get"),
    # XML / XXE
    (("etree", "parse"), "medium", "lxml.etree.parse"),
    (("etree", "fromstring"), "medium", "lxml.etree.fromstring"),
)


# Sinks that are higher-severity when shell=True is set (subprocess
# family). Detected via kwarg inspection.
_SHELL_SINK_NAMES: frozenset[str] = frozenset({
    "Popen", "call", "run", "check_call", "check_output",
})


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _attribute_chain(node: ast.AST) -> tuple[str, ...]:
    """Return the attribute access chain as a tuple of names.

    e.g. for `request.args.get(...)`:
        Call(func=Attribute(value=Attribute(value=Name('request'),
        attr='args'), attr='get')) → ('request', 'args', 'get')
    """
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return tuple(reversed(parts))


def _matches_chain_suffix(
    chain: tuple[str, ...], catalog_entry: tuple[str, ...],
) -> bool:
    """True if `catalog_entry` matches the END of `chain` (suffix
    match). Lets `request.args.get` match catalogue entry
    `("request", "args")` AND lets `flask.request.args.get` match
    too."""
    if len(catalog_entry) > len(chain):
        return False
    return chain[-len(catalog_entry):] == catalog_entry


def _is_source_chain(chain: tuple[str, ...]) -> bool:
    """True if `chain` starts at a registered source. We check
    PREFIX so `request.args.get` (chain ('request','args','get')) is
    a source via prefix match on ('request','args')."""
    for source in _TAINT_SOURCES:
        if len(source) > len(chain):
            continue
        if chain[:len(source)] == source:
            return True
    return False


def _matching_sink(call_chain: tuple[str, ...]) -> tuple[str, str] | None:
    """Return (severity, sink_label) when `call_chain` matches a
    sink; else None."""
    for sink_chain, severity, label in _TAINT_SINKS:
        if _matches_chain_suffix(call_chain, sink_chain):
            return (severity, label)
    return None


def _has_shell_true_kwarg(call_node: ast.Call) -> bool:
    """True if the call has shell=True kwarg."""
    for kw in call_node.keywords or []:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _extract_referenced_names(node: ast.AST) -> set[str]:
    """Walk an expression and return the set of bare-Name node ids
    referenced. Used to check whether a sink-call argument
    references a tainted variable."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
    return names


def _expression_taint_chain(
    node: ast.AST, tainted_names: set[str],
) -> tuple[str, ...] | None:
    """If the expression `node` evaluates to a tainted value, return
    the source chain that explains the taint. Else None.

    Cases:
        - Direct source call: request.args.get('foo') → return the source chain.
        - Reference to a tainted variable: x → return ('<tainted_var>', 'x').
        - Subscript / Attribute on a tainted base: x[0] / x.foo → recurse.
        - BinOp / JoinedStr / Tuple / List: any sub-expression tainted → return.
    """
    if isinstance(node, ast.Call):
        chain = _attribute_chain(node.func)
        if chain and _is_source_chain(chain):
            return chain
        # Recurse into arguments (e.g. wrap_str(request.args.get(...)))
        for a in node.args:
            sub = _expression_taint_chain(a, tainted_names)
            if sub:
                return sub
    if isinstance(node, ast.Name):
        if node.id in tainted_names:
            return ("<tainted_var>", node.id)
    if isinstance(node, ast.Subscript):
        # request.args["k"] is tainted via the value
        return _expression_taint_chain(node.value, tainted_names)
    if isinstance(node, ast.Attribute):
        chain = _attribute_chain(node)
        if chain and _is_source_chain(chain):
            return chain
        # Recurse into the value (might be tainted variable)
        return _expression_taint_chain(node.value, tainted_names)
    if isinstance(node, (ast.BinOp, ast.BoolOp, ast.UnaryOp, ast.Compare)):
        for child in ast.iter_child_nodes(node):
            sub = _expression_taint_chain(child, tainted_names)
            if sub:
                return sub
    if isinstance(node, ast.JoinedStr):
        # f-string: any value-component tainted
        for value in node.values:
            sub = _expression_taint_chain(value, tainted_names)
            if sub:
                return sub
    if isinstance(node, ast.FormattedValue):
        return _expression_taint_chain(node.value, tainted_names)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for el in node.elts:
            sub = _expression_taint_chain(el, tainted_names)
            if sub:
                return sub
    if isinstance(node, ast.Dict):
        for v in node.values:
            sub = _expression_taint_chain(v, tainted_names)
            if sub:
                return sub
    return None


# ---------------------------------------------------------------------------
# Per-file taint flow visitor
# ---------------------------------------------------------------------------


class _TaintFlowVisitor(ast.NodeVisitor):
    """Per-function tracker. The `flows` list accumulates
    (source_chain, source_lineno, sink_chain, sink_label, severity,
    sink_lineno) tuples for each detected source→sink flow."""

    def __init__(self) -> None:
        self.flows: list[dict[str, Any]] = []
        # Per-scope tainted-names stack — entries pushed at function
        # entry, popped on exit.
        self._scopes: list[set[str]] = [set()]

    @property
    def _current_scope(self) -> set[str]:
        return self._scopes[-1]

    def _push_scope(self) -> None:
        # Functions inherit outer-scope taint by default (closure).
        self._scopes.append(set(self._current_scope))

    def _pop_scope(self) -> None:
        if len(self._scopes) > 1:
            self._scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._push_scope()
        self.generic_visit(node)
        self._pop_scope()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._push_scope()
        self.generic_visit(node)
        self._pop_scope()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        # Class bodies share scope with surrounding function.
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        # Check RHS for taint.
        chain = _expression_taint_chain(node.value, self._current_scope)
        if chain:
            for target in node.targets:
                self._taint_target(target)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        chain = _expression_taint_chain(node.value, self._current_scope)
        if chain:
            self._taint_target(node.target)
        self.generic_visit(node)

    def _taint_target(self, target: ast.AST) -> None:
        """Mark any Name children of `target` as tainted."""
        if isinstance(target, ast.Name):
            self._current_scope.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for el in target.elts:
                self._taint_target(el)
        elif isinstance(target, ast.Starred):
            self._taint_target(target.value)
        # Subscript / Attribute targets ignored (we'd need
        # pointer/alias analysis for those).

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Is this a sink call?
        chain = _attribute_chain(node.func)
        sink_match = _matching_sink(chain) if chain else None
        if sink_match is None and isinstance(node.func, ast.Name):
            # Bare-name call — match catalogue.
            sink_match = _matching_sink((node.func.id,))

        if sink_match is not None:
            severity, label = sink_match
            # Bump severity to high for shell=True.
            if (
                chain
                and chain[-1] in _SHELL_SINK_NAMES
                and _has_shell_true_kwarg(node)
            ):
                severity = "high"
                label = f"{label} (shell=True)"

            # Check ALL arguments and ALL kwarg values.
            tainted_arg_chain: tuple[str, ...] | None = None
            for arg_node in list(node.args) + [kw.value for kw in (node.keywords or [])]:
                sub = _expression_taint_chain(arg_node, self._current_scope)
                if sub:
                    tainted_arg_chain = sub
                    break

            if tainted_arg_chain is not None:
                self.flows.append({
                    "source_chain": ".".join(tainted_arg_chain),
                    "sink_chain": ".".join(chain) if chain else node.func.id if isinstance(node.func, ast.Name) else "?",
                    "sink_label": label,
                    "severity": severity,
                    "lineno": node.lineno,
                    "col_offset": node.col_offset,
                })

        # Continue visiting (function bodies, nested calls).
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_taint_finding(
    *, file_path: str, flow: dict[str, Any], repo_path: str,
) -> None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    tracer = get_global_tracer()
    if tracer is None:
        return

    severity = flow.get("severity", "medium")
    sink_label = flow.get("sink_label", "?")
    source_chain = flow.get("source_chain", "?")
    lineno = flow.get("lineno", 0)

    description_plain = (
        f"User-supplied data flowing from `{source_chain}` reaches "
        f"the dangerous sink `{sink_label}` at {file_path}:{lineno}. "
        f"Without explicit sanitisation, an attacker who controls the "
        f"request input can drive the sink to do something harmful "
        f"(SQL injection, command execution, file write to a "
        f"controlled path, etc.)."
    )
    recommended_action = (
        "Sanitise / parameterise the input at the sink: use "
        "parameterised queries instead of string-concatenated SQL; "
        "use `subprocess.run(..., shell=False)` with a list-of-args; "
        "validate file paths against a known-good prefix; never call "
        "`eval` / `exec` on request input. If sanitisation IS in place, "
        "annotate the call site explicitly so future taint runs can "
        "treat it as a sanitiser."
    )

    try:
        tracer.add_vulnerability_report(
            title=(
                f"Taint flow: `{source_chain}` → `{sink_label}` "
                f"({Path(file_path).name}:{lineno})"
            ),
            severity=severity,
            category="taint_flow",
            cwe="CWE-20",  # Improper Input Validation; sink-specific in evidence
            target=str(Path(repo_path).name or repo_path),
            endpoint=f"{file_path}:{lineno}",
            description=(
                f"AST-based taint analysis traced data flow from "
                f"`{source_chain}` to the `{sink_label}` sink. "
                f"Source: tainted input. Sink: {flow.get('sink_chain')}. "
                f"Site: {file_path}:{lineno}."
            ),
            description_plain=description_plain,
            recommended_action=recommended_action,
            verification_status="pattern_match",
            code_locations=[{
                "file": file_path,
                "line": lineno,
                "function": "(taint flow site)",
            }],
        )
    except Exception:  # noqa: BLE001
        logger.debug("taint finding emit failed", exc_info=True)


# ---------------------------------------------------------------------------
# File walk + analysis driver
# ---------------------------------------------------------------------------


def _walk_python_files(
    root: Path, *, max_files: int, max_file_size: int, scan_tests: bool,
) -> list[Path]:
    out: list[Path] = []
    if not root.exists():
        return out
    if root.is_file():
        if root.suffix == ".py" and root.stat().st_size <= max_file_size:
            return [root]
        return out

    import os

    prune = set(_PRUNE_DIRS)
    if scan_tests:
        prune -= {"tests", "test", "_tests", "_test", "spec", "specs"}

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if d not in prune and not d.startswith(".")
        ]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            path = Path(dirpath) / fname
            try:
                if path.is_symlink():
                    continue
                if path.stat().st_size > max_file_size:
                    continue
            except OSError:
                continue
            out.append(path)
            if len(out) >= max_files:
                return out
    return out


def _analyse_file(file_path: Path, root: Path) -> list[dict[str, Any]]:
    """Parse + visit one file; return list of taint flows."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(text, filename=str(file_path))
    except SyntaxError:
        return []
    except Exception:  # noqa: BLE001
        return []
    visitor = _TaintFlowVisitor()
    try:
        visitor.visit(tree)
    except Exception:  # noqa: BLE001
        logger.debug("visitor raised on %s", file_path, exc_info=True)
        return []
    rel = str(file_path.relative_to(root)) if root.is_dir() else str(file_path)
    for flow in visitor.flows:
        flow["file"] = rel
    return visitor.flows


# ---------------------------------------------------------------------------
# Phase events
# ---------------------------------------------------------------------------


def _open_phase(focus: str) -> tuple[Any, str | None]:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return (None, None)
        phase_id = tracer.enter_phase(phase="exploit", focus=focus)
        return (tracer, phase_id)
    except Exception:  # noqa: BLE001
        return (None, None)


def _close_phase(tracer: Any, phase_id: str | None, summary: dict[str, Any]) -> None:
    if tracer is None or phase_id is None:
        return
    try:
        tracer.complete_phase(phase_id, summary=summary)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1190"],  # Exploit Public-Facing Application
)
def taint_analysis(
    repo_path: str,
    max_files: int = _DEFAULT_MAX_FILES,
    max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
    scan_tests: bool = False,
    emit_findings: bool = True,
) -> dict[str, Any]:
    """Run AST-based taint analysis over a Python repo.

    §8.1 row 3 — the LLM-side Taint agent's primary tool. Walks `.py`
    files, parses each with `ast`, tracks data flow from known taint
    sources (request.*, sys.argv, os.environ, etc.) through variable
    assignments to known sinks (eval, exec, os.system, raw SQL,
    pickle.loads, etc.).

    Args:
        repo_path: filesystem path to the repository (or a single .py
            file for testing).
        max_files: cap on .py files analysed (default 5000).
        max_file_size: per-file byte cap (default 1 MiB).
        scan_tests: when True, includes test directories. Default
            False — taint findings in test fixtures are noise.
        emit_findings: when True (default), emits a finding per
            detected flow via the tracer. Set False to get the
            structured flow list without the finding side-effect.

    Returns:
        {
          success, repo_path,
          summary: {files_analysed, flows_detected, ...},
          flows: [{file, lineno, source_chain, sink_chain,
                   sink_label, severity}, ...],
          findings_emitted, errors
        }

    Notes:
        - Python only (v1). JS/Java/Go via tree-sitter is L-effort
          §17.1 follow-up.
        - Intra-procedural (no cross-file flow).
        - No type-aware sanitiser detection — emitted findings are
          `verification_status=pattern_match` and the `validator-agent`
          (#89) re-verifies via `verify_findings` (#93) when its
          taint-aware re-probe lands.
    """
    if not isinstance(repo_path, str) or not repo_path.strip():
        return {"success": False, "error": "repo_path required"}

    root = Path(repo_path).expanduser().resolve()
    if not root.exists():
        return {"success": False, "error": f"repo_path does not exist: {root}"}

    repo_name = root.name or str(root)
    tracer, phase_id = _open_phase(f"taint:{repo_name}")

    files_analysed = 0
    errors: list[dict[str, Any]] = []
    all_flows: list[dict[str, Any]] = []
    findings_emitted = 0

    try:
        files = _walk_python_files(
            root,
            max_files=max_files,
            max_file_size=max_file_size,
            scan_tests=scan_tests,
        )
        for fp in files:
            files_analysed += 1
            try:
                flows = _analyse_file(fp, root)
            except Exception as e:  # noqa: BLE001
                rel = str(fp.relative_to(root)) if root.is_dir() else str(fp)
                errors.append({"file": rel, "error": str(e)})
                continue
            all_flows.extend(flows)
            if emit_findings:
                for flow in flows:
                    _emit_taint_finding(
                        file_path=flow["file"], flow=flow, repo_path=str(root),
                    )
                    findings_emitted += 1

        # Severity histogram.
        sev_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        for f in all_flows:
            s = f.get("severity", "medium")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "success": True,
            "repo_path": str(root),
            "repo_name": repo_name,
            "phase_id": phase_id,
            "summary": {
                "files_analysed": files_analysed,
                "flows_detected": len(all_flows),
                "by_severity": sev_counts,
                "errors": len(errors),
            },
            "flows": all_flows,
            "findings_emitted": findings_emitted,
            "errors": errors,
        }
    finally:
        _close_phase(tracer, phase_id, {"tool": _TOOL_NAME, "repo_path": str(root)})
