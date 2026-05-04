"""Tests for taint_analysis (roadmap §8.1 row 3).

Hermetic — uses tmp_path with synthetic .py files containing known
taint flows. Tests cover source detection, sink detection, intra-
procedural flow tracking, severity ladder, scan_tests gate, error
resilience.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.telemetry import tracer as tracer_module
from strix.telemetry import utils as telemetry_utils
from strix.telemetry.tracer import Tracer, set_global_tracer
from strix.tools.taint.taint_analysis import taint_analysis


@pytest.fixture(autouse=True)
def _reset_tracer(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tracer_module, "_global_tracer", None)
    monkeypatch.setattr(tracer_module, "_OTEL_BOOTSTRAPPED", False)
    monkeypatch.setattr(tracer_module, "_OTEL_REMOTE_ENABLED", False)
    telemetry_utils.reset_events_write_locks()
    monkeypatch.delenv("STRIX_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_OTEL_TELEMETRY", raising=False)
    monkeypatch.delenv("STRIX_POSTHOG_TELEMETRY", raising=False)
    monkeypatch.setenv("STRIX_KEV_DISABLED", "1")
    tracer = Tracer("ta-test")
    set_global_tracer(tracer)
    tracer.set_scan_config(
        {"targets": [{"type": "repository", "value": str(tmp_path)}]}
    )
    yield


def _make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    for rel, content in files.items():
        full = repo / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8")
    return repo


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_empty_path_rejected() -> None:
    out = taint_analysis(repo_path="")
    assert out["success"] is False


def test_missing_path_rejected() -> None:
    out = taint_analysis(repo_path="/path/does/not/exist")
    assert out["success"] is False


# ---------------------------------------------------------------------------
# Direct source-to-sink flows
# ---------------------------------------------------------------------------


def test_direct_request_args_to_eval_high() -> None:
    """`eval(request.args.get('expr'))` → high-severity flow."""
    repo = _make_repo(Path("."), {
        "app.py": (
            "from flask import request\n"
            "def view():\n"
            "    return eval(request.args.get('expr'))\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert out["success"] is True
    flows = out["flows"]
    assert len(flows) == 1
    assert flows[0]["sink_label"] == "eval"
    assert flows[0]["severity"] == "high"


def test_direct_os_system_high() -> None:
    repo = _make_repo(Path("."), {
        "cmd.py": (
            "import os\n"
            "from flask import request\n"
            "def run():\n"
            "    os.system(request.form['cmd'])\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    flows = out["flows"]
    assert any(f["sink_label"] == "os.system" and f["severity"] == "high" for f in flows)


def test_subprocess_shell_true_high() -> None:
    """subprocess.run(..., shell=True) bumps severity."""
    repo = _make_repo(Path("."), {
        "shell.py": (
            "import subprocess\n"
            "from flask import request\n"
            "def run():\n"
            "    subprocess.run(request.args['cmd'], shell=True)\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    flows = out["flows"]
    assert any(
        "subprocess.run" in f["sink_label"] and "shell=True" in f["sink_label"]
        and f["severity"] == "high"
        for f in flows
    )


def test_raw_sql_execute() -> None:
    repo = _make_repo(Path("."), {
        "db.py": (
            "from flask import request\n"
            "def get_user(cursor):\n"
            "    cursor.execute('SELECT * FROM users WHERE id = ' + request.args.get('id'))\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    flows = out["flows"]
    assert any(f["sink_label"] == "cursor.execute" for f in flows)


# ---------------------------------------------------------------------------
# Variable-propagation flows
# ---------------------------------------------------------------------------


def test_variable_propagation_simple() -> None:
    repo = _make_repo(Path("."), {
        "app.py": (
            "from flask import request\n"
            "def view():\n"
            "    user_input = request.args.get('q')\n"
            "    eval(user_input)\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    flows = out["flows"]
    assert len(flows) == 1
    assert flows[0]["sink_label"] == "eval"


def test_variable_propagation_chain() -> None:
    repo = _make_repo(Path("."), {
        "chain.py": (
            "import os\n"
            "from flask import request\n"
            "def view():\n"
            "    a = request.args.get('cmd')\n"
            "    b = a\n"
            "    c = b\n"
            "    os.system(c)\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    flows = out["flows"]
    assert any(f["sink_label"] == "os.system" for f in flows)


def test_fstring_concatenation_propagates() -> None:
    repo = _make_repo(Path("."), {
        "fmt.py": (
            "from flask import request\n"
            "def view(cursor):\n"
            "    user_id = request.args['id']\n"
            "    cursor.execute(f'SELECT * FROM u WHERE id = {user_id}')\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    flows = out["flows"]
    assert any(f["sink_label"] == "cursor.execute" for f in flows)


def test_subscript_taint() -> None:
    """request.json['key'] → tainted via subscript."""
    repo = _make_repo(Path("."), {
        "subscr.py": (
            "import os\n"
            "from flask import request\n"
            "def run():\n"
            "    cmd = request.json['cmd']\n"
            "    os.system(cmd)\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert any(f["sink_label"] == "os.system" for f in out["flows"])


# ---------------------------------------------------------------------------
# Source coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_expr", [
    "request.args.get('x')",
    "request.form['x']",
    "request.json['x']",
    "request.cookies.get('x')",
    "request.headers.get('x')",
    "request.GET['x']",  # Django
    "request.POST.get('x')",  # Django
    "sys.argv[1]",
    "os.environ.get('FOO')",
])
def test_taint_source_recognised(source_expr) -> None:
    repo = _make_repo(Path("."), {
        "src.py": (
            "import os, sys\n"
            "from flask import request\n"
            "def view():\n"
            f"    eval({source_expr})\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert any(f["sink_label"] == "eval" for f in out["flows"]), source_expr


# ---------------------------------------------------------------------------
# Negative controls — clean code shouldn't flag
# ---------------------------------------------------------------------------


def test_clean_code_no_flow() -> None:
    """No taint sources / sinks → no flows."""
    repo = _make_repo(Path("."), {
        "clean.py": (
            "def add(a, b):\n"
            "    return a + b\n\n"
            "def main():\n"
            "    print(add(1, 2))\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert out["flows"] == []


def test_static_string_to_sink_no_flow() -> None:
    """Hardcoded strings reaching sinks aren't taint."""
    repo = _make_repo(Path("."), {
        "static.py": (
            "import os\n"
            "def boot():\n"
            "    os.system('ls -la')\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert out["flows"] == []


def test_taint_in_unused_var_no_flow() -> None:
    """Tainted var that never reaches a sink → no flow."""
    repo = _make_repo(Path("."), {
        "unused.py": (
            "from flask import request\n"
            "def view():\n"
            "    user_input = request.args.get('q')\n"
            "    return 'static response'\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert out["flows"] == []


# ---------------------------------------------------------------------------
# Additional sinks
# ---------------------------------------------------------------------------


def test_pickle_loads_high() -> None:
    repo = _make_repo(Path("."), {
        "pkl.py": (
            "import pickle\n"
            "from flask import request\n"
            "def load():\n"
            "    return pickle.loads(request.data)\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert any(f["sink_label"] == "pickle.loads" and f["severity"] == "high"
               for f in out["flows"])


def test_yaml_load_high() -> None:
    repo = _make_repo(Path("."), {
        "yml.py": (
            "import yaml\n"
            "from flask import request\n"
            "def load():\n"
            "    return yaml.load(request.json['cfg'])\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert any("yaml.load" in f["sink_label"] for f in out["flows"])


def test_open_taint_medium() -> None:
    repo = _make_repo(Path("."), {
        "fs.py": (
            "from flask import request\n"
            "def read():\n"
            "    return open(request.args['path']).read()\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert any(f["sink_label"] == "open" and f["severity"] == "medium"
               for f in out["flows"])


# ---------------------------------------------------------------------------
# Function scope
# ---------------------------------------------------------------------------


def test_function_scope_isolation() -> None:
    """Tainted var in fn1 doesn't propagate to fn2 (no inter-procedural).

    NOTE: with closure-style scope inheritance, fn2 would not see
    fn1's locals — so the static os.system in fn2 is NOT flagged.
    """
    repo = _make_repo(Path("."), {
        "scopes.py": (
            "import os\n"
            "from flask import request\n"
            "def fn1():\n"
            "    user = request.args.get('u')\n"
            "    return user\n\n"
            "def fn2():\n"
            "    os.system('ls')\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    # No flows — fn2's static os.system is clean; fn1's tainted user
    # is unused.
    assert out["flows"] == []


# ---------------------------------------------------------------------------
# Walk + prune
# ---------------------------------------------------------------------------


def test_test_dirs_skipped_by_default(tmp_path) -> None:
    """tests/ directory pruned by default."""
    repo = _make_repo(tmp_path, {
        "src/app.py": (
            "from flask import request\n"
            "import os\n"
            "def view():\n"
            "    os.system(request.args['cmd'])\n"
        ),
        "tests/test_app.py": (
            "from flask import request\n"
            "import os\n"
            "def test_view():\n"
            "    os.system(request.args['cmd'])\n"
        ),
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    files = {f["file"] for f in out["flows"]}
    # Only the src/app.py flow shows up; tests/ pruned.
    assert any("src/app.py" in f for f in files)
    assert not any("tests/" in f for f in files)


def test_scan_tests_includes_tests(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "tests/test_app.py": (
            "from flask import request\n"
            "import os\n"
            "def test_view():\n"
            "    os.system(request.args['cmd'])\n"
        ),
    })
    out = taint_analysis(
        repo_path=str(repo), emit_findings=False, scan_tests=True,
    )
    # Now tests/ contributes the flow.
    files = {f["file"] for f in out["flows"]}
    assert any("tests/" in f for f in files)


def test_node_modules_pruned(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "src/app.py": "from flask import request\nimport os\ndef v(): os.system(request.args['c'])\n",
        "node_modules/lib/index.py": "from flask import request\nimport os\ndef v(): os.system(request.args['c'])\n",
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    files = {f["file"] for f in out["flows"]}
    assert any("src/app.py" in f for f in files)
    assert not any("node_modules" in f for f in files)


# ---------------------------------------------------------------------------
# Single-file mode
# ---------------------------------------------------------------------------


def test_single_file_input(tmp_path) -> None:
    f = tmp_path / "single.py"
    f.write_text(
        "import os\nfrom flask import request\ndef v(): os.system(request.args['c'])\n"
    )
    out = taint_analysis(repo_path=str(f), emit_findings=False)
    assert out["success"] is True
    assert any(flow["sink_label"] == "os.system" for flow in out["flows"])


# ---------------------------------------------------------------------------
# emit_findings + tracer integration
# ---------------------------------------------------------------------------


def test_findings_emitted_by_default() -> None:
    repo = _make_repo(Path("."), {
        "app.py": "import os\nfrom flask import request\ndef v(): os.system(request.args['c'])\n",
    })
    out = taint_analysis(repo_path=str(repo))
    assert out["findings_emitted"] >= 1
    tracer = tracer_module.get_global_tracer()
    findings = tracer.get_existing_vulnerabilities()
    taint_findings = [f for f in findings if f.get("category") == "taint_flow"]
    assert len(taint_findings) >= 1
    # Severity high (os.system + tainted)
    assert taint_findings[0]["severity"] == "high"


def test_emit_findings_disabled() -> None:
    repo = _make_repo(Path("."), {
        "app.py": "import os\nfrom flask import request\ndef v(): os.system(request.args['c'])\n",
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert out["findings_emitted"] == 0
    tracer = tracer_module.get_global_tracer()
    assert tracer.get_existing_vulnerabilities() == []


def test_finding_carries_code_locations() -> None:
    repo = _make_repo(Path("."), {
        "app.py": "import os\nfrom flask import request\ndef v(): os.system(request.args['c'])\n",
    })
    taint_analysis(repo_path=str(repo))
    tracer = tracer_module.get_global_tracer()
    findings = [f for f in tracer.get_existing_vulnerabilities() if f.get("category") == "taint_flow"]
    assert findings
    assert findings[0].get("code_locations")
    assert findings[0]["code_locations"][0]["file"].endswith("app.py")


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------


def test_syntax_error_files_skipped(tmp_path) -> None:
    repo = _make_repo(tmp_path, {
        "good.py": "import os\nfrom flask import request\ndef v(): os.system(request.args['c'])\n",
        "broken.py": "def syntax_error(:\n    pass\n",
    })
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    # Pipeline didn't crash; good file's flow still detected.
    assert out["success"] is True
    files = {f["file"] for f in out["flows"]}
    assert any("good.py" in f for f in files)


# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------


def test_result_schema(tmp_path) -> None:
    repo = _make_repo(tmp_path, {"a.py": "x = 1\n"})
    out = taint_analysis(repo_path=str(repo), emit_findings=False)
    assert set(out.keys()) >= {
        "success", "repo_path", "summary", "flows",
        "findings_emitted", "errors",
    }
    assert set(out["summary"].keys()) >= {
        "files_analysed", "flows_detected", "by_severity", "errors",
    }


# ---------------------------------------------------------------------------
# MITRE
# ---------------------------------------------------------------------------


def test_mitre_attached() -> None:
    from strix.tools.registry import get_tool_mitre_techniques
    techniques = get_tool_mitre_techniques("taint_analysis")
    assert "T1190" in techniques
