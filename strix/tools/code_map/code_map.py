"""Code-Map agent — repository structure extractor.

Walks a repo and extracts the structural artifacts every downstream
code-target specialist reads:

- **Routes**: HTTP route handlers (Flask / Django / FastAPI /
  Express / Rails / Spring decorators + URL patterns).
- **Models**: ORM model definitions (SQLAlchemy / Django ORM /
  Mongoose schemas / Sequelize).
- **DB queries**: raw SQL strings + ORM calls (where detectable
  via pattern catalogue).
- **External HTTP calls**: requests.get / httpx / fetch / axios
  / http.Client invocations.
- **Auth boundaries**: decorators / middleware that gate access
  (`@login_required`, `@requires_role`, `@authenticated`, custom
  framework-specific markers).

Each artifact records its source location (`file:line`) so
downstream taint / SAST / reachability agents can cross-reference.

The catalogue is **regex-based** for v1 — fast, no AST parse,
language-agnostic enough to ship now. AST-based extraction (via
tree-sitter) is the obvious extension and lives in §8.1's Taint
agent (row 3) which needs proper data-flow anyway.

Output: `code_map.json` next to other handoff artifacts in the run
directory. Validated against the §8.0 handoff-schema pattern
(`strix/agents/handoffs/code_map.py`); contract violations emit
`handoff.shape_violation` events but never block the write.

Skip cases:
- Files larger than `max_file_size` (default 1 MiB) skipped (binary
  / generated artifacts shouldn't be in source code anyway).
- Common ignore directories pruned: `.git`, `node_modules`,
  `venv` / `.venv`, `__pycache__`, `dist` / `build`, `.next`,
  `target`, `vendor`, `coverage`.
- Symlinks not followed (avoids infinite loops).

Composes with §8.0:
- #87 / #91 handoff-schema pattern: producer-side validation +
  emits `handoff.shape_violation` events on contract drift.
- #89 specialist registry: the `webapp-recon-lead` analogue for
  code targets is the agent that calls this tool; downstream
  specialists (`secret-agent`, `dependency-agent`, `sast-agent`)
  read `code_map.json`.

MITRE: T1592 (Gather Victim Host Information) + T1595 (Active
Scanning) — adapted for the code-target scan-mode.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "build_code_map"

_DEFAULT_MAX_FILE_SIZE = 1024 * 1024  # 1 MiB
_DEFAULT_MAX_FILES = 5000

_PRUNE_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components",
    "venv", ".venv", "env", ".env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "out", "target", "bin", "obj",
    ".next", ".nuxt", ".angular", ".cache", ".turbo",
    "vendor", "third_party", "_external",
    "coverage", ".coverage", "htmlcov",
    ".idea", ".vscode",
})

# Source extensions we know how to extract from. Anything else is
# walked but no extractor runs.
_SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".pyi",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".rb", ".go", ".java", ".kt", ".kts", ".scala",
    ".php", ".cs",
    ".sql",
})


# ---------------------------------------------------------------------------
# Pattern catalogue — Routes
# ---------------------------------------------------------------------------


# Each pattern: (compiled_regex, framework, language, http_method_group_or_default,
#                path_group, handler_group_or_None)
# Pattern is run line-by-line; multi-line decorators are joined to the
# next non-blank line for handler attribution.

_ROUTE_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str, int, int], ...] = (
    # Flask: @app.route("/path", methods=["GET","POST"]) or @bp.get("/path")
    (
        "flask_route",
        re.compile(
            r"@\s*\w+\.route\s*\(\s*[\"']([^\"']+)[\"'](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?",
            re.IGNORECASE,
        ),
        "flask", "python", 2, 1,  # methods group = 2, path group = 1
    ),
    (
        "flask_method_decorator",
        re.compile(
            r"@\s*\w+\.(get|post|put|patch|delete|head|options)\s*\(\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        "flask", "python", 1, 2,
    ),
    # FastAPI: @app.get("/path") / @router.post("/path")
    (
        "fastapi_decorator",
        re.compile(
            r"@\s*(?:app|router|api)\.(get|post|put|patch|delete|head|options|trace)\s*"
            r"\(\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        "fastapi", "python", 1, 2,
    ),
    # Django urls.py: path("api/<int:pk>", view_fn) / re_path(r"...", view_fn)
    (
        "django_path",
        re.compile(
            r"\b(?:re_)?path\s*\(\s*[\"'r]?[\"']([^\"']+)[\"']\s*,\s*([\w.]+)",
        ),
        "django", "python", 0, 1,  # path group = 1; method = "ANY" placeholder
    ),
    # Express: app.get("/path", handler) / router.post("/path", handler)
    (
        "express_route",
        re.compile(
            r"\b(?:app|router)\.(get|post|put|patch|delete|head|options|all|use)\s*"
            r"\(\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        "express", "javascript", 1, 2,
    ),
    # NestJS: @Get("/path") / @Post("/path") class-method decorator
    (
        "nestjs_decorator",
        re.compile(
            r"@\s*(Get|Post|Put|Patch|Delete|Head|Options|All)\s*"
            r"\(\s*[\"']([^\"']+)[\"']",
        ),
        "nestjs", "typescript", 1, 2,
    ),
    # Rails routes.rb: get '/api/users', to: 'users#index' (simple form)
    (
        "rails_route",
        re.compile(
            r"\b(get|post|put|patch|delete|head|match)\s+[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        "rails", "ruby", 1, 2,
    ),
    # Spring (Java/Kotlin): @GetMapping("/path") / @RequestMapping("/path", method=...)
    (
        "spring_mapping",
        re.compile(
            r"@\s*(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*"
            r"\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"']",
        ),
        "spring", "java", 1, 2,
    ),
    # Go net/http: http.HandleFunc("/path", handler) / mux.HandleFunc(...)
    (
        "go_handlefunc",
        re.compile(
            r"\b\w*\.HandleFunc\s*\(\s*[\"']([^\"']+)[\"']",
        ),
        "go_net_http", "go", 0, 1,
    ),
)


# ---------------------------------------------------------------------------
# Pattern catalogue — Models
# ---------------------------------------------------------------------------


_MODEL_PATTERNS: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    # SQLAlchemy: class User(Base): / class Post(db.Model):
    (
        "sqlalchemy_class",
        re.compile(
            r"^\s*class\s+(\w+)\s*\(\s*(?:Base|db\.Model|DeclarativeBase|declarative_base\(\))",
            re.MULTILINE,
        ),
        "sqlalchemy", "python",
    ),
    # Django models: class User(models.Model):
    (
        "django_model",
        re.compile(
            r"^\s*class\s+(\w+)\s*\(\s*(?:models\.)?Model\b",
            re.MULTILINE,
        ),
        "django_orm", "python",
    ),
    # Pydantic v1/v2: class UserSchema(BaseModel):
    (
        "pydantic_model",
        re.compile(
            r"^\s*class\s+(\w+)\s*\(\s*(?:pydantic\.)?BaseModel\b",
            re.MULTILINE,
        ),
        "pydantic", "python",
    ),
    # Mongoose: const UserSchema = new mongoose.Schema({...})
    (
        "mongoose_schema",
        re.compile(
            r"\b(?:const|let|var)\s+(\w+)\s*=\s*new\s+(?:mongoose\.)?Schema\s*\(",
        ),
        "mongoose", "javascript",
    ),
    # Sequelize: const User = sequelize.define("User", {...})
    (
        "sequelize_define",
        re.compile(
            r"\b(?:const|let|var)\s+(\w+)\s*=\s*\w+\.define\s*\(\s*[\"']\w+[\"']",
        ),
        "sequelize", "javascript",
    ),
    # TypeORM: @Entity() class User { ... }
    (
        "typeorm_entity",
        re.compile(
            r"@\s*Entity\s*\([^)]*\)\s*(?:export\s+)?class\s+(\w+)",
        ),
        "typeorm", "typescript",
    ),
    # Rails AR: class User < ApplicationRecord
    (
        "rails_ar",
        re.compile(
            r"^\s*class\s+(\w+)\s*<\s*(?:ApplicationRecord|ActiveRecord::Base)",
            re.MULTILINE,
        ),
        "rails_ar", "ruby",
    ),
    # JPA / Hibernate: @Entity public class User { ... }
    (
        "jpa_entity",
        re.compile(
            r"@\s*Entity\b[^\n]*\n[^\n]*class\s+(\w+)",
        ),
        "jpa", "java",
    ),
)


# ---------------------------------------------------------------------------
# Pattern catalogue — DB queries
# ---------------------------------------------------------------------------


_DB_QUERY_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    # Raw SQL strings — captures any string literal containing SELECT /
    # INSERT / UPDATE / DELETE / CREATE / DROP keywords.
    (
        "raw_sql",
        re.compile(
            r"[\"'`](\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE)\b[^\"'`\n]{0,400})[\"'`]",
            re.IGNORECASE,
        ),
        "raw_sql",
    ),
    # SQLAlchemy: session.execute(text("SELECT ...")) or .filter(...)
    (
        "sqlalchemy_execute",
        re.compile(
            r"\.\s*(?:execute|query|filter|filter_by)\s*\(",
            re.IGNORECASE,
        ),
        "sqlalchemy_call",
    ),
    # Django ORM: User.objects.filter(...).get(...).create(...)
    (
        "django_orm_call",
        re.compile(
            r"\.objects\.(?:filter|get|create|update|delete|raw)\b",
        ),
        "django_orm_call",
    ),
    # Mongoose: User.find / User.findOne / User.aggregate
    (
        "mongoose_call",
        re.compile(
            r"\b\w+\.(?:find|findOne|aggregate|update|deleteOne|deleteMany|insertMany|insertOne)\s*\(",
        ),
        "mongoose_call",
    ),
)


# ---------------------------------------------------------------------------
# Pattern catalogue — External HTTP calls
# ---------------------------------------------------------------------------


_HTTP_CALL_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    # Python requests / httpx
    (
        "python_requests",
        re.compile(
            r"\brequests\.(get|post|put|patch|delete|head|options|request)\s*\(",
            re.IGNORECASE,
        ),
        "python_requests",
    ),
    (
        "python_httpx",
        re.compile(
            r"\bhttpx\.(get|post|put|patch|delete|head|options|request)\s*\(",
            re.IGNORECASE,
        ),
        "python_httpx",
    ),
    (
        "python_urllib",
        re.compile(
            r"\burllib(?:\.request)?\.urlopen\s*\(",
        ),
        "python_urllib",
    ),
    # Node.js fetch / axios
    (
        "javascript_fetch",
        re.compile(
            r"\bfetch\s*\(\s*[\"'`]([^\"'`]+)[\"'`]",
        ),
        "javascript_fetch",
    ),
    (
        "javascript_axios",
        re.compile(
            r"\baxios\.(?:get|post|put|patch|delete|head|options|request)\s*\(",
            re.IGNORECASE,
        ),
        "javascript_axios",
    ),
    # Go net/http
    (
        "go_http",
        re.compile(
            r"\bhttp\.(?:Get|Post|Put|Patch|Delete|Head|NewRequest)\s*\(",
        ),
        "go_http",
    ),
    # Java HttpClient
    (
        "java_httpclient",
        re.compile(
            r"\bHttpClient(?:\.newHttpClient\(\))?\.send\s*\(",
        ),
        "java_httpclient",
    ),
)


# ---------------------------------------------------------------------------
# Pattern catalogue — Auth boundaries
# ---------------------------------------------------------------------------


_AUTH_BOUNDARY_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    # Common Python decorators
    (
        "python_login_required",
        re.compile(
            r"@\s*(login_required|require_login|auth_required|authenticated|"
            r"requires_auth|jwt_required|token_required)\b",
        ),
        "python_decorator",
    ),
    # @permission_required / @user_passes_test (Django)
    (
        "django_permission",
        re.compile(
            r"@\s*(permission_required|user_passes_test|staff_member_required|"
            r"superuser_required)\s*\(",
        ),
        "django_decorator",
    ),
    # @requires_role / @has_role (custom RBAC)
    (
        "rbac_decorator",
        re.compile(
            r"@\s*(requires_role|has_role|requires_permission|has_permission|"
            r"role_required|admin_only|admin_required)\b",
            re.IGNORECASE,
        ),
        "rbac_decorator",
    ),
    # Express middleware: app.use(authMiddleware) / router.use(passport.authenticate(...))
    (
        "express_auth_middleware",
        re.compile(
            r"\b(?:app|router)\.use\s*\(\s*(\w+(?:Auth|auth|Authenticate|authenticate))\b",
        ),
        "express_middleware",
    ),
    # NestJS: @UseGuards(AuthGuard, RolesGuard)
    (
        "nestjs_useguards",
        re.compile(
            r"@\s*UseGuards\s*\(",
        ),
        "nestjs_decorator",
    ),
    # Spring Security: @PreAuthorize / @Secured / @RolesAllowed
    (
        "spring_security",
        re.compile(
            r"@\s*(PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b",
        ),
        "spring_security",
    ),
    # Rails: before_action :authenticate_user!
    (
        "rails_before_action",
        re.compile(
            r"\bbefore_action\s+:(?:authenticate_user!?|require_login|verify_authenticated|require_admin)\b",
        ),
        "rails_filter",
    ),
)


# ---------------------------------------------------------------------------
# File walk
# ---------------------------------------------------------------------------


def _walk_repo(
    root: Path,
    *,
    max_files: int,
    max_file_size: int,
) -> list[Path]:
    """Walk `root`, prune ignore dirs, return list of source files
    (capped at max_files)."""
    out: list[Path] = []
    if not root.exists():
        return out
    if root.is_file():
        # Allow scanning a single file too — useful for tests + agent
        # use.
        if root.suffix.lower() in _SOURCE_EXTENSIONS and root.stat().st_size <= max_file_size:
            return [root]
        return out
    try:
        for entry in _iter_files(root, max_files=max_files, max_file_size=max_file_size):
            out.append(entry)
            if len(out) >= max_files:
                break
    except OSError as e:
        logger.warning("repo walk failed: %s", e)
    return out


def _iter_files(
    root: Path, *, max_files: int, max_file_size: int,
):
    """Generator over source files, pruning ignore dirs in-place."""
    import os

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune in-place — modifies the dirnames list os.walk uses for recursion.
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS and not d.startswith(".")]
        for fname in filenames:
            if fname.startswith("."):
                continue
            path = Path(dirpath) / fname
            if path.suffix.lower() not in _SOURCE_EXTENSIONS:
                continue
            try:
                if path.is_symlink():
                    continue
                if path.stat().st_size > max_file_size:
                    continue
            except OSError:
                continue
            yield path


# ---------------------------------------------------------------------------
# Per-file extractors
# ---------------------------------------------------------------------------


def _extract_routes(text: str, file_path: str) -> list[dict[str, Any]]:
    """Extract HTTP route handlers from a single file."""
    out: list[dict[str, Any]] = []
    for label, pattern, framework, language, method_group, path_group in _ROUTE_PATTERNS:
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            try:
                if method_group == 0:
                    # No method group; default to ANY.
                    method = "ANY"
                    path_value = m.group(path_group)
                else:
                    method_raw = m.group(method_group) or "GET"
                    method = method_raw.strip().upper()
                    # Flask methods= captures: ["GET", "POST"]
                    if "," in method or "'" in method or '"' in method:
                        method = method.replace('"', "").replace("'", "")
                    path_value = m.group(path_group)
            except (IndexError, AttributeError):
                continue
            out.append({
                "framework": framework,
                "language": language,
                "method": method,
                "path": path_value,
                "file": file_path,
                "line": line,
                "match_label": label,
            })
    return out


def _extract_models(text: str, file_path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for label, pattern, framework, language in _MODEL_PATTERNS:
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            try:
                name = m.group(1)
            except (IndexError, AttributeError):
                continue
            out.append({
                "name": name,
                "framework": framework,
                "language": language,
                "file": file_path,
                "line": line,
                "match_label": label,
            })
    return out


def _extract_db_queries(text: str, file_path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for label, pattern, kind in _DB_QUERY_PATTERNS:
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            try:
                sample = m.group(1) if m.lastindex else m.group(0)
            except (IndexError, AttributeError):
                sample = m.group(0)
            out.append({
                "kind": kind,
                "sample": sample.strip()[:300],
                "file": file_path,
                "line": line,
                "match_label": label,
            })
    return out


def _extract_external_http_calls(text: str, file_path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for label, pattern, library in _HTTP_CALL_PATTERNS:
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            try:
                method = (m.group(1) if m.lastindex else "").upper() or "ANY"
            except (IndexError, AttributeError):
                method = "ANY"
            url_or_var = ""
            if m.lastindex and m.lastindex >= 2:
                try:
                    url_or_var = m.group(2)
                except (IndexError, AttributeError):
                    pass
            out.append({
                "library": library,
                "method": method,
                "url_or_var": url_or_var,
                "file": file_path,
                "line": line,
                "match_label": label,
            })
    return out


def _extract_auth_boundaries(text: str, file_path: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for label, pattern, kind in _AUTH_BOUNDARY_PATTERNS:
        for m in pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            try:
                marker = m.group(1) if m.lastindex else m.group(0)
            except (IndexError, AttributeError):
                marker = m.group(0)
            out.append({
                "kind": kind,
                "marker": marker,
                "file": file_path,
                "line": line,
                "match_label": label,
            })
    return out


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _write_code_map(repo_path: str, code_map: dict[str, Any]) -> Path | None:
    """Persist code_map.json. Validates against the handoff schema;
    emits handoff.shape_violation events on contract drift but never
    blocks the write."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    tracer = get_global_tracer()
    if tracer is None:
        return None

    try:
        from strix.agents.handoffs.code_map import (
            has_canonical_errors,
            validate_code_map,
            violations_to_dict_list,
        )

        violations = validate_code_map(code_map)
        if violations:
            violation_dicts = violations_to_dict_list(violations)
            is_canonical = not has_canonical_errors(violations)
            try:
                tracer._emit_event(
                    "handoff.shape_violation",
                    payload={
                        "artifact": "code_map.json",
                        "repo_path": repo_path,
                        "violations": violation_dicts,
                        "is_canonical": is_canonical,
                    },
                    status="warning" if is_canonical else "error",
                    source="strix.handoffs",
                )
            except Exception:  # noqa: BLE001
                logger.debug("handoff event emit failed", exc_info=True)
            if not is_canonical:
                logger.warning(
                    "code_map.json has canonical-contract errors: %s",
                    [v["code"] for v in violation_dicts if v["severity"] == "error"],
                )
    except Exception:  # noqa: BLE001
        logger.debug("code_map validation failed", exc_info=True)

    try:
        run_dir = tracer.get_run_dir()
        path = run_dir / "code_map.json"
        with path.open("w", encoding="utf-8") as f:
            json.dump(code_map, f, indent=2, ensure_ascii=False, default=str)
        return path
    except Exception:  # noqa: BLE001
        logger.warning("failed to write code_map.json", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Phase events
# ---------------------------------------------------------------------------


def _open_phase(focus: str) -> tuple[Any, str | None]:
    try:
        from strix.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer is None:
            return (None, None)
        phase_id = tracer.enter_phase(phase="recon", focus=focus)
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
    mitre_techniques=["T1592", "T1595"],
)
def build_code_map(
    repo_path: str,
    max_files: int = _DEFAULT_MAX_FILES,
    max_file_size: int = _DEFAULT_MAX_FILE_SIZE,
) -> dict[str, Any]:
    """Walk a repository and emit a structured `code_map.json`.

    §8.1 row 1 — the Observe → Decide handoff for code targets.
    Every downstream specialist (`secret-agent`, `dependency-agent`,
    `sast-agent`, taint, validator) reads from this artifact.

    Args:
        repo_path: filesystem path to the repository root (or to a
            single source file, for testing).
        max_files: hard cap on files scanned (default 5000).
        max_file_size: per-file byte cap (default 1 MiB; larger files
            are skipped).

    Effects:
        - Brackets the work in `phase.entered` / `phase.completed`
          (`recon`, focus=`code:<repo_basename>`).
        - Persists `code_map.json` to the run directory.
        - Validates against §8.0 handoff schema.

    Returns the structured code_map dict (also returned in
    `code_map`).
    """
    if not isinstance(repo_path, str) or not repo_path.strip():
        return {"success": False, "error": "repo_path required"}

    root = Path(repo_path).expanduser().resolve()
    if not root.exists():
        return {"success": False, "error": f"repo_path does not exist: {root}"}

    repo_name = root.name or str(root)
    tracer, phase_id = _open_phase(f"code:{repo_name}")

    files_scanned = 0
    file_errors: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    models: list[dict[str, Any]] = []
    db_queries: list[dict[str, Any]] = []
    external_http_calls: list[dict[str, Any]] = []
    auth_boundaries: list[dict[str, Any]] = []

    try:
        files = _walk_repo(root, max_files=max_files, max_file_size=max_file_size)
        for fp in files:
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError as e:
                file_errors.append({"file": str(fp), "error": str(e)})
                continue
            files_scanned += 1
            rel = str(fp.relative_to(root)) if root.is_dir() else str(fp)
            try:
                routes.extend(_extract_routes(text, rel))
                models.extend(_extract_models(text, rel))
                db_queries.extend(_extract_db_queries(text, rel))
                external_http_calls.extend(_extract_external_http_calls(text, rel))
                auth_boundaries.extend(_extract_auth_boundaries(text, rel))
            except Exception as e:  # noqa: BLE001
                file_errors.append({"file": rel, "error": f"extract_failed: {e}"})

        summary = {
            "files_scanned": files_scanned,
            "routes_discovered": len(routes),
            "models_discovered": len(models),
            "db_queries_discovered": len(db_queries),
            "external_http_calls_discovered": len(external_http_calls),
            "auth_boundaries_discovered": len(auth_boundaries),
            "file_errors": len(file_errors),
        }

        code_map: dict[str, Any] = {
            "schema_version": 1,
            "repo_path": str(root),
            "repo_name": repo_name,
            "generated_at": datetime.now(UTC).isoformat(),
            "phase_id": phase_id,
            "summary": summary,
            "routes": routes,
            "models": models,
            "db_queries": db_queries,
            "external_http_calls": external_http_calls,
            "auth_boundaries": auth_boundaries,
            "errors": file_errors,
        }

        path = _write_code_map(str(root), code_map)
        if path:
            code_map["code_map_path"] = str(path)

        return {
            "success": True,
            "repo_path": str(root),
            "repo_name": repo_name,
            "phase_id": phase_id,
            "code_map": code_map,
            "next_steps": _format_next_steps(code_map),
        }
    finally:
        _close_phase(tracer, phase_id, {"tool": _TOOL_NAME, "repo_path": str(root)})


def _format_next_steps(code_map: dict[str, Any]) -> list[str]:
    summary = code_map.get("summary") or {}
    routes_n = summary.get("routes_discovered", 0)
    auth_n = summary.get("auth_boundaries_discovered", 0)
    queries_n = summary.get("db_queries_discovered", 0)
    http_calls_n = summary.get("external_http_calls_discovered", 0)
    files_n = summary.get("files_scanned", 0)

    next_steps: list[str] = []
    if files_n == 0:
        next_steps.append(
            "Scanned 0 files — verify repo_path points at a source "
            "tree. The §8.1 specialist team has nothing to read."
        )
        return next_steps

    next_steps.append(
        f"Scanned {files_n} file(s); discovered {routes_n} route(s), "
        f"{queries_n} query/ORM call(s), {http_calls_n} external HTTP call(s), "
        f"{auth_n} auth-boundary marker(s). Spawn the §8.1 specialist team via "
        f"`spawn_code_specialist_team` to dispatch secret / dependency / "
        f"sast specialists."
    )
    if auth_n == 0 and routes_n > 0:
        next_steps.append(
            f"⚠ {routes_n} route(s) but ZERO auth-boundary markers detected. "
            f"Either auth lives in middleware not picked up by the regex "
            f"catalogue, OR auth is genuinely missing — the auth-attacker "
            f"specialist should investigate as a high-priority signal."
        )
    if queries_n > 0:
        next_steps.append(
            f"{queries_n} DB query/ORM call site(s) — pass to the SAST + "
            f"injection specialists for SQLi-shaped review."
        )
    if http_calls_n > 0:
        next_steps.append(
            f"{http_calls_n} external HTTP call site(s) — pass to the SSRF "
            f"specialist for SSRF-shaped review (URL string flow analysis)."
        )
    return next_steps
