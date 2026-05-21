import json
import logging
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from opentelemetry import trace
from opentelemetry.trace import SpanContext, SpanKind

from strix.config import Config
from strix.telemetry import posthog
from strix.telemetry.flags import is_otel_enabled
from strix.telemetry.utils import (
    TelemetrySanitizer,
    append_jsonl_record,
    bootstrap_otel,
    format_span_id,
    format_trace_id,
    get_events_write_lock,
)


# Stable finding-fingerprint algorithm (roadmap §11). Documented here as
# the contract; consumers should use this exact algorithm when building
# their own dedup. Bump _FINGERPRINT_VERSION when changing — never alter
# v1 silently, since downstream caches keyed on v1 fingerprints would
# silently mis-match.
#
# Algorithm:
#   normalize(cwe) + "|" + normalize(endpoint or file) + "|" + first_80_chars(normalize(title))
#   → sha256 → first 16 hex chars
#
# normalize: lowercase, strip whitespace at edges, collapse runs of internal
# whitespace to a single space. Empty inputs are tolerated (treated as "").
import hashlib as _hashlib
import re as _re_fingerprint

_FINGERPRINT_VERSION = 1
_WS_COLLAPSE = _re_fingerprint.compile(r"\s+")


def _empty_token_breakdown_summary() -> dict[str, Any]:
    """Empty result shape for `Tracer.token_breakdown_summary` —
    used when no `llm.token_breakdown` events have been emitted yet
    or events.jsonl is unreadable."""
    return {
        "schema_version": 1,
        "call_count": 0,
        "totals": {
            "system_tokens": 0,
            "agent_identity_tokens": 0,
            "conversation_tokens": 0,
            "total_input_tokens_estimated": 0,
            "measured_input_tokens": 0,
            "measured_output_tokens": 0,
            "measured_cached_tokens": 0,
            "measured_cost_usd": 0.0,
        },
        "component_fractions": {
            "system_fraction": 0.0,
            "agent_identity_fraction": 0.0,
            "conversation_fraction": 0.0,
        },
        "cache_hit_ratio_run": 0.0,
        "per_agent": {},
        "per_call_count": 0,
    }


def _fingerprint_normalize(s: str | None) -> str:
    if not s:
        return ""
    return _WS_COLLAPSE.sub(" ", s.strip().lower())


def compute_finding_fingerprint(
    *,
    title: str | None,
    cwe: str | None,
    endpoint: str | None = None,
    file: str | None = None,
) -> str:
    """Stable, deterministic fingerprint for a finding. Same inputs ⇒ same
    output, across processes / hosts / strix versions on the same algorithm
    version. Returns 16 lowercase hex characters."""
    title_part = _fingerprint_normalize(title)[:80]
    cwe_part = _fingerprint_normalize(cwe)
    location_part = _fingerprint_normalize(endpoint or file)
    payload = f"{cwe_part}|{location_part}|{title_part}".encode("utf-8")
    return _hashlib.sha256(payload).hexdigest()[:16]


# Map CWE → semantic category. Filled in for the categories most consumers
# bucket findings by; missing CWEs leave category unset (caller can supply
# explicitly via add_vulnerability_report's `category` parameter).
_CWE_TO_CATEGORY: dict[str, str] = {
    "CWE-22": "path_traversal",
    "CWE-78": "cmd_injection",
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-94": "cmd_injection",
    "CWE-200": "info_disclosure",
    "CWE-209": "info_disclosure",
    "CWE-269": "authz",
    "CWE-285": "authz",
    "CWE-287": "auth",
    "CWE-306": "misconfig",
    "CWE-319": "crypto",
    "CWE-326": "crypto",
    "CWE-327": "crypto",
    "CWE-347": "jwt",
    "CWE-352": "csrf",
    "CWE-434": "misconfig",
    "CWE-489": "misconfig",
    "CWE-502": "deserialization",
    "CWE-548": "misconfig",
    "CWE-601": "open_redirect",
    "CWE-611": "xxe",
    "CWE-639": "idor",
    "CWE-732": "misconfig",
    "CWE-798": "info_disclosure",
    "CWE-862": "authz",
    "CWE-863": "authz",
    "CWE-915": "mass_assignment",
    "CWE-918": "ssrf",
    "CWE-943": "sqli",
    "CWE-1104": "misconfig",
    "CWE-1278": "misconfig",
    "CWE-1390": "subdomain_takeover",
}


def _infer_category_from_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    key = cwe.strip().upper()
    if not key.startswith("CWE-") and key.isdigit():
        key = f"CWE-{key}"
    return _CWE_TO_CATEGORY.get(key)


try:
    from traceloop.sdk import Traceloop
except ImportError:  # pragma: no cover - exercised when dependency is absent
    Traceloop = None  # type: ignore[assignment,unused-ignore]


logger = logging.getLogger(__name__)

_global_tracer: Optional["Tracer"] = None

_OTEL_BOOTSTRAP_LOCK = threading.Lock()
_OTEL_BOOTSTRAPPED = False
_OTEL_REMOTE_ENABLED = False


_VALID_KILL_CHAIN_STEP_TYPES: tuple[str, ...] = (
    "recon",
    "discovery",
    "exploitation",
    "escalation",
    "lateral_movement",
    "impact",
    "validation",
)


def _normalize_kill_chain(raw: Any) -> list[dict[str, Any]] | None:
    """Normalize the agent-supplied kill_chain into a list of step dicts.

    Each output step has stable keys: `step_number` (1-based int),
    `type` (one of _VALID_KILL_CHAIN_STEP_TYPES, defaults to "discovery"),
    and any of `description` / `tool` / `evidence` that were supplied.

    Tolerant of malformed input: drops non-dict entries, fills missing
    step numbers, and clamps unknown types to "discovery".
    """
    if not isinstance(raw, list) or not raw:
        return None
    out: list[dict[str, Any]] = []
    for idx, entry in enumerate(raw, start=1):
        if not isinstance(entry, dict):
            continue
        step: dict[str, Any] = {}
        # step_number — accept int, str-of-int, or fall back to position.
        raw_num = entry.get("step_number") or entry.get("step") or entry.get("number")
        try:
            step["step_number"] = int(raw_num) if raw_num is not None else idx
        except (TypeError, ValueError):
            step["step_number"] = idx
        # type — clamp to known set so consumers can render reliably.
        raw_type = (entry.get("type") or "").strip().lower()
        step["type"] = raw_type if raw_type in _VALID_KILL_CHAIN_STEP_TYPES else "discovery"
        for field in ("description", "tool", "evidence", "agent_id"):
            value = entry.get(field)
            if isinstance(value, str) and value.strip():
                step[field] = value.strip()
        # A step with nothing but a number isn't useful.
        if any(k in step for k in ("description", "tool", "evidence")):
            out.append(step)
    return out or None


_VALID_FIX_TIME_ESTIMATES: tuple[str, ...] = ("5min", "1hr", "1day", "1week+")


def _normalize_fix_time_estimate(raw: Any) -> str | None:
    """Coerce a fix_time_estimate value into the canonical bucket set.

    Tolerant of common variants (`'5 min'`, `'5 minutes'`, `'1 hour'`,
    `'1 day'`, `'1 week'`, etc.) — any longer-than-week input clamps to
    `1week+`.
    """
    if not isinstance(raw, str):
        return None
    normalized = raw.strip().lower().replace(" ", "")
    if normalized in _VALID_FIX_TIME_ESTIMATES:
        return normalized
    if normalized in ("5min", "5minutes", "5m", "fewminutes", "minutes"):
        return "5min"
    if normalized in ("1hour", "1hr", "hour", "fewhours", "hours"):
        return "1hr"
    if normalized in ("1day", "day", "1d", "fewdays"):
        return "1day"
    if normalized in ("1week", "1w", "week", "1week+", "manydays", "weeks"):
        return "1week+"
    return None


def _derive_priority_label(
    severity: str | None,
    *,
    is_kev: bool,
    fix_time_estimate: str | None,
) -> str:
    """Auto-derive a user-time-aware priority distinct from technical severity.

    Precedence:
    - critical OR KEV → fix-now
    - high → fix-this-week
    - medium → plan-a-fix
    - low / info → informational
    - fix_time_estimate of `5min` or `1hr` bumps the result up one tier
      (it's cheap to fix; do it now rather than queue it).
    """
    sev = (severity or "").lower().strip()
    if sev == "critical" or is_kev:
        return "fix-now"
    base = {
        "high": "fix-this-week",
        "medium": "plan-a-fix",
        "low": "informational",
        "info": "informational",
    }.get(sev, "informational")
    if fix_time_estimate in ("5min", "1hr"):
        bump = {
            "fix-this-week": "fix-now",
            "plan-a-fix": "fix-this-week",
            "informational": "plan-a-fix",
        }
        return bump.get(base, base)
    return base


def _derive_exploitation_in_wild_plain(report: dict[str, Any]) -> str | None:
    """Plain-English summary of KEV / actively-exploited status.

    Reads existing threat-intel enrichment (set by `threat_intel.enrich`)
    and renders the same signal in language a non-engineer can read.
    """
    if report.get("kev"):
        cve = report.get("cve")
        suffix = f" (CVE {cve})" if cve else ""
        return (
            "This is being actively attacked in the real world today"
            f"{suffix}. CISA has it in their Known Exploited Vulnerabilities "
            "catalog — fix this before tackling lower-risk findings."
        )
    return None


def _emit_kg_auto_for_finding(report: dict[str, Any]) -> None:
    """Auto-populate the KG with `Vuln + Surface + AFFECTS` for any
    finding that carries a URL endpoint. Closes the KG-integration
    gaps surfaced in the post-#263 audit: scanners that emit findings
    via `tracer.add_vulnerability_report` (DAST specialists, nuclei,
    misconfig, threat-intel) now get a default KG triple without
    having to call `record_finding_in_kg` themselves.

    Scanners that need extra Vuln-node props (SQLi's `db_engine`,
    XSS's `detection_kind`) still call `record_finding_in_kg`
    directly — that helper is dedup-cached on the Surface side
    so the auto-emit doesn't create duplicate Surface nodes.

    Fail-open: any error logs + continues. Never raises.

    Skips emission when:
      * `endpoint` not set (code-location-only findings — SAST /
        IaC — need a separate adapter that emits to a different
        Surface shape; tracked as a follow-up).
      * `verification_status` is `pattern_match` with no signal
        beyond signature match (avoid populating the graph with
        low-confidence noise).
    """
    try:
        endpoint = report.get("endpoint") or report.get("target") or ""
        if not isinstance(endpoint, str) or not endpoint.strip():
            return
        # Only URLs go through the URL-shaped Surface path. Repo-
        # path / code-location targets need the code-location
        # Surface adapter (separate follow-up).
        if not endpoint.startswith(("http://", "https://")):
            return

        from strix.agents.kg_emit import record_finding_in_kg

        record_finding_in_kg(
            finding_id=report.get("id"),
            url=endpoint,
            param=report.get("param", "") or "",
            cwe=report.get("cwe") or "CWE-1390",
            severity=report.get("severity") or "medium",
            category=report.get("category") or "",
            method=report.get("method") or "GET",
            detection_kind=report.get("detection_kind") or "",
            db_engine=report.get("db_engine"),
            confidence=report.get("confidence"),
        )
    except Exception:  # noqa: BLE001
        logger.debug("tracer: KG auto-emit failed", exc_info=True)


def _normalize_target_for_events(raw: Any) -> dict[str, str] | None:
    """Coerce a scan_config target entry into a {value, type?} dict.

    Accepts the three shapes the codebase uses in the wild:
    - dict with `value` + `type` (telemetry/tracer test fixtures)
    - dict with `details` + `type` (CLI-built `targets_info`)
    - bare string

    Returns None when no usable value can be extracted.
    """
    if isinstance(raw, str):
        v = raw.strip()
        return {"value": v} if v else None
    if not isinstance(raw, dict):
        return None
    target_type = raw.get("type") or raw.get("target_type")
    # Direct value field takes precedence (test fixtures use this shape).
    value = raw.get("value") or raw.get("target") or raw.get("original")
    if not value:
        # CLI shape: details holds the canonical url/path.
        details = raw.get("details") or {}
        if isinstance(details, dict):
            value = (
                details.get("target_url")
                or details.get("target_repo")
                or details.get("target_ip")
                or details.get("target_path")
            )
    if not value:
        return None
    out: dict[str, str] = {"value": str(value)}
    if target_type:
        out["type"] = str(target_type)
    return out


def _build_summary_text(
    *,
    targets: list[dict[str, str]],
    duration_seconds: float,
    findings_total: int,
    by_severity: dict[str, int],
    by_category: dict[str, int],
    check_summary: dict[str, Any],
) -> str:
    """One-paragraph plain-English headline of how the scan went.

    Roadmap §1. Designed for direct rendering in CI exit logs, dashboard
    cards, and Slack notifications. Avoids markdown so it survives any
    plain-text channel.
    """
    parts: list[str] = []

    # Targets opener.
    if targets:
        if len(targets) == 1:
            t = targets[0]
            label = f"{t['value']}" + (f" ({t.get('type')})" if t.get("type") else "")
            parts.append(f"Scanned {label}")
        else:
            parts.append(f"Scanned {len(targets)} targets")
    else:
        parts.append("Scan completed")

    # Duration.
    if duration_seconds >= 60:
        mins = duration_seconds / 60
        parts.append(f"in {mins:.1f}m")
    elif duration_seconds > 0:
        parts.append(f"in {duration_seconds:.0f}s")

    # Findings.
    if findings_total == 0:
        parts.append("with no findings")
    else:
        sev_pieces: list[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_severity.get(sev) or by_severity.get(sev.upper())
            if count:
                sev_pieces.append(f"{count} {sev}")
        sev_str = ", ".join(sev_pieces) if sev_pieces else f"{findings_total} total"
        parts.append(f"with {findings_total} finding(s): {sev_str}")

    # Top categories — most-hit category names, capped at 3.
    if by_category:
        top_cats = sorted(by_category.items(), key=lambda kv: kv[1], reverse=True)[:3]
        cat_str = ", ".join(c for c, _ in top_cats)
        parts.append(f"primarily in {cat_str}")

    # Negative-coverage signal (so the summary is honest about what was
    # checked even when no findings landed).
    by_result = (check_summary or {}).get("by_result") or {}
    not_vuln = by_result.get("not_vulnerable", 0)
    inconclusive = by_result.get("inconclusive", 0)
    total_checks = (check_summary or {}).get("total", 0)
    if total_checks:
        parts.append(
            f"{total_checks} check(s) ran ({not_vuln} clean, {inconclusive} inconclusive)"
        )

    return "; ".join(parts) + "."


def get_global_tracer() -> Optional["Tracer"]:
    return _global_tracer


def set_global_tracer(tracer: "Tracer") -> None:
    global _global_tracer  # noqa: PLW0603
    _global_tracer = tracer


class Tracer:
    def __init__(self, run_name: str | None = None):
        self.run_name = run_name
        self.run_id = run_name or f"run-{uuid4().hex[:8]}"
        self.start_time = datetime.now(UTC).isoformat()
        self.end_time: str | None = None

        self.agents: dict[str, dict[str, Any]] = {}
        self.tool_executions: dict[int, dict[str, Any]] = {}
        self.chat_messages: list[dict[str, Any]] = []
        self.streaming_content: dict[str, str] = {}
        self.interrupted_content: dict[str, str] = {}

        self.vulnerability_reports: list[dict[str, Any]] = []
        self.final_scan_result: str | None = None

        # engine-wishlist §6 — `STRIX_PROJECT_ID` (or `--project-id`)
        # stamped onto every emitted artefact (findings, discovered
        # assets, run_meta) so the wrapper's cross-scan dedup ledger
        # can group N targets in a project under one finding row
        # instead of N. Engine doesn't dedup — wrapper does.
        # `set_scan_config` overrides this when scan_config carries
        # an explicit `project_id`.
        _env_pid = os.environ.get("STRIX_PROJECT_ID", "").strip()
        self._project_id: str | None = _env_pid or None

        # engine-wishlist §4 — accumulator for assets discovered
        # during the scan (cloud-attack-paths discovery, future
        # researcher recon). Dumped to `assets.discovered.jsonl`
        # at run-end. Stored as raw dicts (the
        # `DiscoveredAsset.to_dict()` shape) so the tracer doesn't
        # import the dataclass.
        self.discovered_assets: list[dict[str, Any]] = []

        # engine-wishlist §8 — accumulator for knowledge-graph
        # deltas (add_node / add_edge rows from the engine's
        # internal CloudGraph). Producers append converted dicts
        # via `kg_delta.from_cloud_graph()`; finalisation flushes
        # to `kg_delta.jsonl` so the wrapper's KG store can union
        # graph state across all scans in a project.
        self.kg_node_deltas: list[dict[str, Any]] = []
        self.kg_edge_deltas: list[dict[str, Any]] = []

        # Phase + check tracking (roadmap §1).
        # `_open_phases` keyed by phase_id; entries are popped on complete_phase.
        # `_open_checks` keyed by check_id; entries are popped on complete_check.
        # `_completed_checks` accumulates the `check.completed` payloads so the
        # end-of-run summary can aggregate negative-coverage assertions.
        self._open_phases: dict[str, dict[str, Any]] = {}
        self._open_checks: dict[str, dict[str, Any]] = {}
        self._completed_checks: list[dict[str, Any]] = []

        # Per-target observability. `_targets_started` is keyed by target_id
        # (e.g. "target-0001") and stores the value/type pair so we can emit
        # a matching `target.completed` event per target at run-end with a
        # rollup of findings + checks scoped to that target.
        self._targets_started: dict[str, dict[str, Any]] = {}
        self._targets_completed_emitted = False

        # Roadmap §16 PR #127 — cryptographically-signed audit trail.
        # Each event gets stamped with `prev_event_hash` + `event_hash`
        # forming a hash chain; the terminal hash is signed at run-end
        # if STRIX_SIGNING_KEY / STRIX_SIGNING_CMD is configured.
        from strix.telemetry.audit_trail import GENESIS_HASH

        self._last_event_hash: str = GENESIS_HASH
        self._event_count: int = 0

        self.scan_results: dict[str, Any] | None = None
        self.scan_config: dict[str, Any] | None = None
        self.run_metadata: dict[str, Any] = {
            "run_id": self.run_id,
            "run_name": self.run_name,
            "start_time": self.start_time,
            "end_time": None,
            "targets": [],
            "status": "running",
        }
        self._run_dir: Path | None = None
        self._events_file_path: Path | None = None
        self._next_execution_id = 1
        self._next_message_id = 1
        self._saved_vuln_ids: set[str] = set()
        self._run_completed_emitted = False
        self._telemetry_enabled = is_otel_enabled()
        self._sanitizer = TelemetrySanitizer()

        self._otel_tracer: Any = None
        self._remote_export_enabled = False

        self.caido_url: str | None = None
        self.vulnerability_found_callback: Callable[[dict[str, Any]], None] | None = None

        self._setup_telemetry()
        self._emit_run_started_event()

    @property
    def events_file_path(self) -> Path:
        if self._events_file_path is None:
            self._events_file_path = self.get_run_dir() / "events.jsonl"
        return self._events_file_path

    def _active_events_file_path(self) -> Path:
        active = get_global_tracer()
        if active and active._events_file_path is not None:
            return active._events_file_path
        return self.events_file_path

    def _get_events_write_lock(self, output_path: Path | None = None) -> threading.Lock:
        path = output_path or self.events_file_path
        return get_events_write_lock(path)

    def _active_run_metadata(self) -> dict[str, Any]:
        active = get_global_tracer()
        if active:
            return active.run_metadata
        return self.run_metadata

    def _setup_telemetry(self) -> None:
        global _OTEL_BOOTSTRAPPED, _OTEL_REMOTE_ENABLED

        if not self._telemetry_enabled:
            self._otel_tracer = None
            self._remote_export_enabled = False
            return

        run_dir = self.get_run_dir()
        self._events_file_path = run_dir / "events.jsonl"
        base_url = (Config.get("traceloop_base_url") or "").strip()
        api_key = (Config.get("traceloop_api_key") or "").strip()
        headers_raw = Config.get("traceloop_headers") or ""

        (
            self._otel_tracer,
            self._remote_export_enabled,
            _OTEL_BOOTSTRAPPED,
            _OTEL_REMOTE_ENABLED,
        ) = bootstrap_otel(
            bootstrapped=_OTEL_BOOTSTRAPPED,
            remote_enabled_state=_OTEL_REMOTE_ENABLED,
            bootstrap_lock=_OTEL_BOOTSTRAP_LOCK,
            traceloop=Traceloop,
            base_url=base_url,
            api_key=api_key,
            headers_raw=headers_raw,
            output_path_getter=self._active_events_file_path,
            run_metadata_getter=self._active_run_metadata,
            sanitizer=self._sanitize_data,
            write_lock_getter=self._get_events_write_lock,
            tracer_name="strix.telemetry.tracer",
        )

    def _set_association_properties(self, properties: dict[str, Any]) -> None:
        if Traceloop is None:
            return
        sanitized = self._sanitize_data(properties)
        try:
            Traceloop.set_association_properties(sanitized)
        except Exception:  # noqa: BLE001
            logger.debug("Failed to set Traceloop association properties")

    def _sanitize_data(self, data: Any, key_hint: str | None = None) -> Any:
        return self._sanitizer.sanitize(data, key_hint=key_hint)

    def _append_event_record(self, record: dict[str, Any]) -> None:
        # Roadmap §16 PR #127 — stamp each event with chain hashes
        # BEFORE write so the on-disk record carries the chain links.
        # Best-effort — any failure falls back to writing the unchained
        # record so observability doesn't depend on the audit-trail
        # subsystem being healthy.
        try:
            from strix.telemetry.audit_trail import stamp_event_record

            stamp_event_record(record, prev_event_hash=self._last_event_hash)
            self._last_event_hash = record.get("event_hash") or self._last_event_hash
            self._event_count += 1
        except Exception:  # noqa: BLE001
            logger.debug("audit-chain stamping failed", exc_info=True)

        try:
            append_jsonl_record(self.events_file_path, record)
        except OSError:
            logger.exception("Failed to append JSONL event record")

    def _enrich_actor(self, actor: dict[str, Any] | None) -> dict[str, Any] | None:
        if not actor:
            return None

        enriched = dict(actor)
        if "agent_name" in enriched:
            return enriched

        agent_id = enriched.get("agent_id")
        if not isinstance(agent_id, str):
            return enriched

        agent_data = self.agents.get(agent_id, {})
        agent_name = agent_data.get("name")
        if isinstance(agent_name, str) and agent_name:
            enriched["agent_name"] = agent_name

        return enriched

    def _emit_event(
        self,
        event_type: str,
        actor: dict[str, Any] | None = None,
        payload: Any | None = None,
        status: str | None = None,
        error: Any | None = None,
        source: str = "strix.tracer",
        include_run_metadata: bool = False,
    ) -> None:
        if not self._telemetry_enabled:
            return

        enriched_actor = self._enrich_actor(actor)
        sanitized_actor = self._sanitize_data(enriched_actor) if enriched_actor else None
        sanitized_payload = self._sanitize_data(payload) if payload is not None else None
        sanitized_error = self._sanitize_data(error) if error is not None else None

        trace_id: str | None = None
        span_id: str | None = None
        parent_span_id: str | None = None

        current_context = trace.get_current_span().get_span_context()
        if isinstance(current_context, SpanContext) and current_context.is_valid:
            parent_span_id = format_span_id(current_context.span_id)

        if self._otel_tracer is not None:
            try:
                with self._otel_tracer.start_as_current_span(
                    f"strix.{event_type}",
                    kind=SpanKind.INTERNAL,
                ) as span:
                    span_context = span.get_span_context()
                    trace_id = format_trace_id(span_context.trace_id)
                    span_id = format_span_id(span_context.span_id)

                    span.set_attribute("strix.event_type", event_type)
                    span.set_attribute("strix.source", source)
                    span.set_attribute("strix.run_id", self.run_id)
                    span.set_attribute("strix.run_name", self.run_name or "")

                    if status:
                        span.set_attribute("strix.status", status)
                    if sanitized_actor is not None:
                        span.set_attribute(
                            "strix.actor",
                            json.dumps(sanitized_actor, ensure_ascii=False),
                        )
                    if sanitized_payload is not None:
                        span.set_attribute(
                            "strix.payload",
                            json.dumps(sanitized_payload, ensure_ascii=False),
                        )
                    if sanitized_error is not None:
                        span.set_attribute(
                            "strix.error",
                            json.dumps(sanitized_error, ensure_ascii=False),
                        )
            except Exception:  # noqa: BLE001
                logger.debug("Failed to create OTEL span for event type '%s'", event_type)

        if trace_id is None:
            trace_id = format_trace_id(uuid4().int & ((1 << 128) - 1)) or uuid4().hex
        if span_id is None:
            span_id = format_span_id(uuid4().int & ((1 << 64) - 1)) or uuid4().hex[:16]

        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            "run_id": self.run_id,
            "trace_id": trace_id,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "actor": sanitized_actor,
            "payload": sanitized_payload,
            "status": status,
            "error": sanitized_error,
            "source": source,
        }
        if include_run_metadata:
            record["run_metadata"] = self._sanitize_data(self.run_metadata)
        self._append_event_record(record)

    def set_run_name(self, run_name: str) -> None:
        self.run_name = run_name
        self.run_id = run_name
        self.run_metadata["run_name"] = run_name
        self.run_metadata["run_id"] = run_name
        self._run_dir = None
        self._events_file_path = None
        self._run_completed_emitted = False
        self._targets_started = {}
        self._targets_completed_emitted = False
        self._set_association_properties({"run_id": self.run_id, "run_name": self.run_name or ""})
        self._emit_run_started_event()

    def _emit_run_started_event(self) -> None:
        if not self._telemetry_enabled:
            return

        self._emit_event(
            "run.started",
            payload={
                "run_name": self.run_name,
                "start_time": self.start_time,
                "local_jsonl_path": str(self.events_file_path),
                "remote_export_enabled": self._remote_export_enabled,
            },
            status="running",
            include_run_metadata=True,
        )

    def build_run_summary(self) -> dict[str, Any]:
        """Assemble the run-summary payload from final tracer state.

        Roadmap §1. Headline answer for "how did the scan go" — consumable
        by CI logs, dashboard cards, and Slack notifications without
        re-parsing the markdown report.

        Always-present fields:
        - schema_version, run_id, run_name, duration_seconds
        - targets: [{value, type}, ...] (from scan_config when available)
        - findings_summary: {total, by_severity, by_category}
        - top_findings: up to 5 findings sorted by severity
        - checks: get_check_summary() output (may be empty when no
          deterministic check events were emitted)
        - summary_text: a short plain-English headline
        """
        # Targets — pull from scan_config (set by `set_scan_config`).
        targets: list[dict[str, str]] = []
        config = self.scan_config or {}
        for raw in (config.get("targets") or []):
            normalized = _normalize_target_for_events(raw)
            if normalized is not None:
                targets.append(normalized)

        # Findings rollup.
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for r in self.vulnerability_reports:
            sev = (r.get("severity") or "unknown").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = (r.get("category") or "uncategorized").lower()
            by_category[cat] = by_category.get(cat, 0) + 1

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            self.vulnerability_reports,
            key=lambda r: (severity_order.get((r.get("severity") or "").lower(), 5), r.get("timestamp", "")),
        )
        top_findings = [
            {
                "id": r.get("id"),
                "title": r.get("title"),
                "severity": r.get("severity"),
                "category": r.get("category"),
                "cwe": r.get("cwe"),
                "endpoint": r.get("endpoint"),
                # Roadmap §11 non-tech-output fields surfaced on the
                # wrapper's dashboard card. Optional — only present when
                # the agent populated them.
                "description_plain": r.get("description_plain"),
                "business_impact_plain": r.get("business_impact_plain"),
                "recommended_action": r.get("recommended_action"),
                "fix_time_estimate": r.get("fix_time_estimate"),
                "priority_label": r.get("priority_label"),
                "exploitation_in_wild_plain": r.get("exploitation_in_wild_plain"),
            }
            for r in sorted_findings[:5]
        ]

        check_summary = self.get_check_summary()
        duration = self._calculate_duration()
        summary_text = _build_summary_text(
            targets=targets,
            duration_seconds=duration,
            findings_total=len(self.vulnerability_reports),
            by_severity=by_severity,
            by_category=by_category,
            check_summary=check_summary,
        )

        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "run_name": self.run_name,
            "duration_seconds": duration,
            "targets": targets,
            "findings_summary": {
                "total": len(self.vulnerability_reports),
                "by_severity": by_severity,
                "by_category": by_category,
            },
            "top_findings": top_findings,
            "checks": check_summary,
            "summary_text": summary_text,
        }

    def build_target_rollup(self, target_value: str) -> dict[str, Any]:
        """Per-target slice of findings + checks for the target.completed payload.

        Findings are matched against `target_value` via the report's `target`
        field. Checks are matched against `surface`. Both fields are
        already lowercased by upstream emission paths.
        """
        target_lower = (target_value or "").lower()
        per_target_findings: list[dict[str, Any]] = []
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for r in self.vulnerability_reports:
            r_target = (r.get("target") or "").lower()
            if r_target != target_lower:
                # Treat substring matches against url-encoded targets as a
                # weaker signal — only count when the target value is at
                # least an exact prefix/suffix match. Belt-and-braces; in
                # practice the recon tools all set `target` to the apex.
                if not r_target or target_lower not in r_target:
                    continue
            per_target_findings.append(r)
            sev = (r.get("severity") or "unknown").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = (r.get("category") or "uncategorized").lower()
            by_category[cat] = by_category.get(cat, 0) + 1

        target_check_count = 0
        target_check_categories: dict[str, int] = {}
        for c in self._completed_checks:
            surface = (c.get("surface") or "").lower()
            if not surface:
                continue
            if surface != target_lower and target_lower not in surface:
                continue
            target_check_count += 1
            cat = c.get("category") or "uncategorized"
            target_check_categories[cat] = target_check_categories.get(cat, 0) + 1

        return {
            "findings": {
                "total": len(per_target_findings),
                "by_severity": by_severity,
                "by_category": by_category,
            },
            "checks": {
                "total": target_check_count,
                "by_category": target_check_categories,
            },
        }

    def _emit_target_completed_events(self) -> None:
        """One target.completed event per target previously started.

        Idempotent — guarded by `_targets_completed_emitted` so a repeated
        save_run_data(mark_complete=True) doesn't double-emit. Roadmap §1.
        """
        if self._targets_completed_emitted:
            return
        if not self._telemetry_enabled:
            self._targets_completed_emitted = True
            return
        for target_id, info in self._targets_started.items():
            rollup = self.build_target_rollup(info["value"])
            self._emit_event(
                "target.completed",
                payload={
                    "target_id": target_id,
                    "value": info["value"],
                    "type": info.get("type"),
                    **rollup,
                },
                status="completed",
                source="strix.run",
            )
        self._targets_completed_emitted = True

    def _emit_run_summary_event(self, payload: dict[str, Any] | None = None) -> None:
        """Emit the run.summary event. Pass `payload` to skip rebuild
        when the caller already has the dict (e.g. when persisting
        `run_summary.json` alongside)."""
        if not self._telemetry_enabled:
            return
        self._emit_event(
            "run.summary",
            payload=payload if payload is not None else self.build_run_summary(),
            status="completed",
            source="strix.run",
            include_run_metadata=True,
        )

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            runs_dir = Path.cwd() / "strix_runs"
            runs_dir.mkdir(exist_ok=True)

            run_dir_name = self.run_name if self.run_name else self.run_id
            self._run_dir = runs_dir / run_dir_name
            self._run_dir.mkdir(exist_ok=True)

        return self._run_dir

    def add_vulnerability_report(  # noqa: PLR0912, PLR0913
        self,
        title: str,
        severity: str,
        description: str | None = None,
        impact: str | None = None,
        target: str | None = None,
        technical_analysis: str | None = None,
        poc_description: str | None = None,
        poc_script_code: str | None = None,
        remediation_steps: str | None = None,
        cvss: float | None = None,
        cvss_breakdown: dict[str, str] | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        cve: str | None = None,
        cwe: str | None = None,
        code_locations: list[dict[str, Any]] | None = None,
        category: str | None = None,
        verification_status: str | None = None,
        kill_chain: list[dict[str, Any]] | None = None,
        description_plain: str | None = None,
        business_impact_plain: str | None = None,
        recommended_action: str | None = None,
        fix_time_estimate: str | None = None,
        # Roadmap §12 / §18-row-4 — finding-quality signals for the
        # RLHF FP feedback loop and auditor-grade explainability.
        confidence: float | None = None,
        reasoning_trace: list[str] | str | None = None,
        counter_proof: dict[str, Any] | None = None,
        # Depth-of-attack — set when verification_status is `exploited`
        # to point at the captured proof-of-impact artifact (cookie,
        # dumped row, IMDS blob, captured flag). Path is relative to
        # the run dir; the scanner is responsible for writing the
        # file before emitting the finding. Enforced by
        # `validate_canonical_finding`.
        proof_artifact_path: str | None = None,
        # Depth-of-attack — chain of finding IDs going back to the
        # root exploit that the post-exploit pivot orchestrator
        # walked to land on this finding. Length-1 list means the
        # immediate parent only; deeper lists encode the full
        # ancestry. Empty / None on root findings (those NOT
        # produced by `pivot_orchestrator.run_pivot_chain`).
        pivot_chain_ancestors: list[str] | None = None,
        # Roadmap §16 — IaC / container rule ID that produced this
        # finding (e.g. `K8S_PRIVILEGED_CONTAINER`,
        # `dockerfile-user-root`). Compliance enrichment uses this
        # to derive CIS Benchmark control mappings that CWE alone
        # is too coarse to pin down. Optional — SAST / DAST findings
        # without a rule_id stay CWE-driven.
        rule_id: str | None = None,
        # V3-2 — finding-discovery provenance. When set to
        # "deterministic_specialist", the verification pipeline
        # auto-registers + records evidence + advances the finding
        # toward VERIFIED in quick / initial scan modes (skipping
        # the LLM verifier round-trip). When set to "ai_specialist"
        # or left None, the finding flows through the normal
        # verifier path — the agent has to call
        # `advance_verification_stage` itself.
        # Source tool name (e.g. "scan_sqli") is captured as the
        # evidence's `tool` field for audit.
        discovery_method: str | None = None,
        discovery_source_tool: str | None = None,
    ) -> str:
        report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

        # Auto-infer category from CWE if not explicitly provided. Keeps the
        # field populated even when older agent prompts don't supply it.
        if not category and cwe:
            category = _infer_category_from_cwe(cwe)

        # verification_status defaults to "verified" when a working PoC script
        # was supplied (the agent ran an exploit). Otherwise "inconclusive" —
        # the agent saw evidence but didn't confirm via execution. The agent
        # can override either default by passing the field explicitly.
        if not verification_status:
            verification_status = "verified" if poc_script_code else "inconclusive"

        report: dict[str, Any] = {
            "id": report_id,
            "title": title.strip(),
            "severity": severity.lower().strip(),
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "verification_status": verification_status.strip().lower(),
        }
        # engine-wishlist §6 — stamp project_id on every finding so
        # the wrapper's cross-scan dedup ledger can group identical
        # findings across N targets within one project.
        if self._project_id:
            report["project_id"] = self._project_id
        if category:
            report["category"] = category.strip().lower()

        if description:
            report["description"] = description.strip()
        if impact:
            report["impact"] = impact.strip()
        if target:
            report["target"] = target.strip()
        if technical_analysis:
            report["technical_analysis"] = technical_analysis.strip()
        if poc_description:
            report["poc_description"] = poc_description.strip()
        if poc_script_code:
            report["poc_script_code"] = poc_script_code.strip()
        if remediation_steps:
            report["remediation_steps"] = remediation_steps.strip()
        if cvss is not None:
            report["cvss"] = cvss
        if cvss_breakdown:
            report["cvss_breakdown"] = cvss_breakdown
        if endpoint:
            report["endpoint"] = endpoint.strip()
        if method:
            report["method"] = method.strip()
        if cve:
            report["cve"] = cve.strip()
        if cwe:
            report["cwe"] = cwe.strip()
        if isinstance(rule_id, str) and rule_id.strip():
            report["rule_id"] = rule_id.strip()

        # MA-S2 P0-CVS-A — EPSS enrichment on every emitted
        # finding. The block is ALWAYS present (per the MA-S2
        # attestation discipline that "we tried" must be
        # explicit). When no CVE is attached / cache is stale /
        # cache is unavailable, the `reason` field carries the
        # explanation; the score is null. Best-effort: failures
        # in the resolver fall through to a `cache_unavailable`
        # block; the finding still lands.
        try:
            from strix.llm.epss_enrichment import resolve_epss_block
            report["epss"] = resolve_epss_block(cve=cve)
        except Exception as e:  # noqa: BLE001
            logger.debug("epss enrichment failed: %s", e)
            report["epss"] = {
                "score": None,
                "percentile": None,
                "last_updated": None,
                "reason": "cache_unavailable",
            }

        # iter-21.1 — CISA KEV enrichment on every emitted finding.
        # Same attestation discipline as EPSS: block is always
        # present, `reason` carries the explanation when listing
        # is missing. Mirrors `epss_enrichment.resolve_epss_block`.
        # When `kev.listed=True`, severity gets auto-promoted to
        # critical via `maybe_promote_severity` (and the
        # promotion is recorded in reasoning_trace below). This
        # unifies the KEV severity-bump logic that previously
        # lived ad-hoc inside `sca/tools.py` +
        # `container_image/scan_container_image.py` but was
        # silently absent from `nuclei_runner` + custom SAST
        # paths.
        try:
            from strix.llm.kev_enrichment import resolve_kev_block
            report["kev_block"] = resolve_kev_block(cve=cve)
        except Exception as e:  # noqa: BLE001
            logger.debug("kev enrichment failed: %s", e)
            report["kev_block"] = {
                "listed": None,
                "date_added": None,
                "due_date": None,
                "known_ransomware_use": None,
                "vendor_project": None,
                "product": None,
                "vulnerability_name": None,
                "short_description": None,
                "required_action": None,
                "last_updated": None,
                "reason": "cache_unavailable",
            }

        # Mirror `kev_block.listed` onto the legacy `kev` /
        # `is_kev` fields so downstream consumers (priority-label
        # derivation, KG emission, compliance) that read either
        # field see the canonical authoritative answer. Tools
        # that already set `kev` manually (sca + container_image)
        # win — we only fill it when not already set, and we
        # never down-grade from True to False.
        try:
            kev_listed = report["kev_block"].get("listed")
            if kev_listed is True and not report.get("kev"):
                report["kev"] = True
                report["actively_exploited_in_wild"] = True
        except Exception:  # noqa: BLE001
            logger.warning("kev mirror failed", exc_info=True)

        # iter-21.1 — severity auto-promotion. If KEV-listed +
        # current severity below critical, bump to critical and
        # record a reasoning_trace line so auditors can see WHY
        # the tier moved. Conservative: only when listing is
        # explicit (not on stale / unavailable / no_cve).
        try:
            from strix.llm.kev_enrichment import maybe_promote_severity
            new_sev, kev_trace_line = maybe_promote_severity(
                current_severity=report.get("severity"),
                kev_block=report.get("kev_block") or {},
            )
            if new_sev is not None:
                report["severity"] = new_sev
                # Keep the promotion visible to the reasoning
                # trace; if the tool didn't pass one, start
                # one with this line.
                _existing_trace = report.get("reasoning_trace") or []
                if isinstance(_existing_trace, str):
                    _existing_trace = [_existing_trace]
                if isinstance(_existing_trace, list) and kev_trace_line:
                    _existing_trace = list(_existing_trace) + [kev_trace_line]
                    report["reasoning_trace"] = _existing_trace
        except Exception as e:  # noqa: BLE001
            logger.debug("kev severity promotion failed: %s", e)

        # MA-S2 P0-CVS-D — discovery_method block for novel-vuln
        # attestation. CVS-0.3 requires demonstrating that novel,
        # zero-day-class vulnerabilities (no CVE matched) are
        # discoverable through the AI specialist pipeline. The
        # block surfaces:
        #   - primary: which discovery path emitted the finding
        #     (ai_specialist / deterministic_specialist /
        #     cve_pattern_match / sast_rule / sca_lookup /
        #     nuclei_template). Falls back to "ai_specialist" when
        #     the emit path doesn't set discovery_method (the
        #     LLM-driven create_vulnerability_report tool path).
        #   - specialist_category: derived from discovery_source_tool
        #     or category (e.g. "sqli").
        #   - is_novel: True when primary=ai_specialist AND no CVE
        #     was matched. This is the literal MA-S2 attestation
        #     for CVS-0.3 — one bit per finding.
        try:
            _primary = (discovery_method or "ai_specialist").strip().lower()
            _src_tool = (discovery_source_tool or "").strip() or None
            _cat = (
                _src_tool[len("scan_"):] if _src_tool and _src_tool.startswith("scan_")
                else (category.strip().lower() if category else None)
            )
            _is_novel = (_primary == "ai_specialist" and not cve)
            report["discovery_method"] = {
                "primary": _primary,
                "specialist_category": _cat,
                "source_tool": _src_tool,
                "is_novel": bool(_is_novel),
            }
        except Exception as e:  # noqa: BLE001
            logger.debug("discovery_method block build failed: %s", e)
            report["discovery_method"] = {
                "primary": "unknown",
                "specialist_category": None,
                "source_tool": None,
                "is_novel": False,
            }

        # MA-S2 P0-CVS-B — contextual_priority rollup. Builds on
        # the EPSS block above + KEV via threat_intel + asset
        # context from target_metadata + reachability evidence
        # from existing finding fields. The block is ALWAYS
        # present; every section is canonical-shape so the
        # wrapper / auditor can rely on the keys existing.
        try:
            from strix.llm.contextual_priority import (
                build_contextual_priority,
            )
            report["contextual_priority"] = build_contextual_priority(
                report=report,
                scan_config=self.scan_config,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("contextual_priority build failed: %s", e)
            report["contextual_priority"] = {
                "raw_cvss": None,
                "raw_severity": report.get("severity"),
                "epss_score": None,
                "kev_listed": False,
                "reachability": {
                    "source_level": "unknown",
                    "dependency_level": "unknown",
                    "runtime_level": "unknown",
                    "verdict": "unknown",
                },
                "asset_context": {
                    "criticality": "unknown",
                    "data_sensitivity": "unknown",
                    "blast_radius": "unknown",
                },
                "attack_path_membership": [],
                "max_chained_severity": report.get("severity"),
                "priority_tier": "unknown",
            }

        if code_locations:
            report["code_locations"] = code_locations

        # Depth-of-attack — proof-of-impact artifact path. Required by
        # `validate_canonical_finding` when verification_status='exploited'.
        # Stored as-given; relative-path semantics enforced by the
        # scanner emitting the finding (no path canonicalisation here —
        # the run dir layout is the caller's contract).
        if isinstance(proof_artifact_path, str) and proof_artifact_path.strip():
            report["proof_artifact_path"] = proof_artifact_path.strip()

        # Depth-of-attack — provenance chain from the pivot orchestrator.
        # Normalise: list of non-empty strings, deduped, order preserved.
        if pivot_chain_ancestors:
            seen: set[str] = set()
            ancestors: list[str] = []
            for anc in pivot_chain_ancestors:
                if isinstance(anc, str) and anc.strip():
                    key = anc.strip()
                    if key not in seen:
                        seen.add(key)
                        ancestors.append(key)
            if ancestors:
                report["pivot_chain_ancestors"] = ancestors

        # Kill chain — multi-step finding context. Roadmap §1.
        # Normalize each step so consumers see a stable shape.
        normalized_chain = _normalize_kill_chain(kill_chain) if kill_chain else None
        if normalized_chain:
            report["kill_chain"] = normalized_chain

        # Roadmap §11 non-tech-output fields. These are the wrapper's
        # primary dashboard surface — non-engineer audience reads
        # description_plain / business_impact_plain / recommended_action
        # instead of the technical fields. Agent-supplied; never auto-
        # generated to avoid the agent shipping a placeholder.
        if isinstance(description_plain, str) and description_plain.strip():
            report["description_plain"] = description_plain.strip()
        if isinstance(business_impact_plain, str) and business_impact_plain.strip():
            report["business_impact_plain"] = business_impact_plain.strip()
        if isinstance(recommended_action, str) and recommended_action.strip():
            report["recommended_action"] = recommended_action.strip()
        if isinstance(fix_time_estimate, str):
            normalized_estimate = _normalize_fix_time_estimate(fix_time_estimate)
            if normalized_estimate:
                report["fix_time_estimate"] = normalized_estimate

        # Threat-intel enrichment — fail-open. CWE → OWASP/MITRE comes from
        # static maps; CVE → KEV from CISA's catalog (cached on disk for 24h).
        try:
            from strix.telemetry import threat_intel

            enrichment = threat_intel.enrich(report.get("cwe"), report.get("cve"))
            if enrichment:
                report.update(enrichment)
        except Exception:  # noqa: BLE001
            logger.warning("threat-intel enrichment failed", exc_info=True)

        # Compliance / GRC enrichment (roadmap §16) — fail-open static
        # map. Adds `compliance_controls: {soc2: [...], pci_dss: [...],
        # ...}` based on CWE, plus `data_classification: pii/phi/pci/
        # credentials/internal/confidential` inferred from category +
        # title + description. Wrappers render compliance overlays from
        # this; auditors consume by control ID.
        try:
            from strix.telemetry import compliance

            compliance_fields = compliance.enrich_finding_with_compliance(report)
            if compliance_fields:
                report.update(compliance_fields)
        except Exception:  # noqa: BLE001
            logger.warning("compliance enrichment failed", exc_info=True)

        # Roadmap §11 — auto-derive non-tech-output fields from the
        # signals we now have. priority_label is user-time-aware
        # (severity + KEV + how cheap the fix is). exploitation_in_wild_plain
        # is the plain-English KEV alert the wrapper renders verbatim
        # ("This is being actively attacked in the real world today").
        try:
            wild_plain = _derive_exploitation_in_wild_plain(report)
            if wild_plain:
                report["exploitation_in_wild_plain"] = wild_plain
            report["priority_label"] = _derive_priority_label(
                report.get("severity"),
                is_kev=bool(report.get("kev")),
                fix_time_estimate=report.get("fix_time_estimate"),
            )
        except Exception:  # noqa: BLE001
            logger.warning("non-tech-output derivation failed", exc_info=True)

        # Roadmap §12 / §18-row-4 — finding-quality signals.
        # Defaults are deliberately conservative so a missing field
        # never reads as "high confidence" by accident.
        # ----------------------------------------------------------
        # confidence: 0.0-1.0 continuous score. Defaults derived
        # from verification_status when not supplied:
        #   verified           → 1.0  (PoC ran)
        #   pattern_match      → 0.7  (signature matched, not exec'd)
        #   inconclusive       → 0.4  (some evidence, not confirmed)
        #   needs_review       → 0.4  (same posture as inconclusive)
        #   could_not_verify   → 0.2  (verifier ran and failed)
        # Agent overrides via the explicit parameter. Clamped [0, 1].
        try:
            if confidence is not None:
                report["confidence"] = max(0.0, min(1.0, float(confidence)))
            else:
                _CONF_DEFAULTS = {
                    "verified": 1.0,
                    "pattern_match": 0.7,
                    "inconclusive": 0.4,
                    "needs_review": 0.4,
                    "could_not_verify": 0.2,
                }
                report["confidence"] = _CONF_DEFAULTS.get(
                    report["verification_status"], 0.4
                )
        except (TypeError, ValueError):
            report["confidence"] = 0.4

        # reasoning_trace: structured "why I believe this is exploitable"
        # bullets. Distinct from kill_chain (which is "what was done").
        # Accepts list[str] or string with newlines (split + strip).
        # Capped at 20 bullets × 320 chars each so payloads stay bounded.
        try:
            trace_lines: list[str] = []
            if isinstance(reasoning_trace, list):
                trace_lines = [str(x).strip() for x in reasoning_trace if str(x).strip()]
            elif isinstance(reasoning_trace, str) and reasoning_trace.strip():
                trace_lines = [
                    line.strip()
                    for line in reasoning_trace.splitlines()
                    if line.strip()
                ]
            if trace_lines:
                report["reasoning_trace"] = [line[:320] for line in trace_lines[:20]]
        except Exception:  # noqa: BLE001
            logger.debug("reasoning_trace normalization failed", exc_info=True)

        # counter_proof: documents the input/condition the system
        # CORRECTLY rejects — establishes the boundary the vuln crosses.
        # Shape: {description: str, evidence: str}. Negative-example
        # signal for RL grading.
        try:
            if isinstance(counter_proof, dict):
                cp_desc = (counter_proof.get("description") or "").strip()
                cp_evidence = (counter_proof.get("evidence") or "").strip()
                if cp_desc or cp_evidence:
                    report["counter_proof"] = {
                        "description": cp_desc[:1024],
                        "evidence": cp_evidence[:2048],
                    }
        except Exception:  # noqa: BLE001
            logger.debug("counter_proof normalization failed", exc_info=True)

        # Stable finding fingerprint (roadmap §11). Computed once at write time
        # over normalized (cwe, endpoint|file, first-80-chars-of-title). The
        # algorithm is documented in this module; bump _FINGERPRINT_VERSION
        # when changing.
        try:
            file_hint: str | None = None
            if report.get("code_locations"):
                first_loc = report["code_locations"][0] if report["code_locations"] else None
                if isinstance(first_loc, dict):
                    file_hint = first_loc.get("file")
            report["fingerprint"] = compute_finding_fingerprint(
                title=report.get("title"),
                cwe=report.get("cwe"),
                endpoint=report.get("endpoint"),
                file=file_hint,
            )
            report["fingerprint_version"] = _FINGERPRINT_VERSION
        except Exception:  # noqa: BLE001
            logger.warning("fingerprint computation failed", exc_info=True)

        # Roadmap §12 #692 — reproducibility token. Distinct from the
        # finding fingerprint (which dedupes the *vuln*); this dedupes
        # the *reasoning attempt*. Two findings can have the same
        # fingerprint but different reproducibility-tokens — same vuln
        # found via different reasoning chains (RL pipeline grades them
        # separately).
        # Inputs hashed: reasoning_trace + kill_chain + target_state
        # (target + endpoint + method). Fingerprint excluded so changes
        # to the reasoning don't propagate into the dedup key.
        try:
            import hashlib as _hashlib
            import json as _json

            repro_inputs = {
                "reasoning_trace": report.get("reasoning_trace") or [],
                "kill_chain": report.get("kill_chain") or [],
                "target_state": {
                    "target": report.get("target") or "",
                    "endpoint": report.get("endpoint") or "",
                    "method": report.get("method") or "",
                },
            }
            canonical = _json.dumps(
                repro_inputs, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, default=str,
            )
            report["reproducibility_token"] = _hashlib.sha256(
                canonical.encode("utf-8")
            ).hexdigest()[:16]
        except Exception:  # noqa: BLE001
            logger.debug("reproducibility_token computation failed", exc_info=True)

        # RLHF Phase 1 / A2 — finding-features extraction. The FP
        # classifier (#A5, future PR) consumes this block. Stable
        # schema; always present so the classifier never has to
        # handle absence.
        try:
            from strix.telemetry.finding_features import extract_features

            report["features"] = extract_features(report)
        except Exception:  # noqa: BLE001
            logger.debug("finding_features extraction failed", exc_info=True)

        # RLHF Phase 1 / A4 — auto-dismiss on prior-FP fingerprint.
        # When a finding emits with a fingerprint that matches a
        # prior verdict=fp label and zero TP labels, auto-dismiss
        # (severity demoted to info, verification_status set to
        # could_not_verify, and a `finding.auto_dismissed` event
        # fired with attribution to the prior label).
        try:
            self._maybe_auto_dismiss_on_prior_fp(report)
        except Exception:  # noqa: BLE001
            logger.debug("auto_dismiss check failed", exc_info=True)

        # Canonical-finding contract validation (roadmap §8.0). Runs AFTER
        # all coercions so it sees the final shape. Never drops a finding
        # — violations are attached to the report and emitted as a
        # `finding.shape_violation` event so the wrapper can flag the
        # run without breaking the agent loop.
        try:
            from strix.telemetry.finding_contract import (
                has_canonical_errors,
                validate_canonical_finding,
                violations_to_dict_list,
            )

            violations = validate_canonical_finding(report)
            if violations:
                violation_dicts = violations_to_dict_list(violations)
                report["shape_violations"] = violation_dicts
                report["is_canonical"] = not has_canonical_errors(violations)
                self._emit_event(
                    "finding.shape_violation",
                    payload={
                        "report_id": report_id,
                        "title": report.get("title"),
                        "fingerprint": report.get("fingerprint"),
                        "violations": violation_dicts,
                        "is_canonical": report["is_canonical"],
                    },
                    status="warning" if report["is_canonical"] else "error",
                    source="strix.findings",
                )
            else:
                report["is_canonical"] = True
        except Exception:  # noqa: BLE001
            logger.warning("canonical-finding validation failed", exc_info=True)

        # Roadmap §9 cross-tool dedup. When a new finding shares the
        # stable fingerprint of an existing one, MERGE rather than
        # create a duplicate row. The accumulated `detected_by` list
        # encodes confidence: `len(detected_by) ≥ 2` means at least
        # two independent detection paths agree, which is a zero-
        # false-positive signal the wrapper can render as a "high
        # confidence" badge on the finding.
        merged_with_existing = self._maybe_merge_into_existing_finding(report)
        if merged_with_existing is not None:
            return merged_with_existing

        self.vulnerability_reports.append(report)
        logger.info(f"Added vulnerability report: {report_id} - {title}")
        posthog.finding(severity)
        self._emit_event(
            "finding.created",
            payload={"report": report},
            status=report["severity"],
            source="strix.findings",
        )

        # KG auto-emit: every finding with a URL endpoint becomes a
        # Vuln + Surface + AFFECTS triple unless a scanner has
        # explicitly emitted (the existing per-scanner pattern is
        # preserved — scanners can keep calling record_finding_in_kg
        # directly for the cases where they need extra props like
        # `db_engine` on a SQLi Vuln; the helper dedups). Fail-open.
        _emit_kg_auto_for_finding(report)

        # Roadmap §1: separate finding.kill_chain event for multi-step findings.
        # Emitted only when the agent supplied a chain — silence is honest when
        # the finding is a single-step pattern match.
        if normalized_chain:
            self._emit_event(
                "finding.kill_chain",
                payload={
                    "report_id": report_id,
                    "fingerprint": report.get("fingerprint"),
                    "title": report["title"],
                    "severity": report["severity"],
                    "step_count": len(normalized_chain),
                    "chain": normalized_chain,
                },
                status="completed",
                source="strix.findings",
            )

        if self.vulnerability_found_callback:
            self.vulnerability_found_callback(report)

        # V3-2 — auto-verify deterministic findings in quick/initial
        # modes. The deterministic specialist that emitted the
        # finding already verified it at the oracle level (payload
        # reflected, time-based delta, static-taint, SCA CVE match).
        # Skipping the LLM verifier saves the lead's verify-phase
        # round-trips. Best-effort: a failure here never blocks
        # the finding from landing.
        if discovery_method == "deterministic_specialist":
            try:
                from strix.agents.verification_pipeline import (  # noqa: PLC0415
                    auto_verify_deterministic,
                    should_auto_verify_deterministic,
                )
                if should_auto_verify_deterministic():
                    auto_verify_deterministic(
                        finding_id=report_id,
                        severity=report["severity"],
                        source_tool=(discovery_source_tool or "deterministic"),
                    )
            except Exception as e:  # noqa: BLE001
                logger.debug(
                    "auto-verify deterministic finding failed: %s", e,
                )

        self.save_run_data()
        return report_id

    def _maybe_auto_dismiss_on_prior_fp(self, report: dict[str, Any]) -> None:
        """RLHF Phase 1 / A4 — auto-dismiss on prior-FP fingerprint.

        When the wrapper has labeled a finding with the same
        fingerprint as `verdict=fp` (and zero TP labels under the
        conservative policy), the engine auto-dismisses on the
        next scan rather than presenting the same FP for re-triage.

        Mutations applied (when triggered):
          - `auto_dismissed = True` (boolean flag)
          - `auto_dismissal_reason` = "prior_human_fp"
          - `prior_label_attribution` = the FP label record (for
            audit-trail traceability per docs/rlhf-design.md §9)
          - `verification_status` → `could_not_verify` (the wrapper's
            triage UI demotes this to a low-confidence card; per
            design choice §3 "demote, don't suppress", the finding
            stays visible).
          - `severity` recorded under `severity_pre_auto_dismissal`
            (for re-promotion if the labeler reverses the FP verdict).
            Severity itself is NOT downgraded to info — the wrapper
            renders the dismissal banner; a future PR may add an
            opt-in severity-demotion mode.

        Best-effort throughout — failures swallowed.
        """
        fingerprint = report.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            return

        # Lazy-load the feedback only once per tracer instance — the
        # wrapper-feedback file rarely changes mid-run.
        if not hasattr(self, "_feedback_cache_loaded") or not self._feedback_cache_loaded:
            try:
                from strix.telemetry.feedback_loader import load_feedback

                run_dir = self.get_run_dir() if self._run_dir is None else self._run_dir
                self._feedback_cache = load_feedback(
                    explicit_path=None, run_dir=run_dir,
                )
                self._feedback_cache_loaded = True
            except Exception:  # noqa: BLE001
                self._feedback_cache = {}
                self._feedback_cache_loaded = True

        history = self._feedback_cache.get(fingerprint) or []
        if not history:
            return

        try:
            from strix.telemetry.feedback_loader import (
                env_policy,
                is_auto_dismissable,
            )

            should_dismiss, attribution = is_auto_dismissable(
                history, policy=env_policy()
            )
        except Exception:  # noqa: BLE001
            return

        if not should_dismiss:
            return

        # Apply auto-dismissal mutations.
        report["auto_dismissed"] = True
        report["auto_dismissal_reason"] = "prior_human_fp"
        report["severity_pre_auto_dismissal"] = report.get("severity")
        report["verification_status"] = "could_not_verify"
        if attribution is not None:
            # Strip free-text `notes` before attaching attribution
            # — it may carry sensitive operator commentary that
            # shouldn't enter the finding artifact.
            sanitised = {
                k: v for k, v in attribution.items()
                if k in ("verdict", "fp_reason", "labeler",
                         "labeled_at", "label_id", "scan_run_id")
            }
            report["prior_label_attribution"] = sanitised

        # Emit a structured event so the wrapper can flag the
        # auto-dismissal in its UI.
        try:
            self._emit_event(
                "finding.auto_dismissed",
                payload={
                    "fingerprint": fingerprint,
                    "auto_dismissal_reason": "prior_human_fp",
                    "prior_label_attribution": report.get("prior_label_attribution"),
                    "severity_pre_auto_dismissal": report.get("severity_pre_auto_dismissal"),
                },
                status="auto_dismissed",
                source="strix.telemetry.feedback_loader",
            )
        except Exception:  # noqa: BLE001
            logger.debug("finding.auto_dismissed emit failed", exc_info=True)

    def _maybe_merge_into_existing_finding(
        self, new_report: dict[str, Any],
    ) -> str | None:
        """Cross-tool dedup (roadmap §9). When `new_report` shares
        its `fingerprint` with an existing finding, merge rather
        than append. Returns the existing report's `id` on merge,
        or None when no match.

        The accumulated `detected_by` list is the wrapper-facing
        confidence signal — multiple detectors agreeing is a
        zero-false-positive indicator.

        Severity ladder on merge: take the MAX of the existing and
        new severity (a tool that says critical wins over one that
        says low). Emits `finding.detection_corroborated` event so
        wrappers can flag the moment the confidence threshold is
        crossed.
        """
        new_fp = new_report.get("fingerprint")
        if not new_fp:
            return None

        # Find the existing finding by fingerprint.
        existing: dict[str, Any] | None = None
        for r in self.vulnerability_reports:
            if r.get("fingerprint") == new_fp:
                existing = r
                break
        if existing is None:
            return None

        # Merge `detected_by`. The new finding's `detected_by` may
        # be a list, a single string, or absent. Existing entry
        # may also be either — normalise both.
        existing_detected = existing.get("detected_by") or []
        if isinstance(existing_detected, str):
            existing_detected = [existing_detected]
        new_detected = new_report.get("detected_by") or []
        if isinstance(new_detected, str):
            new_detected = [new_detected]

        # If the new finding doesn't carry an explicit detected_by,
        # fall back to its `category` as the detector name (the tool
        # is identified by what it found).
        if not new_detected:
            cat = (new_report.get("category") or "").strip().lower()
            if cat:
                new_detected = [cat]

        merged_detected = list(existing_detected)
        for d in new_detected:
            d_norm = str(d).strip().lower()
            if d_norm and d_norm not in merged_detected:
                merged_detected.append(d_norm)

        existing["detected_by"] = merged_detected
        existing["detection_count"] = len(merged_detected)

        # Severity ladder — take the max.
        sev_order = ["info", "low", "medium", "high", "critical"]
        existing_sev = (existing.get("severity") or "info").lower()
        new_sev = (new_report.get("severity") or "info").lower()
        try:
            old_idx = sev_order.index(existing_sev)
        except ValueError:
            old_idx = 0
        try:
            new_idx = sev_order.index(new_sev)
        except ValueError:
            new_idx = 0
        if new_idx > old_idx:
            existing["severity"] = new_sev
            existing["severity_promoted_from"] = existing_sev

        # Track the merge audit trail in the existing finding.
        merge_log = existing.setdefault("dedup_merges", [])
        merge_log.append({
            "merged_at": datetime.now(UTC).isoformat(),
            "from_title": new_report.get("title"),
            "from_category": new_report.get("category"),
            "from_severity": new_sev,
        })

        self._emit_event(
            "finding.detection_corroborated",
            payload={
                "report_id": existing.get("id"),
                "fingerprint": new_fp,
                "detected_by": merged_detected,
                "detection_count": len(merged_detected),
                "title": existing.get("title"),
                "severity": existing.get("severity"),
            },
            status="info",
            source="strix.findings.dedup",
        )

        return existing.get("id")

    def get_existing_vulnerabilities(self) -> list[dict[str, Any]]:
        return list(self.vulnerability_reports)

    def update_finding(
        self,
        *,
        fingerprint: str | None = None,
        report_id: str | None = None,
        verification_status: str | None = None,
        confidence: float | None = None,
        severity: str | None = None,
        reasoning_trace: list[str] | str | None = None,
        counter_proof: dict[str, Any] | None = None,
        poc_script_code: str | None = None,
        additional_evidence: str | None = None,
        updater_agent_id: str | None = None,
        update_reason: str | None = None,
    ) -> dict[str, Any]:
        """Roadmap §8.5 Phase 5 — mutate an already-emitted finding.

        Use after eager-emission + follow-up evidence (e.g. validator
        confirmed; severity needs a bump; counter_proof discovered).
        Per [`single-agent.md §2.4`](single-agent.md), this is the
        review-then-emit half of the eager-emit pattern (B.10): emit
        early at `verification_status="pattern_match"`, then call
        `update_finding(...)` once the validator confirms or refutes.

        Args:
            fingerprint: stable cross-scan finding id (#11 / #137).
                Either this OR `report_id` must be provided.
            report_id: per-run finding id (e.g. `vuln-0001`). Either
                this OR `fingerprint` must be provided.
            verification_status: optional new value. Validated against
                #86 closed-enum. Clears `auto_dismissed` state when
                set to `verified` (re-promotes a previously auto-
                dismissed finding via the operator-driven path; the
                wrapper's force-show button writes `verdict=tp` to
                feedback.jsonl, but the engine itself can also re-
                promote when a validator confirms).
            confidence: optional new value (0.0–1.0). Same semantics
                as #137.
            severity: optional new value. Validated against the
                canonical 5-value enum. Records the prior value under
                `severity_pre_update` for audit.
            reasoning_trace: optional new bullets (capped at 20 ×
                320 chars per #137). REPLACES the existing trace.
                Use when the validator has cleaner reasoning than
                the original eager-emit.
            counter_proof: optional new counter-proof block. REPLACES
                existing.
            poc_script_code: optional new PoC. When set on an
                existing finding without one, also bumps
                `verification_status` toward `verified` if the caller
                didn't pass it explicitly.
            additional_evidence: free-text appended to a new
                `update_evidence_log` field (capped 4096 chars per
                update). Each call appends a new entry.
            updater_agent_id: id of the agent that ran the update
                (for audit). Persisted in `last_updated_by`.
            update_reason: free-text justification (for the
                `finding.updated` event payload).

        Returns:
            ```python
            {
                "success": bool,
                "report_id": str | None,
                "fingerprint": str | None,
                "fields_changed": list[str],
                "previous_values": dict,
                "error": str | None,  # set when success=False
            }
            ```

        Side effects:
          * Mutates the finding in place.
          * Records `severity_pre_update` / `update_evidence_log` /
            `last_updated_at` / `last_updated_by`.
          * Emits `finding.updated` event (additive — wrappers
            ignoring unknowns keep working per engine-usage.md §6).
          * Re-runs #86 contract validation; violations attach to
            the finding's `shape_violations` list.
          * Re-runs #142 features extraction so the FP classifier's
            input reflects latest values.
          * Saves run data so the on-disk `vulnerabilities.json`
            stays current.
        """
        if not fingerprint and not report_id:
            return {
                "success": False,
                "report_id": None,
                "fingerprint": None,
                "fields_changed": [],
                "previous_values": {},
                "error": "either fingerprint or report_id required",
            }

        target: dict[str, Any] | None = None
        for r in self.vulnerability_reports:
            if fingerprint and r.get("fingerprint") == fingerprint:
                target = r
                break
            if report_id and r.get("id") == report_id:
                target = r
                break
        if target is None:
            return {
                "success": False,
                "report_id": report_id,
                "fingerprint": fingerprint,
                "fields_changed": [],
                "previous_values": {},
                "error": (
                    f"no finding with fingerprint={fingerprint!r} "
                    f"or report_id={report_id!r}"
                ),
            }

        previous: dict[str, Any] = {}
        fields_changed: list[str] = []

        # Validate verification_status against the canonical enum.
        try:
            from strix.telemetry.finding_contract import (
                VALID_VERIFICATION_STATUSES,
            )
        except ImportError:
            VALID_VERIFICATION_STATUSES = frozenset({  # noqa: N806
                "verified", "pattern_match", "inconclusive",
                "needs_review", "could_not_verify",
            })
        if verification_status is not None:
            normalised = str(verification_status).strip().lower()
            if normalised not in VALID_VERIFICATION_STATUSES:
                return {
                    "success": False,
                    "report_id": target.get("id"),
                    "fingerprint": target.get("fingerprint"),
                    "fields_changed": [],
                    "previous_values": {},
                    "error": (
                        f"verification_status {verification_status!r} not "
                        f"in canonical enum"
                    ),
                }
            if target.get("verification_status") != normalised:
                previous["verification_status"] = target.get("verification_status")
                target["verification_status"] = normalised
                fields_changed.append("verification_status")
                # Re-promote if previously auto-dismissed and now verified.
                if normalised == "verified" and target.get("auto_dismissed"):
                    previous["auto_dismissed"] = True
                    target["auto_dismissed"] = False
                    target["re_promoted"] = True
                    fields_changed.append("auto_dismissed")

        # Severity update.
        if severity is not None:
            sev = str(severity).strip().lower()
            if sev not in {"info", "low", "medium", "high", "critical"}:
                return {
                    "success": False,
                    "report_id": target.get("id"),
                    "fingerprint": target.get("fingerprint"),
                    "fields_changed": fields_changed,
                    "previous_values": previous,
                    "error": f"severity {severity!r} not in canonical enum",
                }
            if target.get("severity") != sev:
                previous["severity"] = target.get("severity")
                target["severity_pre_update"] = target.get("severity")
                target["severity"] = sev
                fields_changed.append("severity")

        # Confidence update.
        if confidence is not None:
            try:
                c = float(confidence)
            except (TypeError, ValueError):
                return {
                    "success": False,
                    "report_id": target.get("id"),
                    "fingerprint": target.get("fingerprint"),
                    "fields_changed": fields_changed,
                    "previous_values": previous,
                    "error": f"confidence must be numeric, got {confidence!r}",
                }
            if not 0.0 <= c <= 1.0:
                return {
                    "success": False,
                    "report_id": target.get("id"),
                    "fingerprint": target.get("fingerprint"),
                    "fields_changed": fields_changed,
                    "previous_values": previous,
                    "error": f"confidence {c} out of range [0.0, 1.0]",
                }
            if target.get("confidence") != c:
                previous["confidence"] = target.get("confidence")
                target["confidence"] = c
                fields_changed.append("confidence")

        # reasoning_trace — REPLACE (caller passes the new trace).
        if reasoning_trace is not None:
            if isinstance(reasoning_trace, str):
                trace = [s.strip() for s in reasoning_trace.split("\n") if s.strip()]
            else:
                trace = [
                    str(s).strip()[:320] for s in reasoning_trace if str(s).strip()
                ][:20]
            previous["reasoning_trace"] = target.get("reasoning_trace")
            target["reasoning_trace"] = trace
            fields_changed.append("reasoning_trace")

        # counter_proof — REPLACE.
        if counter_proof is not None and isinstance(counter_proof, dict):
            previous["counter_proof"] = target.get("counter_proof")
            cp_normalised: dict[str, Any] = {}
            desc = counter_proof.get("description")
            evid = counter_proof.get("evidence")
            if isinstance(desc, str):
                cp_normalised["description"] = desc[:1024]
            if isinstance(evid, str):
                cp_normalised["evidence"] = evid[:2048]
            target["counter_proof"] = cp_normalised
            fields_changed.append("counter_proof")

        # PoC code update — bumps verification_status to verified
        # when not explicitly set by caller and PoC was previously
        # absent.
        if poc_script_code is not None:
            new_poc = str(poc_script_code)[:16384]
            if target.get("poc_script_code") != new_poc:
                previous["poc_script_code"] = target.get("poc_script_code")
                target["poc_script_code"] = new_poc
                fields_changed.append("poc_script_code")
                if (
                    verification_status is None
                    and target.get("verification_status") in (
                        "pattern_match", "inconclusive", "needs_review",
                    )
                ):
                    previous.setdefault(
                        "verification_status", target.get("verification_status"),
                    )
                    target["verification_status"] = "verified"
                    if "verification_status" not in fields_changed:
                        fields_changed.append("verification_status")

        # Append-only evidence log.
        if additional_evidence is not None and str(additional_evidence).strip():
            log = target.get("update_evidence_log") or []
            if not isinstance(log, list):
                log = []
            log.append({
                "evidence": str(additional_evidence)[:4096],
                "at": datetime.now(UTC).isoformat(),
                "agent_id": updater_agent_id,
            })
            target["update_evidence_log"] = log
            if "update_evidence_log" not in fields_changed:
                fields_changed.append("update_evidence_log")

        if not fields_changed:
            return {
                "success": True,
                "report_id": target.get("id"),
                "fingerprint": target.get("fingerprint"),
                "fields_changed": [],
                "previous_values": {},
                "error": None,
            }

        target["last_updated_at"] = datetime.now(UTC).isoformat()
        if updater_agent_id:
            target["last_updated_by"] = updater_agent_id

        # Re-run #142 features extraction so the FP classifier sees
        # the latest values (the features block already lives on the
        # finding; re-extract to refresh).
        try:
            from strix.telemetry.finding_features import extract_features

            target["features"] = extract_features(target)
        except Exception:  # noqa: BLE001
            logger.debug("update_finding: features re-extraction failed", exc_info=True)

        # Re-run canonical-finding contract validation. Violations
        # attach to the finding rather than aborting the update.
        try:
            from strix.telemetry.finding_contract import (
                validate_canonical_finding,
            )

            shape_violations = validate_canonical_finding(target)
            target["shape_violations"] = shape_violations
            target["is_canonical"] = not any(
                v.get("severity") == "error" for v in shape_violations
            )
        except Exception:  # noqa: BLE001
            logger.debug("update_finding: contract revalidation failed", exc_info=True)

        # Emit the additive `finding.updated` event. Wrapper-side:
        # additive per engine-usage.md §6 versioning contract.
        self._emit_event(
            "finding.updated",
            payload={
                "report_id": target.get("id"),
                "fingerprint": target.get("fingerprint"),
                "fields_changed": fields_changed,
                "previous_values": previous,
                "update_reason": update_reason,
                "updater_agent_id": updater_agent_id,
            },
            actor={"id": updater_agent_id} if updater_agent_id else None,
            status="updated",
            source="strix.findings.update",
        )

        try:
            self.save_run_data()
        except Exception:  # noqa: BLE001
            logger.debug("update_finding: save_run_data failed", exc_info=True)

        return {
            "success": True,
            "report_id": target.get("id"),
            "fingerprint": target.get("fingerprint"),
            "fields_changed": fields_changed,
            "previous_values": previous,
            "error": None,
        }

    def update_finding_verification(
        self,
        report_id: str,
        new_status: str,
        *,
        evidence: str | None = None,
        verifier_agent_id: str | None = None,
    ) -> bool:
        """Update a finding's `verification_status` after deterministic
        re-verification (roadmap §8.2 row 3 — Verifier agent).

        Args:
            report_id: the `id` field of a finding (e.g. `vuln-0001`).
            new_status: the post-verification status. Must be in the
                canonical-finding contract's verification allow-list:
                `verified`, `pattern_match`, `inconclusive`,
                `needs_review`, `could_not_verify`.
            evidence: optional human-readable note describing why the
                verifier set this status. Persisted in the finding's
                `verification_evidence` field.
            verifier_agent_id: id of the agent that ran the
                verification (for audit). Persisted in
                `verification_agent_id`.

        Returns:
            True if a finding with `report_id` was found AND the new
            status is in the allow-list. False otherwise (silent — the
            verifier never raises).

        Side effects:
            - Mutates the finding in place.
            - Emits `finding.verification_attempted` event with the
              previous + new status, the evidence, and the agent id.
            - Re-runs the canonical-finding contract validator on the
              updated finding so any introduced violations are caught.
            - Triggers `save_run_data()` so the on-disk artifact stays
              current.
        """
        # Validate the requested status against the canonical contract's
        # allow-list — keeps the verifier from accidentally introducing
        # a non-canonical status.
        try:
            from strix.telemetry.finding_contract import (
                VALID_VERIFICATION_STATUSES,
            )
        except ImportError:
            VALID_VERIFICATION_STATUSES = frozenset({  # noqa: N806
                "verified", "pattern_match", "inconclusive",
                "needs_review", "could_not_verify",
            })
        normalised = (new_status or "").strip().lower()
        if normalised not in VALID_VERIFICATION_STATUSES:
            logger.warning(
                "update_finding_verification: status %r is not canonical "
                "(allow-list: %s)",
                new_status, sorted(VALID_VERIFICATION_STATUSES),
            )
            return False

        target = None
        for r in self.vulnerability_reports:
            if r.get("id") == report_id:
                target = r
                break
        if target is None:
            logger.debug(
                "update_finding_verification: no finding with id %r",
                report_id,
            )
            return False

        previous = target.get("verification_status")
        target["verification_status"] = normalised
        if evidence:
            target["verification_evidence"] = str(evidence)[:2000]
        if verifier_agent_id:
            target["verification_agent_id"] = verifier_agent_id
        target["verification_updated_at"] = datetime.now(UTC).isoformat()

        self._emit_event(
            "finding.verification_attempted",
            payload={
                "report_id": report_id,
                "fingerprint": target.get("fingerprint"),
                "previous_status": previous,
                "new_status": normalised,
                "evidence": evidence,
                "verifier_agent_id": verifier_agent_id,
            },
            actor={"id": verifier_agent_id} if verifier_agent_id else None,
            status=normalised,
            source="strix.findings.verification",
        )

        try:
            self.save_run_data()
        except Exception:  # noqa: BLE001
            logger.debug("save_run_data failed during verification update", exc_info=True)
        return True

    # ------------------------------------------------------------------
    # Phase + check events (roadmap §1)
    #
    # Phases mark the major stages of a scan (recon → exploit → validate →
    # report). Checks are per-attack-class × per-surface probes that emit
    # both a started-event (work begun) and a completed-event (with a
    # vulnerable | not_vulnerable | inconclusive verdict). Together they
    # answer the "what was tried, not just what was found" question.
    #
    # All methods return cheap string IDs the caller passes back to the
    # corresponding *_complete method. Caller-tracked rather than
    # context-managed because completion can be cross-call (e.g., the
    # check is started by a fingerprint tool and completed by an exploit
    # tool that reads the surface map).
    # ------------------------------------------------------------------

    _PHASE_NAMES = ("recon", "exploit", "validate", "report")
    _CHECK_RESULTS = ("vulnerable", "not_vulnerable", "inconclusive")

    def enter_phase(
        self,
        phase: str,
        agent_id: str | None = None,
        focus: str | None = None,
    ) -> str:
        """Mark the start of a scan phase. Returns a phase_id to pass to complete_phase."""
        phase_id = f"phase-{uuid4().hex[:12]}"
        normalised = phase.strip().lower()
        record = {
            "phase_id": phase_id,
            "phase": normalised,
            "started_at": datetime.now(UTC).isoformat(),
            "agent_id": agent_id,
            "focus": focus,
        }
        self._open_phases[phase_id] = record

        payload: dict[str, Any] = {"phase_id": phase_id, "phase": normalised}
        if focus:
            payload["focus"] = focus
        if normalised not in self._PHASE_NAMES:
            payload["custom"] = True

        actor = {"id": agent_id} if agent_id else None
        self._emit_event(
            "phase.entered",
            actor=actor,
            payload=payload,
            status=normalised,
            source="strix.run",
        )
        return phase_id

    def complete_phase(
        self,
        phase_id: str,
        summary: dict[str, Any] | None = None,
    ) -> None:
        """Mark the end of a phase. Idempotent — completing an unknown id is silently no-op."""
        record = self._open_phases.pop(phase_id, None)
        if record is None:
            logger.debug("complete_phase called with unknown phase_id %s", phase_id)
            return

        try:
            started = datetime.fromisoformat(record["started_at"])
            duration = (datetime.now(UTC) - started).total_seconds()
        except (ValueError, TypeError):
            duration = 0.0

        payload: dict[str, Any] = {
            "phase_id": phase_id,
            "phase": record["phase"],
            "duration_seconds": round(duration, 3),
        }
        if summary:
            payload["summary"] = summary

        actor = {"id": record["agent_id"]} if record["agent_id"] else None
        self._emit_event(
            "phase.completed",
            actor=actor,
            payload=payload,
            status="completed",
            source="strix.run",
        )

    def start_check(
        self,
        category: str,
        surface: str | None = None,
        *,
        tool: str | None = None,
        agent_id: str | None = None,
    ) -> str:
        """Mark the start of one attack-class × surface probe. Returns a check_id."""
        check_id = f"check-{uuid4().hex[:12]}"
        record = {
            "check_id": check_id,
            "category": category.strip().lower(),
            "surface": surface,
            "tool": tool,
            "agent_id": agent_id,
            "started_at": datetime.now(UTC).isoformat(),
        }
        self._open_checks[check_id] = record

        payload: dict[str, Any] = {
            "check_id": check_id,
            "category": record["category"],
        }
        if surface:
            payload["surface"] = surface
        if tool:
            payload["tool"] = tool

        actor = {"id": agent_id} if agent_id else None
        self._emit_event(
            "check.started",
            actor=actor,
            payload=payload,
            source="strix.checks",
        )
        return check_id

    def complete_check(
        self,
        check_id: str,
        result: str,
        *,
        confidence: float | None = None,
        evidence: str | None = None,
        finding_id: str | None = None,
    ) -> None:
        """Mark the end of a check. `result` ∈ {vulnerable, not_vulnerable, inconclusive}.

        On vulnerable: pass `finding_id` to link to the corresponding
        vulnerabilities/<id>.md entry. Confidence is 0.0–1.0; if unset, defaults
        to 1.0 for `vulnerable`/`not_vulnerable` (the caller is making a
        deterministic claim) and 0.5 for `inconclusive`.
        """
        record = self._open_checks.pop(check_id, None)
        if record is None:
            logger.debug("complete_check called with unknown check_id %s", check_id)
            return

        normalised_result = result.strip().lower()
        if normalised_result not in self._CHECK_RESULTS:
            logger.warning(
                "complete_check called with invalid result %r; coercing to inconclusive",
                result,
            )
            normalised_result = "inconclusive"

        if confidence is None:
            confidence = 0.5 if normalised_result == "inconclusive" else 1.0
        # Clamp.
        confidence = max(0.0, min(1.0, float(confidence)))

        try:
            started = datetime.fromisoformat(record["started_at"])
            duration = (datetime.now(UTC) - started).total_seconds()
        except (ValueError, TypeError):
            duration = 0.0

        payload: dict[str, Any] = {
            "check_id": check_id,
            "category": record["category"],
            "result": normalised_result,
            "confidence": round(confidence, 3),
            "duration_seconds": round(duration, 3),
        }
        if record.get("surface"):
            payload["surface"] = record["surface"]
        if record.get("tool"):
            payload["tool"] = record["tool"]
        if evidence:
            payload["evidence"] = evidence
        if finding_id:
            payload["finding_id"] = finding_id

        # Accumulate for end-of-run summary.
        self._completed_checks.append(dict(payload))

        actor = {"id": record["agent_id"]} if record["agent_id"] else None
        self._emit_event(
            "check.completed",
            actor=actor,
            payload=payload,
            status=normalised_result,
            source="strix.checks",
        )

    def token_breakdown_summary(self) -> dict[str, Any]:
        """Roadmap §8.5 Phase 0.A — aggregate `llm.token_breakdown`
        events from `events.jsonl` for cost-bisection analysis.

        Returns per-component totals across the entire run plus the
        aggregate cache-hit ratio. Decision-gate input for the
        single-lead-agent migration: if `conversation_tokens` is
        the dominant bucket (and `inherit_context=True` is responsible
        for most of it), the §8.5 Phase 0.B default-flip is the
        cheapest fix; full architectural migration is deferred.

        Best-effort. Returns zeros when no breakdown events have
        been emitted (e.g. run hasn't called the LLM yet).
        """
        totals = {
            "system_tokens": 0,
            "agent_identity_tokens": 0,
            "conversation_tokens": 0,
            "total_input_tokens_estimated": 0,
            "measured_input_tokens": 0,
            "measured_output_tokens": 0,
            "measured_cached_tokens": 0,
            "measured_cost_usd": 0.0,
        }
        per_call: list[dict[str, Any]] = []
        per_agent: dict[str, dict[str, int | float]] = {}
        call_count = 0

        try:
            events_path = self._events_file_path
            if events_path is None or not events_path.exists():
                return _empty_token_breakdown_summary()
            for raw in events_path.read_text(encoding="utf-8").splitlines():
                if not raw.strip():
                    continue
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if ev.get("event_type") != "llm.token_breakdown":
                    continue
                payload = ev.get("payload") or {}
                call_count += 1

                for k in (
                    "system_tokens", "agent_identity_tokens",
                    "conversation_tokens", "total_input_tokens_estimated",
                    "measured_input_tokens", "measured_output_tokens",
                    "measured_cached_tokens",
                ):
                    totals[k] += int(payload.get(k, 0) or 0)
                totals["measured_cost_usd"] += float(payload.get("measured_cost_usd", 0.0) or 0.0)

                # Per-call summary (lightweight — for histogram rendering).
                per_call.append({
                    "model": payload.get("model"),
                    "agent_id": payload.get("agent_id"),
                    "agent_name": payload.get("agent_name"),
                    "system_tokens": int(payload.get("system_tokens", 0) or 0),
                    "conversation_tokens": int(payload.get("conversation_tokens", 0) or 0),
                    "measured_cached_tokens": int(payload.get("measured_cached_tokens", 0) or 0),
                    "measured_cost_usd": float(payload.get("measured_cost_usd", 0.0) or 0.0),
                    "cache_hit_ratio": float(payload.get("cache_hit_ratio", 0.0) or 0.0),
                })

                # Per-agent aggregation.
                agent_key = str(payload.get("agent_name") or payload.get("agent_id") or "unknown")
                slot = per_agent.setdefault(
                    agent_key,
                    {
                        "calls": 0,
                        "system_tokens": 0,
                        "conversation_tokens": 0,
                        "measured_input_tokens": 0,
                        "measured_cached_tokens": 0,
                        "measured_cost_usd": 0.0,
                    },
                )
                slot["calls"] = int(slot["calls"]) + 1
                for k in (
                    "system_tokens", "conversation_tokens",
                    "measured_input_tokens", "measured_cached_tokens",
                ):
                    slot[k] = int(slot[k]) + int(payload.get(k, 0) or 0)
                slot["measured_cost_usd"] = (
                    float(slot["measured_cost_usd"])
                    + float(payload.get("measured_cost_usd", 0.0) or 0.0)
                )
        except OSError:
            logger.debug("token_breakdown_summary: read failed", exc_info=True)
            return _empty_token_breakdown_summary()

        # Component fractions of total estimated input.
        denom = totals["total_input_tokens_estimated"] or 1
        component_fractions = {
            "system_fraction": round(totals["system_tokens"] / denom, 4),
            "agent_identity_fraction": round(totals["agent_identity_tokens"] / denom, 4),
            "conversation_fraction": round(totals["conversation_tokens"] / denom, 4),
        }

        # Aggregate cache-hit ratio.
        meas_input = totals["measured_input_tokens"] or 1
        cache_hit_ratio_run = round(totals["measured_cached_tokens"] / meas_input, 4)

        return {
            "schema_version": 1,
            "call_count": call_count,
            "totals": {
                **totals,
                "measured_cost_usd": round(totals["measured_cost_usd"], 6),
            },
            "component_fractions": component_fractions,
            "cache_hit_ratio_run": cache_hit_ratio_run,
            "per_agent": per_agent,
            "per_call_count": len(per_call),
        }

    def get_check_summary(self) -> dict[str, Any]:
        """Aggregate completed checks for end-of-run reporting.

        Returns counts per result, per category, and the list of
        not_vulnerable checks (which feed §11 negative-coverage assertions).
        """
        by_result: dict[str, int] = {"vulnerable": 0, "not_vulnerable": 0, "inconclusive": 0}
        by_category: dict[str, dict[str, int]] = {}
        not_vulnerable: list[dict[str, Any]] = []

        for c in self._completed_checks:
            result = c.get("result", "inconclusive")
            by_result[result] = by_result.get(result, 0) + 1
            cat = c.get("category", "unknown")
            by_category.setdefault(cat, {"vulnerable": 0, "not_vulnerable": 0, "inconclusive": 0})
            by_category[cat][result] = by_category[cat].get(result, 0) + 1
            if result == "not_vulnerable":
                not_vulnerable.append(
                    {
                        "category": cat,
                        "surface": c.get("surface"),
                        "tool": c.get("tool"),
                        "confidence": c.get("confidence"),
                    }
                )

        return {
            "total": len(self._completed_checks),
            "by_result": by_result,
            "by_category": by_category,
            "not_vulnerable": not_vulnerable,
        }

    def build_coverage_attestation(self) -> dict[str, Any]:
        """Build the structured coverage-attestation artifact.

        Promotes the §11 check-events stack into a per-(category × surface)
        attestation table that auditors / bug-bounty triagers / GRC platforms
        can consume programmatically. Roadmap §17.1.

        Returns a dict with:
            - schema_version, run_id, run_name, generated_at, targets
            - summary: total, by_result, by_category counts
            - attestations: list of per-check atomic records (category,
              surface, tool, result, confidence, evidence, finding_id,
              duration_seconds, check_id, started_at)
            - negative_coverage: list of {category, surfaces[]} —
              "tested AND clean"
            - inconclusive_coverage: list of {category, surfaces[]} —
              "tested but evidence was observed without confirmation"
            - vulnerable_coverage: list of {category, surfaces[],
              finding_ids[]} — "tested AND a finding was emitted"

        The artifact is structured so cryptographic signing (§16) can be
        added later as a single signing pass without re-renaming any
        existing fields.
        """
        summary = self.get_check_summary()
        attestations: list[dict[str, Any]] = []
        for c in self._completed_checks:
            entry: dict[str, Any] = {
                "check_id": c.get("check_id"),
                "category": c.get("category") or "uncategorised",
                "surface": c.get("surface") or None,
                "tool": c.get("tool") or None,
                "result": c.get("result") or "inconclusive",
                "confidence": c.get("confidence"),
                "duration_seconds": c.get("duration_seconds"),
            }
            if c.get("evidence"):
                entry["evidence"] = c["evidence"]
            if c.get("finding_id"):
                entry["finding_id"] = c["finding_id"]
            if c.get("started_at"):
                entry["started_at"] = c["started_at"]
            attestations.append(entry)

        # Group per-(category, result).
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for a in attestations:
            key = (a["category"], a["result"])
            entry = groups.setdefault(
                key,
                {"category": a["category"], "surfaces": [], "finding_ids": []},
            )
            if a.get("surface"):
                entry["surfaces"].append(a["surface"])
            if a.get("finding_id"):
                entry["finding_ids"].append(a["finding_id"])

        def _bucket(result: str) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            for (cat, res), entry in sorted(groups.items()):
                if res != result:
                    continue
                surfaces = sorted(set(entry["surfaces"]))
                bucket_entry: dict[str, Any] = {
                    "category": cat,
                    "surfaces": surfaces,
                    "surface_count": len(surfaces),
                }
                if entry["finding_ids"]:
                    bucket_entry["finding_ids"] = sorted(set(entry["finding_ids"]))
                out.append(bucket_entry)
            return out

        return {
            "schema_version": 1,
            "run_id": self.run_id,
            "run_name": self.run_name,
            "generated_at": datetime.now(UTC).isoformat(),
            "targets": list(self.run_metadata.get("targets") or []),
            "summary": summary,
            "attestations": attestations,
            "negative_coverage": _bucket("not_vulnerable"),
            "inconclusive_coverage": _bucket("inconclusive"),
            "vulnerable_coverage": _bucket("vulnerable"),
        }

    def _format_coverage_assertions(self) -> str | None:
        """Render the coverage section for penetration_test_report.md.

        Returns markdown text, or None when no check events were recorded
        (in which case we don't claim positive evidence we don't have).

        Roadmap §11 (initial) + §17.1 (promotion: structured attestation
        with explicit negative / inconclusive / vulnerable subsections,
        backed by `coverage_attestation.json`).
        """
        attestation = self.build_coverage_attestation()
        summary = attestation["summary"]
        if summary["total"] == 0:
            return None

        by_result = summary.get("by_result") or {}
        by_category = summary.get("by_category") or {}

        lines: list[str] = ["# Coverage Assertions", ""]
        lines.append(
            f"This scan ran **{summary['total']}** checks across "
            f"**{len(by_category)}** categor"
            f"{'y' if len(by_category) == 1 else 'ies'}: "
            f"{by_result.get('vulnerable', 0)} vulnerable, "
            f"{by_result.get('not_vulnerable', 0)} not vulnerable, "
            f"{by_result.get('inconclusive', 0)} inconclusive."
        )
        lines.append("")
        lines.append(
            "Structured attestation: see [`coverage_attestation.json`]"
            "(./coverage_attestation.json) for the full per-check record "
            "including confidence, evidence, and tool provenance."
        )
        lines.append("")

        # ---- Tested AND clean ----
        neg = attestation.get("negative_coverage") or []
        if neg:
            lines.append("## Tested and not vulnerable")
            lines.append("")
            for entry in neg:
                cat = entry["category"]
                surfaces = entry["surfaces"]
                if not surfaces:
                    lines.append(f"- **{cat}** — (no surface recorded)")
                elif len(surfaces) == 1:
                    lines.append(f"- **{cat}** — `{surfaces[0]}`")
                else:
                    surface_list = ", ".join(f"`{s}`" for s in surfaces[:8])
                    if len(surfaces) > 8:
                        surface_list += f" (and {len(surfaces) - 8} more)"
                    lines.append(f"- **{cat}** — {surface_list}")
            lines.append("")

        # ---- Tested AND a finding fired ----
        vuln = attestation.get("vulnerable_coverage") or []
        if vuln:
            lines.append("## Tested and vulnerable")
            lines.append("")
            for entry in vuln:
                cat = entry["category"]
                surfaces = entry["surfaces"]
                finding_ids = entry.get("finding_ids") or []
                surface_part = (
                    f"`{surfaces[0]}`" if len(surfaces) == 1
                    else f"{len(surfaces)} surface(s)"
                ) if surfaces else "(no surface recorded)"
                ids_part = (
                    f" — finding(s): {', '.join(f'`{f}`' for f in finding_ids)}"
                    if finding_ids else ""
                )
                lines.append(f"- **{cat}** — {surface_part}{ids_part}")
            lines.append("")

        # ---- Tested but inconclusive ----
        incon = attestation.get("inconclusive_coverage") or []
        if incon:
            lines.append("## Tested but inconclusive (needs review)")
            lines.append("")
            for entry in incon:
                cat = entry["category"]
                surfaces = entry["surfaces"]
                if not surfaces:
                    lines.append(f"- **{cat}** — (no surface recorded)")
                elif len(surfaces) == 1:
                    lines.append(f"- **{cat}** — `{surfaces[0]}`")
                else:
                    surface_list = ", ".join(f"`{s}`" for s in surfaces[:8])
                    if len(surfaces) > 8:
                        surface_list += f" (and {len(surfaces) - 8} more)"
                    lines.append(f"- **{cat}** — {surface_list}")
            lines.append("")
            lines.append(
                "_Inconclusive checks observed evidence but couldn't confirm "
                "via execution. Treat as 'needs review', not 'safe'._"
            )
            lines.append("")

        return "\n".join(lines)

    def _evaluate_coverage(self, run_dir: Path) -> None:
        """Compute coverage gaps from the required-coverage matrix vs the
        categories that actually have a check.completed event. Emits a
        `run.coverage_gap` event and persists `coverage.json`. Roadmap §7.0.
        """
        from strix.telemetry import coverage as coverage_module

        target_types: list[str] = []
        for t in self.run_metadata.get("targets") or []:
            if isinstance(t, dict) and t.get("type"):
                target_types.append(str(t["type"]))
            elif isinstance(t, str):
                # When targets were stored as strings (older callers), we can't
                # infer type — skip.
                continue

        # Dedup while preserving insertion order.
        seen: set[str] = set()
        unique_target_types: list[str] = []
        for tt in target_types:
            if tt not in seen:
                seen.add(tt)
                unique_target_types.append(tt)

        completed_categories = {c.get("category") for c in self._completed_checks if c.get("category")}
        scan_mode = self.run_metadata.get("scan_mode") or "standard"

        report = coverage_module.compute_gaps(
            target_types=unique_target_types,
            scan_mode=scan_mode,
            completed_categories={c for c in completed_categories if c},
        )

        # Persist artifact regardless of status — consumers may want to record
        # "no_matrix" runs so they can compare across scan modes.
        try:
            coverage_file = run_dir / "coverage.json"
            with coverage_file.open("w", encoding="utf-8") as f:
                json.dump(
                    {
                        "schema_version": 1,
                        "run_id": self.run_id,
                        "run_name": self.run_name,
                        "generated_at": datetime.now(UTC).isoformat(),
                        **report,
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                )
        except (OSError, TypeError):
            logger.warning("Failed to write coverage.json", exc_info=True)

        # Only emit a gap event when there's meaningful information — either
        # gaps exist or full coverage was achieved (so consumers see the
        # "complete" status as positive evidence, not silence).
        if report["status"] in ("incomplete", "complete"):
            self._emit_event(
                "run.coverage_gap" if report["status"] == "incomplete" else "run.coverage_complete",
                payload=report,
                status=report["status"],
                source="strix.run",
            )

    def update_scan_final_fields(
        self,
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
    ) -> None:
        self.scan_results = {
            "scan_completed": True,
            "executive_summary": executive_summary.strip(),
            "methodology": methodology.strip(),
            "technical_analysis": technical_analysis.strip(),
            "recommendations": recommendations.strip(),
            "success": True,
        }

        self.final_scan_result = f"""# Executive Summary

{executive_summary.strip()}

# Methodology

{methodology.strip()}

# Technical Analysis

{technical_analysis.strip()}

# Recommendations

{recommendations.strip()}
"""

        logger.info("Updated scan final fields")
        self._emit_event(
            "finding.reviewed",
            payload={
                "scan_completed": True,
                "vulnerability_count": len(self.vulnerability_reports),
            },
            status="completed",
            source="strix.findings",
        )
        self.save_run_data(mark_complete=True)
        posthog.end(self, exit_reason="finished_by_tool")

    def log_agent_creation(
        self,
        agent_id: str,
        name: str,
        task: str,
        parent_id: str | None = None,
        category: str | None = None,
    ) -> None:
        agent_data: dict[str, Any] = {
            "id": agent_id,
            "name": name,
            "category": category,
            "task": task,
            "status": "running",
            "parent_id": parent_id,
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
            "tool_executions": [],
        }

        self.agents[agent_id] = agent_data
        self._emit_event(
            "agent.created",
            actor={"agent_id": agent_id, "agent_name": name},
            payload={"task": task, "parent_id": parent_id, "category": category},
            status="running",
            source="strix.agents",
        )

    def log_chat_message(
        self,
        content: str,
        role: str,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        message_id = self._next_message_id
        self._next_message_id += 1

        message_data = {
            "message_id": message_id,
            "content": content,
            "role": role,
            "agent_id": agent_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "metadata": metadata or {},
        }

        self.chat_messages.append(message_data)
        self._emit_event(
            "chat.message",
            actor={"agent_id": agent_id, "role": role},
            payload={"message_id": message_id, "content": content, "metadata": metadata or {}},
            status="logged",
            source="strix.chat",
        )
        return message_id

    def _resolve_tool_event_context(
        self,
        agent_id: str,
        args: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Roadmap §4: surface `agent_name` / `agent_category` / `target`
        directly on every `tool.execution.*` event so wrappers can render
        "Agent X on target Y is running tool Z" without joining across
        `agent.created` + `target.started` + `tool.execution.*`.

        Resolution order for `target`:
          1. Per-call hint from the tool args (`url` / `target_url` /
             `target` / `endpoint` / `host` / `domain`) — host extracted
             from URLs so the field is comparable across tools.
          2. Run-level primary target (first entry of
             `scan_config["targets"]`) when the tool didn't take any
             URL-shaped argument.
          3. None — the field is still emitted (so the schema is
             stable) but downstream parsers handle the null.

        Always returns a dict; never raises."""
        ctx: dict[str, Any] = {
            "agent_name": None,
            "agent_category": None,
            "target": None,
        }

        # Agent name + category from the in-memory agent registry.
        try:
            agent_record = self.agents.get(agent_id) if agent_id else None
            if isinstance(agent_record, dict):
                ctx["agent_name"] = agent_record.get("name")
                ctx["agent_category"] = agent_record.get("category")
        except Exception:  # noqa: BLE001
            logger.debug("agent context lookup failed", exc_info=True)

        # Per-call target hint from args.
        per_call_target: str | None = None
        if isinstance(args, dict):
            for key in ("url", "target_url", "target", "endpoint", "host", "domain"):
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    per_call_target = value.strip()
                    break

        # Normalize to host (so /login on https://api.example.com renders
        # as `api.example.com`, comparable across tools that use the full
        # URL vs ones that use bare host).
        if per_call_target is not None:
            try:
                if "://" in per_call_target:
                    from urllib.parse import urlparse

                    parsed = urlparse(per_call_target)
                    if parsed.netloc:
                        per_call_target = parsed.netloc
            except Exception:  # noqa: BLE001
                logger.debug("target host extraction failed", exc_info=True)

        if per_call_target:
            ctx["target"] = per_call_target
        else:
            # Fall back to the run's primary target.
            try:
                config_targets = (self.scan_config or {}).get("targets") or []
                if config_targets:
                    primary = config_targets[0]
                    normalized = _normalize_target_for_events(primary)
                    if normalized and normalized.get("value"):
                        ctx["target"] = str(normalized["value"])
            except Exception:  # noqa: BLE001
                logger.debug("primary target fallback failed", exc_info=True)

        return ctx

    def log_tool_execution_start(
        self,
        agent_id: str,
        tool_name: str,
        args: dict[str, Any],
    ) -> int:
        execution_id = self._next_execution_id
        self._next_execution_id += 1

        now = datetime.now(UTC).isoformat()
        execution_data = {
            "execution_id": execution_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "args": args,
            "status": "running",
            "result": None,
            "timestamp": now,
            "started_at": now,
            "completed_at": None,
        }

        self.tool_executions[execution_id] = execution_data

        if agent_id in self.agents:
            self.agents[agent_id]["tool_executions"].append(execution_id)

        # Roadmap §10 — surface MITRE ATT&CK techniques per tool. Lets
        # defensive consumers map a Strix scan into their own ATT&CK
        # telemetry. Field is always present (empty list when the tool
        # isn't annotated) so downstream parsers don't need to handle
        # absence.
        mitre_techniques: list[str] = []
        try:
            from strix.tools.registry import get_tool_mitre_techniques

            mitre_techniques = list(get_tool_mitre_techniques(tool_name))
        except Exception:  # noqa: BLE001
            logger.debug("MITRE technique lookup failed", exc_info=True)

        # Roadmap §17.6 / §18 row 10 — tool-output provenance / trust-taint.
        # Always present on the event so the agent's reasoning loop has
        # a structural signal about whether to weight this tool's output
        # as trusted (KEV / OSV) or adversarial (HTTP body from target).
        # Default policy from `get_tool_provenance` falls back to "target"
        # for sandbox_execution=True, "framework" for in-process tools.
        provenance: str = "target"
        try:
            from strix.tools.registry import get_tool_provenance

            provenance = get_tool_provenance(tool_name)
        except Exception:  # noqa: BLE001
            logger.debug("provenance lookup failed", exc_info=True)

        # Roadmap §4: agent + target context inlined onto the actor block
        # so `tool.execution.*` events are self-contained.
        ctx = self._resolve_tool_event_context(agent_id, args)

        # Stash on the execution record so update_tool_execution can
        # re-emit the same context without re-resolving (consistent
        # across started/updated; cheap).
        execution_data["agent_name"] = ctx.get("agent_name")
        execution_data["agent_category"] = ctx.get("agent_category")
        execution_data["target"] = ctx.get("target")
        execution_data["provenance"] = provenance

        actor: dict[str, Any] = {
            "agent_id": agent_id,
            "agent_name": ctx.get("agent_name"),
            "agent_category": ctx.get("agent_category"),
            "tool_name": tool_name,
            "execution_id": execution_id,
            "target": ctx.get("target"),
            "mitre_techniques": mitre_techniques,
            "provenance": provenance,
        }

        self._emit_event(
            "tool.execution.started",
            actor=actor,
            payload={"args": args},
            status="running",
            source="strix.tools",
        )

        return execution_id

    def update_tool_execution(
        self,
        execution_id: int,
        status: str,
        result: Any | None = None,
    ) -> None:
        if execution_id not in self.tool_executions:
            return

        tool_data = self.tool_executions[execution_id]
        tool_data["status"] = status
        tool_data["result"] = result
        tool_data["completed_at"] = datetime.now(UTC).isoformat()

        tool_name = str(tool_data.get("tool_name", "unknown"))
        agent_id = str(tool_data.get("agent_id", "unknown"))
        error_payload = result if status in {"error", "failed"} else None

        # Reuse the context resolved at `started` time. If somehow it
        # wasn't stashed (legacy / replay path), resolve now.
        if (
            "agent_name" not in tool_data
            or "agent_category" not in tool_data
            or "target" not in tool_data
        ):
            ctx = self._resolve_tool_event_context(agent_id, tool_data.get("args"))
        else:
            ctx = {
                "agent_name": tool_data.get("agent_name"),
                "agent_category": tool_data.get("agent_category"),
                "target": tool_data.get("target"),
            }

        # Re-attach provenance from the started-event so the updated
        # event is self-contained too. Falls back to a fresh lookup
        # when missing from the stash.
        provenance = tool_data.get("provenance")
        if not isinstance(provenance, str) or not provenance:
            try:
                from strix.tools.registry import get_tool_provenance

                provenance = get_tool_provenance(tool_name)
            except Exception:  # noqa: BLE001
                provenance = "target"

        self._emit_event(
            "tool.execution.updated",
            actor={
                "agent_id": agent_id,
                "agent_name": ctx.get("agent_name"),
                "agent_category": ctx.get("agent_category"),
                "tool_name": tool_name,
                "execution_id": execution_id,
                "target": ctx.get("target"),
                "provenance": provenance,
            },
            payload={"result": result},
            status=status,
            error=error_payload,
            source="strix.tools",
        )

        if tool_name == "create_vulnerability_report":
            finding_status = "reviewed" if status == "completed" else "rejected"
            self._emit_event(
                "finding.reviewed",
                actor={"agent_id": agent_id, "tool_name": tool_name},
                payload={"execution_id": execution_id, "result": result},
                status=finding_status,
                error=error_payload,
                source="strix.findings",
            )

    def update_agent_status(
        self,
        agent_id: str,
        status: str,
        error_message: str | None = None,
    ) -> None:
        if agent_id in self.agents:
            self.agents[agent_id]["status"] = status
            self.agents[agent_id]["updated_at"] = datetime.now(UTC).isoformat()
            if error_message:
                self.agents[agent_id]["error_message"] = error_message

        self._emit_event(
            "agent.status.updated",
            actor={"agent_id": agent_id},
            payload={"error_message": error_message},
            status=status,
            error=error_message,
            source="strix.agents",
        )

    def set_scan_config(self, config: dict[str, Any]) -> None:
        self.scan_config = config
        update_payload: dict[str, Any] = {
            "targets": config.get("targets", []),
            "user_instructions": config.get("user_instructions", ""),
            "max_iterations": config.get("max_iterations", 200),
            "scan_mode": config.get("scan_mode"),
            "scope_mode": config.get("scope_mode"),
            "model_name": config.get("model_name") or Config.get("strix_llm"),
        }
        # engine-wishlist §3 — target metadata lands in
        # run_meta.json so wrappers can verify the engine received
        # what was passed.
        if config.get("target_metadata"):
            update_payload["target_metadata"] = config["target_metadata"]
        # engine-wishlist §6 — explicit project_id in scan_config
        # beats the env-derived value captured at tracer
        # construction. Stamp into run_meta.json so the wrapper
        # can verify the engine saw it.
        if config.get("project_id"):
            self._project_id = str(config["project_id"]).strip() or None
        if self._project_id:
            update_payload["project_id"] = self._project_id
        self.run_metadata.update(update_payload)
        self._set_association_properties(
            {
                "run_id": self.run_id,
                "run_name": self.run_name or "",
                "targets": config.get("targets", []),
                "max_iterations": config.get("max_iterations", 200),
            }
        )
        self._emit_event(
            "run.configured",
            payload={"scan_config": config},
            status="configured",
            source="strix.run",
        )

        # One target.started per target. Per-target IDs let consumers join
        # the target.completed events back to these without string matching.
        # Roadmap §1.
        for raw in (config.get("targets") or []):
            normalized = _normalize_target_for_events(raw)
            if normalized is None:
                continue
            target_id = f"target-{len(self._targets_started) + 1:04d}"
            self._targets_started[target_id] = normalized
            self._emit_event(
                "target.started",
                payload={
                    "target_id": target_id,
                    "value": normalized["value"],
                    "type": normalized.get("type"),
                },
                status="running",
                source="strix.run",
            )

        # run.test_plan — deterministic outer envelope of "things this run
        # could find" given how Strix is wired today. Emitted right after
        # target.started so consumers reading in order see (1) what's being
        # scanned, then (2) what it's planned to check. Roadmap §1.
        from strix.telemetry.test_plan import build_test_plan

        dns_only = bool(config.get("dns_only")) or os.environ.get("STRIX_DNS_ONLY") == "1"
        test_plan = build_test_plan(config, dns_only=dns_only)
        self._emit_event(
            "run.test_plan",
            payload=test_plan,
            status="configured",
            source="strix.run",
        )

    def save_run_data(self, mark_complete: bool = False) -> None:
        try:
            run_dir = self.get_run_dir()
            if mark_complete:
                if self.end_time is None:
                    self.end_time = datetime.now(UTC).isoformat()
                self.run_metadata["end_time"] = self.end_time
                self.run_metadata["status"] = "completed"

            # Compliance posture (roadmap §16). Attached to run_metadata
            # so it lands in run_meta.json + run.summary event. Wrappers
            # render the cadence_status badge + audit-log-retention
            # contract.
            try:
                from strix.telemetry import compliance

                # days_since_last_scan is computed by the wrapper (we
                # don't yet read prior runs from the runs dir; that's
                # a §16 wrapper-side row). When None, the field is
                # omitted from the posture block.
                self.run_metadata["compliance_posture"] = (
                    compliance.build_compliance_posture()
                )
            except Exception:  # noqa: BLE001
                logger.debug("compliance_posture build failed", exc_info=True)

            # Vendor-risk score (roadmap §16 PR #133). Always derived,
            # always lands in run_meta.json — wrappers can show or hide
            # based on whether `--vendor-mode` was set, but the score
            # itself is informational regardless.
            try:
                from strix.telemetry.vendor_risk import compute_vendor_risk_score

                self.run_metadata["vendor_risk"] = compute_vendor_risk_score(
                    list(self.vulnerability_reports),
                    self.run_metadata,
                )
            except Exception:  # noqa: BLE001
                logger.debug("vendor_risk score derivation failed", exc_info=True)

            # Always write run_meta.json — small, idempotent, lets any consumer
            # reconstruct the scan config from a structured artifact instead of
            # parsing CLI args or env vars at runtime. Roadmap §5.
            try:
                run_meta_file = run_dir / "run_meta.json"
                with run_meta_file.open("w", encoding="utf-8") as f:
                    json.dump(
                        self._sanitize_data(self.run_metadata),
                        f,
                        indent=2,
                        ensure_ascii=False,
                    )
            except (OSError, TypeError):
                logger.warning("Failed to write run_meta.json", exc_info=True)

            # MA-S2 P0-APM-C — emit `simulation_run.json` at scan
            # completion. This is the adversarial-AI-simulation
            # attestation artefact APM-1.2 requires. Always
            # emitted (no opt-out env yet — auditors need the
            # file present; gaps are surfaced via null / 0 values
            # within the file, not via missing files).
            if mark_complete:
                try:
                    from strix.telemetry.simulation_run import (
                        build_simulation_run,
                    )
                    sim_summary = build_simulation_run(self)
                    sim_file = run_dir / "simulation_run.json"
                    with sim_file.open("w", encoding="utf-8") as f:
                        json.dump(sim_summary, f, indent=2, ensure_ascii=False)
                except (OSError, TypeError, ImportError):
                    logger.debug(
                        "Failed to write simulation_run.json", exc_info=True,
                    )

                # MA-S2 P0-APM-A — emit `attack_paths.jsonl` at
                # scan completion. This is the attack-path
                # attestation artefact APM-1.1 requires. ALWAYS
                # written (even when zero paths qualify) so the
                # auditor sees the explicit "we tried"
                # attestation signal.
                try:
                    from strix.telemetry.attack_paths import (
                        write_attack_paths_jsonl,
                    )
                    write_attack_paths_jsonl(
                        tracer=self,
                        run_dir=run_dir,
                        run_id=self.run_metadata.get("run_id"),
                    )
                except Exception:
                    logger.debug(
                        "Failed to write attack_paths.jsonl",
                        exc_info=True,
                    )

                # MA-S2 P0-APM-B — apply contextual triage rules
                # (R9 + R10) AFTER attack_paths.jsonl has been
                # written. R9 downgrades unreachable HIGH/CRITICAL
                # findings to p4_suppressible; R10 upgrades chain-
                # first-link findings to p0_emergency when the
                # chain has critical severity. Also backfills
                # attack_path_membership + max_chained_severity
                # from the loaded paths (couldn't be done at
                # emit time — paths weren't built yet).
                try:
                    from strix.llm.contextual_triage_rules import (
                        apply_contextual_triage_rules,
                        load_attack_paths,
                    )
                    paths = load_attack_paths(run_dir)
                    apply_contextual_triage_rules(
                        findings=self.vulnerability_reports,
                        attack_paths=paths,
                    )
                except Exception:
                    logger.debug(
                        "Failed to apply contextual triage rules",
                        exc_info=True,
                    )

            # engine-wishlist §4 — emit `assets.discovered.jsonl`
            # alongside `run_meta.json`. Modules that discover
            # assets during a scan (cloud_attack_paths discovery,
            # future recon agents) append to
            # `tracer.discovered_assets` and we flush here. Skipped
            # silently when the list is empty per the wishlist
            # "engine runs that don't produce discoveries emit an
            # empty file or omit it entirely" contract.
            if self.discovered_assets:
                try:
                    assets_file = run_dir / "assets.discovered.jsonl"
                    with assets_file.open("w", encoding="utf-8") as f:
                        for asset_d in self.discovered_assets:
                            # engine-wishlist §6 — stamp project_id
                            # so the wrapper can scope its KG / dedup
                            # ledger to one project across N targets.
                            stamped = dict(asset_d)
                            if self._project_id:
                                stamped.setdefault(
                                    "project_id", self._project_id,
                                )
                            f.write(
                                json.dumps(
                                    self._sanitize_data(stamped),
                                    ensure_ascii=False,
                                )
                            )
                            f.write("\n")
                except (OSError, TypeError):
                    logger.warning(
                        "Failed to write assets.discovered.jsonl",
                        exc_info=True,
                    )

            # engine-wishlist §8 — flush `kg_delta.jsonl`. Nodes
            # first (so an `add_edge` within the same scan never
            # references an unknown id), then edges. Same project_id
            # stamp as §4 / §6 — wrapper's KG store scopes the
            # cross-scan union by project. No file when empty.
            if self.kg_node_deltas or self.kg_edge_deltas:
                try:
                    kg_file = run_dir / "kg_delta.jsonl"
                    with kg_file.open("w", encoding="utf-8") as f:
                        for row in self.kg_node_deltas:
                            stamped = dict(row)
                            if self._project_id:
                                stamped.setdefault(
                                    "project_id", self._project_id,
                                )
                            f.write(
                                json.dumps(
                                    self._sanitize_data(stamped),
                                    ensure_ascii=False,
                                )
                            )
                            f.write("\n")
                        for row in self.kg_edge_deltas:
                            stamped = dict(row)
                            if self._project_id:
                                stamped.setdefault(
                                    "project_id", self._project_id,
                                )
                            f.write(
                                json.dumps(
                                    self._sanitize_data(stamped),
                                    ensure_ascii=False,
                                )
                            )
                            f.write("\n")
                except (OSError, TypeError):
                    logger.warning(
                        "Failed to write kg_delta.jsonl",
                        exc_info=True,
                    )

            # Roadmap §16 PR #127 — cryptographically-signed audit trail.
            # Sign the chain's terminal hash (recorded via per-event
            # `event_hash` field on every events.jsonl line) at run-end.
            # No-op when STRIX_SIGNING_KEY / STRIX_SIGNING_CMD aren't set
            # — chain hash is still recorded so a wrapper that has a key
            # can verify retroactively. Writes `run.signature.json` only
            # when run completion is being marked (avoids partial-state
            # signatures on early exits).
            if mark_complete:
                try:
                    from strix.telemetry.audit_trail import sign_chain_terminal

                    signature_block = sign_chain_terminal(self._last_event_hash)
                    signature_block["event_count"] = int(self._event_count)
                    signature_block["run_id"] = self.run_id
                    signature_block["run_name"] = self.run_name
                    signature_file = run_dir / "run.signature.json"
                    with signature_file.open("w", encoding="utf-8") as f:
                        json.dump(
                            signature_block, f, indent=2, ensure_ascii=False,
                        )
                except (OSError, TypeError):
                    logger.warning("Failed to write run.signature.json", exc_info=True)
                except Exception:  # noqa: BLE001
                    logger.debug("audit-trail signing failed", exc_info=True)

            # RLHF Phase 1 / A1 — per-finding trajectory.jsonl.
            # Built post-hoc by walking events.jsonl. The labeler in
            # the wrapper grades the agent's reasoning trail; the FP
            # classifier consumes trajectory features (iterations_to_
            # emit, time_to_emit_seconds, exploration_breadth) for
            # training. Best-effort — failures don't change exit code.
            if mark_complete and self.vulnerability_reports:
                try:
                    from strix.telemetry.trajectory_capture import (
                        write_trajectory_jsonl,
                    )

                    write_trajectory_jsonl(
                        run_dir=run_dir,
                        findings=list(self.vulnerability_reports),
                    )
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "trajectory.jsonl write failed", exc_info=True,
                    )

            # Persist the check summary so downstream consumers can render
            # negative-coverage assertions ("we tested X for Y, clean") without
            # re-aggregating events.jsonl. Empty when no checks were run.
            try:
                checks_summary_file = run_dir / "checks_summary.json"
                summary = self.get_check_summary()
                if summary["total"] > 0:
                    with checks_summary_file.open("w", encoding="utf-8") as f:
                        json.dump(
                            {
                                "schema_version": 1,
                                "run_id": self.run_id,
                                "run_name": self.run_name,
                                "generated_at": datetime.now(UTC).isoformat(),
                                **summary,
                            },
                            f,
                            indent=2,
                            ensure_ascii=False,
                        )
            except (OSError, TypeError):
                logger.warning("Failed to write checks_summary.json", exc_info=True)

            # Promoted coverage attestation (roadmap §17.1). Per-check atomic
            # records grouped into negative / inconclusive / vulnerable
            # buckets — designed for auditor / GRC / bug-bounty consumption.
            # Only emitted when checks were run; structured for future
            # cryptographic signing under §16.
            try:
                attestation = self.build_coverage_attestation()
                if attestation["summary"]["total"] > 0:
                    attestation_file = run_dir / "coverage_attestation.json"
                    with attestation_file.open("w", encoding="utf-8") as f:
                        json.dump(
                            self._sanitize_data(attestation),
                            f,
                            indent=2,
                            ensure_ascii=False,
                            default=str,
                        )
            except (OSError, TypeError):
                logger.warning(
                    "Failed to write coverage_attestation.json", exc_info=True
                )

            # Coverage matrix evaluation (roadmap §7.0). Compares the required
            # category set per (target_type, scan_mode) against the categories
            # that actually have a `check.completed` event. Emits one
            # `run.coverage_gap` event per scan and persists `coverage.json`.
            # Only runs at run completion (mark_complete=True) — a partial
            # save during the run shouldn't claim coverage.
            if mark_complete:
                try:
                    self._evaluate_coverage(run_dir)
                except Exception:  # noqa: BLE001
                    logger.warning("coverage evaluation failed", exc_info=True)

            if self.final_scan_result:
                penetration_test_report_file = run_dir / "penetration_test_report.md"
                with penetration_test_report_file.open("w", encoding="utf-8") as f:
                    f.write("# Security Penetration Test Report\n\n")
                    f.write(
                        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                    )
                    f.write(f"{self.final_scan_result}\n")
                    # Append a coverage-assertions section based on the
                    # check.completed events. Roadmap §11. Only emitted when
                    # at least one check ran — silence is honest when the
                    # agent didn't use the check API yet.
                    coverage_md = self._format_coverage_assertions()
                    if coverage_md:
                        f.write("\n")
                        f.write(coverage_md)
                logger.info(
                    "Saved final penetration test report to: %s",
                    penetration_test_report_file,
                )

            if self.vulnerability_reports:
                vuln_dir = run_dir / "vulnerabilities"
                vuln_dir.mkdir(exist_ok=True)

                new_reports = [
                    report
                    for report in self.vulnerability_reports
                    if report["id"] not in self._saved_vuln_ids
                ]

                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                sorted_reports = sorted(
                    self.vulnerability_reports,
                    key=lambda report: (
                        severity_order.get(report["severity"], 5),
                        report["timestamp"],
                    ),
                )

                for report in new_reports:
                    vuln_file = vuln_dir / f"{report['id']}.md"
                    with vuln_file.open("w", encoding="utf-8") as f:
                        f.write(f"# {report.get('title', 'Untitled Vulnerability')}\n\n")
                        f.write(f"**ID:** {report.get('id', 'unknown')}\n")
                        f.write(f"**Severity:** {report.get('severity', 'unknown').upper()}\n")
                        f.write(f"**Found:** {report.get('timestamp', 'unknown')}\n")
                        if report.get("fingerprint"):
                            f.write(
                                f"**Fingerprint:** {report['fingerprint']} "
                                f"(v{report.get('fingerprint_version', 1)})\n"
                            )

                        # Existing fields kept in their original positions for
                        # downstream parsers that anchor on order; new fields
                        # (Category, Verification) appended at the end of the
                        # metadata block.
                        metadata_fields: list[tuple[str, Any]] = [
                            ("Target", report.get("target")),
                            ("Endpoint", report.get("endpoint")),
                            ("Method", report.get("method")),
                            ("CVE", report.get("cve")),
                            ("CWE", report.get("cwe")),
                        ]
                        cvss_score = report.get("cvss")
                        if cvss_score is not None:
                            metadata_fields.append(("CVSS", cvss_score))
                        if report.get("category"):
                            metadata_fields.append(("Category", report["category"]))
                        if report.get("verification_status"):
                            metadata_fields.append(
                                ("Verification", report["verification_status"])
                            )
                        if report.get("owasp_top_10"):
                            metadata_fields.append(
                                ("OWASP Top 10", report["owasp_top_10"])
                            )
                        if report.get("owasp_api_top_10"):
                            metadata_fields.append(
                                ("OWASP API Top 10", report["owasp_api_top_10"])
                            )
                        if report.get("mitre_attack"):
                            metadata_fields.append(
                                ("MITRE ATT&CK", ", ".join(report["mitre_attack"]))
                            )
                        if report.get("is_kev") is True:
                            kev_label = "yes"
                            if report.get("kev_added_at"):
                                kev_label = f"yes (added {report['kev_added_at']})"
                            metadata_fields.append(("CISA KEV", kev_label))

                        for label, value in metadata_fields:
                            if value:
                                f.write(f"**{label}:** {value}\n")

                        f.write("\n## Description\n\n")
                        description = report.get("description") or "No description provided."
                        f.write(f"{description}\n\n")

                        if report.get("impact"):
                            f.write("## Impact\n\n")
                            f.write(f"{report['impact']}\n\n")

                        if report.get("technical_analysis"):
                            f.write("## Technical Analysis\n\n")
                            f.write(f"{report['technical_analysis']}\n\n")

                        if report.get("poc_description") or report.get("poc_script_code"):
                            f.write("## Proof of Concept\n\n")
                            if report.get("poc_description"):
                                f.write(f"{report['poc_description']}\n\n")
                            if report.get("poc_script_code"):
                                f.write("```\n")
                                f.write(f"{report['poc_script_code']}\n")
                                f.write("```\n\n")

                        if report.get("code_locations"):
                            f.write("## Code Analysis\n\n")
                            for i, loc in enumerate(report["code_locations"]):
                                prefix = f"**Location {i + 1}:**"
                                file_ref = loc.get("file", "unknown")
                                line_ref = ""
                                if loc.get("start_line") is not None:
                                    if loc.get("end_line") and loc["end_line"] != loc["start_line"]:
                                        line_ref = f" (lines {loc['start_line']}-{loc['end_line']})"
                                    else:
                                        line_ref = f" (line {loc['start_line']})"
                                f.write(f"{prefix} `{file_ref}`{line_ref}\n")
                                if loc.get("label"):
                                    f.write(f"  {loc['label']}\n")
                                if loc.get("snippet"):
                                    f.write(f"  ```\n  {loc['snippet']}\n  ```\n")
                                if loc.get("fix_before") or loc.get("fix_after"):
                                    f.write("\n  **Suggested Fix:**\n")
                                    f.write("```diff\n")
                                    if loc.get("fix_before"):
                                        for line in loc["fix_before"].splitlines():
                                            f.write(f"- {line}\n")
                                    if loc.get("fix_after"):
                                        for line in loc["fix_after"].splitlines():
                                            f.write(f"+ {line}\n")
                                    f.write("```\n")
                                f.write("\n")

                        if report.get("remediation_steps"):
                            f.write("## Remediation\n\n")
                            f.write(f"{report['remediation_steps']}\n\n")

                    self._saved_vuln_ids.add(report["id"])

                vuln_csv_file = run_dir / "vulnerabilities.csv"
                with vuln_csv_file.open("w", encoding="utf-8", newline="") as f:
                    import csv

                    # Original 5 columns first; new columns appended so
                    # positional readers keep working.
                    fieldnames = [
                        "id",
                        "title",
                        "severity",
                        "timestamp",
                        "file",
                        "category",
                        "verification_status",
                        "owasp_top_10",
                        "owasp_api_top_10",
                        "mitre_attack",
                        "is_kev",
                        "fingerprint",
                    ]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()

                    for report in sorted_reports:
                        mitre = report.get("mitre_attack") or []
                        writer.writerow(
                            {
                                "id": report["id"],
                                "title": report["title"],
                                # Roadmap §4: machine-readable outputs use stable
                                # lowercase severity. CLI / markdown rendering may
                                # uppercase for display, but every parser-bound
                                # surface (CSV, JSON, JSONL events, SARIF) emits
                                # the canonical lowercased token so wrappers can
                                # `==` compare without case-folding.
                                "severity": (report.get("severity") or "").lower(),
                                "category": report.get("category", ""),
                                "verification_status": report.get("verification_status", ""),
                                "owasp_top_10": report.get("owasp_top_10", ""),
                                "owasp_api_top_10": report.get("owasp_api_top_10", ""),
                                "mitre_attack": ",".join(mitre) if mitre else "",
                                "is_kev": "" if report.get("is_kev") is None else str(report["is_kev"]).lower(),
                                "fingerprint": report.get("fingerprint", ""),
                                "timestamp": report["timestamp"],
                                "file": f"vulnerabilities/{report['id']}.md",
                            }
                        )

                # vulnerabilities.json — full structured dump of every finding
                # with all fields the agent set. Same data as the per-finding
                # markdown, no parsing required. Roadmap §5.
                vuln_json_file = run_dir / "vulnerabilities.json"
                with vuln_json_file.open("w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "schema_version": 1,
                            "run_id": self.run_id,
                            "run_name": self.run_name,
                            "generated_at": datetime.now(UTC).isoformat(),
                            "count": len(sorted_reports),
                            "findings": sorted_reports,
                        },
                        f,
                        indent=2,
                        ensure_ascii=False,
                        default=str,
                    )

                if new_reports:
                    logger.info(
                        "Saved %d new vulnerability report(s) to: %s",
                        len(new_reports),
                        vuln_dir,
                    )
                logger.info("Updated vulnerability index: %s", vuln_csv_file)

            logger.info("📊 Essential scan data saved to: %s", run_dir)
            if mark_complete and not self._run_completed_emitted:
                # Emit per-target completion events first — consumers track
                # progress per-target, so the summary should arrive after
                # all per-target rollups are visible.
                self._emit_target_completed_events()
                # Emit run.summary next so consumers receiving events in
                # order see the structured summary before the terminal
                # run.completed signal. Also persist run_summary.json so
                # filesystem consumers (CI, dashboard scrapers) see the
                # same payload without parsing events.jsonl.
                summary_payload = self.build_run_summary()
                try:
                    summary_path = run_dir / "run_summary.json"
                    with summary_path.open("w", encoding="utf-8") as f:
                        json.dump(summary_payload, f, indent=2, ensure_ascii=False, default=str)
                except OSError:
                    logger.exception("failed to write run_summary.json")
                self._emit_run_summary_event(summary_payload)
                self._emit_event(
                    "run.completed",
                    payload={
                        "duration_seconds": self._calculate_duration(),
                        "vulnerability_count": len(self.vulnerability_reports),
                    },
                    status="completed",
                    source="strix.run",
                    include_run_metadata=True,
                )
                self._run_completed_emitted = True

        except (OSError, RuntimeError):
            logger.exception("Failed to save scan data")

    def _calculate_duration(self) -> float:
        try:
            start = datetime.fromisoformat(self.start_time.replace("Z", "+00:00"))
            if self.end_time:
                end = datetime.fromisoformat(self.end_time.replace("Z", "+00:00"))
                return (end - start).total_seconds()
        except (ValueError, TypeError):
            pass
        return 0.0

    def get_agent_tools(self, agent_id: str) -> list[dict[str, Any]]:
        return [
            exec_data
            for exec_data in list(self.tool_executions.values())
            if exec_data.get("agent_id") == agent_id
        ]

    def get_real_tool_count(self) -> int:
        return sum(
            1
            for exec_data in list(self.tool_executions.values())
            if exec_data.get("tool_name") not in ["scan_start_info", "subagent_start_info"]
        )

    def get_total_llm_stats(self) -> dict[str, Any]:
        from strix.tools.agents_graph.agents_graph_actions import (
            _agent_instances,
            _completed_agent_llm_totals,
            _agent_llm_stats_lock,
        )

        with _agent_llm_stats_lock:
            completed_totals = dict(_completed_agent_llm_totals)
            active_agents = list(_agent_instances.values())

        total_stats = {
            "input_tokens": int(completed_totals.get("input_tokens", 0) or 0),
            "output_tokens": int(completed_totals.get("output_tokens", 0) or 0),
            "cached_tokens": int(completed_totals.get("cached_tokens", 0) or 0),
            "cost": float(completed_totals.get("cost", 0.0) or 0.0),
            "requests": int(completed_totals.get("requests", 0) or 0),
        }

        for agent_instance in active_agents:
            if hasattr(agent_instance, "llm") and hasattr(agent_instance.llm, "_total_stats"):
                agent_stats = agent_instance.llm._total_stats
                total_stats["input_tokens"] += agent_stats.input_tokens
                total_stats["output_tokens"] += agent_stats.output_tokens
                total_stats["cached_tokens"] += agent_stats.cached_tokens
                total_stats["cost"] += agent_stats.cost
                total_stats["requests"] += agent_stats.requests

        total_stats["cost"] = round(total_stats["cost"], 4)

        return {
            "total": total_stats,
            "total_tokens": total_stats["input_tokens"] + total_stats["output_tokens"],
        }

    def update_streaming_content(self, agent_id: str, content: str) -> None:
        self.streaming_content[agent_id] = content

    def clear_streaming_content(self, agent_id: str) -> None:
        self.streaming_content.pop(agent_id, None)

    def get_streaming_content(self, agent_id: str) -> str | None:
        return self.streaming_content.get(agent_id)

    def finalize_streaming_as_interrupted(self, agent_id: str) -> str | None:
        content = self.streaming_content.pop(agent_id, None)
        if content and content.strip():
            self.interrupted_content[agent_id] = content
            self.log_chat_message(
                content=content,
                role="assistant",
                agent_id=agent_id,
                metadata={"interrupted": True},
            )
            return content

        return self.interrupted_content.pop(agent_id, None)

    def cleanup(self) -> None:
        self.save_run_data(mark_complete=True)
