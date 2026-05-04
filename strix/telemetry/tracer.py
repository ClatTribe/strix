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
        if code_locations:
            report["code_locations"] = code_locations

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

        self.save_run_data()
        return report_id

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

        # Roadmap §4: agent + target context inlined onto the actor block
        # so `tool.execution.*` events are self-contained.
        ctx = self._resolve_tool_event_context(agent_id, args)

        # Stash on the execution record so update_tool_execution can
        # re-emit the same context without re-resolving (consistent
        # across started/updated; cheap).
        execution_data["agent_name"] = ctx.get("agent_name")
        execution_data["agent_category"] = ctx.get("agent_category")
        execution_data["target"] = ctx.get("target")

        actor: dict[str, Any] = {
            "agent_id": agent_id,
            "agent_name": ctx.get("agent_name"),
            "agent_category": ctx.get("agent_category"),
            "tool_name": tool_name,
            "execution_id": execution_id,
            "target": ctx.get("target"),
            "mitre_techniques": mitre_techniques,
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

        self._emit_event(
            "tool.execution.updated",
            actor={
                "agent_id": agent_id,
                "agent_name": ctx.get("agent_name"),
                "agent_category": ctx.get("agent_category"),
                "tool_name": tool_name,
                "execution_id": execution_id,
                "target": ctx.get("target"),
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
        self.run_metadata.update(
            {
                "targets": config.get("targets", []),
                "user_instructions": config.get("user_instructions", ""),
                "max_iterations": config.get("max_iterations", 200),
                "scan_mode": config.get("scan_mode"),
                "scope_mode": config.get("scope_mode"),
                "model_name": config.get("model_name") or Config.get("strix_llm"),
            }
        )
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
