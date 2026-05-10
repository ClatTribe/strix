"""Nuclei template YAML parser.

Parses a `.yaml` template file from the nuclei-templates corpus
into a `Template` dataclass. We only model the HTTP subset; other
shapes are signalled via `Template.unsupported_kinds` so the
runner can skip + count them.

Example template (apache-flink-unauth.yaml)::

    id: apache-flink-unauth
    info:
      name: Apache Flink Unauthenticated
      severity: critical
      classification:
        cve-id: CVE-2020-17519
      tags: cve,flink,apache
    http:
      - method: GET
        path:
          - "{{BaseURL}}/jobmanager/logs"
        matchers-condition: and
        matchers:
          - type: word
            words: ["Apache Flink"]
          - type: status
            status: [200]

`parse_template_file(path)` returns a Template; `parse_template_dir
(dir, ...)` walks a directory yielding parsed templates.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


logger = logging.getLogger(__name__)


# Top-level template fields we DON'T support (yet) — presence makes
# the template "skip + count."
_UNSUPPORTED_TOP_KEYS = frozenset({
    "workflows", "network", "dns", "file", "code", "javascript",
    "headless", "websocket", "whois", "ssl", "tcp",
})


@dataclass
class Matcher:
    """One matcher in a probe's `matchers:` list.

    Supported types:
      * word         — substring match in `part`
      * regex        — regex match in `part`
      * status       — response status equals one of `status[]`
      * size         — response body size equals one of `size[]`
      * binary       — hex-byte match (rare, but cheap)

    Unsupported (logged + skipped):
      * dsl
      * xpath
    """
    type: str
    part: str = "body"   # body | header | response | all
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    size: list[int] = field(default_factory=list)
    binary: list[str] = field(default_factory=list)
    case_insensitive: bool = False
    condition: str = "or"   # or | and  (within a single matcher's words)
    negative: bool = False  # invert the match


@dataclass
class HttpRequest:
    """One HTTP probe in a template's `http:` list."""
    method: str = "GET"
    paths: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    matchers_condition: str = "or"   # or | and (across matchers)
    matchers: list[Matcher] = field(default_factory=list)
    stop_at_first_match: bool = True
    raw: list[str] = field(default_factory=list)  # raw HTTP requests (skipped)


@dataclass
class TemplateInfo:
    """Top-level `info:` block."""
    name: str = ""
    author: str = ""
    severity: str = ""    # info | low | medium | high | critical
    description: str = ""
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cve_id: list[str] = field(default_factory=list)
    cwe_id: list[str] = field(default_factory=list)
    cvss_score: float | None = None


@dataclass
class Template:
    """Parsed nuclei template."""
    id: str
    info: TemplateInfo
    http: list[HttpRequest] = field(default_factory=list)
    file_path: str = ""
    unsupported_kinds: list[str] = field(default_factory=list)

    @property
    def has_http(self) -> bool:
        return len(self.http) > 0

    @property
    def is_supported(self) -> bool:
        """Whether we can actually run this template natively."""
        return self.has_http and not self.unsupported_kinds


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _coerce_list(v: Any) -> list[str]:
    """Coerce string | list | None → list[str]. Tags can be CSV
    or list-shaped depending on the template author."""
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    if isinstance(v, str):
        # Tags often come as CSV.
        parts = [p.strip() for p in v.split(",") if p.strip()]
        return parts
    return [str(v)]


def _coerce_int_list(v: Any) -> list[int]:
    if v is None:
        return []
    if not isinstance(v, list):
        v = [v]
    out: list[int] = []
    for x in v:
        try:
            out.append(int(x))
        except (TypeError, ValueError):
            continue
    return out


def _parse_matcher(d: dict[str, Any]) -> Matcher | None:
    """Parse one matcher dict; return None when type is unsupported."""
    if not isinstance(d, dict):
        return None
    mtype = (d.get("type") or "").lower()
    if mtype not in {"word", "regex", "status", "size", "binary"}:
        # `dsl`, `xpath`, etc. — skip with a debug log.
        logger.debug("nuclei_runner: skipping unsupported matcher type %r", mtype)
        return None
    return Matcher(
        type=mtype,
        part=(d.get("part") or "body").lower(),
        words=_coerce_list(d.get("words")),
        regex=_coerce_list(d.get("regex")),
        status=_coerce_int_list(d.get("status")),
        size=_coerce_int_list(d.get("size")),
        binary=_coerce_list(d.get("binary")),
        case_insensitive=bool(d.get("case-insensitive") or d.get("case_insensitive")),
        condition=(d.get("condition") or "or").lower(),
        negative=bool(d.get("negative")),
    )


def _parse_http_request(d: dict[str, Any]) -> HttpRequest | None:
    """Parse one HTTP probe dict."""
    if not isinstance(d, dict):
        return None
    # Skip raw-HTTP probes for now (multi-line raw HTTP is its own
    # parsing nightmare).
    raw = d.get("raw")
    if isinstance(raw, list) and raw:
        return HttpRequest(raw=[str(r) for r in raw])

    paths = _coerce_list(d.get("path"))
    if not paths:
        return None

    headers: dict[str, str] = {}
    h = d.get("headers")
    if isinstance(h, dict):
        for k, v in h.items():
            headers[str(k)] = str(v)

    matchers: list[Matcher] = []
    for m in (d.get("matchers") or []):
        parsed = _parse_matcher(m)
        if parsed is not None:
            matchers.append(parsed)
    if not matchers:
        return None

    return HttpRequest(
        method=(d.get("method") or "GET").upper(),
        paths=paths,
        headers=headers,
        body=d.get("body"),
        matchers_condition=(d.get("matchers-condition") or "or").lower(),
        matchers=matchers,
        stop_at_first_match=bool(d.get("stop-at-first-match", True)),
    )


def _parse_info(d: dict[str, Any]) -> TemplateInfo:
    if not isinstance(d, dict):
        return TemplateInfo()
    classification = d.get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}
    cvss_score = None
    cvss_raw = (
        classification.get("cvss-score")
        or classification.get("cvss_score")
        or d.get("cvss-score")
    )
    try:
        if cvss_raw is not None:
            cvss_score = float(cvss_raw)
    except (TypeError, ValueError):
        cvss_score = None
    return TemplateInfo(
        name=str(d.get("name") or ""),
        author=str(d.get("author") or ""),
        severity=(d.get("severity") or "").lower(),
        description=str(d.get("description") or "").strip()[:8000],
        reference=_coerce_list(d.get("reference")),
        tags=_coerce_list(d.get("tags")),
        cve_id=_coerce_list(
            classification.get("cve-id") or classification.get("cve_id"),
        ),
        cwe_id=_coerce_list(
            classification.get("cwe-id") or classification.get("cwe_id"),
        ),
        cvss_score=cvss_score,
    )


def parse_template(doc: dict[str, Any], *, file_path: str = "") -> Template | None:
    """Parse a YAML-loaded template doc. Returns None when the
    minimum-required fields (id + info) are missing."""
    if not isinstance(doc, dict):
        return None
    tid = doc.get("id")
    if not isinstance(tid, str) or not tid.strip():
        return None
    tid = tid.strip()

    info = _parse_info(doc.get("info"))

    # Identify unsupported top-level kinds.
    unsupported = sorted(
        k for k in doc.keys() if k.lower() in _UNSUPPORTED_TOP_KEYS
    )

    http_requests: list[HttpRequest] = []
    for r in (doc.get("http") or doc.get("requests") or []):
        # Older templates use `requests:` instead of `http:`.
        parsed = _parse_http_request(r)
        if parsed is not None:
            http_requests.append(parsed)

    return Template(
        id=tid,
        info=info,
        http=http_requests,
        file_path=str(file_path),
        unsupported_kinds=unsupported,
    )


def parse_template_file(path: str | Path) -> Template | None:
    """Load + parse a single .yaml file."""
    import yaml
    p = Path(path)
    try:
        with p.open("r", encoding="utf-8", errors="replace") as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        logger.debug("nuclei_runner: parse failed for %s: %s", p, e)
        return None
    return parse_template(doc, file_path=str(p))


def parse_template_dir(
    dir_path: str | Path,
    *,
    tags: list[str] | None = None,
    severity: list[str] | None = None,
    template_ids: list[str] | None = None,
    only_supported: bool = True,
    max_templates: int | None = None,
) -> Iterator[Template]:
    """Walk `dir_path` recursively, yielding parsed templates that
    match the filters. Filters compose AND-style.

    Filters:
      tags          — at least one tag matches (case-insensitive)
      severity      — severity is in the list
      template_ids  — id is in the list
      only_supported — yield only `is_supported` templates
      max_templates — cap iteration count
    """
    p = Path(dir_path)
    if not p.exists() or not p.is_dir():
        return
    yielded = 0
    tags_lower = {t.lower() for t in (tags or [])}
    severity_lower = {s.lower() for s in (severity or [])}
    ids_set = {tid.strip() for tid in (template_ids or []) if tid}
    for root, _dirs, files in os.walk(p):
        for fname in files:
            if not fname.endswith((".yaml", ".yml")):
                continue
            full = Path(root) / fname
            tpl = parse_template_file(full)
            if tpl is None:
                continue
            if ids_set and tpl.id not in ids_set:
                continue
            if tags_lower:
                tpl_tags = {t.lower() for t in tpl.info.tags}
                if not (tpl_tags & tags_lower):
                    continue
            if severity_lower and tpl.info.severity not in severity_lower:
                continue
            if only_supported and not tpl.is_supported:
                continue
            yield tpl
            yielded += 1
            if max_templates is not None and yielded >= max_templates:
                return
