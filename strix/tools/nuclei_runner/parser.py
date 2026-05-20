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
#
# `flow:` was added 2026-05-21: nuclei's flow-control DSL composes
# multi-step HTTP probes (`flow: http(1) && http(2)`); without
# implementing the DSL, a template like CVE-2025-24016 has http(1)
# as an `internal: true` precondition matcher with `negative: true`
# (i.e. "if NameError isn't in body — keep going") and http(2) as
# the real exploit probe. Our interpreter would fire on http(1)
# alone, producing a false positive on ANY 200-OK page. Mark
# `flow:` as unsupported so these templates are skipped cleanly.
_UNSUPPORTED_TOP_KEYS = frozenset({
    "workflows", "network", "dns", "file", "code", "javascript",
    "headless", "websocket", "whois", "ssl", "tcp",
    "flow",
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
class RawHttpRequest:
    """One raw-HTTP probe parsed from a nuclei template's `raw:`
    block. The block looks like:

        - |
          GET /icons/.%2e/.%2e/etc/passwd HTTP/1.1
          Host: {{Hostname}}
          User-Agent: ...

          (optional body bytes)

    Iter-16 (2026-05-21) — strix's pure-Python interpreter
    previously skipped raw-HTTP probes entirely. Measured: 2260/4000
    (≈56%) of CVE templates use this shape, including canonical
    ones like CVE-2021-41773. Now parsed into structured form so
    the interpreter can execute them without shelling to the nuclei
    binary."""
    method: str = "GET"
    # Path-with-querystring as it appears in the raw request-line.
    # Will still contain nuclei interpolation placeholders
    # (`{{Hostname}}`, `{{BaseURL}}`, `{{interactsh-url}}`) — the
    # interpreter resolves these before sending.
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    # Raw original text — kept for debugging and to let the
    # interpreter re-parse if our structured form drops detail.
    raw_text: str = ""


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
    raw: list[str] = field(default_factory=list)   # raw text — preserved
    raw_requests: list[RawHttpRequest] = field(default_factory=list)
    # When True, treat this request entry as raw-HTTP-driven
    # (interpreter iterates raw_requests instead of paths).
    is_raw: bool = False


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
    """Parse one matcher dict; return None when type is unsupported
    OR when the matcher is internal-only (`internal: true`).

    `internal: true` matchers are precondition signals used by nuclei's
    `flow:` DSL — they don't represent a real vuln hit, they just gate
    whether the next HTTP step runs. We strip them at parse time so
    the interpreter never fires on them. Added 2026-05-21 after
    measuring iter-16: CVE-2025-24016 (Wazuh) was firing as a false
    positive on ANY 200-OK page because its internal precondition
    matcher (`negative: NameError not in body`) was treated as a real
    match signal.
    """
    if not isinstance(d, dict):
        return None
    if bool(d.get("internal")):
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


def _parse_raw_http_block(raw_text: str) -> RawHttpRequest | None:
    """Parse one multi-line raw-HTTP block into structured form.

    A raw block looks like:

        GET /icons/.%2e/.%2e/etc/passwd HTTP/1.1
        Host: {{Hostname}}
        User-Agent: ...
        Content-Type: application/x-www-form-urlencoded

        body bytes here

    Returns None when the request-line is unparseable (malformed
    block). The caller's loop tolerates per-block None and skips.

    Nuclei interpolation placeholders (`{{Hostname}}`,
    `{{BaseURL}}`, `{{interactsh-url}}`) are left in-place — the
    interpreter resolves them at send time.
    """
    if not isinstance(raw_text, str) or not raw_text.strip():
        return None

    # Split on first blank line — everything before is request-
    # line + headers; everything after is body. Match either
    # CRLF or LF blank-line conventions (nuclei templates author
    # by hand; both forms appear).
    text = raw_text.replace("\r\n", "\n")
    header_section, _, body = text.partition("\n\n")
    header_lines = [ln for ln in header_section.split("\n") if ln.strip()]
    if not header_lines:
        return None

    # Request line: METHOD SP PATH SP HTTP/X.X
    parts = header_lines[0].strip().split(" ", 2)
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    path = parts[1]
    # We ignore the HTTP version; we always send HTTP/1.1.

    headers: dict[str, str] = {}
    for hl in header_lines[1:]:
        if ":" not in hl:
            continue
        k, v = hl.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k:
            headers[k] = v

    return RawHttpRequest(
        method=method,
        path=path,
        headers=headers,
        body=body,
        raw_text=raw_text,
    )


def _parse_http_request(d: dict[str, Any]) -> HttpRequest | None:
    """Parse one HTTP probe dict.

    Supports both:
      * `path:` + `method:` + `headers:` + `body:` (structured form)
      * `raw:` list of multi-line HTTP request strings (raw form)

    Iter-16 (2026-05-21) — raw form was previously skipped at the
    interpreter level. Now parsed into RawHttpRequest objects and
    executed by the interpreter loop alongside structured-form
    probes.
    """
    if not isinstance(d, dict):
        return None

    matchers: list[Matcher] = []
    raw_matchers = d.get("matchers") or []
    matchers_condition = (d.get("matchers-condition") or "or").lower()
    dropped_matcher_count = 0
    for m in raw_matchers:
        parsed = _parse_matcher(m)
        if parsed is not None:
            matchers.append(parsed)
        else:
            dropped_matcher_count += 1
    # Fail-closed on `matchers-condition: and` when we couldn't
    # evaluate every matcher in the original list. Otherwise we'd
    # fire on the kept-matcher subset alone — which produces FPs
    # like CVE-2024-5230 (FleetCart): the template has a `dsl`
    # matcher gated on `contains_all(body, "razorpayKeyId:", ...)`
    # AND a `negative word` matcher for `razorpayKeyId: ''`. We
    # can't evaluate the dsl, but the negative word matcher fires
    # on any body lacking the razorpay string — i.e. anything that
    # isn't FleetCart. Without this gate we'd emit FleetCart vuln
    # findings against any 200-OK target. Added 2026-05-21.
    if (
        matchers_condition == "and"
        and dropped_matcher_count > 0
    ):
        return None
    stop_at_first_match = bool(d.get("stop-at-first-match", True))

    # Raw-HTTP form
    raw = d.get("raw")
    if isinstance(raw, list) and raw:
        raw_requests: list[RawHttpRequest] = []
        for entry in raw:
            parsed = _parse_raw_http_block(str(entry))
            if parsed is not None:
                raw_requests.append(parsed)
        if not raw_requests:
            return None
        if not matchers:
            # raw probes without matchers can't decide a hit — drop.
            return None
        return HttpRequest(
            raw=[str(r) for r in raw],
            raw_requests=raw_requests,
            is_raw=True,
            matchers=matchers,
            matchers_condition=matchers_condition,
            stop_at_first_match=stop_at_first_match,
        )

    # Structured form
    paths = _coerce_list(d.get("path"))
    if not paths:
        return None

    headers: dict[str, str] = {}
    h = d.get("headers")
    if isinstance(h, dict):
        for k, v in h.items():
            headers[str(k)] = str(v)

    if not matchers:
        return None

    return HttpRequest(
        method=(d.get("method") or "GET").upper(),
        paths=paths,
        headers=headers,
        body=d.get("body"),
        matchers_condition=matchers_condition,
        matchers=matchers,
        stop_at_first_match=stop_at_first_match,
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
    # Reverse-sort dirs so newer CVE-year dirs (cves/2025/, 2024/,
    # 2023/, ...) walk before older. Matters when max_templates
    # caps iteration — without this, a `tags=[cve]` filter exhausts
    # the budget on 2014-2020 templates and never reaches recent
    # high-impact CVEs. Iter-16 catch: CVE-2021-41773 was unreachable
    # in the default tag-set under the 200-template cap because the
    # bench iterates cves/2014/ → 2015/ → ... → 2020/ first and
    # accumulates ~200 hits before reaching cves/2021/.
    for root, _dirs, files in os.walk(p):
        _dirs.sort(reverse=True)
        for fname in sorted(files, reverse=True):
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
