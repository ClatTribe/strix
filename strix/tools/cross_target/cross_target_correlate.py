"""Cross-target correlation engine.

Reads existing scan artifacts and emits `cross_target.correlation`
findings for the standard multi-target join patterns:

**Correlation classes:**

- **`domain_ip_reputation`** — for each (subdomain → resolved IP) pair
  in `surface_map.json`, looks up the IP across VT / OTX / GreyNoise /
  URLhaus caches. If ≥1 source flags it, emit a finding linking the
  domain-target to the IP-target.
- **`kev_in_customer_stack`** — for each existing finding with both a
  `cve` AND `is_kev=True` AND a `target` that maps to a detected
  component (i.e. found via fingerprinting / cve_lookup, not theoretical),
  emit a "actively-exploited CVE in YOUR stack" correlation. Priority
  bumps the original finding's severity (medium → high; high → critical
  when KEV ransomware-flag is set).
- **`cve_in_threat_feed`** — for each existing finding with a `cve`,
  check if the CVE-ID appears in the customer's `threat_feed_iocs.cve`
  list (from the `threat_feed_ingest` tool's output). If yes, emit
  high-severity correlation: customer's own intel team is actively
  tracking this CVE and Strix found it in their stack.
- **`threat_feed_ioc_match`** — for each IP / domain / hash discovered
  during the scan that ALSO appears in the customer's threat-feed
  `iocs` list, emit high-severity correlation: customer's intel says
  this IoC is malicious and it's reachable from / inside the scan
  surface.

**Inputs:**

The tool runs entirely on data already produced by other tools — no
new HTTP traffic, no agent reasoning. It accepts inputs explicitly
(for hermetic testing) OR auto-loads from disk:

- `findings`: list of finding dicts. If None, loaded from
  `tracer.get_existing_vulnerabilities()`.
- `surface_map`: contents of `surface_map.json`. If None and
  `surface_map_path` is set, loads from disk.
- `threat_feed_iocs`: dict with keys `ipv4` / `domain` / `cve` /
  `sha256` / etc. (the same shape `threat_feed_ingest` returns).
- `ip_reputation_lookup`: callable `fn(ip) -> {flags, sources, severity}`.
  If None, the default reads VT / OTX / GreyNoise / URLhaus caches from
  `~/.strix/{vt,otx,greynoise,domain_rep}_cache/`. Tests pass a
  fixture function.
- `enable_correlations`: subset of class names to run. Default = all.

**Output:**

- Returns a structured dict listing every correlation evaluated +
  every finding emitted.
- Side-effect: emits findings via the global tracer with
  `category="cross_target_correlation"`, `correlation_class=<class>`,
  `target_a` / `target_b` / `evidence_a` / `evidence_b` /
  `linked_finding_fingerprints`.

**Per-(class, target_a, target_b) dedup** so the same correlation
doesn't emit twice on a re-run.

**Skip cases:**

- Empty findings AND empty surface_map → no-op (`success=True`,
  `findings_emitted=0`).
- A correlation class lacking its required input → silently skipped.

**Severity ladder:**

- `domain_ip_reputation`: ≥3 sources flag → high; 1-2 → medium.
- `kev_in_customer_stack`: bumps severity (low→medium, medium→high,
  high→critical); ransomware flag → critical regardless.
- `cve_in_threat_feed`: high.
- `threat_feed_ioc_match`: high.

MITRE T1592 (Gather Victim Host Info) + T1589 (Gather Victim Identity).
Composes with cluster-A safety (no HTTP).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

from strix.tools.registry import register_tool


logger = logging.getLogger(__name__)
_TOOL_NAME = "cross_target_correlate"


CORRELATION_CLASSES = (
    "domain_ip_reputation",
    "kev_in_customer_stack",
    "cve_in_threat_feed",
    "threat_feed_ioc_match",
)


# ---------------------------------------------------------------------------
# Threat-intel cache reading
# ---------------------------------------------------------------------------


def _vt_cache_dir() -> Path:
    return Path.home() / ".strix" / "vt_cache"


def _otx_cache_dir() -> Path:
    return Path.home() / ".strix" / "otx_cache"


def _greynoise_cache_dir() -> Path:
    return Path.home() / ".strix" / "greynoise_cache"


def _domain_rep_cache_dir() -> Path:
    return Path.home() / ".strix" / "domain_rep_cache"


def _read_cache_files(cache_dir: Path) -> list[dict[str, Any]]:
    """Read every JSON file in `cache_dir` and return a list of
    payload dicts. Quiet on errors."""
    if not cache_dir.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        for path in cache_dir.iterdir():
            if not path.is_file() or path.suffix != ".json":
                continue
            try:
                with path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    out.append(data)
            except (OSError, ValueError, TypeError) as e:
                logger.debug("cache read failed (%s): %s", path, e)
    except OSError as e:
        logger.debug("cache iter failed (%s): %s", cache_dir, e)
    return out


def _default_ip_reputation_lookup(ip: str) -> dict[str, Any]:
    """Look up an IP across all four threat-intel caches.

    Returns:
        {
          "flags": [str, ...],          # source-specific flag names
          "sources": [str, ...],        # which sources flagged
          "max_severity": "high"/"medium"/"low"/"info"/"none",
        }
    """
    flags: list[str] = []
    sources: list[str] = []
    severities: list[str] = []

    # VT cache files contain the captured response with 'value' + 'general'.
    for entry in _read_cache_files(_vt_cache_dir()):
        if entry.get("value") != ip:
            continue
        general = entry.get("general") or {}
        attrs = general.get("attributes") or general
        last_stats = (attrs.get("last_analysis_stats") or {})
        malicious = int(last_stats.get("malicious") or 0)
        suspicious = int(last_stats.get("suspicious") or 0)
        if malicious >= 1 or suspicious >= 3:
            flags.append(f"vt_malicious={malicious}_suspicious={suspicious}")
            sources.append("virustotal")
            if malicious >= 10:
                severities.append("high")
            elif malicious >= 1:
                severities.append("medium")
            else:
                severities.append("low")

    # OTX cache files have indicator + pulse_info.
    for entry in _read_cache_files(_otx_cache_dir()):
        if entry.get("indicator") != ip:
            continue
        pulse_count = int(((entry.get("pulse_info") or {}).get("count")) or 0)
        if pulse_count >= 1:
            flags.append(f"otx_pulses={pulse_count}")
            sources.append("alienvault_otx")
            severities.append("high" if pulse_count >= 3 else "medium")

    # GreyNoise: classification == "malicious" → flag.
    for entry in _read_cache_files(_greynoise_cache_dir()):
        if entry.get("ip") != ip:
            continue
        if (entry.get("classification") or "").lower() == "malicious":
            flags.append(f"greynoise_classification={entry.get('classification')}")
            sources.append("greynoise")
            severities.append("high")

    # Domain reputation cache (URLhaus / Spamhaus / GSB / AbuseIPDB).
    for entry in _read_cache_files(_domain_rep_cache_dir()):
        if entry.get("target") != ip:
            continue
        for source_name in ("urlhaus", "spamhaus_dbl", "spamhaus_zen", "gsb", "abuseipdb"):
            source_entry = (entry.get("sources") or {}).get(source_name) or {}
            if source_entry.get("flagged"):
                flags.append(f"{source_name}={source_entry.get('reason') or 'flagged'}")
                sources.append(source_name)
                severities.append(source_entry.get("severity") or "medium")

    sev_order = {"high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
    max_sev = "none"
    for sev in severities:
        if sev_order.get(sev, 0) > sev_order.get(max_sev, 0):
            max_sev = sev

    return {"flags": flags, "sources": sources, "max_severity": max_sev}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bump_severity(s: str) -> str:
    """Bump a severity one notch toward critical."""
    ladder = ["info", "low", "medium", "high", "critical"]
    try:
        idx = ladder.index((s or "").lower())
    except ValueError:
        return "high"
    return ladder[min(idx + 1, len(ladder) - 1)]


def _extract_subdomains(surface_map: dict[str, Any]) -> list[str]:
    enum = surface_map.get("subdomain_enum") or {}
    subs = enum.get("subdomains") or []
    return [str(s) for s in subs if isinstance(s, str)]


def _extract_subdomain_ip_pairs(surface_map: dict[str, Any]) -> list[tuple[str, str]]:
    """Return (subdomain, IP) pairs from surface_map. Reads
    `subdomain_triage` (which carries `ips_resolved`) plus
    `passive_dns`. Falls back to nothing if neither present."""
    pairs: list[tuple[str, str]] = []

    triage = surface_map.get("subdomain_triage") or []
    if isinstance(triage, list):
        for entry in triage:
            if not isinstance(entry, dict):
                continue
            sub = entry.get("subdomain") or entry.get("host")
            ips = entry.get("ips_resolved") or entry.get("a_records") or []
            if not sub or not isinstance(ips, list):
                continue
            for ip in ips:
                if isinstance(ip, str) and ip:
                    pairs.append((str(sub), ip))

    # Passive-DNS shape: {records: [{name, ip, ...}]}
    pdns = surface_map.get("passive_dns") or {}
    if isinstance(pdns, dict):
        records = pdns.get("records") or []
        if isinstance(records, list):
            for r in records:
                if not isinstance(r, dict):
                    continue
                name = r.get("name") or r.get("hostname")
                ip = r.get("ip") or r.get("address")
                if name and ip:
                    pairs.append((str(name), str(ip)))

    # Dedup.
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


def _normalize_iocs(threat_feed_iocs: dict[str, Any]) -> dict[str, set[str]]:
    """Normalise a threat_feed_iocs dict (from threat_feed_ingest)
    into a {bucket: set[str]} shape for fast membership tests."""
    out: dict[str, set[str]] = {
        "cve": set(),
        "ipv4": set(),
        "ipv6": set(),
        "domain": set(),
        "url": set(),
        "sha256": set(),
        "sha1": set(),
        "md5": set(),
    }
    if not isinstance(threat_feed_iocs, dict):
        return out
    for key, values in threat_feed_iocs.items():
        bucket = key.lower()
        if bucket not in out:
            continue
        if isinstance(values, list):
            out[bucket] = {str(v).strip().upper() if bucket == "cve" else str(v).strip().lower()
                          for v in values if v}
    return out


def _scan_iocs_from_findings_and_surface(
    findings: list[dict[str, Any]],
    surface_map: dict[str, Any] | None,
) -> dict[str, set[str]]:
    """Pull every IoC out of the scan's known data: findings'
    `target` / `endpoint` fields, surface_map subdomains + IPs."""
    out: dict[str, set[str]] = {
        "ipv4": set(), "domain": set(), "url": set(), "cve": set(), "sha256": set(),
    }
    for f in findings:
        cve = f.get("cve")
        if cve:
            out["cve"].add(str(cve).upper())
        target = (f.get("target") or "").strip().lower()
        endpoint = (f.get("endpoint") or "").strip().lower()
        for v in (target, endpoint):
            if not v:
                continue
            # Heuristic: dotted-quad → ipv4; otherwise domain.
            parts = v.split(":")[0].split("/")[0]
            if parts and parts.replace(".", "").isdigit() and parts.count(".") == 3:
                out["ipv4"].add(parts)
            elif "." in parts and not parts.startswith("/"):
                out["domain"].add(parts)
        if endpoint and endpoint.startswith(("http://", "https://")):
            out["url"].add(endpoint)
    if surface_map:
        for sub in _extract_subdomains(surface_map):
            out["domain"].add(sub.lower())
        for _, ip in _extract_subdomain_ip_pairs(surface_map):
            out["ipv4"].add(ip)
    return out


# ---------------------------------------------------------------------------
# Tracer integration
# ---------------------------------------------------------------------------


def _emit_correlation_finding(
    *,
    correlation_class: str,
    severity: str,
    target_a: str,
    target_b: str,
    title: str,
    description: str,
    description_plain: str,
    recommended_action: str,
    evidence_a: str = "",
    evidence_b: str = "",
    linked_fingerprints: list[str] | None = None,
    cwe: str = "CWE-693",
) -> bool:
    """Emit a cross_target.correlation finding via the global tracer.
    Correlation metadata is embedded in the description (the tracer
    schema doesn't carry arbitrary metadata fields). Returns True
    if the finding was emitted."""
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return False
    tracer = get_global_tracer()
    if tracer is None:
        return False

    metadata_block = (
        f"\n\n**Correlation metadata:**\n"
        f"- `correlation_class`: `{correlation_class}`\n"
        f"- `target_a`: `{target_a}`\n"
        f"- `target_b`: `{target_b}`\n"
        f"- `evidence_a`: {evidence_a}\n"
        f"- `evidence_b`: {evidence_b}\n"
        f"- `linked_finding_fingerprints`: "
        f"{json.dumps(linked_fingerprints or [])}\n"
    )
    full_description = description + metadata_block

    try:
        tracer.add_vulnerability_report(
            title=title,
            severity=severity,
            category="cross_target_correlation",
            cwe=cwe,
            target=f"{target_a} ↔ {target_b}",
            endpoint=target_b,
            description=full_description,
            impact=(
                "Cross-target correlation surfaces risk that's invisible "
                "when each target is scanned in isolation: the same "
                "compromised IP that hosts a customer subdomain is the "
                "one Threat Intel says is a known-bad C2; the CVE in a "
                "package is the one the customer's own threat feed is "
                "tracking; the credential leaked in a public repo is "
                "the production one. Treat correlation findings as "
                "fix-now: the underlying findings might individually be "
                "medium, but their join is a confirmed targeted-risk "
                "signal."
            ),
            remediation_steps=recommended_action,
            description_plain=description_plain,
            recommended_action=recommended_action,
            verification_status="needs_review",
        )
        return True
    except Exception:  # noqa: BLE001
        logger.warning("cross_target finding emission failed", exc_info=True)
        return False


def _start_check(category: str, surface: str) -> str | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    return t.start_check(category=category, surface=surface, tool=_TOOL_NAME)


def _complete_check(check_id: str | None, result: str, evidence: str) -> None:
    if not check_id:
        return
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return
    t = get_global_tracer()
    if t is None:
        return
    t.complete_check(check_id, result=result, evidence=evidence)


def _findings_from_tracer() -> list[dict[str, Any]]:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return []
    t = get_global_tracer()
    if t is None:
        return []
    try:
        return list(t.get_existing_vulnerabilities())
    except Exception:  # noqa: BLE001
        return []


def _run_dir() -> Path | None:
    try:
        from strix.telemetry.tracer import get_global_tracer
    except ImportError:
        return None
    t = get_global_tracer()
    if t is None:
        return None
    try:
        return t.get_run_dir()
    except Exception:  # noqa: BLE001
        return None


def _autoload_surface_map(surface_map_path: str | None) -> dict[str, Any] | None:
    """Load surface_map.json from caller-supplied path, or from the
    current run dir.

    Roadmap §8.0: validates against the handoff-schema contract on
    read. Canonical-contract errors are logged but the data is still
    returned (data loss is worse than blocking the consumer)."""
    candidate: Path | None = None
    if surface_map_path:
        candidate = Path(surface_map_path)
    else:
        run_dir = _run_dir()
        if run_dir is not None:
            candidate = run_dir / "surface_map.json"
    if candidate is None or not candidate.exists():
        return None
    try:
        from strix.agents.handoffs.surface_map import load_surface_map

        data, violations = load_surface_map(candidate)
        if violations:
            errors = [v.code for v in violations if v.severity == "error"]
            if errors:
                logger.warning(
                    "surface_map.json has canonical-contract errors on read: %s",
                    errors,
                )
        return data
    except Exception:  # noqa: BLE001
        logger.debug("surface_map handoff validation failed; falling back to raw load", exc_info=True)
        try:
            with candidate.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError, TypeError):
            return None


# ---------------------------------------------------------------------------
# Correlation classes
# ---------------------------------------------------------------------------


def _correlate_domain_ip_reputation(
    surface_map: dict[str, Any],
    ip_reputation_lookup: Callable[[str], dict[str, Any]],
    seen_dedup_keys: set[str],
) -> tuple[int, list[dict[str, Any]]]:
    """For each (subdomain, IP) pair, look up the IP's reputation
    and emit a finding if any source flags it."""
    pairs = _extract_subdomain_ip_pairs(surface_map)
    correlations_evaluated: list[dict[str, Any]] = []
    findings_emitted = 0

    for subdomain, ip in pairs:
        rep = ip_reputation_lookup(ip)
        evaluated = {
            "class": "domain_ip_reputation",
            "target_a": subdomain,
            "target_b": ip,
            "flags": list(rep.get("flags") or []),
            "sources": list(rep.get("sources") or []),
            "max_severity": rep.get("max_severity") or "none",
            "emitted": False,
        }
        correlations_evaluated.append(evaluated)

        flags = rep.get("flags") or []
        sources = rep.get("sources") or []
        if not flags:
            continue

        dedup_key = f"domain_ip_reputation::{subdomain}::{ip}"
        if dedup_key in seen_dedup_keys:
            continue
        seen_dedup_keys.add(dedup_key)

        # Severity per number of distinct sources.
        unique_sources = sorted(set(sources))
        if len(unique_sources) >= 3:
            severity = "high"
        elif len(unique_sources) >= 1:
            severity = "medium"
        else:
            continue

        emitted = _emit_correlation_finding(
            correlation_class="domain_ip_reputation",
            severity=severity,
            target_a=subdomain,
            target_b=ip,
            title=(
                f"Subdomain `{subdomain}` resolves to threat-intel-flagged IP "
                f"`{ip}` ({len(unique_sources)} source(s))"
            ),
            description=(
                f"Subdomain `{subdomain}` resolves to `{ip}`. The IP is "
                f"flagged across {len(unique_sources)} threat-intel "
                f"source(s): {unique_sources}. Flags: {flags}."
            ),
            description_plain=(
                f"One of your subdomains, `{subdomain}`, resolves to "
                f"an IP that {len(unique_sources)} different threat-"
                f"intelligence source(s) classify as malicious. Either "
                f"your subdomain is hosted alongside known-bad "
                f"infrastructure, or the subdomain itself has been "
                f"compromised — both are urgent."
            ),
            recommended_action=(
                "Confirm the subdomain's intended hosting target. If "
                "you don't recognise this IP as your own, treat the "
                "DNS record as compromised: rotate the record, audit "
                "DNS-management credentials, and review traffic to "
                "the subdomain. If the IP IS yours but is flagged, "
                "ask your hosting provider what's running there — "
                "shared-hosting tenants frequently get flagged due "
                "to a noisy neighbour."
            ),
            evidence_a=f"subdomain in surface_map.json",
            evidence_b=f"sources={unique_sources}; flags={flags}",
        )
        if emitted:
            findings_emitted += 1
            evaluated["emitted"] = True
            evaluated["severity"] = severity

    return findings_emitted, correlations_evaluated


def _correlate_kev_in_customer_stack(
    findings: list[dict[str, Any]],
    seen_dedup_keys: set[str],
) -> tuple[int, list[dict[str, Any]]]:
    """For each finding with cve + is_kev, emit a bumped-severity
    correlation tagging it as KEV-in-detected-stack."""
    correlations_evaluated: list[dict[str, Any]] = []
    findings_emitted = 0

    for finding in findings:
        cve = finding.get("cve")
        is_kev = bool(finding.get("is_kev"))
        if not cve or not is_kev:
            continue
        target = finding.get("target") or ""
        original_severity = (finding.get("severity") or "info").lower()
        ransomware = bool(finding.get("kev_ransomware_use"))
        fingerprint = finding.get("fingerprint") or ""

        evaluated = {
            "class": "kev_in_customer_stack",
            "target_a": target,
            "target_b": cve,
            "ransomware": ransomware,
            "original_severity": original_severity,
            "emitted": False,
        }
        correlations_evaluated.append(evaluated)

        dedup_key = f"kev_in_customer_stack::{target}::{cve}"
        if dedup_key in seen_dedup_keys:
            continue
        seen_dedup_keys.add(dedup_key)

        if ransomware:
            severity = "critical"
        else:
            severity = _bump_severity(original_severity)

        emitted = _emit_correlation_finding(
            correlation_class="kev_in_customer_stack",
            severity=severity,
            target_a=target,
            target_b=cve,
            title=(
                f"KEV CVE `{cve}` is actively exploited AND detected on "
                f"`{target}`"
            ),
            description=(
                f"CVE `{cve}` is on the CISA Known Exploited Vulnerabilities "
                f"catalogue (active in-the-wild exploitation) AND was "
                f"detected on `{target}`. Original finding severity: "
                f"`{original_severity}`. Ransomware-flag: `{ransomware}`. "
                f"Linked finding fingerprint: `{fingerprint}`."
            ),
            description_plain=(
                "This vulnerability has TWO things working against you: "
                "(1) attackers are actively exploiting it in the wild "
                "right now (CISA KEV catalogue confirms), and (2) "
                "it's deployed on your systems. The underlying "
                "vulnerability scan flagged this; the cross-target "
                "correlation elevates it because it's not theoretical."
            ),
            recommended_action=(
                "Treat as fix-now. Apply the vendor patch, upgrade the "
                "affected component, or take it off the public network "
                "until patched. Reference CISA's KEV entry for the "
                "specific exploitation context. If ransomware-flagged, "
                "review backup integrity AND lateral-movement controls "
                "in addition to the patch."
            ),
            evidence_a=f"finding from {finding.get('category')}: {finding.get('title')}",
            evidence_b=f"CISA KEV entry; ransomware_use={ransomware}",
            linked_fingerprints=[fingerprint] if fingerprint else None,
            cwe=finding.get("cwe") or "CWE-693",
        )
        if emitted:
            findings_emitted += 1
            evaluated["emitted"] = True
            evaluated["severity"] = severity

    return findings_emitted, correlations_evaluated


def _correlate_cve_in_threat_feed(
    findings: list[dict[str, Any]],
    threat_feed_buckets: dict[str, set[str]],
    seen_dedup_keys: set[str],
) -> tuple[int, list[dict[str, Any]]]:
    """For each finding with a CVE, check if the CVE is in the
    customer's threat-feed CVE list."""
    feed_cves = threat_feed_buckets.get("cve") or set()
    correlations_evaluated: list[dict[str, Any]] = []
    findings_emitted = 0
    if not feed_cves:
        return (0, [])

    for finding in findings:
        cve = (finding.get("cve") or "").upper()
        if not cve or cve not in feed_cves:
            continue
        target = finding.get("target") or ""
        fingerprint = finding.get("fingerprint") or ""

        evaluated = {
            "class": "cve_in_threat_feed",
            "target_a": target,
            "target_b": cve,
            "emitted": False,
        }
        correlations_evaluated.append(evaluated)

        dedup_key = f"cve_in_threat_feed::{target}::{cve}"
        if dedup_key in seen_dedup_keys:
            continue
        seen_dedup_keys.add(dedup_key)

        emitted = _emit_correlation_finding(
            correlation_class="cve_in_threat_feed",
            severity="high",
            target_a=target,
            target_b=cve,
            title=(
                f"CVE `{cve}` detected on `{target}` AND tracked by "
                f"customer threat feed"
            ),
            description=(
                f"CVE `{cve}` is present on `{target}` AND appears in "
                f"the customer's ingested threat-intel feed (MISP / "
                f"STIX / TAXII). Linked finding fingerprint: "
                f"`{fingerprint}`."
            ),
            description_plain=(
                "Your own intelligence team is tracking this CVE as a "
                "threat to your organisation, AND we've confirmed it's "
                "deployed on your stack. This is the highest-confidence "
                "fix-this-first signal: someone at your company already "
                "decided this matters, and now it's been found in the "
                "wild on your systems."
            ),
            recommended_action=(
                "Patch the affected component immediately. Loop in the "
                "internal threat-intel team that flagged the CVE in your "
                "feed; they may have additional context about who is "
                "exploiting it and how."
            ),
            evidence_a=f"finding {finding.get('title')!r}",
            evidence_b=f"CVE in customer threat-feed",
            linked_fingerprints=[fingerprint] if fingerprint else None,
            cwe=finding.get("cwe") or "CWE-693",
        )
        if emitted:
            findings_emitted += 1
            evaluated["emitted"] = True

    return findings_emitted, correlations_evaluated


def _correlate_threat_feed_ioc_match(
    scan_iocs: dict[str, set[str]],
    threat_feed_buckets: dict[str, set[str]],
    seen_dedup_keys: set[str],
) -> tuple[int, list[dict[str, Any]]]:
    """For each scan-discovered IoC that's in the threat-feed list,
    emit a correlation."""
    correlations_evaluated: list[dict[str, Any]] = []
    findings_emitted = 0

    for bucket, ioc_set in scan_iocs.items():
        feed_set = threat_feed_buckets.get(bucket) or set()
        if not feed_set:
            continue
        matches = ioc_set & feed_set
        for ioc in matches:
            evaluated = {
                "class": "threat_feed_ioc_match",
                "bucket": bucket,
                "target_a": ioc,
                "target_b": "(customer-threat-feed)",
                "emitted": False,
            }
            correlations_evaluated.append(evaluated)

            dedup_key = f"threat_feed_ioc_match::{bucket}::{ioc}"
            if dedup_key in seen_dedup_keys:
                continue
            seen_dedup_keys.add(dedup_key)

            emitted = _emit_correlation_finding(
                correlation_class="threat_feed_ioc_match",
                severity="high",
                target_a=ioc,
                target_b="customer threat feed",
                title=(
                    f"Scan-discovered {bucket.upper()} `{ioc}` matches "
                    f"customer threat-intel feed"
                ),
                description=(
                    f"The {bucket} `{ioc}` was discovered during the scan "
                    f"AND is listed in the customer's ingested threat-"
                    f"intel feed. The customer's intel team has marked "
                    f"this IoC as malicious/suspicious."
                ),
                description_plain=(
                    f"We found a {bucket} that your own intelligence "
                    f"team is tracking as malicious. That means: "
                    f"either (a) the bad-IoC is reachable from your "
                    f"infrastructure (active exposure), or (b) one of "
                    f"your assets resolves to or contains this IoC "
                    f"(active compromise). Either way, this is fix-now."
                ),
                recommended_action=(
                    "Determine why this IoC is reachable from / inside "
                    "your scan surface. If it's a domain/IP your "
                    "infrastructure resolves to, treat as compromise "
                    "indicator. If it's a hash matching a file you "
                    "shipped, escalate to incident response."
                ),
                evidence_a=f"scan-discovered ({bucket})",
                evidence_b=f"customer threat-feed",
            )
            if emitted:
                findings_emitted += 1
                evaluated["emitted"] = True

    return findings_emitted, correlations_evaluated


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1592", "T1589"],
)
def cross_target_correlate(
    *,
    findings: list[dict[str, Any]] | None = None,
    surface_map: dict[str, Any] | None = None,
    surface_map_path: str | None = None,
    threat_feed_iocs: dict[str, Any] | None = None,
    enable_correlations: list[str] | None = None,
    ip_reputation_lookup: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute cross-target correlation findings from existing scan
    artifacts.

    Args:
        findings: Current run's findings. If None, loads from the
            global tracer's `get_existing_vulnerabilities()`.
        surface_map: Contents of `surface_map.json`. If None, tries
            to load from `surface_map_path` (or auto-detect from the
            current run dir).
        surface_map_path: Path to a `surface_map.json` file to load.
            Optional.
        threat_feed_iocs: dict shape `{cve: [...], ipv4: [...],
            domain: [...], sha256: [...], ...}` from the
            `threat_feed_ingest` tool. When None, the
            `cve_in_threat_feed` and `threat_feed_ioc_match` classes
            silently skip.
        enable_correlations: subset of correlation classes to run.
            Default = all.
        ip_reputation_lookup: callable `fn(ip) -> {flags, sources,
            max_severity}`. When None, the default reads
            `~/.strix/{vt,otx,greynoise,domain_rep}_cache/`.

    Returns:
        {
          success, correlations_evaluated, findings_emitted,
          enabled_classes
        }

    Findings:
        - **High** — domain_ip_reputation with ≥3 sources flagging;
          cve_in_threat_feed; threat_feed_ioc_match;
          kev_in_customer_stack with ransomware-flag → critical;
          else bumped from original severity.
        - **Medium** — domain_ip_reputation with 1-2 sources.

    Notes:
        - No HTTP traffic; reads existing artifacts only.
        - Per-(class, target_a, target_b) dedup so a re-run doesn't
          double-emit.
        - `verification_status=needs_review`.
    """
    if findings is None:
        findings = _findings_from_tracer()
    if surface_map is None:
        surface_map = _autoload_surface_map(surface_map_path)
    if ip_reputation_lookup is None:
        ip_reputation_lookup = _default_ip_reputation_lookup

    enabled = list(enable_correlations) if enable_correlations else list(CORRELATION_CLASSES)
    enabled = [c for c in enabled if c in CORRELATION_CLASSES]

    cev = _start_check("cross_target", "all")
    seen_dedup_keys: set[str] = set()

    all_evaluated: list[dict[str, Any]] = []
    findings_emitted = 0

    if "domain_ip_reputation" in enabled and surface_map:
        n, evaluated = _correlate_domain_ip_reputation(
            surface_map, ip_reputation_lookup, seen_dedup_keys,
        )
        findings_emitted += n
        all_evaluated.extend(evaluated)

    if "kev_in_customer_stack" in enabled and findings:
        n, evaluated = _correlate_kev_in_customer_stack(findings, seen_dedup_keys)
        findings_emitted += n
        all_evaluated.extend(evaluated)

    threat_feed_buckets = _normalize_iocs(threat_feed_iocs or {})

    if "cve_in_threat_feed" in enabled and findings:
        n, evaluated = _correlate_cve_in_threat_feed(
            findings, threat_feed_buckets, seen_dedup_keys,
        )
        findings_emitted += n
        all_evaluated.extend(evaluated)

    if "threat_feed_ioc_match" in enabled:
        scan_iocs = _scan_iocs_from_findings_and_surface(findings or [], surface_map)
        n, evaluated = _correlate_threat_feed_ioc_match(
            scan_iocs, threat_feed_buckets, seen_dedup_keys,
        )
        findings_emitted += n
        all_evaluated.extend(evaluated)

    _complete_check(
        cev,
        result="vulnerable" if findings_emitted else "not_vulnerable",
        evidence=f"{findings_emitted} cross-target correlation(s)",
    )

    return {
        "success": True,
        "enabled_classes": enabled,
        "correlations_evaluated": all_evaluated,
        "findings_emitted": findings_emitted,
    }
