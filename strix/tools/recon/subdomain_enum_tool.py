"""Multi-source subdomain enumeration with bounded per-source budgets.

Roadmap §7.3 Tier-1 item. Today's pipeline uses subfinder + passive DNS only.
This tool adds amass, DNS bruteforce against a tunable wordlist, permutation
generation from already-discovered seeds, and Wayback Machine CDX historical-
URL mining — all behind a single entry point with explicit source selection.

Sources, in order of network-load:

- **subfinder** — passive (CT logs, common providers). ~5–50 results typical.
- **amass** — deeper active + passive enum. Bigger, slower, finds more.
- **dns_bruteforce** — query each entry in a wordlist against the apex.
  Default wordlist is ~120 common names. Custom wordlist via path.
- **permutations** — apply `prod-` / `staging-` / etc. transformations to
  already-discovered seeds; resolve each candidate.
- **wayback** — query archive.org's CDX API for historical URLs containing
  the apex; extract subdomains. No API key required.

Each source has its own hard cap to bound total network volume. The tool
emits one `check.started` / `check.completed` event per source.

The tool is sandbox-executable: subfinder, amass, dig live in the
sandbox image. Wayback uses HTTP. Bruteforce uses dig.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from typing import Any

from strix.tools.registry import register_tool

from ._common import (
    complete_check,
    dig,
    http_get_text,
    looks_like_domain,
    start_check,
)


logger = logging.getLogger(__name__)
_TOOL_NAME = "subdomain_enum"

_SUBFINDER_TIMEOUT = 60
_AMASS_TIMEOUT = 90
_BRUTEFORCE_PER_QUERY_TIMEOUT = 3
_WAYBACK_TIMEOUT = 30


# Common-subdomain wordlist used by `dns_bruteforce` when no explicit list
# is supplied. Curated for high hit-rate on real-world infra. Bigger lists
# (commonspeak2, jhaddix-all.txt) ship via `--wordlist <path>` to avoid
# bundling a 100K+ entry blob in the package.
_DEFAULT_WORDLIST: tuple[str, ...] = (
    "www", "mail", "api", "app", "admin", "blog", "shop", "store", "support",
    "help", "docs", "wiki", "status", "vpn", "secure", "portal", "dashboard",
    "login", "signup", "auth", "sso", "accounts", "billing", "payment",
    "checkout", "cart", "search", "news", "media", "images", "img", "static",
    "assets", "cdn", "files", "dl", "downloads", "uploads", "data", "db",
    "ftp", "sftp", "ssh", "smtp", "mx", "mx1", "mx2", "pop", "pop3", "imap",
    "ns1", "ns2", "ns3", "ns4", "dns", "dev", "develop", "development",
    "stage", "staging", "test", "testing", "qa", "uat", "preprod", "prod",
    "production", "demo", "sandbox", "internal", "external", "intranet",
    "extranet", "private", "public", "beta", "alpha", "preview", "stg",
    "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd", "build",
    "deploy", "registry", "harbor", "artifacts", "jira", "confluence",
    "wiki", "monitoring", "metrics", "grafana", "kibana", "elastic",
    "elasticsearch", "logs", "log", "splunk", "prometheus", "alertmanager",
    "kafka", "redis", "mongo", "mysql", "postgres", "postgresql", "sql",
    "cache", "queue", "worker", "task", "scheduler", "cron",
    "webhook", "hook", "callback", "events", "stream", "ws", "websocket",
    "graphql", "rest", "v1", "v2", "v3", "api1", "api2", "api3", "api-v1",
    "api-v2", "api-internal", "api-public", "admin-panel", "admin-api",
    "console", "control", "manage", "manager", "ops", "devops",
    "mobile", "m", "ios", "android", "app1", "app2", "app3",
    "web", "web1", "web2", "web3", "www1", "www2",
    "vpc", "gateway", "lb", "loadbalancer", "edge", "origin",
    "host", "server", "node1", "node2",
    "vault", "secrets", "kms", "kube", "k8s", "kubernetes", "docker",
    "smtp1", "mail1", "mail2", "email", "newsletter",
    "client", "customer", "partner", "merchant", "vendor", "supplier",
    "feedback", "survey", "form", "contact", "press", "careers", "jobs",
    "calendar", "office", "drive", "share", "shared",
    "old", "legacy", "v1-old", "old-www", "archive",
)


# Permutation generators applied to seed subdomains. Conservative — each
# pattern adds ~5x the seed count, so cap permutation_max tightly.
_PERMUTATION_PREFIXES: tuple[str, ...] = (
    "prod-", "dev-", "staging-", "test-", "qa-", "uat-", "demo-",
    "internal-", "admin-", "old-",
)
_PERMUTATION_SUFFIXES: tuple[str, ...] = (
    "-prod", "-dev", "-staging", "-test", "-qa", "-internal", "-admin",
    "-old", "-new", "-v2",
)


# ---------------------------------------------------------------------------
# Source: subfinder
# ---------------------------------------------------------------------------


def _enum_subfinder(domain: str, max_results: int) -> list[str]:
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-timeout", "5"],
            capture_output=True, text=True,
            timeout=_SUBFINDER_TIMEOUT, check=False,
        )
        out = (proc.stdout or "").strip().splitlines()
        return [line.strip().lower() for line in out if line.strip()][:max_results]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning("subfinder failed for %s: %s", domain, e)
        return []


# ---------------------------------------------------------------------------
# Source: amass
# ---------------------------------------------------------------------------


def _enum_amass(domain: str, max_results: int) -> list[str]:
    """Run amass in passive mode by default (no aggressive active probes;
    sandbox-time-bounded). Amass output format is one subdomain per line."""
    try:
        proc = subprocess.run(
            ["amass", "enum", "-d", domain, "-passive", "-silent", "-timeout", "1"],
            capture_output=True, text=True,
            timeout=_AMASS_TIMEOUT, check=False,
        )
        out = (proc.stdout or "").strip().splitlines()
        # amass output may include source labels in [brackets]; strip them.
        cleaned: list[str] = []
        for line in out:
            tok = line.strip().split()[0] if line.strip() else ""
            tok = tok.lower().rstrip(".")
            if tok and "." in tok and not tok.startswith("["):
                cleaned.append(tok)
        return cleaned[:max_results]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning("amass failed for %s: %s", domain, e)
        return []


# ---------------------------------------------------------------------------
# Source: dns_bruteforce
# ---------------------------------------------------------------------------


def _read_wordlist(path: str | None) -> list[str]:
    if not path:
        return list(_DEFAULT_WORDLIST)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            words = [
                w.strip().lower()
                for w in f.readlines()
                if w.strip() and not w.startswith("#")
            ]
        return words
    except OSError as e:
        logger.warning("could not read wordlist %s: %s", path, e)
        return list(_DEFAULT_WORDLIST)


def _enum_dns_bruteforce(
    domain: str, wordlist: list[str], max_results: int
) -> list[str]:
    """For each word, query <word>.<domain> A. Keep words that resolve.
    Bounded by max_results — stops dispatching new queries once cap is hit."""
    found: list[str] = []
    deadline = time.time() + 90  # hard wall clock cap for the whole bruteforce
    for word in wordlist:
        if len(found) >= max_results:
            break
        if time.time() > deadline:
            logger.info("dns_bruteforce hit walltime cap for %s", domain)
            break
        host = f"{word}.{domain}"
        try:
            out = dig(host, "A")
        except Exception:  # noqa: BLE001
            continue
        if out and re.search(r"\d+\.\d+\.\d+\.\d+", out):
            found.append(host)
    return found


# ---------------------------------------------------------------------------
# Source: permutations
# ---------------------------------------------------------------------------


def _enum_permutations(
    seeds: list[str], domain: str, max_results: int
) -> list[str]:
    """Apply prefix/suffix transformations + simple digit substitution to
    seed subdomains. Resolve each candidate; keep only the ones that resolve
    AND aren't already in the seed list."""
    seed_set = {s.lower() for s in seeds}
    apex_label_count = domain.count(".") + 1

    candidates: set[str] = set()

    for seed in seeds:
        seed = seed.lower()
        if not seed.endswith(domain):
            continue
        # Extract the leftmost label of the seed (the "name" part before the apex).
        # For "api.example.com" with apex "example.com", the label is "api".
        # For "api-v1.staging.example.com", the label is "api-v1" (we only
        # permute the leftmost component to keep candidate count bounded).
        labels = seed[: -(len(domain) + 1)].split(".") if seed != domain else []
        if not labels:
            continue
        leftmost = labels[0]
        rest = ".".join(labels[1:]) + ("." if labels[1:] else "")

        for prefix in _PERMUTATION_PREFIXES:
            cand = f"{prefix}{leftmost}.{rest}{domain}".rstrip(".")
            if cand not in seed_set:
                candidates.add(cand)

        for suffix in _PERMUTATION_SUFFIXES:
            cand = f"{leftmost}{suffix}.{rest}{domain}".rstrip(".")
            if cand not in seed_set:
                candidates.add(cand)

        # Simple digit substitution: dev1 → dev2/dev3, api → api1/api2.
        digit_match = re.match(r"^([a-z]+)(\d*)$", leftmost)
        if digit_match:
            base, digits = digit_match.group(1), digit_match.group(2)
            for n in (1, 2, 3, 4):
                if str(n) != digits:
                    cand = f"{base}{n}.{rest}{domain}".rstrip(".")
                    if cand not in seed_set:
                        candidates.add(cand)

    # Resolve candidates, bounded by max_results.
    found: list[str] = []
    for cand in sorted(candidates):
        if len(found) >= max_results:
            break
        try:
            out = dig(cand, "A")
        except Exception:  # noqa: BLE001
            continue
        if out and re.search(r"\d+\.\d+\.\d+\.\d+", out):
            found.append(cand)
    return found


# ---------------------------------------------------------------------------
# Source: wayback
# ---------------------------------------------------------------------------


_WAYBACK_HOSTNAME_RE = re.compile(
    r"https?://([a-zA-Z0-9.\-]+)(?::\d+)?[/?#]", re.IGNORECASE
)


def _enum_wayback(domain: str, max_results: int) -> list[str]:
    """Query archive.org's CDX API for historical URLs touching the apex.
    No API key needed; bounded by `limit` parameter on the CDX call."""
    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        f"&output=text&fl=original&collapse=urlkey&limit={max_results * 4}"
    )
    status, body = http_get_text(cdx_url, max_bytes=512_000)
    if status != 200 or not body:
        return []

    seen: set[str] = set()
    apex_lower = domain.lower()
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _WAYBACK_HOSTNAME_RE.match(line)
        if m:
            host = m.group(1).lower().rstrip(".")
        else:
            # Some CDX rows are bare URLs without scheme — try parsing the
            # host out of the first slash-separated segment.
            head = line.split("/", 1)[0].lower()
            host = head.split("?", 1)[0].split("#", 1)[0]

        if host and host.endswith(apex_lower):
            seen.add(host)
            if len(seen) >= max_results:
                break

    return sorted(seen)


# ---------------------------------------------------------------------------
# Source: Certificate Transparency logs (crt.sh + certspotter)
# ---------------------------------------------------------------------------
#
# CT logs every TLS cert ever issued for a domain. For most orgs this
# surfaces 5-10× more subdomains than passive-DNS sources alone — every
# internal service that ever got a Let's Encrypt cert is in there, even
# if it never appeared in DNS-source-of-truth feeds.
#
# Subfinder hits crt.sh internally as one of its many sources, but it's
# not deterministic which CT logs subfinder's plugins query, and the
# per-source counts can't tell us what CT actually contributed. Adding
# crt.sh + certspotter as explicit sources guarantees coverage and lets
# the pipeline report "we got N subdomains from CT".
#
# Both APIs are free and require no authentication.


# Strip wildcard prefix (`*.foo.example.com` → `foo.example.com`) and
# leading whitespace; cap to a reasonable hostname length.
_CT_WILDCARD_PREFIX = "*."


def _normalize_ct_hostname(raw: Any, apex: str) -> str | None:
    """Validate + scope-filter a CT-derived hostname.

    Returns the lowercased hostname when it ends with `.apex` (or equals
    `apex`); otherwise None. Wildcard prefix stripped.
    """
    if not isinstance(raw, str):
        return None
    host = raw.strip().lower()
    if host.startswith(_CT_WILDCARD_PREFIX):
        host = host[len(_CT_WILDCARD_PREFIX):]
    host = host.rstrip(".")
    if not host or len(host) > 253:
        return None
    apex_lower = apex.lower()
    if host == apex_lower or host.endswith(f".{apex_lower}"):
        return host
    return None


def _enum_crtsh(domain: str, max_results: int) -> list[str]:
    """Query crt.sh for every certificate ever issued for `*.<domain>`.

    crt.sh returns one JSON record per cert; the `name_value` field is a
    newline-separated list of SANs. We dedup across records and scope-
    filter to the apex.

    Free, no key required, but the public endpoint is rate-limited so
    we apply a generous bytes cap and treat 504 / 429 as soft failures.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, body = http_get_text(url, max_bytes=4 * 1024 * 1024)
    if status != 200 or not body:
        return []
    try:
        import json

        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    seen: set[str] = set()
    for record in data:
        if not isinstance(record, dict):
            continue
        for field in ("common_name", "name_value"):
            value = record.get(field)
            if isinstance(value, str):
                # name_value is newline-separated; common_name is a single name.
                for line in value.splitlines():
                    norm = _normalize_ct_hostname(line, domain)
                    if norm:
                        seen.add(norm)
        if len(seen) >= max_results * 4:
            # Stop scanning records once we have plenty — sort + cap below.
            break
    return sorted(seen)[:max_results]


def _enum_certspotter(domain: str, max_results: int) -> list[str]:
    """Query SSLMate's certspotter API for issuances against the apex.

    Free for unauthenticated callers (rate-limited per source IP).
    `include_subdomains=true` returns SANs across the apex's whole tree;
    `expand=dns_names` includes the per-cert SAN list inline.
    """
    url = (
        f"https://api.certspotter.com/v1/issuances?domain={domain}"
        "&include_subdomains=true&expand=dns_names"
    )
    status, body = http_get_text(url, max_bytes=4 * 1024 * 1024)
    if status != 200 or not body:
        return []
    try:
        import json

        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    seen: set[str] = set()
    for issuance in data:
        if not isinstance(issuance, dict):
            continue
        names = issuance.get("dns_names")
        if not isinstance(names, list):
            continue
        for name in names:
            norm = _normalize_ct_hostname(name, domain)
            if norm:
                seen.add(norm)
        if len(seen) >= max_results * 4:
            break
    return sorted(seen)[:max_results]


# ---------------------------------------------------------------------------
# Public tool
# ---------------------------------------------------------------------------


_VALID_SOURCES = (
    "subfinder", "amass", "dns_bruteforce", "wayback", "permutations",
    "crtsh", "certspotter",
)


@register_tool(
    sandbox_execution=True,
    mitre_techniques=["T1590.005"],  # Gather Victim Network Information: IP Addresses
)
def subdomain_enum(  # noqa: PLR0913
    domain: str,
    sources: str | None = None,
    wordlist: str | None = None,
    max_per_source: int = 1000,
    permutation_seeds: str | None = None,
) -> dict[str, Any]:
    """Multi-source subdomain enumeration with bounded per-source budgets.

    Args:
        domain: apex domain to enumerate (e.g. "example.com").
        sources: comma-separated subset of {subfinder, amass, dns_bruteforce,
                 wayback, permutations}. Default: "subfinder,amass,dns_bruteforce,wayback".
                 Note: permutations needs seeds; when omitted from `sources` (default)
                 it auto-runs only if the other sources produced seeds.
        wordlist: path to a custom wordlist file (one entry per line) for
                  dns_bruteforce. Defaults to a built-in ~150-name list.
        max_per_source: hard cap on subdomains kept per source. Default 1000.
                        Caps total network volume; bruteforce respects this
                        before iterating the rest of the wordlist.
        permutation_seeds: comma-separated subdomains to use as permutation
                           seeds. When omitted, the union of other sources'
                           results is used.

    Each source emits a `check.started` / `check.completed` event via the
    tracer (category=`subdomain_enum`). Returns the per-source counts plus
    the merged + deduped subdomain list.
    """
    if not looks_like_domain(domain):
        return {"success": False, "error": f"invalid domain: {domain!r}"}

    if sources is None or sources.strip().lower() == "all":
        active_sources = list(_VALID_SOURCES)
    elif sources.strip().lower() == "default":
        active_sources = [
            "subfinder", "amass", "dns_bruteforce", "wayback",
            "crtsh", "certspotter",
        ]
    else:
        active_sources = [s.strip().lower() for s in sources.split(",") if s.strip()]
        unknown = [s for s in active_sources if s not in _VALID_SOURCES]
        if unknown:
            return {"success": False, "error": f"unknown sources: {unknown}"}

    # Per-source results.
    per_source_results: dict[str, list[str]] = {}

    def _run(src_name: str, fn) -> list[str]:
        cev_id = start_check(category="subdomain_enum", surface=domain, tool=_TOOL_NAME)
        try:
            results = fn()
        except Exception as e:  # noqa: BLE001
            logger.exception("source %s failed for %s", src_name, domain)
            complete_check(cev_id, "inconclusive", evidence=f"{src_name}: {e}")
            return []
        complete_check(
            cev_id,
            "not_vulnerable",  # enumeration isn't itself vuln/not-vuln; using NV for clean coverage
            evidence=f"{src_name}: {len(results)} subdomain(s)",
        )
        return results

    if "subfinder" in active_sources:
        per_source_results["subfinder"] = _run(
            "subfinder", lambda: _enum_subfinder(domain, max_per_source)
        )

    if "amass" in active_sources:
        per_source_results["amass"] = _run(
            "amass", lambda: _enum_amass(domain, max_per_source)
        )

    if "dns_bruteforce" in active_sources:
        words = _read_wordlist(wordlist)
        per_source_results["dns_bruteforce"] = _run(
            "dns_bruteforce",
            lambda: _enum_dns_bruteforce(domain, words, max_per_source),
        )

    if "wayback" in active_sources:
        per_source_results["wayback"] = _run(
            "wayback", lambda: _enum_wayback(domain, max_per_source)
        )

    if "crtsh" in active_sources:
        per_source_results["crtsh"] = _run(
            "crtsh", lambda: _enum_crtsh(domain, max_per_source)
        )

    if "certspotter" in active_sources:
        per_source_results["certspotter"] = _run(
            "certspotter", lambda: _enum_certspotter(domain, max_per_source)
        )

    # Permutations need seeds — either explicit or accumulated from other sources.
    if "permutations" in active_sources or (
        sources is None or sources.strip().lower() in ("", "all")
    ):
        if permutation_seeds:
            seeds = [s.strip().lower() for s in permutation_seeds.split(",") if s.strip()]
        else:
            seeds = []
            for results in per_source_results.values():
                seeds.extend(results)
        # Dedupe + bound seed count to keep candidate space manageable.
        seeds = sorted(set(seeds))[:50]
        if seeds:
            per_source_results["permutations"] = _run(
                "permutations",
                lambda: _enum_permutations(seeds, domain, max_per_source),
            )
        else:
            per_source_results["permutations"] = []

    # Merge + dedup.
    merged: set[str] = set()
    for results in per_source_results.values():
        for s in results:
            merged.add(s)

    # KG: emit one Asset per discovered subdomain so cross-tool
    # correlation (threat-intel observations on the subdomain;
    # vulns at the subdomain's surfaces) joins on the shared node.
    try:
        from strix.agents.kg_emit import record_asset_in_kg

        for sub in merged:
            record_asset_in_kg(
                asset_type="subdomain",
                value=sub,
                source="subdomain_enum_tool",
                parent_value=domain,
            )
    except Exception:  # noqa: BLE001
        # Recon emit failures must not break tool output.
        pass

    return {
        "success": True,
        "domain": domain,
        "sources_run": list(per_source_results.keys()),
        "per_source_counts": {k: len(v) for k, v in per_source_results.items()},
        "subdomains": sorted(merged),
        "total_unique": len(merged),
    }
