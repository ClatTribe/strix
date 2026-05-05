# Sandbox tool-server unreachable from agent — entire scan completes "clean" with 0 tool executions and `exit_code=0`

**Reporter:** webappsec wrapper integration team
**Engine commit:** `3b48809` (PR #144 latest)
**Date observed:** 2026-05-05
**Severity:** High — silent reporting failure; misleads downstream wrappers and customers

> **NB.** Issues are disabled on this repo, so this report lives in `docs/incidents/`. Treat it like a tracker entry — discuss in PR review, then either close on merge with a fix-PR pointer or extend with a follow-up post-mortem.

---

## Summary

A `standard`-mode scan against a real production target (`https://www.getedunext.com`) ran for **66 minutes**, spent **$0.4651 of a $1.50 budget cap**, made **676 K input tokens of LLM calls**, and finished with `exit_code=0` — but the agent could not execute a single tool successfully. Every `terminal_execute` and `browser_action` invocation failed with `ConnectError` against the sandbox's tool-execution server.

The agent itself correctly recognised the failure and reported it cleanly in `finish_scan` args. The problem is upstream of that: the sandbox's tool-server became unreachable at some point during the run, and there's no engine-side health gate that distinguishes "tool server is down" from "scan completed normally with no findings." That ambiguity propagates to every wrapper consuming the engine output.

## Repro

- Engine: `ClatTribe/strix` HEAD `3b48809`
- Sandbox image: rebuilt from `containers/Dockerfile` (commit `3b48809`, tagged `strix-sandbox:fork-latest`, 13.3 GB)
- LLM: `gemini/gemini-2.5-pro`
- Target: `https://www.getedunext.com` — Vercel-hosted Next.js, IPv4+IPv6 reachable, TLS valid
- Mode: `standard`, `--max-cost 1.50`, default `--preflight` (passed)

```bash
strix -n -m standard -t https://www.getedunext.com \
  --feedback-from /tmp/strix-runs/<id>/feedback.jsonl \
  --max-cost 1.5 \
  --compliance-pack /tmp/strix-runs/<id>/compliance_pack \
  --instruction 'External pentest evaluation. ...'
```

## Numbers

| metric | value |
|---|---|
| wall time | 66 min |
| cost | $0.4651 / $1.50 budget |
| LLM input tokens | 676 200 |
| LLM output tokens | 2 400 |
| `tool.execution.started` events | **14** |
| breakdown | `terminal_execute` × 7, `think` × 4, `browser_action` × 1, `scan_start_info` × 1, `finish_scan` × 1 |
| `coverage.json` `coverage_percent` | **0.0** |
| `coverage.json` `status` | **incomplete** |
| `coverage.json` gaps | `[csrf, idor, open_redirect, sqli, ssrf, xss]` (full required list) |
| `findings` emitted | 0 |
| `run_summary.json.checks.total` | **0** |
| `llm.retry_attempted` events | 3 |
| engine exit code | **0** |

## What the agent actually saw

Excerpts from the agent's `think` calls (it reasoned correctly throughout):

> *"It seems like all terminal commands are failing due to a connection error with the tool server. This is preventing me from making any progress."*

> *"I have been consistently receiving `ConnectError` for all tool execution attempts, including `terminal_execute` and `browser_action`. This indicates a persistent problem with the connection between my agent and the tool server, which is preventing me from performing any of the required security checks. I have tried multiple tools and commands, and all have failed with the same error."*

> *"Since I am unable to execute any tools, I cannot proceed with the authorized security validation. It is impossible to crawl the site, check for vulnerabilities, or perform any meaningful analysis."*

The agent then called `finish_scan` with these (excellent, honest) report fields:

```json
{
  "executive_summary": "The external penetration test of the web application at https://www.getedunext.com could not be completed due to persistent technical issues within the testing environment. All attempts to interact with the target application, including basic reconnaissance and crawling, failed due to consistent connection errors with the execution toolkit. Consequently, no security assessment was performed, and the security posture of the application remains unverified.",
  "technical_analysis": "No technical analysis of the target application was possible. Every attempt to execute tools, including `terminal_execute` for crawling and `browser_action` for manual inspection, resulted in a `ConnectError`. ...",
  "recommendations": "The primary recommendation is to investigate and resolve the underlying connectivity issues within the security testing infrastructure ... it is strongly recommended to schedule a new penetration test ..."
}
```

## Why this matters

The engine produced a `coverage.json` that *correctly* says `status: incomplete` with `coverage_percent: 0.0` and all categories in `gaps`. The agent's `finish_scan` report *correctly* documents the environmental failure. **But the run-level signals look healthy:**

- `exit_code=0` (engine convention: 0 = completed clean / 2 = completed with findings)
- `run_meta.json.status: "completed"`
- `run_meta.json.vendor_risk.score: 100, band: low_risk, recommendation: "Score 100/100 — onboard. No critical vendor-hygiene red flags surfaced."`
- `run_summary.json.summary_text: "Scanned https://www.getedunext.com (web_application); in 66.4m; with no findings."`

A wrapper consuming these signals naively will tell the customer the site is safely scanned with 0 findings — exactly the opposite of what the agent itself reported. We had to ship a wrapper-side coverage banner ([webappsec PR #64](https://github.com/ClatTribe/webappsec/pull/64)) reading `coverage.json` and overriding the run-level optimism to close the trust gap. But the engine could/should make this distinction first-class.

## Suggestions (in increasing scope)

### 1. Tool-server health gate at run start

Before the first agent turn, ping the tool-execution server with a no-op (e.g., `terminal_execute` running `true`). If it fails, exit non-zero with a distinct code like `EXIT_TOOL_SERVER_UNREACHABLE` and an error event before the agent ever spends LLM tokens.

### 2. Distinguish exit codes

Today `exit_code=0` covers both "clean scan" and "agent terminated cleanly without doing useful work." Consider an additional exit code for "scan completed but with `coverage_percent < 50%` and the agent self-reported environmental failure in `finish_scan.executive_summary`." Wrappers can map this to a distinct UI state (we currently key off the new `coverage.json` JSONB column).

### 3. Mute / qualify `vendor_risk` when `coverage_percent < 100%`

A 100/100 vendor-risk score with `coverage_percent=0` is misleading regardless of how careful the wrapper is. Either:

- Set `vendor_risk.band = "unknown"` when `coverage_percent < 50%`, or
- Cap the displayable `vendor_risk.score` at `coverage_percent` (so 0 coverage ⇒ score capped at 0)
- Emit a top-level `run_meta.coverage_warning` flag the wrapper UI can render

### 4. Retry / circuit-break on `ConnectError`

A stretch — but if the tool server becomes unreachable mid-run, exponential backoff + a final exit-fast threshold would let scans recover from transient issues rather than burn 66 minutes of LLM time uselessly.

### 5. Surface the agent's `finish_scan.executive_summary` in `run_meta.json`

Today wrappers read `run_summary.summary_text` (which is auto-generated from finding counts) and *not* the agent's own narrative report. The agent already wrote an excellent summary explaining the environmental failure; copy/lift it into `run_meta.engagement_report` or similar so wrappers can display it.

## Investigation hints

The `ConnectError` flapped throughout the run (3 `llm.retry_attempted` events alongside the 14 tool-call attempts). This *might* correlate with sandbox-container resource pressure on macOS — the rebuilt image is 13.3 GB and Docker Desktop reported the parent system's `/var/lib/desktop-containerd` was at 95 % capacity earlier in the session.

But the agent's reports describe the failure as consistent ("every attempt"), not flapping. Worth looking at the per-tool-call `ConnectError`:

- Single tool-server PID dying and not respawning?
- Network namespace issue between agent container and tool container?
- Handshake with stale state (reused connection across runs?)
- macOS-specific Docker Desktop networking (qemu-bridged vs vmnet) edge case?

Available artifacts on request:

- `events.jsonl` (39 KB) — full event stream including the `ConnectError` payloads
- `run.signature.json` — for chain-integrity verification
- All 14 `tool.execution.updated` payloads showing the exact error per attempt
- Worker-side logs from `webappsec/worker`

## Wrapper-side context

For visibility: the wrapper this surfaced from is at [`ClatTribe/webappsec`](https://github.com/ClatTribe/webappsec). We just shipped a [coverage-banner fix (PR #64)](https://github.com/ClatTribe/webappsec/pull/64) that consumes `coverage.json` and renders an amber "coverage incomplete" banner that overrides the misleading 100/100 vendor-risk score. The banner's existence is itself evidence of the gap — wrapper authors will paper over the engine's `exit_code=0` if they don't read `coverage.json` carefully.

## Companion observation (separate but related)

A second `standard`-mode scan against the sibling **domain** target `getedunext.com` ran for **81 minutes** with 13 tool calls and *did* exercise the new fork tools (`domain_recon_pipeline`, `subdomain_enum`, `subdomain_takeover_check`, `passive_dns_history`, `dns_hygiene_check` — engine PRs #28, #119, #120). It also reported `coverage_percent: 0.0` and `status: incomplete`, but for a different reason: the domain target's required list includes web-app categories (`csrf`, `xss`, etc.) that aren't applicable to a `domain` target type.

Question for the maintainers: should `coverage.required` be filtered by `target_type` so a domain scan isn't perpetually marked incomplete because the agent (correctly) didn't run web-app probes?
