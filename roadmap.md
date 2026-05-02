# Strix Roadmap

Forward-looking work for the Strix engine. Items below are prioritized by
user-visible impact: blockers for serious adoption first, then high-impact
additions, then nice-to-haves and research.

This roadmap is shaped by integration feedback — the bumps that show up when
real consumers (CI pipelines, headless wrappers, hosted platforms) drive
Strix at scale — and by the AI-security-engineer lens of "what does
comprehensive coverage actually require?". Most items are valuable to
direct CLI users; where an item is primarily a non-interactive concern,
the row says so.

Read alongside the [README](README.md) for what Strix already does and the
in-tree skills directory for how the agent's knowledge expands.

---

## Status legend

| | meaning |
|---|---|
| ✅ | shipped on `main` |
| 🚧 | partial — design landed or rough mitigation in place |
| ⬜ | open — not started |

Effort estimates: **S** ≈ a day, **M** ≈ a week, **L** ≈ a month.

---

## Table of contents

1. [Scan readability — what was actually checked](#1-scan-readability--what-was-actually-checked)
2. [Authenticated web application testing](#2-authenticated-web-application-testing)
3. [Per-target-type CLI flags](#3-per-target-type-cli-flags)
4. [Cost, control, and resilience](#4-cost-control-and-resilience)
5. [Structured outputs and event-stream contract](#5-structured-outputs-and-event-stream-contract)
6. [Cloud credential pass-through](#6-cloud-credential-pass-through)
7. [Comprehensive coverage and recon pipeline](#7-comprehensive-coverage-and-recon-pipeline)
8. [Specialist sub-agent teams per target type](#8-specialist-sub-agent-teams-per-target-type)
9. [Multi-tool orchestration](#9-multi-tool-orchestration)
10. [Threat intelligence enrichment](#10-threat-intelligence-enrichment)
11. [Reporting and messaging integration](#11-reporting-and-messaging-integration)
12. [Triage and continuous-learning hooks](#12-triage-and-continuous-learning-hooks)
13. [Integration ergonomics](#13-integration-ergonomics)
14. [Cross-target correlation and adversary modeling](#14-cross-target-correlation-and-adversary-modeling)
15. [Research and longer-horizon ideas](#15-research-and-longer-horizon-ideas)

---

## Recently shipped

Items that were `⬜` when this roadmap was first written and have landed on `main`. Each row links the merge commit so the history is browsable.

| Roadmap area | What landed | PR |
|---|---|---|
| §1 Scan readability | Findings tagged with semantic `category` enum (auto-inferred from CWE) | [#6](https://github.com/ClatTribe/strix/pull/6) |
| §1 Scan readability | `phase.entered` / `phase.completed` events for recon → exploit → validate → report | [#11](https://github.com/ClatTribe/strix/pull/11) |
| §1 Scan readability | `check.started` / `check.completed` events with vulnerable / not_vulnerable / inconclusive verdict + confidence | [#11](https://github.com/ClatTribe/strix/pull/11) |
| §5 Structured outputs | `vulnerabilities.json` written alongside markdown / CSV — full structured dump | [#6](https://github.com/ClatTribe/strix/pull/6) |
| §5 Structured outputs | `run_meta.json` at every save_run_data — scan config snapshot | [#6](https://github.com/ClatTribe/strix/pull/6) |
| §5 Structured outputs | `run.configured` event with effective scan_mode / scope_mode / model_name | [#6](https://github.com/ClatTribe/strix/pull/6) |
| §5 Structured outputs | `checks_summary.json` written when checks ran — counts per result + category, plus the not_vulnerable list | [#11](https://github.com/ClatTribe/strix/pull/11) |
| §7.0 Coverage / recon | Tech-stack fingerprinting → deterministic skill loading via `fingerprint_tech_stack` tool | [#10](https://github.com/ClatTribe/strix/pull/10) |
| §7.0 Coverage / recon | Coverage matrix per (target_type, scan_mode) with end-of-run gap detection — `coverage.json` + `run.coverage_complete` / `run.coverage_gap` events | [#13](https://github.com/ClatTribe/strix/pull/13) |
| §7.3 Domain checks | `dns_hygiene_check` — SPF / DMARC / DKIM / MTA-STS / CAA / DNSSEC / wildcard / AXFR | [#8](https://github.com/ClatTribe/strix/pull/8) |
| §7.3 Domain checks | `subdomain_takeover_check` — CNAME → 13-provider matrix with HTTP fingerprint verification | [#8](https://github.com/ClatTribe/strix/pull/8) |
| §7.3 Domain checks | `discover_cloud_assets` — S3 / GCS / Azure permutation discovery | [#8](https://github.com/ClatTribe/strix/pull/8) |
| §7.3 Domain checks | WAF / CDN detection (Cloudflare, Akamai) inside fingerprint tool — partial; doesn't reshape downstream scans yet | [#10](https://github.com/ClatTribe/strix/pull/10) |
| §9 Threat intel | CISA KEV catalog enrichment with 24h on-disk cache, fail-open | [#9](https://github.com/ClatTribe/strix/pull/9) |
| §9 Threat intel | OWASP Top 10 + OWASP API Top 10 + MITRE ATT&CK auto-tagging from CWE | [#9](https://github.com/ClatTribe/strix/pull/9) |
| §11 Triage hooks | `verification_status` enum (verified / pattern_match / inconclusive) | [#6](https://github.com/ClatTribe/strix/pull/6) |
| §11 Triage hooks | Negative-coverage data via `get_check_summary` + `checks_summary.json` | [#11](https://github.com/ClatTribe/strix/pull/11) |
| §11 Triage hooks | Stable, documented finding fingerprint algorithm (SHA-256 over normalized cwe + endpoint/file + title) with explicit version field | [#14](https://github.com/ClatTribe/strix/pull/14) |
| §11 Triage hooks | `# Coverage Assertions` section appended to `penetration_test_report.md` — categories tested cleanly per surface, with inconclusive caveat | [#14](https://github.com/ClatTribe/strix/pull/14) |
| §7.3 Domain checks | `org_fingerprint` — WHOIS / ASN / GitHub-org / typosquats with HTTP-fingerprint verification | [#16](https://github.com/ClatTribe/strix/pull/16) |
| §7.3 Domain checks | `passive_dns_history` — SecurityTrails + VirusTotal Passive DNS with fail-open when keys absent | [#16](https://github.com/ClatTribe/strix/pull/16) |
| §8.3 Domain team | `domain_recon_pipeline` orchestrator — composes the deterministic recon tools in one phase-bracketed call, persists `surface_map.json`, classifies subdomains deep/shallow/skip. Pragmatic interpretation of the specialist-team architecture | [#17](https://github.com/ClatTribe/strix/pull/17) |

Below, individual items that have shipped are marked ✅ inline. Items where part of the work has landed but more remains (e.g. WAF/CDN fingerprint detects but doesn't reshape downstream scans) are marked 🚧.

---

## 1. Scan readability — what was actually checked

A scan today emits agent identifiers, tool-call counts, and a final
`vulnerabilities/` directory. That tells the user *what was found* but not
*what was tried*. A clean run with zero findings is indistinguishable from a
broken run with zero findings. Closing that gap is the single biggest UX
improvement for non-CLI consumers (and a big one for the TUI).

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`run.test_plan` event after `run.configured`.** Carries the categories the planner intends to cover and the per-target planned checks. | Lets any consumer (TUI, CI log, dashboard) answer "what is this scan doing?" before findings exist. The planner already decomposes the instruction into sub-goals; this just surfaces them. | [`strix/agents/StrixAgent`](strix/agents/StrixAgent), planner stage. | M |
| ✅ | **Phase-state events.** `phase.entered {phase}` for `recon`, `exploit`, `validate`, `report`. Tracer API: `enter_phase` / `complete_phase`. Agent-callable via the `record_phase` tool. ([#11](https://github.com/ClatTribe/strix/pull/11)) | Consumers can render a meaningful progress bar; the agent's own behaviour benefits from explicit phase boundaries (recon completeness check before exploit). | [`strix/agents/StrixAgent`](strix/agents/StrixAgent). | M |
| ✅ | **Semantic checkpoint events: `check.started` / `check.completed`.** Per attack class × surface. `result` ∈ {vulnerable, not_vulnerable, inconclusive} with confidence. Aggregated per-run via `get_check_summary` and persisted to `checks_summary.json`. The recon tools in §7.3 emit one check per sub-check automatically. ([#11](https://github.com/ClatTribe/strix/pull/11)) | A scan that tested 8 attack classes and found 2 vulns reads very differently from a scan that found 2 vulns with no idea what else was tried. This is the data behind a real coverage report and behind "negative coverage assertions" downstream. | New event types emitted from the per-class probe code. | M |
| ✅ | **Findings tagged with a semantic category enum**, not just CWE. Auto-inferred from CWE via a 32-CWE map; agent can override explicitly via the `category` parameter on `create_vulnerability_report`. ([#6](https://github.com/ClatTribe/strix/pull/6)) | CWE alone forces every consumer to redo keyword bucketing. Today downstream tools regex on title + CWE; that drifts. | `add_vulnerability_report` and the report dict shape in [`strix/tools/reporting`](strix/tools/reporting). | S |
| ⬜ | **Per-agent `category` tag on `agent.created`.** When a sub-agent is spawned to probe a single attack class, declare it. | Today downstream UIs render `agent.created.payload.task` verbatim, which is just the user's instruction echoed back. A category gives sub-agents named roles ("auth-attacker", "ssrf-scanner") rather than "Investigator #3". Pairs with §8's specialist-team architecture. | Same place that builds the `agent.created` payload. | S |
| ⬜ | **`run.summary` event at scan end.** A one-paragraph plain-English summary: targets covered, categories tested, key findings, duration. The agent already writes a markdown report — emit the same summary as a structured event so consumers don't have to re-parse markdown. | Headline answer to "how did the scan go" in 10 seconds. Useful for CI exit logs, dashboard cards, Slack notifications. | Final phase of [`StrixAgent.execute_scan`](strix/agents/StrixAgent/strix_agent.py). | S |
| ⬜ | **`target.started` / `target.completed` events** with the target value. | Multi-target scans have no clean per-target progress today — consumers join across multiple events to figure out what's running where. | Multi-target loop in `execute_scan`. | S |
| ⬜ | **`finding.kill_chain` event for multi-step findings.** When a finding required several steps (leaked credential → re-used to log in → escalated to admin), emit a structured event grouping the tool-calls + reasoning steps that led to the finding. | "Pattern matcher" tools emit findings as standalone alerts. A real adversarial agent's value is the chain. Consumers render this as a numbered timeline; triage layers feed it into per-finding context. Triage-side consumers in §12 also depend on this. | New event type, populated when a finding is finalized. | M |

---

## 2. Authenticated web application testing

The single biggest coverage gap in Strix today: most real apps live behind a
login, and the only way to authenticate the agent is to put credentials in
`--instruction` text. That works inconsistently, and the credentials end up
in `events.jsonl` and the LLM's conversation history. Every team running
Strix against a non-trivial web app hits this.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`--auth-cookie <value>`, `--auth-bearer <token>`, `--auth-basic <user:pass>` flags.** Stored in an env var the HTTP-tool layer reads at request time; never injected into the prompt or logged in `events.jsonl`. The agent's system prompt gets a note "you have credentials; use them" — not the credentials themselves. | The fragile-by-default behavior today is the docs-prescribed pattern. A first-class flag means credentials cross the host→sandbox boundary as a transport concern, not a prompt concern. | New flags in [`strix/interface/main.py`](strix/interface/main.py); plumbing through `DockerRuntime` env to the HTTP tool inside the sandbox. | M |
| ⬜ | **`--header <name:value>` (repeatable).** API-key auth, custom WAF bypass, `X-Forwarded-For`, etc. Sensitive headers go on the same path as the auth flags above. | Any non-cookie/bearer auth scheme today has to live in the instruction. Breaks for any header-driven gateway. | Same plumbing as auth flags. | S |
| ⬜ | **Recorded-login replay for SSO / MFA.** A user records a login flow once (Playwright codegen-style); Strix replays it at scan start to acquire session state. WebAuthn / passkeys / hardware keys remain out of reach by design. | Today TOTP can be hand-fed via instruction; SSO redirects often work but with no guarantee; passkeys are impossible. Recorded replay is the standard escape hatch in commercial scanners. | New tool/recording mode + sandbox-side replay using existing Playwright integration. | L |
| ⬜ | **Built-in read-only IAM-style scan profile pattern**, documented. Once the auth flags above land, ship a documented pattern: provision a least-privilege test account, point Strix at it, rotate after the run. | Hygiene guidance shipped *with* Strix, not as a thing every user invents. | New section in [README](README.md) + a skill in `strix/skills/`. | S |

---

## 3. Per-target-type CLI flags

Strix's CLI today is intentionally small — `-t`, `-m`, `--instruction`,
`--scope-mode`, `--diff-base`. Per-target-type options end up in the
free-text `--instruction`, which the model honours about 80% of the time.
That's fine for hints (language, branch); it's not fine for safety-critical
controls (rate limits, exclude paths) where compliance matters.

Each item below is a thin flag with a clear semantic — a wrapper around an
existing tool the agent already invokes (`git clone`, `nmap`, the HTTP tool).

| | Item | Target type | Why | Proposed shape | Effort |
|---|---|---|---|---|---|
| ⬜ | **`--branch <ref>`** | `repository` | Today Strix clones the default branch. Security-conscious teams want to scan `develop` or `staging`. | Single string; passed to `git clone --branch` in [`clone_repository`](strix/interface/utils.py). Strix logs the resolved ref. | S |
| ⬜ | **`--seed-url <url>` (repeatable)** | `web_application` | Steer the crawl. "Don't start at /, start at /api and /admin." Pairs with the recon-first pipeline (§7) — a pre-scan crawl can hand seeds in. | Repeatable; agent treats them as the only crawl entrypoints unless told otherwise. | S |
| ⬜ | **`--exclude-path <glob>` (repeatable)** | `web_application` | "Don't hit `/api/billing/charge` or `/admin/destroy-account`." Hard rule, not a hint — production safety. The agent's HTTP tool short-circuits and emits a `tool.skipped {reason: excluded}` event if it tries to navigate to an excluded path. | New parameter on the HTTP tool; enforced at request time in the sandbox. | M |
| ⬜ | **`--openapi <url>`** | `web_application` | Test every documented endpoint. Today the agent has to discover the spec via crawl. | Strix fetches + parses + uses it as additional seed context. | S |
| ⬜ | **`--rate-limit <qps>`** | `web_application` | "Don't exceed 10 req/s — production traffic." Today the agent self-limits via natural language, which is unreliable. | Hard cap enforced inside the HTTP tool layer; not just a hint to the model. | M |
| ⬜ | **`--dns-only`** | `domain` | Surface mapping without active probing. | Disables HTTP-stage tools, keeps DNS / CT / passive recon. | S |
| ⬜ | **`--ports <spec>`** + **`--protocol <tcp\|udp\|both>`** | `ip_address` | Today's port/protocol selection lives inside the agent's nmap invocation. SMB / IoT users want explicit control. | Passed straight through to the underlying nmap command. | S |
| ⬜ | **CIDR / IP-range support on `-t`** | `ip_address` | "Scan my office's `203.0.113.0/24`." Today only single IPs are accepted. | Validator update + per-host fan-out (or pass-through if nmap can take it directly). | S |
| ⬜ | **`--preflight` / fail-fast unreachable check** | all network targets | A scan that runs for 10 minutes and finds nothing because the target was down is the worst-feeling failure mode. Resolve DNS + single HEAD/TCP probe before spawning the agent loop. | New phase before the recon phase in §7. | S |

Until each of these lands, the documented pattern stays "put it in
`--instruction`". When a flag lands, the corresponding instruction-augmentation
pattern in consumer wrappers can be deleted.

---

## 4. Cost, control, and resilience

A long Strix run is expensive. Today, runaway protection is the user's
responsibility — set `--max-iterations`, watch the rendered stats panel,
hope. These items move that responsibility into the engine.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`--max-cost <usd>` and `--max-input-tokens <n>` flags with self-exit.** Strix exits cleanly with a documented exit code (`3` = budget exceeded) and emits a `run.terminated` event. | Belt-and-braces against runaway. The cost panel shows totals only after they've been spent; a budget cap stops the spend. | LLM call site in [`strix/llm/llm.py`](strix/llm/llm.py); exit-code handling in [`strix/interface/main.py`](strix/interface/main.py). | M |
| ⬜ | **Retry transient LLM 5xx / rate-limits with exponential backoff.** Real incident: a Gemini `503 ServiceUnavailableError` mid-scan exits Strix immediately, throwing away a 7-minute agent context. Retry 2–3 times with `5s / 15s / 45s` backoff on 429/502/503/504 and `litellm.ServiceUnavailableError`. Emit `llm.retry_attempted` events. Only exit 1 if all retries fail. | A 30-minute scan disappearing because of one transient upstream blip is the worst-feeling failure mode. | LLM wrapper in [`strix/llm/llm.py`](strix/llm/llm.py). | S |
| ⬜ | **Clean SIGTERM handling.** On SIGTERM: cancel in-flight LLM call, flush `events.jsonl`, emit `run.cancelled`, tear down the sandbox, exit 143. Document the contract. | A scan-cancel button in any wrapper needs a signal it can trust. Today `kill -TERM` may leave half-written `events.jsonl` and an orphaned sandbox. | Signal handler in [`strix/interface/main.py`](strix/interface/main.py); cleanup hook in [`strix/runtime/docker_runtime.py`](strix/runtime/docker_runtime.py). | S |
| ⬜ | **Documented exit-code contract.** `0` = clean / no findings; `2` = clean / with findings; `1` = config or setup error; `3` = budget exceeded; `130` = SIGINT; `143` = SIGTERM. | Today `0/2 = success` is documented in a code comment. CI gates and wrapper logic need a contract they can rely on. | [README](README.md) + per-exit-path code that conforms. | S |
| ⬜ | **`run.heartbeat` event every ~60s** with `last_activity_at`, `seconds_idle`, `last_tool_call`, `last_llm_request_at`. | Detect stuck scans without polling. Real incident: Gemini Pro rate-limit hangs presented as a silently idle agent. | Background task in the agent loop. | S |

---

## 5. Structured outputs and event-stream contract

Strix's machine-readable surface today is `events.jsonl` plus the
`vulnerabilities/` markdown directory. It's good but inconsistent — some
data lives only in the rendered stdout panel, some severity values are
uppercased, finding parsing requires a literal-prefix regex. These items
clean that up.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Token / cost stats inside `events.jsonl`.** Emit `usage.updated` events as agents finish, or include a `total` + per-agent breakdown in the `run.completed` payload. Keep the rendered panel for the CLI; just *also* write the raw ints to `events.jsonl`. | Required for cost gating, billing, plan enforcement. Without persistence in the structured stream, every consumer scrapes stdout. The rendered panel humanizes counts (`2.6M`, `14.4K`) — losing precision above 1M. | Stats accumulator in [`strix/llm/llm.py`](strix/llm/llm.py) and the run-finalization path. | M |
| ⬜ | **Per-event token usage on each LLM round-trip.** Attach `{input_tokens, output_tokens, cached_tokens, cost, model}` to every `chat.message` (or a new `llm.request.completed` event). | Lets consumers enforce per-scan cost caps mid-flight, not post-mortem. Pairs with `--max-cost` above. | Same code path. | S |
| ✅ | **`vulnerabilities.json` alongside the per-finding markdown.** Schema versioned, includes all fields per finding plus run_id / generated_at / count. ([#6](https://github.com/ClatTribe/strix/pull/6)) | Today consumers parse `**Field:** value` lines out of `vuln-NNNN.md` — a literal-prefix regex that has silently broken before (the severity parser). | [`strix/tools/reporting`](strix/tools/reporting). | S |
| ⬜ | **Stable lowercase severity in machine-readable outputs.** Markdown can stay uppercased for display. | Today markdown uppercases, event payloads lowercase, CSV uppercases. Every consumer defensively `.lower()`s. | All severity write sites. | S |
| ✅ | **`run_meta.json` written at run start.** Now carries `run_id`, `run_name`, `start_time`, `end_time`, `targets`, `scan_mode`, `scope_mode`, `model_name`, `max_iterations`, `user_instructions`, `status`. ([#6](https://github.com/ClatTribe/strix/pull/6)) | Reconstructing the scan config from scattered sources (env vars, CLI args, computed defaults) is fragile. | Same place that creates the run directory. | S |
| ✅ | **`run.configured` event with the resolved effective config.** scan_mode / scope_mode / model_name now flow through from cli.py + tui.py into `set_scan_config`. ([#6](https://github.com/ClatTribe/strix/pull/6)) | Audit / debugging — know exactly what model + flags ran without recreating the env. | After arg parse + config resolve in [`strix/interface/main.py`](strix/interface/main.py). | S |
| ⬜ | **Documented `events.jsonl` flush contract.** Each line is flushed on write; consumers can tail in real time. Tail-friendly already in practice — just needs a contract. | Today consumers tail and hope. A documented contract lets them rely on it. | [README](README.md) + sanity check the writer. | S |
| ⬜ | **Agent / target context on every `tool.execution.*` event.** Include `agent_name` and `target` directly on the event. | Today consumers join across multiple events to display "Agent X on target Y" per tool call. | Tool execution event emitter. | S |
| ⬜ | **`--quiet` mode that still writes `events.jsonl`.** Suppress Rich panels and ANSI escapes; keep file output untouched. | Server-side use has no terminal — Rich panels are pollution and sometimes still emit ANSI under non-TTY detection. | TUI/CLI dispatch in [`strix/interface`](strix/interface). | S |

---

## 6. Cloud credential pass-through

Today's `DockerRuntime` env is hardcoded — see [`_create_container`](strix/runtime/docker_runtime.py):

```python
environment={
    "PYTHONUNBUFFERED": "1",
    "TOOL_SERVER_PORT": ...,
    "TOOL_SERVER_TOKEN": ...,
    "STRIX_SANDBOX_EXECUTION_TIMEOUT": ...,
    "HOST_GATEWAY": HOST_GATEWAY_HOSTNAME,
}
```

So a user's `AWS_ACCESS_KEY_ID` / `AZURE_CLIENT_*` / `GOOGLE_APPLICATION_CREDENTIALS` does not reach the agent. The documented workaround — putting credentials in `--instruction` — leaks them into `events.jsonl`.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Documented allow-list of cloud env vars passed through.** Default-off, opt-in via flag (e.g. `--pass-env AWS_*,AZURE_*,GOOGLE_APPLICATION_CREDENTIALS,KUBECONFIG`). Values are env-var-only — never logged in `events.jsonl`, never injected into the prompt. | Cloud testing without leaking secrets into the conversation history. | [`strix/runtime/docker_runtime.py`](strix/runtime/docker_runtime.py) `_create_container`. | S |
| ⬜ | **Native cloud skill packs.** AWS (`iam`, `s3`, `lambda`, `rds`, `cognito`), Azure (`entra`, `storage`), GCP (`iam`, `gcs`), Terraform / CloudFormation. Today only `cloud/kubernetes` exists. | The agent currently improvises with raw `aws` CLI; a skill pack gives it the playbook. | [`strix/skills/cloud/`](strix/skills/cloud/). | M |
| ⬜ | **Vault / secret-manager integration.** First-class `--vault hashicorp://path` / `--secret aws-secrets-manager:arn` flags that resolve at scan start and inject as env. | Production users keep credentials in vault, not env files. Without this, `--pass-env` above leans on the host being correctly configured. | New resolver layer before container spawn. | M |

---

## 7. Comprehensive coverage and recon pipeline

Sections 1–6 are about the contract between Strix and its consumers. This
section is about the **scan itself**: what does an AI security engineer
actually need Strix to do to claim "comprehensive coverage" of a target?

Today the agent decides what to do organically. That works — it's the
whole point — but it makes coverage probabilistic. A model that's tired,
distracted, or context-pressured may skip a category. The items below
introduce structured guarantees on top of agent improvisation: explicit
phases, tech-driven skill loading, and a coverage matrix the agent has to
clear before it can claim the scan is done.

The section is organized by target type because that's the natural way an
AI security engineer thinks about coverage — code targets need taint and
reachability analysis, web apps need an authz matrix and GraphQL handling,
domains need DNS hygiene and takeover detection, IPs need service-specialist
depth. The §7.0 foundations apply to every target type; the per-type
subsections list the specialist gaps.

### 7.0 Foundations (apply to every target type)

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| 🚧 | **Explicit recon phase before exploit phase.** Phase events + tracer API landed in [#11](https://github.com/ClatTribe/strix/pull/11). `surface_map.json` handoff artifact landed in [#17](https://github.com/ClatTribe/strix/pull/17) (the `domain_recon_pipeline` orchestrator emits it at the close of recon). Open: making the agent loop *required* to enter recon before exploit (currently the agent has to choose to call `record_phase` / the orchestrator). | Today the agent oscillates between recon and exploit. It works for small targets but loses coverage on large ones — once the agent finds one bug, it tunnels into validating it and forgets the other 50 endpoints. Phase-gating forces breadth. Foundation for §8. | Loop enforcement pending in [`strix/agents/StrixAgent`](strix/agents/StrixAgent); skill-prompt update could partially substitute. | L |
| ✅ | **Tech-stack fingerprinting → deterministic skill loading.** `fingerprint_tech_stack` tool detects via headers, cookies, body markers, and TLS cert SANs (Next.js / NestJS / FastAPI / Django / Rails / Laravel / Firebase / Supabase / WordPress / Cloudflare / etc.) and auto-loads the matching skills via the same internal API as `load_skill`. ([#10](https://github.com/ClatTribe/strix/pull/10)) | Today `load_skill` is agent-driven and probabilistic. A deterministic mapping makes coverage repeatable. The agent can still pull additional skills via `load_skill` for edge cases. | New fingerprinter in [`strix/tools/recon/fingerprint.py`](strix/tools/recon/fingerprint.py). | M |
| ✅ | **Coverage matrix per target type.** Required-category set defined per (target_type, scan_mode); end-of-run validator computes gaps from `check.completed` events, persists `coverage.json`, and emits `run.coverage_complete` / `run.coverage_gap` events. Override via `STRIX_COVERAGE_MATRIX_PATH`. ([#13](https://github.com/ClatTribe/strix/pull/13)) | Without this, "comprehensive scan" means whatever the model felt like covering. With this, it means a known matrix. | [`strix/telemetry/coverage.py`](strix/telemetry/coverage.py) + integration in `tracer.save_run_data`. | M |
| ⬜ | **`--surface-map-only` / recon-only mode.** Run recon, emit the surface map, exit. Useful for separating expensive recon from cheap follow-up scans, and for wrappers that want to run recon nightly + targeted scans on demand. | Recon is the most expensive phase for many targets. Letting consumers run it independently unlocks a "weekly recon, daily targeted scan" pattern. | New mode flag + early-exit after `phase.completed {phase: recon}`. | S |

### 7.1 Code targets (`repository`, `local_code`)

The white-box specialist team's missing capabilities. Today the agent
reads files line-by-line and reasons about flow in natural language —
wasteful and lossy on non-trivial codebases. These items raise the
floor.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Codebase map artifact at recon end.** A `code_map.json` listing entry points (HTTP routes, CLI commands, queue consumers), controllers, models, DB queries, external HTTP calls, auth-boundary file:line references, and a route → handler-file index. Built once; every downstream agent reads from it. | LLM-only code reasoning is wasteful — the agent re-greps the same routes 30 times in a long scan. A built artifact is read O(1) by every specialist. | New: `strix/tools/code_map/`. | M |
| ⬜ | **Taint analysis / data-flow tracing.** Trace user-controlled inputs (request body, query params, headers, cookies) to dangerous sinks (raw SQL, `exec`, `system`, file I/O, deserialization, template rendering). Emit candidate-flow findings the LLM then triages for false positives. Engine: CodeQL, Joern, or a built-in source-sink registry per language. | Static taint analysis is the single highest-precision SAST technique for injection-class bugs. Today Strix doesn't run any. | New: `strix/tools/taint/`. | L |
| ⬜ | **Reachability scoring on candidate findings.** For each candidate finding, score 0–1 by reachability from internet-facing entrypoints, dependency in the dependency graph, and whether the affected file is exercised by tests vs. only-imported-from-tests. Findings on dead code drop to severity:info; findings on the auth path bump to fix-now. | A SQL injection in dead code wastes triage cycles. Reachability-aware severity is closer to "real engineer" judgement. | Built on top of the codebase map. | M |
| ⬜ | **Git-history mining.** Scan recently-removed code (deleted in last N commits but still deployed if no release has happened), historical-version vulnerabilities, blame-based ownership for findings (so the report can route to the right team). | Today the agent scans HEAD; vulnerabilities introduced and removed go unseen even when still in production. | New: pre-scan git-walk in the recon phase. | M |
| ⬜ | **Diff-impact scoring (beyond binary).** For PR-scoped scans, score each changed line by reachability, exposure, and historical bug density of the surrounding file. A line in `auth.py` is higher-impact than a line in `tests/utils.py`. | Today `--scope-mode diff` is binary (in-scope or out). Real reviewers prioritize within the diff. | Built on top of the codebase map + git history. | S |
| ⬜ | **Supply-chain / dependency skill pack.** `npm audit`, `pip-audit`, `cargo audit`, `bundle audit`, plus `osv-scanner` for cross-ecosystem coverage. Findings flow through the canonical finding shape with `category: dependency`. | Today the agent might run these via terminal; a first-class skill makes it deterministic and emits structured findings. | New: `strix/skills/vulnerabilities/supply_chain/` + tool wrapper. | M |
| ⬜ | **White-box → black-box bridging (Validator agent).** For top-N candidate findings, spin up the app (`docker compose up`, language-specific runners) and exploit dynamically, capturing the vulnerable response. Sets `verification_status: verified` only when the exploit triggered. | Verified findings are the difference between "looks vulnerable" and "is vulnerable". Today this bridge is agent-discretion. | New: `strix/agents/ValidatorAgent/` (white-box code targets). | L |

### 7.2 Web application targets

Today's web-app coverage is good at injection-class probing and weak at
state-aware testing (race conditions, multi-step flows, authz matrix
testing, second-order injection). These items close the structural gaps.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Structured BFS crawl with JS-bundle endpoint extraction.** A dedicated crawl agent runs breadth-first (not the agent's natural depth-first), extracts endpoints from minified JS via `LinkFinder` patterns, parses sitemap.xml/robots.txt, optionally consumes `--openapi`. | Today large SPAs hide most of their attack surface inside bundled JS. Agent-driven crawl misses it. | New: `strix/tools/web_crawler/`. | M |
| ⬜ | **API Security Top 10 skill pack.** BOLA, broken authentication, broken object property level authorization, unrestricted resource consumption, function-level authorization, server-side request forgery, security misconfiguration, lack of inventory, unsafe consumption of APIs, mass assignment. Distinct from web-app top 10. | Today's skills lean web-app; pure-API targets get probabilistic API-specific coverage. The OWASP API Top 10 is the standard checklist. | New: `strix/skills/vulnerabilities/api_top_10/`. | M |
| ⬜ | **Authz matrix testing as a first-class probe.** For each (role × resource × verb) cell, send the request as that role and check outcome. Emit a per-cell `check.completed` event. | The classical pen-test approach to authorization. Today the agent fragments this across many sessions; gaps are inevitable. | New: `strix/tools/authz_matrix/` (consumes auth credentials from §2). | M |
| ⬜ | **GraphQL specialist support.** Auto-introspect, build the query graph, test field-level authz, depth/batching abuse, alias overloading, query-cost DoS. Falls back gracefully if introspection is disabled. | Today GraphQL endpoints get a probabilistic subset of the actual API tested. | New: `strix/tools/graphql/`. | M |
| ⬜ | **WebSocket / SSE first-class testing.** Connect, fuzz frames, test origin checks, auth-on-upgrade, message-level authz. | Today the agent can connect via terminal but has no structured fuzzing approach. Auth-on-upgrade and origin checks are routinely missed. | New: `strix/tools/websocket/`. | M |
| ⬜ | **Race-condition prober.** Turbo-Intruder-style dispatch: send N concurrent requests within milliseconds to test for TOCTOU on state-changing endpoints (purchase, redeem, transfer, change-password). | Race conditions are deterministic in concept and nearly impossible for an agent to test reliably without dedicated tooling. | New: `strix/tools/race/` using the existing python sandbox. | S |
| ⬜ | **State-mutation rollback / transactional probe pattern.** A documented pattern (and tool support) for safe testing of state-changing endpoints: snapshot DB → run probe → restore. Lets users say yes to deeper testing on staging. | Without this, `--exclude-path` is the only safety lever. Many users would consent to deeper testing if rollback existed. | New skill + helper. | M |
| ⬜ | **Cross-subdomain cookie/JWT scoping checks.** When multiple subdomains are in scope, probe whether session cookies leak across subdomain boundaries, JWT audience/issuer mismatch is exploitable, or `SameSite` settings are inconsistent. | Pivots between sister apps in the same org are a real attack class. Single-target scans never see them. | Cross-target probe. Pairs with §14 cross-target correlation. | M |

### 7.3 Domain targets

Domain targets are external-attack-surface scans. Today's coverage is
"subfinder + httpx + nuclei templates" — competent but incidental on the
checks that catch the most-impactful real findings.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ✅ | **Subdomain takeover detection** as a first-class check. `subdomain_takeover_check` tool covers a 13-provider matrix (GitHub Pages, Heroku, S3 website, Shopify, Tumblr, WordPress, Fastly, Azure CloudApp, Vercel, Netlify, Bitbucket, Ghost, ReadMe) with HTTP fingerprint verification for confirmed-vs-pattern-match distinction. ([#8](https://github.com/ClatTribe/strix/pull/8)) | A standard external-attack-surface check. The fingerprint database is well-known (e.g. `can-i-take-over-xyz`). High-impact, low-cost. | [`strix/tools/recon/takeover.py`](strix/tools/recon/takeover.py). | S |
| ✅ | **DNS hygiene checks.** `dns_hygiene_check` covers wildcard DNS, public AXFR exposure (per-NS), missing CAA, DNSSEC posture. ([#8](https://github.com/ClatTribe/strix/pull/8)) | DNS misconfiguration is rarely caught by HTTP-driven scanners but enables real attacks (subdomain takeover, mail spoofing, BGP hijack defense). | [`strix/tools/recon/dns_hygiene.py`](strix/tools/recon/dns_hygiene.py). | S |
| ✅ | **Email security checks.** SPF presence, DMARC presence + policy enforcement (p=none flagged), DKIM common-selector probe (default / google / k1 / mail / etc.), MTA-STS record + policy file reachability. ([#8](https://github.com/ClatTribe/strix/pull/8)) | 30-second checks that catch misconfigurations directly enabling phishing of the brand. Absent today. | Within [`strix/tools/recon/dns_hygiene.py`](strix/tools/recon/dns_hygiene.py). | S |
| ✅ | **Cloud asset discovery from org name.** `discover_cloud_assets` tool — wordlist of 24 suffixes × 6 prefixes against AWS S3, GCS, Azure Blob; configurable extra suffixes for org-specific naming. 200 → public listing (medium); 403 → owned namespace (info). ([#8](https://github.com/ClatTribe/strix/pull/8)) | Where real treasure lives in external recon. Today the agent has to be told. | [`strix/tools/recon/cloud_assets.py`](strix/tools/recon/cloud_assets.py). | M |
| ✅ | **Passive DNS history mining.** `passive_dns_history` tool integrates SecurityTrails (preferred) and VirusTotal Passive DNS. Fail-open when no keys configured. Returns merged historical resolutions + deduped subdomain list. ([#16](https://github.com/ClatTribe/strix/pull/16)) | Stale records are a classic source of subdomain-takeover candidates and hidden internal infra. | [`strix/tools/recon/passive_dns.py`](strix/tools/recon/passive_dns.py). | S |
| 🚧 | **WAF / CDN fingerprinting that reshapes downstream scans.** Detection landed in `fingerprint_tech_stack` (Cloudflare, Akamai). Open: bypass-pattern skill packs and downstream rate-limit tuning that consumes the detection. ([#10](https://github.com/ClatTribe/strix/pull/10) — partial) | Today the agent rediscovers WAF behaviour each scan. Up-front fingerprinting + skill-loading is far more efficient. | Recon-phase tool + skill registry. | S |
| ✅ | **Org-level fingerprinting.** `org_fingerprint` tool covers WHOIS (registrar, dates, NS, registrant org/country, privacy detection), ASN via Team Cymru, GitHub-org probes (apex label / dash-stripped variants), and ~25 typosquat candidates (homoglyphs / alt-TLDs / transpositions / deletions / neighbour-keys) with DNS-resolution + HEAD probing. Resolved typosquats emit info_disclosure findings. ([#16](https://github.com/ClatTribe/strix/pull/16)) | Today every domain target is an island. Real engagements scope to "everything we own"; this finds it. | [`strix/tools/recon/org_recon.py`](strix/tools/recon/org_recon.py). | M |
| ⬜ | **Email-security depth in dns_hygiene_check** — DANE / TLSA records, BIMI record, DMARC RUA mailbox reachability, SPF flattening / 10-lookup-limit audit, DKIM key-strength check (RSA-1024 weak vs 2048+). | Each one is a deterministic dig-or-HTTP query the agent currently skips. Real-world misconfigurations show up frequently in these dimensions even when the basic record is present. | Extend [`dns_hygiene_check`](strix/tools/recon/dns_hygiene.py). | S |
| ⬜ | **DNS-security depth in dns_hygiene_check** — open recursive resolver detection on the target's authoritative NS, dangling-NS detection (NS pointing at non-resolving servers). | Open resolvers signal lax operator hygiene + enable amplification attacks; dangling NS is a real-world subdomain-takeover precursor. | Extend [`dns_hygiene_check`](strix/tools/recon/dns_hygiene.py). | S |
| ⬜ | **Subdomain takeover provider expansion to 60+ providers.** Currently covers 13 of the ~60 in the `can-i-take-over-xyz` registry. Easy adds: Statuspage, Helpjuice, Cargocollective, Smartling, Cloudfront-S3-origin, AWS API Gateway custom domain, Google Sites, Surge.sh, Fly.io, Render. | Coverage gap surfaces during real engagements; provider matrix is the limiting factor on takeover detection. | Extend [`takeover.py`](strix/tools/recon/takeover.py)'s `_PROVIDERS` table. | S |
| ✅ | **Cloud-asset platform extensions** — Heroku apps, Vercel projects, Netlify sites, GitHub Pages, Firebase Hosting, Supabase projects via subdomain-pattern probing (`<org>.herokuapp.com`, `<org>.netlify.app`, `<org>.web.app`, etc.). Per-provider candidate generators: storage providers use the wide ~140-name bucket-permutation list; PaaS providers use a smaller 8-suffix app-name list. PaaS hits emit info-severity findings (CWE-200) with provider-specific guidance (Firebase Rules / Supabase RLS / abandoned-project takeover follow-up). ([#22](https://github.com/ClatTribe/strix/pull/22)) | Today's `discover_cloud_assets` covers S3 / GCS / Azure Blob only. PaaS platforms expose org-named projects with similar leak risk. | Extend [`discover_cloud_assets`](strix/tools/recon/cloud_assets.py). | M |
| ⬜ | **Public SaaS leak discovery** — Trello board permalinks, Notion published pages, Google Docs published links indexed for the org name. Mostly Google / Bing / archive.org dorking with org-name + platform-specific path patterns. | Real treasure source. Many orgs accidentally publish internal docs to "the world" via permalink. | New: `strix/tools/recon/saas_leaks.py`. | M |
| ⬜ | **Subdomain enumeration depth: amass + DNS bruteforce + permutations + Wayback Machine.** Today's pipeline uses subfinder + passive-DNS only. Add amass as a deeper-active source, DNS bruteforce with `commonspeak2` / `jhaddix` wordlists, permutation generation (`altdns`/`dnsgen`-style for `prod-*`, `*-internal`, `dev-*` patterns), and Wayback CDX as an explicit historical-URL source. | Subfinder typically finds 5–50 subdomains per org; deeper enumeration commonly 5–10× that. The §17 orchestrator's enum step is the limiting factor on coverage breadth. | Extend [`domain_recon_pipeline`](strix/tools/recon/domain_pipeline.py)'s subdomain step. | M |
| ⬜ | **Code-search for org domain** across GitHub / GitLab / Bitbucket. Finds dev/staging URLs and leaked secrets referencing the apex in committed code. | Catches subdomains never advertised externally. GitHub's public-API code-search is rate-limited but free. | New: `strix/tools/recon/code_search.py`. Opt-in via `STRIX_GITHUB_TOKEN`. | M |
| ⬜ | **Reverse-IP discovery.** Given the target's IP from `org_fingerprint`'s ASN lookup, query reverse-IP databases (HackerTarget free, ViewDNS free) to find other domains sharing the host. | Shared hosting often colocates orgs; a vulnerable neighbour can be a pivot vector. Cheap; useful even at info-severity. | New: `strix/tools/recon/reverse_ip.py`. | S |
| ⬜ | **MX server software fingerprint + sample-mail header analysis.** Resolve MX records, capture SMTP banner for version disclosure (single-packet exchange). When the user can supply a saved email from the target's domain, parse `Authentication-Results` for actual SPF/DKIM/DMARC pass/fail behaviour against real mail flow. | Validates that published records actually function — record presence ≠ working enforcement. | New: `strix/tools/recon/mail_recon.py`. | M |

### 7.4 IP / network targets

Today's IP-target coverage is `nmap + naabu + agent-improvised
service-specific probes`. The right tools, used inconsistently. These
items make service-specialist depth deterministic.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Service-specialist skill packs.** SMB (null sessions, signing, anonymous shares), RDP (BlueKeep, NLA, certificate validity), SSH (algorithms, host-key reuse, weak ciphers, auth methods), SNMP (default community, walk public OIDs), LDAP (anonymous bind, base DN enumeration), RPC, NFS (exports, anonymous mount), Database services (Mongo / Redis / Elastic / PostgreSQL — auth required?). Each is its own deterministic playbook. | Agent-discretion service probing means coverage varies by run. A skill pack per service makes it repeatable. | New: `strix/skills/protocols/<service>/` per service. | M |
| ⬜ | **IoT / OT protocol skill pack.** Modbus, BACnet, MQTT, CoAP, S7, DNP3, OPC-UA. Read-only enumeration; no actuator manipulation. Targets infra customers in industrial/IoT space. | Industrial customers have these in scope; today Strix can't usefully test them. | New: `strix/skills/protocols/ot/` + sandbox tool wrappers. | L |
| ⬜ | **Internal-network pivot awareness (with explicit auth).** For an authorized internal scan, after recon-mapping the target IP, discover the L2/L3 neighborhood (broadcast probes, ARP scan, traceroute pivots). Report what's reachable from this host. | "What does this compromised host see?" is the lateral-movement question every internal pen-test asks. | New tool, gated behind an explicit `--allow-internal-pivot` flag. | L |
| ⬜ | **Structured surface-map artifact for IP targets.** Today recon output is embedded in agent prose. A `surface_map.json` for IP targets: per-host port list, service versions, banner snippets, fingerprints. Read by every downstream specialist. | Same shape rationale as the codebase map (§7.1) — built once, read O(1). | New: emitted by the recon-trio (Port-scan + Service-detect + CVE-correlation) in §8.4. | S |

---

## 8. Specialist sub-agent teams per target type

Sections 1–7 are individual capability gaps. This section is the
**architectural commitment** that makes them sustainable.

Today Strix has multi-agent capability — the lead `StrixAgent` can
spawn sub-agents via `agents_graph` — but no structural commitment to
per-target specialization. The lead improvises which sub-agents to
spawn and what to delegate. The result is closer to *one strong
generalist with a bag of tools* than to a structured pen-test team. As
target complexity grows, the generalist's coverage starts to depend on
context size and model attention — both of which are noisy.

The shift is to **specialist sub-agent teams per target type**. Each
team has a lead (planner), a recon group, an exploit group, a validate
group, and a reporter. Each specialist owns one job, runs to a tight
budget, and emits canonical findings.

Three commitments make this tractable:

1. **Phase gating.** Recon must complete (and emit `surface_map`)
   before exploit starts. Exploit emits `candidate_findings`; validate
   consumes them; report consumes verified findings only. No phase
   blurring. Connects to §1 phase-state events and §7.0 explicit recon
   phase.

2. **Specialist scope.** Each sub-agent has one job, a tight system
   prompt, ~20 iterations max, and emits canonical findings. The model
   spends compute on the work, not on context-juggling. Concretely:
   the SQLi specialist's system prompt does not include the SSRF
   skill — and vice versa.

3. **Structured handoffs.** Recon → exploit handoff is `surface_map`.
   Exploit → validate is `candidate_findings`. Validate → report is
   `verified_findings` with PoCs. No prose-as-state — every handoff is
   a typed JSON artifact written to the run directory.

The sections below define the team roster per target type. Building the
teams is incremental: ship the lead-team scaffolding first (§8.0), then
one specialist per team per release.

### 8.0 Foundations (apply to every team)

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Documented lead-team protocol.** Spec for how a lead agent spawns specialists, hands off context, collects findings, adjudicates conflicts (e.g., two specialists report overlapping findings). Today this is implicit in `agents_graph`. | Without a documented protocol, every team reimplements coordination ad-hoc; bugs in coordination look like model-quality problems. | New design doc + reference impl in [`strix/agents/`](strix/agents/). | M |
| ⬜ | **Sub-agent canonical-finding contract.** Every sub-agent emits findings in the canonical shape (cf. §9). Validation at write time rejects malformed findings instead of letting them poison the report. | Cross-team dedup, cross-team confidence scoring depend on this. | Schema + validation in finding-write path. | S |
| ⬜ | **Per-sub-agent budget enforcement.** Each sub-agent has its own iteration / token / time budget; the lead enforces. A runaway specialist gets terminated and emits `agent.budget_exceeded` instead of starving the rest of the team. | Without per-sub-agent budgets, one over-eager specialist can burn the whole scan budget. | Budget tracking in `BaseAgent` state. | M |
| ⬜ | **Specialist scope discipline (system-prompt convention).** Each specialist's system prompt is small, single-purpose, and does **not** include the full Strix toolset. The SQLi specialist gets the SQLi skill + the HTTP tool, not the whole skill registry. | Today every spawned agent gets the full prompt; the breadth dilutes focus. Smaller prompts are also faster + cheaper. | Per-specialist prompt templates + a registry. | M |
| ⬜ | **Handoff artifact schemas (`surface_map.json`, `candidate_findings.json`, `verified_findings.json`).** Documented JSON schemas for every inter-phase handoff. | Replaces "prose as state" with structured contracts. Lets specialists be tested in isolation. | Schemas in `strix/agents/handoffs/`. | M |

### 8.1 Code-target team

```
  Code-Target Lead (planner)
   ├── Code-Map agent      — emits codebase map (routes, models, queries, external calls, auth boundaries)
   ├── Dependency agent    — SBOM + osv-scanner; emits CVE findings deterministically
   ├── Secret agent        — gitleaks + trufflehog + custom patterns
   ├── SAST agent          — Semgrep + per-language packs; emits pattern findings
   ├── Taint agent         — data-flow from user inputs to dangerous sinks
   ├── Reachability agent  — scores candidate findings by reachability from entrypoints
   ├── Validator agent     — for top-N candidates, spin up the app and exploit dynamically
   └── Reporter            — dedupes across specialists, ranks by reachability × severity
```

| | Item | Why | Effort |
|---|---|---|---|
| ⬜ | **Build the Code-Map agent first.** Single-purpose specialist that produces the codebase map artifact. All downstream agents read from it. | First specialist to land — others depend on it. | M |
| ⬜ | **Wire Dependency / Secret / SAST as deterministic specialists.** Each invokes its first-class tool (§9), emits canonical findings, exits. No improvisation. | Removes ~40% of LLM-driven coverage that should be deterministic, freeing tokens for the work that needs reasoning. | M |
| ⬜ | **Build the Taint agent.** Engine: CodeQL or Joern. The agent's role is to triage candidate flows for relevance and false-positive likelihood, then forward to the Validator. | LLM-only taint reasoning is lossy on non-trivial codebases. | L |
| ⬜ | **Build the Validator agent (the white-box → black-box bridge).** Spins up the app, exploits the candidate, captures the vulnerable response. Sets `verification_status` (§12). | Verified findings are the difference between "looks vulnerable" and "is vulnerable". Pairs with §7.1. | L |

### 8.2 Web-application team

```
  Web-App Lead (planner)
   ├── Fingerprint agent       — tech stack, framework, WAF/CDN; loads matching skills deterministically
   ├── Crawl agent             — structured BFS, JS-bundle extraction, OpenAPI discovery, sitemap parsing
   ├── Auth agent              — handles login (cookie/bearer/recorded-replay), maintains and refreshes session
   ├── Surface-map writer      — emits endpoints, parameters, auth requirements, content types, observed responses
   │ ─── recon phase done ───
   ├── Authz matrix agent      — for each (role × resource × verb), probe and assess
   ├── Injection agent         — SQLi/NoSQLi/SSTI/XSS/cmd/path probes, parameter-aware
   ├── SSRF agent              — internal-resource access, DNS rebinding, gopher/dict variants
   ├── IDOR agent              — predictable-ID enumeration, cross-tenant probing
   ├── GraphQL agent           — introspect, build query graph, field-level authz, depth/batching abuse
   ├── WebSocket agent         — origin checks, auth-on-upgrade, frame fuzzing
   ├── Race agent              — Turbo-Intruder-style for state-changing endpoints
   ├── Auth-flaws agent        — JWT alg-confusion, OAuth state CSRF, session fixation
   ├── Business-logic agent    — consumes threat model (§14); workflow abuse, entitlement bypass
   └── Verifier agent          — for each candidate, reproduce deterministically and capture PoC
```

| | Item | Why | Effort |
|---|---|---|---|
| ⬜ | **Build the recon group first** (Fingerprint + Crawl + Auth + Surface-map writer). Runs to completion; emits the surface map; nothing else starts before it. | Without a structured surface map, every exploit specialist re-discovers the surface — costly and lossy. | L |
| ⬜ | **Convert today's monolithic exploit behaviour into specialist exploit agents.** Start with the highest-leverage three: Authz-matrix, Injection, IDOR. Then SSRF, GraphQL, Race. | Specialists outperform a generalist when each owns one playbook. | L |
| ⬜ | **Build the Verifier agent.** Reads `candidate_findings`, reproduces, captures PoC. Sets `verification_status` (§12). | The "verified vs pattern-match" distinction has to come from a specialist whose only job is verification. | M |

### 8.3 Domain team

```
  Domain Lead
   ├── Subdomain enum agent       — subfinder + amass + CT + DNS bruteforce
   ├── DNS-hygiene agent          — SPF/DMARC/DKIM/MTA-STS/DANE/CAA scoring
   ├── Takeover agent             — CNAME → unclaimed third-party detection
   ├── Cloud-asset agent          — S3/GCS/Azure storage from org name + subdomain patterns
   ├── Passive-DNS agent          — historical resolution mining
   ├── Org-fingerprint agent      — WHOIS, ASN, GitHub org, similar-named orgs
   ├── Pivot-triage agent         — for each live subdomain, classify: deep | shallow | skip
   └── Web-app sub-teams           — invoked per "deep" subdomain with a tighter scope
```

| | Item | Why | Effort |
|---|---|---|---|
| ✅ | **Build the Pivot-triage agent.** Inline triage classifier in `domain_recon_pipeline` HEAD-probes each live subdomain, classifies as deep / shallow / skip based on status code + Content-Type. Surfaces in `surface_map.subdomain_triage` with `deep_targets` / `shallow_targets` lists. ([#17](https://github.com/ClatTribe/strix/pull/17)) | Coverage breadth without paying for deep scans on every subdomain. | [`strix/tools/recon/domain_pipeline.py`](strix/tools/recon/domain_pipeline.py) `_triage_subdomain`. | M |
| ⬜ | **Cross-team handoff: domain team spawns web-app sub-teams.** When Pivot-triage classifies a subdomain as "deep web app", spawn a full §8.2 team scoped to that subdomain. Today the orchestrator surfaces `deep_targets` for the agent to reason over; literal multi-agent sub-team spawning still pending. | Real attacks pivot from external recon to web-app exploitation. The architecture has to support it. | M |
| ✅ | **Build the DNS-hygiene + Email-security + Takeover trio first.** Shipped in #8 (`dns_hygiene_check` covering SPF/DMARC/DKIM/MTA-STS/CAA/DNSSEC/wildcard/AXFR + `subdomain_takeover_check` covering 13 providers). Composed alongside org_fingerprint / passive_dns / cloud_assets in the [#17](https://github.com/ClatTribe/strix/pull/17) `domain_recon_pipeline` orchestrator with phase events + `surface_map.json` handoff. | These are the "free wins" of domain-target scans. Shipping them first proves the team architecture without LLM cost noise. | M |
| ⬜ | **Domain orchestrator entry point landed; literal multi-agent sub-team architecture still open.** [#17](https://github.com/ClatTribe/strix/pull/17) ships `domain_recon_pipeline` which composes the deterministic specialists in one phase-bracketed call with a `surface_map.json` handoff — pragmatic interpretation of the team architecture. The literal version (parallel LLM contexts per specialist with isolated prompts and message-passing) is still open; payoff vs the orchestrator approach is debatable. | Multi-agent gives true parallelism + isolation per specialist; orchestrator gives the same handoff shape with one LLM context. | New: `strix/agents/DomainTeam/` if pursued. | XL |

### 8.4 IP / network team

```
  IP Lead
   ├── Port-scan agent          — nmap + naabu, deterministic top-1000 + targeted
   ├── Service-detect agent     — nmap -sV + banners + custom probes
   ├── CVE-correlation agent    — for each (service, version), OSV/NVD/exploit-db lookup
   ├── Service-specialists (parallel):
   │     ├── SMB-prober
   │     ├── SSH-prober
   │     ├── RDP-prober
   │     ├── SNMP-prober
   │     ├── LDAP-prober
   │     ├── HTTP-on-port-N → escalates to web-application sub-team
   │     └── Database-prober
   ├── Pivot-discovery agent    — only with explicit `--allow-internal-pivot`
   └── Reporter
```

| | Item | Why | Effort |
|---|---|---|---|
| ⬜ | **Build the recon trio first** (Port-scan + Service-detect + CVE-correlation). Every IP target should produce the same `surface_map.json` shape regardless of which paths the agent took that day. | Today an IP target's findings depend heavily on agent improvisation at recon time. Determinism is more valuable than creativity at the recon layer. | M |
| ⬜ | **Cross-team handoff: HTTP-on-port-N spawns a web-application sub-team.** When a service-detect agent identifies HTTP/HTTPS on any port, hand off to the §8.2 web-app team scoped to that URL. | Real internal IPs run web admin UIs on weird ports (8080, 8443, 9090, 5601 …). Cross-team handoff makes them first-class. | S |
| ⬜ | **Build service-specialists incrementally.** Start with SMB and SSH (highest hit rate in real engagements), then RDP, then the rest. | Each specialist is a contained delivery; users see depth improve with each release. | M |

---

## 9. Multi-tool orchestration

The Strix sandbox already ships `nuclei`, `nmap`, `sqlmap`, `subfinder`,
`naabu`, `ffuf`, `httpx`, `katana`, `semgrep`, and `trivy`. Today the agent
invokes them ad-hoc through `terminal_execute` and the resulting findings
are whatever it chooses to write. Promoting these tools to first-class
scanners — with structured outputs that flow into the canonical finding
shape — is what turns Strix from "an agent with tools" into "an
AI-orchestrated multi-tool platform".

The agent stays the lead. These tools are first-pass filters that surface
broad coverage cheaply; the agent still does verification, exploit chains,
and business-logic findings.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`nuclei_scan` first-class tool.** Wraps the in-sandbox `nuclei` binary with explicit template selection: by detected tech (from §7 fingerprinter), by category (CVEs, exposures, misconfigurations, takeovers), by severity floor. Emits canonical findings with `detected_by: nuclei` and the matching template ID. | Today the agent's nuclei use is improvised; templates that should always run on a given tech often don't. A first-class wrapper makes this deterministic. | New: [`strix/tools/nuclei/`](strix/tools/nuclei/). | M |
| ⬜ | **`semgrep_scan` first-class tool for code targets.** Auto-runs Semgrep with the `r/security-audit` and language-specific rule packs as a SAST first-pass; output normalized to canonical findings. | The agent's static analysis is LLM-based and slow. Semgrep covers high-confidence patterns in seconds and is complementary to LLM reasoning. | New: [`strix/tools/semgrep/`](strix/tools/semgrep/). | M |
| ⬜ | **`trivy_scan` first-class tool.** Auto-runs Trivy on `repository` / `local_code` targets for SBOM, IaC, image, and secret scanning. Output normalized. | Trivy is the broad-strokes coverage tool for code/IaC; today its output is raw stdout. | New: [`strix/tools/trivy/`](strix/tools/trivy/). | S |
| ⬜ | **Secret-detection first-pass tool.** Wraps `gitleaks` or `trufflehog` for `repository` / `local_code` targets. | Secrets in code are a high-confidence, high-impact category that's cheap to scan for and currently improvised. | New: [`strix/tools/secrets_scan/`](strix/tools/secrets_scan/). | S |
| ⬜ | **TLS/crypto first-pass tool.** Wraps `testssl.sh` or `sslyze` for any HTTPS target. | Crypto findings (weak ciphers, expired certs, missing HSTS, TLS 1.0) are deterministic and cheap. | New tool. | S |
| ⬜ | **Canonical finding shape across tools.** Define and document the contract: `(severity, cwe, category, target, endpoint, file, line, description_md, poc_md, remediation_md, detected_by, tool_metadata)`. Every first-class tool wrapper conforms. The agent's own findings conform too. | Without this, multi-tool output bleeds tool-specific shapes into the consumer. With it, adding a tool is invisible to anything downstream. | Document in [README](README.md) + enforce in tool wrappers. | S |
| ⬜ | **Cross-tool finding deduplication.** Same `(file, line, cwe)` from Strix + Semgrep collapses to one finding with `detected_by: ['strix', 'semgrep']`. | A multi-tool scan that returns 3× the findings is the opposite of what users want. | Extend dedup logic in `add_vulnerability_report`. | S |
| ⬜ | **SARIF intake for arbitrary external tools.** Read a SARIF file post-scan and ingest as canonical findings. Unlocks Snyk, CodeQL, Bandit, GitLeaks, Checkov, KICS, tfsec, tflint with a single adapter. | Lowest-effort way to support most of the OSS security ecosystem. | New: SARIF parser. | M |
| ⬜ | **Per-tool sandbox capability declarations.** Each tool wrapper declares what it needs (network, mounts, capabilities). Today the sandbox has blanket privileges for the agent's full toolset. | Defense in depth — Semgrep doesn't need network; Trivy doesn't need a privileged container. | Tool registry extension. | M |

---

## 10. Threat intelligence enrichment

A finding without context is just a string. An AI security engineer
contextualizes every finding: "this CVE is on the CISA KEV list", "this
maps to OWASP API4:2023", "this is the technique CAPEC-66". Today Strix
emits the finding; downstream consumers do this work themselves
(inconsistently). Building it into Strix means every consumer gets the
same enriched data.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **CVE / OSV lookup at fingerprint time.** When the recon phase (§7) detects a tech version, query OSV.dev / NVD for known CVEs affecting that version. Emit a finding for each known-vulnerable, unpatched dependency before the agent loop even starts. | Catches the obvious "you're running Express 4.16.0 which has CVE-2022-24999" without spending agent tokens. | New: [`strix/tools/cve_lookup/`](strix/tools/cve_lookup/) using OSV's free API. | M |
| ✅ | **CISA KEV catalog enrichment.** Every CVE-attached finding tagged with `is_kev`, `kev_added_at`, `kev_due_date`, `kev_ransomware_use`, `cisa_kev_url`. Lazy-loaded with 24h on-disk cache; fail-open on network failure (falls back to stale cache, then to "unknown"). Disable via `STRIX_KEV_DISABLED=1` for offline use. ([#9](https://github.com/ClatTribe/strix/pull/9)) | KEV is the ground-truth list of actively-exploited CVEs. A finding that's on KEV is fix-now; the same CVE that isn't can be a sprint-later. | [`strix/telemetry/threat_intel.py`](strix/telemetry/threat_intel.py). | S |
| ✅ | **OWASP Top 10 / API Top 10 / MITRE ATT&CK auto-tagging.** ~70 well-known CWEs mapped to OWASP Top 10 (2021); narrower set to OWASP API Top 10 (2023); curated CWE → ATT&CK technique-ID list. Surfaces in `vulnerabilities.json`, the markdown metadata block, and `vulnerabilities.csv`. ([#9](https://github.com/ClatTribe/strix/pull/9)) | Compliance teams view findings through these lenses. Today every consumer maps CWE → framework manually. | Static mapping tables in [`strix/telemetry/threat_intel.py`](strix/telemetry/threat_intel.py); applied at finding-write time. | M |
| ⬜ | **Nuclei template auto-update at scan start.** Currently templates are baked into the sandbox image at build time. An optional `--update-templates` flag (or default-on for `deep` mode) pulls the latest from the upstream repo. | Nuclei templates ship daily; image-baked templates go stale within weeks. CVE coverage degrades as templates lag. | Pre-scan step in the recon phase. | S |
| ⬜ | **ExploitDB / Metasploit reference attachment.** When a finding maps to a known CVE, attach links to the matching ExploitDB / Metasploit / GitHub PoC entries. Display-only — does not fetch or execute the exploit. | Helps the user assess the realness of a CVE finding. The data is freely indexable. | Lookup table or live API in finding finalization. | S |
| ⬜ | **Systematic Perplexity / web-search use for fresh CVE intel.** `PERPLEXITY_API_KEY` already enables `web_search`, but its use is incidental. In `deep` mode and when a known-tech version is detected, run a structured query for "latest CVEs and exploits affecting `<tech> <version>`" and feed the result to the agent's context. | Today's web search is opportunistic. A structured CVE-intel query closes the gap between baked-in skills and the day-to-day CVE stream. | Hook in the recon phase + a templated query helper. | S |
| ⬜ | **MITRE ATT&CK technique tagging on tool calls.** Each `tool.execution.started` event optionally carries a `mitre_technique` field (e.g. `T1190` for an exploit attempt against a public-facing app). | Lets defensive consumers map a Strix scan into their own ATT&CK telemetry. | Per-tool registry annotation. | S |
| ⬜ | **Optional MISP / STIX / TAXII feed ingestion.** For enterprise deployments that already curate threat-intel feeds, accept a feed URL and use the IoCs / TTPs as additional context for the agent. | Enterprise pen-tests are graded against the customer's own threat model. Letting them feed it in keeps the scan relevant. | New: `strix/intel/feeds/`. Opt-in flag. | L |
| ⬜ | **Shodan / Censys integration** for IP-based historical attack and exposure data. Surfaces "the IP this domain points at has been seen scanned for X by N actors in the last 30 days" + open-port history that the live scan can't see. | Adds an attacker's-eye-view of the asset's exposure history; complements the deterministic recon tools with operational intelligence. | New: `strix/intel/shodan.py` + `censys.py`. Opt-in via `STRIX_SHODAN_KEY` / `STRIX_CENSYS_KEY`. | M |
| ⬜ | **Have I Been Pwned domain breach lookup.** When a domain target is in scope, query HIBP's domain-search API for historical breaches affecting users at that domain. Emit findings noting the breach context. | Actionable for prioritising auth/session findings — "users at this domain were exposed in breach X 6 months ago". Pairs naturally with `org_fingerprint`. | New: `strix/intel/hibp.py`. Opt-in via `STRIX_HIBP_KEY`. | S |
| ⬜ | **Domain reputation lookups** — Spamhaus DBL, AbuseIPDB, URLhaus, Google Safe Browsing. Cheap blocklist queries surface whether the target's IP / domain has been flagged for abuse, malware-hosting, or phishing. | High-signal context: a "clean" target with an IP on URLhaus is a real finding (someone else compromised the shared host); a flagged domain you own is an incident-response lead. | New: `strix/intel/reputation.py`. Most APIs free with rate limits; some need keys. | S |

---

## 11. Reporting and messaging integration

The contract between Strix and the rest of the developer's world: chat
notifications, PR comments, SIEM ingestion, dashboards. Today's only output
formats are markdown + the in-process events stream. These items add the
formats the rest of the toolchain expects.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`--webhook-url <url>` for live finding events.** POST each finding to the URL as it lands. HMAC-SHA256 signature in `X-Strix-Signature` header (key from `--webhook-secret` or env). Retry with backoff on non-2xx. | The standard way for any external system (Slack, JIRA, PagerDuty, custom dashboard) to consume findings without polling. | New flag + delivery worker. | M |
| ⬜ | **SARIF output (`--sarif <path>`).** Industry-standard JSON format for static-analysis findings. Consumed by GitHub Code Scanning, GitLab Security Dashboard, most enterprise SIEMs. | Without SARIF, security teams can't move findings into existing workflow. | Renderer over the canonical finding shape from §9. | M |
| ⬜ | **JUnit XML output (`--junit <path>`).** CI systems (Jenkins, GitLab CI, CircleCI, Azure DevOps) parse JUnit natively for test reporting. Renders findings as test failures. | Lets Strix slot into existing CI test-result UIs. | Renderer. | S |
| ⬜ | **JSON / CSV output flags.** `--json <path>`, `--csv <path>`. Same data as `vulnerabilities.json` (§5) but at the run level (one file with all findings). | "I just need to give this to a consultant" use case. | Trivial renderers. | S |
| ⬜ | **Slack / Teams / Discord card-ready payload mode.** A `--message-format slack-blocks` (also `teams-adaptive`, `discord-embed`) flag makes the webhook (or a separate `--message-output`) emit a payload that maps directly to the platform's card format. No template engine needed downstream. | Most chat integrations want one POST that renders well. Today every consumer assembles a card from raw fields. | Renderer per platform. | M |
| ⬜ | **`--web-base-url <url>` for deep-linkable findings.** Consumers (web UIs, dashboards) want to render "View in dashboard" links inside the markdown / message payloads. Strix uses `<base>/findings/<finding_id>` as the link template. | Webhook payloads are useless for routing humans back to a UI without this. | Template substitution in renderers. | S |
| ⬜ | **PR-comment-ready format.** A `--pr-comment <path>` flag emits short markdown ready for GitHub Actions to post via `gh pr comment`. Includes only diff-scope findings (when `--scope-mode diff`), severity-grouped, with the verdict line ("Block: 1 critical SSRF" / "Pass: 0 fix-now findings"). | The single most-requested CI integration. The format today (full markdown report) is too long for PR comments. | New renderer. | S |
| ⬜ | **Per-finding evidence bundle (`--evidence-bundle <dir>`).** Per finding, write a directory: `<finding_id>/{report.md, request.http, response.http, screenshot.png, tool_outputs.json}` so the full forensic trail travels with the finding. Optionally zip per-run. | Auditors and incident responders need everything-we-know-about-this-finding, not just the markdown summary. | Capture during agent execution + assemble at finalization. | M |
| ⬜ | **HTML email-ready summary report.** Self-contained HTML with inline CSS (no external assets) for a one-paragraph + table summary. | Many SMB users still operate via email; "send the scan summary to the security mailbox" is a real workflow. | Renderer using existing `run.summary` (§1). | S |

---

## 12. Triage and continuous-learning hooks

Strix doesn't ship a triage layer or a learning loop — that's a consumer
concern, and consumers should own their own triage. But for a consumer's
triage / RL / "we never see the same false positive twice" loop to *work*,
Strix has to emit the right shapes: stable fingerprints, embedding vectors,
verification distinctions, kill-chain traces. Without these, every consumer
reinvents the same fragile glue.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ✅ | **`verification_status` enum on every finding.** Values: `verified` (PoC ran), `pattern_match` (signature only), `inconclusive`. Defaults to `verified` when `poc_script_code` is non-empty, else `inconclusive`; agent can override via the schema parameter. ([#6](https://github.com/ClatTribe/strix/pull/6)) | The "real vulnerabilities, not noise" promise hinges on this distinction. Verified findings should look unmistakably different to consumers. | Schema field on the report dict; agent populates based on tool-call outcome. | S |
| ⬜ | **PoC artifact reference on `verified` findings.** `poc_artifacts: [{type: "http_exchange", path: "..."}, {type: "screenshot", path: "..."}]`. Pairs with the evidence bundle (§11). | Today PoC content lives in the markdown body; structured references let consumers build "view PoC" UI without parsing markdown. | Same code path as `verification_status`. | S |
| ✅ | **Stable, documented fingerprint algorithm.** `sha256(normalize(cwe) + "\|" + normalize(endpoint or first_code_location.file) + "\|" + first_80_chars(normalize(title)))[:16]`. Emitted on every finding as `fingerprint` + `fingerprint_version`. Algorithm documented in `tracer.py`; version bump required for any change. ([#14](https://github.com/ClatTribe/strix/pull/14)) | Cross-scan dedup needs stability across versions; today every consumer hashes their own way. | [`strix/telemetry/tracer.py`](strix/telemetry/tracer.py) `compute_finding_fingerprint`. | S |
| ⬜ | **Optional per-finding embedding vector.** With `--emit-embeddings`, attach a `description_embedding: [float]` (and the model used) to each finding. Embedding model is configurable via env. | Per-tenant similarity search and "have we seen this before?" retrieval need embeddings. Computing them at finding-write time is far cheaper than re-embedding the corpus per query. Not default — costs tokens. | New optional field + a small embedding helper. | M |
| ⬜ | **`finding.kill_chain` event** (also referenced from §1). Structured representation of the multi-step exploit chain that produced a finding: ordered list of `{step, tool_call, observation, reasoning}`. | Triage layers want to render this as a timeline; consumers also feed it as RAG context for "is this a real attack chain or did the agent talk itself into one?". | New event type. | M |
| ⬜ | **Optional source-snippet attachment for code-target findings.** When the finding references `file:line`, attach N lines of source around it (default 20). Behind a `--attach-source-snippets` flag (off by default — increases finding payload size). | Today triage RAG layers re-clone the repo to pull these snippets. Attaching them at finding-write time means downstream triage works without filesystem access. | Reading sites in `add_vulnerability_report`. | S |
| ⬜ | **Cross-scan continuity input (`--prior-findings <path>`).** Accept a JSON array of prior findings (with fingerprint, status, triage notes). Agent's system prompt is augmented with "these were found previously; here's their status" so the model can re-test fixes / acknowledge known FPs / spot regressions rather than rediscovering. | Closes the "remembers what was tested last time" loop. The wrapper emits the prior set; Strix uses it. | New flag + system-prompt augmentation. | M |
| ⬜ | **Pre-finalization finding hook (`--on-finding-script <path>`).** Strix calls the script with the finding JSON on stdin before writing the finding. Script output: `pass` (write as-is), `dismiss` (skip), `enrich:<json>` (merge enrichment). | Consumer-side AI-triage / suppression rules / enrichment without forking Strix. CI users use it for project-specific suppressions; wrapper users use it for AI triage at the source. | New hook in `add_vulnerability_report`. | M |
| ✅ | **Negative-coverage assertions in the report.** Data side from [#11](https://github.com/ClatTribe/strix/pull/11) (`get_check_summary` + `checks_summary.json`); rendering into `penetration_test_report.md` landed in [#14](https://github.com/ClatTribe/strix/pull/14) — appends a `# Coverage Assertions` section listing categories tested cleanly per surface, plus an inconclusive caveat when relevant. Section omitted when no checks ran (honest by design). | A scan returning 0 findings looks like a broken scanner; a scan returning 0 findings *plus a coverage assertion* looks like a clean bill of health. | Aggregator + renderer in [`strix/telemetry/tracer.py`](strix/telemetry/tracer.py). | S |

---

## 13. Integration ergonomics

Smaller items that smooth the rough edges between Strix and any non-CLI driver.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`--events-stdout` mode.** Interleaves NDJSON event records with normal stdout. | Useful for orchestrators that don't have filesystem access to the run directory. | TUI/CLI dispatch. | S |
| ⬜ | **`--state-dir <path>` flag.** Override the default `strix_runs/<run-name>/` location. | Wrappers want to control where state lands (mounted volume, per-scan tmpdir, etc.) without parsing run-name conventions. | Run-name resolution. | S |
| ⬜ | **`STRIX_PERSIST_CONFIG=false` documented.** Already supported (suppresses `~/.strix/cli-config.json` writes); just needs to be in the README so server-side users don't have to discover it. | Server workers shouldn't write user-config files. | Documentation. | S |

---

## 14. Cross-target correlation and adversary modeling

Multi-target scans today are N independent scans that happen to share a
workspace. The agent doesn't natively connect findings across targets,
doesn't understand the user's threat model, and doesn't tune to a
specified adversary. The items below close those gaps and turn
multi-target scans into something closer to a real engagement.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Cross-target finding correlation.** A finding on one target that suggests an attack chain into another (e.g., SSRF on a `web_application` target → automatically probe reachability of any `ip_address` target in scope; subdomain takeover → probe related `web_application` targets for auth-bypass via the taken-over subdomain). The correlator is a first-class agent watching the shared findings store and emitting `chain_of_attack` findings. | Today every target is an island; real attacks span them. The chains are often the highest-impact findings. | New: `strix/agents/CorrelationAgent/`. | M |
| ⬜ | **Multi-target dependency graph.** When user passes `-t code-repo -t web-app -t domain`, the lead agent builds a dependency graph: "this repo deploys to that web-app at that domain." Cross-target findings reference the relationship. Recon teams in §8 share fingerprints across targets when they match. | Today multi-target scans are independent; correlation only happens when the agent notices and remembers. A built graph makes it deterministic. | Lead-agent recon stage. | M |
| ⬜ | **Structured threat-model input.** Today users put threat-model context in `--instruction` (prose). Better: a structured `--threat-model <file>` flag accepting YAML/JSON with: data classifications, trust boundaries, role list, sensitive operations, regulatory context (PCI / HIPAA / SOX / DPDP), high-value assets, abuse scenarios. The Business-logic specialist (§8.2) consumes this directly. | Without structure, business-logic findings are luck-of-the-draw. With structure, the lead agent prioritizes deterministically and the Business-logic agent has a real spec to test against. | New flag + system-prompt augmentation + schema in `docs/threat-model-schema.json`. | M |
| ⬜ | **Adversary-model selector.** `--adversary <model>` accepting `external` (default), `low_priv_user`, `insider`, `compromised_ci`, `peer_tenant`, `nation_state`. Reshapes which checks run, which credentials the agent assumes available, and the cost/risk tolerance for the testing. | One-size-fits-all `deep` mode treats every threat actor the same. Real assessments tune to who's modeled. | New flag + per-adversary scan-mode skills in [`strix/skills/scan_modes/`](strix/skills/scan_modes/). | M |
| ⬜ | **Cost-aware planning at the lead agent.** Given the budget (`--max-cost`, §4), the lead declares which target-type teams (§8) it will deploy and which it will skip, emits a `run.budget_plan` event up front, and sticks to it. Findings get a `priority_under_budget` field. The plan is published as part of `run.test_plan` (§1). | Today the agent runs until it runs out of iterations or the user runs out of patience. A real engineer scopes to the budget. | Lead-agent planner extension. | M |
| ⬜ | **Per-finding business-impact scoring.** When a threat model is provided, every finding gets a `business_impact: low/medium/high/critical` field derived from which trust boundary it crosses and which data classification it touches. | CWE severity is technical; business impact is what the user decides on. Computing it from the threat model means the consumer doesn't have to. | Finding finalization with threat-model lookup. | S |

---

## 15. Research and longer-horizon ideas

Lower-confidence items. Listed for tracking, not committed.

- **Plan-then-execute mode.** Emit `run.test_plan` (§1) for review *before* spending tokens. Useful for high-cost scans where a human should approve scope.
- **Replay scan from a specific commit.** Re-run a prior scan against a different commit to verify a fix landed. Needs deterministic-enough sandboxing to be meaningful.
- **Differential triage signal.** When a finding's confidence shifts between scans (codebase changed, model changed), surface the delta and the reasoning rather than emitting a fresh finding.
- **Auto-remediation safety nets.** Before applying a generated patch, verify existing tests pass *and* add a regression test that the original PoC no longer exploits. Pairs with the triage hooks in §12.
- **Anonymized cross-org benchmarks.** Voluntary opt-in: "your stack typically has 3 SSRFs; you have 1." Privacy-respecting; the data is aggregated across consenting users only.
- **Threat-model-driven scanning.** Let users describe their app's architecture once (data-flow diagram, trust boundaries); the agent uses it as scaffolding. Pairs with §10's threat-intel feeds for enterprise relevance and with §14's structured threat-model input.
- **Bug-bounty disclosure pattern feed.** Anonymous learning from public HackerOne / Bugcrowd disclosures — extract the attack pattern, normalize it as a skill, ship the skill. The hard part is the legal/ethical review.
- **Specialist-team cross-pollination.** A finding by the Web-app team's IDOR specialist sometimes hints at a related Code team Authz check (e.g., "this endpoint missed `@require_role` decorator"). Today the teams are siloed; cross-pollination would let one team's finding spawn a targeted check in another.

---

## How to land an item

1. Open an issue referencing the row above.
2. For event-shape changes (§1, §5, §12): include the proposed JSON shape in the issue. Once shipped, document the event in the [README](README.md).
3. For new flags (§2, §3, §4, §11, §14): note the proposed semantic and how it interacts with existing flags. Flags that overlap with `--instruction` should clearly document precedence.
4. For new tools or skills (§7, §9, §10): the contribution should include a documented capability matrix (target types it applies to, categories it covers, expected runtime).
5. For new sub-agent specialists (§8): include the system prompt, the iteration/token budget, the input/output schemas, and at least one end-to-end integration test against a known-vulnerable fixture.
6. When an item ships, strike through the row and link the merged PR.

This roadmap is a living document. Items move between sections as we learn,
and "P0" today is whatever blocks real users from real outcomes — not a
fixed promise.
