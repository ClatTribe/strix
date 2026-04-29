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
8. [Multi-tool orchestration](#8-multi-tool-orchestration)
9. [Threat intelligence enrichment](#9-threat-intelligence-enrichment)
10. [Reporting and messaging integration](#10-reporting-and-messaging-integration)
11. [Triage and continuous-learning hooks](#11-triage-and-continuous-learning-hooks)
12. [Integration ergonomics](#12-integration-ergonomics)
13. [Research and longer-horizon ideas](#13-research-and-longer-horizon-ideas)

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
| ⬜ | **Phase-state events.** `phase.entered {phase}` for `recon`, `exploit`, `validate`, `report`. Today the agent slides between modes ad-hoc; an explicit phase machine makes progress visible and connects to the recon pipeline in §7. | Consumers can render a meaningful progress bar; the agent's own behaviour benefits from explicit phase boundaries (recon completeness check before exploit). | [`strix/agents/StrixAgent`](strix/agents/StrixAgent). | M |
| ⬜ | **Semantic checkpoint events: `check.started` / `check.completed`.** Per attack class × surface. `result` is one of `vulnerable`, `not_vulnerable`, `inconclusive`; include a `confidence` score. | A scan that tested 8 attack classes and found 2 vulns reads very differently from a scan that found 2 vulns with no idea what else was tried. This is the data behind a real coverage report and behind "negative coverage assertions" downstream. | New event types emitted from the per-class probe code. | M |
| ⬜ | **Findings tagged with a semantic category enum**, not just CWE. Suggested values: `sqli`, `xss`, `cmd_injection`, `ssrf`, `auth`, `authz`, `idor`, `crypto`, `info_disclosure`, `csrf`, `path_traversal`, `misconfig`, `race_condition`, `open_redirect`, `deserialization`, `mass_assignment`, `ssti`, `xxe`, `request_smuggling`, `cache_poisoning`, `subdomain_takeover`, `cors`, `jwt`, `oauth`, `graphql`, `other`. | CWE alone forces every consumer to redo keyword bucketing. Today downstream tools regex on title + CWE; that drifts. | `add_vulnerability_report` and the report dict shape in [`strix/tools/reporting`](strix/tools/reporting). | S |
| ⬜ | **Per-agent `category` tag on `agent.created`.** When a sub-agent is spawned to probe a single attack class, declare it. | Today downstream UIs render `agent.created.payload.task` verbatim, which is just the user's instruction echoed back. A category gives sub-agents named roles ("auth-attacker", "ssrf-scanner") rather than "Investigator #3". | Same place that builds the `agent.created` payload. | S |
| ⬜ | **`run.summary` event at scan end.** A one-paragraph plain-English summary: targets covered, categories tested, key findings, duration. The agent already writes a markdown report — emit the same summary as a structured event so consumers don't have to re-parse markdown. | Headline answer to "how did the scan go" in 10 seconds. Useful for CI exit logs, dashboard cards, Slack notifications. | Final phase of [`StrixAgent.execute_scan`](strix/agents/StrixAgent/strix_agent.py). | S |
| ⬜ | **`target.started` / `target.completed` events** with the target value. | Multi-target scans have no clean per-target progress today — consumers join across multiple events to figure out what's running where. | Multi-target loop in `execute_scan`. | S |
| ⬜ | **`finding.kill_chain` event for multi-step findings.** When a finding required several steps (leaked credential → re-used to log in → escalated to admin), emit a structured event grouping the tool-calls + reasoning steps that led to the finding. | "Pattern matcher" tools emit findings as standalone alerts. A real adversarial agent's value is the chain. Consumers render this as a numbered timeline; triage layers feed it into per-finding context. Triage-side consumers in §11 also depend on this. | New event type, populated when a finding is finalized. | M |

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
| ⬜ | **`vulnerabilities.json` alongside the per-finding markdown.** Same data the agent writes via `add_vulnerability_report`, no parsing required. Markdown stays for humans. | Today consumers parse `**Field:** value` lines out of `vuln-NNNN.md` — a literal-prefix regex that has silently broken before (the severity parser). | [`strix/tools/reporting`](strix/tools/reporting). | S |
| ⬜ | **Stable lowercase severity in machine-readable outputs.** Markdown can stay uppercased for display. | Today markdown uppercases, event payloads lowercase, CSV uppercases. Every consumer defensively `.lower()`s. | All severity write sites. | S |
| ⬜ | **`run_meta.json` written at run start.** Carries `run_id`, `run_name`, `start_time`, `model_name`, `targets`, `mode`, `max_iterations`, `scope_mode`. | Reconstructing the scan config from scattered sources (env vars, CLI args, computed defaults) is fragile. | Same place that creates the run directory. | S |
| ⬜ | **`run.configured` event with the resolved effective config.** Single event after CLI arg parsing. | Audit / debugging — know exactly what model + flags ran without recreating the env. | After arg parse + config resolve in [`strix/interface/main.py`](strix/interface/main.py). | S |
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

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **Explicit recon phase before exploit phase.** Recon completes a deterministic checklist (subdomain enumeration, service detection, tech fingerprinting, endpoint discovery, JS analysis) and emits `phase.completed {phase: recon, surface_map}` *before* the agent starts attacking. The exploit phase reads `surface_map` rather than re-discovering. | Today the agent oscillates between recon and exploit. It works for small targets but loses coverage on large ones — once the agent finds one bug, it tunnels into validating it and forgets the other 50 endpoints. Phase-gating forces breadth. | New phase machine in [`strix/agents/StrixAgent`](strix/agents/StrixAgent). Connects to `phase.entered` events in §1. | L |
| ⬜ | **Tech-stack fingerprinting → deterministic skill loading.** Detect framework/runtime/library versions via headers, fingerprints, dependency manifests; auto-load the matching skills. Django detected → `frameworks/django` loaded; Firebase SDK detected → `technologies/firebase` loaded. | Today `load_skill` is agent-driven and probabilistic. A deterministic mapping makes coverage repeatable. The agent can still pull additional skills via `load_skill` for edge cases. | New fingerprinter in `strix/tools/` + a registry mapping in [`strix/skills/`](strix/skills/). | M |
| ⬜ | **Coverage matrix per target type.** Document and enforce the minimum-category coverage for each target type. `web_application` → at minimum: authn, authz, IDOR, SQLi, XSS, SSRF, open redirect, CSRF, security headers, CORS, JWT/session handling, rate-limiting, error handling. The agent can't emit `run.completed` unless every required category has at least one `check.completed` event. | Without this, "comprehensive scan" means whatever the model felt like covering. With this, it means a known matrix. | New required-coverage table in [`strix/skills/scan_modes/`](strix/skills/scan_modes/) + an end-of-run validator. | M |
| ⬜ | **API Security Top 10 skill pack.** BOLA, broken authentication, broken object property level authorization, unrestricted resource consumption, function-level authorization, server-side request forgery, security misconfiguration, lack of inventory, unsafe consumption of APIs, mass assignment. Distinct from web-app top 10. | Today's skills lean web-app; pure-API targets get probabilistic API-specific coverage. The OWASP API Top 10 is the standard checklist. | New: `strix/skills/vulnerabilities/api_top_10/`. | M |
| ⬜ | **Supply-chain / dependency skill pack.** `npm audit`, `pip-audit`, `cargo audit`, `bundle audit`, plus `osv-scanner` for cross-ecosystem coverage. Findings flow through the canonical finding shape with `category: dependency`. | Today the agent might run these via terminal; a first-class skill makes it deterministic and emits structured findings. | New: `strix/skills/vulnerabilities/supply_chain/` + tool wrapper. | M |
| ⬜ | **Mobile API skill pack.** Deeplink / URI-scheme abuse, certificate-pinning bypass detection patterns, JWT-in-mobile-app, IPC, exported activities. | Android/iOS API backends are a huge attack surface; the same agent should be able to handle one if pointed at the API endpoint. | New: `strix/skills/vulnerabilities/mobile_api/`. | M |
| ⬜ | **Subdomain takeover detection** as a first-class check on `domain` targets. CNAME → unclaimed third-party service (S3 bucket, Heroku app, GitHub Pages, etc.). | A standard external-attack-surface check. The fingerprint database is well-known (e.g. `can-i-take-over-xyz`). | New tool wrapping `subjack` / `nuclei` takeover templates. | S |
| ⬜ | **JS analysis pass for SPAs.** Extract minified JS, run an extractor for endpoints, secrets, internal API structure. Feeds `surface_map` for the exploit phase. | Today large SPAs hide most of their attack surface inside bundled JS — endpoints the agent never sees by crawling HTML. | New tool wrapping `katana` + `LinkFinder` / `secretfinder` patterns. | M |
| ⬜ | **`--surface-map-only` / recon-only mode.** Run recon, emit the surface map, exit. Useful for separating expensive recon from cheap follow-up scans, and for wrappers that want to run recon nightly + targeted scans on demand. | Recon is the most expensive phase for many targets. Letting consumers run it independently unlocks a "weekly recon, daily targeted scan" pattern. | New mode flag + early-exit after `phase.completed {phase: recon}`. | S |

---

## 8. Multi-tool orchestration

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

## 9. Threat intelligence enrichment

A finding without context is just a string. An AI security engineer
contextualizes every finding: "this CVE is on the CISA KEV list", "this
maps to OWASP API4:2023", "this is the technique CAPEC-66". Today Strix
emits the finding; downstream consumers do this work themselves
(inconsistently). Building it into Strix means every consumer gets the
same enriched data.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **CVE / OSV lookup at fingerprint time.** When the recon phase (§7) detects a tech version, query OSV.dev / NVD for known CVEs affecting that version. Emit a finding for each known-vulnerable, unpatched dependency before the agent loop even starts. | Catches the obvious "you're running Express 4.16.0 which has CVE-2022-24999" without spending agent tokens. | New: [`strix/tools/cve_lookup/`](strix/tools/cve_lookup/) using OSV's free API. | M |
| ⬜ | **CISA KEV catalog enrichment.** Every CVE-attached finding tagged with `is_kev: bool` and `kev_added_at`. Drives prioritization. | KEV is the ground-truth list of actively-exploited CVEs. A finding that's on KEV is fix-now; the same CVE that isn't can be a sprint-later. | KEV catalog refresh + lookup in finding finalization. | S |
| ⬜ | **OWASP Top 10 / API Top 10 / MITRE ATT&CK auto-tagging.** Every finding tagged with the matching framework IDs (e.g. `owasp_top_10: A03:2021`, `owasp_api_top_10: API1:2023`, `mitre_attack: T1190`). | Compliance teams view findings through these lenses. Today every consumer maps CWE → framework manually. | Static mapping table in [`strix/skills/`](strix/skills/) + applied at finding-write time. | M |
| ⬜ | **Nuclei template auto-update at scan start.** Currently templates are baked into the sandbox image at build time. An optional `--update-templates` flag (or default-on for `deep` mode) pulls the latest from the upstream repo. | Nuclei templates ship daily; image-baked templates go stale within weeks. CVE coverage degrades as templates lag. | Pre-scan step in the recon phase. | S |
| ⬜ | **ExploitDB / Metasploit reference attachment.** When a finding maps to a known CVE, attach links to the matching ExploitDB / Metasploit / GitHub PoC entries. Display-only — does not fetch or execute the exploit. | Helps the user assess the realness of a CVE finding. The data is freely indexable. | Lookup table or live API in finding finalization. | S |
| ⬜ | **Systematic Perplexity / web-search use for fresh CVE intel.** `PERPLEXITY_API_KEY` already enables `web_search`, but its use is incidental. In `deep` mode and when a known-tech version is detected, run a structured query for "latest CVEs and exploits affecting `<tech> <version>`" and feed the result to the agent's context. | Today's web search is opportunistic. A structured CVE-intel query closes the gap between baked-in skills and the day-to-day CVE stream. | Hook in the recon phase + a templated query helper. | S |
| ⬜ | **MITRE ATT&CK technique tagging on tool calls.** Each `tool.execution.started` event optionally carries a `mitre_technique` field (e.g. `T1190` for an exploit attempt against a public-facing app). | Lets defensive consumers map a Strix scan into their own ATT&CK telemetry. | Per-tool registry annotation. | S |
| ⬜ | **Optional MISP / STIX / TAXII feed ingestion.** For enterprise deployments that already curate threat-intel feeds, accept a feed URL and use the IoCs / TTPs as additional context for the agent. | Enterprise pen-tests are graded against the customer's own threat model. Letting them feed it in keeps the scan relevant. | New: `strix/intel/feeds/`. Opt-in flag. | L |

---

## 10. Reporting and messaging integration

The contract between Strix and the rest of the developer's world: chat
notifications, PR comments, SIEM ingestion, dashboards. Today's only output
formats are markdown + the in-process events stream. These items add the
formats the rest of the toolchain expects.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`--webhook-url <url>` for live finding events.** POST each finding to the URL as it lands. HMAC-SHA256 signature in `X-Strix-Signature` header (key from `--webhook-secret` or env). Retry with backoff on non-2xx. | The standard way for any external system (Slack, JIRA, PagerDuty, custom dashboard) to consume findings without polling. | New flag + delivery worker. | M |
| ⬜ | **SARIF output (`--sarif <path>`).** Industry-standard JSON format for static-analysis findings. Consumed by GitHub Code Scanning, GitLab Security Dashboard, most enterprise SIEMs. | Without SARIF, security teams can't move findings into existing workflow. | Renderer over the canonical finding shape from §8. | M |
| ⬜ | **JUnit XML output (`--junit <path>`).** CI systems (Jenkins, GitLab CI, CircleCI, Azure DevOps) parse JUnit natively for test reporting. Renders findings as test failures. | Lets Strix slot into existing CI test-result UIs. | Renderer. | S |
| ⬜ | **JSON / CSV output flags.** `--json <path>`, `--csv <path>`. Same data as `vulnerabilities.json` (§5) but at the run level (one file with all findings). | "I just need to give this to a consultant" use case. | Trivial renderers. | S |
| ⬜ | **Slack / Teams / Discord card-ready payload mode.** A `--message-format slack-blocks` (also `teams-adaptive`, `discord-embed`) flag makes the webhook (or a separate `--message-output`) emit a payload that maps directly to the platform's card format. No template engine needed downstream. | Most chat integrations want one POST that renders well. Today every consumer assembles a card from raw fields. | Renderer per platform. | M |
| ⬜ | **`--web-base-url <url>` for deep-linkable findings.** Consumers (web UIs, dashboards) want to render "View in dashboard" links inside the markdown / message payloads. Strix uses `<base>/findings/<finding_id>` as the link template. | Webhook payloads are useless for routing humans back to a UI without this. | Template substitution in renderers. | S |
| ⬜ | **PR-comment-ready format.** A `--pr-comment <path>` flag emits short markdown ready for GitHub Actions to post via `gh pr comment`. Includes only diff-scope findings (when `--scope-mode diff`), severity-grouped, with the verdict line ("Block: 1 critical SSRF" / "Pass: 0 fix-now findings"). | The single most-requested CI integration. The format today (full markdown report) is too long for PR comments. | New renderer. | S |
| ⬜ | **Per-finding evidence bundle (`--evidence-bundle <dir>`).** Per finding, write a directory: `<finding_id>/{report.md, request.http, response.http, screenshot.png, tool_outputs.json}` so the full forensic trail travels with the finding. Optionally zip per-run. | Auditors and incident responders need everything-we-know-about-this-finding, not just the markdown summary. | Capture during agent execution + assemble at finalization. | M |
| ⬜ | **HTML email-ready summary report.** Self-contained HTML with inline CSS (no external assets) for a one-paragraph + table summary. | Many SMB users still operate via email; "send the scan summary to the security mailbox" is a real workflow. | Renderer using existing `run.summary` (§1). | S |

---

## 11. Triage and continuous-learning hooks

Strix doesn't ship a triage layer or a learning loop — that's a consumer
concern, and consumers should own their own triage. But for a consumer's
triage / RL / "we never see the same false positive twice" loop to *work*,
Strix has to emit the right shapes: stable fingerprints, embedding vectors,
verification distinctions, kill-chain traces. Without these, every consumer
reinvents the same fragile glue.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`verification_status` enum on every finding.** Values: `verified` (PoC ran and the vulnerable response was captured), `pattern_match` (signature only — e.g. a Semgrep regex hit), `inconclusive` (the agent saw evidence but couldn't confirm). | The "real vulnerabilities, not noise" promise hinges on this distinction. Verified findings should look unmistakably different to consumers. | Schema field on the report dict; agent populates based on tool-call outcome. | S |
| ⬜ | **PoC artifact reference on `verified` findings.** `poc_artifacts: [{type: "http_exchange", path: "..."}, {type: "screenshot", path: "..."}]`. Pairs with the evidence bundle (§10). | Today PoC content lives in the markdown body; structured references let consumers build "view PoC" UI without parsing markdown. | Same code path as `verification_status`. | S |
| ⬜ | **Stable, documented fingerprint algorithm.** Specify the exact algorithm (e.g. `sha256(cwe + ":" + endpoint + ":" + first_80_chars_of_normalized_title)`) in the [README](README.md). Emit the fingerprint on every finding. Bump a version field if the algorithm changes. | Cross-scan dedup needs stability across versions; today every consumer hashes their own way. | New field + documentation. Promotes the `dedup_key` item from §5. | S |
| ⬜ | **Optional per-finding embedding vector.** With `--emit-embeddings`, attach a `description_embedding: [float]` (and the model used) to each finding. Embedding model is configurable via env. | Per-tenant similarity search and "have we seen this before?" retrieval need embeddings. Computing them at finding-write time is far cheaper than re-embedding the corpus per query. Not default — costs tokens. | New optional field + a small embedding helper. | M |
| ⬜ | **`finding.kill_chain` event** (also referenced from §1). Structured representation of the multi-step exploit chain that produced a finding: ordered list of `{step, tool_call, observation, reasoning}`. | Triage layers want to render this as a timeline; consumers also feed it as RAG context for "is this a real attack chain or did the agent talk itself into one?". | New event type. | M |
| ⬜ | **Optional source-snippet attachment for code-target findings.** When the finding references `file:line`, attach N lines of source around it (default 20). Behind a `--attach-source-snippets` flag (off by default — increases finding payload size). | Today triage RAG layers re-clone the repo to pull these snippets. Attaching them at finding-write time means downstream triage works without filesystem access. | Reading sites in `add_vulnerability_report`. | S |
| ⬜ | **Cross-scan continuity input (`--prior-findings <path>`).** Accept a JSON array of prior findings (with fingerprint, status, triage notes). Agent's system prompt is augmented with "these were found previously; here's their status" so the model can re-test fixes / acknowledge known FPs / spot regressions rather than rediscovering. | Closes the "remembers what was tested last time" loop. The wrapper emits the prior set; Strix uses it. | New flag + system-prompt augmentation. | M |
| ⬜ | **Pre-finalization finding hook (`--on-finding-script <path>`).** Strix calls the script with the finding JSON on stdin before writing the finding. Script output: `pass` (write as-is), `dismiss` (skip), `enrich:<json>` (merge enrichment). | Consumer-side AI-triage / suppression rules / enrichment without forking Strix. CI users use it for project-specific suppressions; wrapper users use it for AI triage at the source. | New hook in `add_vulnerability_report`. | M |
| ⬜ | **Negative-coverage assertions in the report.** "We tested `/api/auth` for SQLi, IDOR, and broken session — clean." Derived from `check.completed {result: not_vulnerable}` events (§1). | A scan returning 0 findings looks like a broken scanner; a scan returning 0 findings *plus a coverage assertion* looks like a clean bill of health. | Aggregator at run finalization, written to the report and to a structured event. | S |

---

## 12. Integration ergonomics

Smaller items that smooth the rough edges between Strix and any non-CLI driver.

| | Item | Why | Where | Effort |
|---|---|---|---|---|
| ⬜ | **`--events-stdout` mode.** Interleaves NDJSON event records with normal stdout. | Useful for orchestrators that don't have filesystem access to the run directory. | TUI/CLI dispatch. | S |
| ⬜ | **`--state-dir <path>` flag.** Override the default `strix_runs/<run-name>/` location. | Wrappers want to control where state lands (mounted volume, per-scan tmpdir, etc.) without parsing run-name conventions. | Run-name resolution. | S |
| ⬜ | **`STRIX_PERSIST_CONFIG=false` documented.** Already supported (suppresses `~/.strix/cli-config.json` writes); just needs to be in the README so server-side users don't have to discover it. | Server workers shouldn't write user-config files. | Documentation. | S |

---

## 13. Research and longer-horizon ideas

Lower-confidence items. Listed for tracking, not committed.

- **Plan-then-execute mode.** Emit `run.test_plan` (§1) for review *before* spending tokens. Useful for high-cost scans where a human should approve scope.
- **Replay scan from a specific commit.** Re-run a prior scan against a different commit to verify a fix landed. Needs deterministic-enough sandboxing to be meaningful.
- **Differential triage signal.** When a finding's confidence shifts between scans (codebase changed, model changed), surface the delta and the reasoning rather than emitting a fresh finding.
- **Auto-remediation safety nets.** Before applying a generated patch, verify existing tests pass *and* add a regression test that the original PoC no longer exploits. Pairs with the triage hooks in §11.
- **Anonymized cross-org benchmarks.** Voluntary opt-in: "your stack typically has 3 SSRFs; you have 1." Privacy-respecting; the data is aggregated across consenting users only.
- **Threat-model-driven scanning.** Let users describe their app's architecture once (data-flow diagram, trust boundaries); the agent uses it as scaffolding. Pairs with §9's threat-intel feeds for enterprise relevance.
- **Bug-bounty disclosure pattern feed.** Anonymous learning from public HackerOne / Bugcrowd disclosures — extract the attack pattern, normalize it as a skill, ship the skill. The hard part is the legal/ethical review.

---

## How to land an item

1. Open an issue referencing the row above.
2. For event-shape changes (§1, §5, §11): include the proposed JSON shape in the issue. Once shipped, document the event in the [README](README.md).
3. For new flags (§2, §3, §4, §10): note the proposed semantic and how it interacts with existing flags. Flags that overlap with `--instruction` should clearly document precedence.
4. For new tools or skills (§7, §8, §9): the contribution should include a documented capability matrix (target types it applies to, categories it covers, expected runtime).
5. When an item ships, strike through the row and link the merged PR.

This roadmap is a living document. Items move between sections as we learn,
and "P0" today is whatever blocks real users from real outcomes — not a
fixed promise.
