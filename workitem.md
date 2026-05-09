# Strix work items — dependency-ordered backlog

This is the post-§8.5 backlog ordered by dependency. Items in earlier
phases either (a) have no dependencies on other items, or (b) unblock
later items. Items in later phases require earlier ones.

Each entry tags the **tier** (A.1 = AI security engineer behavior;
A.2 = generic vulnerability discovery; B = operational quality),
**effort** (S/M/L), and **closes** (CWE / OWASP entry / manifest gap)
where applicable.

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## Phase 1 — Foundation (independent, unblocks everything else)

These are foundational. They don't depend on each other and can ship
in parallel. Phase 2+ items work substantially better — or only work
at all — once these land.

### 1.1 — Provider failover
- **Tier:** B · **Effort:** S
- **What:** When `llm.retry_attempted` rate exceeds threshold (e.g. 50%
  over a 5-minute window), automatically swap from
  `gemini-2.5-pro` → `claude-sonnet-4.5` (or `gpt-4o`) for the rest
  of the run. Surface the swap as a `llm.provider_failed_over` event.
- **Why first:** Today's benchmarks are 70-80% retry-bound. Every
  Phase 2+ feature is harder to validate without this. Single-day
  scan throughput goes from ~25 LLM calls / 30 min to ~80+ / 30 min.
- **Closes:** today's throttle ceiling

### 1.2 — Sandbox container sync on editable install
- **Tier:** B · **Effort:** S
- **What:** When `pip install -e .` runs against the strix package,
  the sandbox docker image rebuilds (or the live sandbox container
  is volume-mounted to the dev source tree). Eliminates the "specialist
  not found in sandbox" surprise that PR #182 hit.
- **Why first:** Without this, every specialist with `sandbox_execution=True`
  silently fails on dev installs. New specialists (Phase 2-4) all
  need this to be testable end-to-end.
- **Closes:** the post-#182 dependency-mismatch class

### 1.3 — OOB-DNS callback service (interactsh integration)
- **Tier:** B · **Effort:** M
- **What:** Wire the existing `interactsh-client` binary (already in
  the docker image's environment listing) into a strix-internal
  service. Specialists request a callback URL, the service polls
  the OOB infra, and emits a callback-received event when triggered.
- **Why first:** Unlocks blind-class detection across many later
  specialists (`scan_oob_xxe`, blind variants of `scan_ssrf`,
  `scan_cmd_injection`, `scan_deserialization`, `scan_log4shell`).
- **Closes:** all blind-class vulnerability detection

### 1.4 — Threat-model-aware probing from OpenAPI/Swagger
- **Tier:** A.1 · **Effort:** S
- **What:** When SecurityContext records a `/swagger`, `/openapi.json`,
  `/api-docs`, `/redoc` endpoint, parse the OpenAPI spec and auto-derive
  per-endpoint test plans: `POST` = state-change → CSRF + auth check;
  numeric path param = IDOR candidate; query string param = XSS/SQLi
  candidate; etc. Push as `partial_signal`s + specialist
  recommendations into SecurityContext.
- **Why first:** Independent; removes the "agent doesn't know what
  to probe" failure mode that throttling worsens. All Phase 2-4
  specialists become more effective with explicit per-endpoint plans.
- **Closes:** discovery gaps; targeting accuracy

### 1.5 — Knowledge base injection on tech-stack match
- **Tier:** A.1 · **Effort:** S
- **What:** SecurityContext already tracks `tech_stack` (server,
  language, framework, database). On tech-stack updates, inject
  stack-specific guidance into the prompt: "PHP detected → unserialize
  sinks; common CVEs: CVE-…"; "MongoDB detected → NoSQL operator
  payloads at request body level"; "Spring detected → Spring4Shell
  CVE-2022-22965 worth probing".
- **Why first:** Independent; makes Phase 2 specialists smarter at
  payload selection (e.g. `scan_sqli` chooses MSSQL fingerprints
  when `database: MSSQL`).
- **Closes:** generic-vs-targeted payload mismatch

### 1.6 — Decision provenance log
- **Tier:** A.1 · **Effort:** S
- **What:** Every emitted finding records the chain of probes that
  led to it: `(probe_X → signal_Y → hypothesis_Z → confirmed_via_W)`.
  Stored alongside `vulnerabilities.json`; rendered into the finding's
  `reasoning_trace` field (already exists in schema; underused).
- **Why first:** Independent; **enables the chaining graph (Phase 5)**.
  Wrappers can render reasoning trees, and the data feeds RLHF tuning.
- **Closes:** explainability gap

### 1.7 — Parallel specialist dispatch
- **Tier:** B · **Effort:** S
- **What:** When SecurityContext renders multiple specialist
  recommendations and the lead would invoke them serially, instead
  dispatch them concurrently via `asyncio.gather`. SecurityContext
  is thread-safe (per `threading.Lock` in #178); specialists don't
  share mutable state otherwise.
- **Why first:** Independent; 3-5× faster recon phase. Doesn't change
  detection logic.
- **Closes:** scan duration

---

## Phase 2 — Independent generic specialists (rule 2)

These specialists each close a CWE Top 25 / OWASP Top 10 entry. They
have no dependencies on each other and can ship in any order. Most
have in-band detection paths that work without OOB-DNS (Phase 1.3);
blind variants ship as a follow-up once 1.3 lands.

### 2.1 — `scan_ssrf`
- **Tier:** A.2 · **Effort:** M
- **What:** Probe URL/host/IP-typed params with `file://`, `gopher://`,
  `dict://`, internal IPs (`127.0.0.1`, `169.254.169.254`,
  `10.0.0.1`), cloud metadata endpoints (AWS IMDSv1+v2, GCP, Azure,
  OCI). In-band detection via response-content fingerprint; OOB
  detection via Phase 1.3 once that lands.
- **Closes:** A10:2021 (currently 0 coverage), CWE-918

### 2.2 — `scan_path_traversal`
- **Tier:** A.2 · **Effort:** M
- **What:** Probe file/path-shaped params (`file=`, `path=`, `template=`,
  `name=` with file-extension heuristic) with `../`, `....//`,
  URL-encoded variants (`..%2F`, `%2e%2e%2f`), null-byte truncation
  (`x%00.png`), absolute paths. Detect via known-content fingerprints
  (`/etc/passwd` line shape, `package.json` markers, `web.config` XML)
  + framework error patterns.
- **Closes:** CWE-22 (#5 CWE Top 25); Juice Shop `directory-traversal-ftp`
  manifest gap

### 2.3 — `scan_ssti`
- **Tier:** A.2 · **Effort:** S
- **What:** Polyglot template-injection probes: `{{7*7}}` (Jinja2/Twig),
  `${7*7}` (Freemarker/Spring SpEL), `#{7*7}` (Velocity), `<%= 7*7 %>`
  (ERB/JSP), `${{7*7}}` (Smarty), `#set($x=7*7)$x` (Velocity directive).
  Detection: response contains `49` near the canary location.
- **Closes:** CWE-1336 (SSTI — common modern bug class)

### 2.4 — `scan_nosql_injection`
- **Tier:** A.2 · **Effort:** S
- **What:** When `body_template` is a dict, also try operator-based
  payloads: `{"$ne":null}`, `{"$gt":""}`, `{"$where":"sleep(5000)"}`,
  `{"$regex":".*"}`, `{"$or":[{},{"x":""}]}`. PR #181 already added
  the `_NOSQL_PAYLOADS` constants — this work-item just wires them
  into the probe loop with a separate detection path (auth-bypass-style:
  baseline 401 → operator-payload 200 + token).
- **Closes:** A03:2021 NoSQL injection; Juice Shop `nosqli-products`
  manifest gap; CWE-943

### 2.5 — `scan_secrets_in_response`
- **Tier:** A.2 · **Effort:** S
- **What:** Hook `send_request` to scan every response body for
  AWS/GCP/Azure/Slack/SSH/private-key fingerprints (already have
  patterns in `secrets_scan` — extend to runtime). Auto-emit
  CWE-798 / CWE-200 finding when detected.
- **Closes:** CWE-200/798 (passive bonus on every probe)

### 2.6 — `scan_cmd_injection` (in-band variant)
- **Tier:** A.2 · **Effort:** M
- **What:** OS command injection via `;id`, `&&whoami`, backticks,
  `$()`, `|nslookup ...`. In-band detection: response contains
  `uid=N(name)` (Unix), `Microsoft Windows` (Windows). Time-based
  via `; sleep 5` (compare baseline + spike). Blind via OOB-DNS
  callback (depends on Phase 1.3).
- **Closes:** CWE-78/77/94 (3 of CWE Top 25)

### 2.7 — `scan_xpath_injection`
- **Tier:** A.2 · **Effort:** S
- **What:** XPath injection via `' or '1'='1`, `' or contains(.,'')`,
  `') or '1'='1`. Same shape as scan_sqli's auth-bypass for
  XML-backed login.
- **Closes:** CWE-643

### 2.8 — `scan_ldap_injection`
- **Tier:** A.2 · **Effort:** S
- **What:** LDAP injection: `*)(uid=*`, `*)(uid=*))(|(uid=*`,
  `admin*`, `*)(&)`. Targets LDAP-bound auth and search.
- **Closes:** CWE-90

### 2.9 — `scan_subdomain_takeover_active`
- **Tier:** A.2 · **Effort:** M
- **What:** Extends existing `subdomain_takeover_check` (read-only)
  with active probing: DNS resolution + CNAME inspection +
  signature matching for vulnerable third-party providers (S3,
  Heroku, GH Pages, Azure CDN, Fastly). Optionally attempts
  registration probe if user opts in.
- **Closes:** CWE-1390

### 2.10 — `scan_request_smuggling_active`
- **Tier:** A.2 · **Effort:** M
- **What:** Active CL.TE / TE.CL / TE.TE probing on top of the existing
  `request_smuggling_check` static analysis. Sends crafted CL/TE
  combinations and watches for response desynchronization.
- **Closes:** CWE-444

### 2.11 — `scan_oauth`
- **Tier:** A.2 · **Effort:** M
- **What:** OAuth-specific specialist: `state` parameter validation
  bypass, `redirect_uri` allowlist bypass (subdomain confusion,
  path tricks), missing `code_verifier` for PKCE, `scope` escalation,
  cross-site request forgery on auth callback.
- **Closes:** A07 expansion; OAuth-specific bugs not caught by
  generic auth-flow

---

## Phase 3 — Multi-role auth orchestration (gate for IDOR class)

### 3.1 — Multi-role authz orchestrator
- **Tier:** A.1 · **Effort:** M
- **What:** Extends `scan_auth_flow` to capture sessions for multiple
  user roles in one call:
    * **anon** (no creds) — already implicit
    * **default-creds** (existing — single user from successful
      default-cred attempt)
    * **registered-user** (from self-registration fallback)
    * **second-registered-user** (NEW — register a second account
      with a unique seed, capture independently)
    * **admin** (NEW — when default-creds matches a known-admin
      account or registered-user gains admin via separate path)
  All written to `SecurityContext.AuthState[label]`. Subsequent
  specialists can specify which `auth_label` to use; default cycles
  through all captured.
- **Why this position:** Depends on existing `scan_auth_flow` (have).
  **Required by 4.1 (`scan_idor`).** Many other specialists become
  more powerful with multi-role awareness but don't strictly require it.
- **Closes:** preconditions for IDOR + missing-auth detection

---

## Phase 4 — Dependent specialists

These require Phase 1.3 (OOB-DNS) or Phase 3.1 (multi-role auth).

### 4.1 — `scan_idor`
- **Tier:** A.2 · **Effort:** M
- **Depends on:** 3.1 (multi-role auth)
- **What:** Dedicated IDOR specialist. With User-A and User-B sessions
  captured, probe every endpoint with a numeric/UUID path or query
  param using each session's auth header against the OTHER user's
  resource ID. Auto-emit when User-B's session reads User-A's data.
- **Closes:** A01:2021 IDOR; CWE-639/CWE-284; Juice Shop `idor-basket`
  manifest gap (with proper category emit, not info_disclosure)

### 4.2 — `scan_oob_xxe`
- **Tier:** A.2 · **Effort:** M
- **Depends on:** 1.3 (OOB-DNS infra)
- **What:** Out-of-band XXE for blind cases that `scan_xxe`'s in-band
  detection misses. Parameter-entity payload that fetches
  `<callback-url>/<unique-token>`; OOB service signals when fetched.
- **Closes:** Juice Shop `deprecated-interface` manifest gap (the
  blind-XXE class); CWE-611 expansion

### 4.3 — `scan_cmd_injection` (blind variant)
- **Tier:** A.2 · **Effort:** S (delta vs 2.6)
- **Depends on:** 1.3 + 2.6
- **What:** Adds OOB-DNS callback payloads (`; nslookup <cb-url>`)
  to the existing in-band command injection specialist. Catches the
  bugs where output isn't echoed in the response.
- **Closes:** the rest of CWE-78/77

### 4.4 — `scan_deserialization`
- **Tier:** A.2 · **Effort:** L
- **Depends on:** 1.3 (OOB-DNS) + 1.5 (tech-stack KB)
- **What:** Stack-aware deserialization payloads:
    * Java — ysoserial gadget chains (CommonsCollections, Spring, etc.)
    * PHP — `O:N:"<class>":...` with magic-method gadgets
    * Python — pickle protocol payloads
    * Ruby — Marshal payloads
    * .NET — BinaryFormatter / TypeNameHandling abuse
  Detection: time-based + OOB callback. Phase 1.5's tech-stack hint
  selects the right family; without it, every probe is sent and most
  miss.
- **Closes:** A08:2021; CWE-502

### 4.5 — `scan_blind_ssrf`
- **Tier:** A.2 · **Effort:** S (delta vs 2.1)
- **Depends on:** 1.3 + 2.1
- **What:** OOB-DNS payloads (`http://<cb-url>/`) added to scan_ssrf.
  Catches SSRF where the response doesn't include the fetched content.
- **Closes:** the blind half of A10

---

## Phase 5 — AI security engineer reasoning improvements

These build on the foundation + specialists landed in Phases 1-4.

### 5.1 — Hypothesis-experiment-result loop
- **Tier:** A.1 · **Effort:** M
- **Depends on:** 1.6 (provenance log); ideally 1.4 (OpenAPI plans)
- **What:** Every tool call references a hypothesis ID. The lead
  picks the highest-EV unconfirmed hypothesis next instead of
  freelancing. `confirm_hypothesis` / `dismiss_hypothesis` are
  required after a probe. Surfaces stuck-without-progress patterns.
- **Closes:** the random-walk pattern from benchmark transcripts

### 5.2 — Vulnerability chaining graph
- **Tier:** A.1 · **Effort:** M
- **Depends on:** 1.6 (provenance log) + at least 5 specialists (have)
- **What:** Build a graph of `if A then B` findings — XSS → cookie
  theft → CSRF; weak JWT secret → forge token → IDOR; default-creds
  → admin access → arbitrary user data. Render the chain as a
  consolidated "exploit story" finding alongside individual findings.
- **Closes:** zero-day discovery via chaining; output quality jump

### 5.3 — Counter-example logging
- **Tier:** A.1 · **Effort:** S
- **Depends on:** none directly; pairs with 5.4 (telemetry)
- **What:** When an emitted finding has a path matching a specialist
  that returned 0 findings on the same endpoint, log the (input,
  expected output, actual output) tuple as a counter-example to
  `<run_dir>/specialist_misses.jsonl`.
- **Closes:** silent-regression detection for heuristic tuning

### 5.4 — Specialist call telemetry
- **Tier:** B · **Effort:** S
- **Depends on:** none
- **What:** Emit `specialist.miss` and `specialist.hit` events with
  enough metadata (tool, args, response shape, decision-path) for
  offline heuristic tuning. Output → `<run_dir>/specialist_telemetry.jsonl`.
- **Closes:** data gap for Phase 6.1

### 5.5 — Replay-with-mutation testing
- **Tier:** A.1 · **Effort:** M
- **Depends on:** mature specialist library (Phase 2-4); existing
  HAR/Burp ingest (have via `traffic_ingest`)
- **What:** Ingest a HAR or Burp file. For each captured request,
  auto-replay with a mutation matrix per param: SQLi, XSS, IDOR,
  command injection, SSRF, etc. Mostly orchestration on top of
  existing specialists.
- **Closes:** black-box coverage at SAST density

### 5.6 — `scan_business_logic`
- **Tier:** A.2 · **Effort:** L
- **Depends on:** 1.4 (OpenAPI threat model) + 3.1 (multi-role)
- **What:** Race conditions on critical flows (already have `race_check`
  primitive — extends), price/coupon tampering, parameter
  pollution for state-change endpoints, workflow skip (e.g. POST
  payment success without going through cart).
- **Closes:** A04:2021 (currently 0 coverage)

---

## Phase 6 — Advanced (depends on Phases 1-5 maturity)

### 6.1 — Active-learning specialist tuning
- **Tier:** A.1 · **Effort:** L
- **Depends on:** 5.3 (counter-examples) + 5.4 (telemetry) + a few
  weeks of run data
- **What:** When a specialist's miss-rate on a given pattern exceeds
  threshold, automatically generate a tuning suggestion (broaden
  fingerprint regex, lower length-delta threshold). Surface as a PR
  draft for the maintainer to review.
- **Closes:** self-improving detection without manual heuristic work

### 6.2 — Per-iteration EV budget allocator
- **Tier:** A.1 · **Effort:** M
- **Depends on:** 5.1 (hypothesis loop) + 5.4 (telemetry baseline)
- **What:** Score each next-best probe candidate by
  `expected_value = P(finding) × severity / cost`. Pick top-k each
  iteration instead of declared order. Concentrates throttle-bound
  scans on highest-yield probes.
- **Closes:** throughput-bound recall ceiling

### 6.3 — Differential testing
- **Tier:** A.1 · **Effort:** L
- **Depends on:** stable behavior baselines from 5.4 telemetry
- **What:** Compare app responses against a reference implementation
  (e.g., a clean Juice Shop instance) to find logic bugs / business
  rule violations. Surfaces only on regression / divergent behavior.
- **Closes:** unknown-unknown bugs the manifest doesn't pre-state

### 6.4 — Automatic exploit-chain PoC generation
- **Tier:** A.1 · **Effort:** M
- **Depends on:** 5.2 (chaining graph)
- **What:** For confirmed exploit chains, auto-generate a runnable
  Python/curl script that demonstrates the full impact (e.g.,
  default-creds → JWT capture → admin-endpoint readout → arbitrary
  user data). Distinguishes "list of findings" from "this is what
  an attacker actually does."
- **Closes:** report quality / customer-facing impact narrative

### 6.5 — Scan-resume + checkpoint
- **Tier:** B · **Effort:** M
- **Depends on:** SecurityContext persistence (have)
- **What:** When a scan is killed (throttle, budget, manual), the
  next invocation can resume from the saved SecurityContext +
  conversation history. Reduces wasted recon work on retries.
- **Closes:** retry-bound repeat work

---

## Coverage delta if all phases ship

| metric | today | after Phase 2 | after Phase 4 | after Phase 6 |
|---|---|---|---|---|
| OWASP Top 10 fully covered | 2/10 | 5/10 | 8/10 | 9/10 |
| OWASP Top 10 partial | 6/10 | 4/10 | 2/10 | 1/10 |
| CWE Top 25 fully covered | 8/25 | 13/25 | 18/25 | 20/25 |
| Juice Shop benchmark recall (target) | 3/9 | 5/9 | 7/9 | 8/9 |
| Cost per scan (Juice Shop) | $0.19 (native) | $0.30 | $0.50 | $0.70 |
| Time per scan | 12 min (native) | 20 min | 30 min | 40 min |

The cost/time growth is intentional — more specialists = more probes
= more LLM iterations, but recall climbs faster than cost.

---

## Recommended execution sequence (~8-10 weeks for one engineer)

**Week 1:** Phase 1.1 + 1.2 + 1.7 (foundational ops; 1-2 days each)
**Week 2:** Phase 1.3 + 1.4 + 1.5 + 1.6 (foundational reasoning;
  parallel)
**Week 3-4:** Phase 2 specialists (8 of them; ~2 days each, ship
  them in parallel as separate PRs)
**Week 5:** Phase 3.1 (multi-role orchestrator)
**Week 6:** Phase 4 specialists (5 of them, mostly fast follow-ups)
**Week 7-8:** Phase 5 reasoning improvements
**Week 9-10:** Phase 6 advanced (only if Phase 5 telemetry has
  enough data)

A dual-engineer team can compress this to ~5 weeks by parallelizing
Phase 2 specialists with Phase 1.3-1.6 reasoning work.
