---
name: unknown-vuln-hypothesis
description: Hypothesising novel vulnerability classes from architectural primitives — webhook receivers, signed payloads, queue consumers, AI agents
triggers: [unknown vuln, novel attack, hypothesis, architectural primitive, webhook, signed payload, queue, batch import]
---

# Unknown-Vuln Hypothesis

Skills like `sql_injection.md`, `xss.md`, `cache_deception.md` teach known patterns. This skill teaches the agent to **hypothesise new attack classes from architectural primitives** — patterns it sees in the codebase or traffic that *look like* they should be vulnerable, even when no published CWE matches yet. The lead loads this skill when the surface looks "interesting" but no specialist matches.

This is the most valuable single meta-skill: it makes Strix capable of **discovering** vulns, not just **detecting** them.

## The Method

For any new architectural pattern the agent encounters, work through 5 questions:

### 1. What trust boundary does this primitive cross?
A trust boundary is anywhere data goes from a less-trusted to a more-trusted context. Examples:
- HTTP request → application server (the classic web boundary)
- Application → database (less-trusted business logic → trusted persistence)
- Application → external service (internet boundary; SSRF surface)
- One service → another in service mesh (intra-VPC trust)
- Webhook receiver → app's business logic (third-party → first-party)
- Queue producer → queue consumer (one operator → another, time-shifted)
- LLM → tool execution (the new "I'm trusted but compromised" boundary)
- AI training data → model behavior (slow-but-permanent boundary)

### 2. What invariants is the primitive supposed to enforce?
For each boundary:
- Signature / HMAC verification?
- Schema validation?
- Authentication of the producer?
- Idempotency (single-use token)?
- Time-bound freshness (TTL, nonce)?
- Source-attribution (which user / service originated)?

### 3. What happens if each invariant fails (independently)?
For each invariant the primitive claims to enforce, ask: "if this check is missing, what's the worst case?"

- No HMAC → attacker spoofs the producer
- No schema validation → attacker injects fields the consumer doesn't expect (mass assignment, prototype pollution, deserialisation gadgets)
- No idempotency → replay attack (double-spend, double-charge, double-grant)
- No time-bound → indefinitely-valid stale data
- No source-attribution → confused-deputy / cross-user data corruption

### 4. Can the attacker reach the primitive?
For each likely-broken invariant, ask: "what's the attacker's entry point?"
- Public webhook URL → anyone can fire requests
- Internal queue → attacker needs upstream compromise
- Internal API → attacker needs SSRF or network position
- AI tool call → attacker needs prompt-injection capability

### 5. What's the chain to impact?
The hypothesis is concrete when you can name:
- Entry: how the attacker triggers the primitive
- Bypass: which invariant fails
- Outcome: what the attacker accomplishes
- Mitigations that would block each step

## Worked Examples

### Example 1 — Stripe-like webhook receiver

**Primitive observed**: app has a route `/api/webhooks/stripe` that receives `payment.succeeded` events and provisions premium features.

**Trust boundary**: third-party (Stripe's servers) → first-party (app's fulfillment).

**Invariants**:
- Webhook signature verification (HMAC over body + timestamp).
- Event-id deduplication.
- Idempotency of fulfillment.

**Hypotheses** (numbered by which invariant fails):
1. Signature verification missing → attacker spoofs `payment.succeeded` events for any customer → provision premium for arbitrary users.
2. Event-id dedup missing → attacker captures one legitimate event + replays N times → N-fold fulfillment for the same payment.
3. Idempotency on fulfillment missing → race-condition: two concurrent valid webhooks → double-provision.

**Reachability**: webhook URL is public + linked from app for Stripe's webhook UI. Discovery is easy.

**Chain to impact**: hypothesis 1 → free premium accounts → revenue loss.

**Specialist to dispatch**: `dispatch_specialist(category="generic", objective="probe /api/webhooks/stripe for missing signature verification", skills_override=["stripe"])` — or fall back to manual probing.

### Example 2 — Background queue consumer

**Primitive observed**: app uses Celery / Sidekiq / BullMQ with a queue that accepts user-submitted tasks (e.g., "generate PDF report for user X").

**Trust boundary**: web layer → queue producer (web puts task into queue) → queue consumer (worker picks up + runs).

**Invariants**:
- Worker validates task payload before processing.
- Task includes user-attribution (knows which user requested it).
- Worker enforces per-user permissions.
- Task TTL prevents stale-task abuse.

**Hypotheses**:
1. Worker doesn't validate user-attribution → task says "generate report for user 1" but the requesting principal is user 2 → cross-user data leak.
2. Task payload contains user-supplied paths / filenames → path-traversal / SSRF when worker fetches.
3. No TTL → tasks from yesterday still process; rolled-back permissions don't apply.

**Reachability**: anyone authenticated to the web layer can submit tasks.

**Chain**: hypothesis 1 → cross-tenant data via report-as-pdf endpoint → bulk exfil.

### Example 3 — LLM agent with a "DB query" tool

**Primitive observed**: LangChain agent has a SQL tool (`SQLDatabaseToolkit`) that lets the LLM run queries.

**Trust boundary**: user (untrusted) → LLM (theoretically follows system prompt) → SQL execution (definitely runs whatever LLM produces).

**Invariants**:
- LLM only emits SQL that matches the user's authority.
- App parameterises any user-supplied values before LLM constructs the query.
- App validates the SQL before executing.

**Hypotheses**:
1. Prompt injection causes LLM to emit SQL with attacker-chosen WHERE → cross-user data.
2. LLM emits valid SQL but the SELECT scope exceeds the user's authority → privilege escalation.
3. LLM emits destructive SQL (DELETE / DROP) → data destruction.
4. SQL goes through without parameterisation → secondary SQLi when user input flows into the SQL string.

**Reachability**: any user with chat access.

**Chain**: prompt-injection skill confirms LLM is injectable → hypothesis 1 → bulk user-data exfil.

### Example 4 — AI-generated content with side-effect markup

**Primitive observed**: app generates emails via LLM, then sends them. Emails contain Markdown that's rendered to HTML.

**Trust boundary**: user prompt → LLM output → email body → recipient.

**Invariants**:
- Markdown renderer doesn't allow JS / inline event handlers.
- Email links validated (no `javascript:` URIs).
- Tracking pixels can't exfil unintended data.

**Hypotheses**:
1. Prompt injection → LLM emits `<script>` in markdown → renderer doesn't strip → email-borne XSS in webmail clients that render HTML.
2. LLM emits `<img src="javascript:...">` → webmail with weak sanitiser executes.
3. LLM exfils sensitive data via tracking-pixel URL containing user secrets.

**Chain**: prompt-injection-confirms → hypothesis 1 → mass-phishing platform under brand's domain.

## Operational Runbook

### Step 1 — recognise an unfamiliar primitive
Patterns the agent should pay attention to:
- Routes named `/webhooks/*`, `/callback`, `/_internal/*`, `/events`
- Code that calls `crypto.timingSafeEqual` or `hmac.compare` — there's a signature being verified (or one *should* be)
- ORM models with `before_save` / `before_update` callbacks — hidden business logic
- Async job processors (Celery, Sidekiq, BullMQ, Inngest, Trigger.dev)
- AI agents with tools registered (Function calling, LangChain Tool classes)
- File uploaders that process / transform / OCR / parse
- "Batch import" endpoints that ingest CSV / JSON / XLSX

### Step 2 — work through the 5 questions
Write them out. Even a paragraph each is enough.

### Step 3 — identify the cheapest verifiable hypothesis
Among the hypotheses, which is fastest to confirm? Usually:
- Send a malformed request and see if validation rejects it.
- Send a request with a tampered signature and see if it's processed.
- Send a replay of a captured legit request.

### Step 4 — dispatch a specialist for verification
If a known specialist exists (e.g., signature verification → no specific tool but `scan_business_logic` covers the class), dispatch it with a precise objective.

Otherwise, manual probing via `send_request` is fine — emit a finding when verified.

### Step 5 — file the finding even if the hypothesis was wrong
Even a confirmed-not-vulnerable hypothesis is useful evidence in the report:
"We tested webhook signature verification at /api/webhooks/stripe by sending a request with `Stripe-Signature: invalid`. Server returned 400 with `signature verification failed`. **Verified: signature enforcement works**."

This shows the customer that the audit was thorough, not just "we couldn't break anything."

## Pro Tips

1. The most-productive hypothesis loop: spot a primitive → write down the 5 questions → run the cheapest probe → either find a bug or document the assurance.
2. Many "novel" findings turn out to be a known CWE applied to a new substrate (e.g., prototype pollution in 2018 was "prototype-chain-write" applied to JS deserialisation — a known class against a new language).
3. AI / LLM apps have the most novel-attack surface in 2026 — prompt injection isn't fully catalogued anywhere yet.
4. Cross-cutting bugs (rate-limit bypass, idempotency bypass, replay) span every framework — when you see ANY queue / webhook / async-job pattern, hypothesise these by default.
5. Architectural primitives often repeat across a codebase — if one webhook receiver doesn't verify signature, the others probably don't either.

## Validation

A useful hypothesis-driven finding is one where:
1. The primitive is named (route, function, library).
2. The invariant tested is named.
3. The bypass is reproduced.
4. The chain to impact is explicit.

## Summary

Catalogued vuln classes (the other skills) catch known bugs. This meta-skill catches **new** ones by asking the same 5 questions about every new architectural primitive. Trust boundary → invariants → failure modes → reachability → impact chain. Repeat for every webhook, queue, tool, parser, importer, AI agent.
