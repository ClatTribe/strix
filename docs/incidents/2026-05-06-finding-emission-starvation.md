# 8 specialists spawn correctly, attempt the right tests with the right tools, but burn the budget before any of them emits `finding.created`

**Reporter:** webappsec wrapper integration team
**Engine commit:** `3b48809` (PR #144 latest)
**Date observed:** 2026-05-06
**Severity:** High — engine orchestration is correct but the *output* is empty
**Companion to:** [`docs/incidents/2026-05-05-tool-server-unreachable.md`](2026-05-05-tool-server-unreachable.md) (different failure mode)

> Issues are disabled on this repo, so this report lives in `docs/incidents/`. Treat the file as a tracker entry — discuss in PR review, then close on merge with a fix-PR pointer or extend with a post-mortem.

---

## Summary

Standard-mode scan against IBM/HCL AppScan's public testbed (`http://demo.testfire.net`, the well-known intentionally-vulnerable "Altoro Mutual" demo banking app) ran for **45 minutes**, consumed **5.8 million input tokens at $2.50 budget cap**, spawned **8 specialist sub-agents with correct scopes and the right tooling** — and emitted **0 `finding.created` events**. Every classic vulnerability the testbed is famous for went un-reported as a structured finding.

This is materially different from [#tool-server-unreachable](2026-05-05-tool-server-unreachable.md): there the sandbox was broken and no probing occurred. *Here* the probing was extensive and on-target — the agents just never converted their findings into structured emission before the budget fired.

## Repro

- Engine: `ClatTribe/strix` HEAD `3b48809`
- Sandbox image: `strix-sandbox:fork-latest` (rebuilt from fork's `containers/Dockerfile`)
- LLM: `gemini/gemini-2.5-pro`
- Target: `http://demo.testfire.net` — IBM/HCL "Altoro Mutual" demo banking app, intentionally vulnerable, ~20 publicly documented vulnerabilities (SQLi at `/bank/login.aspx` and `/search.aspx`, reflected/stored XSS, LFI at `/default.aspx?content=`, default creds `admin:admin`, missing security headers, plaintext-HTTP banking, exposed `/comment.txt`, etc.)
- Mode: `standard`, `--max-cost 2.50`, default `--preflight` (passed)

```bash
strix -n -m standard -t http://demo.testfire.net \
  --max-cost 2.50 \
  --feedback-from /tmp/strix-runs/<id>/feedback.jsonl \
  --compliance-pack /tmp/strix-runs/<id>/compliance_pack \
  --instruction 'External pentest evaluation against the IBM/HCL AppScan public testbed (intentionally vulnerable, authorized). Exercise standard methodology: SQLi at /bank/login.aspx + /search.aspx, reflected/stored XSS, LFI at /default.aspx?content=, parameter tampering, HTTP TRACE, default creds admin:admin / jsmith:Demo1234, CSRF on money-transfer flows, missing security headers, info disclosure (robots.txt, /comment.txt, server banner). Run thorough probing — testbed not production.'
```

## Numbers

| metric | value |
|---|---|
| wall time | 45 min (2677 s) |
| cost | **$2.50 cap exceeded → $2.5037 actual → exit_code=3** |
| LLM input tokens | **5 800 000** |
| LLM output tokens | 18 800 |
| LLM requests | 103 |
| `tool.execution.started` events | **107** total |
| `agent.created` events | **8** specialist sub-agents |
| `agent.budget_exceeded` events | yes |
| `coverage.json.coverage_percent` | **0.0** |
| `coverage.json.status` | **incomplete** |
| `coverage.json.gaps` | `[csrf, idor, open_redirect, sqli, ssrf, xss]` (full required) |
| `finding.created` events | **0** |
| `hypothesis.opened/confirmed/dismissed` events | **0** (none emitted) |
| `run_summary.json.checks.total` | 0 |
| `run.terminated.reason` | `budget_exceeded` |

### Tool-call distribution (across all 8 specialists)

```
browser_action          38
think                   23
terminal_execute        20
create_agent             8
subagent_start_info      7
list_requests            3
str_replace_editor       2
send_request             2
view_request             1
fingerprint_tech_stack   1
llm_error_details        1
python_action            1
scan_start_info          1
agent_finish             1
```

Lots of real work happened. Browser_action (38×) means the agents actually loaded pages, clicked buttons, navigated forms. terminal_execute (20×) means they ran real CLI tools.

### What the 8 specialists were tasked with (from `agent.created.task`)

| Agent | Scope |
|---|---|
| 1 | Recon + tech-stack fingerprint + info disclosure (`robots.txt`, `comment.txt`, default creds) |
| 2 | SQL injection at `/bank/login.aspx` and `/search.aspx` |
| 3 | XSS specialist — reflected / stored / DOM, context-aware payloads, CSP-bypass eval |
| 4 | XSS — second specialist with stored-XSS scope |
| 5 | File inclusion — `content=` parameter on `/default.aspx` |
| 6 | Parameter tampering / IDOR on accounts and transactions |
| 7 | CSRF on money-transfer flows |
| 8 | Misconfig — TRACE method, security headers, server-version banners |

This is *exactly* the right specialist split for the testbed. A senior pentester running Burp + ZAP + nikto manually would arrive at the same agenda.

### What the agents actually ran (excerpts from `terminal_execute.command`)

```
curl -s -L http://demo.testfire.net/robots.txt
curl -s -L http://demo.testfire.net/comment.txt
katana -u http://demo.testfire.net -d 5 -jc -o katana_output.txt
sqlmap -u "http://demo.testfire.net/bank/login.aspx" --forms --batch --level 2 --risk 1
sqlmap -u "http://demo.testfire.net/search.aspx?txtSearch=test" --batch --level 2 --risk 1
sqlmap -r search_request.txt --batch --level 2 --risk 1
…
```

Real, on-target tooling. The recon agent grabbed `robots.txt` and `comment.txt` first (correct — those are info-disclosure baselines). The SQLi specialist picked the right URL and parameter. Same for the others.

## Why the agents didn't emit findings

From the agents' own `think` excerpts, two patterns repeatedly appeared:

### Pattern 1 — sqlmap hitting 404 against URLs the browser proxy confirmed working

```
"This is extremely strange. Even with the raw request file, sqlmap is getting a 404. This
suggests there's something more fundamental that I'm missing. Perhaps there's a session
cookie that's required, or some other parameter that's set on a..."

"sqlmap is still getting a 404, even though the browser and the proxy history clearly show a
request was made to that URL. It's possible the application is behaving differently based
on the User-Agent or other headers..."

"I've created the search_request.txt file with the raw HTTP request, but I used a generic
browser User-Agent to mimic a real browser. Now I will use this file with sqlmap's -r option..."
```

The SQLi specialist burned **4 retries** of `sqlmap` against `/bank/login.aspx` and `/search.aspx`, each with 60-90 seconds of LLM context-loading, before pivoting. The site genuinely behaves differently under non-browser User-Agents (a known Altoro quirk), and the agent correctly diagnosed it — but each retry cost ~$0.30 of LLM time on context-reload.

### Pattern 2 — agents reasoning about findings without converting to structured emission

```
"I have been consistently receiving... I'll proceed with the URLs I have gathered so far
and analyze them. I will now check the security headers of the main page."
```

The agents were *thinking* about evidence but not calling whatever tool the engine uses to convert that thinking into a `finding.created` event. By the time the budget cap fired, the misconfig agent had observed (in browser headers) that `X-Frame-Options` was missing — but it was apparently still gathering more evidence rather than emitting.

### What the budget actually went toward

5.8M input tokens / 8 agents = ~725K input tokens per agent average. At gemini-2.5-pro pricing (~$0.31 per 1M input tokens), that's ~$0.225 per agent. Most of that was each specialist re-reading the entire test plan + previous tool outputs on every turn. Cache hits were not visible in the run.terminated payload.

## Suggestions

### 1. **Eager finding emission** — emit on first credible evidence, refine later

When the misconfig specialist sees `X-Frame-Options: <missing>` on the first `curl -I`, it should emit a `finding.created` with `verification_status: pattern_match` and `confidence: 0.7` immediately. Subsequent agent turns can refine the finding (add reasoning_trace, counter_proof, kill_chain) — but the *primary emission* shouldn't wait for the agent to finalize.

Today, agents seem to want to write the entire finding payload (description + impact + remediation_steps + poc_md + technical_analysis) in a single `finish_scan` or `emit_finding` call, which means budget exhaustion = zero emission.

### 2. **Per-agent budget cap with finding-or-die**

`--max-cost <USD>` is currently a *run-level* cap. Consider adding a *per-agent* cap such that each specialist must either:
- emit at least one finding within its allocation, OR
- explicitly emit a `finding.dismissed` with an evidence-backed reason

…before the cap fires. Today an agent can spend its entire share on `think` tokens and emit nothing.

### 3. **sqlmap session/UA defaults for live-web targets**

The SQLi specialist's instruction-template should mention "live HTTP targets often respond differently to default sqlmap User-Agent / cookie behaviour; consider passing `-A` and `--cookie` from the browser session" — would have saved 4 retries here.

### 4. **Hypothesis emission missing**

`hypothesis.opened/confirmed/dismissed` events are 0 in this run despite 8 specialists working for 45 minutes. The hypothesis-lifecycle (engine PR #138) is the natural artifact for "I'm investigating X but haven't confirmed yet" — its absence here is a separate bug. Wrappers' live "watching the engine work" view (e.g. webappsec's `HypothesisPane`) is empty for the entire run.

### 5. **Cache hits in run.terminated payload**

The `run.terminated.consumed.cached_tokens` field is `[REDACTED]` in the wrapper's view. If most of the 5.8M tokens *were* cached, the cost surprise is reduced — but there's no way to verify that from the payload. Either un-redact for the in-app view, or add a `cache_hit_ratio` summary field.

## Cross-reference

This complements [tool-server-unreachable.md](2026-05-05-tool-server-unreachable.md). That one documented a *plumbing* failure (sandbox unreachable, agent honest about it). This one documents a different failure mode: *plumbing works, orchestration is correct, but emission starves out under realistic budgets.*

The wrapper-side fix in [`webappsec` PR #64](https://github.com/ClatTribe/webappsec/pull/64) (coverage banner + budget-exceeded amber UX) ensured a buyer reading the report wouldn't be misled. But the underlying engine behaviour is the gap — and unlike #146, the gap here isn't environmental, it's about how the agent's "thinking → evidence → emission" loop is shaped.

## Available artifacts on request

- `events.jsonl` for the full run — the 38 browser_action + 20 terminal_execute payloads with their stdout/stderr
- `run.signature.json` for chain integrity
- The 8 `agent.created.payload.task` strings showing the specialist split
- The exact 4 `sqlmap` invocations + their stderr showing the 404-loop
