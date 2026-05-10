# strix vibe-coded SAST rules

YAML rules targeting AI-generated code patterns that commonly
introduce security bugs in vibe-coded apps. Loaded by
`strix.sast.semgrep_runner.run_semgrep` via Semgrep's
`--config <dir>` mechanism.

## Rule index (v2 — 39 rules)

### Express / Node.js (10)

| File                                       | CWE      | Pattern                                              |
|--------------------------------------------|----------|------------------------------------------------------|
| `express-mass-assignment.yml`              | CWE-915  | `Model.create(req.body)` without allowlist           |
| `express-permissive-cors.yml`              | CWE-1004 | `cors({origin:'*', credentials:true})`               |
| `express-helmet-not-applied.yml`           | CWE-1004 | `express()` instantiated, `helmet()` never used      |
| `express-session-cookie-insecure.yml`      | CWE-614  | `session({cookie:{secure:false / httpOnly:false}})`  |
| `express-redirect-from-user-input.yml`     | CWE-601  | `res.redirect(req.body.url)`                         |
| `express-raw-body-no-size-limit.yml`       | CWE-400  | `bodyParser.json({limit:'500mb'})`                   |
| `xss-from-user-in-res-send.yml`            | CWE-79   | `res.send(req.body.x)` (HTML by default)             |
| `hardcoded-jwt-secret.yml`                 | CWE-798  | `jwt.sign(data, "literal-secret")`                   |
| `jwt-none-algorithm.yml`                   | CWE-347  | `jwt.verify({algorithms:['none']})`                  |
| `jwt-verify-no-options.yml`                | CWE-347  | `jwt.verify(token, key)` without options arg         |

### Python — Django / Flask (8)

| File                                       | CWE      | Pattern                                              |
|--------------------------------------------|----------|------------------------------------------------------|
| `django-debug-true.yml`                    | CWE-489  | `DEBUG = True` at module scope                       |
| `django-csrf-exempt.yml`                   | CWE-352  | `@csrf_exempt` on state-changing view                |
| `flask-debug-run.yml`                      | CWE-489  | `app.run(debug=True)` (Werkzeug debugger console)    |
| `flask-render-template-string-user.yml`    | CWE-1336 | `render_template_string(request.x)` (SSTI)           |
| `python-pickle-untrusted.yml`              | CWE-502  | `pickle.loads(request.body)`                         |
| `python-subprocess-shell-true.yml`         | CWE-78   | `subprocess.run(shell=True)` with user input         |
| `python-yaml-load-unsafe.yml`              | CWE-502  | `yaml.load()` without SafeLoader                     |
| `python-requests-verify-false.yml`         | CWE-295  | `requests.get(verify=False)` (TLS bypass)            |

### Generic (3)

| File                                       | CWE      | Pattern                                              |
|--------------------------------------------|----------|------------------------------------------------------|
| `sql-string-concat.yml`                    | CWE-89   | SQL via template literal / string concat             |
| `path-traversal-from-params.yml`           | CWE-22   | `fs.readFile(req.params.x)` w/o `path.basename`      |
| `eval-with-user-input.yml`                 | CWE-94   | `eval(req.body.x)` / `new Function(req.body.x)`      |
| `insecure-random-for-crypto.yml`           | CWE-338  | `Math.random()` for tokens / secrets / OTPs          |
| `ssrf-from-user-url.yml`                   | CWE-918  | `fetch(req.body.url)` w/o allowlist                  |

### React / Next.js (5)

| File                                       | CWE      | Pattern                                              |
|--------------------------------------------|----------|------------------------------------------------------|
| `react-dangerously-set-innerhtml.yml`      | CWE-79   | `dangerouslySetInnerHTML` from user input            |
| `react-href-javascript-protocol.yml`       | CWE-79   | `<a href={user_input}>` accepts `javascript:` URLs   |
| `localstorage-token-storage.yml`           | CWE-922  | `localStorage.setItem('token', x)`                   |
| `nextjs-server-action-no-auth.yml`         | CWE-862  | `'use server'` mutating DB without `await auth()`    |
| `nextjs-api-cors-wildcard.yml`             | CWE-1004 | API route `Access-Control-Allow-Origin: *`           |
| `nextjs-getserversideprops-secret-leak.yml`| CWE-200  | `getServerSideProps` returns `process.env`           |
| `window-open-from-user.yml`                | CWE-601  | `window.open(req.body.url)` / `router.push(searchParams)`|

### LLM / AI features (4)

| File                                       | CWE      | Pattern                                              |
|--------------------------------------------|----------|------------------------------------------------------|
| `llm-openai-key-in-source.yml`             | CWE-798  | `new OpenAI({apiKey: "sk-..."})`                     |
| `llm-prompt-from-user-no-validation.yml`   | CWE-1336 | `messages: [{role:'user', content: req.body.x}]`     |
| `llm-tool-call-shell.yml`                  | CWE-78   | LLM tool function passes args to shell               |
| `langchain-llmchain-user-template.yml`     | CWE-1336 | `PromptTemplate(template=request.x)`                 |

### Crypto (5)

| File                                       | CWE      | Pattern                                              |
|--------------------------------------------|----------|------------------------------------------------------|
| `crypto-md5-for-security.yml`              | CWE-327  | MD5 in password / signature pathways                 |
| `crypto-sha1-for-security.yml`             | CWE-327  | SHA-1 in password / signature pathways               |
| `crypto-des-cipher.yml`                    | CWE-327  | DES / 3DES cipher in use                             |
| `crypto-ecb-mode.yml`                      | CWE-327  | AES in ECB mode                                      |
| `crypto-bcrypt-low-rounds.yml`             | CWE-916  | bcrypt with cost factor < 10                         |

## Adding rules

1. Create `<short-name>.yml` in this dir.
2. Use `strix-<short-name>` as the rule `id` (id collision check
   runs via `tests/sast/test_rules.py::test_rule_ids_are_unique`).
3. Set `metadata.vibe_pattern: true` so the rules can be filtered
   from non-AI-generated patterns at scoring time.
4. Map to a CWE that's in `_CWE_TO_CATEGORY` in
   `strix/sast/semgrep_runner.py` so findings get the right
   semantic category for cross-asset routing.
5. **YAML gotcha**: any pattern containing `:` characters
   (object literals, type annotations, dict keys) MUST use
   block-literal style (`pattern: |`). Inline `pattern: foo: bar`
   trips the YAML parser into thinking the colon starts a
   nested mapping.

## Validation

Rules don't compile-check until Semgrep parses them. The unit
tests in `tests/sast/test_rules.py` verify YAML structure and
rule-id uniqueness; run-time errors surface in `SemgrepResult.
status="partial"`.

## Coverage growth

| Phase | Rules | Notes                                          |
|-------|-------|------------------------------------------------|
| v1    | 9     | Anchor rules — top vibe-coded patterns         |
| v2    | 39    | Express + Python + React/Next.js + LLM + crypto |
