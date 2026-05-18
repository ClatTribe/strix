---
name: django
description: Django security audit — admin, ORM raw / extra, template autoescape, settings.py exposure, REST framework gaps
triggers: [django, drf, django-rest-framework, admin, orm, queryset, settings.py, runserver, debug=true]
---

# Django Security

Django is the canonical Python web framework: large default surface (admin, ORM, templates, middleware, REST framework), strong defaults that fail loudly when bypassed. Bugs cluster in (1) `DEBUG=True` in production, (2) `extra()` / `raw()` / `RawSQL` ORM escapes, (3) template autoescape disabled or `mark_safe()` misuse, (4) Django REST Framework permission / serializer gaps, (5) `SECRET_KEY` exposure.

## Attack Surface

### Settings exposure
- `DEBUG=True` in production → `/__debug__/` traceback pages with full source + env vars
- `SECRET_KEY` leaks via env-vars-in-error-page, repo `settings.py`, or `dumpdata` output
- `ALLOWED_HOSTS=['*']` — Host-header validation off
- `SESSION_COOKIE_SECURE=False` + `CSRF_COOKIE_SECURE=False` — cookies over HTTP

### Django admin
- `/admin/` mounted by default; brute-forceable if no rate-limit
- Default username `admin` very common
- Admin-side SQL injection via `list_filter` with user-controlled filters on Django < 4.2

### ORM escapes
- `Model.objects.extra(where=["..."])` — raw SQL in WHERE → SQLi
- `Model.objects.raw("SELECT ... WHERE x = %s", [user_input])` — parameterised but the SQL string itself often built unsafely
- `Func`, `RawSQL` — escape hatches
- `connection.cursor().execute(...)` — full SQLi if user-controlled

### Templates
- `{% autoescape off %}` block → no escaping → XSS
- `{{ var|safe }}` filter → same
- `mark_safe(user_input)` in views → XSS once rendered

### DRF (Django REST Framework)
- `default_permission_classes = (AllowAny,)` in `settings.py` — every view public unless overridden
- Serializer `Meta.fields = '__all__'` → mass-assignment surface
- `SerializerMethodField` returning sensitive data without permission check
- Browsable API in production exposes object introspection

### Middleware ordering
- `SecurityMiddleware` must precede `CommonMiddleware`
- `CsrfViewMiddleware` after authentication = CSRF token not bound to user
- `AuthenticationMiddleware` must precede any middleware checking `request.user`

## Detection Channels

### `DEBUG=True` probe
```bash
# Trigger an error
curl 'https://<TARGET>/__nonexistent_path__/'

# DEBUG=True returns a yellow stack trace with full source
# DEBUG=False returns Django's plain 404 / 500
```

### `/admin/` discovery
```bash
curl -s 'https://<TARGET>/admin/login/' | grep -oE 'csrfmiddlewaretoken'
# Presence of CSRF token confirms Django admin
```

### Settings leak
```bash
# Common gotchas — accidentally committed settings
curl -s 'https://<TARGET>/settings.py'
curl -s 'https://<TARGET>/.env'
curl -s 'https://<TARGET>/django_secret_key'

# Some apps expose /static/admin/css/base.css → fingerprint Django version
curl -sI 'https://<TARGET>/static/admin/css/base.css'
```

### DRF schema endpoints
```bash
# Browsable API
curl -s 'https://<TARGET>/api/' -H 'Accept: text/html' | grep -i 'django rest framework'

# DRF schema generators
curl -s 'https://<TARGET>/openapi/'
curl -s 'https://<TARGET>/swagger/'
curl -s 'https://<TARGET>/redoc/'
```

## Operational Runbook

### Step 1 — fingerprint version + middleware
```bash
# Static file paths reveal version
curl -sI 'https://<TARGET>/static/admin/css/base.css'

# X-Frame-Options / SECURE_HSTS_SECONDS / etc. reveal SecurityMiddleware config
curl -sI 'https://<TARGET>/' | grep -iE 'x-frame|content-security|strict-transport'
```

### Step 2 — admin brute / discovery
```bash
# Common admin users
for user in admin root django user1; do
  curl -s -c /tmp/cookies.txt 'https://<TARGET>/admin/login/' > /tmp/admin_page.html
  TOKEN=$(grep -oE 'csrfmiddlewaretoken" value="[^"]+' /tmp/admin_page.html | cut -d'"' -f3)

  curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt -X POST 'https://<TARGET>/admin/login/' \
    -d "username=${user}&password=admin&csrfmiddlewaretoken=${TOKEN}&next=/admin/"
done
```

### Step 3 — DRF permission audit
```bash
# Walk every API endpoint, check 401/403 vs 200
for endpoint in $(curl -s 'https://<TARGET>/api/' | jq -r '.|.url? // empty'); do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$endpoint")
  echo "${endpoint}: ${STATUS}"
done

# 200 without auth = AllowAny endpoint; flag
```

### Step 4 — serializer / mass-assignment
```bash
# Probe a known-write endpoint with extra unexpected fields
curl -X POST 'https://<TARGET>/api/users/' \
  -H 'Authorization: Token ...' \
  -H 'Content-Type: application/json' \
  -d '{"username":"strix","email":"x@y.com","is_staff":true,"is_superuser":true}'

# Response includes is_superuser:true → mass-assignment
```

### Step 5 — ORM `extra` / `raw` discovery (when source is available)
```bash
# Grep the codebase
grep -rn '\.extra(' .  # extra() escape hatch
grep -rn '\.raw(' .    # raw() escape hatch
grep -rn 'RawSQL' .    # explicit raw fragments
grep -rn 'cursor()\.execute' .  # bare cursor
```

For each hit, audit whether user input flows into the SQL string.

### Step 6 — template XSS
```bash
# Grep templates for autoescape off / safe filter / mark_safe
grep -rn '{% autoescape off %}' templates/
grep -rn '|safe' templates/
grep -rn 'mark_safe' .
```

### Step 7 — SECRET_KEY exposure → session forging
```bash
# Once SECRET_KEY is leaked, attacker can forge sessionid cookies
# Django uses signed cookies (django.contrib.sessions.backends.signed_cookies) for default backend
# With the key, attacker mints sessions for any user

python3 -c "
from django.core.signing import TimestampSigner
import django
django.setup()
# Construct + sign a session for user_id=1 (admin)
"
```

## Specific Vulnerability Classes

### Django < 4.0 `QuerySet.order_by()` injection
- User-controlled `order_by` parameter pre-4.0 allowed `__` traversal across relations
- Post-4.0: explicit `__` allowlist required

### `Q()` object SQL injection via field lookup chains
- `Q(**{user_input: value})` — when user controls the field name, `__exact`, `__icontains`, `__regex` open up SQLi

### Pickle session serializer
- `SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'` (Django < 3.0 default)
- Combined with SECRET_KEY leak = RCE via gadget chain (see deserialization.md)

### `RawSQL` in annotate
- `qs.annotate(x=RawSQL("..."))` — same SQLi class as `extra()`

### Admin file-upload bypass
- Admin's `FileField` lets uploads; default `validate_image()` doesn't check MIME beyond file extension
- Pre-2024 versions had paths to RCE via SVG with embedded JS / polyglot uploads

## Bypass Techniques

- **CSRF token via GET**: Django provides `csrf_exempt` decorator — find views with that decorator + state-changing logic
- **Host-header validation off**: `ALLOWED_HOSTS=['*']` + `URL routing via request.get_host()` = open redirect / cache poisoning
- **DEBUG=False but `SHOW_TRACEBACKS=True`** in some middleware → still leaks
- **Settings module override**: `DJANGO_SETTINGS_MODULE=myapp.settings.production` env var; if overridable via request, switch to a more permissive module

## Validation

1. `/admin/` reachable + login page renders.
2. Settings exposure: `SECRET_KEY` retrievable from error page or repo.
3. ORM escape: `extra` / `raw` audit returns matches in user-input flow.
4. DRF permission: 200 response without auth on a write endpoint.
5. Document: Django version, DRF version, exposed admin path, AllowAny endpoints, raw-SQL usage sites.

## False Positives

- Admin login page intentionally public (hardened separately); 200 is expected.
- DRF endpoints intentionally public (status pages, public APIs); confirm with operator.
- DEBUG=True in *staging* but not prod — confirm environment.
- `extra()` / `raw()` with hard-coded SQL (no user input) — not exploitable.

## Impact

- Admin compromise → ORM access → full DB → app takeover.
- SECRET_KEY leak → session forging → any-user impersonation.
- DRF mass-assignment → privilege escalation.
- Template XSS → session cookie theft → admin compromise.

## Remediation

1. **`DEBUG=False`** in production; verify via the probe.
2. **`SECRET_KEY` from env-var** (`django-environ` / `python-dotenv`); never in repo.
3. **`ALLOWED_HOSTS` explicit**: list of expected hostnames.
4. **DRF default permission `IsAuthenticated`** (override with `AllowAny` only where intended).
5. **Serializer `Meta.fields`** explicit list, never `'__all__'` for write-capable serializers.
6. **`HttpOnly` + `Secure` + `SameSite=Lax` on session cookies**; `CSRF_COOKIE_SECURE=True`.
7. **`django-axes` or rate-limit middleware** on `/admin/login/`.

## Pro Tips

1. The most common Django finding in real engagements: `DEBUG=True` in production. Always probe first.
2. Django version fingerprint via `/static/admin/css/base.css` etag — Strix's `fingerprint_tech_stack` auto-loads this skill on detection.
3. Common admin paths beyond `/admin/`: `/dashboard/`, `/manage/`, `/control/`, `/console/`.
4. DRF browsable API is gold for understanding the surface — pretty-prints every endpoint + accepted methods.
5. Django's `settings.py` is frequently committed to repos with hardcoded secrets — even when `.env` exists, the secret is in the env-loading default.

## Summary

Django bugs cluster at settings exposure, ORM escapes, admin discovery, DRF permission gaps, template XSS. Default-loud failures help defenders; the attack surface is the same on every Django app. Always check DEBUG state first.
