# WebGoat fixture

OWASP WebGoat 2023.8 — a Java vulnerability-training app. Added in
iter-15 as a **tougher** web_application benchmark than juiceshop:
where juiceshop is an Angular SPA designed for automation, WebGoat
is server-rendered Tomcat with the majority of bugs sitting BEHIND
a login. This stresses L1's ability to detect pre-auth signals
without exfiltrating deep app state.

## Run

```bash
# Just this fixture:
python -m benchmarks.per_target.bench_l1_only --fixture web/webgoat

# As part of the default 6-fixture run, add to the list in
# bench_l1_only.py:_DEFAULT_FIXTURES.
```

The compose file binds only to 127.0.0.1:8082. WebGoat is
deliberately vulnerable; bridging to 0.0.0.0 would expose
authenticated lessons + (in some builds) the H2 DB console
to anything routable to the host.

## Recall semantics

`must_find=true` entries are the **pre-auth** L1 surface:

- `tomcat-version-disclosure` — Server header version
- `login-no-rate-limit` — POST to /WebGoat/login is uncapped

`must_find=false` entries are advisory (build-profile-dependent):

- `spring-actuator-exposed` (if dev profile is on)
- `h2-console-exposed` (if `webgoat.start.hsqldb=true`)
- `webgoat-default-credentials` (if nuclei has a matching template)

The dozens of post-auth lesson bugs (SQLi, XSS, JWT, CSRF) are
intentionally NOT in the recall denominator — those are L2
territory and only catchable after auth-flow setup.

## What this benchmark probes about strix's L1

1. Does the L1 prepass identify framework-version disclosure on
   a Java webapp? (probe_http_port → Server header regex)
2. Does L1 detect a login-form-no-rate-limit signal without auth
   state? (scan_api_rate_limit on the discovered login URL)
3. Does L1 reach commonly-exposed admin paths (/actuator, /H2Console)?
4. Does fingerprint_tech_stack detect "Spring Boot + Tomcat" and
   route to relevant skills?

## Safety profile

- Loopback-only port binding (`127.0.0.1:8082:8080`)
- Memory + CPU + PID caps
- `cap_drop: ALL` + minimal cap_add
- `no-new-privileges:true`
- Ephemeral (no host bind-mounts, no persistent volumes)

After bench teardown: `docker compose down` wipes the container.
The L1 bench harness invokes that in a `finally:` block.
