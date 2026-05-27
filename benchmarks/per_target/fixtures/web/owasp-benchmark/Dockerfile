# iter-Q1.1 (rewritten in iter-Q5.26) — OWASP Benchmark Project v1.2
# (BenchmarkJava) container.
#
# WHY THIS IS NOT A STANDARD TOMCAT DEPLOY
# ----------------------------------------
# The previous iter-Q1.1 layout was multi-stage: `mvn package` produced
# `benchmark.war`, copied into stock `tomcat:9.0-jre11`. That fails at
# request time with:
#   javax.naming.NameNotFoundException:
#     Name [jdbc/ApplicationContext_BenchmarkDB] is not bound in this Context.
#
# Every BenchmarkJava servlet routes through DataBaseFilter →
# DatabaseHelper.getSqlConnection(), which JNDI-looks-up the
# `java:comp/env/jdbc/BenchmarkDB` ResourceLink. The webapp's
# `META-INF/context.xml` declares the ResourceLink, but the GLOBAL
# resource it points at (`jdbc/ApplicationContext_BenchmarkDB`) lives
# in the upstream `src/config/<runenv>/server.xml` — which the
# cargo-maven3-plugin injects into the managed Tomcat's `conf/`. A
# standalone Tomcat has no such global resource, hence the cascade of
# 500s and `is unhealthy` HEALTHCHECK.
#
# Upstream's `runBenchmark.sh` invokes:
#   mvn initialize
#   mvn clean package cargo:run -Pdeploy
# We follow that runtime: keep the source tree, let cargo manage the
# Tomcat, expose port 8080.

FROM maven:3.9-eclipse-temurin-17

# iter-Q5.25 — pin the upstream sha for reproducibility (was `master`).
ARG BENCHMARK_REF=f9b87c9638213ec3d7a1ee8b1465471aed8f3ce0

WORKDIR /src

# Clone the pinned sha. Needs `git init + fetch + checkout` because
# `clone --branch` doesn't accept sha refs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
    && rm -rf /var/lib/apt/lists/* \
    && git init . \
    && git remote add origin https://github.com/OWASP-Benchmark/BenchmarkJava.git \
    && git fetch --depth 1 origin "${BENCHMARK_REF}" \
    && git checkout FETCH_HEAD

# iter-Q5.26 — patch src/config/remote/server.xml to serve HTTP on
# 8080 (bound to all interfaces) instead of HTTPS-only on 8443. The
# upstream remote profile keeps the HTTPS 8443 connector active with
# the HTTP 8080 connector commented out. The bench harness's default
# target URL is http://host.docker.internal:8080 — switching the
# connector here is the minimum-change fix; avoids dragging in a
# self-signed cert + a sandbox-side TLS-skip-verify dance for every
# strix probe.
RUN sed -i \
    -e '/<Connector .*port="8443"/d' \
    -e 's|<!-- *<Connector executor="tomcatThreadPool"|<Connector executor="tomcatThreadPool"|' \
    -e 's|connectionTimeout="20000"|connectionTimeout="20000"|' \
    -e 's|redirectPort="8443" /> *-->|redirectPort="8443" />|' \
    src/config/remote/server.xml \
 && echo "--- patched remote/server.xml ---" \
 && grep -E "<Connector" src/config/remote/server.xml

# Build-time pre-warm: download every plugin + dep into the local
# maven repo so container startup is fast. `cargo:run` will reuse the
# cached repo rather than re-resolving on every container boot.
#
# Spotless skip flags from iter-Q5.25 carry forward — the plugin's
# Java 17 mojo classes load fine on the temurin-17 base, then the skip
# bypasses execution. `-Dmaven.compiler.release=11` produces Java 11-
# compatible bytecode (the cargo plugin downloads its own Tomcat that
# happens to run on the build-time JDK, but matching the canonical
# upstream runtime keeps the bench reproducible).
RUN mvn -q \
        -DskipTests \
        -Dspotless.apply.skip=true \
        -Dspotless.check.skip=true \
        -Dmaven.compiler.release=11 \
        -Pdeploy \
        package

# Pre-resolve cargo deps so the first request doesn't pay the network
# tax. `cargo:help` is the cheapest goal that forces cargo to be
# downloaded; we don't want to actually `cargo:run` at build time.
RUN mvn -q \
        -Dspotless.apply.skip=true \
        -Dspotless.check.skip=true \
        -Pdeploy \
        org.codehaus.cargo:cargo-maven3-plugin:help \
    || true

LABEL org.opencontainers.image.source="https://github.com/OWASP-Benchmark/BenchmarkJava"
LABEL org.opencontainers.image.description="OWASP Benchmark Project v1.2 — strix bench fixture (cargo:run runtime)"

EXPOSE 8080

# Container CMD = the upstream-recommended run command. cargo will:
#   1. Download the configured Tomcat zip (if not cached) to
#      ./target/cargo/installs/...
#   2. Stage the webapp + the server.xml from src/config/<env>/
#   3. Boot Tomcat in the foreground on port 8080
# `-Dorg.owasp.esapi.logSpecial.discard=true` quiets the ESAPI
# bootstrap warning the bench harness doesn't care about.
HEALTHCHECK --interval=10s --timeout=5s --start-period=180s --retries=60 \
    CMD curl -fsS http://localhost:8080/benchmark/ || exit 1
CMD ["mvn", \
     "-Dspotless.apply.skip=true", \
     "-Dspotless.check.skip=true", \
     "-Dorg.owasp.esapi.logSpecial.discard=true", \
     "-Drunenv=remote", \
     "-Pdeploy", \
     "cargo:run"]
