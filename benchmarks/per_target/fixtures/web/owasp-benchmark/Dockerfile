# iter-Q1.1 — OWASP Benchmark Project v1.2 (BenchmarkJava) build.
#
# Two-stage:
#   1. maven:3.9-eclipse-temurin-11 — clone + mvn package
#   2. tomcat:9.0-jre11 — serve the built WAR
#
# Pinned to BenchmarkJava commit hash for reproducibility. The
# upstream repo is in maintenance mode; pinning avoids drift.

# iter-Q5.25 — bumped from `maven:3.9-eclipse-temurin-11` to the
# Java 17 builder. Upstream spotless-maven-plugin 3.5.1 mojo classes
# are compiled for Java 17 (class file v61); Java 11's class loader
# (v55 cap) rejects them BEFORE checking skip flags. The Tomcat 9
# stage stays on Java 11 (`9.0-jre11`); we force compile target via
# `-Dmaven.compiler.release=11` so the produced .class files
# still run on the 11-jre at runtime.
FROM maven:3.9-eclipse-temurin-17 AS build

# iter-Q5.25 — pin to a known-good commit hash rather than `master`.
# The README has always called for pinning ("avoids drift"); we
# weren't doing it. f9b87c9638 is upstream master as of 2026-05-27.
# Override via `--build-arg BENCHMARK_REF=<sha>` if upstream lands a
# detection-affecting fix worth picking up.
ARG BENCHMARK_REF=f9b87c9638213ec3d7a1ee8b1465471aed8f3ce0

WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
    && rm -rf /var/lib/apt/lists/* \
    && git init . \
    && git remote add origin https://github.com/OWASP-Benchmark/BenchmarkJava.git \
    && git fetch --depth 1 origin "${BENCHMARK_REF}" \
    && git checkout FETCH_HEAD

# Build the WAR. Skip tests + skip spotless.
#
# iter-Q5.25: upstream BenchmarkJava bumped spotless-maven-plugin to
# 3.5.1, whose mojo classes are compiled for a JDK newer than the
# Java 11 we run maven on. The plugin fails to load with
# `UnsupportedClassVersionError`, killing the whole build. Spotless
# is a code-formatter — it's NOT load-bearing for the WAR artifact —
# so skipping it bypasses the version mismatch with no impact on
# detection.
#
# `-DskipTests` skips JUnit runs; `-Dspotless.apply.skip=true` +
# `-Dspotless.check.skip=true` skip both spotless goals (one or the
# other depending on phase binding). All three needed.
RUN mvn -q \
        -DskipTests \
        -Dspotless.apply.skip=true \
        -Dspotless.check.skip=true \
        -Dmaven.compiler.release=11 \
        package


FROM tomcat:9.0-jre11

# Tomcat 10 changed javax.* → jakarta.* — BenchmarkJava still uses
# javax. Tomcat 9 is the last release supporting javax.servlet.
LABEL org.opencontainers.image.source="https://github.com/OWASP-Benchmark/BenchmarkJava"
LABEL org.opencontainers.image.description="OWASP Benchmark Project v1.2 — strix bench fixture"

# Remove the default Tomcat ROOT app + drop the BenchmarkJava WAR.
RUN rm -rf /usr/local/tomcat/webapps/* /usr/local/tomcat/webapps.dist
COPY --from=build /src/target/benchmark.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=60s --retries=30 \
    CMD curl -fsS http://localhost:8080/ || exit 1
CMD ["catalina.sh", "run"]
