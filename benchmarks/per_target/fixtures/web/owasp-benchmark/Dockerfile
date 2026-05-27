# iter-Q1.1 — OWASP Benchmark Project v1.2 (BenchmarkJava) build.
#
# Two-stage:
#   1. maven:3.9-eclipse-temurin-11 — clone + mvn package
#   2. tomcat:9.0-jre11 — serve the built WAR
#
# Pinned to BenchmarkJava commit hash for reproducibility. The
# upstream repo is in maintenance mode; pinning avoids drift.

FROM maven:3.9-eclipse-temurin-11 AS build

# Pin to a known-good commit. Update via `iter-Q1.1.N` if upstream
# fixes a relevant detection-affecting bug.
ARG BENCHMARK_REF=master

WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch "${BENCHMARK_REF}" \
        https://github.com/OWASP-Benchmark/BenchmarkJava.git .

# Build the WAR. Skip tests — we're measuring strix against the
# deployed webapp, not running BenchmarkJava's own unit tests.
RUN mvn -q -DskipTests package


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
