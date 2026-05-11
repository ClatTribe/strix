# Synthetic deliberately-bad Dockerfile for the strix IaC benchmark.
# Every rule in strix/iac/rules/docker_rules.py for the Dockerfile
# section is intentionally violated below.

# Bad #1 — latest tag (dockerfile_latest_tag)
FROM node:latest

# Bad #2 — ADD from URL (dockerfile_add_from_url)
ADD https://example.com/setup.sh /tmp/setup.sh

# Bad #3 — hardcoded secret in ENV (dockerfile_env_hardcoded_secret)
ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE_FAKEKEY_FOR_BENCHMARK

WORKDIR /app
COPY . /app
RUN npm install

# Bad #4 — runs as root explicitly (dockerfile_user_root)
USER root

# Bad #5 — implicitly, no _final_ USER directive switching off root
# (dockerfile_no_user_directive) — note the `USER root` above does
# NOT count as a non-root user, so this rule still fires.

EXPOSE 3000
CMD ["node", "server.js"]
