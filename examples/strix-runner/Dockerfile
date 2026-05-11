# Strix runner image — minimal single-tenant.
#
# Builds an image that can:
#   * Run `strix` as a CLI inside a Celery worker
#   * Run `python -m strix.threat_intel.refresh` as a sidecar
#   * Serve the example FastAPI control plane
#
# Build context = repo root (so we can `pip install` strix from
# the local source). The docker-compose.yml at the same path
# wires that up.
#
# To rebuild without cache:
#   docker compose build --no-cache
#
# Image size: ~600 MB (Python slim + semgrep + git). Acceptable
# for an example; production builds should multi-stage to shave
# the build toolchain.

FROM python:3.12-slim

# --- System deps --------------------------------------------------
#
# git           — strix uses git for clones + diff-aware SAST
# tini          — proper PID 1 (signal handling for Celery + uvicorn)
# build-essential gcc — required by some transitive Python deps
#                      (e.g. cffi → ssl; lxml). Removed after pip install.
#
# Docker CLI is intentionally NOT installed. This example uses
# `STRIX_SANDBOX_MODE=false` (Option B in docs/wrapper-integration.md
# §6) so strix runs the agent loop directly inside this container
# rather than spawning a Docker-in-Docker sandbox. If you need
# inner-sandbox mode, install `docker.io` and mount the host socket
# (see compose file comments).
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        tini \
        ca-certificates \
        build-essential \
        gcc \
    && rm -rf /var/lib/apt/lists/*

# --- Python deps --------------------------------------------------
#
# strix itself is installed from the build context below
# (COPY . /strix-src + pip install). Pin runtime deps for the
# example control plane here.

RUN pip install --no-cache-dir --upgrade pip

# Example control-plane deps (pin in pyproject when this graduates
# from /examples).
RUN pip install --no-cache-dir \
        celery[redis]==5.3.6 \
        fastapi==0.115.5 \
        uvicorn[standard]==0.32.1 \
        pydantic==2.9.2 \
        redis==5.2.0 \
        boto3==1.35.71

# Semgrep — optional but strongly recommended; SAST is a no-op
# without it. Adds ~80 MB. Drop this line if you only need
# SCA / IaC / DAST.
RUN pip install --no-cache-dir semgrep==1.162.0

# --- Strix install ------------------------------------------------
#
# Copy the strix source from the build context and install it in
# editable mode so local development re-installs are cheap. In a
# real wrapper deployment, you'd pin a strix version
# (`pip install strix-agent==<version>`) instead.

COPY pyproject.toml /strix-src/pyproject.toml
COPY README.md /strix-src/README.md
COPY strix /strix-src/strix
RUN pip install --no-cache-dir /strix-src

# Trim the build toolchain to keep the image lean.
RUN apt-get purge -y --auto-remove build-essential gcc && \
    rm -rf /var/lib/apt/lists/*

# --- Runtime layout -----------------------------------------------

# Non-root user. Strix doesn't require root, and running as
# non-root is the right default for multi-tenant.
RUN useradd --create-home --shell /bin/bash strix
USER strix
WORKDIR /home/strix

# Pre-create the dirs the strix-runner example writes to.
RUN mkdir -p /home/strix/runs /home/strix/cache

# Copy the example control plane code.
COPY --chown=strix:strix examples/strix-runner/worker.py /home/strix/worker.py
COPY --chown=strix:strix examples/strix-runner/api.py /home/strix/api.py

# Sensible defaults; override via docker-compose env or K8s envFrom.
ENV STRIX_THREAT_INTEL_CACHE=/home/strix/cache/threat_intel.db \
    STRIX_SANDBOX_MODE=false \
    PYTHONUNBUFFERED=1

# Tini ensures Celery's child processes get clean signals on
# SIGTERM (otherwise scans-in-flight are zombie'd).
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command is the Celery worker. Override in compose for
# the API / refresher services.
CMD ["celery", "-A", "worker", "worker", "--loglevel=info", "--concurrency=2"]
