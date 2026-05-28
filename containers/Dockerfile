# syntax=docker/dockerfile:1.6
#
# Strix sandbox image — multi-stage build (Phase 1 / Section A of the
# image-slimming track; benchmark.md §C).
#
# What changed vs the pre-Phase-1 layout:
#   A1. Multi-stage build — builder toolchains (golang-go,
#       build-essential, gcc, pkg-config, libpcap-dev, libssl-dev,
#       python3-dev, npm) are confined to dedicated stages and never
#       reach the final runtime image.
#   A2. Base swap — `kalilinux/kali-rolling:latest` (~2.5 GB of
#       meta-distribution tools strix never invokes) → plain
#       `debian:bookworm-slim` (~120 MB). All apt packages strix
#       actually needs exist in Debian main + contrib; Go-built tools
#       that aren't packaged (nuclei / subfinder / naabu / ffuf) move
#       into the go-builder stage.
#   A3. Go binaries stripped via `-ldflags="-s -w" -trimpath` — removes
#       the symbol table from each Go binary (~30-50% per binary, ~80
#       MB across the nine ProjectDiscovery tools).
#   A4. Scanner data (nuclei templates, trivy DB, grype DB) is NOT
#       baked at build time. The entrypoint lazy-fetches on first start
#       when no shared host volume is mounted; the wrapper's
#       recommended setup mounts /var/strix-cache and refreshes nightly.
#       Saves ~300 MB of perpetually-stale data from the image.
#   A5. Trivy Java DB is no longer pre-downloaded (saves ~150 MB).
#       Trivy fetches it on first JAR-bearing scan.
#   A6. Layer cleanup — every apt-get install uses
#       --no-install-recommends; pip / pipx / uv installs use
#       --no-cache-dir; per-stage caches are cleaned in the same RUN.
#
# Approximate size by section (uncompressed):
#   - kali base (was)               ~2.5 GB
#   - debian-slim base (now)        ~120 MB
#   - builder toolchains (was)      ~600 MB (now in builder stages only)
#   - chromium + playwright         ~400 MB
#   - caido-cli                     ~150 MB
#   - tools (Go + npm + pipx)       ~300 MB total
#   - venv + strix package          ~250 MB (post-N1 — was 1.34 GB pre-N1)
#   - chromium runtime libs + fonts ~80 MB
#
# Measured runtime image: ~6.4 GB after Section B (8 redundant tools
# dropped: gospider, JS-Snooper, jsniper.sh, wafw00f, ZAP, JRE, wapiti3,
# dirsearch). Down from ~19.5 GB Kali baseline.

# =============================================================================
# Stage: go-builder
# =============================================================================
#
# Compiles every Go-built tool strix relies on. ProjectDiscovery's nuclei /
# subfinder / naabu / ffuf are NOT in Debian's apt repos, so they move from
# `apt-get install` (Kali-only path) into `go install` here. naabu needs
# CGO=1 + libpcap headers to build the SYN scanner; we install libpcap-dev
# only in this stage and ship only the resulting static-stripped binaries.

FROM golang:1.25-bookworm AS go-builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libpcap-dev libssl-dev pkg-config ca-certificates \
        curl jq \
 && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1 \
    GOFLAGS="-trimpath"

# `-s -w` strips the symbol table + DWARF debug info from each binary.
# Cuts each ProjectDiscovery binary by 30-50% with no functional impact.
RUN go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/cvemap/cmd/vulnx@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install -ldflags="-s -w" github.com/ffuf/ffuf/v2@latest \
 # iter-21.7 — cosign for Sigstore signature + SLSA / SBOM /
 # VEX attestation verification. The verification code in
 # `strix/tools/container_image/scan_container_image.py`
 # (Phase 5 block at line 590+) has shipped since iter-5 and is
 # wired into the main scan flow at line 1466 — but the binary
 # was never installed in the sandbox image, so
 # `_cosign_available()` always returned False and the whole
 # ~950-line integration was silently dead. Building from source
 # rather than fetching the GitHub release tarball keeps the
 # go-builder pattern uniform with the other PD tools.
 && go install -ldflags="-s -w" github.com/sigstore/cosign/v2/cmd/cosign@latest \
 # iter-22.8 — dalfox (Go XSS scanner). 100+ payloads + filter
 # bypass. Wrapped by `scan_xss_dalfox`.
 && go install -ldflags="-s -w" github.com/hahwul/dalfox/v2@latest
# Note: gospider dropped in Section B (image-slim). katana is a strict
# superset (JS crawling via jsluice, headless mode, deeper recursion) and
# is the canonical crawler used by anchor_prepass._katana_crawl.

# iter-22.4 — Dockle (CIS Docker Benchmark auditor). Originally
# installed via `go install` alongside the other Go tools above.
# Broken since dockle's transitive dep on
# `github.com/containers/storage` pulled in btrfs build-time
# headers (`btrfs/version.h`) that aren't in the go-builder stage's
# base image. iter-27.4 switched to the upstream prebuilt release
# tarball — same pattern as hadolint / gitleaks / feroxbuster.
RUN ARCH="$(uname -m)" \
 && case "$ARCH" in \
        x86_64) DOCKLE_ARCH="64bit" ;; \
        aarch64|arm64) DOCKLE_ARCH="ARM64" ;; \
        *) echo "Unsupported architecture for dockle: $ARCH" >&2; exit 1 ;; \
    esac \
 && TAG="$(curl -fsSL https://api.github.com/repos/goodwithtech/dockle/releases/latest | jq -r .tag_name)" \
 && VER="${TAG#v}" \
 && curl -fsSL "https://github.com/goodwithtech/dockle/releases/download/${TAG}/dockle_${VER}_Linux-${DOCKLE_ARCH}.tar.gz" \
        -o /tmp/dockle.tgz \
 && tar -xzf /tmp/dockle.tgz -C /tmp \
 && install -m 0755 /tmp/dockle /usr/local/bin/dockle \
 && rm -f /tmp/dockle /tmp/dockle.tgz /tmp/LICENSE /tmp/README.md 2>/dev/null || true

# =============================================================================
# Stage: node-builder
# =============================================================================
#
# npm globals strix references via the agent's terminal tool. Installed as
# self-contained binaries; we ship the resulting /usr/lib/node_modules tree
# + symlinks in /usr/local/bin into the runtime stage without keeping `npm`
# itself there.

FROM node:20-bookworm-slim AS node-builder

RUN npm config set update-notifier false \
 && npm install -g --omit=dev --no-fund --no-audit \
        retire@latest \
        eslint@latest \
        js-beautify@latest \
        @ast-grep/cli@latest \
        tree-sitter-cli@latest \
        jshint@latest \
 && rm -rf /root/.npm

# =============================================================================
# Stage: py-builder
# =============================================================================
#
# pipx-managed Python tools. `pipx` puts each into its own venv under
# /opt/pipx, with launcher scripts in /opt/pipx/bin — we ship only those
# two trees into the runtime image, no python3-dev / build-essential leak.
#
# Notes:
#   - wapiti is installed from PyPI (`wapiti3`) rather than apt — same code,
#     no Debian-version-pinning surprise.
#   - dirsearch needs setuptools injected post-install (matches the original
#     Kali-era Dockerfile).

FROM python:3.12-slim-bookworm AS py-builder

ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/opt/pipx/bin \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pipx \
 && rm -rf /var/lib/apt/lists/*

RUN pipx install semgrep \
 && pipx install bandit \
 && pipx install checkov \
 && pipx install arjun \
 # iter-21.6.1 — bbot ASM toolkit. Wrapped by
 # `scan_buckets_via_bbot` for multi-cloud bucket discovery
 # (AWS S3 / GCP GCS / Azure Blob / DigitalOcean Spaces /
 # Firebase / IBM COS). Replaces the in-house bucket probe
 # from PR #400 (reverted via PR #401) — strix already wraps
 # mature OSS scanners (trivy / semgrep / nuclei / checkov /
 # gitleaks), so the bucket-discovery sub-iter follows the
 # same pattern. bbot is a substantial install (~50MB+ of
 # transitive deps including httpx / dnspython / deepdiff /
 # mmh3 / lxml) — pipx-isolated like the other Python CLIs.
 && pipx install bbot \
 # iter-22.4 — `checkdmarc` pure-Python DNS/email-hygiene
 # auditor. Wrapped by `scan_dns_hygiene_checkdmarc`. Audits
 # SPF / DKIM / DMARC / MX / CAA / MTA-STS records.
 && pipx install checkdmarc \
 # iter-22.6 — `dnstwist` typosquat / brand-impersonation
 # domain discovery. Wrapped by `scan_typosquats_dnstwist`.
 # Commercial-feed-equivalent (Cyble / ZeroFOX brand protection
 # tier) but free + zero-auth.
 && pipx install dnstwist \
 && pipx install inql \
 # iter-Q5.22 — schemathesis (Python-based OpenAPI conformance fuzzer).
 # Wrapped by `scan_api_schemathesis`. Fuzzes APIs against their declared
 # spec for status_code / content_type / schema / auth conformance —
 # complements nuclei (signature-driven) with property-based testing of
 # the spec's own contract. The wrapper falls back to the `st` shorter
 # alias if `schemathesis` isn't found.
 && pipx install schemathesis
# Note: dirsearch / wafw00f / wapiti3 dropped in Section B (image-slim):
#   * dirsearch is superseded by feroxbuster (Rust-fast, larger default
#     wordlists; shipped in iter-23.3 / #415).
#   * wafw00f's WAF fingerprint is weakly covered by fingerprint_tech_stack
#     (Wappalyzer-based); knowing WAF=X doesn't help bypass deterministically.
#   * wapiti3's per-vuln scans are subsumed by strix's per-endpoint
#     scan_sqli / scan_xss / scan_xxe / scan_ssrf / scan_path_traversal /
#     scan_cmd_injection family, which the prepass hydrates with body
#     schemas from openapi_spec_ingest (richer signal than wapiti's
#     URL-only scan).
# arjun kept — fills the hidden-parameter brute-force gap that nothing
# else in the stack covers (openapi_spec_ingest only emits documented
# params; katana only emits linked ones).

# =============================================================================
# Stage: clone-builder
# =============================================================================
#
# Sources that are just git clones — no compilation, just COPY-ready in the
# runtime image. Keeping these in their own stage keeps git off the runtime
# (curl is enough for ad-hoc HTTP, and strix's own clone path uses
# `dulwich` from Python). Tree-sitter grammars are cloned here too — the
# runtime keeps `gcc` + `libc6-dev` for tree-sitter's lazy parser.c
# compile path. That's ~80 MB vs ~600 MB for the full build-essential.

FROM debian:bookworm-slim AS clone-builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/clones \
 && git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/clones/jwt_tool \
 && chmod +x /opt/clones/jwt_tool/jwt_tool.py \
 # iter-Q5.22 — smuggler (HTTP request-smuggling fuzzer). Pure-Python,
 # no build step; ship as a clone. Wrapped by
 # `scan_smuggling_smuggler`, which probes `shutil.which("smuggler")`
 # first and falls back to `/opt/smuggler/smuggler.py` — we satisfy
 # BOTH paths: the clone goes to /opt/clones/smuggler (so the runtime
 # COPY lands it at the wrapper's fallback location), and the runtime
 # adds a `/usr/local/bin/smuggler` launcher that `python3`-invokes
 # the cloned script.
 && git clone --depth 1 https://github.com/defparam/smuggler.git /opt/clones/smuggler \
 && chmod +x /opt/clones/smuggler/smuggler.py \
 && find /opt/clones -name '.git' -type d -exec rm -rf {} + 2>/dev/null || true
# Note: JS-Snooper + jsniper.sh dropped in Section B (image-slim). JS
# secret/endpoint extraction is now handled by trufflehog (more accurate
# secret detection, runs in the secrets_scan tool) + katana with
# `-jc -jsl` (JS-AST-aware endpoint extraction via jsluice) +
# source_maps tool. Both upstream paths are LLM-shellable in the existing
# system_prompt and bench fixtures don't use them.

ENV TS_PARSER_DIR=/opt/tree-sitter/parsers
RUN mkdir -p "$TS_PARSER_DIR" \
 && for repo in tree-sitter-java tree-sitter-javascript tree-sitter-python \
                tree-sitter-go tree-sitter-bash tree-sitter-json \
                tree-sitter-typescript; do \
        git clone --depth 1 "https://github.com/tree-sitter/${repo}.git" \
                            "$TS_PARSER_DIR/${repo}"; \
    done \
 && git clone --depth 1 https://github.com/tree-sitter-grammars/tree-sitter-yaml.git \
              "$TS_PARSER_DIR/tree-sitter-yaml" \
 && if [ -d "$TS_PARSER_DIR/tree-sitter-typescript/typescript" ]; then \
        ln -sfn "$TS_PARSER_DIR/tree-sitter-typescript/typescript" \
                "$TS_PARSER_DIR/tree-sitter-typescript-typescript"; \
    fi \
 && if [ -d "$TS_PARSER_DIR/tree-sitter-typescript/tsx" ]; then \
        ln -sfn "$TS_PARSER_DIR/tree-sitter-typescript/tsx" \
                "$TS_PARSER_DIR/tree-sitter-typescript-tsx"; \
    fi \
 && find "$TS_PARSER_DIR" -name '.git' -type d -exec rm -rf {} + 2>/dev/null || true

# =============================================================================
# Stage: venv-builder
# =============================================================================
#
# Builds the strix Python venv with all transitive deps that need source
# compilation. Several pinned deps (libcst via openhands-aci, uvloop via
# litellm[proxy], cryptography, etc.) ship without manylinux_aarch64
# wheels for cp312 and fall back to source build, which pulls in Rust +
# autotools + ssl/ffi headers. We confine that toolchain to this stage
# and COPY only the resulting `/app/.venv` into runtime.
#
# Two important env knobs:
#   - UV_LINK_MODE=copy makes the venv self-contained (no symlinks into
#     /root/.cache that would break across stages).
#   - PLAYWRIGHT_BROWSERS_PATH puts the chromium download under a known
#     /opt path that we then relocate into the runtime user's cache dir.

FROM python:3.12-slim-bookworm AS venv-builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
        build-essential gcc g++ make \
        autoconf automake libtool pkg-config \
        rustc cargo \
        libssl-dev libffi-dev libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

WORKDIR /app

ENV UV_LINK_MODE=copy \
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers \
    PIP_NO_CACHE_DIR=1

COPY pyproject.toml uv.lock ./
RUN echo "# stub" > README.md \
 && mkdir -p strix \
 && touch strix/__init__.py

# Resolves uv.lock against the system python:3.12 (no auto-download of a
# managed Python — keeps the venv linked to /usr/local/bin/python3 which
# the runtime stage (also python:3.12-slim-bookworm) will provide.
RUN uv sync --frozen --no-dev --extra sandbox

# Pull jwt_tool's small Python deps into the same venv so the runtime
# doesn't need uv at all. jwt_tool itself is a shell-invokable script;
# only its dependencies (pyjwt, termcolor, requests, etc.) are needed
# from the venv side.
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /tmp/jwt_tool \
 && uv pip install --no-cache-dir -r /tmp/jwt_tool/requirements.txt \
 && rm -rf /tmp/jwt_tool

# Playwright chromium (~300 MB). Installed under /opt/playwright-browsers
# so the runtime stage can drop it into /home/pentester/.cache/ms-playwright.
RUN /app/.venv/bin/python -m playwright install chromium

# =============================================================================
# Stage: ca-builder
# =============================================================================
#
# Generates the local Testing Root CA used by the Caido proxy to intercept
# TLS traffic from inside the sandbox. Splitting this from runtime keeps the
# openssl binary out of the final image (the CA is built once, then trusted;
# nothing in normal operation regenerates it).

FROM debian:bookworm-slim AS ca-builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app/certs
RUN openssl ecparam -name prime256v1 -genkey -noout -out ca.key \
 && openssl req -x509 -new -key ca.key \
        -out ca.crt \
        -days 3650 \
        -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
 && openssl pkcs12 -export \
        -out ca.p12 \
        -inkey ca.key \
        -in ca.crt \
        -passout pass:"" \
        -name "Testing Root CA" \
 && chmod 644 ca.crt \
 && chmod 600 ca.key ca.p12

# =============================================================================
# Stage: runtime
# =============================================================================
#
# Base is python:3.12-slim-bookworm rather than plain debian:bookworm-slim
# because the venv built in venv-builder targets cpython 3.12, and Debian
# bookworm's apt-installed python is 3.11. python:3.12-slim-bookworm is
# debian:bookworm-slim + the cpython 3.12 install — same Debian
# everywhere, just with the matching Python.

FROM python:3.12-slim-bookworm AS runtime

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

# Overwrite the deb822 apt sources with a single predictable layout.
# bookworm-slim ships `/etc/apt/sources.list.d/debian.sources`; the
# classic `/etc/apt/sources.list` (if any) is cleared so apt only sees
# the file we control. `contrib` + `non-free` repos retained — none of
# our runtime packages currently need them (zaproxy was pulled in
# Section B), but keeping them enabled is zero-cost and avoids breakage
# if a future iter pulls a contrib package.
RUN rm -f /etc/apt/sources.list \
 && cat > /etc/apt/sources.list.d/debian.sources <<'EOF'
Types: deb
URIs: http://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://deb.debian.org/debian-security
Suites: bookworm-security
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF

# Single apt block; --no-install-recommends throughout; cache wiped in the
# same RUN to keep the layer tight. Package groups (in order):
#   - core utilities + archive + edit + transport + runtime .so libs
#   - python runtime (no -dev / build-essential — those live in py-builder)
#   - nodejs (no npm — globals come from node-builder)
#   - gcc + libc6-dev for tree-sitter's lazy parser.c compile path
#     (~80 MB, vs ~600 MB if we kept full build-essential)
#   - net / dns / shell utilities used by both the agent and tools
#   - debian-main security tools (nmap, sqlmap, hydra). ZAP+JRE
#     dropped in Section B (image-slim): nuclei + per-endpoint
#     scan_sqli / scan_xss / scan_xxe / scan_ssrf /
#     scan_path_traversal / scan_cmd_injection (all hydrated by
#     openapi_spec_ingest) already cover ZAP's automated-scan
#     ground with better signal:noise. Bench fixtures don't measure
#     any ZAP catches. iter-Q5.22 added hydra here so
#     `probe_default_creds_hydra` (iter-37.4 wrapper) finds its
#     engine on PATH.
#   - libcap2-bin for setcap; libnss3-tools for certutil
#   - chromium runtime .so deps (for playwright-installed chrome)
#   - fonts (chrome rendering + screenshot tooling)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git sudo \
        unzip tar vim nano less \
        apt-transport-https gnupg \
        libpcap0.8 libssl3 libffi8 \
        nodejs \
        gcc libc6-dev \
        net-tools dnsutils whois iproute2 iputils-ping netcat-traditional \
        jq parallel ripgrep procps htop tmux gdb \
        nmap ncat ndiff sqlmap \
        hydra \
        libcap2-bin libnss3-tools \
        libnss3 libnspr4 libdbus-1-3 \
        libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libatspi2.0-0 \
        libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
        libgbm1 libxkbcommon0 libpango-1.0-0 libcairo2 libasound2 \
        fonts-unifont fonts-noto-color-emoji fonts-freefont-ttf \
        fonts-dejavu-core ttf-bitstream-vera \
 && apt-get autoremove -y \
 && apt-get autoclean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# nmap needs raw-socket + admin caps for SYN scans / OS detection.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# uv for venv management. Installed system-wide so both root (sandbox setup)
# and pentester (runtime tool-server) can invoke it.
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# Create the unprivileged runtime user.
#
# iter-Q5.29 — extend sudo's `secure_path` so the tool_server, which
# launches via `sudo -E -u pentester /app/.venv/bin/python -m
# strix.runtime.tool_server` in the entrypoint, inherits PATH entries
# for pipx-installed OSS tools (semgrep, bandit, schemathesis, inql,
# bbot, dnstwist, checkdmarc) at /opt/pipx/bin. Default Debian
# sudoers ships `Defaults secure_path="/usr/local/sbin:/usr/local/bin:
# /usr/sbin:/usr/bin:/sbin:/bin"` which is fixed regardless of the
# caller's PATH — so even `sudo -E` couldn't recover the parent
# PATH. Symptom prior to fix: every L1-SAST anchor (scan_sast +
# friends) returned `status=partial / "semgrep CLI not installed"`
# even though semgrep was in the image. Verified by inspecting
# `sudo -u pentester sh -c 'echo $PATH'` returning only the default
# system paths. The OWASP BenchmarkJava L1-SAST bench produced
# 0% Youden as a direct consequence (iter-Q5.27 → Q5.28 →
# this PR).
#
# The replacement secure_path mirrors the Dockerfile's
# user-PATH ENV directive below — `/opt/pipx/bin` + `/app/.venv/bin`
# + go/node/npm-global trees + the standard system paths. This is
# the canonical PATH every sudo-launched strix process should see.
RUN useradd -m -s /bin/bash pentester \
 && usermod -aG sudo pentester \
 && echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
 && echo 'Defaults secure_path="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:/opt/pipx/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' > /etc/sudoers.d/strix-secure-path \
 && chmod 0440 /etc/sudoers.d/strix-secure-path \
 && touch /home/pentester/.hushlogin \
 && mkdir -p /home/pentester/configs \
             /home/pentester/wordlists \
             /home/pentester/output \
             /home/pentester/scripts \
             /home/pentester/tools \
             /app/runtime \
             /app/tools \
             /app/certs \
 && chown -R pentester:pentester /app/certs /home/pentester

# ---- COPY artifacts from builders ----

# Go binaries → /usr/local/bin (system path so all users see them).
COPY --from=go-builder /go/bin/* /usr/local/bin/

# npm globals — node-builder (official node:20 image) lays them out at
# /usr/local/lib/node_modules. We copy that tree across to /usr/local/lib
# so the runtime's debian-packaged `nodejs` (which looks at /usr/lib and
# /usr/local/lib) can resolve them; then re-create launcher symlinks
# under /usr/local/bin. NOT copying /usr/local/bin from the node-builder
# image wholesale because that would clobber `node` / `npm` from the
# runtime apt package; we pick exactly the launchers each package installs.
COPY --from=node-builder /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN set -eux; \
    ln -sf /usr/local/lib/node_modules/retire/lib/retire.js              /usr/local/bin/retire        || true; \
    ln -sf /usr/local/lib/node_modules/eslint/bin/eslint.js              /usr/local/bin/eslint        || true; \
    ln -sf /usr/local/lib/node_modules/js-beautify/js/bin/js-beautify.js  /usr/local/bin/js-beautify   || true; \
    ln -sf /usr/local/lib/node_modules/js-beautify/js/bin/css-beautify.js /usr/local/bin/css-beautify  || true; \
    ln -sf /usr/local/lib/node_modules/js-beautify/js/bin/html-beautify.js /usr/local/bin/html-beautify || true; \
    ln -sf /usr/local/lib/node_modules/jshint/bin/jshint                 /usr/local/bin/jshint        || true; \
    ln -sf /usr/local/lib/node_modules/tree-sitter-cli/cli.js            /usr/local/bin/tree-sitter   || true; \
    if [ -d /usr/local/lib/node_modules/@ast-grep/cli ]; then \
        ASG_BIN="$(find /usr/local/lib/node_modules/@ast-grep/cli -maxdepth 3 -type f -name 'ast-grep' | head -1)"; \
        if [ -n "${ASG_BIN}" ]; then \
            ln -sf "${ASG_BIN}" /usr/local/bin/ast-grep; \
            ln -sf "${ASG_BIN}" /usr/local/bin/sg; \
        fi; \
    fi

# pipx tools — bring across /opt/pipx (venvs) and the bin shims.
COPY --from=py-builder /opt/pipx /opt/pipx
ENV PATH="/opt/pipx/bin:${PATH}"

# Static clones (tools shipped as raw scripts). `--chown` set during COPY
# to skip the follow-up `RUN chown` layer-duplication trap.
COPY --from=clone-builder --chown=pentester:pentester /opt/clones /home/pentester/tools
COPY --from=clone-builder --chown=pentester:pentester /opt/tree-sitter /home/pentester/.tree-sitter

# iter-Q5.22 — smuggler launcher. The `scan_smuggling_smuggler` wrapper
# probes `shutil.which("smuggler")` first, so expose the python script
# as a PATH command. The clone-builder COPY already put the script at
# /home/pentester/tools/smuggler/smuggler.py; this shim PATH-exposes
# it. `printf` over heredoc to keep the `&&`-chain syntax-clean inside
# a single RUN.
RUN printf '%s\n' \
        '#!/bin/sh' \
        'exec python3 /home/pentester/tools/smuggler/smuggler.py "$@"' \
        > /usr/local/bin/smuggler \
 && chmod 0755 /usr/local/bin/smuggler

# tree-sitter parser-directory config (matches the prior Kali-era setup so
# `tree-sitter parse foo.py` finds the cloned grammars on first invocation).
USER pentester
RUN tree-sitter init-config >/dev/null 2>&1 || true \
 && TS_CONFIG="/home/pentester/.config/tree-sitter/config.json" \
 && mkdir -p "$(dirname "$TS_CONFIG")" \
 && [ -f "$TS_CONFIG" ] || printf '{}\n' > "$TS_CONFIG" \
 && TMP_CFG="$(mktemp)" \
 && jq --arg p "/home/pentester/.tree-sitter/parsers" \
       '.["parser-directories"] = ((.["parser-directories"] // []) + [$p] | unique)' \
       "$TS_CONFIG" > "$TMP_CFG" \
 && mv "$TMP_CFG" "$TS_CONFIG"

USER root

# CA cert from the dedicated builder stage. Installed into the system trust
# store so curl / python-requests / playwright all chain through Caido.
COPY --from=ca-builder /app/certs /app/certs
RUN chown -R pentester:pentester /app/certs \
 && cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt \
 && update-ca-certificates

# Caido — released as a static tarball; download + drop the binary. ARCH-aware.
RUN ARCH=$(uname -m) \
 && if [ "$ARCH" = "x86_64" ]; then CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then CAIDO_ARCH="aarch64"; \
    else echo "Unsupported architecture: $ARCH" && exit 1; fi \
 && curl -fsSLo /tmp/caido.tar.gz \
        "https://caido.download/releases/v0.48.0/caido-cli-v0.48.0-linux-${CAIDO_ARCH}.tar.gz" \
 && tar -xzf /tmp/caido.tar.gz -C /tmp \
 && chmod +x /tmp/caido-cli \
 && mv /tmp/caido-cli /usr/local/bin/caido-cli \
 && rm /tmp/caido.tar.gz

# trufflehog + gitleaks — published binary tarballs. Both used at L1 by
# `secrets_scan`; they MUST exist at runtime.
RUN curl -fsSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin

RUN ARCH="$(uname -m)" \
 && case "$ARCH" in \
        x86_64) GITLEAKS_ARCH="x64" ;; \
        aarch64|arm64) GITLEAKS_ARCH="arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac \
 && TAG="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)" \
 && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/${TAG}/gitleaks_${TAG#v}_linux_${GITLEAKS_ARCH}.tar.gz" \
        -o /tmp/gitleaks.tgz \
 && tar -xzf /tmp/gitleaks.tgz -C /tmp \
 && install -m 0755 /tmp/gitleaks /usr/local/bin/gitleaks \
 && rm -f /tmp/gitleaks /tmp/gitleaks.tgz

# iter-22.4 — Hadolint (Haskell-built Dockerfile linter). Same
# release-binary pattern as gitleaks. Used by
# `scan_dockerfile_hadolint`.
RUN ARCH="$(uname -m)" \
 && case "$ARCH" in \
        x86_64) HADOLINT_ARCH="x86_64" ;; \
        aarch64|arm64) HADOLINT_ARCH="arm64" ;; \
        *) echo "Unsupported architecture for hadolint: $ARCH" >&2; exit 1 ;; \
    esac \
 && TAG="$(curl -fsSL https://api.github.com/repos/hadolint/hadolint/releases/latest | jq -r .tag_name)" \
 && curl -fsSL "https://github.com/hadolint/hadolint/releases/download/${TAG}/hadolint-Linux-${HADOLINT_ARCH}" \
        -o /usr/local/bin/hadolint \
 && chmod 0755 /usr/local/bin/hadolint

# iter-23.3 — feroxbuster (Rust recursive content discovery). Same
# release-binary pattern as gitleaks / hadolint. Used by
# `discover_paths_feroxbuster`.
# iter-27.4 — feroxbuster release-asset naming differs by arch:
# x86_64 has `.tar.gz`; aarch64 only ships `.zip`. The original
# Dockerfile assumed both arches had tar.gz and the build broke on
# arm64. Handle both.
RUN ARCH="$(uname -m)" \
 && case "$ARCH" in \
        x86_64) FEROX_ASSET="x86_64-linux-feroxbuster.tar.gz"; EXT="tar.gz" ;; \
        aarch64|arm64) FEROX_ASSET="aarch64-linux-feroxbuster.zip"; EXT="zip" ;; \
        *) echo "Unsupported architecture for feroxbuster: $ARCH" >&2; exit 1 ;; \
    esac \
 && TAG="$(curl -fsSL https://api.github.com/repos/epi052/feroxbuster/releases/latest | jq -r .tag_name)" \
 && apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://github.com/epi052/feroxbuster/releases/download/${TAG}/${FEROX_ASSET}" \
        -o /tmp/feroxbuster.archive \
 && (if [ "$EXT" = "tar.gz" ]; then \
        tar -xzf /tmp/feroxbuster.archive -C /tmp; \
    else \
        unzip -q /tmp/feroxbuster.archive -d /tmp; \
    fi) \
 && install -m 0755 /tmp/feroxbuster /usr/local/bin/feroxbuster \
 && rm -f /tmp/feroxbuster /tmp/feroxbuster.archive

# iter-24.1 — build-time seed of the ruleset cache. Pull the canonical
# upstream rule files into /home/pentester/.strix/cache/rules/ so a
# freshly-pulled sandbox already has every config, even without
# network. The runtime `update_*` tools refresh these in place once
# the 24h freshness window expires. Files: gitleaks.toml (secret
# detection rules), hadolint.yaml (Dockerfile linter rules),
# wappalyzer-technologies.json (tech fingerprinting DB).
# Best-effort: failure here MUST NOT break the build; the runtime
# tools fall back to baked-in defaults.
RUN mkdir -p /home/pentester/.strix/cache/rules \
 && (curl -fsSL --connect-timeout 10 --max-time 30 \
        "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml" \
        -o /home/pentester/.strix/cache/rules/gitleaks.toml \
     || echo "[warn] gitleaks.toml seed skipped (no net?)") \
 && (curl -fsSL --connect-timeout 10 --max-time 30 \
        "https://raw.githubusercontent.com/hadolint/hadolint/master/.hadolint.yaml" \
        -o /home/pentester/.strix/cache/rules/hadolint.yaml \
     || echo "[warn] hadolint.yaml seed skipped (no net?)") \
 && (curl -fsSL --connect-timeout 10 --max-time 30 \
        "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies.json" \
        -o /home/pentester/.strix/cache/rules/wappalyzer-technologies.json \
     || echo "[warn] wappalyzer-technologies.json seed skipped (no net?)") \
 && chown -R pentester:pentester /home/pentester/.strix

# iter-22.3 — testssl.sh (bash-based TLS auditor, ~50 checks).
# Cloned from upstream and symlinked. Used by
# `tls_audit_testssl`. Apt's testssl.sh is often stale; cloning
# the release branch gets the latest CVE-test coverage.
RUN git clone --depth 1 --branch 3.2 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
 && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
 && find /opt/testssl.sh -name '.git' -type d -exec rm -rf {} + 2>/dev/null || true

# trivy + grype — installed via vendor scripts. Vuln DBs are NOT downloaded
# at build time (A4): the entrypoint lazy-fetches them on first start if no
# /var/strix-cache/{trivy,grype} volume is mounted. Saves ~300 MB of
# already-stale data baked into the image.
#
# Also skips the trivy java DB (A5) — only useful for JAR-bearing scans;
# trivy fetches it on first encounter rather than baking ~150 MB upfront.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin

# osv-scanner — Google lockfile-against-osv.dev scanner. Wired into
# scan_sca_lockfiles as the cache-empty fallback (#376).
RUN ARCH="$(uname -m)" \
 && case "$ARCH" in \
        x86_64) OSV_ARCH="linux_amd64" ;; \
        aarch64|arm64) OSV_ARCH="linux_arm64" ;; \
        *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac \
 && TAG="$(curl -fsSL https://api.github.com/repos/google/osv-scanner/releases/latest | jq -r .tag_name)" \
 && curl -fsSL "https://github.com/google/osv-scanner/releases/download/${TAG}/osv-scanner_${OSV_ARCH}" \
        -o /tmp/osv-scanner \
 && install -m 0755 /tmp/osv-scanner /usr/local/bin/osv-scanner \
 && rm -f /tmp/osv-scanner

# jwt_tool — clone-staged; expose as a PATH command for the agent.
USER pentester
RUN mkdir -p /home/pentester/.local/bin \
 && ln -sf /home/pentester/tools/jwt_tool/jwt_tool.py /home/pentester/.local/bin/jwt_tool

USER root

# ---- Strix Python package + sandbox venv ----

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/.venv/bin:${PATH}" \
    VIRTUAL_ENV="/app/.venv" \
    STRIX_SANDBOX_MODE=true \
    PYTHONPATH=/app \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app

RUN mkdir -p /workspace \
 && chown -R pentester:pentester /workspace /app

# Pre-built venv from venv-builder. Self-contained (UV_LINK_MODE=copy in
# the builder) and linked against python:3.12-slim-bookworm's
# /usr/local/bin/python3, which is also our base here — so the
# /app/.venv/bin/python symlink resolves cleanly.
#
# `--chown=pentester:pentester` sets ownership during the COPY itself
# rather than spawning a follow-up RUN chown, which would duplicate every
# file into a fresh layer (a 2.3 GB chown layer was observed on the first
# build of this Dockerfile — same files written twice in OverlayFS).
COPY --from=venv-builder --chown=pentester:pentester /app/.venv /app/.venv

# Playwright chromium pre-downloaded in venv-builder under
# /opt/playwright-browsers; relocate to the runtime user's standard
# cache path so playwright finds it without a re-download.
COPY --from=venv-builder --chown=pentester:pentester /opt/playwright-browsers /home/pentester/.cache/ms-playwright

# Stub pyproject.toml / uv.lock + the editable-install marker files so any
# `python -m strix` invocation that walks back through the project root
# still resolves. The full source is COPY'd below.
COPY pyproject.toml uv.lock ./
RUN echo "# Sandbox Environment" > README.md \
 && mkdir -p strix \
 && touch strix/__init__.py

# Copy the full strix package source into /app/strix/. Required because
# strix/tools/__init__.py + strix/runtime/* import from many strix.*
# sub-modules; selective COPYs leave the runtime importing from a half-
# populated tree and break the sandbox at runtime. Documented as a previous
# incident: "No module named 'strix.sca'" / "strix.threat_intel".
COPY strix/ /app/strix/

RUN echo 'export PATH="/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.bashrc \
 && echo 'export PATH="/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
