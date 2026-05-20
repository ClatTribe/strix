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
#   - zaproxy + JRE                 ~500 MB
#   - caido-cli                     ~150 MB
#   - tools (Go + npm + pipx)       ~300 MB total
#   - venv + strix package          ~250 MB
#   - chromium runtime libs + fonts ~80 MB
#
# Expected runtime image: ~2.5-3 GB (down from ~7 GB pre-Phase-1).

# =============================================================================
# Stage: go-builder
# =============================================================================
#
# Compiles every Go-built tool strix relies on. ProjectDiscovery's nuclei /
# subfinder / naabu / ffuf are NOT in Debian's apt repos, so they move from
# `apt-get install` (Kali-only path) into `go install` here. naabu needs
# CGO=1 + libpcap headers to build the SYN scanner; we install libpcap-dev
# only in this stage and ship only the resulting static-stripped binaries.

FROM golang:1.22-bookworm AS go-builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libpcap-dev libssl-dev pkg-config ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1 \
    GOFLAGS="-trimpath"

# `-s -w` strips the symbol table + DWARF debug info from each binary.
# Cuts each ProjectDiscovery binary by 30-50% with no functional impact.
RUN go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/cvemap/cmd/vulnx@latest \
 && go install -ldflags="-s -w" github.com/jaeles-project/gospider@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install -ldflags="-s -w" github.com/ffuf/ffuf/v2@latest

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
 && pipx install dirsearch \
 && pipx inject dirsearch setuptools \
 && pipx install wafw00f \
 && pipx install wapiti3

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
 && git clone --depth 1 https://github.com/aravind0x7/JS-Snooper.git /opt/clones/JS-Snooper \
 && chmod +x /opt/clones/JS-Snooper/js_snooper.sh \
 && git clone --depth 1 https://github.com/xchopath/jsniper.sh.git /opt/clones/jsniper.sh \
 && chmod +x /opt/clones/jsniper.sh/jsniper.sh \
 && git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/clones/jwt_tool \
 && chmod +x /opt/clones/jwt_tool/jwt_tool.py \
 && find /opt/clones -name '.git' -type d -exec rm -rf {} + 2>/dev/null || true

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

FROM debian:bookworm-slim AS runtime

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

# Enable contrib + non-free repos so zaproxy (in contrib/web) is installable.
# bookworm-slim ships the deb822-format `/etc/apt/sources.list.d/debian.sources`;
# overwrite it with a single, predictable layout rather than sed'ing the
# unknown shape we inherited. The classic /etc/apt/sources.list (if any) is
# cleared so apt only sees the file we control.
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
#   - debian-main security tools (nmap, sqlmap, zaproxy)
#   - libcap2-bin for setcap; libnss3-tools for certutil
#   - chromium runtime .so deps (for playwright-installed chrome)
#   - fonts (chrome rendering + screenshot tooling)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git sudo \
        unzip tar vim nano less \
        apt-transport-https gnupg \
        libpcap0.8 libssl3 \
        python3 python3-venv pipx \
        nodejs \
        gcc libc6-dev \
        net-tools dnsutils whois iproute2 iputils-ping netcat-traditional \
        jq parallel ripgrep procps htop tmux gdb \
        nmap ncat ndiff sqlmap \
        zaproxy \
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
RUN useradd -m -s /bin/bash pentester \
 && usermod -aG sudo pentester \
 && echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
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

# npm globals — node-builder lays them out at /usr/lib/node_modules; we
# copy that tree across and re-create the launcher symlinks under
# /usr/local/bin. NOT copying /usr/local/bin from the node-builder image
# wholesale because that would clobber `node` / `npm` from the runtime
# apt package; we pick exactly the launchers each package installs.
COPY --from=node-builder /usr/lib/node_modules /usr/lib/node_modules
RUN set -eux; \
    ln -sf /usr/lib/node_modules/retire/lib/retire.js          /usr/local/bin/retire    || true; \
    ln -sf /usr/lib/node_modules/eslint/bin/eslint.js          /usr/local/bin/eslint    || true; \
    ln -sf /usr/lib/node_modules/js-beautify/js/bin/js-beautify.js   /usr/local/bin/js-beautify    || true; \
    ln -sf /usr/lib/node_modules/js-beautify/js/bin/css-beautify.js  /usr/local/bin/css-beautify   || true; \
    ln -sf /usr/lib/node_modules/js-beautify/js/bin/html-beautify.js /usr/local/bin/html-beautify  || true; \
    ln -sf /usr/lib/node_modules/jshint/bin/jshint             /usr/local/bin/jshint    || true; \
    ln -sf /usr/lib/node_modules/tree-sitter-cli/cli.js        /usr/local/bin/tree-sitter || true; \
    if [ -d /usr/lib/node_modules/@ast-grep/cli ]; then \
        ASG_BIN="$(find /usr/lib/node_modules/@ast-grep/cli -maxdepth 2 -type f -name 'ast-grep' | head -1)"; \
        if [ -n "${ASG_BIN}" ]; then \
            ln -sf "${ASG_BIN}" /usr/local/bin/ast-grep; \
            ln -sf "${ASG_BIN}" /usr/local/bin/sg; \
        fi; \
    fi

# pipx tools — bring across /opt/pipx (venvs) and the bin shims.
COPY --from=py-builder /opt/pipx /opt/pipx
ENV PATH="/opt/pipx/bin:${PATH}"

# Static clones (tools shipped as raw scripts).
COPY --from=clone-builder /opt/clones /home/pentester/tools
COPY --from=clone-builder /opt/tree-sitter /home/pentester/.tree-sitter
RUN chown -R pentester:pentester /home/pentester/tools /home/pentester/.tree-sitter

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

COPY pyproject.toml uv.lock ./
RUN echo "# Sandbox Environment" > README.md \
 && mkdir -p strix \
 && touch strix/__init__.py

USER pentester
RUN uv sync --frozen --no-dev --extra sandbox \
 && uv pip install --no-cache-dir -r /home/pentester/tools/jwt_tool/requirements.txt

# Playwright chromium download (~300 MB). Wired through the proxy via the
# Caido CA cert installed above, so MITM works out of the box.
RUN /app/.venv/bin/python -m playwright install chromium

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
