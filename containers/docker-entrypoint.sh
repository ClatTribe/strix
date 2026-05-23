#!/bin/bash
set -e

CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

if [ ! -f /app/certs/ca.p12 ]; then
  echo "ERROR: CA certificate file /app/certs/ca.p12 not found."
  exit 1
fi

# ---------------------------------------------------------------------------
# Lazy-init scanner data (Phase 1 / A4)
# ---------------------------------------------------------------------------
#
# Nuclei templates, trivy vuln DB, and grype DB are no longer baked into the
# image at build time — they go stale within days and shed ~300 MB from the
# image. The wrapper's recommended setup is to mount /var/strix-cache from
# a host volume and refresh it nightly via cron, in which case the checks
# below see existing data and skip the download.
#
# When no volume is mounted (operator-direct `strix` CLI invocation), the
# first scan in a fresh container pays a 30-60 s init cost. Subsequent
# tools in the same container reuse the cached data. The wall-clock hit
# only happens once per container lifetime.
#
# Kill switch: `STRIX_SKIP_CACHE_INIT=1` disables all three fetches (useful
# for air-gapped runs, CI tests, or when a custom cache layout is wired in).
# ---------------------------------------------------------------------------

if [ "${STRIX_SKIP_CACHE_INIT:-0}" != "1" ]; then
  # iter-27.6: trivy + grype + syft pull DBs from OCI registries
  # (mirror.gcr.io / ghcr.io). Caido (the egress MITM proxy on
  # 48080) intermittently truncates OCI artifacts because it
  # rewrites response bodies. Bypass it for those hosts only — we
  # still want Caido in the loop for real test traffic (HTTP probes
  # against the SUT). Without this, the nginx-vuln bench aborted
  # with `unexpected EOF` mid-Java-DB-download.
  NO_PROXY_OCI="localhost,127.0.0.1,mirror.gcr.io,ghcr.io,docker.io,registry-1.docker.io,index.docker.io,public.ecr.aws,quay.io"
  export NO_PROXY="$NO_PROXY_OCI"
  export no_proxy="$NO_PROXY_OCI"

  NUCLEI_TEMPLATES_DIR="${HOME}/nuclei-templates"
  if [ ! -d "$NUCLEI_TEMPLATES_DIR" ] || [ -z "$(ls -A "$NUCLEI_TEMPLATES_DIR" 2>/dev/null)" ]; then
    echo "Lazy-init: fetching nuclei templates (one-time, ~30s)..."
    nuclei -update-templates -silent 2>&1 | tail -3 || \
      echo "WARNING: nuclei template fetch failed; signature scans will be empty."
  fi

  # iter-27.10: pre-fetch trivy DBs AS the pentester user directly,
  # not as root with a follow-up `cp -rn`. trivy's bolt-db files
  # contain page-aligned mmapable structures that the cp wasn't
  # preserving — the iter-27.8 nginx-vuln re-bench tripped a
  # `panic: assertion failed: Page expected to be: 269803, but
  # self identifies as 0` when the tool server (running as pentester)
  # tried to read root's cp'd DB. Running the fetch as pentester
  # writes the DB directly to the right location in the right format.
  PENTESTER_HAS_TRIVY_DB=0
  if id pentester >/dev/null 2>&1; then
    sudo -u pentester mkdir -p /home/pentester/.cache/trivy 2>/dev/null || true
    if [ -f /home/pentester/.cache/trivy/db/trivy.db ]; then
      PENTESTER_HAS_TRIVY_DB=1
    fi
  fi
  if [ "$PENTESTER_HAS_TRIVY_DB" = "0" ] && id pentester >/dev/null 2>&1; then
    echo "Lazy-init: fetching trivy vuln DB as pentester (one-time, ~10s)..."
    sudo -E -u pentester trivy image --download-db-only --quiet 2>&1 | tail -3 || \
      echo "WARNING: trivy DB fetch failed; container CVE scans may be slow or empty."
  fi

  # iter-27.6 + 27.10: pre-fetch trivy Java DB as pentester too.
  # Without this, the first scan against ANY image (even non-JVM
  # ones like nginx) triggers a JIT Java DB pull mid-pipeline; if
  # interrupted by proxy truncation the whole scan aborts.
  PENTESTER_HAS_JAVA_DB=0
  if id pentester >/dev/null 2>&1 && \
     [ -d /home/pentester/.cache/trivy/java-db ] && \
     [ -n "$(ls -A /home/pentester/.cache/trivy/java-db 2>/dev/null)" ]; then
    PENTESTER_HAS_JAVA_DB=1
  fi
  if [ "$PENTESTER_HAS_JAVA_DB" = "0" ] && id pentester >/dev/null 2>&1; then
    echo "Lazy-init: fetching trivy Java DB as pentester (one-time, ~30s)..."
    sudo -E -u pentester trivy image --download-java-db-only --quiet 2>&1 | tail -3 || \
      echo "WARNING: trivy Java DB fetch failed; JAR-bearing CVE scans may abort."
  fi

  GRYPE_DB_DIR="${HOME}/.cache/grype/db"
  if [ ! -d "$GRYPE_DB_DIR" ] || [ -z "$(ls -A "$GRYPE_DB_DIR" 2>/dev/null)" ]; then
    echo "Lazy-init: fetching grype vuln DB (one-time, ~10s)..."
    grype db update 2>&1 | tail -3 || \
      echo "WARNING: grype DB fetch failed; reachability-filtered SCA may be incomplete."
  fi
fi


caido-cli --listen 0.0.0.0:${CAIDO_PORT} \
          --allow-guests \
          --no-logging \
          --no-open \
          --import-ca-cert /app/certs/ca.p12 \
          --import-ca-cert-pass "" > "$CAIDO_LOG" 2>&1 &

CAIDO_PID=$!
echo "Started Caido with PID $CAIDO_PID on port $CAIDO_PORT"

echo "Waiting for Caido API to be ready..."
CAIDO_READY=false
for i in {1..30}; do
  if ! kill -0 $CAIDO_PID 2>/dev/null; then
    echo "ERROR: Caido process died while waiting for API (iteration $i)."
    echo "=== Caido log ==="
    cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
    exit 1
  fi

  if curl -s -o /dev/null -w "%{http_code}" http://localhost:${CAIDO_PORT}/graphql/ | grep -qE "^(200|400)$"; then
    echo "Caido API is ready (attempt $i)."
    CAIDO_READY=true
    break
  fi
  sleep 1
done

if [ "$CAIDO_READY" = false ]; then
  echo "ERROR: Caido API did not become ready within 30 seconds."
  echo "Caido process status: $(kill -0 $CAIDO_PID 2>&1 && echo 'running' || echo 'dead')"
  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

sleep 2

echo "Fetching API token..."
TOKEN=""
for attempt in 1 2 3 4 5; do
  RESPONSE=$(curl -sL -X POST \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}' \
    http://localhost:${CAIDO_PORT}/graphql)

  TOKEN=$(echo "$RESPONSE" | jq -r '.data.loginAsGuest.token.accessToken // empty')

  if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
    echo "Successfully obtained API token (attempt $attempt)."
    break
  fi

  echo "Token fetch attempt $attempt failed: $RESPONSE"
  sleep $((attempt * 2))
done

if [ -z "$TOKEN" ] || [ "$TOKEN" == "null" ]; then
  echo "ERROR: Failed to get API token from Caido after 5 attempts."
  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

export CAIDO_API_TOKEN=$TOKEN
echo "Caido API token has been set."

echo "Creating a new Caido project..."
CREATE_PROJECT_RESPONSE=$(curl -sL -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation CreateProject { createProject(input: {name: \"sandbox\", temporary: true}) { project { id } } }"}' \
  http://localhost:${CAIDO_PORT}/graphql)

PROJECT_ID=$(echo $CREATE_PROJECT_RESPONSE | jq -r '.data.createProject.project.id')

if [ -z "$PROJECT_ID" ] || [ "$PROJECT_ID" == "null" ]; then
  echo "Failed to create Caido project."
  echo "Response: $CREATE_PROJECT_RESPONSE"
  exit 1
fi

echo "Caido project created with ID: $PROJECT_ID"

echo "Selecting Caido project..."
SELECT_RESPONSE=$(curl -sL -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"query":"mutation SelectProject { selectProject(id: \"'$PROJECT_ID'\") { currentProject { project { id } } } }"}' \
  http://localhost:${CAIDO_PORT}/graphql)

SELECTED_ID=$(echo $SELECT_RESPONSE | jq -r '.data.selectProject.currentProject.project.id')

if [ "$SELECTED_ID" != "$PROJECT_ID" ]; then
    echo "Failed to select Caido project."
    echo "Response: $SELECT_RESPONSE"
    exit 1
fi

echo "✅ Caido project selected successfully."

echo "Configuring system-wide proxy settings..."

# iter-27.6: NO_PROXY for OCI registries so trivy/grype/syft/dockle
# can pull their vuln DBs without going through Caido (which
# truncates OCI artifact responses). The list must match the one in
# the cache-init block above, since the tool server inherits this
# env (via sudo -E) and re-runs DB fetches when caches expire.
NO_PROXY_OCI="localhost,127.0.0.1,mirror.gcr.io,ghcr.io,docker.io,registry-1.docker.io,index.docker.io,public.ecr.aws,quay.io"

cat << EOF | sudo tee /etc/profile.d/proxy.sh
export http_proxy=http://127.0.0.1:${CAIDO_PORT}
export https_proxy=http://127.0.0.1:${CAIDO_PORT}
export HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
export HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
export ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
export NO_PROXY=${NO_PROXY_OCI}
export no_proxy=${NO_PROXY_OCI}
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export CAIDO_API_TOKEN=${TOKEN}
EOF

cat << EOF | sudo tee /etc/environment
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
HTTP_PROXY=http://127.0.0.1:${CAIDO_PORT}
HTTPS_PROXY=http://127.0.0.1:${CAIDO_PORT}
ALL_PROXY=http://127.0.0.1:${CAIDO_PORT}
NO_PROXY=${NO_PROXY_OCI}
no_proxy=${NO_PROXY_OCI}
CAIDO_API_TOKEN=${TOKEN}
EOF

cat << EOF | sudo tee /etc/wgetrc
use_proxy=yes
http_proxy=http://127.0.0.1:${CAIDO_PORT}
https_proxy=http://127.0.0.1:${CAIDO_PORT}
EOF

echo "source /etc/profile.d/proxy.sh" >> ~/.bashrc
echo "source /etc/profile.d/proxy.sh" >> ~/.zshrc

source /etc/profile.d/proxy.sh

echo "✅ System-wide proxy configuration complete"

echo "Adding CA to browser trust store..."
sudo -u pentester mkdir -p /home/pentester/.pki/nssdb
sudo -u pentester certutil -N -d sql:/home/pentester/.pki/nssdb --empty-password
sudo -u pentester certutil -A -n "Testing Root CA" -t "C,," -i /app/certs/ca.crt -d sql:/home/pentester/.pki/nssdb
echo "✅ CA added to browser trust store"

echo "Starting tool server..."
cd /app
export PYTHONPATH=/app
export STRIX_SANDBOX_MODE=true
# iter-27.5: bump default from 120s → 300s. The 120s default dated
# from when L1 tools were lightweight HTTP probes; modern tools
# (trivy with DB init, sqlmap --batch --level 3, full nuclei template
# fan-out, dalfox payload set) routinely need 3-5 minutes. nginx-vuln
# container_image fixture timed out at 120s on every bench run
# despite the underlying trivy scan being well under its own 600s
# tool-side cap. Operators can override via
# STRIX_SANDBOX_EXECUTION_TIMEOUT env var.
export TOOL_SERVER_TIMEOUT="${STRIX_SANDBOX_EXECUTION_TIMEOUT:-300}"
TOOL_SERVER_LOG="/tmp/tool_server.log"

sudo -E -u pentester \
  /app/.venv/bin/python -m strix.runtime.tool_server \
  --token="$TOOL_SERVER_TOKEN" \
  --host=0.0.0.0 \
  --port="$TOOL_SERVER_PORT" \
  --timeout="$TOOL_SERVER_TIMEOUT" > "$TOOL_SERVER_LOG" 2>&1 &

for i in {1..10}; do
  if curl -s "http://127.0.0.1:$TOOL_SERVER_PORT/health" | grep -q '"status":"healthy"'; then
    echo "✅ Tool server healthy on port $TOOL_SERVER_PORT"
    break
  fi
  if [ $i -eq 10 ]; then
    echo "ERROR: Tool server failed to become healthy"
    echo "=== Tool server log ==="
    cat "$TOOL_SERVER_LOG" 2>/dev/null || echo "(no log)"
    exit 1
  fi
  sleep 1
done

echo "✅ Container ready"

cd /workspace
exec "$@"
