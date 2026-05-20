#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IMAGE="strix-sandbox"
# Default tag is `local` because that's what `STRIX_IMAGE` resolves to in
# the saved CLI config when developing against a locally-built image
# (strix/config/config.py sets the registry default `ghcr.io/usestrix/...`
# only when no override is present). Passing a tag arg overrides this:
#   ./scripts/docker.sh             → strix-sandbox:local
#   ./scripts/docker.sh phase2-test → strix-sandbox:phase2-test
TAG="${1:-local}"

echo "Building $IMAGE:$TAG ..."
docker build \
  -f "$PROJECT_ROOT/containers/Dockerfile" \
  -t "$IMAGE:$TAG" \
  "$PROJECT_ROOT"

echo "Done: $IMAGE:$TAG"
