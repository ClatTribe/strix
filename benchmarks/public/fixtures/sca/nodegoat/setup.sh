#!/usr/bin/env bash
#
# Fetch NodeGoat at a pinned commit into ./src so the benchmark is
# reproducible. NodeGoat itself is a 2 MB clone; we pin to a stable
# 2023-06 commit because the repo hasn't materially changed since.
#
# Idempotent — if ./src already exists with the right commit, no-op.

set -euo pipefail

FIXTURE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${FIXTURE_DIR}/src"
PINNED_COMMIT="c5cb68a7084e4ae7dcc60e6a98768720a81841e8"
UPSTREAM="https://github.com/OWASP/NodeGoat.git"

if [[ -d "${SRC_DIR}/.git" ]]; then
  current="$(git -C "${SRC_DIR}" rev-parse HEAD)"
  if [[ "${current}" == "${PINNED_COMMIT}" ]]; then
    echo "[setup] NodeGoat already at ${PINNED_COMMIT:0:8} — skipping clone"
    exit 0
  fi
  echo "[setup] ${SRC_DIR} is on a different commit (${current:0:8}) — resetting"
  rm -rf "${SRC_DIR}"
fi

echo "[setup] cloning NodeGoat → ${SRC_DIR}"
git clone --quiet "${UPSTREAM}" "${SRC_DIR}"
git -C "${SRC_DIR}" -c advice.detachedHead=false checkout --quiet "${PINNED_COMMIT}"
echo "[setup] pinned to ${PINNED_COMMIT:0:8}"
