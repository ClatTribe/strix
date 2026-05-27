# Deploying / consuming this Strix fork

This document covers how to take this Strix repository and put it in front
of a real consumer — the [ClatTribe/webappsec](https://github.com/ClatTribe/webappsec)
SaaS wrapper, a CI pipeline, or any other host that drives `strix` as a
subprocess.

> If you only want to *use* upstream Strix, install via pipx + the public
> sandbox image — see the [README](README.md) Quick Start. This document
> is for shipping a **fork-built** Strix to a consumer.

---

## The two layers

Strix is delivered as two cooperating Docker concerns. Knowing which one
your fork changes determines which one you need to rebuild:

| Layer | Built from | Default location | Used by |
|---|---|---|---|
| **Sandbox image** — Kali + nuclei/nmap/sqlmap/Caido/Playwright/Trivy etc. The Strix agent spawns this per-scan as the tool-execution environment. | [`containers/Dockerfile`](containers/Dockerfile) in this repo | `strix-sandbox:local` — the ClatTribe fork builds its own (the upstream `ghcr.io/usestrix/strix-sandbox:0.1.13` tag is NOT mirrored to ClatTribe and 404s on pull). Set in [`strix/config/config.py:43`](strix/config/config.py:43); override via `STRIX_IMAGE` env. | The Strix CLI itself, via Docker SDK |
| **Strix CLI** — the Python package that orchestrates scans. | [`pyproject.toml`](pyproject.toml) → wheel on PyPI as `strix-agent` | PyPI `strix-agent` | Whoever invokes `strix` (CI runner, wrapper worker, your shell) |

Forks usually need **both** rebuilt, because most non-trivial changes
touch either skill files (bundled into the wheel) or sandbox tooling.

---

## Local-only flow (recommended for development)

Build the sandbox image once on your dev machine, point the wrapper at
it, and iterate. No registry push, no CI, no GHCR auth.

The flow works because Strix's [`pull_docker_image`](strix/interface/main.py:487)
short-circuits on `image_exists()` — a locally-tagged image is detected
and the registry pull is skipped.

### 1. Build the sandbox image

```bash
cd /path/to/strix
docker build -f containers/Dockerfile -t strix-sandbox:local .
```

> Heads-up: this is a heavy build. Kali rolling base + nuclei / nmap / ffuf
> / sqlmap / Playwright / Trivy / etc. — first build is typically
> **30–60 minutes**, final image ~3–5 GB. Subsequent builds are much
> faster thanks to layer caching.

Verify when it finishes:

```bash
docker images strix-sandbox:local
# REPOSITORY        TAG     IMAGE ID       CREATED          SIZE
# strix-sandbox     local   <id>           <time>           ~4GB
```

### 2. Point the wrapper at the local image

In `webappsec/webapp/worker/.env` (copy from `.env.example` if not done yet):

```bash
STRIX_IMAGE=strix-sandbox:local
```

That's it for the sandbox side. The worker passes `STRIX_IMAGE` through
to `strix` as an env var; Strix sees the tag exists locally, skips the
pull, and runs scan containers from your build.

### 3. (Optional) Use this fork's CLI too

Skip this step if your fork only changes `containers/Dockerfile`. Do it
if your fork has any Python-side changes — including
`strix/skills/*` files, since skills are bundled into the wheel.

```bash
# In the webappsec worker's local-dev shell
pipx uninstall strix-agent 2>/dev/null  # remove upstream if present

# Install from your local fork
pipx install /path/to/strix

# Verify
which strix && strix --version
```

For active development on the fork, use editable install so saves are
picked up immediately:

```bash
pipx install --editable /path/to/strix
```

### 4. Run the worker

```bash
cd /path/to/webappsec/webapp/worker
uv sync
uv run strix-worker
```

When a scan kicks off, look for these in the worker logs:

```
running: strix -n -m standard -t <target> ...
```

In another terminal, confirm Strix is using your local image:

```bash
docker ps | grep strix-scan
docker inspect <container-id> | grep '"Image":'
# "Image": "strix-sandbox:local"
```

That confirms the loop: wrapper → Strix CLI → spawning a container from
your locally-built image.

### 5. Sanity test (without the wrapper)

To validate the image works end-to-end against a known-vulnerable
fixture before plugging into the wrapper:

```bash
cd /path/to/strix
export STRIX_IMAGE=strix-sandbox:local
export STRIX_LLM=anthropic/claude-sonnet-4-6
export LLM_API_KEY=<your-key>

strix -n -t benchmarks/per_target/fixtures/code/flask-vuln/app.py \
      --scan-mode quick
```

A `strix-scan-*` container that boots from `strix-sandbox:local` and a
scan that completes (exit code 0 or 2) means the fork is wired up
correctly.

For full per-target coverage measurement, see
[`benchmarks/per_target/README.md`](benchmarks/per_target/README.md).

---

## Caveats for the local-only flow

- **The worker must share the Docker daemon with the build host.** In
  webappsec's local-dev quickstart the worker runs directly on the host
  (`uv run strix-worker`), so the locally-built image is visible
  automatically. If you instead use webappsec's root-level
  `docker-compose.yml` to containerize the worker, that compose file
  must mount `/var/run/docker.sock` into the worker container —
  otherwise the worker spawns scan containers on a different (or
  non-existent) daemon and your local image is invisible to them.
- **Don't push `:local`.** A locally-tagged image is fine for the box
  that built it. On any other host, the wrapper will try to pull and
  fail. For shared / staging / production deploys, use a real tag like
  `strix-sandbox:0.1.13-fork` and push it to a registry — see
  [Registry-based deploy](#registry-based-deploy) below.
- **Re-run the build after changes to `containers/Dockerfile`.** The
  image only rebuilds when you ask. Bump the tag (`:local-2`,
  `:local-3`) as you iterate — `STRIX_IMAGE` will need to follow.
  Use `--no-cache` to force a clean rebuild when caching gives stale
  layers.
- **`docker build` runs as root.** The Dockerfile internally drops to
  the `pentester` user; just don't be surprised by intermediate steps
  showing as root.

---

## Registry-based deploy

Once past local dev, you'll want a real tag in a real registry so any
host can pull the image without rebuilding.

### Manual push to GHCR

```bash
# 1. Login (one-time per host)
gh auth token | docker login ghcr.io -u $(gh api user --jq .login) --password-stdin

# 2. Build for the platform your runtime needs (Fly is amd64)
docker buildx create --use --name strix-builder 2>/dev/null || true
docker buildx build \
  --platform linux/amd64 \
  -t ghcr.io/clattribe/strix-sandbox:0.1.13-fork \
  -f containers/Dockerfile \
  --push \
  .

# 3. Wrapper config — use the registry tag instead of :local
# In webappsec/webapp/worker/.env:
STRIX_IMAGE=ghcr.io/clattribe/strix-sandbox:0.1.13-fork
```

Required GitHub token scope: `package:write` on the repo's namespace.
Make the package public on GHCR (Settings → Packages) if your worker
host doesn't have credentials.

### CI-driven build (recommended for a real deploy)

Add a GitHub Actions workflow that builds and pushes on tag. A minimal
working skeleton:

```yaml
# .github/workflows/sandbox-image.yml
name: build-sandbox-image
on:
  push:
    tags: ['sandbox-v*']
  workflow_dispatch:
    inputs:
      tag:
        description: 'image tag (e.g. 0.1.13-fork)'
        required: true

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: containers/Dockerfile
          platforms: linux/amd64
          push: true
          tags: |
            ghcr.io/${{ github.repository_owner }}/strix-sandbox:${{ inputs.tag || github.ref_name }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

Trigger:

```bash
# either tag-driven
git tag sandbox-v0.1.13-fork
git push origin sandbox-v0.1.13-fork

# or manual
gh workflow run sandbox-image.yml -f tag=0.1.13-fork
```

The existing
[`.github/workflows/build-release.yml`](.github/workflows/build-release.yml)
handles CLI binary releases (PyInstaller). The sandbox-image workflow
above is purely additive.

### CLI distribution options

For a registry deploy, choose how the wrapper installs the CLI:

1. **Stick with upstream PyPI for the CLI, fork only the sandbox.** Works
   if your fork's changes are entirely inside `containers/Dockerfile`.
   No worker change beyond `STRIX_IMAGE`.
2. **Install from fork-git in the worker Dockerfile.** Edit
   `webapp/worker/Dockerfile`:
   ```dockerfile
   # replace
   RUN pipx install strix-agent
   # with
   RUN pipx install "git+https://github.com/ClatTribe/strix.git@v0.8.3-fork"
   ```
   Pros: no PyPI publishing. Cons: every worker rebuild re-clones.
3. **Publish your fork to a registry.** Either rename the package in
   [`pyproject.toml`](pyproject.toml) (e.g. `clattribe-strix-agent`) and
   publish to public PyPI, or push a wheel artifact to a private
   index. Then `pipx install clattribe-strix-agent==0.8.3` in the worker
   Dockerfile.

For a SaaS deploy where you want fast deterministic builds and don't
need PyPI discoverability, **Option 2 is usually the right call**.

---

## Wrapper-side checklist (one-time)

In the [webappsec](https://github.com/ClatTribe/webappsec) repo:

1. **Set `STRIX_IMAGE` as a Fly secret on the worker app.** For local
   dev: edit `webapp/worker/.env`. For Fly deploy:
   ```bash
   fly secrets set \
     STRIX_IMAGE=ghcr.io/clattribe/strix-sandbox:0.1.13-fork \
     -a <worker-app-name>
   ```
2. **(If using a fork CLI)** edit `webapp/worker/Dockerfile`'s
   `pipx install` line to point at your fork. Rebuild and redeploy the
   worker.
3. **Make sure the worker host can pull from your registry.** GHCR
   public packages are anonymous-pullable. For private packages, add
   `docker login` to the worker Dockerfile (with secrets) or configure
   Fly's image pull credentials.

---

## Where the defaults live

If you want your fork's CLI to default to your sandbox image so users
don't have to set `STRIX_IMAGE` themselves, edit
[`strix/config/config.py:43`](strix/config/config.py:43):

```python
strix_image = "ghcr.io/clattribe/strix-sandbox:0.1.13-fork"
```

This is a small change but a meaningful identity decision — the rest of
the codebase points at upstream's image as the "ours". Bump it on
release tags only, not on every build.

---

## Troubleshooting

**`Pulling image strix-sandbox:local` followed by an error.** You set
`STRIX_IMAGE=strix-sandbox:local` but the image isn't present on this
host's daemon. Run `docker images strix-sandbox:local` — if it's missing,
go back to Step 1.

**Worker spawns scans but they immediately fail.** Check
`docker ps -a | grep strix-scan` and inspect the failed container's
logs. The most common cause for a custom sandbox image is a missing
binary the agent expected — the upstream skills assume nuclei / nmap /
sqlmap / etc. exist; if your fork removed any, the agent will fail when
it reaches for them. Compare against the upstream `containers/Dockerfile`.

**Permission denied on `/var/run/docker.sock` from the worker.** The
user running the worker process needs to be in the `docker` group, or
the socket needs to be world-readable. On macOS with Docker Desktop
this is automatic; on Linux: `sudo usermod -aG docker $USER` and
re-login.

**`No such image` on a host that should have pulled it.** Verify the
host has registry credentials (for private images) and the platform
matches (`docker manifest inspect <image>` will show available
architectures). Fly.io machines are amd64; if you only built for arm64,
the pull fails.
