"""Dockerfile + docker-compose rules — Phase 11.3.

Dockerfile rules walk the parsed directive list (from
`parsers/docker.py::_parse_dockerfile_lines`) so every finding
gets a precise line number.

docker-compose rules walk the YAML structure under `services:`.
"""

from __future__ import annotations

import re
from typing import Any

from strix.iac.parsers.base import (
    PLATFORM_DOCKER,
    PLATFORM_DOCKER_COMPOSE,
    IacFile,
)
from strix.iac.rules import IacFinding, register_rule


# Sensitive ports — exposing these to the host network is
# almost always a misconfig in a vibe-coded SaaS context. The
# DB container should be reachable from the app container, not
# from the host.
_SENSITIVE_DB_PORTS = {
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "9200": "Elasticsearch",
    "11211": "Memcached",
    "5984": "CouchDB",
    "9042": "Cassandra",
    "8086": "InfluxDB",
}


_SECRET_LIKE = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AKIA[A-Z0-9]{16}"),
    re.compile(r"AIza[A-Za-z0-9_-]{35}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY"),
]


# ---------------------------------------------------------------------------
# Dockerfile rules
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_DOCKER)
def dockerfile_no_user_directive(iac: IacFile) -> list[IacFinding]:
    """No `USER` directive → container runs as root. CIS
    benchmark 4.1. AI-generated Dockerfiles routinely omit USER
    because tutorials don't show it. Add `USER 1001:1001` (or a
    named user) before CMD."""
    if not isinstance(iac.data, list):
        return []
    has_user = any(d.get("directive") == "USER" for d in iac.data)
    if has_user:
        return []
    # Find the FROM line so we can pin the finding to it.
    from_line = next(
        (d["line"] for d in iac.data if d.get("directive") == "FROM"),
        1,
    )
    return [IacFinding(
        rule_id="dockerfile-no-user-directive",
        file=iac.path,
        line=from_line,
        severity="high",
        message=(
            "Dockerfile has no `USER` directive — container "
            "runs as root. CIS Docker Benchmark 4.1: containers "
            "should run as a non-root user. A breakout from a "
            "root container has full host access; from a "
            "non-root container the blast radius is much smaller. "
            "Add `USER 1001:1001` (or a named user created via "
            "`useradd`) before the final CMD/ENTRYPOINT."
        ),
        cwe="CWE-269",
        category="misconfig",
        platform=iac.platform,
    )]


@register_rule(platform=PLATFORM_DOCKER)
def dockerfile_user_root(iac: IacFile) -> list[IacFinding]:
    """Explicit `USER root` / `USER 0` after a downgrade. CIS
    4.1 again — even an explicit root re-elevation is suspicious."""
    if not isinstance(iac.data, list):
        return []
    out: list[IacFinding] = []
    for d in iac.data:
        if d.get("directive") != "USER":
            continue
        args = (d.get("args") or "").strip().lower()
        if args in ("root", "0", "0:0"):
            out.append(IacFinding(
                rule_id="dockerfile-user-root",
                file=iac.path,
                line=d.get("line", 0),
                severity="high",
                message=(
                    f"Dockerfile sets `USER {d['args']}` — "
                    f"container runs as root. If this is the "
                    f"final USER in the file, the running "
                    f"container is privileged; if an earlier "
                    f"USER was non-root, this is a deliberate "
                    f"escalation. Either way: switch to a "
                    f"non-root user."
                ),
                cwe="CWE-269",
                category="misconfig",
                platform=iac.platform,
            ))
    return out


@register_rule(platform=PLATFORM_DOCKER)
def dockerfile_latest_tag(iac: IacFile) -> list[IacFinding]:
    """`FROM image:latest` (or `FROM image` with no tag) — non-
    deterministic builds. Tomorrow's `latest` may be a different
    image than today's. AI-generated Dockerfiles ship with
    `:latest` because tutorials use it; the cost is supply-chain
    surprises."""
    if not isinstance(iac.data, list):
        return []
    out: list[IacFinding] = []
    for d in iac.data:
        if d.get("directive") != "FROM":
            continue
        args = (d.get("args") or "").strip()
        # Strip "AS stage" suffix.
        image = args.split(" AS ", 1)[0].split(" as ", 1)[0].strip()
        # Skip ARG-substituted images (`$BASE`).
        if image.startswith("$"):
            continue
        # `image` (no tag) → defaults to :latest.
        # `image:latest` → explicit.
        if "@sha256:" in image:
            # Pinned by digest — best practice; skip.
            continue
        if ":" not in image or image.endswith(":latest"):
            out.append(IacFinding(
                rule_id="dockerfile-latest-tag",
                file=iac.path,
                line=d.get("line", 0),
                severity="low",
                message=(
                    f"Dockerfile `FROM {image}` uses `:latest` "
                    f"(or no tag, which defaults to `:latest`). "
                    f"Builds are non-deterministic — same "
                    f"Dockerfile, different image at different "
                    f"times. Pin to a specific version "
                    f"(e.g. `node:18.19.0-alpine`) or a digest "
                    f"(`@sha256:...`) for reproducibility."
                ),
                cwe="CWE-1357",
                category="misconfig",
                platform=iac.platform,
                metadata={"image": image},
            ))
    return out


@register_rule(platform=PLATFORM_DOCKER)
def dockerfile_env_hardcoded_secret(iac: IacFile) -> list[IacFinding]:
    """`ENV` with a literal secret-shaped value. ENV values
    survive into the running container's process env AND into
    every layer of the built image — extractable with
    `docker history`."""
    if not isinstance(iac.data, list):
        return []
    out: list[IacFinding] = []
    for d in iac.data:
        if d.get("directive") != "ENV":
            continue
        args = d.get("args") or ""
        for pat in _SECRET_LIKE:
            if pat.search(args):
                out.append(IacFinding(
                    rule_id="dockerfile-env-hardcoded-secret",
                    file=iac.path,
                    line=d.get("line", 0),
                    severity="critical",
                    message=(
                        "Dockerfile `ENV` contains a literal "
                        "matching a known secret pattern. "
                        "ENV survives into image layers — "
                        "`docker history` exposes it to anyone "
                        "with the image. Use build secrets "
                        "(`--secret`) or runtime env "
                        "(`docker run -e`) instead. Rotate the "
                        "value if this Dockerfile has been "
                        "published."
                    ),
                    cwe="CWE-798",
                    category="info_disclosure",
                    platform=iac.platform,
                ))
                break
    return out


@register_rule(platform=PLATFORM_DOCKER)
def dockerfile_add_from_url(iac: IacFile) -> list[IacFinding]:
    """`ADD <url> ...` — fetches arbitrary URL at build time
    without integrity verification. Use `COPY` for local files;
    for remote files, use `RUN curl --fail ... && sha256sum -c`."""
    if not isinstance(iac.data, list):
        return []
    out: list[IacFinding] = []
    for d in iac.data:
        if d.get("directive") != "ADD":
            continue
        args = (d.get("args") or "").strip()
        # First token is the source.
        src = args.split()[0] if args else ""
        if src.startswith(("http://", "https://", "ftp://")):
            out.append(IacFinding(
                rule_id="dockerfile-add-from-url",
                file=iac.path,
                line=d.get("line", 0),
                severity="medium",
                message=(
                    f"Dockerfile `ADD {src}` fetches a remote URL "
                    f"at build time without integrity check. The "
                    f"upstream can change unilaterally — supply-"
                    f"chain risk. Use `RUN curl --fail $URL > x && "
                    f"echo 'SHA256...' | sha256sum -c -` to pin "
                    f"the content hash."
                ),
                cwe="CWE-494",
                category="misconfig",
                platform=iac.platform,
            ))
    return out


# ---------------------------------------------------------------------------
# docker-compose.yml rules
# ---------------------------------------------------------------------------


def _line_for(raw: str, needle: str) -> int:
    if not raw or not needle:
        return 0
    idx = raw.find(needle)
    return raw[:idx].count("\n") + 1 if idx >= 0 else 0


@register_rule(platform=PLATFORM_DOCKER_COMPOSE)
def compose_privileged_container(iac: IacFile) -> list[IacFinding]:
    """`privileged: true` gives the container almost-host
    capabilities — kernel modules, raw devices, network admin.
    AI-generated docker-compose files use this to "make
    GPU/USB/whatever just work". Audit each instance."""
    if not isinstance(iac.data, dict):
        return []
    out: list[IacFinding] = []
    for svc_name, cfg in (iac.data.get("services") or {}).items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("privileged") is True:
            out.append(IacFinding(
                rule_id="compose-privileged-container",
                file=iac.path,
                line=_line_for(iac.raw_text, svc_name),
                severity="high",
                message=(
                    f"Service `{svc_name}` runs with "
                    f"`privileged: true`. The container has "
                    f"near-host capabilities — kernel modules, "
                    f"raw block devices, network admin. A "
                    f"breakout from this container is a host "
                    f"compromise. Replace with the specific "
                    f"`cap_add: [...]` you actually need."
                ),
                cwe="CWE-269",
                category="misconfig",
                platform=iac.platform,
                metadata={"service": svc_name},
            ))
    return out


@register_rule(platform=PLATFORM_DOCKER_COMPOSE)
def compose_host_network_mode(iac: IacFile) -> list[IacFinding]:
    """`network_mode: host` removes container network isolation.
    The container can bind to host ports directly and reach all
    host interfaces. Almost always a misconfig in production."""
    if not isinstance(iac.data, dict):
        return []
    out: list[IacFinding] = []
    for svc_name, cfg in (iac.data.get("services") or {}).items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("network_mode") == "host":
            out.append(IacFinding(
                rule_id="compose-host-network-mode",
                file=iac.path,
                line=_line_for(iac.raw_text, svc_name),
                severity="medium",
                message=(
                    f"Service `{svc_name}` uses "
                    f"`network_mode: host`. Container shares "
                    f"the host's network namespace — can bind "
                    f"to any host port, reach localhost on the "
                    f"host machine, and bypass any docker "
                    f"network policies. Use the default bridge "
                    f"network unless you specifically need raw "
                    f"network access."
                ),
                cwe="CWE-732",
                category="misconfig",
                platform=iac.platform,
                metadata={"service": svc_name},
            ))
    return out


@register_rule(platform=PLATFORM_DOCKER_COMPOSE)
def compose_docker_socket_mount(iac: IacFile) -> list[IacFinding]:
    """`/var/run/docker.sock` bind-mount = container can manage
    the host's Docker daemon = effective root. The classic
    "Watchtower" / "portainer" pattern that gets copy-pasted
    into security-sensitive contexts."""
    if not isinstance(iac.data, dict):
        return []
    out: list[IacFinding] = []
    for svc_name, cfg in (iac.data.get("services") or {}).items():
        if not isinstance(cfg, dict):
            continue
        for vol in (cfg.get("volumes") or []):
            spec = vol if isinstance(vol, str) else (
                vol.get("source", "") if isinstance(vol, dict) else ""
            )
            if "docker.sock" in spec:
                out.append(IacFinding(
                    rule_id="compose-docker-socket-mount",
                    file=iac.path,
                    line=_line_for(iac.raw_text, "docker.sock"),
                    severity="critical",
                    message=(
                        f"Service `{svc_name}` mounts the "
                        f"Docker socket. Code in the container "
                        f"can spawn arbitrary containers on the "
                        f"host (including `--privileged` ones), "
                        f"giving it effective root on the host. "
                        f"Use the Docker daemon's HTTP API with "
                        f"TLS auth instead, or use a separate "
                        f"container-management plane."
                    ),
                    cwe="CWE-269",
                    category="misconfig",
                    platform=iac.platform,
                    metadata={"service": svc_name},
                ))
                break  # one finding per service
    return out


@register_rule(platform=PLATFORM_DOCKER_COMPOSE)
def compose_db_port_exposed_to_host(iac: IacFile) -> list[IacFinding]:
    """`ports: ['3306:3306']` exposes the MySQL port to the
    host, which usually means to the public internet on dev
    boxes / cloud VMs. Use `expose:` for inter-container access
    instead."""
    if not isinstance(iac.data, dict):
        return []
    out: list[IacFinding] = []
    for svc_name, cfg in (iac.data.get("services") or {}).items():
        if not isinstance(cfg, dict):
            continue
        for port in (cfg.get("ports") or []):
            spec = port if isinstance(port, str) else (
                f"{port.get('published', '')}:{port.get('target', '')}"
                if isinstance(port, dict) else ""
            )
            if not spec:
                continue
            # Format `HOST:CONTAINER` or `HOST:CONTAINER/proto`.
            host_part = spec.split(":", 1)[0].strip()
            cont_part = spec.split(":", 1)[1].split("/", 1)[0].strip() \
                if ":" in spec else ""
            for port_str in (host_part, cont_part):
                if port_str in _SENSITIVE_DB_PORTS:
                    out.append(IacFinding(
                        rule_id="compose-db-port-exposed",
                        file=iac.path,
                        line=_line_for(iac.raw_text, spec),
                        severity="high",
                        message=(
                            f"Service `{svc_name}` exposes "
                            f"port `{port_str}` "
                            f"({_SENSITIVE_DB_PORTS[port_str]}) "
                            f"to the host. On a cloud VM, this "
                            f"typically means the database is "
                            f"reachable from the public "
                            f"internet. Use `expose:` for "
                            f"inter-container access only, or "
                            f"bind to `127.0.0.1:` explicitly."
                        ),
                        cwe="CWE-668",
                        category="misconfig",
                        platform=iac.platform,
                        metadata={"service": svc_name,
                                  "port": port_str,
                                  "service_type":
                                  _SENSITIVE_DB_PORTS[port_str]},
                    ))
                    break
    return out


@register_rule(platform=PLATFORM_DOCKER_COMPOSE)
def compose_environment_hardcoded_secret(iac: IacFile) -> list[IacFinding]:
    """Service `environment:` with a literal secret value. Like
    Dockerfile ENV, this lands in the container's process env
    and is readable by anyone who can `docker inspect` the
    container."""
    if not isinstance(iac.data, dict):
        return []
    out: list[IacFinding] = []
    for svc_name, cfg in (iac.data.get("services") or {}).items():
        if not isinstance(cfg, dict):
            continue
        env = cfg.get("environment") or {}
        if isinstance(env, list):
            # `["KEY=value", ...]` form.
            entries = [e for e in env if isinstance(e, str)]
            for entry in entries:
                for pat in _SECRET_LIKE:
                    if pat.search(entry):
                        out.append(IacFinding(
                            rule_id="compose-environment-hardcoded-secret",
                            file=iac.path,
                            line=_line_for(iac.raw_text, entry[:40]),
                            severity="critical",
                            message=(
                                f"Service `{svc_name}` has a "
                                f"hardcoded secret in "
                                f"`environment:`. Move to "
                                f"`env_file:` (gitignored) or "
                                f"a secret-manager integration."
                            ),
                            cwe="CWE-798",
                            category="info_disclosure",
                            platform=iac.platform,
                            metadata={"service": svc_name},
                        ))
                        break
        elif isinstance(env, dict):
            for key, value in env.items():
                if not isinstance(value, str):
                    continue
                for pat in _SECRET_LIKE:
                    if pat.search(value):
                        out.append(IacFinding(
                            rule_id="compose-environment-hardcoded-secret",
                            file=iac.path,
                            line=_line_for(iac.raw_text, key),
                            severity="critical",
                            message=(
                                f"Service `{svc_name}` env var "
                                f"`{key}` contains a literal "
                                f"matching a known secret "
                                f"pattern. Move to `env_file:` "
                                f"(gitignored) or a secret-"
                                f"manager integration."
                            ),
                            cwe="CWE-798",
                            category="info_disclosure",
                            platform=iac.platform,
                            metadata={"service": svc_name,
                                      "env_key": key},
                        ))
                        break
    return out
