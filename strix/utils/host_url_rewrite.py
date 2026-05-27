"""iter-Q5.23 — translate the docker host-gateway alias to a
host-loopback IP before issuing a HOST-SIDE HTTP request.

Background
----------
Tools registered with `sandbox_execution=False` execute inside the
strix host process. The L1 bench harness — and any production caller
that routes work through both sandbox-side and host-side tools — may
hand them URLs containing `host.docker.internal` (the docker
host-gateway alias). That alias is resolvable *from inside a docker
container* (where it's mapped to the host's loopback via
`extra_hosts={"host.docker.internal": "host-gateway"}` —
`strix/runtime/docker_runtime.py:188`). It is NOT resolvable from a
plain host shell on macOS, and not by default on Linux either.

The symptom (observed in the post-iter-Q5.21 bench run): host-side
`fingerprint_tech_stack` and `openapi_spec_ingest` raise
`ConnectError: nodename nor servname provided` and contribute zero
findings, even though the target's docker-compose IS reachable on
the host's `127.0.0.1` at the same port.

The cure is symmetric to iter-Q5.21's bench-side rewrite: when a
host-side tool gets a `host.docker.internal` URL, rewrite the host
part of the URL to `127.0.0.1` before issuing the HTTP request. The
sandbox-side counterpart already does this implicitly via the
host-gateway alias.

What this does NOT touch
------------------------
- DNS lookups for non-loopback hostnames (real domains).
- IPv6 literals or hostnames the host can resolve normally.
- Sandbox-routed tools — they continue to use the docker alias
  unchanged.

Empty / None / non-URL strings pass through unchanged.
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse


# The docker host-gateway alias. Mirrors `HOST_GATEWAY_HOSTNAME` in
# strix/runtime/docker_runtime.py — kept duplicated here rather than
# imported to avoid pulling the runtime module into pure-host tools
# (it would force docker dependencies into every host-side import).
_DOCKER_HOST_ALIAS = "host.docker.internal"

# The loopback the host-side process can always reach. Picked over
# `localhost` for two reasons: (1) some test environments stub
# /etc/hosts and remove the `localhost` entry but keep 127.0.0.1,
# (2) IP form skips DNS entirely.
_HOST_LOOPBACK = "127.0.0.1"


def to_host_loopback(url: str) -> str:
    """If `url`'s host part is the docker host-gateway alias, return
    a new URL with `127.0.0.1` substituted; otherwise return `url`
    unchanged.

    Preserves scheme, port, path, query, and fragment exactly. The
    only mutation is the netloc's hostname.

    Examples
    --------
    >>> to_host_loopback("http://host.docker.internal:5001/api")
    'http://127.0.0.1:5001/api'
    >>> to_host_loopback("https://example.com/x")
    'https://example.com/x'
    >>> to_host_loopback("")
    ''
    """
    if not url or not isinstance(url, str):
        return url
    # Cheap fast-path: substring miss means no rewrite possible.
    if _DOCKER_HOST_ALIAS not in url:
        return url
    try:
        parsed = urlparse(url)
    except (ValueError, AttributeError):
        return url
    if parsed.hostname != _DOCKER_HOST_ALIAS:
        # The alias appears in the URL but not as the hostname (path
        # or query). Leave it alone — only the netloc matters for
        # resolution.
        return url
    # Rebuild netloc with the loopback IP, preserving userinfo + port.
    new_netloc = _HOST_LOOPBACK
    if parsed.port is not None:
        new_netloc = f"{_HOST_LOOPBACK}:{parsed.port}"
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo = f"{userinfo}:{parsed.password}"
        new_netloc = f"{userinfo}@{new_netloc}"
    return urlunparse(parsed._replace(netloc=new_netloc))


def to_host_loopback_host(host: str) -> str:
    """The bare-hostname variant of `to_host_loopback`. For tools
    that take just `hostname:port` or `hostname` strings (no scheme),
    so a `urlparse` wouldn't be appropriate.

    Returns `127.0.0.1` if `host == "host.docker.internal"`; otherwise
    returns `host` unchanged. Port suffixes like
    `host.docker.internal:5001` are also handled.
    """
    if not host or not isinstance(host, str):
        return host
    if host == _DOCKER_HOST_ALIAS:
        return _HOST_LOOPBACK
    if host.startswith(_DOCKER_HOST_ALIAS + ":"):
        return _HOST_LOOPBACK + host[len(_DOCKER_HOST_ALIAS):]
    return host
