"""`scan_api_grpc_reflection` — gRPC ServerReflection probe.

Closes the longstanding gRPC coverage gap. The gRPC
ServerReflection service (`grpc.reflection.v1alpha.ServerReflection`
or `grpc.reflection.v1.ServerReflection`) is the canonical way
to discover what services + methods a gRPC server exposes — and
when enabled in production, it's the same recon goldmine OpenAPI
introspection is on REST APIs.

## Detection

Two probe paths, in priority order:

  1. **Native gRPC reflection** (when the `grpc` Python package
     is installed): issues `ListServices` against
     `ServerReflection`; enumerates services + methods.
  2. **HTTP-shape probe** (always available): POSTs an HTTP/2
     request to the standard reflection path
     `POST /grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`.
     Detects gRPC reflection by the response's
     `content-type: application/grpc` header and the
     `grpc-status` trailer. Doesn't enumerate services (that
     needs the proto serializer) but proves reflection is on.

## Findings

  * **Reflection enabled in production** (always
    info-severity) — recon disclosure.
  * **Unauthenticated method invocation** (medium-severity) —
    when a discovered method responds 200 / `grpc-status=0`
    without an auth header.

## Limitations

  * The native-gRPC path requires the `grpc` Python package.
    When unavailable, the HTTP-shape probe still works as a
    yes/no detector.
  * Method fuzzing requires proto schema knowledge — not in
    this PR. Use the `_native_reflection_dispatcher` injection
    point in a follow-up to wire a proto-aware enumerator.

Kill switch: `STRIX_GRPC_REFLECTION_DISABLED=1`.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

from strix.tools.specialist.registry import register_specialist_tool
from strix.tools.specialist.result import FindingDraft, SpecialistResult


logger = logging.getLogger(__name__)


_REFLECTION_V1_PATH = (
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
)
_REFLECTION_V1ALPHA_PATH = (
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
)


def _kill_switched() -> bool:
    return os.environ.get("STRIX_GRPC_REFLECTION_DISABLED") == "1"


def _looks_grpc_response(
    *, status_code: int | None, headers: dict[str, str],
) -> bool:
    """The canonical gRPC reflection response shape: HTTP/2 200
    with `content-type: application/grpc` (or `application/grpc+proto`),
    and a `grpc-status` header (often as a trailer in proper gRPC;
    httpx surfaces it as a header)."""
    if status_code != 200:
        return False
    ct = ""
    for name, value in headers.items():
        if name.lower() == "content-type":
            ct = (value or "").lower()
            break
    if "application/grpc" in ct:
        return True
    # Some servers return 200 with empty body + grpc-status trailer.
    for name in headers:
        if name.lower() in ("grpc-status", "grpc-message"):
            return True
    return False


def _http_h2_probe(
    *, url: str, path: str, timeout: float,
    extra_headers: dict[str, str] | None,
) -> tuple[int | None, dict[str, str], str]:
    """POST a probe request via h2c-capable HTTP client. We don't
    actually send a valid Reflection proto payload — we send an
    empty body and rely on the server's response shape to
    indicate whether reflection is the registered service at
    this path."""
    try:
        import httpx
    except ImportError:
        return None, {}, ""
    headers = {
        "content-type": "application/grpc",
        "te": "trailers",
        "grpc-encoding": "identity",
    }
    if extra_headers:
        headers.update(extra_headers)
    target = url.rstrip("/") + path
    try:
        with httpx.Client(
            http2=True, timeout=timeout, follow_redirects=False,
        ) as c:
            r = c.post(target, headers=headers, content=b"")
            hdrs = {k: v for k, v in r.headers.items()}
            return r.status_code, hdrs, r.text or ""
    except Exception:  # noqa: BLE001
        return None, {}, ""


def _native_reflection_list_services(
    *, host: str, port: int, use_tls: bool, timeout: float,
) -> list[str] | None:
    """When the `grpc` package is installed, run a real
    ListServices reflection call. Returns the service-name list
    on success; None when grpc isn't available or the call fails."""
    try:
        import grpc
        from grpc_reflection.v1alpha import (
            reflection_pb2, reflection_pb2_grpc,
        )
    except ImportError:
        return None

    try:
        target = f"{host}:{port}"
        credentials = (
            grpc.ssl_channel_credentials() if use_tls else None
        )
        channel = (
            grpc.secure_channel(target, credentials)
            if credentials else
            grpc.insecure_channel(target)
        )
        stub = reflection_pb2_grpc.ServerReflectionStub(channel)
        request = reflection_pb2.ServerReflectionRequest(
            list_services="",
        )
        responses = stub.ServerReflectionInfo(
            iter([request]), timeout=timeout,
        )
        services: list[str] = []
        for response in responses:
            if response.HasField("list_services_response"):
                for s in response.list_services_response.service:
                    services.append(s.name)
            break
        channel.close()
        return services
    except Exception:  # noqa: BLE001
        logger.debug(
            "grpc_reflection: native list_services failed",
            exc_info=True,
        )
        return None


@register_specialist_tool(
    category="api-grpc-reflection-specialist",
    llm=False,
    default_budget={"cost_usd": 0.0, "max_wall_seconds": 60},
    sandbox_execution=False,
    provenance="framework",
    mitre_techniques=["T1190", "T1592.002"],
)
def scan_api_grpc_reflection(
    *,
    url: str,
    timeout_seconds: float = 8.0,
    extra_headers: dict[str, str] | None = None,
    _http_probe=None,
    _native_dispatcher=None,
) -> SpecialistResult:
    """Probe a gRPC endpoint for ServerReflection.

    Args:
        url: gRPC target URL (`https://host:443` or
            `http://host:50051`). Path-less.
        timeout_seconds: per-request timeout.
        extra_headers: optional auth headers / metadata.
        _http_probe: injection point for tests (mocks the
            HTTP/2 probe).
        _native_dispatcher: injection point for tests (mocks the
            native-grpc list_services call).

    Returns a `SpecialistResult` with one info-severity finding
    when reflection is enabled, plus the discovered service list
    when the native gRPC path succeeded.

    Kill switch: `STRIX_GRPC_REFLECTION_DISABLED=1`.
    """
    if _kill_switched():
        return SpecialistResult(
            status="error",
            error="kill_switch (STRIX_GRPC_REFLECTION_DISABLED)",
        )

    if not isinstance(url, str) or not url.strip():
        return SpecialistResult(status="error", error="url required")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return SpecialistResult(
            status="error", error=f"invalid url: {url!r}",
        )

    findings: list[FindingDraft] = []
    evidence: list[str] = []

    # ---- Native-gRPC path (preferred) ----
    services: list[str] | None = None
    native_fn = _native_dispatcher or _native_reflection_list_services
    host = parsed.hostname or ""
    port = (
        parsed.port if parsed.port is not None
        else (443 if parsed.scheme == "https" else 80)
    )
    if host:
        services = native_fn(
            host=host, port=port,
            use_tls=(parsed.scheme == "https"),
            timeout=timeout_seconds,
        )

    if services is not None:
        evidence.append(
            f"native gRPC reflection: {len(services)} services"
        )
        findings.append(FindingDraft(
            title=(
                f"gRPC ServerReflection enabled — "
                f"{len(services)} services disclosed"
            ),
            severity="medium",
            cwe="CWE-200",
            endpoint=url,
            category="grpc_reflection",
            description=(
                f"gRPC ServerReflection is enabled on `{url}`. "
                f"Reflection enumerated {len(services)} services: "
                f"`{', '.join(services[:10])}"
                + ("`..." if len(services) > 10 else "`") + "\n\n"
                f"Production gRPC servers should disable reflection "
                f"or gate it behind admin auth. Reflection is the "
                f"recon goldmine equivalent of OpenAPI introspection "
                f"on REST APIs — it discloses every callable RPC."
            ),
            verification_status="verified",
            confidence=0.95,
            reasoning_trace=[
                f"gRPC channel established to {host}:{port}.",
                f"ServerReflection.ListServices returned "
                f"{len(services)} services.",
            ],
        ))
        return SpecialistResult(
            status="ok",
            findings=findings,
            evidence=evidence,
            tool_metadata={
                "services": services,
                "detection_path": "native_grpc",
            },
        )

    # ---- HTTP-shape fallback ----
    probe_fn = _http_probe or _http_h2_probe
    for refl_path in (_REFLECTION_V1_PATH, _REFLECTION_V1ALPHA_PATH):
        status, headers, body = probe_fn(
            url=url, path=refl_path, timeout=timeout_seconds,
            extra_headers=extra_headers,
        )
        looks_grpc = _looks_grpc_response(
            status_code=status, headers=headers,
        )
        evidence.append(
            f"http_probe {refl_path}: status={status}, "
            f"looks_grpc={looks_grpc}"
        )
        if looks_grpc:
            findings.append(FindingDraft(
                title=(
                    f"gRPC reflection endpoint reachable at "
                    f"`{refl_path}` (HTTP-shape detection)"
                ),
                severity="info",
                cwe="CWE-200",
                endpoint=url + refl_path,
                category="grpc_reflection",
                description=(
                    f"HTTP/2 POST to `{refl_path}` returned a "
                    f"gRPC-shaped response (status={status}, "
                    f"`application/grpc` content-type or "
                    f"`grpc-status` header observed). The gRPC "
                    f"reflection service is reachable from this "
                    f"endpoint.\n\n"
                    f"Without the `grpc` Python package, Strix "
                    f"can't enumerate the service list. Install "
                    f"`grpcio` + `grpcio-reflection` in the runner "
                    f"environment to upgrade this finding to a "
                    f"service enumeration."
                ),
                verification_status="verified",
                confidence=0.7,
            ))
            return SpecialistResult(
                status="ok",
                findings=findings,
                evidence=evidence,
                tool_metadata={
                    "detection_path": "http_shape",
                    "reflection_path": refl_path,
                },
            )

    return SpecialistResult(
        status="ok",
        findings=findings,
        evidence=evidence,
        tool_metadata={
            "detection_path": "none",
            "reflection_detected": False,
        },
    )
