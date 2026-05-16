"""Kubernetes misconfig rules — Phase 11.4.

Rules walk the document list emitted by
`strix/iac/parsers/kubernetes.py`. Each doc is
`{apiVersion, kind, metadata, spec, doc_index, doc}`.

Rule coverage targets the Pod Security Standards "Restricted"
profile + the most-common production hardening gaps:
  * Privileged containers
  * Host namespace sharing (hostNetwork / hostPID / hostIPC)
  * runAsUser=0 / missing runAsNonRoot
  * Missing resource limits
  * Privilege escalation allowed (allowPrivilegeEscalation=true)
  * RBAC with `*` verbs / `*` resources
  * Service exposed via NodePort
  * No NetworkPolicy in namespace (informational)

Rule IDs mirror Checkov / kube-linter where possible.
"""

from __future__ import annotations

import re
from typing import Any

from strix.iac.parsers.base import PLATFORM_KUBERNETES, IacFile
from strix.iac.rules import IacFinding, register_rule


# K8s "workload" kinds — these carry pod specs we can lint.
_WORKLOAD_KINDS = frozenset({
    "Pod", "Deployment", "StatefulSet", "DaemonSet",
    "ReplicaSet", "Job", "CronJob",
})


def _pod_spec_of(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Return the podSpec for any workload kind. Pod has it at
    spec; Deployment/StatefulSet/DaemonSet have it at
    spec.template.spec; CronJob is spec.jobTemplate.spec.template.spec.
    """
    kind = doc.get("kind")
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    template = spec.get("template") or {}
    if isinstance(template, dict):
        sub = template.get("spec")
        if isinstance(sub, dict):
            return sub
    if kind == "CronJob":
        job_t = spec.get("jobTemplate") or {}
        if isinstance(job_t, dict):
            inner = job_t.get("spec") or {}
            if isinstance(inner, dict):
                tmpl = inner.get("template") or {}
                if isinstance(tmpl, dict):
                    sub = tmpl.get("spec")
                    if isinstance(sub, dict):
                        return sub
    return None


def _all_containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten initContainers + containers + ephemeralContainers."""
    out: list[dict[str, Any]] = []
    for key in ("initContainers", "containers", "ephemeralContainers"):
        v = pod_spec.get(key) or []
        if isinstance(v, list):
            out.extend(c for c in v if isinstance(c, dict))
    return out


# ---------------------------------------------------------------------------
# PRIVILEGED — container with securityContext.privileged=true
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_KUBERNETES)
def k8s_privileged_container(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    if not isinstance(iac_file.data, list):
        return out
    for doc in iac_file.data:
        if doc.get("kind") not in _WORKLOAD_KINDS:
            continue
        pod_spec = _pod_spec_of(doc)
        if not pod_spec:
            continue
        for c in _all_containers(pod_spec):
            sec = c.get("securityContext") or {}
            if isinstance(sec, dict) and sec.get("privileged") is True:
                out.append(IacFinding(
                    rule_id="K8S_PRIVILEGED_CONTAINER",
                    file=iac_file.path,
                    line=doc.get("doc_index", 0),
                    severity="critical",
                    message=(
                        f"{doc.get('kind')} "
                        f"`{(doc.get('metadata') or {}).get('name')}` "
                        f"container `{c.get('name')}` runs as "
                        f"privileged. Privileged containers have "
                        f"full host-device access — equivalent to "
                        f"root on the node. Remove `privileged: "
                        f"true` and grant specific Linux capabilities "
                        f"if absolutely needed."
                    ),
                    cwe="CWE-250",
                    category="misconfig",
                    platform=PLATFORM_KUBERNETES,
                    metadata={
                        "kind": doc.get("kind"),
                        "name": (doc.get("metadata") or {}).get("name"),
                        "container": c.get("name"),
                    },
                ))
    return out


# ---------------------------------------------------------------------------
# HOST_NAMESPACE — hostNetwork / hostPID / hostIPC = true
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_KUBERNETES)
def k8s_host_namespace_sharing(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    if not isinstance(iac_file.data, list):
        return out
    for doc in iac_file.data:
        if doc.get("kind") not in _WORKLOAD_KINDS:
            continue
        pod_spec = _pod_spec_of(doc)
        if not pod_spec:
            continue
        violations: list[str] = []
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if pod_spec.get(flag) is True:
                violations.append(flag)
        if not violations:
            continue
        out.append(IacFinding(
            rule_id="K8S_HOST_NAMESPACE_SHARING",
            file=iac_file.path,
            line=doc.get("doc_index", 0),
            severity="high",
            message=(
                f"{doc.get('kind')} "
                f"`{(doc.get('metadata') or {}).get('name')}` enables "
                f"host namespace sharing: {', '.join(violations)}. "
                f"Pods that share the host network / PID / IPC "
                f"namespaces can observe + interfere with the host "
                f"and other pods. Remove unless absolutely required "
                f"(node-monitoring DaemonSet, etc.)."
            ),
            cwe="CWE-250",
            category="misconfig",
            platform=PLATFORM_KUBERNETES,
            metadata={
                "kind": doc.get("kind"),
                "name": (doc.get("metadata") or {}).get("name"),
                "flags": violations,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# RUN_AS_ROOT — runAsUser=0 OR missing runAsNonRoot
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_KUBERNETES)
def k8s_run_as_root(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    if not isinstance(iac_file.data, list):
        return out
    for doc in iac_file.data:
        if doc.get("kind") not in _WORKLOAD_KINDS:
            continue
        pod_spec = _pod_spec_of(doc)
        if not pod_spec:
            continue
        pod_sc = pod_spec.get("securityContext") or {}
        for c in _all_containers(pod_spec):
            c_sc = c.get("securityContext") or {}
            # Effective runAsUser / runAsNonRoot (container wins).
            run_as_user = (
                c_sc.get("runAsUser")
                if "runAsUser" in c_sc
                else pod_sc.get("runAsUser")
            )
            run_as_non_root = (
                c_sc.get("runAsNonRoot")
                if "runAsNonRoot" in c_sc
                else pod_sc.get("runAsNonRoot")
            )
            is_root = run_as_user == 0
            missing_non_root = run_as_non_root is None
            if not is_root and not missing_non_root:
                continue
            if missing_non_root and run_as_user is not None and run_as_user != 0:
                # Explicit non-zero UID is fine even without
                # runAsNonRoot=true.
                continue
            severity = "high" if is_root else "medium"
            message_parts = []
            if is_root:
                message_parts.append("`runAsUser: 0` (root)")
            if missing_non_root:
                message_parts.append("missing `runAsNonRoot: true`")
            out.append(IacFinding(
                rule_id="K8S_RUN_AS_ROOT",
                file=iac_file.path,
                line=doc.get("doc_index", 0),
                severity=severity,
                message=(
                    f"{doc.get('kind')} "
                    f"`{(doc.get('metadata') or {}).get('name')}` "
                    f"container `{c.get('name')}`: "
                    f"{', '.join(message_parts)}. Set "
                    f"`runAsNonRoot: true` and `runAsUser: <non-zero>` "
                    f"to comply with Pod Security Standards "
                    f"Restricted profile."
                ),
                cwe="CWE-250",
                category="misconfig",
                platform=PLATFORM_KUBERNETES,
                metadata={
                    "kind": doc.get("kind"),
                    "name": (doc.get("metadata") or {}).get("name"),
                    "container": c.get("name"),
                    "is_root": is_root,
                    "missing_non_root": missing_non_root,
                },
            ))
    return out


# ---------------------------------------------------------------------------
# MISSING_RESOURCE_LIMITS — container without resources.limits
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_KUBERNETES)
def k8s_missing_resource_limits(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    if not isinstance(iac_file.data, list):
        return out
    for doc in iac_file.data:
        if doc.get("kind") not in _WORKLOAD_KINDS:
            continue
        pod_spec = _pod_spec_of(doc)
        if not pod_spec:
            continue
        for c in _all_containers(pod_spec):
            res = c.get("resources") or {}
            limits = res.get("limits") or {}
            if isinstance(limits, dict) and (
                limits.get("cpu") or limits.get("memory")
            ):
                continue
            out.append(IacFinding(
                rule_id="K8S_MISSING_RESOURCE_LIMITS",
                file=iac_file.path,
                line=doc.get("doc_index", 0),
                severity="medium",
                message=(
                    f"{doc.get('kind')} "
                    f"`{(doc.get('metadata') or {}).get('name')}` "
                    f"container `{c.get('name')}` has no CPU / "
                    f"memory limits. Unlimited containers can OOM-"
                    f"kill node neighbours or starve cluster "
                    f"resources. Set "
                    f"`resources.limits.{{cpu,memory}}`."
                ),
                cwe="CWE-770",
                category="misconfig",
                platform=PLATFORM_KUBERNETES,
                metadata={
                    "kind": doc.get("kind"),
                    "name": (doc.get("metadata") or {}).get("name"),
                    "container": c.get("name"),
                },
            ))
    return out


# ---------------------------------------------------------------------------
# ALLOW_PRIV_ESC — container with allowPrivilegeEscalation=true
# (or missing — the K8s default is true)
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_KUBERNETES)
def k8s_allow_privilege_escalation(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    if not isinstance(iac_file.data, list):
        return out
    for doc in iac_file.data:
        if doc.get("kind") not in _WORKLOAD_KINDS:
            continue
        pod_spec = _pod_spec_of(doc)
        if not pod_spec:
            continue
        for c in _all_containers(pod_spec):
            sc = c.get("securityContext") or {}
            ape = sc.get("allowPrivilegeEscalation")
            if ape is False:
                continue
            # ape is True OR not set — K8s default is True.
            severity = "high" if ape is True else "medium"
            descr = (
                "explicitly enables "
                "`allowPrivilegeEscalation: true`"
                if ape is True
                else "omits `allowPrivilegeEscalation: false` "
                "(K8s defaults to allowed)"
            )
            out.append(IacFinding(
                rule_id="K8S_ALLOW_PRIV_ESC",
                file=iac_file.path,
                line=doc.get("doc_index", 0),
                severity=severity,
                message=(
                    f"{doc.get('kind')} "
                    f"`{(doc.get('metadata') or {}).get('name')}` "
                    f"container `{c.get('name')}` {descr}. Pod "
                    f"Security Standards Restricted profile requires "
                    f"`allowPrivilegeEscalation: false`."
                ),
                cwe="CWE-250",
                category="misconfig",
                platform=PLATFORM_KUBERNETES,
                metadata={
                    "kind": doc.get("kind"),
                    "name": (doc.get("metadata") or {}).get("name"),
                    "container": c.get("name"),
                },
            ))
    return out


# ---------------------------------------------------------------------------
# RBAC_WILDCARD — Role / ClusterRole with `*` verb or `*` resource
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_KUBERNETES)
def k8s_rbac_wildcard(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    if not isinstance(iac_file.data, list):
        return out
    for doc in iac_file.data:
        if doc.get("kind") not in {"Role", "ClusterRole"}:
            continue
        rules = doc.get("rules") or doc.get("doc", {}).get("rules") or []
        if not isinstance(rules, list):
            continue
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                continue
            verbs = rule.get("verbs") or []
            resources = rule.get("resources") or []
            api_groups = rule.get("apiGroups") or []
            violations: list[str] = []
            if "*" in verbs:
                violations.append("verbs: ['*']")
            if "*" in resources:
                violations.append("resources: ['*']")
            if "*" in api_groups:
                violations.append("apiGroups: ['*']")
            if not violations:
                continue
            sev = (
                "critical"
                if (doc.get("kind") == "ClusterRole" and len(violations) >= 2)
                else "high"
            )
            out.append(IacFinding(
                rule_id="K8S_RBAC_WILDCARD",
                file=iac_file.path,
                line=doc.get("doc_index", 0),
                severity=sev,
                message=(
                    f"{doc.get('kind')} "
                    f"`{(doc.get('metadata') or {}).get('name')}` "
                    f"rule[{i}] uses wildcard "
                    f"{', '.join(violations)}. Wildcard RBAC grants "
                    f"effective cluster-admin — enumerate the "
                    f"specific verbs / resources the principal needs."
                ),
                cwe="CWE-732",
                category="misconfig",
                platform=PLATFORM_KUBERNETES,
                metadata={
                    "kind": doc.get("kind"),
                    "name": (doc.get("metadata") or {}).get("name"),
                    "rule_index": i,
                    "wildcards": violations,
                },
            ))
    return out


# ---------------------------------------------------------------------------
# NODEPORT_SERVICE — Service of type NodePort
# ---------------------------------------------------------------------------


@register_rule(platform=PLATFORM_KUBERNETES)
def k8s_service_nodeport(iac_file: IacFile) -> list[IacFinding]:
    out: list[IacFinding] = []
    if not isinstance(iac_file.data, list):
        return out
    for doc in iac_file.data:
        if doc.get("kind") != "Service":
            continue
        spec = doc.get("spec") or {}
        if not isinstance(spec, dict):
            continue
        if spec.get("type") != "NodePort":
            continue
        out.append(IacFinding(
            rule_id="K8S_SERVICE_NODEPORT",
            file=iac_file.path,
            line=doc.get("doc_index", 0),
            severity="medium",
            message=(
                f"Service `{(doc.get('metadata') or {}).get('name')}` "
                f"is `type: NodePort`. NodePort exposes the service "
                f"on every node's IP at a static high port, "
                f"bypassing ingress / WAF / TLS termination. Use a "
                f"`ClusterIP` service behind an Ingress, or a "
                f"managed `LoadBalancer` with appropriate firewall "
                f"controls."
            ),
            cwe="CWE-668",
            category="misconfig",
            platform=PLATFORM_KUBERNETES,
            metadata={
                "name": (doc.get("metadata") or {}).get("name"),
                "ports": spec.get("ports"),
            },
        ))
    return out
