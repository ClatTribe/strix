"""Tests for Kubernetes parser + rule set (Phase 11.4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from strix.iac.parsers.base import PLATFORM_KUBERNETES
from strix.iac.parsers.kubernetes import (
    _is_kubernetes_doc,
    _parse_kubernetes_yaml,
    parse_kubernetes,
)
from strix.iac.rules import run_rules
from strix.iac.rules.kubernetes_rules import (
    k8s_allow_privilege_escalation,
    k8s_host_namespace_sharing,
    k8s_missing_resource_limits,
    k8s_privileged_container,
    k8s_rbac_wildcard,
    k8s_run_as_root,
    k8s_service_nodeport,
)


def _tmp_yaml(tmp_path: Path, content: str, name: str = "x.yaml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Parser — _is_kubernetes_doc + parse_kubernetes
# ---------------------------------------------------------------------------


def test_is_kubernetes_doc_requires_apiversion_and_kind() -> None:
    assert _is_kubernetes_doc({"apiVersion": "v1", "kind": "Pod"}) is True
    assert _is_kubernetes_doc({"apiVersion": "v1"}) is False
    assert _is_kubernetes_doc({"kind": "Pod"}) is False
    assert _is_kubernetes_doc({}) is False
    assert _is_kubernetes_doc("string") is False


def test_parser_extracts_single_doc() -> None:
    docs = _parse_kubernetes_yaml(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: x"
    )
    assert len(docs) == 1
    assert docs[0]["kind"] == "Pod"


def test_parser_extracts_multi_doc() -> None:
    docs = _parse_kubernetes_yaml(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: b"
    )
    assert len(docs) == 2
    assert docs[0]["kind"] == "Pod"
    assert docs[1]["kind"] == "Service"


def test_parser_skips_non_k8s_docs_in_multi_yaml() -> None:
    """A YAML file with one K8s doc and one arbitrary config doc
    — keep only the K8s one."""
    docs = _parse_kubernetes_yaml(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n"
        "---\n"
        "random_config:\n  key: value"
    )
    assert len(docs) == 1
    assert docs[0]["kind"] == "Pod"


def test_parse_kubernetes_skips_helm_template(tmp_path: Path) -> None:
    """File with `{{ .Values.X }}` is a Helm template, not K8s."""
    p = _tmp_yaml(tmp_path, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Values.name }}")
    assert parse_kubernetes(p) is None


def test_parse_kubernetes_skips_non_k8s_yaml(tmp_path: Path) -> None:
    """Arbitrary YAML config — should NOT be picked up as K8s."""
    p = _tmp_yaml(tmp_path, "version: 1\nsettings:\n  debug: true")
    assert parse_kubernetes(p) is None


# ---------------------------------------------------------------------------
# Rules — Pod Security
# ---------------------------------------------------------------------------


_PRIVILEGED_POD = """
apiVersion: v1
kind: Pod
metadata:
  name: bad
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      privileged: true
"""


def test_privileged_container_detected(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, _PRIVILEGED_POD))
    out = k8s_privileged_container(iac)
    assert len(out) == 1
    assert out[0].severity == "critical"


def test_non_privileged_not_flagged(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: ok
spec:
  containers:
  - name: app
    image: nginx
"""))
    assert k8s_privileged_container(iac) == []


def test_host_network_detected(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: x
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: app
    image: nginx
"""))
    out = k8s_host_namespace_sharing(iac)
    assert len(out) == 1
    assert "hostNetwork" in out[0].metadata["flags"]
    assert "hostPID" in out[0].metadata["flags"]


def test_run_as_root_explicit_detected(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: x
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsUser: 0
"""))
    out = k8s_run_as_root(iac)
    assert len(out) == 1
    assert out[0].severity == "high"
    assert out[0].metadata["is_root"] is True


def test_missing_run_as_non_root_detected(tmp_path: Path) -> None:
    """Container without runAsUser AND without runAsNonRoot —
    K8s default allows root. Flag as medium."""
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: x
spec:
  containers:
  - name: app
    image: nginx
"""))
    out = k8s_run_as_root(iac)
    assert len(out) == 1
    assert out[0].severity == "medium"


def test_explicit_non_zero_uid_not_flagged(tmp_path: Path) -> None:
    """`runAsUser: 1000` is fine even without `runAsNonRoot: true`."""
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: x
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      runAsUser: 1000
"""))
    assert k8s_run_as_root(iac) == []


def test_resource_limits_missing_detected(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: x
spec:
  containers:
  - name: app
    image: nginx
"""))
    out = k8s_missing_resource_limits(iac)
    assert len(out) == 1


def test_resource_limits_present_not_flagged(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: x
spec:
  containers:
  - name: app
    image: nginx
    resources:
      limits:
        cpu: 500m
        memory: 256Mi
"""))
    assert k8s_missing_resource_limits(iac) == []


def test_allow_priv_escalation_explicit_true_high(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: x
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: true
"""))
    out = k8s_allow_privilege_escalation(iac)
    assert len(out) == 1
    assert out[0].severity == "high"


def test_allow_priv_escalation_explicit_false_ok(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Pod
metadata:
  name: x
spec:
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
"""))
    assert k8s_allow_privilege_escalation(iac) == []


def test_rbac_clusterrole_wildcard_critical(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
"""))
    out = k8s_rbac_wildcard(iac)
    assert len(out) == 1
    assert out[0].severity == "critical"


def test_rbac_role_narrow_wildcard_high(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["*"]
"""))
    out = k8s_rbac_wildcard(iac)
    assert len(out) == 1
    assert out[0].severity == "high"


def test_rbac_specific_not_flagged(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
"""))
    assert k8s_rbac_wildcard(iac) == []


def test_nodeport_service_detected(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: NodePort
  ports:
  - port: 80
    nodePort: 30080
"""))
    out = k8s_service_nodeport(iac)
    assert len(out) == 1
    assert out[0].severity == "medium"


def test_clusterip_service_not_flagged(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  type: ClusterIP
  ports:
  - port: 80
"""))
    assert k8s_service_nodeport(iac) == []


# ---------------------------------------------------------------------------
# Deployment podSpec extraction
# ---------------------------------------------------------------------------


def test_deployment_pod_spec_extracted(tmp_path: Path) -> None:
    """Deployment.spec.template.spec is the podSpec. Privileged-
    container check needs to find it there, not directly under
    spec."""
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
"""))
    out = k8s_privileged_container(iac)
    assert len(out) == 1


def test_cronjob_pod_spec_extracted(tmp_path: Path) -> None:
    """CronJob.spec.jobTemplate.spec.template.spec is the
    podSpec. Privileged check should still fire."""
    iac = parse_kubernetes(_tmp_yaml(tmp_path, """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: job
spec:
  schedule: "0 0 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: app
            image: nginx
            securityContext:
              privileged: true
"""))
    out = k8s_privileged_container(iac)
    assert len(out) == 1


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------


def test_run_rules_dispatches_to_kubernetes_rules(tmp_path: Path) -> None:
    iac = parse_kubernetes(_tmp_yaml(tmp_path, _PRIVILEGED_POD))
    findings = run_rules(iac)
    assert any(f.rule_id == "K8S_PRIVILEGED_CONTAINER" for f in findings)
    for f in findings:
        assert f.platform == PLATFORM_KUBERNETES
