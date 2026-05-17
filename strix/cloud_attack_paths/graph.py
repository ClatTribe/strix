"""CloudGraph — typed nodes + edges over a cloud account.

Pure Python, no external graph library. The graph is small (cloud
accounts have hundreds or low thousands of relevant entities, not
millions) so dict-of-sets indexing is fast enough; networkx would
add a dep without a real benefit.

Design choices:

  * **Node identity = ARN-or-equivalent string.** AWS ARNs are
    globally unique. Azure resource IDs and GCP resource names
    work the same way. We don't try to enforce ARN syntax — any
    stable string identifier works.

  * **Edges are typed strings**, not enums, so wrappers can add
    custom edge types without forking. The built-in set covers
    the patterns we ship; new patterns can introduce new edges
    without touching this module.

  * **Indexed lookup**: outgoing(node, edge_kind), incoming(...),
    neighbors_of_kind(...). Most attack-path patterns are local
    traversal from a "seed" node (a public-exposed resource);
    indexed lookup makes the traversal O(degree) instead of
    O(edges).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Edge-type constants (canonical strings)
# ---------------------------------------------------------------------------

# Resource is reachable from the public internet.
EDGE_EXPOSED_TO_INTERNET = "exposed_to_internet"

# IAM identity (role / instance profile) is attached to a compute
# resource (EC2 instance, Lambda function, ECS task, K8s pod, ...).
EDGE_ATTACHED_TO = "attached_to"

# IAM principal A can assume IAM role B (via trust policy).
EDGE_CAN_ASSUME = "can_assume"

# Policy grants access TO a resource — derived from policy statement
# allowed actions + resources. Best-effort parse.
EDGE_GRANTS_ACCESS_TO = "grants_access_to"

# Identity has policy attached. Distinct from grants_access_to
# (which is the per-resource derived edge).
EDGE_HAS_POLICY = "has_policy"

# Resource potentially contains credentials / secrets / state files
# that grant further access. Marked when a finding suggests data
# residing in the resource is sensitive. Inferred from CSPM
# findings + heuristics.
EDGE_MAY_CONTAIN_CREDENTIALS = "may_contain_credentials"


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------


@dataclass
class CloudResource:
    """A cloud resource (S3 bucket, EC2 instance, RDS, Lambda, ...).

    `kind` is a short service-qualified label like `s3_bucket`,
    `rds_db_instance`, `lambda_function`, `ec2_security_group`.
    The pattern matchers read this; keep new ingester values
    consistent or extend the patterns.
    """
    arn: str
    kind: str
    region: str | None = None
    account_id: str | None = None
    # Resource holds data classified as sensitive (PII, credentials,
    # config). Derived from naming heuristics + service type.
    is_data_store: bool = False
    # Resource is exposed to the public internet. Mirrored as an
    # outgoing `exposed_to_internet` edge for graph queries; also
    # available as a fast attribute for filters.
    is_public: bool = False
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def node_key(self) -> str:
        return self.arn

    def to_dict(self) -> dict:
        return {
            "node_type": "cloud_resource",
            "arn": self.arn,
            "kind": self.kind,
            "region": self.region,
            "account_id": self.account_id,
            "is_data_store": self.is_data_store,
            "is_public": self.is_public,
            "attributes": dict(self.attributes),
        }


@dataclass
class CloudIdentity:
    """An IAM principal — user, role, service account, group."""
    arn: str
    kind: str   # iam_user | iam_role | iam_group | service_account | aws_root
    name: str | None = None
    # Trust-policy principals (for roles): who can assume this role.
    # List of canonical principal strings (e.g. `lambda.amazonaws.com`,
    # arn:aws:iam::123:root, *).
    trust_principals: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def node_key(self) -> str:
        return self.arn

    @property
    def is_world_assumable(self) -> bool:
        """True when the trust policy lets *anyone* assume this role
        (`Principal: *` or wildcard external account). Critical
        attack-path seed."""
        return any(
            p.strip() == "*" or p.strip().lower() == "principal: *"
            for p in self.trust_principals
        )

    def to_dict(self) -> dict:
        return {
            "node_type": "cloud_identity",
            "arn": self.arn,
            "kind": self.kind,
            "name": self.name,
            "trust_principals": list(self.trust_principals),
            "attributes": dict(self.attributes),
        }


@dataclass
class CloudPolicy:
    """An IAM / resource-attached policy.

    `statements` is the parsed list of policy statements:
    `[{effect, actions: [...], resources: [...], conditions: ...}, ...]`.
    Pattern matchers walk these to find wildcard / overly-broad
    grants without re-parsing the raw policy JSON each time.
    """
    arn: str
    kind: str   # iam_managed_policy | iam_inline_policy | bucket_policy | kms_key_policy
    statements: list[dict[str, Any]] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def node_key(self) -> str:
        return self.arn

    def has_wildcard_admin(self) -> bool:
        """`Effect: Allow + Action: * + Resource: *` in any
        statement — the admin-equivalent anti-pattern."""
        for s in self.statements:
            if (s.get("effect") or "").lower() != "allow":
                continue
            actions = _as_list(s.get("actions"))
            resources = _as_list(s.get("resources"))
            if "*" in actions and "*" in resources:
                return True
        return False

    def to_dict(self) -> dict:
        return {
            "node_type": "cloud_policy",
            "arn": self.arn,
            "kind": self.kind,
            "statements": list(self.statements),
            "attributes": dict(self.attributes),
        }


def _as_list(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


# ---------------------------------------------------------------------------
# Edge dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CloudEdge:
    """A directed typed edge `from_key --kind--> to_key`. `to_key`
    is None for self-relationships like `exposed_to_internet`."""
    from_key: str
    kind: str
    to_key: str | None = None
    attributes: tuple[tuple[str, Any], ...] = ()

    def to_dict(self) -> dict:
        return {
            "from": self.from_key,
            "kind": self.kind,
            "to": self.to_key,
            "attributes": dict(self.attributes),
        }


# ---------------------------------------------------------------------------
# CloudGraph
# ---------------------------------------------------------------------------


# Union of node types — duck-typed in helpers since each has
# `.node_key` and `.to_dict()`.
NodeT = CloudResource | CloudIdentity | CloudPolicy


class CloudGraph:
    """Indexed graph of a cloud account.

    Mutation API: `add_node` / `add_edge`. Query API:
    `outgoing` / `incoming` / `neighbors_of_kind` / `nodes_by_kind`.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, NodeT] = {}
        # Indexed adjacency: from_key → kind → set(to_key | None).
        self._out: dict[str, dict[str, set[str | None]]] = {}
        self._in: dict[str | None, dict[str, set[str]]] = {}
        self._edges: list[CloudEdge] = []

    # ----- mutation -----

    def add_node(self, node: NodeT) -> NodeT:
        """Add or replace a node. Returns the node currently in the
        graph (caller's `node` if it was new, the existing one
        otherwise) so callers can chain attribute merges."""
        key = node.node_key
        if key in self._nodes:
            return self._nodes[key]
        self._nodes[key] = node
        return node

    def add_edge(
        self, from_key: str, kind: str,
        to_key: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> CloudEdge:
        edge = CloudEdge(
            from_key=from_key, kind=kind, to_key=to_key,
            attributes=tuple((attributes or {}).items()),
        )
        self._edges.append(edge)
        self._out.setdefault(from_key, {}).setdefault(kind, set()).add(to_key)
        self._in.setdefault(to_key, {}).setdefault(kind, set()).add(from_key)
        return edge

    # ----- query -----

    def has_node(self, key: str) -> bool:
        return key in self._nodes

    def get_node(self, key: str) -> NodeT | None:
        return self._nodes.get(key)

    def nodes(self) -> Iterable[NodeT]:
        return self._nodes.values()

    def edges(self) -> list[CloudEdge]:
        return list(self._edges)

    def nodes_by_type(self, node_type: type) -> list[NodeT]:
        return [n for n in self._nodes.values() if isinstance(n, node_type)]

    def resources_of_kind(self, kind: str) -> list[CloudResource]:
        return [
            n for n in self._nodes.values()
            if isinstance(n, CloudResource) and n.kind == kind
        ]

    def outgoing(self, from_key: str, kind: str) -> set[str | None]:
        return set(self._out.get(from_key, {}).get(kind, set()))

    def incoming(self, to_key: str | None, kind: str) -> set[str]:
        return set(self._in.get(to_key, {}).get(kind, set()))

    def has_edge(
        self, from_key: str, kind: str, to_key: str | None,
    ) -> bool:
        return to_key in self._out.get(from_key, {}).get(kind, set())

    def is_internet_exposed(self, key: str) -> bool:
        """True when the resource has an outgoing
        `exposed_to_internet` edge OR its `is_public` attribute is
        true (fast path)."""
        node = self._nodes.get(key)
        if isinstance(node, CloudResource) and node.is_public:
            return True
        return None in self._out.get(key, {}).get(EDGE_EXPOSED_TO_INTERNET, set())

    def public_resources(self) -> list[CloudResource]:
        """All resources flagged as internet-exposed."""
        return [
            n for n in self._nodes.values()
            if isinstance(n, CloudResource) and self.is_internet_exposed(n.node_key)
        ]

    # ----- serialisation -----

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "summary": {
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
                "resource_count": sum(
                    1 for n in self._nodes.values()
                    if isinstance(n, CloudResource)
                ),
                "identity_count": sum(
                    1 for n in self._nodes.values()
                    if isinstance(n, CloudIdentity)
                ),
                "policy_count": sum(
                    1 for n in self._nodes.values()
                    if isinstance(n, CloudPolicy)
                ),
            },
        }
