"""Same-scan IAM permissions-document identity, coverage and provenance; no AWS calls."""

import hashlib
import json
from collections.abc import Mapping

from app.assessment.evidence_graph import source_provenance_key
from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.execution import RequiredSource, ResourceFamily
from app.assessment.iam_key_evidence import _ids
from app.assessment.relationships import RelationshipType
from app.schemas.resource import ResourceScope

MANAGED_TYPES = ("iam_customer_managed_policy", "iam_aws_managed_policy")
POLICY_FAMILIES = tuple(
    ResourceFamily(service="iam", resource_type=kind)
    for kind in (*MANAGED_TYPES, "iam_managed_policy_version", "iam_inline_policy")
)


def policy_source(collector, kind, api, *, global_scope=False, admitted=False):
    return RequiredSource(
        collector=f"iam.{collector}",
        evidence_kind=f"iam.{kind}",
        source_api=f"iam:{api}",
        subject="global_account" if global_scope else "target",
        contract_version="1.0.0",
        completeness_fields=() if admitted else ("complete",),
        completion="admitted_resource_v1" if admitted else "payload_flags_v1",
    )


POLICY_DISCOVERY = tuple(
    policy_source(collector, kind, api, global_scope=True)
    for collector, kind, api in (
        ("users", "users.discovery", "ListUsers"),
        ("groups", "groups.discovery", "ListGroups"),
        ("roles", "roles.discovery", "ListRoles"),
        ("policies", "customer-managed-policies.discovery", "ListPolicies"),
    )
)


def _require(condition):
    if not condition:
        raise IncompleteAssessmentEvidence("required IAM policy evidence is inconsistent")


def _canonical(value):
    # Graph payloads freeze JSON arrays to tuples and objects to immutable mappings.
    def plain(item):
        if isinstance(item, Mapping):
            return {key: plain(child) for key, child in item.items()}
        if isinstance(item, list | tuple):
            return [plain(child) for child in item]
        return item

    return json.dumps(plain(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def policy_targets(snapshot):
    """One version/inline observation per document; missing versions retain a parent gap target."""
    documents = [
        r
        for r in snapshot.resources
        if r.service == "iam"
        and r.resource_type
        in (
            "iam_managed_policy_version",
            "iam_inline_policy",
        )
    ]
    versions = {
        r.aws_resource_id for r in documents if r.resource_type == "iam_managed_policy_version"
    }
    for resource in snapshot.resources:
        if resource.service != "iam" or resource.resource_type not in MANAGED_TYPES:
            continue
        expected = _canonical(
            {
                "policy_arn": resource.aws_resource_id,
                "version_id": resource.configuration.get("default_version_id"),
            }
        )
        if expected not in versions:
            documents.append(resource)
    _require(len({r.identity for r in documents}) == len(documents))
    return tuple(sorted(documents, key=lambda r: r.identity))


class _PolicyProof:
    def __init__(self, reader, citations=None, edge_ids=None):
        self.reader = reader
        self.citations = dict(citations or {})
        self.edge_ids = set(edge_ids or ())

    def source(self, required, target):
        outcome, payload, citation = self.reader.resolve_source(required, target)
        self.citations[str(outcome.source_outcome_id)] = citation
        if required.subject == "target":
            _require(
                payload.get("resource_id") == target.aws_resource_id
                and payload.get("resource_type") == target.resource_type
                and payload.get("account_id") == target.account_id
            )
        else:
            _require(payload.get("account_id") == self.reader.snapshot.account_id)
        return outcome, payload

    def edges(self, owner, kind, expected_ids, outcome):
        edges = self.reader._edges.get((self.reader._target_id(owner), kind), ())
        _require(
            len(edges) == len(expected_ids)
            and {e.target.aws_resource_id for e in edges} == expected_ids
        )
        result = []
        for edge in edges:
            _require(edge.is_resolved)
            endpoint = self.reader.resources.get(edge.target.resource_snapshot_id)
            provenance = self.reader._provenance.get(source_provenance_key(edge.provenance), ())
            _require(
                endpoint is not None
                and len(provenance) == 1
                and provenance[0].source_outcome_id == outcome.source_outcome_id
            )
            self.edge_ids.add(str(edge.observation_id))
            result.append(endpoint)
        return result


def _coverage(reader):
    """Prove the finite policy population and all usage contexts once per reader."""
    if reader._iam_policy_coverage is not None:
        return reader._iam_policy_coverage
    proof = _PolicyProof(reader)
    resources = reader.snapshot.resources
    by_type = {}
    for resource in resources:
        if resource.service == "iam":
            by_type.setdefault(resource.resource_type, []).append(resource)
    local_ids = set()
    for required, kind in zip(
        POLICY_DISCOVERY,
        (
            "iam_user",
            "iam_group",
            "iam_role",
            "iam_customer_managed_policy",
        ),
        strict=True,
    ):
        _, payload = proof.source(required, resources[0] if resources else None)
        ids = _ids(payload, "resource_ids", "resource_count")
        observed = {r.aws_resource_id for r in by_type.get(kind, ())}
        _require(ids == observed)
        if kind == "iam_customer_managed_policy":
            local_ids = ids
    usages = {}
    inline_ids = set()
    managed_ids = set(local_ids)
    membership_edges = {}
    for edge in reader.graph.relationships:
        if edge.relationship_type is RelationshipType.MEMBER_OF_GROUP:
            membership_edges.setdefault(edge.target.resource_snapshot_id, []).append(edge)
    for owner_type, family, singular, suffix in (
        ("iam_user", "users", "user", "User"),
        ("iam_group", "groups", "group", "Group"),
        ("iam_role", "roles", "role", "Role"),
    ):
        for owner in by_type.get(owner_type, ()):
            _require(
                owner.account_id == reader.snapshot.account_id
                and owner.scope is ResourceScope.GLOBAL
            )
            proof.source(policy_source(family, singular, f"List{suffix}s", admitted=True), owner)
            if singular == "group":
                outcome, members = proof.source(
                    policy_source("groups", "group.members", "GetGroup"), owner
                )
                ids = _ids(members, "member_user_ids", "member_count")
                edges = membership_edges.get(reader._target_id(owner), ())
                _require(
                    len(edges) == len(ids) and {e.source.aws_resource_id for e in edges} == ids
                )
                for edge in edges:
                    provenance = reader._provenance.get(source_provenance_key(edge.provenance), ())
                    _require(
                        edge.is_resolved
                        and len(provenance) == 1
                        and provenance[0].source_outcome_id == outcome.source_outcome_id
                    )
                    proof.edge_ids.add(str(edge.observation_id))
            attached_outcome, attached = proof.source(
                policy_source(
                    family,
                    f"{singular}.attached-managed-policies",
                    f"ListAttached{suffix}Policies",
                ),
                owner,
            )
            arns = _ids(attached, "policy_arns", "policy_count")
            attached_policies = proof.edges(
                owner, RelationshipType.ATTACHED_MANAGED_POLICY, arns, attached_outcome
            )
            contexts = [(p, "attachment") for p in attached_policies]
            if singular != "group":
                outcome, profile = proof.source(
                    policy_source(
                        family,
                        f"{singular}.profile",
                        f"Get{suffix}",
                    ),
                    owner,
                )
                _require("permissions_boundary_arn" in profile)
                boundary = profile["permissions_boundary_arn"]
                _require(boundary is None or isinstance(boundary, str) and bool(boundary))
                _require(owner.configuration.get("permissions_boundary_arn") == boundary)
                policies = proof.edges(
                    owner,
                    RelationshipType.PERMISSIONS_BOUNDARY,
                    {boundary} if boundary else set(),
                    outcome,
                )
                contexts.extend((p, "permissions_boundary") for p in policies)
            for policy, context in contexts:
                _require(policy.resource_type in MANAGED_TYPES)
                managed_ids.add(policy.aws_resource_id)
                usages.setdefault(str(reader._target_id(policy)), []).append(
                    {
                        "owner_snapshot_id": str(reader._target_id(owner)),
                        "usage": context,
                    }
                )
            outcome, enumeration = proof.source(
                policy_source(
                    family,
                    f"{singular}.inline-policies",
                    f"List{suffix}Policies",
                ),
                owner,
            )
            names = _ids(enumeration, "policy_names", "policy_count")
            ids = {
                _canonical(
                    {
                        "owner_account_id": owner.account_id,
                        "owner_resource_id": owner.aws_resource_id,
                        "owner_resource_type": owner.resource_type,
                        "policy_name": name,
                    }
                )
                for name in names
            }
            for inline in proof.edges(owner, RelationshipType.ATTACHED_INLINE_POLICY, ids, outcome):
                config = inline.configuration
                _require(
                    inline.resource_type == "iam_inline_policy"
                    and inline.account_id == owner.account_id
                    and config.get("owner_resource_type") == owner.resource_type
                    and config.get("owner_resource_id") == owner.aws_resource_id
                    and config.get("owner_name") == owner.name
                    and isinstance(config.get("policy_name"), str)
                    and config.get("policy_name") in names
                )
                inline_ids.add(inline.aws_resource_id)
                usages.setdefault(str(reader._target_id(inline)), []).append(
                    {
                        "owner_snapshot_id": str(reader._target_id(owner)),
                        "usage": "inline",
                    }
                )
    _require(managed_ids == {r.aws_resource_id for t in MANAGED_TYPES for r in by_type.get(t, ())})
    _require(inline_ids == {r.aws_resource_id for r in by_type.get("iam_inline_policy", ())})
    for kind in MANAGED_TYPES:
        for policy in by_type.get(kind, ()):
            parts = policy.aws_resource_id.split(":", 5)
            _require(
                len(parts) == 6
                and parts[0] == "arn"
                and parts[2:4] == ["iam", ""]
                and parts[4] == policy.account_id
                and parts[5].startswith("policy/")
                and policy.scope is ResourceScope.GLOBAL
                and policy.account_id
                == ("aws" if kind == "iam_aws_managed_policy" else reader.snapshot.account_id)
            )
    reader._iam_policy_coverage = (proof.citations, proof.edge_ids, usages)
    return reader._iam_policy_coverage


def _statements(document):
    """Validate the accepted bounded syntax before evaluating any literal pattern."""
    _require(isinstance(document, Mapping))
    statements = document.get("Statement")
    if isinstance(statements, Mapping):
        statements = (statements,)
    _require(isinstance(statements, list | tuple) and bool(statements))
    for statement in statements:
        _require(isinstance(statement, Mapping))
        _require(statement.get("Effect") in ("Allow", "Deny"))
        _require(
            sum(key in statement for key in ("Action", "NotAction")) == 1
            and sum(key in statement for key in ("Resource", "NotResource")) == 1
            and "Principal" not in statement
            and "NotPrincipal" not in statement
        )
        for field in ("Action", "NotAction", "Resource", "NotResource"):
            if field in statement:
                values = statement[field]
                values = (values,) if isinstance(values, str) else values
                _require(
                    isinstance(values, list | tuple)
                    and bool(values)
                    and all(isinstance(v, str) and bool(v.strip()) for v in values)
                )
        if "Condition" in statement:
            _require(isinstance(statement["Condition"], Mapping))
    return statements


def iam_policy_proof(reader, target):
    citations, edge_ids, usages = _coverage(reader)
    proof = _PolicyProof(reader, citations, edge_ids)
    fact = None
    if target.resource_type == "aws_account":
        _require(not policy_targets(reader.snapshot))
    else:
        target = reader.resources.get(reader._target_id(target))
        _require(target is not None and target.scope is ResourceScope.GLOBAL)
        config = target.configuration
        if target.resource_type == "iam_managed_policy_version":
            arn, version = config.get("policy_arn"), config.get("version_id")
            _require(isinstance(arn, str) and isinstance(version, str) and bool(version))
            parents = [
                r
                for r in reader.snapshot.resources
                if r.service == "iam"
                and r.resource_type in MANAGED_TYPES
                and r.aws_resource_id == arn
            ]
            _require(len(parents) == 1)
            parent = parents[0]
            outcome, metadata = proof.source(
                policy_source(
                    "policies",
                    "managed-policy.metadata",
                    "GetPolicy",
                ),
                parent,
            )
            _require(
                metadata.get("metadata_complete") is True
                and parent.configuration.get("metadata_complete") is True
                and metadata.get("policy_arn") == arn
                and metadata.get("default_version_id") == version
                and parent.configuration.get("default_version_id") == version
                and config.get("is_default_version") is True
                and target.account_id == parent.account_id
                and target.aws_resource_id == _canonical({"policy_arn": arn, "version_id": version})
            )
            proof.edges(
                parent, RelationshipType.SELECTS_DEFAULT_VERSION, {target.aws_resource_id}, outcome
            )
            _, payload = proof.source(
                policy_source(
                    "policies",
                    "managed-policy-version.document",
                    "GetPolicyVersion",
                ),
                target,
            )
            _require(payload.get("policy_arn") == arn and payload.get("version_id") == version)
            contexts = usages.get(str(reader._target_id(parent)), [])
            fact = {"policy_arn": arn, "version_id": version}
        elif target.resource_type == "iam_inline_policy":
            contexts = usages.get(str(reader._target_id(target)), [])
            _require(len(contexts) == 1)
            owner_type = config.get("owner_resource_type")
            _require(owner_type in ("iam_user", "iam_group", "iam_role"))
            singular = owner_type.removeprefix("iam_")
            _, payload = proof.source(
                policy_source(
                    f"{singular}s",
                    "inline-policy.document",
                    f"Get{singular.title()}Policy",
                ),
                target,
            )
            _require(payload.get("policy_name") == config.get("policy_name"))
            fact = {
                "owner_snapshot_id": contexts[0]["owner_snapshot_id"],
                "policy_name": config["policy_name"],
            }
        else:
            raise IncompleteAssessmentEvidence("managed policy default version is unavailable")
        document = payload.get("document")
        _statements(document)
        digest = hashlib.sha256(_canonical(document).encode("utf-8")).hexdigest()
        _require(
            config.get("document_complete") is True
            and payload.get("document_sha256") == digest
            and config.get("document_sha256") == digest
            and _canonical(config.get("document")) == _canonical(document)
        )
        fact.update(
            resource_snapshot_id=str(reader._target_id(target)),
            document_sha256=digest,
            usage_contexts=sorted(contexts, key=lambda c: (c["owner_snapshot_id"], c["usage"])),
        )
    return {
        "schema_version": "1.2.0",
        "scan_id": str(reader.snapshot.scan_id),
        "sources": [proof.citations[key] for key in sorted(proof.citations)],
        "relationship_observation_ids": sorted(proof.edge_ids),
        "iam_policy_document": fact,
    }
