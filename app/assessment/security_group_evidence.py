"""Bounded security-group/VPC proofs over retained evidence, without AWS calls."""

from ipaddress import ip_network

from app.assessment.ec2_evidence import canonical
from app.assessment.evidence_reader import IncompleteAssessmentEvidence
from app.assessment.execution import RequiredSource
from app.assessment.relationships import RelationshipType
from app.schemas.resource import ResourceScope

NETWORK_CONTROL_IDS = ("NET-003", "NET-004", "NET-005")


def source(collector, kind, api, *, resource=False):
    return RequiredSource(
        collector=collector,
        evidence_kind=kind,
        source_api=api,
        subject="target" if resource else "regional_account",
        contract_version="1.0.0",
        completion="admitted_resource_v1" if resource else "payload_flags_v1",
        completeness_fields=() if resource else ("complete", "admission_complete"),
    )


GROUP_DISCOVERY = source(
    "ec2.security-groups", "ec2.security-groups.discovery", "ec2:DescribeSecurityGroups"
)
GROUP_FACTS = source(
    "ec2.security-groups", "ec2.security-group", "ec2:DescribeSecurityGroups", resource=True
)
VPC_DISCOVERY = source("ec2.vpcs", "ec2.vpcs.discovery", "ec2:DescribeVpcs")
VPC_FACTS = source("ec2.vpcs", "ec2.vpc", "ec2:DescribeVpcs", resource=True)
NETWORK_SOURCES = (GROUP_DISCOVERY, GROUP_FACTS, VPC_DISCOVERY)


def require(condition):
    if not condition:
        raise IncompleteAssessmentEvidence("required security-group evidence is incomplete")


def _population(reader, required, target, resource_type):
    _, payload, citation = reader.resolve_source(required, target)
    resources = tuple(
        r
        for r in reader.snapshot.resources
        if r.service == "ec2" and r.resource_type == resource_type
    )
    require(payload.get("account_id") == reader.snapshot.account_id)
    require(payload.get("region") == reader.snapshot.requested_region)
    require(
        all(
            r.scope is ResourceScope.REGIONAL and r.region == reader.snapshot.requested_region
            for r in resources
        )
    )
    ids = sorted(r.aws_resource_id for r in resources)
    require(canonical(payload.get("resource_ids")) == canonical(ids))
    require(type(payload.get("resource_count")) is int and payload["resource_count"] == len(ids))
    return resources, citation


def _facts(reader, required, resource):
    _, payload, citation = reader.resolve_source(required, resource)
    expected = {
        "account_id": resource.account_id,
        "region": resource.region,
        "resource_type": resource.resource_type,
        "resource_id": resource.aws_resource_id,
        "arn": resource.arn,
        "tags": [{"key": k, "value": v} for k, v in sorted(resource.tags.items())],
        "configuration": resource.configuration,
    }
    require(canonical(payload) == canonical(expected))
    return citation


def security_group_proof(reader, target):
    """Bind complete membership and the exact directional VPC edge, including its source."""
    groups, group_discovery = _population(reader, GROUP_DISCOVERY, target, "security_group")
    citations = [group_discovery]
    edge_ids = []
    facts = {"empty_population": True}
    if target.resource_type == "aws_account":
        require(not groups)
    else:
        group = reader.resources.get(reader._target_id(target))
        require(group is not None and group in groups)
        citations.append(_facts(reader, GROUP_FACTS, group))
        vpcs, vpc_discovery = _population(reader, VPC_DISCOVERY, target, "vpc")
        citations.append(vpc_discovery)
        edges = reader._edges.get((reader._target_id(group), RelationshipType.IN_VPC), ())
        require(len(edges) == 1 and edges[0].is_resolved)
        edge = edges[0]
        vpc = reader.resources.get(edge.target.resource_snapshot_id)
        require(vpc is not None and vpc in vpcs)
        require(vpc.account_id == group.account_id and vpc.region == group.region)
        require(group.configuration.get("vpc_id") == vpc.aws_resource_id)
        from app.assessment.evidence_graph import source_provenance_key

        outcomes = reader._provenance[source_provenance_key(edge.provenance)]
        require(len(outcomes) == 1)
        require(str(outcomes[0].source_outcome_id) == citations[1]["source_outcome_id"])
        citations.append(_facts(reader, VPC_FACTS, vpc))
        edge_ids.append(str(edge.observation_id))
        facts = {
            "configuration": group.configuration,
            "vpc_snapshot_id": str(edge.target.resource_snapshot_id),
        }
    return {
        "schema_version": "1.3.0",
        "scan_id": str(reader.snapshot.scan_id),
        "sources": sorted(citations, key=lambda c: c["source_outcome_id"]),
        "relationship_observation_ids": edge_ids,
        "security_group": facts,
    }


def permissions(value, *, ports_required=False):
    """Validate the normalized permission subset required by the canonical controls."""
    require(isinstance(value, list))
    for rule in value:
        require(isinstance(rule, dict))
        protocol = rule.get("protocol")
        require(isinstance(protocol, str))
        require(
            protocol in {"-1", "tcp", "udp", "icmp", "icmpv6"}
            or (protocol.isascii() and protocol.isdecimal() and 0 <= int(protocol) <= 255)
        )
        if ports_required and protocol == "tcp":
            first, last = rule.get("from_port"), rule.get("to_port")
            require(type(first) is int and type(last) is int and 0 <= first <= last <= 65535)
        for key, version in (("ipv4_ranges", 4), ("ipv6_ranges", 6)):
            ranges = rule.get(key)
            require(isinstance(ranges, list))
            for item in ranges:
                require(isinstance(item, dict) and isinstance(item.get("cidr"), str))
                try:
                    network = ip_network(item["cidr"], strict=False)
                except ValueError:
                    raise IncompleteAssessmentEvidence("invalid network source") from None
                require("/" in item["cidr"] and network.version == version)
        for key, identity in (
            ("prefix_lists", "prefix_list_id"),
            ("referenced_security_groups", "group_id"),
        ):
            values = rule.get(key)
            require(isinstance(values, list))
            require(
                all(
                    isinstance(v, dict)
                    and isinstance(v.get(identity), str)
                    and bool(v[identity].strip())
                    for v in values
                )
            )
    return value


def public_permission(rule):
    return any(
        ip_network(item["cidr"], strict=False).prefixlen == 0
        for key in ("ipv4_ranges", "ipv6_ranges")
        for item in rule[key]
    )
