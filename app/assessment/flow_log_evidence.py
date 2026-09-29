"""Bounded VPC/Flow Log membership proof, including authoritative empty coverage."""

from app.assessment.evidence_graph import source_provenance_key
from app.assessment.relationships import RelationshipType
from app.assessment.security_group_evidence import (
    VPC_DISCOVERY,
    VPC_FACTS,
    _facts,
    _population,
    require,
    source,
)

FLOW_DISCOVERY = source("ec2.flow-logs", "ec2.flow-logs.discovery", "ec2:DescribeFlowLogs")
FLOW_FACTS = source("ec2.flow-logs", "ec2.vpc-flow-log", "ec2:DescribeFlowLogs", resource=True)
FLOW_SOURCES = (VPC_DISCOVERY, VPC_FACTS, FLOW_DISCOVERY)


def flow_log_proof(reader, target):
    vpcs, discovery = _population(reader, VPC_DISCOVERY, target, "vpc")
    citations, edge_ids = [discovery], []
    facts = {"empty_population": True}
    if target.resource_type == "aws_account":
        require(not vpcs)
    else:
        vpc = reader.resources.get(reader._target_id(target))
        require(vpc is not None and vpc in vpcs)
        # Discovery covers the collection account, not an external owner's logs.
        require(vpc.account_id == reader.snapshot.account_id)
        citations.append(_facts(reader, VPC_FACTS, vpc))
        logs, discovery = _population(reader, FLOW_DISCOVERY, target, "vpc_flow_log")
        citations.append(discovery)
        # Prove each log's referenced identity before selecting the matching subset.
        matches = {}
        for log in logs:
            citation = _facts(reader, FLOW_FACTS, log)
            citations.append(citation)
            resource_id = log.configuration.get("resource_id")
            require(isinstance(resource_id, str) and bool(resource_id.strip()))
            require(log.account_id == reader.snapshot.account_id)
            if (
                resource_id == vpc.aws_resource_id
                and log.account_id == vpc.account_id
                and log.region == vpc.region
            ):
                matches[reader._target_id(log)] = (log, citation)
        edges = reader._edges.get((reader._target_id(vpc), RelationshipType.HAS_FLOW_LOG), ())
        require(len(edges) == len(matches))
        require({edge.target.resource_snapshot_id for edge in edges} == set(matches))
        for edge in edges:
            require(edge.is_resolved)
            _, citation = matches[edge.target.resource_snapshot_id]
            outcomes = reader._provenance.get(source_provenance_key(edge.provenance), ())
            require(len(outcomes) == 1)
            require(str(outcomes[0].source_outcome_id) == citation["source_outcome_id"])
            edge_ids.append(str(edge.observation_id))
        facts = {
            "tags": vpc.tags,
            "flow_logs": [
                {"snapshot_id": str(key), "configuration": log.configuration}
                for key, (log, _) in sorted(matches.items(), key=lambda item: str(item[0]))
            ],
        }
    return {
        "schema_version": "1.4.0",
        "scan_id": str(reader.snapshot.scan_id),
        "sources": sorted(citations, key=lambda c: c["source_outcome_id"]),
        "relationship_observation_ids": sorted(edge_ids),
        "vpc_flow_logs": facts,
    }
