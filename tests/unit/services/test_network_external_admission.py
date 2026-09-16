"""Cross-collector exceptional-owner admission for Sprint 5B network evidence."""

from uuid import UUID

import pytest

from app.assessment.evidence_graph import EvidenceGraph, SourceEvidenceArtifact
from app.assessment.models import AssessmentResult
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE
from app.assessment.source_outcomes import (
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
    SourceEvidenceOutcome,
)
from app.collectors.base import graph_collection_status_for
from app.collectors.network import VPCNetworkCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.rules.network import PublicSSHRule
from app.schemas.inventory import CollectionStatus
from app.services.inventory_service import InventoryService
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error

COLLECTION_ACCOUNT_ID = "123456789012"
EXTERNAL_ACCOUNT_ID = "210987654321"
REGION = "us-east-1"
SCAN_ID = UUID("46b61f35-c969-4aa1-9f71-95aca489b170")


def _security_group(
    group_id: str,
    *,
    owner_id: str,
    vpc_id: str,
) -> dict[str, object]:
    return {
        "GroupId": group_id,
        "OwnerId": owner_id,
        "GroupName": "application",
        "Description": "network admission fixture",
        "VpcId": vpc_id,
        "IpPermissions": [],
        "IpPermissionsEgress": [],
        "Tags": [],
    }


def _vpc(vpc_id: str, *, owner_id: str) -> dict[str, object]:
    return {
        "VpcId": vpc_id,
        "OwnerId": owner_id,
        "State": "available",
        "CidrBlock": "10.0.0.0/16",
        "IsDefault": False,
        "Tags": [],
    }


def _subnet(subnet_id: str, *, owner_id: str, vpc_id: str) -> dict[str, object]:
    return {
        "SubnetId": subnet_id,
        "OwnerId": owner_id,
        "VpcId": vpc_id,
        "State": "available",
        "CidrBlock": "10.0.1.0/24",
        "AvailabilityZone": f"{REGION}a",
        "MapPublicIpOnLaunch": False,
        "Tags": [],
    }


def _provider(
    *,
    security_groups: list[dict[str, object]] | None = None,
    vpcs: list[dict[str, object]] | None = None,
    subnets: list[dict[str, object]] | None = None,
    vpc_error: BaseException | None = None,
) -> FakeClientProvider:
    client = FakeAWSClient(
        paginators={
            "describe_security_groups": FakePaginator([{"SecurityGroups": security_groups or []}]),
            "describe_vpcs": FakePaginator([{"Vpcs": vpcs or []}], error=vpc_error),
            "describe_subnets": FakePaginator([{"Subnets": subnets or []}]),
            "describe_flow_logs": FakePaginator([{"FlowLogs": []}]),
        }
    )
    return FakeClientProvider(
        {("ec2", REGION): client},
        region_name=REGION,
        account_id=COLLECTION_ACCOUNT_ID,
    )


def _collect(provider: FakeClientProvider):
    return InventoryService(
        provider,
        collectors=(
            SecurityGroupCollector(provider),
            VPCNetworkCollector(provider),
        ),
    ).collect(scan_id=SCAN_ID)


def _reconstructed_status(snapshot, collector_name: str) -> CollectionStatus:
    assert snapshot.evidence_graph is not None
    graph = EvidenceGraph.model_validate_json(snapshot.evidence_graph.model_dump_json())
    return graph_collection_status_for(
        collector_name=collector_name,
        outcomes=graph.source_outcomes,
        artifacts=graph.artifacts,
    )


def test_external_security_group_without_edge_is_pruned_and_coverage_is_partial() -> None:
    provider = _provider(
        security_groups=[
            _security_group(
                "sg-same-account",
                owner_id=COLLECTION_ACCOUNT_ID,
                vpc_id="vpc-unavailable",
            ),
            _security_group(
                "sg-external-orphan",
                owner_id=EXTERNAL_ACCOUNT_ID,
                vpc_id="vpc-unavailable",
            ),
        ],
        vpc_error=client_error("UnauthorizedOperation", "DescribeVpcs", status_code=403),
    )

    snapshot = _collect(provider)

    assert snapshot.collection_status("security_groups") is CollectionStatus.PARTIAL
    assert snapshot.collection_status("vpc_network_evidence") is CollectionStatus.PARTIAL
    assert [resource.aws_resource_id for resource in snapshot.resources] == ["sg-same-account"]
    assert snapshot.evidence_graph is not None
    assert not any(
        isinstance(outcome.subject, ResourceEvidenceSubject)
        and outcome.subject.aws_account_id == EXTERNAL_ACCOUNT_ID
        for outcome in snapshot.evidence_graph.source_outcomes
    )
    discovery = next(
        outcome
        for outcome in snapshot.evidence_graph.source_outcomes
        if outcome.evidence_kind == "ec2.security-groups.discovery"
    )
    assert discovery.state is EvidenceSourceState.PRESENT
    assert discovery.failure_category is None
    discovery_artifact = next(
        artifact
        for artifact in snapshot.evidence_graph.artifacts
        if artifact.evidence_reference == discovery.evidence_reference
    )
    payload = discovery_artifact.model_dump(mode="json")["normalized_payload"]
    assert payload["resource_ids"] == ["sg-external-orphan", "sg-same-account"]
    assert payload["resource_count"] == 2
    assert payload["discarded_item_count"] == 0
    assert payload["complete"] is True
    assert payload["failure_category"] is None
    assert payload["admission_complete"] is False
    assert payload["unadmitted_resources"] == [
        {
            "account_id": EXTERNAL_ACCOUNT_ID,
            "service": "ec2",
            "resource_type": "security_group",
            "scope": "regional",
            "region": REGION,
            "resource_id": "sg-external-orphan",
        }
    ]
    assert discovery.evidence_sha256 == discovery_artifact.evidence_sha256
    assert _reconstructed_status(snapshot, "security_groups") is CollectionStatus.PARTIAL
    assert not any(
        relationship.source.aws_account_id == EXTERNAL_ACCOUNT_ID
        for relationship in snapshot.evidence_graph.relationships
    )

    assessment = PublicSSHRule().assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)[0]
    assert assessment.result is AssessmentResult.INSUFFICIENT_EVIDENCE


def test_external_subnet_without_vpc_edge_does_not_abort_partial_snapshot() -> None:
    provider = _provider(
        subnets=[
            _subnet(
                "subnet-same-account",
                owner_id=COLLECTION_ACCOUNT_ID,
                vpc_id="vpc-unavailable",
            ),
            _subnet(
                "subnet-external-orphan",
                owner_id=EXTERNAL_ACCOUNT_ID,
                vpc_id="vpc-unavailable",
            ),
        ],
        vpc_error=client_error("UnauthorizedOperation", "DescribeVpcs", status_code=403),
    )

    snapshot = _collect(provider)

    assert snapshot.collection_status("security_groups") is CollectionStatus.SUCCEEDED
    assert snapshot.collection_status("vpc_network_evidence") is CollectionStatus.PARTIAL
    assert [resource.aws_resource_id for resource in snapshot.resources] == ["subnet-same-account"]
    assert snapshot.evidence_graph is not None
    assert not any(
        isinstance(outcome.subject, ResourceEvidenceSubject)
        and outcome.subject.aws_account_id == EXTERNAL_ACCOUNT_ID
        for outcome in snapshot.evidence_graph.source_outcomes
    )
    discovery = next(
        outcome
        for outcome in snapshot.evidence_graph.source_outcomes
        if outcome.evidence_kind == "ec2.subnets.discovery"
    )
    assert discovery.state is EvidenceSourceState.PRESENT
    assert discovery.failure_category is None
    discovery_artifact = next(
        artifact
        for artifact in snapshot.evidence_graph.artifacts
        if artifact.evidence_reference == discovery.evidence_reference
    )
    payload = discovery_artifact.model_dump(mode="json")["normalized_payload"]
    assert payload["resource_ids"] == ["subnet-external-orphan", "subnet-same-account"]
    assert payload["resource_count"] == 2
    assert payload["discarded_item_count"] == 0
    assert payload["complete"] is True
    assert payload["failure_category"] is None
    assert payload["admission_complete"] is False
    assert payload["unadmitted_resources"] == [
        {
            "account_id": EXTERNAL_ACCOUNT_ID,
            "service": "ec2",
            "resource_type": "subnet",
            "scope": "regional",
            "region": REGION,
            "resource_id": "subnet-external-orphan",
        }
    ]
    assert discovery.evidence_sha256 == discovery_artifact.evidence_sha256
    assert _reconstructed_status(snapshot, "vpc_network_evidence") is CollectionStatus.PARTIAL


def test_external_vpc_and_subnet_with_exact_resolved_edge_are_admitted() -> None:
    provider = _provider(
        vpcs=[_vpc("vpc-shared", owner_id=EXTERNAL_ACCOUNT_ID)],
        subnets=[
            _subnet(
                "subnet-shared",
                owner_id=EXTERNAL_ACCOUNT_ID,
                vpc_id="vpc-shared",
            )
        ],
    )

    snapshot = _collect(provider)

    assert snapshot.collection_status("security_groups") is CollectionStatus.SUCCEEDED
    assert snapshot.collection_status("vpc_network_evidence") is CollectionStatus.SUCCEEDED
    assert {
        (resource.account_id, resource.resource_type, resource.aws_resource_id)
        for resource in snapshot.resources
    } == {
        (EXTERNAL_ACCOUNT_ID, "vpc", "vpc-shared"),
        (EXTERNAL_ACCOUNT_ID, "subnet", "subnet-shared"),
    }
    assert snapshot.evidence_graph is not None
    assert len(snapshot.evidence_graph.relationships) == 1
    relationship = snapshot.evidence_graph.relationships[0]
    assert relationship.source.aws_account_id == EXTERNAL_ACCOUNT_ID
    assert relationship.target.aws_account_id == EXTERNAL_ACCOUNT_ID
    discovery_artifacts = [
        artifact.model_dump(mode="json")["normalized_payload"]
        for artifact in snapshot.evidence_graph.artifacts
        if artifact.evidence_reference.endswith("/discovery")
    ]
    assert all(payload["unadmitted_resources"] == [] for payload in discovery_artifacts)
    assert all(payload["admission_complete"] is True for payload in discovery_artifacts)
    assert _reconstructed_status(snapshot, "vpc_network_evidence") is CollectionStatus.SUCCEEDED


def test_unadmitted_identity_order_and_digest_are_deterministic() -> None:
    groups = [
        _security_group(
            "sg-external-z",
            owner_id=EXTERNAL_ACCOUNT_ID,
            vpc_id="vpc-unavailable",
        ),
        _security_group(
            "sg-external-a",
            owner_id=EXTERNAL_ACCOUNT_ID,
            vpc_id="vpc-unavailable",
        ),
    ]

    snapshots = [
        _collect(
            _provider(
                security_groups=ordered,
                vpc_error=client_error("UnauthorizedOperation", "DescribeVpcs", status_code=403),
            )
        )
        for ordered in (groups, list(reversed(groups)))
    ]
    artifacts = []
    for snapshot in snapshots:
        assert snapshot.evidence_graph is not None
        artifact = next(
            item
            for item in snapshot.evidence_graph.artifacts
            if item.evidence_schema == "ec2.security-groups.discovery"
        )
        artifacts.append(artifact)

    first_payload = artifacts[0].model_dump(mode="json")["normalized_payload"]
    second_payload = artifacts[1].model_dump(mode="json")["normalized_payload"]
    assert first_payload == second_payload
    assert artifacts[0].evidence_sha256 == artifacts[1].evidence_sha256
    assert [item["resource_id"] for item in first_payload["unadmitted_resources"]] == [
        "sg-external-a",
        "sg-external-z",
    ]
    assert all(
        _reconstructed_status(snapshot, "security_groups") is CollectionStatus.PARTIAL
        for snapshot in snapshots
    )


def test_admission_gap_preserves_preexisting_malformed_discovery_state() -> None:
    malformed_group = _security_group(
        "sg-malformed",
        owner_id=COLLECTION_ACCOUNT_ID,
        vpc_id="vpc-unavailable",
    )
    malformed_group.pop("OwnerId")
    snapshot = _collect(
        _provider(
            security_groups=[
                _security_group(
                    "sg-external-orphan",
                    owner_id=EXTERNAL_ACCOUNT_ID,
                    vpc_id="vpc-unavailable",
                ),
                malformed_group,
            ],
            vpc_error=client_error("UnauthorizedOperation", "DescribeVpcs", status_code=403),
        )
    )

    assert snapshot.evidence_graph is not None
    discovery = next(
        outcome
        for outcome in snapshot.evidence_graph.source_outcomes
        if outcome.evidence_kind == "ec2.security-groups.discovery"
    )
    artifact = next(
        item
        for item in snapshot.evidence_graph.artifacts
        if item.evidence_reference == discovery.evidence_reference
    )
    payload = artifact.model_dump(mode="json")["normalized_payload"]
    assert discovery.state is EvidenceSourceState.MALFORMED
    assert discovery.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert payload["complete"] is False
    assert payload["failure_category"] == "MALFORMED_RESPONSE"
    assert payload["discarded_item_count"] == 1
    assert payload["resource_ids"] == ["sg-external-orphan"]
    assert payload["admission_complete"] is False
    assert _reconstructed_status(snapshot, "security_groups") is CollectionStatus.PARTIAL


def test_malformed_admission_metadata_fails_coverage_reconstruction() -> None:
    snapshot = _collect(_provider())
    assert snapshot.evidence_graph is not None
    discovery = next(
        outcome
        for outcome in snapshot.evidence_graph.source_outcomes
        if outcome.evidence_kind == "ec2.security-groups.discovery"
    )
    artifact = next(
        item
        for item in snapshot.evidence_graph.artifacts
        if item.evidence_reference == discovery.evidence_reference
    )
    payload = artifact.model_dump(mode="json")["normalized_payload"]
    payload.pop("admission_complete")
    replacement_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=artifact.scan_id,
        collection_account_id=artifact.collection_account_id,
        evidence_reference=artifact.evidence_reference,
        evidence_schema=artifact.evidence_schema,
        evidence_schema_version=artifact.evidence_schema_version,
        collected_at=artifact.collected_at,
        normalized_payload=payload,
    )
    replacement_outcome = SourceEvidenceOutcome.for_observation(
        scan_id=discovery.scan_id,
        collection_account_id=discovery.collection_account_id,
        phase=discovery.phase,
        subject=discovery.subject,
        evidence_kind=discovery.evidence_kind,
        state=discovery.state,
        failure_category=discovery.failure_category,
        collector=discovery.collector,
        collector_version=discovery.collector_version,
        source_api=discovery.source_api,
        collected_at=discovery.collected_at,
        evidence_reference=replacement_artifact.evidence_reference,
        evidence_sha256=replacement_artifact.evidence_sha256,
    )

    with pytest.raises(ValueError, match="admission-aware discovery metadata is malformed"):
        graph_collection_status_for(
            collector_name="security_groups",
            outcomes=tuple(
                replacement_outcome if item is discovery else item
                for item in snapshot.evidence_graph.source_outcomes
            ),
            artifacts=tuple(
                replacement_artifact if item is artifact else item
                for item in snapshot.evidence_graph.artifacts
            ),
        )
