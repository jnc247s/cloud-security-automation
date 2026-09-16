"""Inventory-service integration for Sprint 5A evidence graph composition."""

from uuid import UUID

from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.assessment.source_outcomes import EvidenceSourceState
from app.collectors.base import ResourceCollector
from app.collectors.ec2 import EC2EbsCollector
from app.schemas.inventory import CollectionStatus, InventorySnapshot
from app.schemas.resource import NormalizedResource, ResourceScope
from app.services.inventory_service import InventoryService
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error

SCAN_ID = UUID("be018718-c282-4a85-b88a-0f5272cc8a83")


class _StaticSecurityGroups(ResourceCollector):
    collector_name = "security_groups"

    def collect(self) -> list[NormalizedResource]:
        return [
            NormalizedResource(
                account_id="123456789012",
                service="ec2",
                resource_type="security_group",
                aws_resource_id="sg-graph",
                scope=ResourceScope.REGIONAL,
                region="us-east-1",
            )
        ]


def _instance() -> dict[str, object]:
    return {
        "InstanceId": "i-graph",
        "State": {"Name": "running"},
        "MetadataOptions": {
            "State": "applied",
            "HttpEndpoint": "enabled",
            "HttpTokens": "required",
        },
        "VpcId": "vpc-graph",
        "SubnetId": "subnet-graph",
        "NetworkInterfaces": [
            {
                "Groups": [{"GroupId": "sg-graph"}],
                "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.0.10"}],
            }
        ],
        "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-graph"}}],
        "Tags": [{"Key": "Password", "Value": "classification-label-not-a-secret"}],
    }


def _provider(*, volume_error: BaseException | None = None) -> FakeClientProvider:
    return FakeClientProvider(
        {
            ("ec2", "us-east-1"): FakeAWSClient(
                paginators={
                    "describe_instances": FakePaginator(
                        [{"Reservations": [{"Instances": [_instance()]}]}]
                    ),
                    "describe_volumes": FakePaginator(
                        [
                            {
                                "Volumes": [
                                    {
                                        "VolumeId": "vol-graph",
                                        "State": "in-use",
                                        "Encrypted": True,
                                        "Attachments": [
                                            {
                                                "InstanceId": "i-graph",
                                                "State": "attached",
                                            }
                                        ],
                                        "Tags": [],
                                    }
                                ]
                            }
                        ],
                        error=volume_error,
                    ),
                },
                responses={
                    "get_ebs_encryption_by_default": [{"EbsEncryptionByDefault": True}],
                    "get_ebs_default_kms_key_id": [{"KmsKeyId": "alias/aws/ebs"}],
                },
            )
        }
    )


def test_inventory_composes_and_resolves_5a_evidence_graph() -> None:
    provider = _provider()
    snapshot = InventoryService(
        provider,
        collectors=(EC2EbsCollector(provider), _StaticSecurityGroups(provider)),
    ).collect(scan_id=SCAN_ID)

    assert snapshot.collection_status("ec2_ebs_evidence") is CollectionStatus.SUCCEEDED
    assert snapshot.evidence_graph is not None
    graph = snapshot.evidence_graph
    assert graph.scan_id == snapshot.scan_id
    assert graph.collected_at == snapshot.collected_at
    assert len(graph.source_contracts) == len(graph.artifacts) == len(graph.source_outcomes) == 6
    assert all(item.state is EvidenceSourceState.PRESENT for item in graph.source_outcomes)

    relationships = {item.relationship_type: item for item in graph.relationships}
    assert relationships[RelationshipType.USES_VOLUME].resolution is (
        RelationshipResolution.RESOLVED
    )
    assert relationships[RelationshipType.ATTACHED_TO_SECURITY_GROUP].resolution is (
        RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
    )
    assert relationships[RelationshipType.IN_SUBNET].resolution is (
        RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
    )
    assert relationships[RelationshipType.IN_VPC].resolution is (
        RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
    )
    assert all(
        relationships[relationship_type].target.aws_account_id is None
        for relationship_type in (
            RelationshipType.ATTACHED_TO_SECURITY_GROUP,
            RelationshipType.IN_SUBNET,
            RelationshipType.IN_VPC,
        )
    )
    assert InventorySnapshot.model_validate_json(snapshot.model_dump_json()) == snapshot


def test_unavailable_volume_discovery_retains_instance_and_marks_target_access_denied() -> None:
    provider = _provider(
        volume_error=client_error("UnauthorizedOperation", "DescribeVolumes", status_code=403)
    )
    snapshot = InventoryService(
        provider,
        collectors=(EC2EbsCollector(provider),),
    ).collect(scan_id=SCAN_ID)

    assert snapshot.collection_status("ec2_ebs_evidence") is CollectionStatus.PARTIAL
    assert [resource.resource_type for resource in snapshot.resources] == ["ec2_instance"]
    assert snapshot.evidence_graph is not None
    volume_outcome = next(
        outcome
        for outcome in snapshot.evidence_graph.source_outcomes
        if outcome.evidence_kind == "ec2.volumes.discovery"
    )
    assert volume_outcome.state is EvidenceSourceState.UNAVAILABLE
    volume_edge = next(
        relationship
        for relationship in snapshot.evidence_graph.relationships
        if relationship.relationship_type is RelationshipType.USES_VOLUME
    )
    assert volume_edge.resolution is RelationshipResolution.TARGET_ACCESS_DENIED
    assert volume_edge.target.resource_snapshot_id is None
