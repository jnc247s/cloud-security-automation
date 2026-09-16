"""Unit coverage for Sprint 5A EC2 and EBS evidence collection."""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID

import pytest

from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.assessment.source_outcomes import (
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
)
from app.collectors.base import CollectionContext
from app.collectors.ec2 import EC2EbsCollector
from app.schemas.inventory import CollectionStatus
from app.services.inventory_service import InventoryService
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error

ACCOUNT_ID = "123456789012"
REGION = "us-gov-west-1"
SCAN_ID = UUID("153683ed-0d71-4a9a-ae68-0f732120586b")
COLLECTED_AT = datetime(2026, 9, 15, 14, 30, tzinfo=UTC)


def _context() -> CollectionContext:
    return CollectionContext(
        scan_id=SCAN_ID,
        collection_account_id=ACCOUNT_ID,
        region=REGION,
        collected_at=COLLECTED_AT,
    )


def _instance(instance_id: str = "i-0123456789abcdef0") -> dict[str, object]:
    return {
        "InstanceId": instance_id,
        "State": {"Name": "running"},
        "MetadataOptions": {
            "State": "applied",
            "HttpEndpoint": "enabled",
            "HttpTokens": "required",
        },
        "PublicIpAddress": "198.51.100.10",
        "PrivateIpAddress": "10.0.1.10",
        "VpcId": "vpc-0123456789abcdef0",
        "SubnetId": "subnet-0123456789abcdef0",
        "SecurityGroups": [{"GroupId": "sg-00000000000000001"}],
        "NetworkInterfaces": [
            {
                "NetworkInterfaceId": "eni-0123456789abcdef0",
                "Groups": [
                    {"GroupId": "sg-00000000000000001"},
                    {"GroupId": "sg-00000000000000002"},
                ],
                "PrivateIpAddress": "10.0.1.10",
                "Association": {"PublicIp": "198.51.100.11"},
                "PrivateIpAddresses": [
                    {
                        "PrivateIpAddress": "10.0.1.10",
                        "Association": {"PublicIp": "198.51.100.11"},
                    },
                    {
                        "PrivateIpAddress": "10.0.1.11",
                        "Association": {"PublicIp": "198.51.100.12"},
                    },
                ],
            }
        ],
        "BlockDeviceMappings": [
            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-00000000000000001"}},
            {"DeviceName": "/dev/sdb", "VirtualName": "ephemeral0"},
        ],
        "Tags": [
            {"Key": "Name", "Value": "api-one"},
            {"Key": "aws:autoscaling:groupName", "Value": "api"},
            {"Key": "authorization", "Value": "classification-only"},
        ],
    }


def _volume(
    volume_id: str = "vol-00000000000000001",
    *,
    encrypted: object = True,
    instance_id: object = "i-0123456789abcdef0",
) -> dict[str, object]:
    return {
        "VolumeId": volume_id,
        "State": "in-use",
        "Encrypted": encrypted,
        "KmsKeyId": "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/example",
        "Attachments": [
            {
                "InstanceId": instance_id,
                "State": "attached",
                "Device": "/dev/xvda",
                "AssociatedResource": "arn:aws-us-gov:ec2:us-gov-west-1:resource/example",
                "InstanceOwningService": "ec2",
            }
        ],
        "Tags": [{"Key": "Name", "Value": "data-one"}],
    }


def _client(
    *,
    instance_pages: list[object] | None = None,
    volume_pages: list[object] | None = None,
    instance_error: BaseException | None = None,
    volume_error: BaseException | None = None,
    encryption_response: object = None,
    kms_response: object = None,
) -> FakeAWSClient:
    if instance_pages is None:
        instance_pages = [{"Reservations": []}]
    if volume_pages is None:
        volume_pages = [{"Volumes": []}]
    if encryption_response is None:
        encryption_response = {"EbsEncryptionByDefault": True}
    if kms_response is None:
        kms_response = {"KmsKeyId": "alias/aws/ebs"}
    return FakeAWSClient(
        paginators={
            "describe_instances": FakePaginator(instance_pages, error=instance_error),
            "describe_volumes": FakePaginator(volume_pages, error=volume_error),
        },
        responses={
            "get_ebs_encryption_by_default": [encryption_response],
            "get_ebs_default_kms_key_id": [kms_response],
        },
    )


def _collector(client: FakeAWSClient) -> EC2EbsCollector:
    provider = FakeClientProvider(
        {("ec2", REGION): client},
        region_name=REGION,
        account_id=ACCOUNT_ID,
        partition="aws-us-gov",
    )
    return EC2EbsCollector(provider)


def _outcome(result: object, evidence_kind: str):
    matches = [
        item
        for item in result.source_outcomes
        if item.evidence_kind == evidence_kind  # type: ignore[attr-defined]
    ]
    assert len(matches) == 1
    return matches[0]


def test_collects_paginated_instances_volumes_defaults_and_relationship_references() -> None:
    second = _instance("i-0fedcba9876543210")
    second["PublicIpAddress"] = "198.51.100.20"
    client = _client(
        instance_pages=[
            {"Reservations": [{"Instances": [_instance()]}]},
            {"Reservations": [{"Instances": [second]}]},
        ],
        volume_pages=[{"Volumes": [_volume()]}, {"Volumes": []}],
        encryption_response={"EbsEncryptionByDefault": False},
        kms_response={"KmsKeyId": "alias/custom-ebs"},
    )

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    assert [(item.resource_type, item.aws_resource_id) for item in result.resources] == [
        ("ebs_volume", "vol-00000000000000001"),
        ("ec2_instance", "i-0123456789abcdef0"),
        ("ec2_instance", "i-0fedcba9876543210"),
    ]
    instance = next(
        item for item in result.resources if item.aws_resource_id == "i-0123456789abcdef0"
    )
    assert instance.arn == (
        "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:instance/i-0123456789abcdef0"
    )
    assert instance.configuration["metadata_options"] == {
        "state": "applied",
        "http_endpoint": "enabled",
        "http_tokens": "required",
    }
    assert instance.configuration["public_ipv4_addresses"] == [
        "198.51.100.10",
        "198.51.100.11",
        "198.51.100.12",
    ]
    assert instance.configuration["private_ipv4_addresses"] == ["10.0.1.10", "10.0.1.11"]
    assert instance.tags["aws:autoscaling:groupName"] == "api"
    assert instance.tags["authorization"] == "classification-only"

    volume = next(item for item in result.resources if item.resource_type == "ebs_volume")
    assert volume.arn == (
        "arn:aws-us-gov:ec2:us-gov-west-1:123456789012:volume/vol-00000000000000001"
    )
    assert volume.configuration["state"] == "in-use"
    assert volume.configuration["encrypted"] is True
    assert volume.configuration["kms_key_id"] == (
        "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/example"
    )
    assert volume.configuration["attachment_instance_ids"] == ["i-0123456789abcdef0"]

    encryption_artifact = next(
        item for item in result.artifacts if item.evidence_schema == "ec2.ebs-encryption-default"
    )
    assert encryption_artifact.normalized_payload == {
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "ebs_encryption_by_default": False,
        "complete": True,
        "failure_category": None,
    }
    kms_artifact = next(
        item for item in result.artifacts if item.evidence_schema == "ec2.ebs-default-kms-key"
    )
    assert kms_artifact.normalized_payload == {
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "default_kms_key_id": "alias/custom-ebs",
        "complete": True,
        "expected_absence": False,
        "failure_category": None,
    }

    assert len(result.source_contracts) == len(result.artifacts) == len(result.source_outcomes) == 7
    assert (
        sum(item.phase is EvidenceCollectionPhase.DISCOVERY for item in result.source_outcomes) == 4
    )
    assert (
        sum(item.phase is EvidenceCollectionPhase.ENRICHMENT for item in result.source_outcomes)
        == 3
    )
    assert {item.source_api for item in result.source_outcomes} == {
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:GetEbsEncryptionByDefault",
        "ec2:GetEbsDefaultKmsKeyId",
    }
    instance_artifact = next(
        item
        for item in result.artifacts
        if item.evidence_reference.endswith("/instances/i-0123456789abcdef0")
    )
    assert {tuple(tag.values()) for tag in instance_artifact.normalized_payload["tags"]} >= {
        ("authorization", "classification-only"),
        ("aws:autoscaling:groupName", "api"),
    }

    first_edges = {
        (item.relationship_type, item.target.aws_resource_id)
        for item in result.relationships
        if item.source.aws_resource_id == "i-0123456789abcdef0"
    }
    assert first_edges == {
        (RelationshipType.ATTACHED_TO_SECURITY_GROUP, "sg-00000000000000001"),
        (RelationshipType.ATTACHED_TO_SECURITY_GROUP, "sg-00000000000000002"),
        (RelationshipType.USES_VOLUME, "vol-00000000000000001"),
        (RelationshipType.IN_SUBNET, "subnet-0123456789abcdef0"),
        (RelationshipType.IN_VPC, "vpc-0123456789abcdef0"),
    }
    assert all(
        item.provenance.source_api == "ec2:DescribeInstances" for item in result.relationships
    )
    assert client.paginator_requests == ["describe_instances", "describe_volumes"]


def test_successful_empty_sources_and_absent_default_kms_are_complete() -> None:
    client = _client(kms_response={})

    result = _collector(client).collect_with_context(_context())

    assert result.resources == ()
    assert result.status is CollectionStatus.SUCCEEDED
    assert len(result.source_outcomes) == 4
    assert _outcome(result, "ec2.instances.discovery").state is EvidenceSourceState.PRESENT
    assert _outcome(result, "ec2.volumes.discovery").state is EvidenceSourceState.PRESENT
    assert _outcome(result, "ec2.ebs-default-kms-key").state is EvidenceSourceState.EXPECTED_ABSENCE


def test_inventory_service_builds_valid_graph_and_resolves_observed_volume() -> None:
    client = _client(
        instance_pages=[{"Reservations": [{"Instances": [_instance()]}]}],
        volume_pages=[{"Volumes": [_volume()]}],
    )
    provider = FakeClientProvider(
        {("ec2", REGION): client},
        region_name=REGION,
        account_id=ACCOUNT_ID,
        partition="aws-us-gov",
    )

    snapshot = InventoryService(
        provider,
        collectors=(EC2EbsCollector(provider),),
    ).collect(scan_id=SCAN_ID)

    assert snapshot.evidence_graph is not None
    relationships = snapshot.evidence_graph.relationships
    volume_edge = next(
        item for item in relationships if item.relationship_type is RelationshipType.USES_VOLUME
    )
    assert volume_edge.resolution is RelationshipResolution.RESOLVED
    assert volume_edge.target.resource_snapshot_id is not None
    unresolved = {
        item.relationship_type: item.resolution
        for item in relationships
        if item.relationship_type is not RelationshipType.USES_VOLUME
    }
    assert unresolved == {
        RelationshipType.ATTACHED_TO_SECURITY_GROUP: (
            RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
        ),
        RelationshipType.IN_SUBNET: RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
        RelationshipType.IN_VPC: RelationshipResolution.TARGET_IDENTITY_INCOMPLETE,
    }
    assert all(
        item.target.aws_account_id is None
        for item in relationships
        if item.relationship_type is not RelationshipType.USES_VOLUME
    )


def test_malformed_instance_does_not_discard_other_valid_instances() -> None:
    malformed = _instance("i-00000000000000001")
    malformed["MetadataOptions"] = {"State": "applied", "HttpEndpoint": "enabled"}
    valid = _instance("i-00000000000000002")
    client = _client(
        instance_pages=[{"Reservations": [{"Instances": [malformed, valid]}]}],
    )

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert [item.aws_resource_id for item in result.resources] == ["i-00000000000000002"]
    discovery = _outcome(result, "ec2.instances.discovery")
    assert discovery.state is EvidenceSourceState.MALFORMED
    assert discovery.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert _outcome(result, "ec2.instance").state is EvidenceSourceState.PRESENT


def test_unavailable_instance_source_retains_independent_volume_evidence() -> None:
    client = _client(
        instance_error=client_error("AccessDenied", "DescribeInstances", status_code=403),
        volume_pages=[{"Volumes": [_volume()]}],
    )

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert [(item.resource_type, item.aws_resource_id) for item in result.resources] == [
        ("ebs_volume", "vol-00000000000000001")
    ]
    discovery = _outcome(result, "ec2.instances.discovery")
    assert discovery.state is EvidenceSourceState.UNAVAILABLE
    assert discovery.failure_category is EvidenceFailureCategory.ACCESS_DENIED
    serialized_evidence = "".join(
        item.model_dump_json()
        for item in (*result.source_contracts, *result.artifacts, *result.source_outcomes)
    )
    assert "simulated" not in serialized_evidence


def test_partial_pagination_retains_previously_valid_resource_with_incomplete_coverage() -> None:
    class PartialPaginator(FakePaginator):
        def paginate(self, **kwargs: object):  # type: ignore[no-untyped-def]
            self.calls.append(dict(kwargs))
            yield {"Reservations": [{"Instances": [_instance()]}]}
            raise client_error("RequestLimitExceeded", "DescribeInstances", status_code=503)

    client = FakeAWSClient(
        paginators={
            "describe_instances": PartialPaginator(),
            "describe_volumes": FakePaginator([{"Volumes": []}]),
        },
        responses={
            "get_ebs_encryption_by_default": [{"EbsEncryptionByDefault": True}],
            "get_ebs_default_kms_key_id": [{"KmsKeyId": "alias/aws/ebs"}],
        },
    )

    result = _collector(client).collect_with_context(_context())

    assert [item.aws_resource_id for item in result.resources] == ["i-0123456789abcdef0"]
    discovery = _outcome(result, "ec2.instances.discovery")
    assert discovery.state is EvidenceSourceState.UNAVAILABLE
    assert discovery.failure_category is EvidenceFailureCategory.THROTTLED
    assert result.status is CollectionStatus.PARTIAL


def test_volume_encrypted_must_be_a_real_boolean() -> None:
    client = _client(volume_pages=[{"Volumes": [_volume(encrypted="true")]}])

    result = _collector(client).collect_with_context(_context())

    assert result.resources == ()
    assert result.status is CollectionStatus.PARTIAL
    discovery = _outcome(result, "ec2.volumes.discovery")
    assert discovery.state is EvidenceSourceState.MALFORMED
    assert discovery.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE


@pytest.mark.parametrize("instance_id", [None, ""])
def test_empty_attachment_instance_id_is_valid_managed_attachment_context(
    instance_id: object,
) -> None:
    client = _client(volume_pages=[{"Volumes": [_volume(instance_id=instance_id)]}])

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    volume = result.resources[0]
    assert volume.resource_type == "ebs_volume"
    assert volume.configuration["attachment_instance_ids"] == []
    assert volume.configuration["attachments"][0]["instance_id"] is None
    assert result.relationships == ()


def test_missing_attachment_instance_id_is_valid_managed_attachment_context() -> None:
    volume = _volume()
    del volume["Attachments"][0]["InstanceId"]  # type: ignore[index]
    client = _client(volume_pages=[{"Volumes": [volume]}])

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    normalized = result.resources[0]
    assert normalized.configuration["attachment_instance_ids"] == []
    assert normalized.configuration["attachments"][0]["instance_id"] is None
    assert result.relationships == ()


def test_missing_attachment_identity_without_managed_context_fails_closed() -> None:
    volume = _volume()
    attachment = volume["Attachments"][0]  # type: ignore[index]
    del attachment["InstanceId"]
    del attachment["AssociatedResource"]
    del attachment["InstanceOwningService"]
    client = _client(volume_pages=[{"Volumes": [volume]}])

    result = _collector(client).collect_with_context(_context())

    assert result.resources == ()
    discovery = _outcome(result, "ec2.volumes.discovery")
    assert discovery.state is EvidenceSourceState.MALFORMED
    assert discovery.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE


def test_associations_without_public_ip_do_not_discard_valid_instance_evidence() -> None:
    instance = _instance()
    instance.pop("PublicIpAddress")
    interface = instance["NetworkInterfaces"][0]  # type: ignore[index]
    interface["Association"] = {"CarrierIp": "198.51.100.20"}
    interface["PrivateIpAddresses"][0]["Association"] = {  # type: ignore[index]
        "CustomerOwnedIp": "198.51.100.21"
    }
    interface["PrivateIpAddresses"][1].pop("Association")  # type: ignore[index]
    client = _client(instance_pages=[{"Reservations": [{"Instances": [instance]}]}])

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    normalized = result.resources[0]
    assert normalized.configuration["public_ipv4_addresses"] == []
    assert _outcome(result, "ec2.instances.discovery").state is EvidenceSourceState.PRESENT


@pytest.mark.parametrize("resource_kind", ["instance", "volume"])
def test_missing_ec2_tag_value_is_complete_empty_value(resource_kind: str) -> None:
    if resource_kind == "instance":
        resource = _instance()
        resource["Tags"] = [{"Key": "Owner"}]
        client = _client(instance_pages=[{"Reservations": [{"Instances": [resource]}]}])
    else:
        resource = _volume()
        resource["Tags"] = [{"Key": "Owner"}]
        client = _client(volume_pages=[{"Volumes": [resource]}])

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    assert result.resources[0].tags == {"Owner": ""}


def test_conflicting_duplicate_instance_is_not_persisted_as_authoritative() -> None:
    first = _instance()
    conflicting = deepcopy(first)
    conflicting["State"] = {"Name": "stopped"}
    client = _client(
        instance_pages=[
            {"Reservations": [{"Instances": [first]}]},
            {"Reservations": [{"Instances": [conflicting]}]},
        ]
    )

    result = _collector(client).collect_with_context(_context())

    assert result.resources == ()
    discovery = _outcome(result, "ec2.instances.discovery")
    assert discovery.state is EvidenceSourceState.CONFLICT
    assert discovery.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    discovery_artifact = next(
        item for item in result.artifacts if item.evidence_schema == "ec2.instances.discovery"
    )
    assert discovery_artifact.normalized_payload["discarded_item_count"] == 2


@pytest.mark.parametrize("malformed_first", [True, False])
def test_malformed_and_valid_duplicate_instance_conflicts_regardless_of_order(
    malformed_first: bool,
) -> None:
    valid = _instance()
    malformed = deepcopy(valid)
    del malformed["MetadataOptions"]["HttpTokens"]  # type: ignore[index]
    ordered = [malformed, valid] if malformed_first else [valid, malformed]
    client = _client(instance_pages=[{"Reservations": [{"Instances": [item]}]} for item in ordered])

    result = _collector(client).collect_with_context(_context())

    assert result.resources == ()
    discovery = _outcome(result, "ec2.instances.discovery")
    assert discovery.state is EvidenceSourceState.CONFLICT
    assert discovery.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    discovery_artifact = next(
        item for item in result.artifacts if item.evidence_schema == "ec2.instances.discovery"
    )
    assert discovery_artifact.normalized_payload["discarded_item_count"] == 2


@pytest.mark.parametrize("malformed_first", [True, False])
def test_malformed_and_valid_duplicate_volume_conflicts_regardless_of_order(
    malformed_first: bool,
) -> None:
    valid = _volume()
    malformed = deepcopy(valid)
    malformed["Encrypted"] = "true"
    ordered = [malformed, valid] if malformed_first else [valid, malformed]
    client = _client(volume_pages=[{"Volumes": [item]} for item in ordered])

    result = _collector(client).collect_with_context(_context())

    assert result.resources == ()
    discovery = _outcome(result, "ec2.volumes.discovery")
    assert discovery.state is EvidenceSourceState.CONFLICT
    assert discovery.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    discovery_artifact = next(
        item for item in result.artifacts if item.evidence_schema == "ec2.volumes.discovery"
    )
    assert discovery_artifact.normalized_payload["discarded_item_count"] == 2


def test_malformed_nested_association_fails_closed_without_losing_other_sources() -> None:
    malformed = _instance()
    malformed["NetworkInterfaces"][0]["Association"] = {  # type: ignore[index]
        "PublicIp": "not-an-ip-address"
    }
    client = _client(instance_pages=[{"Reservations": [{"Instances": [malformed]}]}])

    result = _collector(client).collect_with_context(_context())

    assert result.resources == ()
    assert _outcome(result, "ec2.instances.discovery").state is EvidenceSourceState.MALFORMED
    assert _outcome(result, "ec2.volumes.discovery").state is EvidenceSourceState.PRESENT


@pytest.mark.parametrize(
    ("response_name", "response"),
    [
        ("encryption_response", {"EbsEncryptionByDefault": "true"}),
        ("kms_response", {"KmsKeyId": 123}),
    ],
)
def test_malformed_regional_setting_is_sanitized(
    response_name: str,
    response: object,
) -> None:
    client = _client(**{response_name: response})

    result = _collector(client).collect_with_context(_context())

    expected_kind = (
        "ec2.ebs-encryption-default"
        if response_name == "encryption_response"
        else "ec2.ebs-default-kms-key"
    )
    outcome = _outcome(result, expected_kind)
    assert outcome.state is EvidenceSourceState.MALFORMED
    assert outcome.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert result.status is CollectionStatus.PARTIAL
