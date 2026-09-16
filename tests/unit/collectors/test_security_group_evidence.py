"""Focused graph-evidence coverage for the security-group collector."""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID

import pytest

from app.assessment.evidence_graph import ResourceOwnerMode
from app.assessment.relationships import RelationshipType, UnresolvedRelationshipTarget
from app.assessment.source_outcomes import (
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
)
from app.collectors.base import CollectionContext, CollectorResult
from app.collectors.security_groups import SecurityGroupCollector
from app.schemas.inventory import CollectionStatus
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error

COLLECTION_ACCOUNT_ID = "123456789012"
EXTERNAL_OWNER_ID = "210987654321"
REGION = "us-gov-west-1"
SCAN_ID = UUID("387c723c-ce82-4511-b8d8-f30ca805c640")
COLLECTED_AT = datetime(2026, 9, 16, 15, 30, tzinfo=UTC)


def _context() -> CollectionContext:
    return CollectionContext(
        scan_id=SCAN_ID,
        collection_account_id=COLLECTION_ACCOUNT_ID,
        region=REGION,
        collected_at=COLLECTED_AT,
    )


def _security_group(
    group_id: str = "sg-0123456789abcdef0",
    *,
    owner_id: str = COLLECTION_ACCOUNT_ID,
    group_name: str = "default",
) -> dict[str, object]:
    return {
        "GroupId": group_id,
        "OwnerId": owner_id,
        "GroupName": group_name,
        "Description": "default VPC security group",
        "VpcId": "vpc-0123456789abcdef0",
        "SecurityGroupArn": (f"arn:aws-us-gov:ec2:{REGION}:{owner_id}:security-group/{group_id}"),
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "public IPv4"}],
                "Ipv6Ranges": [{"CidrIpv6": "::/0", "Description": "public IPv6"}],
                "PrefixListIds": [
                    {"PrefixListId": "pl-0123456789abcdef0", "Description": "managed"}
                ],
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-0fedcba9876543210",
                        "GroupName": "application",
                        "UserId": owner_id,
                        "VpcId": "vpc-0123456789abcdef0",
                    }
                ],
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }
        ],
        "Tags": [
            {"Key": "Environment", "Value": "production"},
            {"Key": "Owner", "Value": "security"},
        ],
    }


def _collector(client: FakeAWSClient) -> SecurityGroupCollector:
    provider = FakeClientProvider(
        {("ec2", REGION): client},
        region_name=REGION,
        account_id=COLLECTION_ACCOUNT_ID,
        partition="aws-us-gov",
    )
    return SecurityGroupCollector(provider)


def _client(*pages: object, error: BaseException | None = None) -> FakeAWSClient:
    configured_pages = list(pages) if pages else [{"SecurityGroups": []}]
    return FakeAWSClient(
        paginators={
            "describe_security_groups": FakePaginator(configured_pages, error=error),
        }
    )


def _outcome(result: CollectorResult, evidence_kind: str):
    matches = [
        outcome for outcome in result.source_outcomes if outcome.evidence_kind == evidence_kind
    ]
    assert len(matches) == 1
    return matches[0]


def _artifact(result: CollectorResult, evidence_schema: str):
    matches = [
        artifact for artifact in result.artifacts if artifact.evidence_schema == evidence_schema
    ]
    assert len(matches) == 1
    return matches[0]


def test_graph_collection_preserves_security_group_contract_and_complete_facts() -> None:
    collector = _collector(_client({"SecurityGroups": [_security_group()]}))

    result = collector.collect_with_context(_context())

    assert collector.collector_name == "security_groups"
    assert result.status is CollectionStatus.SUCCEEDED
    assert len(result.resources) == 1
    resource = result.resources[0]
    assert resource.account_id == COLLECTION_ACCOUNT_ID
    assert resource.resource_type == "security_group"
    assert resource.aws_resource_id == "sg-0123456789abcdef0"
    assert resource.name == "default"
    assert resource.tags == {"Environment": "production", "Owner": "security"}
    assert resource.configuration == {
        "description": "default VPC security group",
        "group_name": "default",
        "vpc_id": "vpc-0123456789abcdef0",
        "is_default": True,
        "ingress_rules": [
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "ipv4_ranges": [{"cidr": "0.0.0.0/0", "description": "public IPv4"}],
                "ipv6_ranges": [{"cidr": "::/0", "description": "public IPv6"}],
                "prefix_lists": [
                    {"prefix_list_id": "pl-0123456789abcdef0", "description": "managed"}
                ],
                "referenced_security_groups": [
                    {
                        "group_id": "sg-0fedcba9876543210",
                        "group_name": "application",
                        "user_id": COLLECTION_ACCOUNT_ID,
                        "vpc_id": "vpc-0123456789abcdef0",
                        "vpc_peering_connection_id": None,
                        "peering_status": None,
                        "description": None,
                    }
                ],
            }
        ],
        "egress_rules": [
            {
                "protocol": "-1",
                "from_port": None,
                "to_port": None,
                "ipv4_ranges": [{"cidr": "0.0.0.0/0", "description": None}],
                "ipv6_ranges": [],
                "prefix_lists": [],
                "referenced_security_groups": [],
            }
        ],
    }

    discovery = _outcome(result, "ec2.security-groups.discovery")
    resource_outcome = _outcome(result, "ec2.security-group")
    assert discovery.phase is EvidenceCollectionPhase.DISCOVERY
    assert discovery.state is EvidenceSourceState.PRESENT
    assert resource_outcome.phase is EvidenceCollectionPhase.ENRICHMENT
    assert resource_outcome.state is EvidenceSourceState.PRESENT
    resource_contract = next(
        contract
        for contract in result.source_contracts
        if contract.evidence_kind == "ec2.security-group"
    )
    assert resource_contract.identity_authoritative is True
    assert resource_contract.owner_mode is ResourceOwnerMode.COLLECTION_ACCOUNT

    resource_artifact = _artifact(result, "ec2.security-group")
    serialized_artifact = resource_artifact.model_dump(mode="json")
    assert serialized_artifact["normalized_payload"]["configuration"] == resource.configuration
    assert serialized_artifact["normalized_payload"]["tags"] == [
        {"key": "Environment", "value": "production"},
        {"key": "Owner", "value": "security"},
    ]


def test_graph_collection_emits_vpc_reference_for_inventory_resolver() -> None:
    result = _collector(_client({"SecurityGroups": [_security_group()]})).collect_with_context(
        _context()
    )

    assert len(result.relationships) == 1
    relationship = result.relationships[0]
    assert relationship.relationship_type is RelationshipType.IN_VPC
    assert relationship.source.aws_resource_id == "sg-0123456789abcdef0"
    assert isinstance(relationship.target, UnresolvedRelationshipTarget)
    assert relationship.target.aws_account_id is None
    assert relationship.target.aws_resource_id == "vpc-0123456789abcdef0"
    assert relationship.target_collector_name == "vpc_network_evidence"
    assert relationship.target_evidence_kind == "ec2.vpcs.discovery"
    assert relationship.provenance.source_api == "ec2:DescribeSecurityGroups"


def test_external_owner_is_identity_authoritative_and_not_collection_account() -> None:
    result = _collector(
        _client({"SecurityGroups": [_security_group("sg-external", owner_id=EXTERNAL_OWNER_ID)]})
    ).collect_with_context(_context())

    resource = result.resources[0]
    assert resource.account_id == EXTERNAL_OWNER_ID
    assert resource.arn == (
        f"arn:aws-us-gov:ec2:{REGION}:{EXTERNAL_OWNER_ID}:security-group/sg-external"
    )
    contract = next(
        item for item in result.source_contracts if item.evidence_kind == "ec2.security-group"
    )
    assert contract.owner_mode is ResourceOwnerMode.EXTERNAL_ACCOUNT
    assert contract.identity_authoritative is True
    assert f"/{EXTERNAL_OWNER_ID}/sg-external" in (
        _outcome(result, "ec2.security-group").evidence_reference
    )
    assert result.relationships[0].source.aws_account_id == EXTERNAL_OWNER_ID


def test_malformed_group_retains_valid_sibling_and_marks_discovery_partial() -> None:
    malformed = _security_group("sg-malformed")
    malformed.pop("OwnerId")
    valid = _security_group("sg-valid", group_name="application")

    result = _collector(_client({"SecurityGroups": [malformed, valid]})).collect_with_context(
        _context()
    )

    assert result.status is CollectionStatus.PARTIAL
    assert [resource.aws_resource_id for resource in result.resources] == ["sg-valid"]
    discovery = _outcome(result, "ec2.security-groups.discovery")
    assert discovery.state is EvidenceSourceState.MALFORMED
    assert discovery.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert (
        _artifact(result, "ec2.security-groups.discovery").normalized_payload[
            "discarded_item_count"
        ]
        == 1
    )
    assert _outcome(result, "ec2.security-group").state is EvidenceSourceState.PRESENT


@pytest.mark.parametrize(
    "missing_field",
    ("GroupName", "VpcId", "IpPermissions", "IpPermissionsEgress"),
)
def test_graph_collection_rejects_missing_decision_fact(
    missing_field: str,
) -> None:
    malformed = _security_group("sg-malformed")
    malformed.pop(missing_field)
    valid = _security_group("sg-valid", group_name="application")

    result = _collector(_client({"SecurityGroups": [malformed, valid]})).collect_with_context(
        _context()
    )

    assert result.status is CollectionStatus.PARTIAL
    assert [resource.aws_resource_id for resource in result.resources] == ["sg-valid"]
    discovery = _outcome(result, "ec2.security-groups.discovery")
    assert discovery.state is EvidenceSourceState.MALFORMED
    assert discovery.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert (
        _artifact(result, "ec2.security-groups.discovery").normalized_payload[
            "discarded_item_count"
        ]
        == 1
    )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    (
        ("GroupId", "sg-unsafe\nidentifier"),
        ("VpcId", "vpc-unsafe\x1fidentifier"),
        (
            "SecurityGroupArn",
            "arn:aws-us-gov:ec2:us-gov-west-1:999999999999:security-group/sg-malformed",
        ),
    ),
)
def test_graph_collection_sanitizes_unsafe_or_contradictory_identity(
    field_name: str,
    invalid_value: str,
) -> None:
    malformed = _security_group("sg-malformed")
    malformed[field_name] = invalid_value
    valid = _security_group("sg-valid", group_name="application")

    result = _collector(_client({"SecurityGroups": [malformed, valid]})).collect_with_context(
        _context()
    )

    assert result.status is CollectionStatus.PARTIAL
    assert [resource.aws_resource_id for resource in result.resources] == ["sg-valid"]
    discovery = _outcome(result, "ec2.security-groups.discovery")
    assert discovery.state is EvidenceSourceState.MALFORMED
    assert discovery.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert (
        _artifact(result, "ec2.security-groups.discovery").normalized_payload[
            "discarded_item_count"
        ]
        == 1
    )


def test_conflicting_group_is_discarded_without_losing_valid_sibling() -> None:
    first = _security_group("sg-conflict")
    conflicting = deepcopy(first)
    conflicting["Description"] = "contradictory observation"
    valid = _security_group("sg-valid", group_name="application")

    result = _collector(
        _client({"SecurityGroups": [first, valid, conflicting]})
    ).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert [resource.aws_resource_id for resource in result.resources] == ["sg-valid"]
    discovery = _outcome(result, "ec2.security-groups.discovery")
    assert discovery.state is EvidenceSourceState.CONFLICT
    assert discovery.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    assert (
        _artifact(result, "ec2.security-groups.discovery").normalized_payload[
            "discarded_item_count"
        ]
        == 2
    )


@pytest.mark.parametrize("malformed_first", [True, False])
def test_malformed_and_valid_duplicate_group_is_conflict_regardless_of_order(
    malformed_first: bool,
) -> None:
    valid = _security_group("sg-conflict")
    malformed = deepcopy(valid)
    malformed.pop("OwnerId")
    ordered = [malformed, valid] if malformed_first else [valid, malformed]

    result = _collector(_client({"SecurityGroups": ordered})).collect_with_context(_context())

    assert not result.resources
    discovery = _outcome(result, "ec2.security-groups.discovery")
    assert discovery.state is EvidenceSourceState.CONFLICT
    assert discovery.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    assert (
        _artifact(result, "ec2.security-groups.discovery").normalized_payload[
            "discarded_item_count"
        ]
        == 2
    )


def test_operational_source_failure_is_sanitized() -> None:
    result = _collector(
        _client(
            error=client_error(
                "UnauthorizedOperation",
                "DescribeSecurityGroups",
                status_code=403,
            )
        )
    ).collect_with_context(_context())

    assert result.resources == ()
    assert result.status is CollectionStatus.FAILED
    outcome = _outcome(result, "ec2.security-groups.discovery")
    assert outcome.state is EvidenceSourceState.UNAVAILABLE
    assert outcome.failure_category is EvidenceFailureCategory.ACCESS_DENIED
    serialized = "".join(
        item.model_dump_json()
        for item in (*result.source_contracts, *result.artifacts, *result.source_outcomes)
    )
    assert "simulated" not in serialized
    assert "UnauthorizedOperation" not in serialized


def test_direct_collect_preserves_legacy_graphless_behavior() -> None:
    legacy_shape = _security_group()
    legacy_shape.pop("OwnerId")
    collector = _collector(_client({"SecurityGroups": [legacy_shape]}))

    resources = collector.collect()

    assert collector.collector_name == "security_groups"
    assert len(resources) == 1
    resource = resources[0]
    assert resource.account_id == COLLECTION_ACCOUNT_ID
    assert resource.aws_resource_id == "sg-0123456789abcdef0"
    assert resource.arn == (
        f"arn:aws-us-gov:ec2:{REGION}:{COLLECTION_ACCOUNT_ID}:security-group/sg-0123456789abcdef0"
    )
    assert set(resource.configuration) == {
        "description",
        "vpc_id",
        "ingress_rules",
        "egress_rules",
    }
    assert resource.configuration["ingress_rules"][0]["protocol"] == "tcp"
    assert resource.configuration["egress_rules"][0]["protocol"] == "-1"
