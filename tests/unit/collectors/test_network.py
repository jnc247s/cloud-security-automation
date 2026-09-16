"""Unit coverage for Sprint 5B VPC, subnet, and Flow Log evidence."""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID

import pytest

from app.assessment.evidence_graph import ResourceOwnerMode
from app.assessment.relationships import RelationshipType
from app.assessment.source_outcomes import (
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
)
from app.collectors.base import CollectionContext, CollectorResult
from app.collectors.network import VPCNetworkCollector
from app.schemas.inventory import CollectionStatus
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, client_error

COLLECTION_ACCOUNT_ID = "123456789012"
RESOURCE_OWNER_ID = "210987654321"
REGION = "us-gov-west-1"
SCAN_ID = UUID("0149306e-f122-46ec-a9b3-4b2d073b9006")
COLLECTED_AT = datetime(2026, 9, 16, 10, 15, tzinfo=UTC)


def _context() -> CollectionContext:
    return CollectionContext(
        scan_id=SCAN_ID,
        collection_account_id=COLLECTION_ACCOUNT_ID,
        region=REGION,
        collected_at=COLLECTED_AT,
    )


def _vpc(
    vpc_id: str = "vpc-0123456789abcdef0",
    *,
    owner_id: str = COLLECTION_ACCOUNT_ID,
) -> dict[str, object]:
    return {
        "VpcId": vpc_id,
        "OwnerId": owner_id,
        "State": "available",
        "CidrBlock": "10.0.0.0/16",
        "IsDefault": False,
        "Tags": [
            {"Key": "Environment", "Value": "production"},
            {"Key": "Password", "Value": "classification-label-not-a-secret"},
        ],
    }


def _subnet(
    subnet_id: str = "subnet-0123456789abcdef0",
    *,
    owner_id: str = COLLECTION_ACCOUNT_ID,
) -> dict[str, object]:
    return {
        "SubnetId": subnet_id,
        "OwnerId": owner_id,
        "VpcId": "vpc-0123456789abcdef0",
        "State": "available",
        "CidrBlock": "10.0.1.0/24",
        "AvailabilityZone": f"{REGION}a",
        "AvailabilityZoneId": "usgw1-az1",
        "MapPublicIpOnLaunch": False,
        "Tags": [{"Key": "Environment", "Value": "production"}],
    }


def _flow_log(
    flow_log_id: str = "fl-0123456789abcdef0",
    *,
    resource_id: str = "vpc-0123456789abcdef0",
) -> dict[str, object]:
    return {
        "FlowLogId": flow_log_id,
        "ResourceId": resource_id,
        "FlowLogStatus": "ACTIVE",
        "TrafficType": "ALL",
        "LogDestinationType": "cloud-watch-logs",
        "LogGroupName": "/aws/vpc/flow-logs",
        "LogDestination": (
            "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/vpc/flow-logs"
        ),
        "DeliverLogsPermissionArn": ("arn:aws-us-gov:iam::123456789012:role/vpc-flow-logs"),
        "Tags": [{"Key": "Environment", "Value": "production"}],
    }


def _client(
    *,
    vpc_pages: list[object] | None = None,
    subnet_pages: list[object] | None = None,
    flow_log_pages: list[object] | None = None,
    vpc_error: BaseException | None = None,
    subnet_error: BaseException | None = None,
    flow_log_error: BaseException | None = None,
) -> FakeAWSClient:
    return FakeAWSClient(
        paginators={
            "describe_vpcs": FakePaginator(
                vpc_pages if vpc_pages is not None else [{"Vpcs": []}],
                error=vpc_error,
            ),
            "describe_subnets": FakePaginator(
                subnet_pages if subnet_pages is not None else [{"Subnets": []}],
                error=subnet_error,
            ),
            "describe_flow_logs": FakePaginator(
                flow_log_pages if flow_log_pages is not None else [{"FlowLogs": []}],
                error=flow_log_error,
            ),
        }
    )


def _collector(client: FakeAWSClient) -> VPCNetworkCollector:
    provider = FakeClientProvider(
        {("ec2", REGION): client},
        region_name=REGION,
        account_id=COLLECTION_ACCOUNT_ID,
        partition="aws-us-gov",
    )
    return VPCNetworkCollector(provider)


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


def _without(item: dict[str, object], key: str) -> dict[str, object]:
    candidate = deepcopy(item)
    candidate.pop(key)
    return candidate


def test_collects_paginated_network_resources_sources_and_relationships() -> None:
    vpc = _vpc()
    subnet = _subnet()
    flow_log = _flow_log()
    client = _client(
        vpc_pages=[{"Vpcs": []}, {"Vpcs": [vpc]}, {"Vpcs": [deepcopy(vpc)]}],
        subnet_pages=[{"Subnets": [subnet]}, {"Subnets": []}],
        flow_log_pages=[{"FlowLogs": []}, {"FlowLogs": [flow_log]}],
    )

    result = _collector(client).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    resources = {
        (resource.resource_type, resource.aws_resource_id): resource
        for resource in result.resources
    }
    assert set(resources) == {
        ("vpc", "vpc-0123456789abcdef0"),
        ("subnet", "subnet-0123456789abcdef0"),
        ("vpc_flow_log", "fl-0123456789abcdef0"),
    }

    normalized_vpc = resources[("vpc", "vpc-0123456789abcdef0")]
    assert normalized_vpc.account_id == COLLECTION_ACCOUNT_ID
    assert normalized_vpc.region == REGION
    assert normalized_vpc.tags == {
        "Environment": "production",
        "Password": "classification-label-not-a-secret",
    }
    assert normalized_vpc.configuration["state"] == "available"
    assert normalized_vpc.configuration["cidr_block"] == "10.0.0.0/16"
    assert normalized_vpc.configuration["is_default"] is False

    normalized_subnet = resources[("subnet", "subnet-0123456789abcdef0")]
    assert normalized_subnet.account_id == COLLECTION_ACCOUNT_ID
    assert normalized_subnet.configuration["vpc_id"] == "vpc-0123456789abcdef0"
    assert normalized_subnet.configuration["state"] == "available"
    assert normalized_subnet.configuration["cidr_block"] == "10.0.1.0/24"
    assert normalized_subnet.configuration["availability_zone"] == f"{REGION}a"
    assert normalized_subnet.configuration["availability_zone_id"] == "usgw1-az1"
    assert normalized_subnet.configuration["map_public_ip_on_launch"] is False

    normalized_flow_log = resources[("vpc_flow_log", "fl-0123456789abcdef0")]
    assert normalized_flow_log.account_id == COLLECTION_ACCOUNT_ID
    assert normalized_flow_log.configuration["resource_id"] == "vpc-0123456789abcdef0"
    assert normalized_flow_log.configuration["flow_log_status"] == "ACTIVE"
    assert normalized_flow_log.configuration["traffic_type"] == "ALL"
    assert normalized_flow_log.configuration["log_destination_type"] == "cloud-watch-logs"
    assert normalized_flow_log.configuration["log_group_name"] == "/aws/vpc/flow-logs"
    assert normalized_flow_log.configuration["log_destination"] == (
        "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:/aws/vpc/flow-logs"
    )
    assert normalized_flow_log.configuration["deliver_logs_permission_arn"] == (
        "arn:aws-us-gov:iam::123456789012:role/vpc-flow-logs"
    )

    assert len(result.source_contracts) == len(result.artifacts) == len(result.source_outcomes) == 6
    assert {outcome.evidence_kind for outcome in result.source_outcomes} == {
        "ec2.vpcs.discovery",
        "ec2.vpc",
        "ec2.subnets.discovery",
        "ec2.subnet",
        "ec2.flow-logs.discovery",
        "ec2.vpc-flow-log",
    }
    assert all(outcome.state is EvidenceSourceState.PRESENT for outcome in result.source_outcomes)
    assert (
        sum(
            outcome.phase is EvidenceCollectionPhase.DISCOVERY for outcome in result.source_outcomes
        )
        == 3
    )
    assert (
        sum(
            outcome.phase is EvidenceCollectionPhase.ENRICHMENT
            for outcome in result.source_outcomes
        )
        == 3
    )
    assert {outcome.source_api for outcome in result.source_outcomes} == {
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeFlowLogs",
    }

    resource_contracts = [
        contract
        for contract in result.source_contracts
        if contract.phase is EvidenceCollectionPhase.ENRICHMENT
    ]
    assert all(contract.identity_authoritative for contract in resource_contracts)
    assert all(
        contract.owner_mode is ResourceOwnerMode.COLLECTION_ACCOUNT
        for contract in resource_contracts
    )
    vpc_artifact = _artifact(result, "ec2.vpc")
    assert {tuple(tag.values()) for tag in vpc_artifact.normalized_payload["tags"]} >= {
        ("Environment", "production"),
        ("Password", "classification-label-not-a-secret"),
    }

    relationships = {
        (
            relationship.relationship_type,
            relationship.source.aws_resource_id,
            relationship.target.aws_resource_id,
        ): relationship
        for relationship in result.relationships
    }
    assert set(relationships) == {
        (
            RelationshipType.CONTAINS_SUBNET,
            "vpc-0123456789abcdef0",
            "subnet-0123456789abcdef0",
        ),
        (
            RelationshipType.HAS_FLOW_LOG,
            "vpc-0123456789abcdef0",
            "fl-0123456789abcdef0",
        ),
    }
    assert (
        relationships[
            (
                RelationshipType.CONTAINS_SUBNET,
                "vpc-0123456789abcdef0",
                "subnet-0123456789abcdef0",
            )
        ].provenance.source_api
        == "ec2:DescribeSubnets"
    )
    assert (
        relationships[
            (
                RelationshipType.HAS_FLOW_LOG,
                "vpc-0123456789abcdef0",
                "fl-0123456789abcdef0",
            )
        ].provenance.source_api
        == "ec2:DescribeFlowLogs"
    )
    assert client.paginator_requests == [
        "describe_vpcs",
        "describe_subnets",
        "describe_flow_logs",
    ]


def test_shared_vpc_and_subnet_preserve_authoritative_external_owner() -> None:
    client = _client(
        vpc_pages=[{"Vpcs": [_vpc("vpc-shared", owner_id=RESOURCE_OWNER_ID)]}],
        subnet_pages=[
            {
                "Subnets": [
                    {
                        **_subnet("subnet-shared", owner_id=RESOURCE_OWNER_ID),
                        "VpcId": "vpc-shared",
                    }
                ]
            }
        ],
    )

    result = _collector(client).collect_with_context(_context())

    resources = {resource.resource_type: resource for resource in result.resources}
    assert resources["vpc"].account_id == RESOURCE_OWNER_ID
    assert resources["subnet"].account_id == RESOURCE_OWNER_ID
    external_contracts = [
        contract
        for contract in result.source_contracts
        if contract.phase is EvidenceCollectionPhase.ENRICHMENT
    ]
    assert all(contract.identity_authoritative for contract in external_contracts)
    assert all(
        contract.owner_mode is ResourceOwnerMode.EXTERNAL_ACCOUNT for contract in external_contracts
    )
    assert all(
        f"/{RESOURCE_OWNER_ID}/" in outcome.evidence_reference
        for outcome in result.source_outcomes
        if outcome.phase is EvidenceCollectionPhase.ENRICHMENT
    )
    edge = result.relationships[0]
    assert edge.relationship_type is RelationshipType.CONTAINS_SUBNET
    assert edge.source.aws_account_id == RESOURCE_OWNER_ID
    assert edge.target.aws_account_id == RESOURCE_OWNER_ID


def test_non_vpc_flow_log_is_retained_without_fabricating_vpc_relationship() -> None:
    client = _client(
        vpc_pages=[{"Vpcs": [_vpc()]}],
        flow_log_pages=[
            {
                "FlowLogs": [
                    _flow_log(
                        "fl-subnet-scoped",
                        resource_id="subnet-0123456789abcdef0",
                    )
                ]
            }
        ],
    )

    result = _collector(client).collect_with_context(_context())

    assert {
        (resource.resource_type, resource.aws_resource_id) for resource in result.resources
    } == {
        ("vpc", "vpc-0123456789abcdef0"),
        ("vpc_flow_log", "fl-subnet-scoped"),
    }
    assert not any(
        relationship.relationship_type is RelationshipType.HAS_FLOW_LOG
        for relationship in result.relationships
    )
    assert _outcome(result, "ec2.flow-logs.discovery").state is EvidenceSourceState.PRESENT


@pytest.mark.parametrize(
    ("source", "malformed", "valid", "resource_type", "valid_id", "evidence_kind"),
    (
        (
            "vpc",
            {key: value for key, value in _vpc("vpc-malformed").items() if key != "OwnerId"},
            _vpc("vpc-valid"),
            "vpc",
            "vpc-valid",
            "ec2.vpcs.discovery",
        ),
        (
            "subnet",
            {**_subnet("subnet-malformed"), "MapPublicIpOnLaunch": "false"},
            _subnet("subnet-valid"),
            "subnet",
            "subnet-valid",
            "ec2.subnets.discovery",
        ),
        (
            "flow_log",
            {
                key: value
                for key, value in _flow_log("fl-malformed").items()
                if key != "TrafficType"
            },
            _flow_log("fl-valid"),
            "vpc_flow_log",
            "fl-valid",
            "ec2.flow-logs.discovery",
        ),
    ),
)
def test_malformed_item_retains_valid_sibling_and_marks_source_partial(
    source: str,
    malformed: dict[str, object],
    valid: dict[str, object],
    resource_type: str,
    valid_id: str,
    evidence_kind: str,
) -> None:
    pages: dict[str, list[object]] = {
        "vpc_pages": [{"Vpcs": []}],
        "subnet_pages": [{"Subnets": []}],
        "flow_log_pages": [{"FlowLogs": []}],
    }
    key_by_source = {"vpc": "Vpcs", "subnet": "Subnets", "flow_log": "FlowLogs"}
    pages[f"{source}_pages"] = [{key_by_source[source]: [malformed, valid]}]

    result = _collector(_client(**pages)).collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert [
        resource.aws_resource_id
        for resource in result.resources
        if resource.resource_type == resource_type
    ] == [valid_id]
    outcome = _outcome(result, evidence_kind)
    assert outcome.state is EvidenceSourceState.MALFORMED
    assert outcome.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    discovery_artifact = _artifact(result, evidence_kind)
    assert discovery_artifact.normalized_payload["discarded_item_count"] == 1


@pytest.mark.parametrize(
    ("source", "item", "evidence_kind"),
    (
        ("vpc", _without(_vpc(), "VpcId"), "ec2.vpcs.discovery"),
        ("vpc", {**_vpc(), "VpcId": "vpc-unsafe\nidentifier"}, "ec2.vpcs.discovery"),
        ("vpc", _without(_vpc(), "OwnerId"), "ec2.vpcs.discovery"),
        ("vpc", {**_vpc(), "OwnerId": "not-an-account"}, "ec2.vpcs.discovery"),
        ("subnet", _without(_subnet(), "SubnetId"), "ec2.subnets.discovery"),
        ("subnet", _without(_subnet(), "OwnerId"), "ec2.subnets.discovery"),
        ("subnet", _without(_subnet(), "VpcId"), "ec2.subnets.discovery"),
        (
            "subnet",
            {**_subnet(), "VpcId": "vpc-unsafe\x1fidentifier"},
            "ec2.subnets.discovery",
        ),
        (
            "subnet",
            {
                **_subnet(),
                "SubnetArn": (
                    "arn:aws-us-gov:ec2:us-gov-west-1:999999999999:subnet/subnet-0123456789abcdef0"
                ),
            },
            "ec2.subnets.discovery",
        ),
        (
            "subnet",
            _without(_subnet(), "MapPublicIpOnLaunch"),
            "ec2.subnets.discovery",
        ),
        (
            "subnet",
            {**_subnet(), "MapPublicIpOnLaunch": "false"},
            "ec2.subnets.discovery",
        ),
        (
            "flow_log",
            _without(_flow_log(), "FlowLogId"),
            "ec2.flow-logs.discovery",
        ),
        (
            "flow_log",
            _without(_flow_log(), "ResourceId"),
            "ec2.flow-logs.discovery",
        ),
        (
            "flow_log",
            {**_flow_log(), "ResourceId": "vpc-unsafe\ridentifier"},
            "ec2.flow-logs.discovery",
        ),
        (
            "flow_log",
            _without(_flow_log(), "FlowLogStatus"),
            "ec2.flow-logs.discovery",
        ),
        (
            "flow_log",
            {**_flow_log(), "FlowLogStatus": "DELETING"},
            "ec2.flow-logs.discovery",
        ),
        (
            "flow_log",
            _without(_flow_log(), "TrafficType"),
            "ec2.flow-logs.discovery",
        ),
        (
            "flow_log",
            _without(_flow_log(), "LogDestinationType"),
            "ec2.flow-logs.discovery",
        ),
        (
            "flow_log",
            _without(_without(_flow_log(), "LogGroupName"), "LogDestination"),
            "ec2.flow-logs.discovery",
        ),
        (
            "flow_log",
            _without(
                {
                    **_flow_log(),
                    "LogDestinationType": "s3",
                },
                "LogDestination",
            ),
            "ec2.flow-logs.discovery",
        ),
    ),
)
def test_required_identity_and_network_facts_fail_closed(
    source: str,
    item: dict[str, object],
    evidence_kind: str,
) -> None:
    page_key = {"vpc": "Vpcs", "subnet": "Subnets", "flow_log": "FlowLogs"}[source]
    pages = {f"{source}_pages": [{page_key: [item]}]}

    result = _collector(_client(**pages)).collect_with_context(_context())

    outcome = _outcome(result, evidence_kind)
    assert outcome.state is EvidenceSourceState.MALFORMED
    assert outcome.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert result.status is CollectionStatus.PARTIAL
    assert _artifact(result, evidence_kind).normalized_payload["discarded_item_count"] == 1


@pytest.mark.parametrize("malformed_first", [True, False])
@pytest.mark.parametrize("source", ["vpc", "subnet", "flow_log"])
def test_conflicting_duplicate_identity_is_rejected_regardless_of_order(
    source: str,
    malformed_first: bool,
) -> None:
    if source == "vpc":
        first = _vpc("vpc-conflict")
        second = deepcopy(first)
        second["Tags"] = [{"Key": "Environment", "Value": "staging"}]
        pages = {"vpc_pages": [{"Vpcs": [first, second]}]}
        resource_type = "vpc"
        resource_id = "vpc-conflict"
        evidence_kind = "ec2.vpcs.discovery"
    elif source == "subnet":
        first = _subnet("subnet-conflict")
        second = deepcopy(first)
        second["MapPublicIpOnLaunch"] = True
        pages = {"subnet_pages": [{"Subnets": [first, second]}]}
        resource_type = "subnet"
        resource_id = "subnet-conflict"
        evidence_kind = "ec2.subnets.discovery"
    else:
        first = _flow_log("fl-conflict")
        second = deepcopy(first)
        second["TrafficType"] = "REJECT"
        pages = {"flow_log_pages": [{"FlowLogs": [first, second]}]}
        resource_type = "vpc_flow_log"
        resource_id = "fl-conflict"
        evidence_kind = "ec2.flow-logs.discovery"
    ordered = [second, first] if malformed_first else [first, second]
    page_key = {"vpc": "Vpcs", "subnet": "Subnets", "flow_log": "FlowLogs"}[source]
    pages[f"{source}_pages"] = [{page_key: ordered}]

    result = _collector(_client(**pages)).collect_with_context(_context())

    assert not any(
        resource.resource_type == resource_type and resource.aws_resource_id == resource_id
        for resource in result.resources
    )
    outcome = _outcome(result, evidence_kind)
    assert outcome.state is EvidenceSourceState.CONFLICT
    assert outcome.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    discovery_artifact = _artifact(result, evidence_kind)
    assert discovery_artifact.normalized_payload["discarded_item_count"] == 2


@pytest.mark.parametrize("malformed_first", [True, False])
@pytest.mark.parametrize("source", ["vpc", "subnet", "flow_log"])
def test_malformed_and_valid_duplicate_identity_is_conflict_regardless_of_order(
    source: str,
    malformed_first: bool,
) -> None:
    if source == "vpc":
        valid = _vpc("vpc-conflict")
        malformed = _without(valid, "OwnerId")
        pages = {"vpc_pages": [{"Vpcs": []}]}
        resource_type = "vpc"
        resource_id = "vpc-conflict"
        evidence_kind = "ec2.vpcs.discovery"
        page_key = "Vpcs"
    elif source == "subnet":
        valid = _subnet("subnet-conflict")
        malformed = _without(valid, "MapPublicIpOnLaunch")
        pages = {"subnet_pages": [{"Subnets": []}]}
        resource_type = "subnet"
        resource_id = "subnet-conflict"
        evidence_kind = "ec2.subnets.discovery"
        page_key = "Subnets"
    else:
        valid = _flow_log("fl-conflict")
        malformed = _without(valid, "TrafficType")
        pages = {"flow_log_pages": [{"FlowLogs": []}]}
        resource_type = "vpc_flow_log"
        resource_id = "fl-conflict"
        evidence_kind = "ec2.flow-logs.discovery"
        page_key = "FlowLogs"
    ordered = [malformed, valid] if malformed_first else [valid, malformed]
    pages[f"{source}_pages"] = [{page_key: ordered}]

    result = _collector(_client(**pages)).collect_with_context(_context())

    assert not any(
        resource.resource_type == resource_type and resource.aws_resource_id == resource_id
        for resource in result.resources
    )
    outcome = _outcome(result, evidence_kind)
    assert outcome.state is EvidenceSourceState.CONFLICT
    assert outcome.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    assert _artifact(result, evidence_kind).normalized_payload["discarded_item_count"] == 2


def test_partial_pagination_retains_valid_vpc_and_sanitizes_failure() -> None:
    class PartialPaginator(FakePaginator):
        def paginate(self, **kwargs: object):  # type: ignore[no-untyped-def]
            self.calls.append(dict(kwargs))
            yield {"Vpcs": [_vpc()]}
            raise client_error("RequestLimitExceeded", "DescribeVpcs", status_code=503)

    client = FakeAWSClient(
        paginators={
            "describe_vpcs": PartialPaginator(),
            "describe_subnets": FakePaginator([{"Subnets": []}]),
            "describe_flow_logs": FakePaginator([{"FlowLogs": []}]),
        }
    )

    result = _collector(client).collect_with_context(_context())

    assert [resource.aws_resource_id for resource in result.resources] == ["vpc-0123456789abcdef0"]
    outcome = _outcome(result, "ec2.vpcs.discovery")
    assert outcome.state is EvidenceSourceState.UNAVAILABLE
    assert outcome.failure_category is EvidenceFailureCategory.THROTTLED
    assert result.status is CollectionStatus.PARTIAL
    serialized = "".join(
        item.model_dump_json()
        for item in (*result.source_contracts, *result.artifacts, *result.source_outcomes)
    )
    assert "simulated" not in serialized


def test_flow_log_access_denial_retains_independent_vpc_and_subnet_evidence() -> None:
    client = _client(
        vpc_pages=[{"Vpcs": [_vpc()]}],
        subnet_pages=[{"Subnets": [_subnet()]}],
        flow_log_error=client_error("UnauthorizedOperation", "DescribeFlowLogs", status_code=403),
    )

    result = _collector(client).collect_with_context(_context())

    assert {
        (resource.resource_type, resource.aws_resource_id) for resource in result.resources
    } == {
        ("vpc", "vpc-0123456789abcdef0"),
        ("subnet", "subnet-0123456789abcdef0"),
    }
    flow_outcome = _outcome(result, "ec2.flow-logs.discovery")
    assert flow_outcome.state is EvidenceSourceState.UNAVAILABLE
    assert flow_outcome.failure_category is EvidenceFailureCategory.ACCESS_DENIED
    assert result.status is CollectionStatus.PARTIAL
    assert not any(
        relationship.relationship_type is RelationshipType.HAS_FLOW_LOG
        for relationship in result.relationships
    )


def test_absent_tags_are_complete_empty_maps() -> None:
    vpc = _vpc()
    subnet = _subnet()
    flow_log = _flow_log()
    vpc.pop("Tags")
    subnet.pop("Tags")
    flow_log.pop("Tags")

    result = _collector(
        _client(
            vpc_pages=[{"Vpcs": [vpc]}],
            subnet_pages=[{"Subnets": [subnet]}],
            flow_log_pages=[{"FlowLogs": [flow_log]}],
        )
    ).collect_with_context(_context())

    assert result.status is CollectionStatus.SUCCEEDED
    assert all(resource.tags == {} for resource in result.resources)


@pytest.mark.parametrize("source", ["vpc", "subnet", "flow_log"])
def test_malformed_present_tags_fail_closed_without_losing_other_sources(source: str) -> None:
    item_by_source = {
        "vpc": _vpc(),
        "subnet": _subnet(),
        "flow_log": _flow_log(),
    }
    item_by_source[source]["Tags"] = [{"Key": "Environment", "Value": None}]
    page_key = {"vpc": "Vpcs", "subnet": "Subnets", "flow_log": "FlowLogs"}[source]
    pages = {f"{source}_pages": [{page_key: [item_by_source[source]]}]}

    result = _collector(_client(**pages)).collect_with_context(_context())

    evidence_kind = {
        "vpc": "ec2.vpcs.discovery",
        "subnet": "ec2.subnets.discovery",
        "flow_log": "ec2.flow-logs.discovery",
    }[source]
    outcome = _outcome(result, evidence_kind)
    assert outcome.state is EvidenceSourceState.MALFORMED
    assert outcome.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert result.status is CollectionStatus.PARTIAL
