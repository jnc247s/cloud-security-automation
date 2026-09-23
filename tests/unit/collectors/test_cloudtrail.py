"""Tests for CloudTrail trail collection."""

import hashlib
from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID

import pytest
from botocore.exceptions import ClientError

from app.assessment.relationships import RelationshipType, UnresolvedRelationshipTarget
from app.assessment.source_outcomes import EvidenceFailureCategory, EvidenceSourceState
from app.collectors.base import CollectionContext, CollectorEvidenceError
from app.collectors.cloudtrail import (
    CloudTrailCollectionBundle,
    CloudTrailCollector,
    CloudTrailEvidenceCollector,
)
from app.schemas.inventory import CollectionStatus
from app.services.inventory_service import InventoryService
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, RecordedCall, client_error

TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/TestTrail"
HOME_REGION = "us-east-1"
ACCOUNT_ID = "123456789012"
EXTERNAL_ACCOUNT_ID = "210987654321"
SCAN_ID = UUID("724d5044-ca5d-54d3-a96c-bd0d81546fd0")
COLLECTED_AT = datetime(2026, 9, 23, 14, 30, tzinfo=UTC)


def _trail(arn: str, name: str, home_region: str, *, multi_region: bool) -> dict[str, object]:
    return {
        "Name": name,
        "S3BucketName": f"{name.lower()}-logs",
        "IncludeGlobalServiceEvents": True,
        "IsMultiRegionTrail": multi_region,
        "HomeRegion": home_region,
        "TrailARN": arn,
        "LogFileValidationEnabled": True,
    }


def _collector_for_one_trail(
    *,
    summary: dict[str, object] | None = None,
    trail_response: dict[str, object] | BaseException | None = None,
    status_response: dict[str, object] | BaseException | None = None,
    tag_pages: list[dict[str, object]] | None = None,
) -> tuple[CloudTrailCollector, FakeAWSClient]:
    resolved_summary = (
        summary
        if summary is not None
        else {
            "TrailARN": TRAIL_ARN,
            "Name": "TestTrail",
            "HomeRegion": HOME_REGION,
        }
    )
    resolved_trail_response = (
        trail_response
        if trail_response is not None
        else {"Trail": _trail(TRAIL_ARN, "TestTrail", HOME_REGION, multi_region=True)}
    )
    resolved_status_response = (
        status_response if status_response is not None else {"IsLogging": True}
    )
    resolved_tag_pages = tag_pages if tag_pages is not None else [{"ResourceTagList": []}]
    client = FakeAWSClient(
        paginators={
            "list_trails": FakePaginator([{"Trails": [resolved_summary]}]),
            "list_tags": FakePaginator(resolved_tag_pages),
        },
        responses={
            "get_trail": [resolved_trail_response],
            "get_trail_status": [resolved_status_response],
        },
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})
    return CloudTrailCollector(provider), client


def _context(
    *,
    account_id: str = ACCOUNT_ID,
    region: str = HOME_REGION,
) -> CollectionContext:
    return CollectionContext(
        scan_id=SCAN_ID,
        collection_account_id=account_id,
        region=region,
        collected_at=COLLECTED_AT,
    )


def _five_f_one_trail(
    *,
    trail_arn: str = TRAIL_ARN,
    name: str = "TestTrail",
    home_region: str = HOME_REGION,
    collection_account_id: str = ACCOUNT_ID,
    trail_response: dict[str, object] | BaseException | None = None,
    status_response: dict[str, object] | BaseException | None = None,
    selector_response: dict[str, object] | BaseException | None = None,
    tag_pages: list[dict[str, object]] | None = None,
) -> tuple[
    FakeClientProvider,
    CloudTrailCollectionBundle,
    CloudTrailCollector,
    CloudTrailEvidenceCollector,
    FakeAWSClient,
]:
    resolved_trail = (
        trail_response
        if trail_response is not None
        else {"Trail": _trail(trail_arn, name, home_region, multi_region=True)}
    )
    resolved_status = status_response if status_response is not None else {"IsLogging": True}
    resolved_selectors = (
        selector_response
        if selector_response is not None
        else {"TrailARN": trail_arn, "EventSelectors": [{}]}
    )
    resolved_tags = (
        tag_pages
        if tag_pages is not None
        else [{"ResourceTagList": [{"ResourceId": trail_arn, "TagsList": []}]}]
    )
    client = FakeAWSClient(
        paginators={
            "list_trails": FakePaginator(
                [
                    {
                        "Trails": [
                            {
                                "TrailARN": trail_arn,
                                "Name": name,
                                "HomeRegion": home_region,
                            }
                        ]
                    }
                ]
            ),
            "list_tags": FakePaginator(resolved_tags),
        },
        responses={
            "get_trail": [resolved_trail],
            "get_trail_status": [resolved_status],
            "get_event_selectors": [resolved_selectors],
        },
    )
    provider = FakeClientProvider(
        {("cloudtrail", home_region): client},
        region_name=home_region,
        account_id=collection_account_id,
    )
    bundle = CloudTrailCollectionBundle(provider)
    return (
        provider,
        bundle,
        CloudTrailCollector(provider, collection_bundle=bundle),
        CloudTrailEvidenceCollector(provider, collection_bundle=bundle),
        client,
    )


def _artifact_payload(result, evidence_kind: str) -> dict[str, object]:
    artifacts = [
        artifact for artifact in result.artifacts if artifact.evidence_schema == evidence_kind
    ]
    assert len(artifacts) == 1
    payload = artifacts[0].model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    return payload


def _outcome(result, evidence_kind: str):
    outcomes = [
        outcome for outcome in result.source_outcomes if outcome.evidence_kind == evidence_kind
    ]
    assert len(outcomes) == 1
    return outcomes[0]


def test_collects_all_pages_deduplicates_and_uses_trail_home_regions() -> None:
    east_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/EastTrail"
    west_arn = "arn:aws:cloudtrail:us-west-2:123456789012:trail/WestTrail"
    discovery_pages = FakePaginator(
        [
            {"Trails": [{"TrailARN": east_arn, "Name": "EastTrail", "HomeRegion": "us-east-1"}]},
            {"Trails": []},
            {
                "Trails": [
                    {"TrailARN": east_arn, "Name": "EastTrail", "HomeRegion": "us-east-1"},
                    {"TrailARN": west_arn, "Name": "WestTrail", "HomeRegion": "us-west-2"},
                ]
            },
        ]
    )
    east_tags = FakePaginator(
        [
            {
                "ResourceTagList": [
                    {"ResourceId": east_arn, "TagsList": [{"Key": "Owner", "Value": "audit"}]}
                ]
            },
            {
                "ResourceTagList": [
                    {
                        "ResourceId": east_arn,
                        "TagsList": [{"Key": "Environment", "Value": "test"}],
                    }
                ]
            },
        ]
    )
    west_tags = FakePaginator([{"ResourceTagList": []}])
    east_client = FakeAWSClient(
        paginators={"list_trails": discovery_pages, "list_tags": east_tags},
        responses={
            "get_trail": [{"Trail": _trail(east_arn, "EastTrail", "us-east-1", multi_region=True)}],
            "get_trail_status": [
                {
                    "IsLogging": True,
                    "LatestDeliveryTime": datetime(2025, 4, 5, tzinfo=UTC),
                    "ResponseMetadata": {"HTTPStatusCode": 200},
                }
            ],
        },
    )
    west_client = FakeAWSClient(
        paginators={"list_tags": west_tags},
        responses={
            "get_trail": [
                {"Trail": _trail(west_arn, "WestTrail", "us-west-2", multi_region=False)}
            ],
            "get_trail_status": [{"IsLogging": False}],
        },
    )
    provider = FakeClientProvider(
        {
            ("cloudtrail", "us-east-1"): east_client,
            ("cloudtrail", "us-west-2"): west_client,
        }
    )

    resources = CloudTrailCollector(provider).collect()

    assert [resource.arn for resource in resources] == [east_arn, west_arn]
    assert discovery_pages.calls == [{}]
    assert resources[0].region == "us-east-1"
    assert resources[0].tags == {"Owner": "audit", "Environment": "test"}
    assert resources[0].configuration["is_multi_region_trail"] is True
    assert resources[0].configuration["is_logging"] is True
    assert resources[0].configuration["status"] == {
        "IsLogging": True,
        "LatestDeliveryTime": "2025-04-05T00:00:00+00:00",
    }
    assert resources[1].region == "us-west-2"
    assert resources[1].configuration["is_logging"] is False
    assert east_client.calls.count(RecordedCall("get_trail", {"Name": east_arn})) == 1
    assert provider.client_requests == [
        ("cloudtrail", "us-east-1"),
        ("cloudtrail", "us-east-1"),
        ("cloudtrail", "us-west-2"),
    ]


def test_propagates_cloudtrail_status_errors() -> None:
    trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/DeniedTrail"
    discovery = FakePaginator(
        [
            {
                "Trails": [
                    {
                        "TrailARN": trail_arn,
                        "Name": "DeniedTrail",
                        "HomeRegion": "us-east-1",
                    }
                ]
            }
        ]
    )
    error = client_error("AccessDeniedException", "GetTrailStatus", status_code=403)
    client = FakeAWSClient(
        paginators={"list_trails": discovery},
        responses={
            "get_trail": [
                {"Trail": _trail(trail_arn, "DeniedTrail", "us-east-1", multi_region=False)}
            ],
            "get_trail_status": [error],
        },
    )
    provider = FakeClientProvider({("cloudtrail", "us-east-1"): client})

    with pytest.raises(ClientError) as exc_info:
        CloudTrailCollector(provider).collect()

    assert exc_info.value.response["Error"]["Code"] == "AccessDeniedException"


def test_valid_empty_trail_inventory_is_not_malformed() -> None:
    client = FakeAWSClient(
        paginators={"list_trails": FakePaginator([{"Trails": []}])},
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})

    assert CloudTrailCollector(provider).collect() == []


@pytest.mark.parametrize("field_name", ("TrailARN", "HomeRegion"))
@pytest.mark.parametrize(
    "value", (None, 42, "", "   "), ids=("null", "wrong-type", "empty", "blank")
)
def test_rejects_unusable_required_trail_summary_identity(
    field_name: str,
    value: object,
) -> None:
    summary: dict[str, object] = {
        "TrailARN": TRAIL_ARN,
        "Name": "TestTrail",
        "HomeRegion": HOME_REGION,
        field_name: value,
    }
    collector, _client = _collector_for_one_trail(summary=summary)

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert field_name in exc_info.value.fact_path
    if value not in {"", "   "}:
        assert str(value) not in str(exc_info.value)


@pytest.mark.parametrize("field_name", ("TrailARN", "HomeRegion"))
def test_rejects_missing_required_trail_summary_identity(field_name: str) -> None:
    summary: dict[str, object] = {
        "TrailARN": TRAIL_ARN,
        "Name": "TestTrail",
        "HomeRegion": HOME_REGION,
    }
    summary.pop(field_name)
    collector, _client = _collector_for_one_trail(summary=summary)

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert field_name in exc_info.value.fact_path


@pytest.mark.parametrize("value", (None, 7, ""), ids=("null", "wrong-type", "empty"))
def test_rejects_malformed_optional_summary_name(value: object) -> None:
    collector, _client = _collector_for_one_trail(
        summary={
            "TrailARN": TRAIL_ARN,
            "Name": value,
            "HomeRegion": HOME_REGION,
        }
    )

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.fact_path == "Trails[].Name"


def test_rejects_malformed_trail_page_result() -> None:
    client = FakeAWSClient(
        paginators={"list_trails": FakePaginator([{"Trails": None}])},
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})

    with pytest.raises(CollectorEvidenceError, match="list_trails"):
        CloudTrailCollector(provider).collect()


def test_rejects_conflicting_duplicate_trail_summary() -> None:
    summaries = [
        {"TrailARN": TRAIL_ARN, "Name": "TestTrail", "HomeRegion": HOME_REGION},
        {"TrailARN": TRAIL_ARN, "Name": "ChangedTrail", "HomeRegion": HOME_REGION},
    ]
    client = FakeAWSClient(
        paginators={
            "list_trails": FakePaginator([{"Trails": summaries}]),
            "list_tags": FakePaginator([{"ResourceTagList": []}]),
        },
        responses={
            "get_trail": [
                {"Trail": _trail(TRAIL_ARN, "TestTrail", HOME_REGION, multi_region=True)}
            ],
            "get_trail_status": [{"IsLogging": True}],
        },
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})

    with pytest.raises(CollectorEvidenceError) as exc_info:
        CloudTrailCollector(provider).collect()

    assert exc_info.value.fact_path == "Trails[].duplicate_identity"


@pytest.mark.parametrize(
    "trail_value",
    (None, [], "not-an-object"),
    ids=("null", "list", "string"),
)
def test_rejects_malformed_get_trail_object(trail_value: object) -> None:
    collector, _client = _collector_for_one_trail(
        trail_response={"Trail": trail_value},
    )

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.operation_name == "get_trail"
    assert exc_info.value.fact_path == "Trail"


def test_rejects_missing_get_trail_object() -> None:
    collector, _client = _collector_for_one_trail(trail_response={})

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.fact_path == "Trail"


def test_rejects_non_mapping_get_trail_response(monkeypatch) -> None:
    collector, client = _collector_for_one_trail()
    monkeypatch.setattr(client, "get_trail", Mock(return_value=None), raising=False)

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.operation_name == "get_trail"
    assert exc_info.value.fact_path == "response"


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("TrailARN", None),
        ("TrailARN", 7),
        ("TrailARN", "arn:aws:cloudtrail:us-east-1:123456789012:trail/Other"),
        ("HomeRegion", None),
        ("HomeRegion", "us-west-2"),
        ("Name", 7),
        ("S3BucketName", False),
        ("IncludeGlobalServiceEvents", "true"),
        ("IsMultiRegionTrail", 1),
    ),
)
def test_rejects_invalid_or_inconsistent_get_trail_fields(
    field_name: str,
    value: object,
) -> None:
    trail = _trail(TRAIL_ARN, "TestTrail", HOME_REGION, multi_region=True)
    trail[field_name] = value
    collector, _client = _collector_for_one_trail(trail_response={"Trail": trail})

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.operation_name == "get_trail"
    assert field_name in exc_info.value.fact_path
    assert str(value) not in str(exc_info.value)


@pytest.mark.parametrize(
    "status_response",
    ({}, {"IsLogging": None}, {"IsLogging": "true"}, {"IsLogging": 1}),
    ids=("missing", "null", "string", "integer"),
)
def test_rejects_missing_or_non_boolean_logging_status(
    status_response: dict[str, object],
) -> None:
    collector, _client = _collector_for_one_trail(status_response=status_response)

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.operation_name == "get_trail_status"
    assert exc_info.value.fact_path == "IsLogging"


def test_rejects_non_mapping_status_response(monkeypatch) -> None:
    collector, client = _collector_for_one_trail()
    monkeypatch.setattr(client, "get_trail_status", Mock(return_value=[]), raising=False)

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.operation_name == "get_trail_status"
    assert exc_info.value.fact_path == "response"


def test_missing_tag_list_and_missing_tag_value_have_explicit_empty_semantics() -> None:
    collector, _client = _collector_for_one_trail(
        tag_pages=[
            {
                "ResourceTagList": [
                    {"ResourceId": TRAIL_ARN},
                    {
                        "ResourceId": TRAIL_ARN,
                        "TagsList": [{"Key": "EmptyValue"}],
                    },
                ]
            }
        ]
    )

    resources = collector.collect()

    assert resources[0].tags == {"EmptyValue": ""}


@pytest.mark.parametrize(
    "resource_tags",
    (
        {},
        {"ResourceId": None, "TagsList": []},
        {"ResourceId": 7, "TagsList": []},
        {"ResourceId": "arn:aws:cloudtrail:us-east-1:123456789012:trail/Other", "TagsList": []},
        {"ResourceId": TRAIL_ARN, "TagsList": None},
        {"ResourceId": TRAIL_ARN, "TagsList": "not-a-list"},
        {"ResourceId": TRAIL_ARN, "TagsList": [None]},
        {"ResourceId": TRAIL_ARN, "TagsList": [{}]},
        {"ResourceId": TRAIL_ARN, "TagsList": [{"Key": None}]},
        {"ResourceId": TRAIL_ARN, "TagsList": [{"Key": 7}]},
        {"ResourceId": TRAIL_ARN, "TagsList": [{"Key": ""}]},
        {"ResourceId": TRAIL_ARN, "TagsList": [{"Key": "Owner", "Value": None}]},
        {"ResourceId": TRAIL_ARN, "TagsList": [{"Key": "Owner", "Value": 7}]},
    ),
    ids=(
        "missing-resource-id",
        "null-resource-id",
        "wrong-resource-id-type",
        "mismatched-resource-id",
        "null-tag-list",
        "wrong-tag-list-type",
        "wrong-tag-item-type",
        "missing-tag-key",
        "null-tag-key",
        "wrong-tag-key-type",
        "empty-tag-key",
        "null-tag-value",
        "wrong-tag-value-type",
    ),
)
def test_rejects_malformed_or_mismatched_tag_evidence(
    resource_tags: dict[str, object],
) -> None:
    collector, _client = _collector_for_one_trail(tag_pages=[{"ResourceTagList": [resource_tags]}])

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.operation_name == "list_tags"
    assert "TOP-SECRET" not in str(exc_info.value)


def test_rejects_conflicting_duplicate_tag_values_across_pages() -> None:
    collector, _client = _collector_for_one_trail(
        tag_pages=[
            {
                "ResourceTagList": [
                    {"ResourceId": TRAIL_ARN, "TagsList": [{"Key": "Owner", "Value": "one"}]}
                ]
            },
            {
                "ResourceTagList": [
                    {"ResourceId": TRAIL_ARN, "TagsList": [{"Key": "Owner", "Value": "two"}]}
                ]
            },
        ]
    )

    with pytest.raises(CollectorEvidenceError) as exc_info:
        collector.collect()

    assert exc_info.value.operation_name == "list_tags"


def test_propagates_cloudtrail_throttling_errors() -> None:
    error = client_error("ThrottlingException", "ListTrails", status_code=429)
    client = FakeAWSClient(
        paginators={"list_trails": FakePaginator(error=error)},
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})

    with pytest.raises(ClientError) as exc_info:
        CloudTrailCollector(provider).collect()

    assert exc_info.value.response["Error"]["Code"] == "ThrottlingException"


def test_5f_shared_bundle_collects_once_and_emits_exact_fact_graph() -> None:
    kms_arn = f"arn:aws:kms:{HOME_REGION}:{ACCOUNT_ID}:key/key-123"
    trail = _trail(TRAIL_ARN, "TestTrail", HOME_REGION, multi_region=True)
    trail.update(
        {
            "S3KeyPrefix": "audit",
            "CloudWatchLogsLogGroupArn": (
                f"arn:aws:logs:{HOME_REGION}:{ACCOUNT_ID}:log-group:trail:*"
            ),
            "CloudWatchLogsRoleArn": f"arn:aws:iam::{ACCOUNT_ID}:role/CloudTrailLogs",
            "KmsKeyId": kms_arn,
            "IsOrganizationTrail": False,
            # Newer CloudTrail API models return this optional member. The 5F contract does not
            # consume it, but a valid response containing it must remain compatible.
            "RecursiveLogging": False,
        }
    )
    provider, bundle, legacy, evidence, client = _five_f_one_trail(
        trail_response={"Trail": trail},
        status_response={
            "IsLogging": True,
            "LatestDeliveryTime": datetime(2026, 9, 23, 14, tzinfo=UTC),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
        selector_response={
            "TrailARN": TRAIL_ARN,
            "EventSelectors": [
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {
                            "Type": "AWS::S3::Object",
                            "Values": ["arn:aws:s3:::z/", "arn:aws:s3:::a/"],
                        }
                    ],
                    "ExcludeManagementEventSources": ["kms.amazonaws.com"],
                }
            ],
        },
        tag_pages=[
            {
                "ResourceTagList": [
                    {
                        "ResourceId": TRAIL_ARN,
                        "TagsList": [
                            {"Key": "Owner", "Value": "audit"},
                            {"Key": "Environment", "Value": "test"},
                        ],
                    }
                ]
            }
        ],
    )
    context = _context()

    legacy_result = legacy.collect_with_context(context)
    graph_result = evidence.collect_with_context(context)

    assert legacy.collection_bundle is bundle
    assert evidence.collection_bundle is bundle
    assert legacy_result.status is CollectionStatus.SUCCEEDED
    assert graph_result.status is CollectionStatus.SUCCEEDED
    assert graph_result.resources == ()
    assert provider.client_requests == [("cloudtrail", HOME_REGION)]
    assert client.paginator_requests == ["list_trails", "list_tags"]
    assert client.calls == [
        RecordedCall("get_trail", {"Name": TRAIL_ARN}),
        RecordedCall("get_trail_status", {"Name": TRAIL_ARN}),
        RecordedCall("get_event_selectors", {"TrailName": TRAIL_ARN}),
    ]

    assert len(legacy_result.resources) == 1
    resource = legacy_result.resources[0]
    assert resource.account_id == ACCOUNT_ID
    assert resource.aws_resource_id == TRAIL_ARN
    assert resource.arn == TRAIL_ARN
    assert resource.name == "TestTrail"
    assert resource.region == HOME_REGION
    assert resource.tags == {"Environment": "test", "Owner": "audit"}
    selector_value = {
        "selector_form": "BASIC",
        "basic_selectors": [
            {
                "raw_presence": {
                    "include_management_events": True,
                    "read_write_type": True,
                    "exclude_management_event_sources": True,
                    "data_resources": True,
                },
                "include_management_events": True,
                "read_write_type": "All",
                "exclude_management_event_sources": ["kms.amazonaws.com"],
                "data_resources": [
                    {
                        "type": "AWS::S3::Object",
                        "values": ["arn:aws:s3:::a/", "arn:aws:s3:::z/"],
                    }
                ],
            }
        ],
        "advanced_selectors": [],
    }
    assert resource.configuration == {
        "home_region": HOME_REGION,
        "s3_bucket_name": "testtrail-logs",
        "s3_key_prefix": "audit",
        "include_global_service_events": True,
        "is_multi_region_trail": True,
        "log_file_validation_enabled": True,
        "cloudwatch_logs_log_group_arn": (
            f"arn:aws:logs:{HOME_REGION}:{ACCOUNT_ID}:log-group:trail:*"
        ),
        "cloudwatch_logs_role_arn": f"arn:aws:iam::{ACCOUNT_ID}:role/CloudTrailLogs",
        "kms_key_id": kms_arn,
        "is_organization_trail": False,
        "is_logging": True,
        "status": {
            "IsLogging": True,
            "LatestDeliveryTime": "2026-09-23T14:00:00+00:00",
        },
        "event_selectors": selector_value,
        "source_states": {
            "identity": "PRESENT",
            "configuration": "PRESENT",
            "status": "PRESENT",
            "event_selectors": "PRESENT",
            "tags": "PRESENT",
        },
    }
    assert resource.raw_configuration == {
        "summary": {
            "TrailARN": TRAIL_ARN,
            "Name": "TestTrail",
            "HomeRegion": HOME_REGION,
        },
        "trail": {
            "name": "TestTrail",
            "s3_bucket_name": "testtrail-logs",
            "s3_key_prefix": "audit",
            "include_global_service_events": True,
            "is_multi_region_trail": True,
            "log_file_validation_enabled": True,
            "cloudwatch_logs_log_group_arn": (
                f"arn:aws:logs:{HOME_REGION}:{ACCOUNT_ID}:log-group:trail:*"
            ),
            "cloudwatch_logs_role_arn": f"arn:aws:iam::{ACCOUNT_ID}:role/CloudTrailLogs",
            "kms_key_id": kms_arn,
            "is_organization_trail": False,
        },
        "status": {
            "IsLogging": True,
            "LatestDeliveryTime": "2026-09-23T14:00:00+00:00",
        },
        "event_selectors": selector_value,
    }

    expected_sources = {
        "cloudtrail.trails.discovery": ("cloudtrail.trails", "cloudtrail:ListTrails"),
        "cloudtrail.trail.identity": ("cloudtrail.trails", "cloudtrail:ListTrails"),
        "cloudtrail.trail.configuration": (
            "cloudtrail.trail-configuration",
            "cloudtrail:GetTrail",
        ),
        "cloudtrail.trail.status": (
            "cloudtrail.trail-status",
            "cloudtrail:GetTrailStatus",
        ),
        "cloudtrail.trail.event-selectors": (
            "cloudtrail.trail-event-selectors",
            "cloudtrail:GetEventSelectors",
        ),
        "cloudtrail.trail.tags": ("cloudtrail.trail-tags", "cloudtrail:ListTags"),
    }
    assert {
        outcome.evidence_kind: (outcome.collector, outcome.source_api)
        for outcome in graph_result.source_outcomes
    } == expected_sources
    assert all(
        not contract.allows_supplemental_region for contract in graph_result.source_contracts
    )
    assert {
        contract.evidence_kind
        for contract in graph_result.source_contracts
        if contract.identity_authoritative
    } == {"cloudtrail.trail.identity"}
    assert _artifact_payload(graph_result, "cloudtrail.trails.discovery") == {
        "collection_account_id": ACCOUNT_ID,
        "invocation_region": HOME_REGION,
        "trail_arns": [TRAIL_ARN],
        "trail_count": 1,
        "discarded_item_count": 0,
        "admission_complete": True,
        "unadmitted_resources": [],
        "complete": True,
        "failure_category": None,
    }
    assert _artifact_payload(graph_result, "cloudtrail.trail.identity") == {
        "collection_account_id": ACCOUNT_ID,
        "owner_account_id": ACCOUNT_ID,
        "partition": "aws",
        "trail_arn": TRAIL_ARN,
        "name": "TestTrail",
        "home_region": HOME_REGION,
        "complete": True,
        "failure_category": None,
    }
    assert (
        _artifact_payload(graph_result, "cloudtrail.trail.event-selectors")["value"]
        == selector_value
    )
    assert _artifact_payload(graph_result, "cloudtrail.trail.tags")["value"] == [
        {"key": "Environment", "value": "test"},
        {"key": "Owner", "value": "audit"},
    ]

    assert len(graph_result.relationships) == 2
    bucket_relationship = next(
        item
        for item in graph_result.relationships
        if item.relationship_type is RelationshipType.DELIVERS_TO_BUCKET
    )
    assert isinstance(bucket_relationship.target, UnresolvedRelationshipTarget)
    assert bucket_relationship.target.aws_resource_id == "testtrail-logs"
    assert bucket_relationship.target.aws_account_id is None
    assert bucket_relationship.target.region is None
    assert bucket_relationship.target_collector_name == "s3_evidence"
    assert bucket_relationship.target_evidence_kind == "s3.buckets.discovery"
    kms_relationship = next(
        item
        for item in graph_result.relationships
        if item.relationship_type is RelationshipType.ENCRYPTED_WITH
    )
    assert kms_relationship.target.aws_resource_id == kms_arn
    assert kms_relationship.target.aws_account_id == ACCOUNT_ID
    assert kms_relationship.target.region == HOME_REGION
    assert kms_relationship.target.resource_snapshot_id is None
    assert kms_relationship.target_collector_name == "s3_evidence"
    expected_digest = hashlib.sha256(f"{HOME_REGION}\x00{kms_arn}".encode()).hexdigest()
    assert kms_relationship.target_evidence_kind == f"kms.key.{expected_digest}"
    assert all(
        relationship.provenance.source_api == "cloudtrail:GetTrail"
        for relationship in graph_result.relationships
    )


def test_5f_uses_parameterless_paginated_discovery_and_actual_home_region_owner() -> None:
    home_region = "us-west-2"
    trail_name = "OrganizationTrail"
    trail_arn = f"arn:aws:cloudtrail:{home_region}:{EXTERNAL_ACCOUNT_ID}:trail/{trail_name}"
    discovery = FakePaginator(
        [
            {"Trails": []},
            {
                "Trails": [
                    {
                        "TrailARN": trail_arn,
                        "Name": trail_name,
                        "HomeRegion": home_region,
                    }
                ]
            },
        ]
    )
    tags = FakePaginator([{"ResourceTagList": [{"ResourceId": trail_arn, "TagsList": []}]}])
    discovery_client = FakeAWSClient(paginators={"list_trails": discovery})
    home_client = FakeAWSClient(
        paginators={"list_tags": tags},
        responses={
            "get_trail": [
                {
                    "Trail": {
                        **_trail(
                            trail_arn,
                            trail_name,
                            home_region,
                            multi_region=True,
                        ),
                        "IsOrganizationTrail": True,
                    }
                }
            ],
            "get_trail_status": [{"IsLogging": True}],
            "get_event_selectors": [{"TrailARN": trail_arn, "EventSelectors": [{}]}],
        },
    )
    provider = FakeClientProvider(
        {
            ("cloudtrail", HOME_REGION): discovery_client,
            ("cloudtrail", home_region): home_client,
        },
        account_id=ACCOUNT_ID,
    )
    bundle = CloudTrailCollectionBundle(provider)
    legacy = CloudTrailCollector(provider, collection_bundle=bundle)
    evidence = CloudTrailEvidenceCollector(provider, collection_bundle=bundle)

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert discovery.calls == [{}]
    assert tags.calls == [{"ResourceIdList": [trail_arn]}]
    assert provider.client_requests == [
        ("cloudtrail", HOME_REGION),
        ("cloudtrail", home_region),
    ]
    assert home_client.calls == [
        RecordedCall("get_trail", {"Name": trail_arn}),
        RecordedCall("get_trail_status", {"Name": trail_arn}),
        RecordedCall("get_event_selectors", {"TrailName": trail_arn}),
    ]
    assert legacy_result.resources[0].account_id == EXTERNAL_ACCOUNT_ID
    assert legacy_result.resources[0].region == home_region
    assert legacy_result.resources[0].configuration["is_organization_trail"] is True
    identity = _artifact_payload(graph_result, "cloudtrail.trail.identity")
    assert identity["collection_account_id"] == ACCOUNT_ID
    assert identity["owner_account_id"] == EXTERNAL_ACCOUNT_ID
    identity_outcome = _outcome(graph_result, "cloudtrail.trail.identity")
    assert identity_outcome.subject.aws_account_id == EXTERNAL_ACCOUNT_ID


@pytest.mark.parametrize(
    ("organization_value", "expected_state", "expected_category"),
    (
        (
            False,
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.CONFLICTING_EVIDENCE,
        ),
        (
            None,
            EvidenceSourceState.MALFORMED,
            EvidenceFailureCategory.MALFORMED_RESPONSE,
        ),
    ),
    ids=("explicitly-not-organization", "missing-organization-context"),
)
def test_5f_external_owner_requires_explicit_organization_trail_context(
    organization_value: bool | None,
    expected_state: EvidenceSourceState,
    expected_category: EvidenceFailureCategory,
) -> None:
    trail_name = "OrganizationTrail"
    trail_arn = f"arn:aws:cloudtrail:{HOME_REGION}:{EXTERNAL_ACCOUNT_ID}:trail/{trail_name}"
    trail = _trail(trail_arn, trail_name, HOME_REGION, multi_region=True)
    if organization_value is not None:
        trail["IsOrganizationTrail"] = organization_value
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        trail_arn=trail_arn,
        name=trail_name,
        trail_response={"Trail": trail},
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.PARTIAL
    assert legacy_result.resources[0].account_id == EXTERNAL_ACCOUNT_ID
    assert legacy_result.resources[0].configuration["source_states"]["configuration"] == (
        expected_state.value
    )
    assert legacy_result.resources[0].configuration["is_organization_trail"] is None
    assert graph_result.status is CollectionStatus.PARTIAL
    configuration = _outcome(graph_result, "cloudtrail.trail.configuration")
    assert configuration.state is expected_state
    assert configuration.failure_category is expected_category
    assert _artifact_payload(graph_result, "cloudtrail.trail.configuration")["value"] is None
    assert graph_result.relationships == ()


def test_5f_normalizes_basic_selector_defaults_with_raw_presence() -> None:
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        selector_response={"TrailARN": TRAIL_ARN, "EventSelectors": [{}]},
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    expected = {
        "selector_form": "BASIC",
        "basic_selectors": [
            {
                "raw_presence": {
                    "include_management_events": False,
                    "read_write_type": False,
                    "exclude_management_event_sources": False,
                    "data_resources": False,
                },
                "include_management_events": True,
                "read_write_type": "All",
                "exclude_management_event_sources": [],
                "data_resources": [],
            }
        ],
        "advanced_selectors": [],
    }
    assert legacy_result.resources[0].configuration["event_selectors"] == expected
    assert _artifact_payload(graph_result, "cloudtrail.trail.event-selectors")["value"] == expected


def test_5f_normalizes_advanced_selector_all_operators_canonically() -> None:
    selector_response = {
        "TrailARN": TRAIL_ARN,
        "AdvancedEventSelectors": [
            {
                "Name": "AllOperators",
                "FieldSelectors": [
                    {
                        "Field": "resources.type",
                        "Equals": ["z", "a"],
                        "StartsWith": ["start-z", "start-a"],
                        "EndsWith": ["end-z", "end-a"],
                        "NotEquals": ["not-z", "not-a"],
                        "NotStartsWith": ["ns-z", "ns-a"],
                        "NotEndsWith": ["ne-z", "ne-a"],
                    }
                ],
            }
        ],
    }
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        selector_response=selector_response,
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    expected = {
        "selector_form": "ADVANCED",
        "basic_selectors": [],
        "advanced_selectors": [
            {
                "name": "AllOperators",
                "field_selectors": [
                    {
                        "field": "resources.type",
                        "equals": ["a", "z"],
                        "starts_with": ["start-a", "start-z"],
                        "ends_with": ["end-a", "end-z"],
                        "not_equals": ["not-a", "not-z"],
                        "not_starts_with": ["ns-a", "ns-z"],
                        "not_ends_with": ["ne-a", "ne-z"],
                    }
                ],
            }
        ],
    }
    assert legacy_result.resources[0].configuration["event_selectors"] == expected
    assert _artifact_payload(graph_result, "cloudtrail.trail.event-selectors")["value"] == expected


def test_5f_preserves_cross_region_destination_kms_identity() -> None:
    kms_arn = f"arn:aws:kms:eu-west-1:{ACCOUNT_ID}:key/key-123"
    trail = _trail(TRAIL_ARN, "TestTrail", HOME_REGION, multi_region=True)
    trail["KmsKeyId"] = kms_arn
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        trail_response={"Trail": trail}
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.SUCCEEDED
    assert legacy_result.resources[0].configuration["kms_key_id"] == kms_arn
    kms_relationship = next(
        relationship
        for relationship in graph_result.relationships
        if relationship.relationship_type is RelationshipType.ENCRYPTED_WITH
    )
    assert kms_relationship.target.region == "eu-west-1"
    assert kms_relationship.target.aws_resource_id == kms_arn


@pytest.mark.parametrize(
    ("selector_response", "expected_state", "expected_category"),
    (
        (
            {"TrailARN": TRAIL_ARN},
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.CONFLICTING_EVIDENCE,
        ),
        (
            {
                "TrailARN": TRAIL_ARN,
                "EventSelectors": [{}],
                "AdvancedEventSelectors": [
                    {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}]}
                ],
            },
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.CONFLICTING_EVIDENCE,
        ),
        (
            {
                "TrailARN": TRAIL_ARN,
                "EventSelectors": [{"DataResources": [{"Type": "AWS::S3::Object", "Values": []}]}],
            },
            EvidenceSourceState.MALFORMED,
            EvidenceFailureCategory.MALFORMED_RESPONSE,
        ),
        (
            {
                "TrailARN": TRAIL_ARN,
                "EventSelectors": [
                    {"ExcludeManagementEventSources": ["unsupported.amazonaws.com"]}
                ],
            },
            EvidenceSourceState.MALFORMED,
            EvidenceFailureCategory.MALFORMED_RESPONSE,
        ),
        (
            {
                "TrailARN": TRAIL_ARN,
                "AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory"}]}],
            },
            EvidenceSourceState.MALFORMED,
            EvidenceFailureCategory.MALFORMED_RESPONSE,
        ),
        (
            {"TrailARN": TRAIL_ARN, "EventSelectors": [{}, {}]},
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.CONFLICTING_EVIDENCE,
        ),
        (
            {
                "TrailARN": TRAIL_ARN,
                "AdvancedEventSelectors": [
                    {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]},
                    {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]},
                ],
            },
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.CONFLICTING_EVIDENCE,
        ),
        (
            {
                "TrailARN": TRAIL_ARN,
                "EventSelectors": [
                    {
                        "DataResources": [
                            {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::example/"]},
                            {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::example/"]},
                        ]
                    }
                ],
            },
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.CONFLICTING_EVIDENCE,
        ),
        (
            {
                "TrailARN": TRAIL_ARN,
                "AdvancedEventSelectors": [
                    {
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Management"]},
                            {"Field": "eventCategory", "Equals": ["Management"]},
                        ]
                    }
                ],
            },
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.CONFLICTING_EVIDENCE,
        ),
    ),
    ids=(
        "empty-form",
        "mixed-form",
        "empty-data-resource-values",
        "unsupported-management-exclusion",
        "vacuous-advanced-field",
        "duplicate-basic-selector",
        "duplicate-advanced-selector",
        "duplicate-data-resource",
        "duplicate-advanced-field",
    ),
)
def test_5f_selector_uncertainty_does_not_erase_legacy_logging_evidence(
    selector_response: dict[str, object],
    expected_state: EvidenceSourceState,
    expected_category: EvidenceFailureCategory,
) -> None:
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        selector_response=selector_response,
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.SUCCEEDED
    assert legacy_result.resources[0].configuration["is_logging"] is True
    assert (
        legacy_result.resources[0].configuration["source_states"]["event_selectors"]
        == expected_state.value
    )
    assert graph_result.status is CollectionStatus.PARTIAL
    outcome = _outcome(graph_result, "cloudtrail.trail.event-selectors")
    assert outcome.state is expected_state
    assert outcome.failure_category is expected_category
    assert _artifact_payload(graph_result, "cloudtrail.trail.event-selectors") == {
        "trail_arn": TRAIL_ARN,
        "home_region": HOME_REGION,
        "value": None,
        "complete": False,
        "failure_category": expected_category.value,
    }


@pytest.mark.parametrize(
    ("tag_pages", "expected_state", "expected_category"),
    (
        (
            [{"ResourceTagList": []}],
            EvidenceSourceState.MALFORMED,
            EvidenceFailureCategory.MALFORMED_RESPONSE,
        ),
        (
            [
                {
                    "ResourceTagList": [
                        {"ResourceId": TRAIL_ARN, "TagsList": []},
                        {"ResourceId": TRAIL_ARN, "TagsList": []},
                    ]
                }
            ],
            EvidenceSourceState.CONFLICT,
            EvidenceFailureCategory.CONFLICTING_EVIDENCE,
        ),
    ),
    ids=("omitted-requested-arn", "duplicate-resource-entry"),
)
def test_5f_list_tags_requires_unambiguous_per_trail_attribution(
    tag_pages: list[dict[str, object]],
    expected_state: EvidenceSourceState,
    expected_category: EvidenceFailureCategory,
) -> None:
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        tag_pages=tag_pages,
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.SUCCEEDED
    assert legacy_result.resources[0].tags == {}
    assert legacy_result.resources[0].configuration["source_states"]["tags"] == expected_state.value
    assert graph_result.status is CollectionStatus.PARTIAL
    outcome = _outcome(graph_result, "cloudtrail.trail.tags")
    assert outcome.state is expected_state
    assert outcome.failure_category is expected_category


def test_5f_explicit_tag_entry_without_tags_is_complete_empty_tags() -> None:
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        tag_pages=[{"ResourceTagList": [{"ResourceId": TRAIL_ARN}]}],
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.SUCCEEDED
    assert legacy_result.resources[0].tags == {}
    assert _outcome(graph_result, "cloudtrail.trail.tags").state is EvidenceSourceState.PRESENT
    assert _artifact_payload(graph_result, "cloudtrail.trail.tags")["value"] == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("HomeRegion", "not-a-region"),
        ("HomeRegion", "us-éast-1"),
        ("Name", "ab"),
        ("Name", "a" * 129),
        ("Name", "bad..name"),
        ("Name", "192.168.1.1"),
        ("Name", "éxample"),
    ),
    ids=(
        "region-grammar",
        "region-non-ascii",
        "name-too-short",
        "name-too-long",
        "name-adjacent-punctuation",
        "name-ip-shaped",
        "name-non-ascii",
    ),
)
def test_5f_malformed_identity_is_sanitized_discovery_uncertainty(
    field: str,
    value: object,
) -> None:
    summary = {
        "TrailARN": TRAIL_ARN,
        "Name": "TestTrail",
        "HomeRegion": HOME_REGION,
        field: value,
    }
    discovery = FakePaginator([{"Trails": [summary]}])
    client = FakeAWSClient(paginators={"list_trails": discovery})
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})
    collector = CloudTrailEvidenceCollector(provider)

    result = collector.collect_with_context(_context())

    assert result.status is CollectionStatus.PARTIAL
    assert len(result.source_outcomes) == 1
    outcome = _outcome(result, "cloudtrail.trails.discovery")
    assert outcome.state is EvidenceSourceState.MALFORMED
    assert outcome.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    payload = _artifact_payload(result, "cloudtrail.trails.discovery")
    assert payload["trail_arns"] == []
    assert payload["discarded_item_count"] == 1
    assert str(value) not in result.artifacts[0].model_dump_json()


def test_5f_discovery_conflict_retains_valid_siblings() -> None:
    valid_name = "ValidTrail"
    valid_arn = f"arn:aws:cloudtrail:{HOME_REGION}:{ACCOUNT_ID}:trail/{valid_name}"
    conflicted_name = "ConflictedTrail"
    conflicted_arn = f"arn:aws:cloudtrail:{HOME_REGION}:{ACCOUNT_ID}:trail/{conflicted_name}"
    discovery = FakePaginator(
        [
            {
                "Trails": [
                    {
                        "TrailARN": conflicted_arn,
                        "Name": conflicted_name,
                        "HomeRegion": HOME_REGION,
                    },
                    {
                        "TrailARN": valid_arn,
                        "Name": valid_name,
                        "HomeRegion": HOME_REGION,
                    },
                    {
                        "TrailARN": conflicted_arn,
                        "Name": "DifferentName",
                        "HomeRegion": HOME_REGION,
                    },
                ]
            }
        ]
    )
    tags = FakePaginator([{"ResourceTagList": [{"ResourceId": valid_arn, "TagsList": []}]}])
    client = FakeAWSClient(
        paginators={"list_trails": discovery, "list_tags": tags},
        responses={
            "get_trail": [{"Trail": _trail(valid_arn, valid_name, HOME_REGION, multi_region=True)}],
            "get_trail_status": [{"IsLogging": True}],
            "get_event_selectors": [{"TrailARN": valid_arn, "EventSelectors": [{}]}],
        },
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})
    bundle = CloudTrailCollectionBundle(provider)
    legacy = CloudTrailCollector(provider, collection_bundle=bundle)
    evidence = CloudTrailEvidenceCollector(provider, collection_bundle=bundle)

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.PARTIAL
    assert [item.aws_resource_id for item in legacy_result.resources] == [valid_arn]
    assert graph_result.status is CollectionStatus.PARTIAL
    discovery_outcome = _outcome(graph_result, "cloudtrail.trails.discovery")
    assert discovery_outcome.state is EvidenceSourceState.CONFLICT
    assert discovery_outcome.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    payload = _artifact_payload(graph_result, "cloudtrail.trails.discovery")
    assert payload["trail_arns"] == [valid_arn]
    assert payload["discarded_item_count"] == 2


def test_5f_discovery_not_found_is_not_a_resource_disappearance() -> None:
    error = client_error("TrailNotFoundException", "ListTrails", status_code=404)
    client = FakeAWSClient(
        paginators={"list_trails": FakePaginator(error=error)},
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})

    result = CloudTrailEvidenceCollector(provider).collect_with_context(_context())

    outcome = _outcome(result, "cloudtrail.trails.discovery")
    assert outcome.state is EvidenceSourceState.UNAVAILABLE
    assert outcome.failure_category is EvidenceFailureCategory.SERVICE_ERROR
    assert result.status is CollectionStatus.FAILED


def test_5f_empty_discovery_is_complete_without_enrichment_calls() -> None:
    discovery = FakePaginator([{"Trails": []}])
    client = FakeAWSClient(paginators={"list_trails": discovery})
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})
    bundle = CloudTrailCollectionBundle(provider)
    legacy = CloudTrailCollector(provider, collection_bundle=bundle)
    evidence = CloudTrailEvidenceCollector(provider, collection_bundle=bundle)

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.SUCCEEDED
    assert legacy_result.resources == ()
    assert graph_result.status is CollectionStatus.SUCCEEDED
    assert [item.evidence_kind for item in graph_result.source_outcomes] == [
        "cloudtrail.trails.discovery"
    ]
    assert discovery.calls == [{}]
    assert client.paginator_requests == ["list_trails"]
    assert client.calls == []


def test_5f_status_denial_is_independent_from_configuration_relationships() -> None:
    denied = client_error("AccessDeniedException", "GetTrailStatus", status_code=403)
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        status_response=denied,
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    resource = legacy_result.resources[0]
    assert legacy_result.status is CollectionStatus.PARTIAL
    assert resource.configuration["s3_bucket_name"] == "testtrail-logs"
    assert resource.configuration["is_logging"] is None
    assert resource.configuration["source_states"]["configuration"] == "PRESENT"
    assert resource.configuration["source_states"]["status"] == "UNAVAILABLE"
    status = _outcome(graph_result, "cloudtrail.trail.status")
    assert status.state is EvidenceSourceState.UNAVAILABLE
    assert status.failure_category is EvidenceFailureCategory.ACCESS_DENIED
    assert len(graph_result.relationships) == 1
    assert graph_result.relationships[0].relationship_type is RelationshipType.DELIVERS_TO_BUCKET


@pytest.mark.parametrize(
    "field_name",
    ("CloudWatchLogsLogGroupArn", "CloudWatchLogsRoleArn"),
)
def test_5f_unsafe_cloudwatch_delivery_value_is_typed_malformed(
    field_name: str,
) -> None:
    trail = _trail(TRAIL_ARN, "TestTrail", HOME_REGION, multi_region=True)
    trail.update(
        {
            "CloudWatchLogsLogGroupArn": (
                f"arn:aws:logs:{HOME_REGION}:{ACCOUNT_ID}:log-group:trail:*"
            ),
            "CloudWatchLogsRoleArn": f"arn:aws:iam::{ACCOUNT_ID}:role/CloudTrailLogs",
        }
    )
    trail[field_name] = "unsafe\nvalue"
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        trail_response={"Trail": trail}
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.PARTIAL
    assert legacy_result.resources[0].configuration["source_states"]["configuration"] == (
        EvidenceSourceState.MALFORMED.value
    )
    outcome = _outcome(graph_result, "cloudtrail.trail.configuration")
    assert outcome.state is EvidenceSourceState.MALFORMED
    assert outcome.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE


def test_5f_per_trail_not_found_remains_resource_disappearance() -> None:
    not_found = client_error("TrailNotFoundException", "GetTrail", status_code=404)
    _provider, _bundle, legacy, evidence, _client = _five_f_one_trail(
        trail_response=not_found,
    )

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert legacy_result.status is CollectionStatus.PARTIAL
    assert (
        legacy_result.resources[0].configuration["source_states"]["configuration"]
        == EvidenceSourceState.RESOURCE_DISAPPEARED.value
    )
    outcome = _outcome(graph_result, "cloudtrail.trail.configuration")
    assert outcome.state is EvidenceSourceState.RESOURCE_DISAPPEARED
    assert outcome.failure_category is EvidenceFailureCategory.RESOURCE_NOT_FOUND
    assert graph_result.relationships == ()


def test_5f_batches_and_paginates_tags_by_home_region_at_twenty_arns() -> None:
    names = [f"Trail{index:02d}" for index in range(21)]
    arns = [f"arn:aws:cloudtrail:{HOME_REGION}:{ACCOUNT_ID}:trail/{name}" for name in names]
    discovery = FakePaginator(
        [
            {
                "Trails": [
                    {
                        "TrailARN": arn,
                        "Name": name,
                        "HomeRegion": HOME_REGION,
                    }
                    for arn, name in zip(reversed(arns[:10]), reversed(names[:10]), strict=True)
                ]
            },
            {
                "Trails": [
                    {
                        "TrailARN": arn,
                        "Name": name,
                        "HomeRegion": HOME_REGION,
                    }
                    for arn, name in zip(reversed(arns[10:]), reversed(names[10:]), strict=True)
                ]
            },
        ]
    )
    first_tags = FakePaginator(
        [
            {"ResourceTagList": [{"ResourceId": arn, "TagsList": []} for arn in arns[:10]]},
            {"ResourceTagList": [{"ResourceId": arn, "TagsList": []} for arn in arns[10:20]]},
        ]
    )
    second_tags = FakePaginator([{"ResourceTagList": [{"ResourceId": arns[20], "TagsList": []}]}])
    client = FakeAWSClient(
        paginators={
            "list_trails": discovery,
            "list_tags": [first_tags, second_tags],
        },
        responses={
            "get_trail": [
                {"Trail": _trail(arn, name, HOME_REGION, multi_region=True)}
                for arn, name in zip(arns, names, strict=True)
            ],
            "get_trail_status": [{"IsLogging": True} for _arn in arns],
            "get_event_selectors": [{"TrailARN": arn, "EventSelectors": [{}]} for arn in arns],
        },
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})
    bundle = CloudTrailCollectionBundle(provider)
    legacy = CloudTrailCollector(provider, collection_bundle=bundle)
    evidence = CloudTrailEvidenceCollector(provider, collection_bundle=bundle)

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert discovery.calls == [{}]
    assert first_tags.calls == [{"ResourceIdList": arns[:20]}]
    assert second_tags.calls == [{"ResourceIdList": arns[20:]}]
    assert len(first_tags.calls[0]["ResourceIdList"]) == 20
    assert len(second_tags.calls[0]["ResourceIdList"]) == 1
    assert [item.aws_resource_id for item in legacy_result.resources] == arns
    assert legacy_result.status is CollectionStatus.SUCCEEDED
    assert graph_result.status is CollectionStatus.SUCCEEDED
    assert len(graph_result.source_outcomes) == 1 + (5 * len(arns))


def test_5f_tag_batch_not_found_isolated_before_resource_disappearance_attribution() -> None:
    names = ("MissingTrail", "ValidTrail")
    arns = tuple(f"arn:aws:cloudtrail:{HOME_REGION}:{ACCOUNT_ID}:trail/{name}" for name in names)
    batch_error = FakePaginator(
        error=client_error("ResourceNotFoundException", "ListTags", status_code=404)
    )
    missing_error = FakePaginator(
        error=client_error("ResourceNotFoundException", "ListTags", status_code=404)
    )
    valid_tags = FakePaginator(
        [
            {
                "ResourceTagList": [
                    {
                        "ResourceId": arns[1],
                        "TagsList": [{"Key": "Owner", "Value": "security"}],
                    }
                ]
            }
        ]
    )
    client = FakeAWSClient(
        paginators={
            "list_trails": FakePaginator(
                [
                    {
                        "Trails": [
                            {"TrailARN": arn, "Name": name, "HomeRegion": HOME_REGION}
                            for arn, name in zip(arns, names, strict=True)
                        ]
                    }
                ]
            ),
            "list_tags": [batch_error, missing_error, valid_tags],
        },
        responses={
            "get_trail": [
                {"Trail": _trail(arn, name, HOME_REGION, multi_region=True)}
                for arn, name in zip(arns, names, strict=True)
            ],
            "get_trail_status": [{"IsLogging": True}, {"IsLogging": True}],
            "get_event_selectors": [{"TrailARN": arn, "EventSelectors": [{}]} for arn in arns],
        },
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})
    bundle = CloudTrailCollectionBundle(provider)
    legacy = CloudTrailCollector(provider, collection_bundle=bundle)
    evidence = CloudTrailEvidenceCollector(provider, collection_bundle=bundle)

    legacy_result = legacy.collect_with_context(_context())
    graph_result = evidence.collect_with_context(_context())

    assert batch_error.calls == [{"ResourceIdList": list(arns)}]
    assert missing_error.calls == [{"ResourceIdList": [arns[0]]}]
    assert valid_tags.calls == [{"ResourceIdList": [arns[1]]}]
    resources = {resource.aws_resource_id: resource for resource in legacy_result.resources}
    assert resources[arns[0]].configuration["source_states"]["tags"] == (
        EvidenceSourceState.RESOURCE_DISAPPEARED.value
    )
    assert resources[arns[1]].configuration["source_states"]["tags"] == (
        EvidenceSourceState.PRESENT.value
    )
    assert resources[arns[1]].tags == {"Owner": "security"}
    tag_outcomes = {
        outcome.subject.aws_resource_id: outcome
        for outcome in graph_result.source_outcomes
        if outcome.evidence_kind == "cloudtrail.trail.tags"
    }
    assert tag_outcomes[arns[0]].state is EvidenceSourceState.RESOURCE_DISAPPEARED
    assert tag_outcomes[arns[1]].state is EvidenceSourceState.PRESENT
    assert graph_result.status is CollectionStatus.PARTIAL


def test_5f_inventory_prunes_unadmitted_external_trail_from_both_projections() -> None:
    local_name = "LocalTrail"
    local_arn = f"arn:aws:cloudtrail:{HOME_REGION}:{ACCOUNT_ID}:trail/{local_name}"
    external_name = "OrganizationTrail"
    external_arn = f"arn:aws:cloudtrail:{HOME_REGION}:{EXTERNAL_ACCOUNT_ID}:trail/{external_name}"
    ordered = sorted(
        (
            (local_arn, local_name, False),
            (external_arn, external_name, True),
        )
    )
    client = FakeAWSClient(
        paginators={
            "list_trails": FakePaginator(
                [
                    {
                        "Trails": [
                            {
                                "TrailARN": external_arn,
                                "Name": external_name,
                                "HomeRegion": HOME_REGION,
                            },
                            {
                                "TrailARN": local_arn,
                                "Name": local_name,
                                "HomeRegion": HOME_REGION,
                            },
                        ]
                    }
                ]
            ),
            "list_tags": FakePaginator(
                [
                    {
                        "ResourceTagList": [
                            {"ResourceId": external_arn, "TagsList": []},
                            {"ResourceId": local_arn, "TagsList": []},
                        ]
                    }
                ]
            ),
        },
        responses={
            "get_trail": [
                {
                    "Trail": {
                        **_trail(arn, name, HOME_REGION, multi_region=True),
                        "IsOrganizationTrail": is_organization,
                    }
                }
                for arn, name, is_organization in ordered
            ],
            "get_trail_status": [{"IsLogging": True} for _item in ordered],
            "get_event_selectors": [
                {"TrailARN": arn, "EventSelectors": [{}]}
                for arn, _name, _is_organization in ordered
            ],
        },
    )
    provider = FakeClientProvider({("cloudtrail", HOME_REGION): client})
    bundle = CloudTrailCollectionBundle(provider)

    snapshot = InventoryService(
        provider,
        collectors=(
            CloudTrailCollector(provider, collection_bundle=bundle),
            CloudTrailEvidenceCollector(provider, collection_bundle=bundle),
        ),
    ).collect(scan_id=SCAN_ID)

    assert snapshot.collection_status("cloudtrail_trails") is CollectionStatus.PARTIAL
    assert snapshot.collection_status("cloudtrail_evidence") is CollectionStatus.PARTIAL
    assert [item.aws_resource_id for item in snapshot.resources] == [local_arn]
    assert snapshot.evidence_graph is not None
    graph = snapshot.evidence_graph
    assert all(
        getattr(contract.subject, "aws_resource_id", None) != external_arn
        for contract in graph.source_contracts
    )
    assert all(
        getattr(outcome.subject, "aws_resource_id", None) != external_arn
        for outcome in graph.source_outcomes
    )
    assert all(
        relationship.source.aws_resource_id != external_arn for relationship in graph.relationships
    )
    discovery_artifacts = [
        artifact
        for artifact in graph.artifacts
        if artifact.evidence_schema == "cloudtrail.trails.discovery"
    ]
    assert len(discovery_artifacts) == 1
    discovery_payload = discovery_artifacts[0].model_dump(mode="json")["normalized_payload"]
    assert discovery_payload == {
        "collection_account_id": ACCOUNT_ID,
        "invocation_region": HOME_REGION,
        "trail_arns": sorted([local_arn, external_arn]),
        "trail_count": 2,
        "discarded_item_count": 0,
        "admission_complete": False,
        "unadmitted_resources": [
            {
                "account_id": EXTERNAL_ACCOUNT_ID,
                "service": "cloudtrail",
                "resource_type": "cloudtrail_trail",
                "scope": "regional",
                "region": HOME_REGION,
                "resource_id": external_arn,
            }
        ],
        "complete": True,
        "failure_category": None,
    }
