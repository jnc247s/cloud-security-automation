"""Tests for CloudTrail trail collection."""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from app.collectors.base import CollectorEvidenceError
from app.collectors.cloudtrail import CloudTrailCollector
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, RecordedCall, client_error

TRAIL_ARN = "arn:aws:cloudtrail:us-east-1:123456789012:trail/TestTrail"
HOME_REGION = "us-east-1"


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
