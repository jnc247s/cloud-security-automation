"""Tests for CloudTrail trail collection."""

from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError

from app.collectors.cloudtrail import CloudTrailCollector
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, RecordedCall, client_error


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


def test_collects_all_pages_deduplicates_and_uses_trail_home_regions() -> None:
    east_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/EastTrail"
    west_arn = "arn:aws:cloudtrail:us-west-2:123456789012:trail/WestTrail"
    discovery_pages = FakePaginator(
        [
            {"Trails": [{"TrailARN": east_arn, "Name": "EastTrail", "HomeRegion": "us-east-1"}]},
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
