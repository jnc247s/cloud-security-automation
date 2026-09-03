"""Tests for AWS inventory orchestration."""

from typing import Any

import pytest
from botocore.exceptions import ClientError

from app.collectors.base import ResourceCollector
from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.iam import IAMUserCollector
from app.collectors.s3 import S3BucketCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.schemas.resource import NormalizedResource, ResourceScope
from app.services.inventory_service import (
    InventoryCollectionError,
    InventoryService,
    build_default_collectors,
)


class FakeClientProvider:
    """Provide only the identity fields needed by the service tests."""

    region_name = "us-west-2"
    account_id = "123456789012"
    partition = "aws"

    def client(self, service_name: str, *, region_name: str | None = None) -> Any:
        raise AssertionError("No AWS client should be requested by these service tests")


class StaticCollector(ResourceCollector):
    collector_name = "static"

    def __init__(self, resources: list[NormalizedResource]) -> None:
        self.resources = resources

    def collect(self) -> list[NormalizedResource]:
        return self.resources


class FailingCollector(ResourceCollector):
    collector_name = "failing"

    def __init__(self, error: Exception) -> None:
        self.error = error

    def collect(self) -> list[NormalizedResource]:
        raise self.error


def _resource(resource_id: str, service: str) -> NormalizedResource:
    return NormalizedResource(
        account_id="123456789012",
        service=service,
        resource_type=f"{service}_resource",
        aws_resource_id=resource_id,
        scope=ResourceScope.REGIONAL,
        region="us-west-2",
    )


def test_default_collectors_cover_sprint_one_inventory() -> None:
    provider = FakeClientProvider()

    collectors = build_default_collectors(provider)

    assert tuple(type(collector) for collector in collectors) == (
        SecurityGroupCollector,
        S3BucketCollector,
        IAMUserCollector,
        CloudTrailCollector,
    )


def test_collect_returns_deterministically_sorted_snapshot() -> None:
    provider = FakeClientProvider()
    collector = StaticCollector(
        [
            _resource("bucket-b", "s3"),
            _resource("sg-a", "ec2"),
            _resource("bucket-a", "s3"),
        ]
    )

    snapshot = InventoryService(provider, collectors=(collector,)).collect()

    assert snapshot.account_id == "123456789012"
    assert snapshot.requested_region == "us-west-2"
    assert snapshot.collected_at.tzinfo is not None
    assert snapshot.resource_count == 3
    assert [(item.service, item.aws_resource_id) for item in snapshot.resources] == [
        ("ec2", "sg-a"),
        ("s3", "bucket-a"),
        ("s3", "bucket-b"),
    ]


def test_explicit_empty_collector_set_returns_successful_empty_snapshot() -> None:
    snapshot = InventoryService(FakeClientProvider(), collectors=()).collect()

    assert snapshot.resource_count == 0
    assert snapshot.resources == ()


def test_aws_failure_identifies_collector_without_exposing_response() -> None:
    client_error = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "sensitive upstream detail",
            }
        },
        "ListThings",
    )
    collector = FailingCollector(client_error)

    with pytest.raises(InventoryCollectionError, match="failing") as error_info:
        InventoryService(FakeClientProvider(), collectors=(collector,)).collect()

    assert error_info.value.collector_name == "failing"
    assert "sensitive upstream detail" not in str(error_info.value)
    assert error_info.value.__cause__ is client_error


def test_programming_error_is_not_mislabeled_as_aws_failure() -> None:
    collector = FailingCollector(ValueError("invalid normalized data"))

    with pytest.raises(ValueError, match="invalid normalized data"):
        InventoryService(FakeClientProvider(), collectors=(collector,)).collect()
