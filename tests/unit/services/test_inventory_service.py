"""Tests for AWS inventory orchestration."""

from typing import Any

import pytest
from botocore.exceptions import ClientError

from app.collectors.base import CollectorEvidenceError, ResourceCollector
from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.iam import IAMUserCollector
from app.collectors.s3 import S3BucketCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import NormalizedResource, ResourceScope
from app.services.inventory_service import (
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


class PartialCollector(ResourceCollector):
    collector_name = "partial"

    def collect(self) -> list[NormalizedResource]:
        raise CollectorEvidenceError("ListThings", "pages[0].Things")


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
    assert snapshot.collection_status("static") is CollectionStatus.SUCCEEDED
    assert [(item.service, item.aws_resource_id) for item in snapshot.resources] == [
        ("ec2", "sg-a"),
        ("s3", "bucket-a"),
        ("s3", "bucket-b"),
    ]


def test_explicit_empty_collector_set_returns_successful_empty_snapshot() -> None:
    snapshot = InventoryService(FakeClientProvider(), collectors=()).collect()

    assert snapshot.resource_count == 0
    assert snapshot.resources == ()
    assert snapshot.collector_outcomes == ()


def test_aws_failure_becomes_sanitized_failed_collection_coverage() -> None:
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

    snapshot = InventoryService(FakeClientProvider(), collectors=(collector,)).collect()

    assert snapshot.resources == ()
    assert snapshot.collection_status("failing") is CollectionStatus.FAILED
    assert "sensitive upstream detail" not in snapshot.model_dump_json()


def test_collection_continues_after_one_collector_fails() -> None:
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "sensitive detail"}},
        "ListThings",
    )
    succeeding = StaticCollector([_resource("resource-after-failure", "s3")])

    snapshot = InventoryService(
        FakeClientProvider(),
        collectors=(FailingCollector(error), succeeding),
    ).collect()

    assert snapshot.collection_status("failing") is CollectionStatus.FAILED
    assert snapshot.collection_status("static") is CollectionStatus.SUCCEEDED
    assert [resource.aws_resource_id for resource in snapshot.resources] == [
        "resource-after-failure"
    ]


def test_malformed_aws_response_becomes_partial_collection_coverage() -> None:
    snapshot = InventoryService(
        FakeClientProvider(),
        collectors=(PartialCollector(FakeClientProvider()),),
    ).collect()

    assert snapshot.resources == ()
    assert snapshot.collection_status("partial") is CollectionStatus.PARTIAL


def test_programming_error_is_not_mislabeled_as_aws_failure() -> None:
    collector = FailingCollector(ValueError("invalid normalized data"))

    with pytest.raises(ValueError, match="invalid normalized data"):
        InventoryService(FakeClientProvider(), collectors=(collector,)).collect()
