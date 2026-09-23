"""Tests for AWS inventory orchestration."""

from typing import Any

import pytest
from botocore.exceptions import ClientError, PaginationError

from app.collectors.access_analyzer import AccessAnalyzerCollector
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceError,
    CollectorResult,
    ResourceCollector,
)
from app.collectors.cloudtrail import (
    CloudTrailCollectionBundle,
    CloudTrailCollector,
    CloudTrailEvidenceCollector,
)
from app.collectors.ec2 import EC2EbsCollector
from app.collectors.iam import IAMUserCollector
from app.collectors.iam_account import IAMAccountEvidenceCollector
from app.collectors.network import VPCNetworkCollector
from app.collectors.s3 import S3BucketCollector, S3CollectionBundle, S3EvidenceCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import NormalizedResource, ResourceScope
from app.services.inventory_service import (
    InventoryService,
    build_default_collectors,
)
from tests.fakes import (
    FakeAWSClient,
    FakePaginator,
    client_error,
)
from tests.fakes import (
    FakeClientProvider as QueuedFakeClientProvider,
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


class RecordingAccessAnalyzerCollector(ResourceCollector):
    collector_name = "access_analyzer_evidence"

    def __init__(self) -> None:
        self.contexts: list[CollectionContext] = []

    def collect(self) -> list[NormalizedResource]:
        raise AssertionError("the context-aware collection path is required")

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        self.contexts.append(context)
        return CollectorResult()


class StaticS3Collector(ResourceCollector):
    collector_name = "s3_buckets"

    def __init__(self, resources: list[NormalizedResource]) -> None:
        self.resources = resources

    def collect(self) -> list[NormalizedResource]:
        return self.resources


def _resource(resource_id: str, service: str) -> NormalizedResource:
    return NormalizedResource(
        account_id="123456789012",
        service=service,
        resource_type=f"{service}_resource",
        aws_resource_id=resource_id,
        scope=ResourceScope.REGIONAL,
        region="us-west-2",
    )


def _bucket(resource_id: str, region: str) -> NormalizedResource:
    return NormalizedResource(
        account_id="123456789012",
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id=resource_id,
        scope=ResourceScope.REGIONAL,
        region=region,
    )


def test_default_collectors_cover_accepted_inventory() -> None:
    provider = FakeClientProvider()

    collectors = build_default_collectors(provider)

    assert tuple(type(collector) for collector in collectors) == (
        EC2EbsCollector,
        SecurityGroupCollector,
        VPCNetworkCollector,
        S3BucketCollector,
        S3EvidenceCollector,
        AccessAnalyzerCollector,
        IAMAccountEvidenceCollector,
        IAMUserCollector,
        CloudTrailCollector,
        CloudTrailEvidenceCollector,
    )
    legacy = collectors[-2]
    evidence = collectors[-1]
    assert isinstance(legacy, CloudTrailCollector)
    assert isinstance(evidence, CloudTrailEvidenceCollector)
    assert isinstance(legacy.collection_bundle, CloudTrailCollectionBundle)
    assert legacy.collection_bundle is evidence.collection_bundle


def test_pre_5f_default_collectors_omit_cloudtrail_evidence_bundle() -> None:
    provider = FakeClientProvider()

    collectors = build_default_collectors(provider, include_cloudtrail_evidence=False)

    assert tuple(type(collector) for collector in collectors[-2:]) == (
        IAMUserCollector,
        CloudTrailCollector,
    )
    cloudtrail = collectors[-1]
    assert isinstance(cloudtrail, CloudTrailCollector)
    assert cloudtrail.collection_bundle is None


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


def test_access_analyzer_context_uses_sorted_unique_normalized_bucket_regions() -> None:
    analyzer = RecordingAccessAnalyzerCollector()

    InventoryService(
        FakeClientProvider(),
        collectors=(
            StaticS3Collector(
                [
                    _bucket("west", "us-west-2"),
                    _bucket("east-two", "us-east-2"),
                    _bucket("east-one", "us-east-1"),
                    _bucket("east-one-again", "us-east-1"),
                ]
            ),
            analyzer,
        ),
    ).collect()

    assert len(analyzer.contexts) == 1
    context = analyzer.contexts[0]
    assert context.region == "us-west-2"
    assert context.supplemental_regions == ("us-east-1", "us-east-2")
    assert context.supplemental_region_source_complete is True


def test_access_analyzer_context_fails_closed_without_s3_discovery() -> None:
    analyzer = RecordingAccessAnalyzerCollector()
    denied = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "sensitive detail"}},
        "ListBuckets",
    )

    snapshot = InventoryService(
        FakeClientProvider(),
        collectors=(FailingCollector(denied), analyzer),
    ).collect()

    assert snapshot.collection_status("failing") is CollectionStatus.FAILED
    assert analyzer.contexts[0].supplemental_regions == ()
    assert analyzer.contexts[0].supplemental_region_source_complete is False


def test_5e_analyzer_context_uses_location_evidence_not_enrichment_rollup() -> None:
    region = "us-west-2"
    bucket_name = "evidence-bucket"
    s3_client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [{"Buckets": [{"Name": bucket_name, "BucketRegion": region}]}]
            )
        },
        responses={
            "get_bucket_location": [{"LocationConstraint": region}],
            "get_bucket_tagging": [{"TagSet": []}],
            "get_public_access_block": [
                {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    }
                }
            ],
            "get_bucket_policy": [client_error("AccessDenied", "GetBucketPolicy")],
            "get_bucket_policy_status": [{"PolicyStatus": {"IsPublic": False}}],
            "get_bucket_acl": [{"Owner": {"ID": "owner-id"}, "Grants": []}],
            "get_bucket_versioning": [{}],
            "get_bucket_encryption": [
                client_error(
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "GetBucketEncryption",
                )
            ],
            "get_bucket_ownership_controls": [
                client_error("OwnershipControlsNotFoundError", "GetBucketOwnershipControls")
            ],
        },
    )
    s3control_client = FakeAWSClient(
        responses={
            "get_public_access_block": [
                {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    }
                }
            ]
        }
    )
    provider = QueuedFakeClientProvider(
        {
            ("s3", region): s3_client,
            ("s3control", region): s3control_client,
        },
        region_name=region,
    )
    bundle = S3CollectionBundle(provider)
    analyzer = RecordingAccessAnalyzerCollector()

    snapshot = InventoryService(
        provider,
        collectors=(
            S3BucketCollector(provider, collection_bundle=bundle),
            S3EvidenceCollector(provider, collection_bundle=bundle),
            analyzer,
        ),
    ).collect()

    assert snapshot.collection_status("s3_buckets") is CollectionStatus.SUCCEEDED
    assert snapshot.collection_status("s3_evidence") is CollectionStatus.PARTIAL
    assert analyzer.contexts[0].supplemental_region_source_complete is True


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


def test_botocore_pagination_failure_is_sanitized_as_operational_failure() -> None:
    collector = FailingCollector(PaginationError(message="sensitive malformed continuation token"))

    snapshot = InventoryService(FakeClientProvider(), collectors=(collector,)).collect()

    assert snapshot.collection_status("failing") is CollectionStatus.FAILED
    assert "sensitive malformed continuation token" not in snapshot.model_dump_json()
