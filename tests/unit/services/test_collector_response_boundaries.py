"""Cross-layer regression tests for malformed AWS collector evidence."""

from datetime import UTC, datetime

import pytest

from app.assessment.models import AssessmentResult
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE
from app.collectors.base import ResourceCollector
from app.collectors.cloudtrail import CloudTrailCollector
from app.collectors.iam import IAMUserCollector
from app.collectors.s3 import S3BucketCollector
from app.collectors.security_groups import SecurityGroupCollector
from app.rules.audit_logging import MissingCloudTrailRule
from app.rules.base import SecurityRule
from app.rules.identity import IAMUserWithoutMFARule
from app.rules.network import PublicSSHRule
from app.rules.storage import MissingBucketEncryptionRule
from app.schemas.inventory import CollectionStatus
from app.services.inventory_service import InventoryService
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator


def _iam_case() -> tuple[FakeClientProvider, type[ResourceCollector], SecurityRule]:
    client = FakeAWSClient(
        paginators={
            "list_users": FakePaginator(
                [
                    {
                        "Users": [
                            {
                                "Path": "/",
                                "UserName": "analyst",
                                "UserId": None,
                                "Arn": "arn:aws:iam::123456789012:user/analyst",
                                "CreateDate": datetime(2026, 9, 1, tzinfo=UTC),
                            }
                        ]
                    }
                ]
            )
        }
    )
    return (
        FakeClientProvider({("iam", "us-east-1"): client}),
        IAMUserCollector,
        IAMUserWithoutMFARule(),
    )


def _s3_case() -> tuple[FakeClientProvider, type[ResourceCollector], SecurityRule]:
    client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [{"Buckets": [{"Name": "boundary-bucket", "BucketRegion": "us-east-1"}]}]
            )
        },
        responses={
            "get_bucket_tagging": [{"TagSet": []}],
            "get_bucket_encryption": [
                {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": None}}]
                    }
                }
            ],
        },
    )
    return (
        FakeClientProvider({("s3", "us-east-1"): client}),
        S3BucketCollector,
        MissingBucketEncryptionRule(),
    )


def _cloudtrail_case() -> tuple[FakeClientProvider, type[ResourceCollector], SecurityRule]:
    trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/boundary"
    client = FakeAWSClient(
        paginators={
            "list_trails": FakePaginator(
                [
                    {
                        "Trails": [
                            {
                                "TrailARN": trail_arn,
                                "Name": "boundary",
                                "HomeRegion": "us-east-1",
                            }
                        ]
                    }
                ]
            )
        },
        responses={
            "get_trail": [
                {
                    "Trail": {
                        "TrailARN": trail_arn,
                        "Name": "boundary",
                        "HomeRegion": "us-east-1",
                    }
                }
            ],
            "get_trail_status": [{"IsLogging": "yes"}],
        },
    )
    return (
        FakeClientProvider({("cloudtrail", "us-east-1"): client}),
        CloudTrailCollector,
        MissingCloudTrailRule(),
    )


def _security_group_case() -> tuple[FakeClientProvider, type[ResourceCollector], SecurityRule]:
    client = FakeAWSClient(
        paginators={
            "describe_security_groups": FakePaginator(
                [
                    {
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-boundary",
                                "IpPermissions": [
                                    {
                                        "IpProtocol": "tcp",
                                        "FromPort": 22,
                                        "ToPort": 22,
                                        "IpRanges": [{"CidrIp": None}],
                                        "Ipv6Ranges": [],
                                    }
                                ],
                                "IpPermissionsEgress": [],
                            }
                        ]
                    }
                ]
            )
        }
    )
    return (
        FakeClientProvider({("ec2", "us-east-1"): client}),
        SecurityGroupCollector,
        PublicSSHRule(),
    )


@pytest.mark.parametrize(
    "case_factory",
    (_iam_case, _s3_case, _cloudtrail_case, _security_group_case),
    ids=("iam", "s3", "cloudtrail", "security-group"),
)
def test_malformed_collector_evidence_becomes_partial_and_never_passes(
    case_factory,
) -> None:
    provider, collector_type, rule = case_factory()
    collector = collector_type(provider)

    snapshot = InventoryService(provider, collectors=(collector,)).collect()
    assessments = rule.assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)

    assert snapshot.resources == ()
    assert snapshot.collection_status(collector.collector_name) is CollectionStatus.PARTIAL
    assert len(assessments) == 1
    assert assessments[0].result is AssessmentResult.INSUFFICIENT_EVIDENCE


def test_all_collectors_preserve_valid_empty_inventory_semantics() -> None:
    provider = FakeClientProvider(
        {
            ("ec2", "us-east-1"): FakeAWSClient(
                paginators={"describe_security_groups": FakePaginator([{"SecurityGroups": []}])}
            ),
            ("s3", "us-east-1"): FakeAWSClient(
                paginators={"list_buckets": FakePaginator([{"Buckets": []}])}
            ),
            ("iam", "us-east-1"): FakeAWSClient(
                paginators={"list_users": FakePaginator([{"Users": []}])}
            ),
            ("cloudtrail", "us-east-1"): FakeAWSClient(
                paginators={"list_trails": FakePaginator([{"Trails": []}])}
            ),
        }
    )

    snapshot = InventoryService(provider).collect()

    assert snapshot.resources == ()
    assert all(
        outcome.status is CollectionStatus.SUCCEEDED for outcome in snapshot.collector_outcomes
    )
    assert IAMUserWithoutMFARule().assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)[0].result is (
        AssessmentResult.NOT_APPLICABLE
    )
    assert (
        MissingBucketEncryptionRule().assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)[0].result
        is AssessmentResult.NOT_APPLICABLE
    )
    assert PublicSSHRule().assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)[0].result is (
        AssessmentResult.NOT_APPLICABLE
    )
    assert MissingCloudTrailRule().assess(snapshot, DEFAULT_ASSESSMENT_PROFILE)[0].result is (
        AssessmentResult.FAIL
    )
