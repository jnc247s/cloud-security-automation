"""Tests for S3 bucket collection."""

from datetime import UTC, datetime

import pytest
from botocore.exceptions import ClientError

from app.collectors.base import CollectorEvidenceError
from app.collectors.s3 import S3BucketCollector
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, RecordedCall, client_error


def test_collects_all_bucket_pages_and_normalizes_configuration() -> None:
    created_at = datetime(2025, 1, 2, 3, 4, tzinfo=UTC)
    paginator = FakePaginator(
        [
            {
                "Buckets": [
                    {
                        "Name": "inventory-east",
                        "CreationDate": created_at,
                        "BucketRegion": "us-east-1",
                    }
                ]
            },
            {
                "Buckets": [
                    {
                        "Name": "inventory-west",
                        "CreationDate": created_at,
                        "BucketRegion": "us-west-2",
                    }
                ]
            },
        ]
    )
    east_client = FakeAWSClient(
        paginators={"list_buckets": paginator},
        responses={
            "get_bucket_tagging": [{"TagSet": [{"Key": "Owner", "Value": "platform"}]}],
            "get_bucket_encryption": [
                {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                        ]
                    }
                }
            ],
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
        },
    )
    west_client = FakeAWSClient(
        responses={
            "get_bucket_tagging": [{"TagSet": []}],
            "get_bucket_encryption": [
                {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "aws:kms",
                                    "KMSMasterKeyID": "arn:aws:kms:us-west-2:123:key/key-id",
                                },
                                "BucketKeyEnabled": True,
                            }
                        ]
                    }
                }
            ],
            "get_public_access_block": [
                {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    }
                },
            ],
        },
    )
    provider = FakeClientProvider(
        {
            ("s3", "us-east-1"): east_client,
            ("s3", "us-west-2"): west_client,
        }
    )

    resources = S3BucketCollector(provider).collect()

    assert [resource.aws_resource_id for resource in resources] == [
        "inventory-east",
        "inventory-west",
    ]
    assert paginator.calls == [{"PaginationConfig": {"PageSize": 1000}}]
    assert resources[0].configuration["creation_date"] == "2025-01-02T03:04:00+00:00"
    assert (
        resources[0].configuration["default_encryption"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["SSEAlgorithm"]
        == "AES256"
    )
    assert resources[1].region == "us-west-2"
    assert resources[1].arn == "arn:aws:s3:::inventory-west"
    assert resources[1].configuration["public_access_block"]["BlockPublicAcls"] is False
    assert resources[0].tags == {"Owner": "platform"}
    assert provider.client_requests == [
        ("s3", "us-east-1"),
        ("s3", "us-east-1"),
        ("s3", "us-west-2"),
    ]

    expected_owner = "123456789012"
    configuration_calls = east_client.calls + west_client.calls
    assert all(
        call.parameters["ExpectedBucketOwner"] == expected_owner for call in configuration_calls
    )


def test_normalizes_expected_missing_configuration_and_head_bucket_region() -> None:
    paginator = FakePaginator([{"Buckets": [{"Name": "legacy-bucket"}]}])
    client = FakeAWSClient(
        paginators={"list_buckets": paginator},
        responses={
            "head_bucket": [
                {"ResponseMetadata": {"HTTPHeaders": {"x-amz-bucket-region": "eu-west-1"}}}
            ],
            "get_bucket_tagging": [
                client_error("NoSuchTagSet", "GetBucketTagging", status_code=404)
            ],
            "get_bucket_encryption": [
                client_error(
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "GetBucketEncryption",
                    status_code=404,
                )
            ],
            "get_public_access_block": [
                client_error(
                    "NoSuchPublicAccessBlockConfiguration",
                    "GetPublicAccessBlock",
                    status_code=404,
                )
            ],
        },
    )
    provider = FakeClientProvider(
        {
            ("s3", "us-east-1"): client,
            ("s3", "eu-west-1"): client,
        }
    )

    resource = S3BucketCollector(provider).collect()[0]

    assert resource.region == "eu-west-1"
    assert resource.tags == {}
    assert resource.configuration["default_encryption"] is None
    assert resource.configuration["public_access_block"] is None
    assert client.calls[0] == RecordedCall(
        "head_bucket",
        {"Bucket": "legacy-bucket", "ExpectedBucketOwner": "123456789012"},
    )


def test_propagates_unexpected_s3_configuration_errors() -> None:
    paginator = FakePaginator(
        [{"Buckets": [{"Name": "denied-bucket", "BucketRegion": "us-east-1"}]}]
    )
    error = client_error("AccessDenied", "GetBucketTagging", status_code=403)
    client = FakeAWSClient(
        paginators={"list_buckets": paginator},
        responses={"get_bucket_tagging": [error]},
    )
    provider = FakeClientProvider({("s3", "us-east-1"): client})

    with pytest.raises(ClientError) as exc_info:
        S3BucketCollector(provider).collect()

    assert exc_info.value.response["Error"]["Code"] == "AccessDenied"


def test_rejects_successful_s3_response_missing_required_configuration() -> None:
    paginator = FakePaginator(
        [{"Buckets": [{"Name": "ambiguous-bucket", "BucketRegion": "us-east-1"}]}]
    )
    client = FakeAWSClient(
        paginators={"list_buckets": paginator},
        responses={
            "get_bucket_tagging": [{"TagSet": []}],
            "get_bucket_encryption": [{}],
        },
    )
    provider = FakeClientProvider({("s3", "us-east-1"): client})

    with pytest.raises(CollectorEvidenceError, match="ServerSideEncryptionConfiguration"):
        S3BucketCollector(provider).collect()
