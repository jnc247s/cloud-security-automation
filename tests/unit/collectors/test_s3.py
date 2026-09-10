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


@pytest.mark.parametrize(
    "bucket",
    (
        {},
        {"Name": None},
        {"Name": 123},
        {"Name": ""},
        {"Name": "   "},
    ),
)
def test_rejects_missing_null_or_malformed_bucket_identity(
    bucket: dict[str, object],
) -> None:
    client = FakeAWSClient(paginators={"list_buckets": FakePaginator([{"Buckets": [bucket]}])})

    with pytest.raises(CollectorEvidenceError) as error_info:
        S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()

    assert error_info.value.operation_name == "list_buckets"
    assert error_info.value.fact_path == "Buckets[].Name"
    assert '"None"' not in str(error_info.value)


@pytest.mark.parametrize("bucket_region", (None, 1, "", "  "))
def test_rejects_explicit_invalid_optional_bucket_region(bucket_region: object) -> None:
    client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [{"Buckets": [{"Name": "example-bucket", "BucketRegion": bucket_region}]}]
            )
        }
    )

    with pytest.raises(CollectorEvidenceError, match="BucketRegion"):
        S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()

    assert client.calls == []


def test_valid_empty_bucket_inventory_succeeds() -> None:
    client = FakeAWSClient(
        paginators={"list_buckets": FakePaginator([{"Buckets": []}, {"Buckets": []}])}
    )

    assert S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect() == []


def test_exact_repeated_bucket_is_collected_and_enriched_once() -> None:
    bucket = {"Name": "repeated-bucket", "BucketRegion": "us-east-1"}
    client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [{"Buckets": [bucket]}, {"Buckets": []}, {"Buckets": [dict(bucket)]}]
            )
        },
        responses={
            "get_bucket_tagging": [{"TagSet": []}],
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

    resources = S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()

    assert [resource.aws_resource_id for resource in resources] == ["repeated-bucket"]
    assert [call.operation_name for call in client.calls] == [
        "get_bucket_tagging",
        "get_bucket_encryption",
        "get_public_access_block",
    ]


def test_conflicting_duplicate_bucket_is_rejected_as_ambiguous() -> None:
    client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [
                    {"Buckets": [{"Name": "duplicate", "BucketRegion": "us-east-1"}]},
                    {"Buckets": [{"Name": "duplicate", "BucketRegion": "us-west-2"}]},
                ]
            )
        },
        responses={
            "get_bucket_tagging": [{"TagSet": []}],
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

    with pytest.raises(CollectorEvidenceError, match="duplicate_identity"):
        S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()


@pytest.mark.parametrize(
    "head_response",
    (
        None,
        [],
        {},
        {"BucketRegion": None},
        {"BucketRegion": 1},
        {"ResponseMetadata": None},
        {"ResponseMetadata": {"HTTPHeaders": None}},
        {"ResponseMetadata": {"HTTPHeaders": {"x-amz-bucket-region": None}}},
    ),
)
def test_rejects_malformed_head_bucket_region_evidence(head_response: object) -> None:
    client = FakeAWSClient(
        paginators={"list_buckets": FakePaginator([{"Buckets": [{"Name": "private-bucket"}]}])},
        responses={"head_bucket": [head_response]},
    )

    with pytest.raises(CollectorEvidenceError) as error_info:
        S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()

    assert error_info.value.operation_name == "head_bucket"
    assert "private-bucket" not in str(error_info.value)


@pytest.mark.parametrize(
    "tagging_response",
    (
        None,
        [],
        {},
        {"TagSet": None},
        {"TagSet": "not-a-list"},
        {"TagSet": [None]},
        {"TagSet": [{}]},
        {"TagSet": [{"Key": None, "Value": "owner"}]},
        {"TagSet": [{"Key": "Owner", "Value": None}]},
    ),
)
def test_rejects_malformed_bucket_tag_evidence(tagging_response: object) -> None:
    client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [{"Buckets": [{"Name": "tagged-bucket", "BucketRegion": "us-east-1"}]}]
            )
        },
        responses={"get_bucket_tagging": [tagging_response]},
    )

    with pytest.raises(CollectorEvidenceError, match="get_bucket_tagging"):
        S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()


@pytest.mark.parametrize(
    "encryption_response",
    (
        None,
        [],
        {"ServerSideEncryptionConfiguration": None},
        {"ServerSideEncryptionConfiguration": {}},
        {"ServerSideEncryptionConfiguration": {"Rules": None}},
        {"ServerSideEncryptionConfiguration": {"Rules": []}},
        {"ServerSideEncryptionConfiguration": {"Rules": [None]}},
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": None}]
            }
        },
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {}}]
            }
        },
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "unknown"}}]
            }
        },
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                        "BucketKeyEnabled": 1,
                    }
                ]
            }
        },
    ),
)
def test_rejects_malformed_nested_encryption_evidence(
    encryption_response: object,
) -> None:
    client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [{"Buckets": [{"Name": "encrypted", "BucketRegion": "us-east-1"}]}]
            )
        },
        responses={
            "get_bucket_tagging": [{"TagSet": []}],
            "get_bucket_encryption": [encryption_response],
        },
    )

    with pytest.raises(CollectorEvidenceError, match="get_bucket_encryption"):
        S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()


@pytest.mark.parametrize(
    "public_access_block",
    (
        None,
        [],
        {"PublicAccessBlockConfiguration": None},
        {"PublicAccessBlockConfiguration": {"BlockPublicAcls": 1}},
        {"PublicAccessBlockConfiguration": {"RestrictPublicBuckets": "false"}},
    ),
)
def test_rejects_malformed_public_access_block_evidence(
    public_access_block: object,
) -> None:
    client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [{"Buckets": [{"Name": "protected", "BucketRegion": "us-east-1"}]}]
            )
        },
        responses={
            "get_bucket_tagging": [{"TagSet": []}],
            "get_bucket_encryption": [
                {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                        ]
                    }
                }
            ],
            "get_public_access_block": [public_access_block],
        },
    )

    with pytest.raises(CollectorEvidenceError, match="get_public_access_block"):
        S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()


def test_accepts_current_aws_backup_encryption_enum_without_deciding_control_result() -> None:
    client = FakeAWSClient(
        paginators={
            "list_buckets": FakePaginator(
                [{"Buckets": [{"Name": "backup-bucket", "BucketRegion": "us-east-1"}]}]
            )
        },
        responses={
            "get_bucket_tagging": [{"TagSet": []}],
            "get_bucket_encryption": [
                {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:backup"}}
                        ]
                    }
                }
            ],
            "get_public_access_block": [{"PublicAccessBlockConfiguration": {}}],
        },
    )

    resource = S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()[0]

    assert (
        resource.configuration["default_encryption"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["SSEAlgorithm"]
        == "aws:backup"
    )


def test_propagates_s3_throttling_as_an_operational_error() -> None:
    error = client_error("Throttling", "ListBuckets", status_code=429)
    client = FakeAWSClient(paginators={"list_buckets": FakePaginator(error=error)})

    with pytest.raises(ClientError) as error_info:
        S3BucketCollector(FakeClientProvider({("s3", "us-east-1"): client})).collect()

    assert error_info.value.response["Error"]["Code"] == "Throttling"
