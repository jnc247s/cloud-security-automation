"""Tests for S3 bucket collection."""

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from botocore.exceptions import ClientError

from app.assessment.evidence_graph import SourceEvidenceArtifact
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipType,
    UnresolvedRelationshipTarget,
)
from app.assessment.source_outcomes import (
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
    SourceEvidenceOutcome,
)
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceError,
    CollectorResult,
    graph_collection_status_for,
)
from app.collectors.s3 import S3BucketCollector, S3CollectionBundle, S3EvidenceCollector
from app.schemas.inventory import CollectionStatus
from tests.fakes import FakeAWSClient, FakeClientProvider, FakePaginator, RecordedCall, client_error

_USE_LOCATION_REGION = object()


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


def test_5e_shared_bundle_collects_s3_and_referenced_kms_once() -> None:
    bucket_name = "sensitive-data"
    kms_arn = "arn:aws:kms:us-east-1:123456789012:key/key-1"
    s3_client = _complete_5e_s3_client(
        bucket_name=bucket_name,
        location_constraint=None,
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": kms_arn,
                },
                "BucketKeyEnabled": True,
            }
        ],
    )
    kms_client = FakeAWSClient(
        responses={
            "describe_key": [
                {
                    "KeyMetadata": {
                        "AWSAccountId": "123456789012",
                        "KeyId": "key-1",
                        "Arn": kms_arn,
                        "KeyManager": "CUSTOMER",
                        "Enabled": True,
                        "KeyState": "Enabled",
                        "Origin": "AWS_KMS",
                        "KeyUsage": "ENCRYPT_DECRYPT",
                        "KeySpec": "SYMMETRIC_DEFAULT",
                        "MultiRegion": False,
                    }
                }
            ]
        }
    )
    provider = _provider_for_5e(s3_client=s3_client, kms_client=kms_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert len(legacy.resources) == 1
    bucket = legacy.resources[0]
    assert bucket.region == "us-east-1"
    assert bucket.tags == {"Classification": "restricted"}
    assert bucket.configuration["encryption"]["rules"][0] == {
        "sse_algorithm": "aws:kms",
        "kms_key_reference": kms_arn,
        "kms_reference_explicit": True,
        "key_management": "EXPLICIT_KMS_REFERENCE",
        "bucket_key_enabled": True,
        "blocked_encryption_types": [],
    }
    assert (
        bucket.configuration["default_encryption"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["SSEAlgorithm"]
        == "aws:kms"
    )
    assert evidence.status is CollectionStatus.SUCCEEDED
    assert (
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=evidence.source_outcomes,
            artifacts=evidence.artifacts,
            contracts=evidence.source_contracts,
        )
        is evidence.status
    )
    assert len(evidence.resources) == 1
    key = evidence.resources[0]
    assert key.aws_resource_id == kms_arn
    assert key.account_id == "123456789012"
    assert key.configuration["key_manager"] == "CUSTOMER"
    assert [call.operation_name for call in kms_client.calls] == ["describe_key"]
    assert s3_client.paginator_requests == ["list_buckets"]
    assert sum(call.operation_name == "get_bucket_location" for call in s3_client.calls) == 1

    location = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.bucket-location"
    )
    location_artifact = next(
        artifact
        for artifact in evidence.artifacts
        if artifact.evidence_reference == location.evidence_reference
    )
    assert location.state is EvidenceSourceState.PRESENT
    assert location_artifact.normalized_payload["location_constraint"] is None
    assert location_artifact.normalized_payload["bucket_region"] == "us-east-1"
    assert len(evidence.relationships) == 1
    relationship = evidence.relationships[0]
    assert relationship.relationship_type is RelationshipType.ENCRYPTED_WITH
    assert relationship.source.aws_resource_id == bucket_name
    assert isinstance(relationship.target, RelationshipEndpoint)
    assert relationship.target.aws_resource_id == kms_arn


def test_5e_manifest_rejects_account_public_access_block_for_another_account() -> None:
    s3_client = _complete_5e_s3_client(bucket_name="sensitive-data")
    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )
    account_source = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.account-public-access-block"
    )
    mismatched_subject = account_source.subject.model_copy(
        update={"aws_account_id": "999900001111"}
    )
    mismatched_source = account_source.model_copy(update={"subject": mismatched_subject})
    outcomes = tuple(
        mismatched_source if outcome is account_source else outcome
        for outcome in evidence.source_outcomes
    )
    contracts = tuple(
        contract.model_copy(update={"subject": mismatched_subject})
        if contract.source_outcome_id == account_source.source_outcome_id
        else contract
        for contract in evidence.source_contracts
    )

    with pytest.raises(ValueError, match="5E S3 source identity"):
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=outcomes,
            artifacts=evidence.artifacts,
            contracts=contracts,
        )


def test_5e_replay_rejects_tampered_account_public_access_block_payload() -> None:
    s3_client = _complete_5e_s3_client(bucket_name="account-bpa-binding")
    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )
    outcomes, artifacts = _rebound_source_payload(
        evidence,
        evidence_kind="s3.account-public-access-block",
        updates={
            "account_id": "999900001111",
            "configured": False,
            "public_access_block": {"BlockPublicAcls": True},
        },
    )

    with pytest.raises(ValueError, match="account Public Access Block evidence"):
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=outcomes,
            artifacts=artifacts,
            contracts=evidence.source_contracts,
        )


def test_5e_expected_absences_and_legacy_eu_location_are_complete() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="legacy-eu",
        location_constraint="EU",
        tag_response=client_error("NoSuchTagSet", "GetBucketTagging", status_code=404),
        public_access_block_response=client_error(
            "NoSuchPublicAccessBlockConfiguration",
            "GetPublicAccessBlock",
            status_code=404,
        ),
        policy_response=client_error(
            "NoSuchBucketPolicy",
            "GetBucketPolicy",
            status_code=404,
        ),
        policy_status_response=client_error(
            "NoSuchBucketPolicy",
            "GetBucketPolicyStatus",
            status_code=404,
        ),
        versioning_response={},
        encryption_response=client_error(
            "ServerSideEncryptionConfigurationNotFoundError",
            "GetBucketEncryption",
            status_code=404,
        ),
        ownership_response=client_error(
            "OwnershipControlsNotFoundError",
            "GetBucketOwnershipControls",
            status_code=404,
        ),
    )
    s3control = FakeAWSClient(
        responses={
            "get_public_access_block": [
                client_error(
                    "NoSuchPublicAccessBlockConfiguration",
                    "GetPublicAccessBlock",
                    status_code=404,
                )
            ]
        }
    )
    provider = _provider_for_5e(s3_client=s3_client, s3control_client=s3control)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].region == "eu-west-1"
    assert legacy.resources[0].tags == {}
    assert legacy.resources[0].configuration["default_encryption"] is None
    assert evidence.status is CollectionStatus.SUCCEEDED
    absent_kinds = {
        outcome.evidence_kind
        for outcome in evidence.source_outcomes
        if outcome.state is EvidenceSourceState.EXPECTED_ABSENCE
    }
    assert absent_kinds == {
        "s3.account-public-access-block",
        "s3.bucket-tags",
        "s3.bucket-public-access-block",
        "s3.bucket-policy",
        "s3.bucket-policy-status",
        "s3.bucket-versioning",
        "s3.bucket-encryption",
        "s3.bucket-ownership-controls",
    }


def test_5e_accepts_absent_policy_with_successful_nonpublic_status() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="policy-absent-nonpublic",
        policy_response=client_error(
            "NoSuchBucketPolicy",
            "GetBucketPolicy",
            status_code=404,
        ),
        policy_status_response={"PolicyStatus": {"IsPublic": False}},
    )

    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )

    states = {outcome.evidence_kind: outcome.state for outcome in evidence.source_outcomes}
    assert evidence.status is CollectionStatus.SUCCEEDED
    assert states["s3.bucket-policy"] is EvidenceSourceState.EXPECTED_ABSENCE
    assert states["s3.bucket-policy-status"] is EvidenceSourceState.PRESENT


@pytest.mark.parametrize(
    ("policy_response", "policy_status_response"),
    [
        pytest.param(
            client_error("NoSuchBucketPolicy", "GetBucketPolicy", status_code=404),
            {"PolicyStatus": {"IsPublic": True}},
            id="absent-policy-public-status",
        ),
        pytest.param(
            {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:*",
                                "Resource": "arn:aws:s3:::policy-coherence",
                            }
                        ]
                    }
                )
            },
            client_error("NoSuchBucketPolicy", "GetBucketPolicyStatus", status_code=404),
            id="present-policy-absent-status",
        ),
        pytest.param(
            {
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "S3:GetObject",
                                "Resource": "arn:aws:s3:::policy-coherence/*",
                            }
                        ]
                    }
                )
            },
            {"PolicyStatus": {"IsPublic": False}},
            id="unconditional-public-policy-nonpublic-status",
        ),
    ],
)
def test_5e_retains_contradictory_policy_sources_as_paired_conflicts(
    policy_response: object,
    policy_status_response: object,
) -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="policy-coherence",
        policy_response=policy_response,
        policy_status_response=policy_status_response,
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    policy_outcomes = {
        outcome.evidence_kind: outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind in {"s3.bucket-policy", "s3.bucket-policy-status"}
    }
    assert legacy.status is CollectionStatus.SUCCEEDED
    assert evidence.status is CollectionStatus.PARTIAL
    assert set(policy_outcomes) == {"s3.bucket-policy", "s3.bucket-policy-status"}
    assert all(
        outcome.state is EvidenceSourceState.CONFLICT
        and outcome.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
        for outcome in policy_outcomes.values()
    )


def test_5e_marks_public_acl_with_effective_ignore_public_acls_as_conflict() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="public-acl-conflict",
        ownership_response={
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
        },
        acl_response={
            "Owner": {"ID": "canonical-owner"},
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ],
        },
    )

    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )

    outcomes = evidence.source_outcomes
    acl = next(item for item in outcomes if item.collector == "s3.bucket-acl")
    artifact = next(
        item for item in evidence.artifacts if item.evidence_reference == acl.evidence_reference
    )
    assert evidence.status is CollectionStatus.PARTIAL
    assert acl.state is EvidenceSourceState.CONFLICT
    assert acl.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    assert artifact.normalized_payload["value"]["grants"][0]["permission"] == "READ"


def test_5e_marks_bucket_owner_enforced_acl_mismatch_as_conflict() -> None:
    all_false = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    s3_client = _complete_5e_s3_client(
        bucket_name="ownership-acl-conflict",
        public_access_block_response={"PublicAccessBlockConfiguration": all_false},
        acl_response={
            "Owner": {"ID": "canonical-owner"},
            "Grants": [
                {
                    "Grantee": {"Type": "CanonicalUser", "ID": "canonical-owner"},
                    "Permission": "FULL_CONTROL",
                },
                {
                    "Grantee": {"Type": "CanonicalUser", "ID": "external-owner"},
                    "Permission": "READ",
                },
            ],
        },
    )
    s3control = FakeAWSClient(
        responses={"get_public_access_block": [{"PublicAccessBlockConfiguration": all_false}]}
    )

    evidence = S3EvidenceCollector(
        _provider_for_5e(s3_client=s3_client, s3control_client=s3control)
    ).collect_with_context(_collection_context())

    outcomes = evidence.source_outcomes
    acl = next(item for item in outcomes if item.collector == "s3.bucket-acl")
    assert evidence.status is CollectionStatus.PARTIAL
    assert acl.state is EvidenceSourceState.CONFLICT
    assert acl.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE


@pytest.mark.parametrize(
    "grantee",
    [
        {
            "Type": "CanonicalUser",
            "ID": "canonical-owner",
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
        },
        {
            "Type": "Group",
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
            "ID": "canonical-owner",
        },
        {
            "Type": "AmazonCustomerByEmail",
            "EmailAddress": "owner@example.test",
            "ID": "canonical-owner",
        },
    ],
)
def test_5e_rejects_acl_grantee_with_conflicting_identity_fields(
    grantee: dict[str, str],
) -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="malformed-acl-grantee",
        acl_response={
            "Owner": {"ID": "canonical-owner"},
            "Grants": [{"Grantee": grantee, "Permission": "FULL_CONTROL"}],
        },
    )

    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )

    acl = next(item for item in evidence.source_outcomes if item.collector == "s3.bucket-acl")
    assert evidence.status is CollectionStatus.PARTIAL
    assert acl.state is EvidenceSourceState.MALFORMED
    assert acl.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE


def test_5e_rejects_multiple_bucket_ownership_rules() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="malformed-ownership-controls",
        ownership_response={
            "OwnershipControls": {
                "Rules": [
                    {"ObjectOwnership": "BucketOwnerPreferred"},
                    {"ObjectOwnership": "BucketOwnerEnforced"},
                ]
            }
        },
    )

    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )

    ownership = next(
        item
        for item in evidence.source_outcomes
        if item.collector == "s3.bucket-ownership-controls"
    )
    assert evidence.status is CollectionStatus.PARTIAL
    assert ownership.state is EvidenceSourceState.MALFORMED
    assert ownership.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE


@pytest.mark.parametrize("encryption_type", ["NONE", "SSE-C"])
def test_5e_accepts_blocked_encryption_type_without_default_encryption(
    encryption_type: str,
) -> None:
    configuration = {"Rules": [{"BlockedEncryptionTypes": {"EncryptionType": [encryption_type]}}]}
    s3_client = _complete_5e_s3_client(
        bucket_name="blocked-encryption-type",
        encryption_response={"ServerSideEncryptionConfiguration": configuration},
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    encryption = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.collector == "s3.bucket-encryption"
    )
    artifact = next(
        item
        for item in evidence.artifacts
        if item.evidence_reference == encryption.evidence_reference
    )
    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].configuration["default_encryption"] == configuration
    assert evidence.status is CollectionStatus.SUCCEEDED
    assert encryption.state is EvidenceSourceState.PRESENT
    payload = artifact.model_dump(mode="json")["normalized_payload"]
    assert payload["value"]["rules"] == [
        {
            "sse_algorithm": None,
            "kms_key_reference": None,
            "kms_reference_explicit": False,
            "key_management": None,
            "bucket_key_enabled": None,
            "blocked_encryption_types": [encryption_type],
        }
    ]


@pytest.mark.parametrize(
    "encryption_types",
    [[], ["NONE", "SSE-C"], ["UNKNOWN"]],
)
def test_5e_rejects_invalid_blocked_encryption_type_states(
    encryption_types: list[str],
) -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="invalid-blocked-encryption-type",
        encryption_response={
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"BlockedEncryptionTypes": {"EncryptionType": encryption_types}}]
            }
        },
    )

    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )

    encryption = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.collector == "s3.bucket-encryption"
    )
    assert encryption.state is EvidenceSourceState.MALFORMED


@pytest.mark.parametrize("algorithm", ["AES256", "aws:kms:dsse"])
def test_5e_bucket_key_true_requires_standard_sse_kms_without_changing_legacy(
    algorithm: str,
) -> None:
    configuration = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": algorithm},
                "BucketKeyEnabled": True,
            }
        ]
    }
    s3_client = _complete_5e_s3_client(
        bucket_name="invalid-bucket-key",
        encryption_response={"ServerSideEncryptionConfiguration": configuration},
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    encryption = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.collector == "s3.bucket-encryption"
    )
    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].configuration["default_encryption"] == configuration
    assert evidence.status is CollectionStatus.PARTIAL
    assert encryption.state is EvidenceSourceState.MALFORMED


@pytest.mark.parametrize(
    "metadata_update",
    [
        {"Enabled": True, "KeyState": "Disabled"},
        {"Enabled": False, "KeyState": "Enabled"},
        {"Enabled": True, "KeyState": "BOGUS"},
        {"Origin": "BOGUS"},
        {"KeyUsage": "BOGUS"},
        {"KeySpec": "BOGUS"},
        {"KeySpec": "HMAC_256", "KeyUsage": "ENCRYPT_DECRYPT"},
    ],
)
def test_5e_rejects_invalid_or_contradictory_kms_metadata(
    metadata_update: dict[str, object],
) -> None:
    reference = "alias/invalid-metadata"
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/key-invalid-metadata"
    s3_client = _complete_5e_s3_client(
        bucket_name="invalid-kms-metadata",
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": reference,
                }
            }
        ],
    )
    metadata = {
        "AWSAccountId": "123456789012",
        "KeyId": "key-invalid-metadata",
        "Arn": key_arn,
        "KeyManager": "CUSTOMER",
        "Enabled": True,
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeySpec": "SYMMETRIC_DEFAULT",
        **metadata_update,
    }
    kms_client = FakeAWSClient(responses={"describe_key": [{"KeyMetadata": metadata}]})

    evidence = S3EvidenceCollector(
        _provider_for_5e(s3_client=s3_client, kms_client=kms_client)
    ).collect_with_context(_collection_context())

    kms = next(outcome for outcome in evidence.source_outcomes if outcome.collector == "kms.keys")
    assert evidence.status is CollectionStatus.PARTIAL
    assert kms.state is EvidenceSourceState.MALFORMED
    assert kms.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE


def test_5e_rejects_mfa_delete_without_versioning_status() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="invalid-versioning",
        versioning_response={"MFADelete": "Enabled"},
    )

    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )

    versioning = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.collector == "s3.bucket-versioning"
    )
    assert evidence.status is CollectionStatus.PARTIAL
    assert versioning.state is EvidenceSourceState.MALFORMED


def test_5e_rejects_literal_us_east_1_location_constraint_without_losing_legacy() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="invalid-east-location",
        location_response={"LocationConstraint": "us-east-1"},
        list_bucket_region="us-east-1",
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    location = next(
        outcome for outcome in evidence.source_outcomes if outcome.collector == "s3.bucket-location"
    )
    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].region == "us-east-1"
    assert evidence.status is CollectionStatus.PARTIAL
    assert location.state is EvidenceSourceState.MALFORMED


def test_5e_policy_failure_is_independent_from_legacy_s3_900_coverage() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="policy-denied",
        policy_response=client_error("AccessDenied", "GetBucketPolicy", status_code=403),
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].configuration["default_encryption"] is not None
    assert evidence.status is CollectionStatus.PARTIAL
    policy = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.bucket-policy"
    )
    assert policy.state is EvidenceSourceState.UNAVAILABLE
    assert policy.failure_category is EvidenceFailureCategory.ACCESS_DENIED


def test_5e_stricter_shapes_do_not_change_accepted_legacy_s3_coverage() -> None:
    encryption_configuration = {
        "Rules": [
            {
                "BucketKeyEnabled": True,
                "BlockedEncryptionTypes": {"EncryptionType": "SSE-C"},
            }
        ]
    }
    legacy_public_access_block = {"BlockPublicAcls": True}
    s3_client = _complete_5e_s3_client(
        bucket_name="legacy-shapes",
        encryption_response={"ServerSideEncryptionConfiguration": encryption_configuration},
        public_access_block_response={"PublicAccessBlockConfiguration": legacy_public_access_block},
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].configuration["default_encryption"] == encryption_configuration
    assert legacy.resources[0].configuration["public_access_block"] == legacy_public_access_block
    source_states = {outcome.evidence_kind: outcome.state for outcome in evidence.source_outcomes}
    assert source_states["s3.bucket-encryption"] is EvidenceSourceState.MALFORMED
    assert source_states["s3.bucket-public-access-block"] is EvidenceSourceState.MALFORMED
    assert evidence.status is CollectionStatus.PARTIAL


def test_5e_rejects_duplicate_policy_keys_without_exposing_policy_text() -> None:
    duplicate_policy = (
        '{"Statement":[{"Effect":"Allow","Effect":"Deny","Principal":"*",'
        '"Action":"s3:GetObject","Resource":"arn:aws:s3:::example/*"}]}'
    )
    s3_client = _complete_5e_s3_client(
        bucket_name="duplicate-policy",
        policy_response={"Policy": duplicate_policy},
    )
    provider = _provider_for_5e(s3_client=s3_client)
    context = _collection_context()

    evidence = S3EvidenceCollector(provider).collect_with_context(context)

    policy = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.bucket-policy"
    )
    artifact = next(
        item for item in evidence.artifacts if item.evidence_reference == policy.evidence_reference
    )
    assert policy.state is EvidenceSourceState.MALFORMED
    assert policy.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert artifact.normalized_payload["value"] is None
    assert duplicate_policy not in artifact.model_dump_json()


@pytest.mark.parametrize(
    "invalid_field",
    (
        '"Principal":42,"Action":"s3:GetObject","Resource":"arn:aws:s3:::example/*"',
        '"Principal":"*","Action":{},"Resource":"arn:aws:s3:::example/*"',
        '"Principal":"*","Action":"s3:GetObject","Resource":false',
        (
            '"Principal":"*","Action":"s3:GetObject",'
            '"Resource":"arn:aws:s3:::example/*","Condition":{"Bool":true}'
        ),
    ),
)
def test_5e_rejects_malformed_policy_principal_action_resource_and_condition(
    invalid_field: str,
) -> None:
    encoded = f'{{"Statement":[{{"Effect":"Allow",{invalid_field}}}]}}'
    s3_client = _complete_5e_s3_client(
        bucket_name="malformed-policy",
        policy_response={"Policy": encoded},
    )
    provider = _provider_for_5e(s3_client=s3_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    policy = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.bucket-policy"
    )
    assert policy.state is EvidenceSourceState.MALFORMED
    assert policy.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE


def test_5e_failed_location_has_collision_safe_outcome_and_no_fabricated_bucket() -> None:
    s3_client = FakeAWSClient(
        paginators={"list_buckets": FakePaginator([{"Buckets": [{"Name": "unlocated"}]}])},
        responses={
            "get_bucket_location": [
                client_error("AccessDenied", "GetBucketLocation", status_code=403)
            ],
            "head_bucket": [client_error("AccessDenied", "HeadBucket", status_code=403)],
        },
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.FAILED
    assert legacy.resources == ()
    assert evidence.resources == ()
    location = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind.startswith("s3.bucket-location.")
    )
    suffix = location.evidence_kind.removeprefix("s3.bucket-location.")
    assert len(suffix) == 64
    assert location.state is EvidenceSourceState.UNAVAILABLE
    assert location.failure_category is EvidenceFailureCategory.ACCESS_DENIED


def test_5e_failed_location_preserves_legacy_list_region_without_graph_admission() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="legacy-list-region",
        list_bucket_region="eu-west-1",
        location_response=client_error("AccessDenied", "GetBucketLocation", status_code=403),
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert [resource.region for resource in legacy.resources] == ["eu-west-1"]
    legacy_bucket = legacy.resources[0]
    assert legacy_bucket.tags == {"Classification": "restricted"}
    assert set(legacy_bucket.configuration) == {
        "creation_date",
        "bucket_region",
        "default_encryption",
        "public_access_block",
    }
    assert legacy_bucket.configuration["bucket_region"] == "eu-west-1"
    assert legacy_bucket.configuration["default_encryption"] == {
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    }
    assert legacy_bucket.configuration["public_access_block"] == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    assert evidence.status is CollectionStatus.PARTIAL
    assert evidence.resources == ()
    assert not evidence.relationships
    assert all(
        not (
            hasattr(outcome.subject, "aws_resource_id")
            and outcome.subject.aws_resource_id == "legacy-list-region"
        )
        for outcome in evidence.source_outcomes
    )
    assert not any(call.operation_name == "head_bucket" for call in s3_client.calls)
    assert [call.operation_name for call in s3_client.calls] == [
        "get_bucket_location",
        "get_bucket_tagging",
        "get_bucket_encryption",
        "get_public_access_block",
    ]
    assert provider.client_requests.count(("s3", "eu-west-1")) == 1


def test_5e_location_conflict_retains_legacy_bucket_and_reconstructs_partial_graph() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="conflicting-location",
        location_constraint="eu-west-1",
        list_bucket_region=None,
        head_response={"BucketRegion": "us-east-1"},
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].region == "us-east-1"
    location = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind.startswith("s3.bucket-location.")
    )
    artifact = next(
        item
        for item in evidence.artifacts
        if item.evidence_reference == location.evidence_reference
    )
    assert location.state is EvidenceSourceState.CONFLICT
    assert location.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
    assert artifact.normalized_payload["location_constraint"] == "eu-west-1"
    assert artifact.normalized_payload["bucket_region"] is None
    assert (
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=evidence.source_outcomes,
            artifacts=evidence.artifacts,
            contracts=evidence.source_contracts,
        )
        is CollectionStatus.PARTIAL
    )
    assert sum(call.operation_name == "head_bucket" for call in s3_client.calls) == 1
    assert provider.client_requests.count(("s3", "us-east-1")) == 2


def test_5e_replay_rejects_authoritative_location_conflicting_with_legacy_region() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="tampered-location",
        list_bucket_region=None,
        head_response={"BucketRegion": "us-east-1"},
    )
    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )
    outcomes, artifacts = _rebound_source_payload(
        evidence,
        evidence_kind="s3.bucket-location",
        updates={"legacy_bucket_region": "eu-west-1"},
    )

    with pytest.raises(ValueError, match="successful S3 bucket-location identity"):
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=outcomes,
            artifacts=artifacts,
            contracts=evidence.source_contracts,
        )


def test_5e_failed_location_preserves_legacy_head_bucket_region() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="legacy-head-region",
        list_bucket_region=None,
        location_response=client_error("AccessDenied", "GetBucketLocation", status_code=403),
        head_response={"ResponseMetadata": {"HTTPHeaders": {"x-amz-bucket-region": "eu-west-1"}}},
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert [resource.region for resource in legacy.resources] == ["eu-west-1"]
    assert evidence.status is CollectionStatus.PARTIAL
    assert evidence.resources == ()
    assert sum(call.operation_name == "head_bucket" for call in s3_client.calls) == 1
    assert [call.operation_name for call in s3_client.calls] == [
        "get_bucket_location",
        "head_bucket",
        "get_bucket_tagging",
        "get_bucket_encryption",
        "get_public_access_block",
    ]
    assert provider.client_requests.count(("s3", "eu-west-1")) == 1


def test_5e_bucket_disappearing_after_list_is_typed_without_authoritative_admission() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="disappeared-bucket",
        location_response=client_error("NoSuchBucket", "GetBucketLocation", status_code=404),
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].region == "us-east-1"
    location = next(
        outcome for outcome in evidence.source_outcomes if outcome.collector == "s3.bucket-location"
    )
    contract = next(
        item
        for item in evidence.source_contracts
        if item.source_outcome_id == location.source_outcome_id
    )
    artifact = next(
        item
        for item in evidence.artifacts
        if item.evidence_reference == location.evidence_reference
    )
    assert location.phase is EvidenceCollectionPhase.ENRICHMENT
    assert isinstance(location.subject, ResourceEvidenceSubject)
    assert location.subject.aws_resource_id == "disappeared-bucket"
    assert location.state is EvidenceSourceState.RESOURCE_DISAPPEARED
    assert location.failure_category is EvidenceFailureCategory.RESOURCE_NOT_FOUND
    assert not contract.identity_authoritative
    assert artifact.normalized_payload["resource_not_found"] is True
    assert artifact.normalized_payload["bucket_region"] is None
    assert evidence.resources == ()
    assert (
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=evidence.source_outcomes,
            artifacts=evidence.artifacts,
            contracts=evidence.source_contracts,
        )
        is CollectionStatus.PARTIAL
    )


def test_5e_tag_artifact_encodes_sensitive_looking_tag_names_as_values() -> None:
    tags = {
        "Password": "classification-label",
        "Authorization": "application-team",
        "SecretKey": "rotation-policy",
    }
    s3_client = _complete_5e_s3_client(
        bucket_name="tagged-bucket",
        tag_response={"TagSet": [{"Key": key, "Value": value} for key, value in tags.items()]},
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.resources[0].tags == tags
    tag_outcome = next(
        outcome for outcome in evidence.source_outcomes if outcome.evidence_kind == "s3.bucket-tags"
    )
    artifact = next(
        item
        for item in evidence.artifacts
        if item.evidence_reference == tag_outcome.evidence_reference
    )
    payload = artifact.model_dump(mode="json")["normalized_payload"]
    assert payload["value"] == [
        {"key": "Authorization", "value": "application-team"},
        {"key": "Password", "value": "classification-label"},
        {"key": "SecretKey", "value": "rotation-policy"},
    ]


def test_5e_replay_rejects_per_bucket_payload_for_another_identity() -> None:
    s3_client = _complete_5e_s3_client(bucket_name="bound-bucket")
    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )
    outcomes, artifacts = _rebound_source_payload(
        evidence,
        evidence_kind="s3.bucket-tags",
        updates={
            "account_id": "999900001111",
            "bucket_name": "another-bucket",
            "bucket_arn": "arn:aws:s3:::another-bucket",
            "bucket_region": "eu-west-1",
        },
    )

    with pytest.raises(ValueError, match="per-bucket evidence identity"):
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=outcomes,
            artifacts=artifacts,
            contracts=evidence.source_contracts,
        )


def test_5e_malformed_location_region_never_reaches_provider_client() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="malformed-location",
        list_bucket_region="us-east-1",
        location_response={"LocationConstraint": "bad region"},
    )
    provider = _provider_for_5e(s3_client=s3_client)
    bundle = S3CollectionBundle(provider)
    context = _collection_context()

    legacy = S3BucketCollector(provider, collection_bundle=bundle).collect_with_context(context)
    evidence = S3EvidenceCollector(provider, collection_bundle=bundle).collect_with_context(context)

    assert legacy.status is CollectionStatus.SUCCEEDED
    assert legacy.resources[0].region == "us-east-1"
    location = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind.startswith("s3.bucket-location.")
    )
    assert location.state is EvidenceSourceState.MALFORMED
    assert location.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert ("s3", "bad region") not in provider.client_requests
    assert all(request[1] != "bad region" for request in provider.client_requests)


def test_5e_distinct_kms_references_coalesce_one_canonical_key_without_colliding() -> None:
    canonical_arn = "arn:aws:kms:us-east-1:123456789012:key/key-1"
    s3_client = _complete_5e_s3_client(
        bucket_name="alias-bucket",
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "alias/restricted-data",
                }
            },
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": canonical_arn,
                }
            },
        ],
    )
    metadata = {
        "AWSAccountId": "123456789012",
        "KeyId": "key-1",
        "Arn": canonical_arn,
        "KeyManager": "CUSTOMER",
    }
    kms_client = FakeAWSClient(
        responses={"describe_key": [{"KeyMetadata": metadata}, {"KeyMetadata": metadata}]}
    )
    provider = _provider_for_5e(s3_client=s3_client, kms_client=kms_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    assert len(kms_client.calls) == 2
    assert len(evidence.resources) == 1
    kms_outcomes = [
        outcome for outcome in evidence.source_outcomes if outcome.collector == "kms.keys"
    ]
    assert len(kms_outcomes) == 2
    assert len({outcome.source_outcome_id for outcome in kms_outcomes}) == 2
    assert len(evidence.relationships) == 2
    assert all(
        isinstance(reference.target, RelationshipEndpoint)
        and reference.target.aws_resource_id == canonical_arn
        for reference in evidence.relationships
    )


@pytest.mark.parametrize(
    ("supplied_reference", "returned_account_id", "returned_key_id"),
    (
        (
            "arn:aws:kms:us-east-1:123456789012:key/key-expected",
            "123456789012",
            "key-other",
        ),
        ("key-expected", "123456789012", "key-other"),
        (
            "arn:aws:kms:us-east-1:123456789012:alias/expected",
            "999900001111",
            "key-other-account",
        ),
    ),
)
def test_5e_kms_response_must_match_the_supplied_reference(
    supplied_reference: str,
    returned_account_id: str,
    returned_key_id: str,
) -> None:
    returned_arn = f"arn:aws:kms:us-east-1:{returned_account_id}:key/{returned_key_id}"
    s3_client = _complete_5e_s3_client(
        bucket_name="mismatched-kms",
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": supplied_reference,
                }
            }
        ],
    )
    kms_client = FakeAWSClient(
        responses={
            "describe_key": [
                {
                    "KeyMetadata": {
                        "AWSAccountId": returned_account_id,
                        "KeyId": returned_key_id,
                        "Arn": returned_arn,
                        "KeyManager": "CUSTOMER",
                    }
                }
            ]
        }
    )
    provider = _provider_for_5e(s3_client=s3_client, kms_client=kms_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    lookup = next(
        outcome for outcome in evidence.source_outcomes if outcome.collector == "kms.keys"
    )
    assert lookup.state is EvidenceSourceState.MALFORMED
    assert lookup.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert evidence.resources == ()
    assert len(evidence.relationships) == 1
    relationship = evidence.relationships[0]
    assert isinstance(relationship.target, UnresolvedRelationshipTarget)
    assert relationship.target.aws_resource_id == supplied_reference
    assert (
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=evidence.source_outcomes,
            artifacts=evidence.artifacts,
            contracts=evidence.source_contracts,
        )
        is CollectionStatus.PARTIAL
    )


def test_5e_replay_rejects_expected_absence_for_describe_key() -> None:
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/key-present"
    s3_client = _complete_5e_s3_client(
        bucket_name="invalid-kms-absence",
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": key_arn,
                }
            }
        ],
    )
    kms_client = FakeAWSClient(
        responses={
            "describe_key": [
                {
                    "KeyMetadata": {
                        "AWSAccountId": "123456789012",
                        "KeyId": "key-present",
                        "Arn": key_arn,
                        "KeyManager": "CUSTOMER",
                    }
                }
            ]
        }
    )
    evidence = S3EvidenceCollector(
        _provider_for_5e(s3_client=s3_client, kms_client=kms_client)
    ).collect_with_context(_collection_context())
    kms_outcome = next(
        outcome for outcome in evidence.source_outcomes if outcome.collector == "kms.keys"
    )
    outcomes, artifacts = _rebound_source_payload(
        evidence,
        evidence_kind=kms_outcome.evidence_kind,
        updates={"key": None, "complete": True, "failure_category": None},
    )
    rebound_artifact = next(
        artifact
        for artifact in artifacts
        if artifact.evidence_reference == kms_outcome.evidence_reference
    )
    invalid_outcome = SourceEvidenceOutcome.for_observation(
        scan_id=kms_outcome.scan_id,
        collection_account_id=kms_outcome.collection_account_id,
        phase=kms_outcome.phase,
        subject=kms_outcome.subject,
        evidence_kind=kms_outcome.evidence_kind,
        state=EvidenceSourceState.EXPECTED_ABSENCE,
        failure_category=None,
        collector=kms_outcome.collector,
        collector_version=kms_outcome.collector_version,
        source_api=kms_outcome.source_api,
        collected_at=kms_outcome.collected_at,
        evidence_reference=kms_outcome.evidence_reference,
        evidence_sha256=rebound_artifact.evidence_sha256,
    )
    outcomes = tuple(
        invalid_outcome if item.source_outcome_id == kms_outcome.source_outcome_id else item
        for item in outcomes
    )
    contracts = tuple(
        contract.model_copy(update={"identity_authoritative": False})
        if contract.source_outcome_id == kms_outcome.source_outcome_id
        else contract
        for contract in evidence.source_contracts
    )

    with pytest.raises(ValueError, match="5E S3 source state"):
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=outcomes,
            artifacts=artifacts,
            contracts=contracts,
        )


def test_5e_replay_rejects_expected_absence_for_bucket_acl() -> None:
    s3_client = _complete_5e_s3_client(bucket_name="invalid-acl-absence")
    evidence = S3EvidenceCollector(_provider_for_5e(s3_client=s3_client)).collect_with_context(
        _collection_context()
    )
    acl_outcome = next(
        outcome for outcome in evidence.source_outcomes if outcome.collector == "s3.bucket-acl"
    )
    outcomes, artifacts = _rebound_source_payload(
        evidence,
        evidence_kind=acl_outcome.evidence_kind,
        updates={
            "value": None,
            "complete": True,
            "expected_absence": True,
            "failure_category": None,
        },
    )
    rebound_artifact = next(
        artifact
        for artifact in artifacts
        if artifact.evidence_reference == acl_outcome.evidence_reference
    )
    invalid_outcome = SourceEvidenceOutcome.for_observation(
        scan_id=acl_outcome.scan_id,
        collection_account_id=acl_outcome.collection_account_id,
        phase=acl_outcome.phase,
        subject=acl_outcome.subject,
        evidence_kind=acl_outcome.evidence_kind,
        state=EvidenceSourceState.EXPECTED_ABSENCE,
        failure_category=None,
        collector=acl_outcome.collector,
        collector_version=acl_outcome.collector_version,
        source_api=acl_outcome.source_api,
        collected_at=acl_outcome.collected_at,
        evidence_reference=acl_outcome.evidence_reference,
        evidence_sha256=rebound_artifact.evidence_sha256,
    )
    outcomes = tuple(
        invalid_outcome if item.source_outcome_id == acl_outcome.source_outcome_id else item
        for item in outcomes
    )

    with pytest.raises(ValueError, match="5E S3 source state"):
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=outcomes,
            artifacts=artifacts,
            contracts=evidence.source_contracts,
        )


def test_5e_conflicting_canonical_kms_key_is_rejected_for_every_reference() -> None:
    canonical_arn = "arn:aws:kms:us-east-1:123456789012:key/key-conflict"
    s3_client = _complete_5e_s3_client(
        bucket_name="conflicting-kms",
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": reference,
                }
            }
            for reference in ("alias/a", "alias/b", "alias/c")
        ],
    )
    metadata = {
        "AWSAccountId": "123456789012",
        "KeyId": "key-conflict",
        "Arn": canonical_arn,
        "KeyManager": "CUSTOMER",
    }
    kms_client = FakeAWSClient(
        responses={
            "describe_key": [
                {"KeyMetadata": {**metadata, "Enabled": True}},
                {"KeyMetadata": {**metadata, "Enabled": False}},
                {"KeyMetadata": {**metadata, "Enabled": True}},
            ]
        }
    )
    provider = _provider_for_5e(s3_client=s3_client, kms_client=kms_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    kms_outcomes = [
        outcome for outcome in evidence.source_outcomes if outcome.collector == "kms.keys"
    ]
    assert len(kms_outcomes) == 3
    assert all(outcome.state is EvidenceSourceState.CONFLICT for outcome in kms_outcomes)
    assert all(
        outcome.failure_category is EvidenceFailureCategory.CONFLICTING_EVIDENCE
        for outcome in kms_outcomes
    )
    assert evidence.resources == ()
    assert len(evidence.relationships) == 3
    assert all(
        isinstance(relationship.target, UnresolvedRelationshipTarget)
        for relationship in evidence.relationships
    )
    assert (
        graph_collection_status_for(
            collector_name="s3_evidence",
            outcomes=evidence.source_outcomes,
            artifacts=evidence.artifacts,
            contracts=evidence.source_contracts,
        )
        is CollectionStatus.PARTIAL
    )


def test_5e_rejects_unconsumed_list_buckets_token_without_losing_retained_item() -> None:
    s3_client = _complete_5e_s3_client(bucket_name="truncated")
    s3_client._paginators["list_buckets"] = type(s3_client._paginators["list_buckets"])(
        [
            FakePaginator(
                [
                    {
                        "Buckets": [{"Name": "truncated", "BucketRegion": "us-east-1"}],
                        "ContinuationToken": "more-results",
                    }
                ]
            )
        ]
    )
    provider = _provider_for_5e(s3_client=s3_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    discovery = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.buckets.discovery"
    )
    assert discovery.state is EvidenceSourceState.MALFORMED
    assert discovery.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert evidence.status is CollectionStatus.PARTIAL


def test_5e_list_buckets_discards_each_malformed_or_conflicting_item_and_keeps_sibling() -> None:
    s3_client = _complete_5e_s3_client(bucket_name="retained")
    s3_client._responses["get_bucket_tagging"].appendleft({"TagSet": []})
    s3_client._responses["get_bucket_encryption"].appendleft(
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
    )
    s3_client._responses["get_public_access_block"].appendleft(
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
    )
    s3_client._paginators["list_buckets"] = type(s3_client._paginators["list_buckets"])(
        [
            FakePaginator(
                [
                    {
                        "Buckets": [
                            42,
                            {"Name": "bad-region", "BucketRegion": "bad region"},
                            {
                                "Name": "conflicting",
                                "CreationDate": datetime(2025, 1, 1, tzinfo=UTC),
                                "BucketRegion": "us-east-1",
                            },
                            {
                                "Name": "conflicting",
                                "CreationDate": datetime(2025, 1, 2, tzinfo=UTC),
                                "BucketRegion": "us-east-1",
                            },
                            {"Name": "retained", "BucketRegion": "us-east-1"},
                        ]
                    }
                ]
            )
        ]
    )
    provider = _provider_for_5e(s3_client=s3_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    discovery = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.buckets.discovery"
    )
    artifact = next(
        item
        for item in evidence.artifacts
        if item.evidence_reference == discovery.evidence_reference
    )
    assert discovery.state is EvidenceSourceState.CONFLICT
    assert artifact.normalized_payload["bucket_names"] == ("retained",)
    assert artifact.normalized_payload["discarded_item_count"] == 4
    location = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.bucket-location"
    )
    assert location.subject.aws_resource_id == "retained"
    assert ("s3", "bad region") not in provider.client_requests


def test_5e_legacy_projection_uses_first_failure_from_accepted_execution_order() -> None:
    pages = [
        {
            "Buckets": [
                42,
                {"Name": "retained", "BucketRegion": "us-east-1"},
            ]
        }
    ]
    shared_client = _complete_5e_s3_client(
        bucket_name="retained",
        tag_response=client_error("AccessDenied", "GetBucketTagging", status_code=403),
    )
    shared_client._paginators["list_buckets"] = type(shared_client._paginators["list_buckets"])(
        [FakePaginator(pages)]
    )
    shared_provider = _provider_for_5e(s3_client=shared_client)
    shared_bundle = S3CollectionBundle(shared_provider)

    projected = S3BucketCollector(
        shared_provider,
        collection_bundle=shared_bundle,
    ).collect_with_context(_collection_context())

    assert projected.status is CollectionStatus.PARTIAL
    assert projected.resources == ()
    assert any(call.operation_name == "get_bucket_tagging" for call in shared_client.calls)

    direct_client = FakeAWSClient(
        paginators={"list_buckets": FakePaginator(pages)},
    )
    direct_provider = FakeClientProvider({("s3", "us-east-1"): direct_client})

    with pytest.raises(CollectorEvidenceError, match="list_buckets"):
        S3BucketCollector(direct_provider).collect()
    assert direct_client.calls == []


def test_5e_failed_kms_lookup_retains_typed_reference_and_exact_source_kind() -> None:
    kms_arn = "arn:aws:kms:us-east-1:123456789012:key/key-denied"
    s3_client = _complete_5e_s3_client(
        bucket_name="kms-denied",
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": kms_arn,
                }
            }
        ],
    )
    kms_client = FakeAWSClient(
        responses={
            "describe_key": [client_error("AccessDeniedException", "DescribeKey", status_code=403)]
        }
    )
    provider = _provider_for_5e(s3_client=s3_client, kms_client=kms_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    lookup = next(
        outcome for outcome in evidence.source_outcomes if outcome.collector == "kms.keys"
    )
    assert lookup.state is EvidenceSourceState.UNAVAILABLE
    assert lookup.failure_category is EvidenceFailureCategory.ACCESS_DENIED
    assert len(evidence.relationships) == 1
    reference = evidence.relationships[0]
    assert isinstance(reference.target, UnresolvedRelationshipTarget)
    assert reference.target.aws_account_id is None
    assert reference.target.aws_resource_id == kms_arn
    assert reference.target_evidence_kind == lookup.evidence_kind
    assert reference.target_collector_name == "s3_evidence"


def test_5e_kms_not_found_is_service_unavailable_not_bucket_disappearance() -> None:
    kms_arn = "arn:aws:kms:us-east-1:123456789012:key/missing-key"
    s3_client = _complete_5e_s3_client(
        bucket_name="kms-missing",
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": kms_arn,
                }
            }
        ],
    )
    kms_client = FakeAWSClient(
        responses={
            "describe_key": [client_error("NotFoundException", "DescribeKey", status_code=404)]
        }
    )
    provider = _provider_for_5e(s3_client=s3_client, kms_client=kms_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    lookup = next(
        outcome for outcome in evidence.source_outcomes if outcome.collector == "kms.keys"
    )
    assert lookup.state is EvidenceSourceState.UNAVAILABLE
    assert lookup.failure_category is EvidenceFailureCategory.SERVICE_ERROR
    assert len(evidence.relationships) == 1
    assert isinstance(evidence.relationships[0].target, UnresolvedRelationshipTarget)


def test_5e_rejects_nul_in_kms_reference_before_lookup_identity_is_built() -> None:
    s3_client = _complete_5e_s3_client(
        bucket_name="nul-reference",
        encryption_rules=[
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "alias/restricted\x00suffix",
                }
            }
        ],
    )
    provider = _provider_for_5e(s3_client=s3_client)

    evidence = S3EvidenceCollector(provider).collect_with_context(_collection_context())

    encryption = next(
        outcome
        for outcome in evidence.source_outcomes
        if outcome.evidence_kind == "s3.bucket-encryption"
    )
    assert encryption.state is EvidenceSourceState.MALFORMED
    assert encryption.failure_category is EvidenceFailureCategory.MALFORMED_RESPONSE
    assert all(outcome.collector != "kms.keys" for outcome in evidence.source_outcomes)
    assert not evidence.relationships
    assert all(service != "kms" for service, _region in provider.client_requests)


def _rebound_source_payload(
    evidence: CollectorResult,
    *,
    evidence_kind: str,
    updates: dict[str, object],
) -> tuple[tuple[SourceEvidenceOutcome, ...], tuple[SourceEvidenceArtifact, ...]]:
    outcome = next(item for item in evidence.source_outcomes if item.evidence_kind == evidence_kind)
    artifact = next(
        item for item in evidence.artifacts if item.evidence_reference == outcome.evidence_reference
    )
    payload = artifact.model_dump(mode="json")["normalized_payload"]
    assert isinstance(payload, dict)
    rebound_artifact = SourceEvidenceArtifact.for_payload(
        scan_id=artifact.scan_id,
        collection_account_id=artifact.collection_account_id,
        evidence_reference=artifact.evidence_reference,
        evidence_schema=artifact.evidence_schema,
        evidence_schema_version=artifact.evidence_schema_version,
        collected_at=artifact.collected_at,
        normalized_payload={**payload, **updates},
    )
    rebound_outcome = outcome.model_copy(
        update={"evidence_sha256": rebound_artifact.evidence_sha256}
    )
    return (
        tuple(rebound_outcome if item is outcome else item for item in evidence.source_outcomes),
        tuple(rebound_artifact if item is artifact else item for item in evidence.artifacts),
    )


def _collection_context() -> CollectionContext:
    return CollectionContext(
        scan_id=UUID("11111111-1111-4111-8111-111111111111"),
        collection_account_id="123456789012",
        region="us-east-1",
        collected_at=datetime(2026, 9, 17, 12, tzinfo=UTC),
    )


def _provider_for_5e(
    *,
    s3_client: FakeAWSClient,
    s3control_client: FakeAWSClient | None = None,
    kms_client: FakeAWSClient | None = None,
) -> FakeClientProvider:
    if s3control_client is None:
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
    clients = {
        ("s3", "us-east-1"): s3_client,
        ("s3", "eu-west-1"): s3_client,
        ("s3control", "us-east-1"): s3control_client,
    }
    if kms_client is not None:
        clients[("kms", "us-east-1")] = kms_client
    return FakeClientProvider(clients)


def _complete_5e_s3_client(
    *,
    bucket_name: str,
    location_constraint: object = None,
    location_response: object = _USE_LOCATION_REGION,
    list_bucket_region: object = _USE_LOCATION_REGION,
    head_response: object = _USE_LOCATION_REGION,
    tag_response: object | None = None,
    public_access_block_response: object | None = None,
    policy_response: object | None = None,
    policy_status_response: object | None = None,
    versioning_response: object | None = None,
    encryption_response: object | None = None,
    ownership_response: object | None = None,
    acl_response: object | None = None,
    encryption_rules: list[dict[str, object]] | None = None,
) -> FakeAWSClient:
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    if list_bucket_region is _USE_LOCATION_REGION:
        list_bucket_region = (
            "us-east-1"
            if location_constraint is None
            else "eu-west-1"
            if location_constraint == "EU"
            else location_constraint
        )
    if location_response is _USE_LOCATION_REGION:
        location_response = {"LocationConstraint": location_constraint}
    if tag_response is None:
        tag_response = {"TagSet": [{"Key": "Classification", "Value": "restricted"}]}
    if public_access_block_response is None:
        public_access_block_response = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
    if policy_response is None:
        policy_response = {
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [bucket_arn, f"{bucket_arn}/*"],
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }
                    ],
                }
            )
        }
    if versioning_response is None:
        versioning_response = {"Status": "Enabled", "MFADelete": "Disabled"}
    if policy_status_response is None:
        policy_status_response = {"PolicyStatus": {"IsPublic": False}}
    if encryption_response is None:
        encryption_response = {
            "ServerSideEncryptionConfiguration": {
                "Rules": encryption_rules
                or [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
    elif encryption_rules is not None:
        raise AssertionError("configure encryption response or rules, not both")
    if ownership_response is None:
        ownership_response = {
            "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
        }
    if acl_response is None:
        acl_response = {
            "Owner": {"ID": "canonical-owner", "DisplayName": "owner"},
            "Grants": [
                {
                    "Grantee": {"Type": "CanonicalUser", "ID": "canonical-owner"},
                    "Permission": "FULL_CONTROL",
                }
            ],
        }
    bucket_summary: dict[str, object] = {
        "Name": bucket_name,
        "CreationDate": datetime(2025, 1, 2, tzinfo=UTC),
    }
    if list_bucket_region is not None:
        bucket_summary["BucketRegion"] = list_bucket_region
    responses: dict[str, list[object]] = {
        "get_bucket_location": [location_response],
        "get_bucket_tagging": [tag_response],
        "get_public_access_block": [public_access_block_response],
        "get_bucket_policy": [policy_response],
        "get_bucket_policy_status": [policy_status_response],
        "get_bucket_acl": [acl_response],
        "get_bucket_versioning": [versioning_response],
        "get_bucket_encryption": [encryption_response],
        "get_bucket_ownership_controls": [ownership_response],
    }
    if head_response is not _USE_LOCATION_REGION:
        responses["head_bucket"] = [head_response]
    return FakeAWSClient(
        paginators={"list_buckets": FakePaginator([{"Buckets": [bucket_summary]}])},
        responses=responses,
    )
