"""Tests for account- and Region-bound S3 bucket policy identities."""

from uuid import UUID

import pytest
from pydantic import ValidationError

from app.assessment.identities import stable_resource_id
from app.assessment.s3_identity import S3BucketIdentity
from app.schemas.resource import ResourceScope

BUCKET_ARN = "arn:aws:s3:::customer-records"


def _identity(**overrides: str) -> S3BucketIdentity:
    values = {
        "aws_account_id": "111122223333",
        "bucket_region": "us-east-1",
        "bucket_arn": BUCKET_ARN,
    }
    values.update(overrides)
    return S3BucketIdentity.for_bucket(**values)


def test_identity_uses_the_existing_canonical_stable_resource_derivation() -> None:
    identity = _identity()

    assert identity.provider == "aws"
    assert identity.bucket_name == "customer-records"
    assert identity.stable_resource_id == stable_resource_id(
        provider="aws",
        aws_account_id="111122223333",
        service="s3",
        resource_type="s3_bucket",
        scope=ResourceScope.REGIONAL,
        region="us-east-1",
        aws_resource_id="customer-records",
    )


def test_same_bucket_arn_in_another_account_or_region_is_a_different_resource() -> None:
    original = _identity()
    another_account = _identity(aws_account_id="444455556666")
    another_region = _identity(bucket_region="us-west-2")

    assert original.stable_resource_id != another_account.stable_resource_id
    assert original.stable_resource_id != another_region.stable_resource_id
    assert another_account.stable_resource_id != another_region.stable_resource_id


@pytest.mark.parametrize(
    "bucket_arn",
    [
        "arn:aws:s3:::customer..records",
        "arn:aws:s3:::customer.-records",
        "arn:aws:s3:::customer-.records",
        "arn:aws:s3:::192.0.2.1",
        "arn:aws:s3:::192.000.002.001",
        "arn:aws:s3:::Customer-Records",
        "arn:aws:s3:::customer-records/object",
        "arn:aws:s3:::customer-*",
        "arn:aws:s3:us-east-1:111122223333:accesspoint/customer-records",
    ],
)
def test_malformed_or_non_bucket_arns_are_rejected(bucket_arn: str) -> None:
    with pytest.raises((ValidationError, ValueError), match="S3 bucket"):
        _identity(bucket_arn=bucket_arn)


def test_syntactically_valid_legacy_name_is_not_rejected_by_creation_time_reservations() -> None:
    assert _identity(bucket_arn="arn:aws:s3:::sthree-historical-bucket").bucket_name == (
        "sthree-historical-bucket"
    )
    assert _identity(bucket_arn="arn:aws:s3:::historical-s3alias").bucket_name == (
        "historical-s3alias"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("aws_account_id", "1234"),
        ("aws_account_id", "abcdefghijkl"),
        ("aws_account_id", "١٢٣٤٥٦٧٨٩٠١٢"),
        ("bucket_region", ""),
        ("bucket_region", "US-EAST-1"),
        ("bucket_region", "global"),
        ("bucket_region", "us-east-١"),
    ],
)
def test_account_and_home_region_are_strictly_validated(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        _identity(**{field: value})


def test_reconstructed_identity_rejects_a_noncanonical_stable_resource_id() -> None:
    identity = _identity()
    payload = identity.model_dump(mode="python")
    payload["stable_resource_id"] = UUID(int=0)

    with pytest.raises(ValidationError, match="does not match the S3 bucket identity"):
        S3BucketIdentity.model_validate(payload)


def test_identity_is_frozen_strict_and_json_reconstructible() -> None:
    identity = _identity()

    assert S3BucketIdentity.model_validate_json(identity.model_dump_json()) == identity

    with pytest.raises(ValidationError, match="frozen"):
        identity.bucket_region = "us-west-2"
    with pytest.raises(ValidationError):
        S3BucketIdentity.model_validate(
            {
                **identity.model_dump(mode="python"),
                "stable_resource_id": str(identity.stable_resource_id),
            }
        )
