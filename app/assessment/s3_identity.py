"""Strict stable identity for general-purpose S3 buckets.

The S3 bucket ARN does not include an AWS account or home Region. Policy decisions must
therefore bind all three values, plus the repository's canonical stable resource identifier,
to avoid carrying a decision across a delete/recreate or a different account/Region.
"""

from __future__ import annotations

import re
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.assessment.identities import stable_resource_id as calculate_stable_resource_id
from app.schemas.resource import ResourceScope

_S3_BUCKET_ARN = re.compile(
    r"^arn:(?:aws|aws-[a-z0-9-]+):s3:::(?P<bucket>[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])$"
)
_IPV4_STYLE_BUCKET_NAME = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")


def _validated_bucket_name(bucket_arn: str) -> str:
    """Return the name from one canonical general-purpose bucket ARN."""

    match = _S3_BUCKET_ARN.fullmatch(bucket_arn)
    if match is None:
        raise ValueError("bucket_arn must be an exact canonical general-purpose S3 bucket ARN")

    bucket_name = match.group("bucket")
    if ".." in bucket_name or ".-" in bucket_name or "-." in bucket_name:
        raise ValueError("bucket_arn contains an invalid general-purpose S3 bucket name")
    if _IPV4_STYLE_BUCKET_NAME.fullmatch(bucket_name):
        raise ValueError("bucket_arn must not use an IPv4-style S3 bucket name")
    return bucket_name


class S3BucketIdentity(BaseModel):
    """An immutable S3 bucket identity safe for exact policy decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    provider: Literal["aws"] = "aws"
    aws_account_id: str = Field(pattern=r"^[0-9]{12}$")
    bucket_region: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$",
    )
    bucket_arn: str
    stable_resource_id: UUID

    @field_validator("bucket_arn")
    @classmethod
    def validate_bucket_arn(cls, value: str) -> str:
        """Exclude object, access-point, wildcard, and malformed bucket ARNs."""

        _validated_bucket_name(value)
        return value

    @model_validator(mode="after")
    def validate_stable_resource_id(self) -> Self:
        """Require the existing canonical identity derivation for this exact bucket."""

        expected = calculate_stable_resource_id(
            provider=self.provider,
            aws_account_id=self.aws_account_id,
            service="s3",
            resource_type="s3_bucket",
            scope=ResourceScope.REGIONAL,
            region=self.bucket_region,
            aws_resource_id=self.bucket_name,
        )
        if self.stable_resource_id != expected:
            raise ValueError("stable_resource_id does not match the S3 bucket identity")
        return self

    @classmethod
    def for_bucket(
        cls,
        *,
        aws_account_id: str,
        bucket_region: str,
        bucket_arn: str,
    ) -> S3BucketIdentity:
        """Construct an identity while deriving its canonical stable resource identifier."""

        bucket_name = _validated_bucket_name(bucket_arn)
        stable_id = calculate_stable_resource_id(
            provider="aws",
            aws_account_id=aws_account_id,
            service="s3",
            resource_type="s3_bucket",
            scope=ResourceScope.REGIONAL,
            region=bucket_region,
            aws_resource_id=bucket_name,
        )
        return cls(
            aws_account_id=aws_account_id,
            bucket_region=bucket_region,
            bucket_arn=bucket_arn,
            stable_resource_id=stable_id,
        )

    @property
    def bucket_name(self) -> str:
        """Return the already-validated general-purpose bucket name."""

        return _validated_bucket_name(self.bucket_arn)
