"""Versioned bucket-scoped approvals for the planned S3-002 control.

This module is a pure policy-schema boundary. It deliberately performs no AWS calls, exposure
evaluation, persistence, profile registration, or application startup work.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

S3_EXPOSURE_APPROVAL_POLICY_ID = "s3-exposure-approvals"
S3_EXPOSURE_APPROVAL_SCHEMA_VERSION = "1.0.0"

_BUCKET_ARN = re.compile(r"^arn:(?:aws|aws-[a-z0-9-]+):s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_ACCOUNT_TOKEN = re.compile(r"^account:(?P<account_id>\d{12})$")
_CANONICAL_USER_TOKEN = re.compile(r"^canonical-user:[0-9a-f]{64}$")
_IAM_PRINCIPAL_ARN = re.compile(
    r"^arn:(?:aws|aws-[a-z0-9-]+):iam::(?P<account_id>\d{12}):"
    r"(?P<resource>root|(?:user|role)/(?:[A-Za-z0-9+=,.@_-]+/)*"
    r"[A-Za-z0-9+=,.@_-]+)$"
)


def _require_bucket_arn(value: str) -> str:
    """Require one exact general-purpose bucket ARN with no resource wildcard."""

    if not _BUCKET_ARN.fullmatch(value) or ".." in value or ".-" in value or "-." in value:
        raise ValueError("bucket_arn must be an exact canonical S3 bucket ARN")
    return value


def _canonical_principal_token(value: str) -> str:
    """Validate and canonicalize one supported external-principal approval token."""

    if _ACCOUNT_TOKEN.fullmatch(value) or _CANONICAL_USER_TOKEN.fullmatch(value):
        return value

    iam_principal = _IAM_PRINCIPAL_ARN.fullmatch(value)
    if iam_principal is None:
        raise ValueError("unsupported S3 exposure approval principal token")
    if iam_principal.group("resource") == "root":
        return f"account:{iam_principal.group('account_id')}"
    return value


class S3BucketExposureApproval(BaseModel):
    """One explicit, non-vacuous approval record for an exact S3 bucket."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    bucket_arn: str
    allow_public: bool
    approved_external_principals: tuple[str, ...] = ()

    @field_validator("bucket_arn")
    @classmethod
    def validate_bucket_arn(cls, value: str) -> str:
        """Reject object, access-point, wildcard, and malformed bucket identities."""

        return _require_bucket_arn(value)

    @field_validator("approved_external_principals")
    @classmethod
    def validate_external_principals(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Canonicalize, sort, and reject duplicate semantic principal approvals."""

        canonical = tuple(_canonical_principal_token(value) for value in values)
        if len(canonical) != len(set(canonical)):
            raise ValueError("approved external principal tokens must be unique")
        return tuple(sorted(canonical))

    @model_validator(mode="after")
    def reject_vacuous_record(self) -> Self:
        """Omit deny-all records instead of preserving policy-free configuration noise."""

        if not self.allow_public and not self.approved_external_principals:
            raise ValueError("bucket approval record must approve public or external exposure")
        return self


class S3ExposureApprovalPolicy(BaseModel):
    """Strict immutable approval artifact used by a future S3-002 evaluator.

    An empty artifact means that no public or supported external exposure is approved. Lookup
    returns only the exact configured record; absence is therefore explicit deny-by-default
    policy, not missing evidence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    policy_id: Literal["s3-exposure-approvals"]
    schema_version: Literal["1.0.0"]
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    bucket_approvals: tuple[S3BucketExposureApproval, ...] = ()
    content_checksum: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("bucket_approvals")
    @classmethod
    def validate_bucket_approvals(
        cls,
        values: tuple[S3BucketExposureApproval, ...],
    ) -> tuple[S3BucketExposureApproval, ...]:
        """Reject multiple meanings for one bucket and canonicalize record ordering."""

        bucket_arns = [value.bucket_arn for value in values]
        if len(bucket_arns) != len(set(bucket_arns)):
            raise ValueError("S3 exposure approval bucket records must be unique")
        return tuple(sorted(values, key=lambda value: value.bucket_arn))

    @model_validator(mode="after")
    def set_or_verify_content_checksum(self) -> Self:
        """Bind identity, versions, and all approval content to a stable digest."""

        expected = self.calculate_content_checksum()
        if self.content_checksum is None:
            object.__setattr__(self, "content_checksum", expected)
        elif not hmac.compare_digest(self.content_checksum, expected):
            raise ValueError("content_checksum does not match S3 exposure approval content")
        return self

    def calculate_content_checksum(self) -> str:
        """Return an order-independent SHA-256 over the complete policy artifact."""

        content = {
            "bucket_approvals": [
                {
                    "allow_public": approval.allow_public,
                    "approved_external_principals": sorted(approval.approved_external_principals),
                    "bucket_arn": approval.bucket_arn,
                }
                for approval in sorted(
                    self.bucket_approvals,
                    key=lambda approval: approval.bucket_arn,
                )
            ],
            "policy_id": self.policy_id,
            "schema_version": self.schema_version,
            "version": self.version,
        }
        encoded = json.dumps(
            content,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def get_bucket_approval(self, bucket_arn: str) -> S3BucketExposureApproval | None:
        """Return only the exact bucket record; perform no exposure evaluation."""

        _require_bucket_arn(bucket_arn)
        return next(
            (approval for approval in self.bucket_approvals if approval.bucket_arn == bucket_arn),
            None,
        )
