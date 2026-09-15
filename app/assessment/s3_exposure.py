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

from app.assessment.s3_identity import S3BucketIdentity

S3_EXPOSURE_APPROVAL_POLICY_ID = "s3-exposure-approvals"
S3_EXPOSURE_APPROVAL_SCHEMA_VERSION = "1.0.0"

_ACCOUNT_TOKEN = re.compile(r"^account:(?P<account_id>[0-9]{12})$")
_CANONICAL_USER_TOKEN = re.compile(r"^canonical-user:[0-9a-f]{64}$")
_IAM_PRINCIPAL_ARN = re.compile(
    r"^arn:(?:aws|aws-[a-z0-9-]+):iam::(?P<account_id>[0-9]{12}):"
    r"(?P<resource>root|(?:user|role)/(?:[A-Za-z0-9+=,.@_-]+/)*"
    r"[A-Za-z0-9+=,.@_-]+)$"
)


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

    bucket_identity: S3BucketIdentity
    allow_public: bool
    approved_external_principals: tuple[str, ...] = ()

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
        """Reject vacuous records and principals controlled by the bucket owner."""

        if not self.allow_public and not self.approved_external_principals:
            raise ValueError("bucket approval record must approve public or external exposure")
        owner_account_id = self.bucket_identity.aws_account_id
        for principal in self.approved_external_principals:
            account_token = _ACCOUNT_TOKEN.fullmatch(principal)
            iam_principal = _IAM_PRINCIPAL_ARN.fullmatch(principal)
            principal_account_id = (
                account_token.group("account_id")
                if account_token is not None
                else iam_principal.group("account_id")
                if iam_principal is not None
                else None
            )
            if principal_account_id == owner_account_id:
                raise ValueError("same-owner principals are not external S3 exposure approvals")
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
    version: str = Field(pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
    bucket_approvals: tuple[S3BucketExposureApproval, ...] = ()
    content_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("bucket_approvals")
    @classmethod
    def validate_bucket_approvals(
        cls,
        values: tuple[S3BucketExposureApproval, ...],
    ) -> tuple[S3BucketExposureApproval, ...]:
        """Reject multiple meanings for one bucket and canonicalize record ordering."""

        stable_resource_ids = [value.bucket_identity.stable_resource_id for value in values]
        if len(stable_resource_ids) != len(set(stable_resource_ids)):
            raise ValueError("S3 exposure approval bucket records must be unique")
        return tuple(
            sorted(values, key=lambda value: str(value.bucket_identity.stable_resource_id))
        )

    @model_validator(mode="after")
    def verify_content_checksum(self) -> Self:
        """Reject stored or reconstructed content that does not match its required digest."""

        expected = self.calculate_content_checksum()
        if not hmac.compare_digest(self.content_checksum, expected):
            raise ValueError("content_checksum does not match S3 exposure approval content")
        return self

    @classmethod
    def create(
        cls,
        *,
        version: str,
        bucket_approvals: tuple[S3BucketExposureApproval, ...] = (),
    ) -> Self:
        """Create new policy content with a calculated digest; reconstruction requires one."""

        canonical_approvals = tuple(
            sorted(
                bucket_approvals,
                key=lambda approval: str(approval.bucket_identity.stable_resource_id),
            )
        )
        checksum = _calculate_policy_checksum(
            policy_id=S3_EXPOSURE_APPROVAL_POLICY_ID,
            schema_version=S3_EXPOSURE_APPROVAL_SCHEMA_VERSION,
            version=version,
            bucket_approvals=canonical_approvals,
        )
        return cls(
            policy_id=S3_EXPOSURE_APPROVAL_POLICY_ID,
            schema_version=S3_EXPOSURE_APPROVAL_SCHEMA_VERSION,
            version=version,
            bucket_approvals=canonical_approvals,
            content_checksum=checksum,
        )

    def calculate_content_checksum(self) -> str:
        """Return an order-independent SHA-256 over the complete policy artifact."""

        return _calculate_policy_checksum(
            policy_id=self.policy_id,
            schema_version=self.schema_version,
            version=self.version,
            bucket_approvals=self.bucket_approvals,
        )

    def get_bucket_approval(
        self,
        bucket_identity: S3BucketIdentity,
    ) -> S3BucketExposureApproval | None:
        """Return only the exact bucket record; perform no exposure evaluation."""

        return next(
            (
                approval
                for approval in self.bucket_approvals
                if approval.bucket_identity == bucket_identity
            ),
            None,
        )


def _calculate_policy_checksum(
    *,
    policy_id: str,
    schema_version: str,
    version: str,
    bucket_approvals: tuple[S3BucketExposureApproval, ...],
) -> str:
    """Calculate the canonical digest used by both creation and reconstruction validation."""

    content = {
        "bucket_approvals": [
            {
                "allow_public": approval.allow_public,
                "approved_external_principals": sorted(approval.approved_external_principals),
                "bucket_identity": approval.bucket_identity.model_dump(mode="json"),
            }
            for approval in sorted(
                bucket_approvals,
                key=lambda approval: str(approval.bucket_identity.stable_resource_id),
            )
        ],
        "policy_id": policy_id,
        "schema_version": schema_version,
        "version": version,
    }
    encoded = json.dumps(
        content,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
