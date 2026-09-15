"""Normalized outcomes for one AWS evidence source.

This contract is intentionally independent of collectors, services, persistence, and rules. It
defines the immutable boundary that future Sprint 5 integration can use to retain successful
resource facts when a separate discovery or enrichment source is incomplete, without changing
the accepted Sprint 0--4 runtime.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.assessment.identities import resource_snapshot_id
from app.assessment.identities import stable_resource_id as calculate_stable_resource_id
from app.schemas.resource import ResourceScope

SOURCE_OUTCOME_SCHEMA_VERSION = "1.0.0"

_SOURCE_OUTCOME_NAMESPACE = UUID("7906fb56-bcb4-528c-939d-a1cc9bdccd70")

CollectionAccountId = Annotated[str, Field(pattern=r"^[0-9]{12}$")]
ResourceOwnerId = Annotated[str, Field(pattern=r"^(?:[0-9]{12}|aws)$")]
NonEmptyString = Annotated[str, Field(min_length=1)]
ResourceSignature = tuple[str, str]

_RESOURCE_SCOPES: dict[ResourceSignature, ResourceScope] = {
    ("access-analyzer", "access_analyzer_finding"): ResourceScope.REGIONAL,
    ("cloudtrail", "cloudtrail_trail"): ResourceScope.REGIONAL,
    ("ec2", "ebs_volume"): ResourceScope.REGIONAL,
    ("ec2", "ec2_instance"): ResourceScope.REGIONAL,
    ("ec2", "security_group"): ResourceScope.REGIONAL,
    ("ec2", "subnet"): ResourceScope.REGIONAL,
    ("ec2", "vpc"): ResourceScope.REGIONAL,
    ("ec2", "vpc_flow_log"): ResourceScope.REGIONAL,
    ("iam", "iam_access_key"): ResourceScope.GLOBAL,
    ("iam", "iam_aws_managed_policy"): ResourceScope.GLOBAL,
    ("iam", "iam_customer_managed_policy"): ResourceScope.GLOBAL,
    ("iam", "iam_group"): ResourceScope.GLOBAL,
    ("iam", "iam_inline_policy"): ResourceScope.GLOBAL,
    ("iam", "iam_managed_policy_version"): ResourceScope.GLOBAL,
    ("iam", "iam_mfa_device"): ResourceScope.GLOBAL,
    ("iam", "iam_role"): ResourceScope.GLOBAL,
    ("iam", "iam_user"): ResourceScope.GLOBAL,
    ("kms", "kms_key"): ResourceScope.REGIONAL,
    ("s3", "s3_bucket"): ResourceScope.REGIONAL,
}
_AWS_OWNED_IAM_TYPES = frozenset(
    {
        ("iam", "iam_aws_managed_policy"),
        ("iam", "iam_managed_policy_version"),
    }
)


class EvidenceCollectionPhase(StrEnum):
    """Whether an AWS call discovers identities or enriches one known resource."""

    DISCOVERY = "DISCOVERY"
    ENRICHMENT = "ENRICHMENT"


class EvidenceSourceState(StrEnum):
    """Result of collecting one declared AWS evidence source."""

    PRESENT = "PRESENT"
    EXPECTED_ABSENCE = "EXPECTED_ABSENCE"
    UNAVAILABLE = "UNAVAILABLE"
    MALFORMED = "MALFORMED"
    CONFLICT = "CONFLICT"
    RESOURCE_DISAPPEARED = "RESOURCE_DISAPPEARED"


class EvidenceFailureCategory(StrEnum):
    """Sanitized, controlled explanation for a non-successful source outcome."""

    ACCESS_DENIED = "ACCESS_DENIED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    THROTTLED = "THROTTLED"
    TIMEOUT = "TIMEOUT"
    SERVICE_ERROR = "SERVICE_ERROR"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"


_UNAVAILABLE_CATEGORIES = frozenset(
    {
        EvidenceFailureCategory.ACCESS_DENIED,
        EvidenceFailureCategory.AUTHENTICATION_FAILED,
        EvidenceFailureCategory.THROTTLED,
        EvidenceFailureCategory.TIMEOUT,
        EvidenceFailureCategory.SERVICE_ERROR,
        EvidenceFailureCategory.UNSUPPORTED_OPERATION,
    }
)


class AccountEvidenceSubject(BaseModel):
    """One account execution scope used by a discovery source."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    subject_kind: Literal["account"] = "account"
    provider: Literal["aws"] = "aws"
    aws_account_id: CollectionAccountId
    scope: ResourceScope
    region: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        """Require the Region exactly when the discovery source is Regional."""

        if self.scope is ResourceScope.REGIONAL and self.region is None:
            raise ValueError("regional account evidence subjects require a region")
        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global account evidence subjects must not define a region")
        return self


class ResourceEvidenceSubject(BaseModel):
    """One stable resource and its immutable observation in the current scan."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    subject_kind: Literal["resource"] = "resource"
    provider: Literal["aws"] = "aws"
    aws_account_id: ResourceOwnerId
    service: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9-]*$")
    resource_type: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")
    aws_resource_id: NonEmptyString
    scope: ResourceScope
    region: NonEmptyString | None = None
    stable_resource_id: UUID
    resource_snapshot_id: UUID

    @field_validator("aws_resource_id", "region")
    @classmethod
    def reject_identity_separator(cls, value: str | None) -> str | None:
        """Prevent ambiguous input to the accepted delimiter-based identity derivation."""

        if value is not None and "\x1f" in value:
            raise ValueError("resource identity components must not contain unit separators")
        return value

    @model_validator(mode="after")
    def validate_identity_and_scope(self) -> Self:
        """Reject an ambiguous scope or IDs for different resource identity content."""

        if self.scope is ResourceScope.REGIONAL and self.region is None:
            raise ValueError("regional resource evidence subjects require a region")
        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global resource evidence subjects must not define a region")

        expected_scope = _RESOURCE_SCOPES.get((self.service, self.resource_type))
        if expected_scope is not None and self.scope is not expected_scope:
            raise ValueError(
                f"{self.service}/{self.resource_type} resource evidence subjects must use "
                f"{expected_scope.value} scope"
            )
        _validate_resource_owner(
            service=self.service,
            resource_type=self.resource_type,
            aws_account_id=self.aws_account_id,
        )

        expected_resource_id = calculate_stable_resource_id(
            provider=self.provider,
            aws_account_id=self.aws_account_id,
            service=self.service,
            resource_type=self.resource_type,
            scope=self.scope,
            region=self.region,
            aws_resource_id=self.aws_resource_id,
        )
        if self.stable_resource_id != expected_resource_id:
            raise ValueError("stable_resource_id does not match evidence subject identity")
        return self

    @classmethod
    def for_aws_resource(
        cls,
        *,
        scan_id: UUID,
        aws_account_id: str,
        service: str,
        resource_type: str,
        aws_resource_id: str,
        scope: ResourceScope,
        region: str | None,
    ) -> Self:
        """Build a resource subject with deterministic stable and per-scan identifiers."""

        return cls(
            aws_account_id=aws_account_id,
            service=service,
            resource_type=resource_type,
            aws_resource_id=aws_resource_id,
            scope=scope,
            region=region,
            stable_resource_id=calculate_stable_resource_id(
                provider="aws",
                aws_account_id=aws_account_id,
                service=service,
                resource_type=resource_type,
                scope=scope,
                region=region,
                aws_resource_id=aws_resource_id,
            ),
            resource_snapshot_id=resource_snapshot_id(
                scan_id=scan_id,
                account_id=aws_account_id,
                service=service,
                resource_type=resource_type,
                scope=scope,
                region=region,
                aws_resource_id=aws_resource_id,
            ),
        )


EvidenceSubject = Annotated[
    AccountEvidenceSubject | ResourceEvidenceSubject,
    Field(discriminator="subject_kind"),
]


class SourceEvidenceOutcome(BaseModel):
    """Immutable state and provenance for one declared AWS evidence source."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    source_outcome_id: UUID
    scan_id: UUID
    collection_account_id: CollectionAccountId
    phase: EvidenceCollectionPhase
    subject: EvidenceSubject
    evidence_kind: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    state: EvidenceSourceState
    failure_category: EvidenceFailureCategory | None = None

    collector: str = Field(min_length=1, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    collector_version: str = Field(
        min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$"
    )
    source: Literal["aws-api"] = "aws-api"
    source_api: str = Field(
        min_length=3,
        pattern=r"^[a-z0-9-]+:[A-Za-z][A-Za-z0-9]*$",
    )
    collected_at: datetime
    evidence_reference: str = Field(min_length=1, max_length=512, pattern=r"^[^\r\n]+$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_version: Literal["1.0.0"] = SOURCE_OUTCOME_SCHEMA_VERSION

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        """Bind phase, state, provenance, failure category, and deterministic identity."""

        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("source outcome collected_at must be timezone-aware")

        if self.phase is EvidenceCollectionPhase.DISCOVERY:
            if not isinstance(self.subject, AccountEvidenceSubject):
                raise ValueError("discovery outcomes require an account evidence subject")
            if self.subject.aws_account_id != self.collection_account_id:
                raise ValueError(
                    "discovery subject account must match the source outcome collection account"
                )
        elif not isinstance(self.subject, ResourceEvidenceSubject):
            raise ValueError("enrichment outcomes require a resource evidence subject")

        if isinstance(self.subject, ResourceEvidenceSubject):
            expected_snapshot_id = resource_snapshot_id(
                scan_id=self.scan_id,
                account_id=self.subject.aws_account_id,
                service=self.subject.service,
                resource_type=self.subject.resource_type,
                scope=self.subject.scope,
                region=self.subject.region,
                aws_resource_id=self.subject.aws_resource_id,
            )
            if self.subject.resource_snapshot_id != expected_snapshot_id:
                raise ValueError("resource_snapshot_id must identify the source outcome scan")

        expected_category: EvidenceFailureCategory | frozenset[EvidenceFailureCategory] | None
        if self.state in {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.EXPECTED_ABSENCE,
        }:
            expected_category = None
        elif self.state is EvidenceSourceState.UNAVAILABLE:
            expected_category = _UNAVAILABLE_CATEGORIES
        elif self.state is EvidenceSourceState.MALFORMED:
            expected_category = EvidenceFailureCategory.MALFORMED_RESPONSE
        elif self.state is EvidenceSourceState.CONFLICT:
            expected_category = EvidenceFailureCategory.CONFLICTING_EVIDENCE
        else:
            expected_category = EvidenceFailureCategory.RESOURCE_NOT_FOUND

        if isinstance(expected_category, frozenset):
            if self.failure_category not in expected_category:
                raise ValueError("UNAVAILABLE requires an availability failure category")
        elif self.failure_category is not expected_category:
            raise ValueError("failure_category does not match the source outcome state")

        if (
            self.state is EvidenceSourceState.RESOURCE_DISAPPEARED
            and self.phase is not EvidenceCollectionPhase.ENRICHMENT
        ):
            raise ValueError("RESOURCE_DISAPPEARED is valid only for resource enrichment")

        expected_outcome_id = calculate_source_outcome_id(
            scan_id=self.scan_id,
            collection_account_id=self.collection_account_id,
            phase=self.phase,
            subject=self.subject,
            evidence_kind=self.evidence_kind,
            collector=self.collector,
            collector_version=self.collector_version,
            source_api=self.source_api,
        )
        if self.source_outcome_id != expected_outcome_id:
            raise ValueError("source_outcome_id does not match source identity and provenance")
        return self

    @classmethod
    def for_observation(
        cls,
        *,
        scan_id: UUID,
        collection_account_id: str,
        phase: EvidenceCollectionPhase,
        subject: AccountEvidenceSubject | ResourceEvidenceSubject,
        evidence_kind: str,
        state: EvidenceSourceState,
        failure_category: EvidenceFailureCategory | None,
        collector: str,
        collector_version: str,
        source_api: str,
        collected_at: datetime,
        evidence_reference: str,
        evidence_sha256: str,
    ) -> Self:
        """Build an outcome whose ID is stable for one declared source in one scan."""

        outcome_id = calculate_source_outcome_id(
            scan_id=scan_id,
            collection_account_id=collection_account_id,
            phase=phase,
            subject=subject,
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=collector_version,
            source_api=source_api,
        )
        return cls(
            source_outcome_id=outcome_id,
            scan_id=scan_id,
            collection_account_id=collection_account_id,
            phase=phase,
            subject=subject,
            evidence_kind=evidence_kind,
            state=state,
            failure_category=failure_category,
            collector=collector,
            collector_version=collector_version,
            source_api=source_api,
            collected_at=collected_at,
            evidence_reference=evidence_reference,
            evidence_sha256=evidence_sha256,
        )


def calculate_source_outcome_id(
    *,
    scan_id: UUID,
    collection_account_id: str,
    phase: EvidenceCollectionPhase,
    subject: AccountEvidenceSubject | ResourceEvidenceSubject,
    evidence_kind: str,
    collector: str,
    collector_version: str,
    source_api: str,
) -> UUID:
    """Identify one declared AWS source observation independently of its result state."""

    subject_document = subject.model_dump(mode="json")
    if isinstance(subject, ResourceEvidenceSubject):
        subject_document.pop("resource_snapshot_id")
    document = {
        "collector": collector,
        "collector_version": collector_version,
        "collection_account_id": collection_account_id,
        "evidence_kind": evidence_kind,
        "phase": phase.value,
        "scan_id": str(scan_id),
        "source_api": source_api,
        "subject": subject_document,
    }
    seed = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return uuid5(_SOURCE_OUTCOME_NAMESPACE, seed)


def _validate_resource_owner(
    *,
    service: str,
    resource_type: str,
    aws_account_id: str,
) -> None:
    """Keep the AWS-owned IAM sentinel from forking or contaminating other identities."""

    signature = (service, resource_type)
    if signature == ("iam", "iam_aws_managed_policy") and aws_account_id != "aws":
        raise ValueError("AWS-managed IAM policy subjects must use the aws owner sentinel")
    if aws_account_id == "aws" and signature not in _AWS_OWNED_IAM_TYPES:
        raise ValueError("the aws owner sentinel is valid only for AWS-owned IAM policy records")
