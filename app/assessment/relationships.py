"""Canonical typed relationships between normalized AWS resource identities.

This module is deliberately independent of collectors, persistence, services, and HTTP.  It
defines the validated domain contract that Sprint 5 producers and consumers will share without
starting that sprint or changing the accepted Sprint 0--4 runtime.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.assessment.identities import (
    resource_snapshot_id,
)
from app.assessment.identities import (
    stable_resource_id as calculate_stable_resource_id,
)
from app.schemas.resource import ResourceScope

RELATIONSHIP_SCHEMA_VERSION = "1.0.0"

_RELATIONSHIP_NAMESPACE = UUID("a8ce7ebd-1141-5bb8-b828-48e9a70174c4")
_RELATIONSHIP_OBSERVATION_NAMESPACE = UUID("1f23e82f-4e5d-5fa8-b27a-012eecebe2fb")
_UNRESOLVED_REFERENCE_NAMESPACE = UUID("d45bfac3-cba3-5aa9-b6c0-4bf094b39bcb")

NonEmptyString = Annotated[str, Field(min_length=1)]
ResourceSignature = tuple[str, str]


class RelationshipType(StrEnum):
    """Controlled, directional relationship vocabulary for approved Sprint 5 evidence."""

    USES_VOLUME = "uses_volume"
    ATTACHED_TO_SECURITY_GROUP = "attached_to_security_group"
    IN_SUBNET = "in_subnet"
    IN_VPC = "in_vpc"
    CONTAINS_SUBNET = "contains_subnet"
    HAS_FLOW_LOG = "has_flow_log"
    MEMBER_OF_GROUP = "member_of_group"
    HAS_ACCESS_KEY = "has_access_key"
    HAS_MFA_DEVICE = "has_mfa_device"
    ATTACHED_MANAGED_POLICY = "attached_managed_policy"
    ATTACHED_INLINE_POLICY = "attached_inline_policy"
    PERMISSIONS_BOUNDARY = "permissions_boundary"
    SELECTS_DEFAULT_VERSION = "selects_default_version"
    REFERENCES_RESOURCE = "references_resource"
    ENCRYPTED_WITH = "encrypted_with"
    DELIVERS_TO_BUCKET = "delivers_to_bucket"


class RelationshipResolution(StrEnum):
    """Whether a referenced target was materialized in the same scan."""

    RESOLVED = "RESOLVED"
    TARGET_NOT_COLLECTED = "TARGET_NOT_COLLECTED"
    TARGET_OUTSIDE_SCAN_SCOPE = "TARGET_OUTSIDE_SCAN_SCOPE"
    TARGET_ACCESS_DENIED = "TARGET_ACCESS_DENIED"
    TARGET_EVIDENCE_INCOMPLETE = "TARGET_EVIDENCE_INCOMPLETE"
    TARGET_IDENTITY_INCOMPLETE = "TARGET_IDENTITY_INCOMPLETE"


_IAM_IDENTITY_TYPES = frozenset(
    {
        ("iam", "iam_user"),
        ("iam", "iam_group"),
        ("iam", "iam_role"),
    }
)
_IAM_BOUNDARY_PRINCIPAL_TYPES = frozenset(
    {
        ("iam", "iam_user"),
        ("iam", "iam_role"),
    }
)
_IAM_MANAGED_POLICY_TYPES = frozenset(
    {
        ("iam", "iam_aws_managed_policy"),
        ("iam", "iam_customer_managed_policy"),
    }
)

# A ``None`` target set means that the source may reference any validated AWS resource type.
# This is required only for Access Analyzer findings, whose supported resource families are
# intentionally broader than the initial collector inventory.
_RELATIONSHIP_DIRECTIONS: dict[
    RelationshipType,
    tuple[frozenset[ResourceSignature], frozenset[ResourceSignature] | None],
] = {
    RelationshipType.USES_VOLUME: (
        frozenset({("ec2", "ec2_instance")}),
        frozenset({("ec2", "ebs_volume")}),
    ),
    RelationshipType.ATTACHED_TO_SECURITY_GROUP: (
        frozenset({("ec2", "ec2_instance")}),
        frozenset({("ec2", "security_group")}),
    ),
    RelationshipType.IN_SUBNET: (
        frozenset({("ec2", "ec2_instance")}),
        frozenset({("ec2", "subnet")}),
    ),
    RelationshipType.IN_VPC: (
        frozenset({("ec2", "ec2_instance"), ("ec2", "security_group")}),
        frozenset({("ec2", "vpc")}),
    ),
    RelationshipType.CONTAINS_SUBNET: (
        frozenset({("ec2", "vpc")}),
        frozenset({("ec2", "subnet")}),
    ),
    RelationshipType.HAS_FLOW_LOG: (
        frozenset({("ec2", "vpc")}),
        frozenset({("ec2", "vpc_flow_log")}),
    ),
    RelationshipType.MEMBER_OF_GROUP: (
        frozenset({("iam", "iam_user")}),
        frozenset({("iam", "iam_group")}),
    ),
    RelationshipType.HAS_ACCESS_KEY: (
        frozenset({("iam", "iam_user")}),
        frozenset({("iam", "iam_access_key")}),
    ),
    RelationshipType.HAS_MFA_DEVICE: (
        frozenset({("iam", "iam_user")}),
        frozenset({("iam", "iam_mfa_device")}),
    ),
    RelationshipType.ATTACHED_MANAGED_POLICY: (
        _IAM_IDENTITY_TYPES,
        _IAM_MANAGED_POLICY_TYPES,
    ),
    RelationshipType.ATTACHED_INLINE_POLICY: (
        _IAM_IDENTITY_TYPES,
        frozenset({("iam", "iam_inline_policy")}),
    ),
    RelationshipType.PERMISSIONS_BOUNDARY: (
        _IAM_BOUNDARY_PRINCIPAL_TYPES,
        _IAM_MANAGED_POLICY_TYPES,
    ),
    RelationshipType.SELECTS_DEFAULT_VERSION: (
        _IAM_MANAGED_POLICY_TYPES,
        frozenset({("iam", "iam_managed_policy_version")}),
    ),
    RelationshipType.REFERENCES_RESOURCE: (
        frozenset({("access-analyzer", "access_analyzer_finding")}),
        None,
    ),
    RelationshipType.ENCRYPTED_WITH: (
        frozenset({("s3", "s3_bucket"), ("cloudtrail", "cloudtrail_trail")}),
        frozenset({("kms", "kms_key")}),
    ),
    RelationshipType.DELIVERS_TO_BUCKET: (
        frozenset({("cloudtrail", "cloudtrail_trail")}),
        frozenset({("s3", "s3_bucket")}),
    ),
}


class RelationshipEndpoint(BaseModel):
    """Stable AWS resource reference, optionally resolved to one scan snapshot.

    A stable target without a snapshot is a reference only. Constructing one does not assert that
    a corresponding ``Resource`` row exists and must never cause a fabricated resource row.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    identity_state: Literal["stable"] = "stable"
    provider: Literal["aws"] = "aws"
    aws_account_id: NonEmptyString
    service: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9-]*$")
    resource_type: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")
    aws_resource_id: NonEmptyString
    scope: ResourceScope
    region: str | None = None
    stable_resource_id: UUID
    resource_snapshot_id: UUID | None = None

    @model_validator(mode="after")
    def validate_identity_and_scope(self) -> Self:
        """Reject ambiguous scope or an identifier for different endpoint content."""

        if self.scope is ResourceScope.REGIONAL and not self.region:
            raise ValueError("regional relationship endpoints require a region")
        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global relationship endpoints must not define a region")

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
            raise ValueError("stable_resource_id does not match relationship endpoint identity")
        return self

    @classmethod
    def for_aws_resource(
        cls,
        *,
        aws_account_id: str,
        service: str,
        resource_type: str,
        aws_resource_id: str,
        scope: ResourceScope,
        region: str | None,
        observed_in_scan_id: UUID | None,
    ) -> Self:
        """Build a stable reference, with a snapshot ID only when the resource was observed."""

        stable_id = calculate_stable_resource_id(
            provider="aws",
            aws_account_id=aws_account_id,
            service=service,
            resource_type=resource_type,
            scope=scope,
            region=region,
            aws_resource_id=aws_resource_id,
        )
        snapshot_id = None
        if observed_in_scan_id is not None:
            snapshot_id = resource_snapshot_id(
                scan_id=observed_in_scan_id,
                account_id=aws_account_id,
                service=service,
                resource_type=resource_type,
                scope=scope,
                region=region,
                aws_resource_id=aws_resource_id,
            )
        return cls(
            aws_account_id=aws_account_id,
            service=service,
            resource_type=resource_type,
            aws_resource_id=aws_resource_id,
            scope=scope,
            region=region,
            stable_resource_id=stable_id,
            resource_snapshot_id=snapshot_id,
        )


class UnresolvedRelationshipTarget(BaseModel):
    """AWS target reference whose canonical stable resource identity is not yet knowable.

    AWS commonly returns a useful target identifier without every component required by the
    stable resource identity contract.  For example, CloudTrail can return an S3 bucket name
    while the bucket owner and home Region remain unknown.  This reference preserves exactly
    that partial fact without pretending that a stable resource or resource snapshot exists.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    identity_state: Literal["unresolved"] = "unresolved"
    provider: Literal["aws"] = "aws"
    aws_account_id: NonEmptyString | None = None
    service: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9-]*$")
    resource_type: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]*$")
    aws_resource_id: NonEmptyString
    scope: ResourceScope | None = None
    region: NonEmptyString | None = None
    reference_id: UUID
    stable_resource_id: None = None
    resource_snapshot_id: None = None

    @model_validator(mode="after")
    def validate_partial_identity(self) -> Self:
        """Reject contradictions, fabricated IDs, and unnecessarily partial identities."""

        if self.scope is ResourceScope.GLOBAL and self.region is not None:
            raise ValueError("global unresolved targets must not define a region")

        identity_is_complete = self.aws_account_id is not None and (
            self.scope is ResourceScope.GLOBAL
            or (self.scope is ResourceScope.REGIONAL and self.region is not None)
        )
        if identity_is_complete:
            raise ValueError("complete target identity must use RelationshipEndpoint")

        expected_reference_id = calculate_unresolved_reference_id(
            provider=self.provider,
            aws_account_id=self.aws_account_id,
            service=self.service,
            resource_type=self.resource_type,
            aws_resource_id=self.aws_resource_id,
            scope=self.scope,
            region=self.region,
        )
        if self.reference_id != expected_reference_id:
            raise ValueError("reference_id does not match unresolved target identity")
        return self

    @classmethod
    def for_aws_reference(
        cls,
        *,
        service: str,
        resource_type: str,
        aws_resource_id: str,
        aws_account_id: str | None = None,
        scope: ResourceScope | None = None,
        region: str | None = None,
    ) -> Self:
        """Build a deterministic reference from exactly the target identity facts AWS returned."""

        reference_id = calculate_unresolved_reference_id(
            provider="aws",
            aws_account_id=aws_account_id,
            service=service,
            resource_type=resource_type,
            aws_resource_id=aws_resource_id,
            scope=scope,
            region=region,
        )
        return cls(
            aws_account_id=aws_account_id,
            service=service,
            resource_type=resource_type,
            aws_resource_id=aws_resource_id,
            scope=scope,
            region=region,
            reference_id=reference_id,
        )


class RelationshipProvenance(BaseModel):
    """Sanitized pointer to the normalized AWS evidence that established one edge."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    collector: str = Field(min_length=1, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    source: Literal["aws-api"] = "aws-api"
    source_api: str = Field(
        min_length=3,
        pattern=r"^[a-z0-9-]+:[A-Za-z][A-Za-z0-9]*$",
    )
    evidence_reference: str = Field(min_length=1, max_length=512, pattern=r"^[^\r\n]+$")
    collected_at: datetime

    @model_validator(mode="after")
    def require_absolute_collection_time(self) -> Self:
        """Require a timezone-aware timestamp for historical reconstruction."""

        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("relationship collected_at must be timezone-aware")
        return self


class ResourceRelationship(BaseModel):
    """One immutable, directional relationship observation in one inventory scan."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    relationship_id: UUID
    observation_id: UUID
    scan_id: UUID
    aws_account_id: NonEmptyString
    relationship_type: RelationshipType
    source: RelationshipEndpoint
    target: RelationshipEndpoint | UnresolvedRelationshipTarget = Field(
        discriminator="identity_state"
    )
    resolution: RelationshipResolution
    provenance: RelationshipProvenance
    schema_version: Literal["1.0.0"] = RELATIONSHIP_SCHEMA_VERSION

    @model_validator(mode="after")
    def validate_relationship(self) -> Self:
        """Bind direction, resolution, snapshots, and deterministic identifiers."""

        if self.source.aws_account_id != self.aws_account_id:
            raise ValueError("relationship account must match the source account")
        if (
            isinstance(self.target, RelationshipEndpoint)
            and self.source.stable_resource_id == self.target.stable_resource_id
        ):
            raise ValueError("relationship source and target must be different resources")

        source_types, target_types = _RELATIONSHIP_DIRECTIONS[self.relationship_type]
        source_signature = (self.source.service, self.source.resource_type)
        target_signature = (self.target.service, self.target.resource_type)
        if source_signature not in source_types:
            raise ValueError("source resource type is invalid for relationship direction")
        if target_types is not None and target_signature not in target_types:
            raise ValueError("target resource type is invalid for relationship direction")

        expected_source_snapshot_id = _endpoint_snapshot_id(self.scan_id, self.source)
        if self.source.resource_snapshot_id != expected_source_snapshot_id:
            raise ValueError("source resource_snapshot_id must identify the relationship scan")

        if self.resolution is RelationshipResolution.TARGET_IDENTITY_INCOMPLETE:
            if not isinstance(self.target, UnresolvedRelationshipTarget):
                raise ValueError(
                    "TARGET_IDENTITY_INCOMPLETE requires an unresolved target reference"
                )
        elif isinstance(self.target, UnresolvedRelationshipTarget):
            raise ValueError(
                "unresolved target references require TARGET_IDENTITY_INCOMPLETE resolution"
            )
        elif self.resolution is RelationshipResolution.RESOLVED:
            expected_target_snapshot_id = _endpoint_snapshot_id(self.scan_id, self.target)
            if self.target.resource_snapshot_id != expected_target_snapshot_id:
                raise ValueError(
                    "resolved target resource_snapshot_id must identify the relationship scan"
                )
        elif self.target.resource_snapshot_id is not None:
            raise ValueError("unresolved relationship targets must not claim a resource snapshot")

        expected_relationship_id = calculate_relationship_id(
            source_resource_id=self.source.stable_resource_id,
            relationship_type=self.relationship_type,
            target_resource_id=(
                self.target.stable_resource_id
                if isinstance(self.target, RelationshipEndpoint)
                else None
            ),
            target_reference_id=(
                self.target.reference_id
                if isinstance(self.target, UnresolvedRelationshipTarget)
                else None
            ),
        )
        if self.relationship_id != expected_relationship_id:
            raise ValueError("relationship_id does not match the directional relationship")

        expected_observation_id = calculate_relationship_observation_id(
            scan_id=self.scan_id,
            relationship_id=self.relationship_id,
        )
        if self.observation_id != expected_observation_id:
            raise ValueError("observation_id does not match the scan relationship")
        return self

    @classmethod
    def for_observation(
        cls,
        *,
        scan_id: UUID,
        aws_account_id: str,
        relationship_type: RelationshipType,
        source: RelationshipEndpoint,
        target: RelationshipEndpoint | UnresolvedRelationshipTarget,
        resolution: RelationshipResolution,
        provenance: RelationshipProvenance,
    ) -> Self:
        """Build an observation with deterministic logical and per-scan identifiers."""

        relationship_id = calculate_relationship_id(
            source_resource_id=source.stable_resource_id,
            relationship_type=relationship_type,
            target_resource_id=(
                target.stable_resource_id if isinstance(target, RelationshipEndpoint) else None
            ),
            target_reference_id=(
                target.reference_id if isinstance(target, UnresolvedRelationshipTarget) else None
            ),
        )
        return cls(
            relationship_id=relationship_id,
            observation_id=calculate_relationship_observation_id(
                scan_id=scan_id,
                relationship_id=relationship_id,
            ),
            scan_id=scan_id,
            aws_account_id=aws_account_id,
            relationship_type=relationship_type,
            source=source,
            target=target,
            resolution=resolution,
            provenance=provenance,
        )

    @property
    def is_resolved(self) -> bool:
        """Return whether both endpoints were observed in this scan."""

        return self.resolution is RelationshipResolution.RESOLVED


def calculate_relationship_id(
    *,
    source_resource_id: UUID,
    relationship_type: RelationshipType,
    target_resource_id: UUID | None = None,
    target_reference_id: UUID | None = None,
) -> UUID:
    """Identify one directional logical edge independently of scan history."""

    if (target_resource_id is None) == (target_reference_id is None):
        raise ValueError("exactly one target identity must define a relationship")
    target_identity = (
        f"stable:{target_resource_id}"
        if target_resource_id is not None
        else f"unresolved:{target_reference_id}"
    )

    return uuid5(
        _RELATIONSHIP_NAMESPACE,
        "\x1f".join(
            (
                str(source_resource_id),
                relationship_type.value,
                target_identity,
            )
        ),
    )


def calculate_unresolved_reference_id(
    *,
    provider: Literal["aws"],
    aws_account_id: str | None,
    service: str,
    resource_type: str,
    aws_resource_id: str,
    scope: ResourceScope | None,
    region: str | None,
) -> UUID:
    """Identify one partial AWS reference without inventing missing identity components."""

    canonical_reference = json.dumps(
        {
            "aws_account_id": aws_account_id,
            "aws_resource_id": aws_resource_id,
            "provider": provider,
            "region": region,
            "resource_type": resource_type,
            "scope": scope.value if scope is not None else None,
            "service": service,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return uuid5(
        _UNRESOLVED_REFERENCE_NAMESPACE,
        canonical_reference,
    )


def calculate_relationship_observation_id(*, scan_id: UUID, relationship_id: UUID) -> UUID:
    """Identify one logical edge as observed in one exact inventory scan."""

    return uuid5(
        _RELATIONSHIP_OBSERVATION_NAMESPACE,
        "\x1f".join((str(scan_id), str(relationship_id))),
    )


def deduplicate_relationships(
    relationships: Iterable[ResourceRelationship],
) -> tuple[ResourceRelationship, ...]:
    """Coalesce exact duplicate API observations and reject conflicting duplicates.

    One scan and logical relationship always produce one observation ID.  Silently selecting one
    of two different records for that ID would discard provenance or resolution state, so only
    value-equivalent validated domain records are coalesced.
    """

    deduplicated: dict[UUID, ResourceRelationship] = {}
    for relationship in relationships:
        existing = deduplicated.get(relationship.observation_id)
        if existing is None:
            deduplicated[relationship.observation_id] = relationship
        elif existing != relationship:
            raise ValueError("conflicting duplicate relationship observation")
    return tuple(sorted(deduplicated.values(), key=lambda item: item.observation_id.hex))


def _endpoint_snapshot_id(scan_id: UUID, endpoint: RelationshipEndpoint) -> UUID:
    """Calculate the existing canonical per-scan resource snapshot identifier."""

    return resource_snapshot_id(
        scan_id=scan_id,
        account_id=endpoint.aws_account_id,
        service=endpoint.service,
        resource_type=endpoint.resource_type,
        scope=endpoint.scope,
        region=endpoint.region,
        aws_resource_id=endpoint.aws_resource_id,
    )
