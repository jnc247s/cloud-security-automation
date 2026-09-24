"""Validated source declarations, artifacts, outcomes, and resource relationships.

The graph is the immutable Sprint 5 hand-off between fact-only collectors and the existing
assessment/persistence boundaries.  It deliberately contains no control, severity, finding, or
remediation decisions.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from uuid import UUID, uuid5

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from app.assessment.identities import resource_snapshot_id
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipProvenance,
    RelationshipResolution,
    RelationshipType,
    ResourceRelationship,
    UnresolvedRelationshipTarget,
    deduplicate_relationships,
)
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    EvidenceSubject,
    ResourceEvidenceSubject,
    SourceEvidenceOutcome,
    calculate_source_outcome_id,
)
from app.schemas.resource import (
    NormalizedResource,
    ResourceScope,
    canonical_resource_scope,
)

EVIDENCE_GRAPH_SCHEMA_VERSION = "1.0.0"
SOURCE_CONTRACT_SCHEMA_VERSION = "1.0.0"
SOURCE_ARTIFACT_SCHEMA_VERSION = "1.0.0"

_AWS_REGION_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$", re.ASCII)
_CLOUDTRAIL_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9]|[._-](?=[A-Za-z0-9])){1,126}[A-Za-z0-9]$",
    re.ASCII,
)
_IP_SHAPED_NAME_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){3}$", re.ASCII)
_S3_ACL_GRANTEE_TYPES = frozenset({"CanonicalUser", "AmazonCustomerByEmail", "Group"})
_S3_ACL_PERMISSIONS = frozenset({"FULL_CONTROL", "WRITE", "WRITE_ACP", "READ", "READ_ACP"})
_S3_ACL_GRANTEE_FIELD_SETS = {
    "CanonicalUser": (frozenset({"type", "id"}), frozenset({"type", "id", "display_name"})),
    "AmazonCustomerByEmail": (frozenset({"type", "email_address"}),),
    "Group": (frozenset({"type", "uri"}),),
}
_S3_PUBLIC_ACL_GROUP_URIS = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)
_S3_ENCRYPTION_ALGORITHMS = frozenset(
    {"AES256", "aws:backup", "aws:fsx", "aws:kms", "aws:kms:dsse"}
)
_S3_KMS_ENCRYPTION_ALGORITHMS = frozenset({"aws:kms", "aws:kms:dsse"})
_S3_BLOCKED_ENCRYPTION_TYPES = frozenset({"NONE", "SSE-C"})
_S3_OBJECT_OWNERSHIP_VALUES = frozenset(
    {"BucketOwnerPreferred", "ObjectWriter", "BucketOwnerEnforced"}
)
_S3_PUBLIC_ACCESS_BLOCK_FIELDS = frozenset(
    {"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"}
)
_S3_VERSIONING_STATUSES = frozenset({"Enabled", "Suspended"})
_S3_MFA_DELETE_STATUSES = frozenset({"Enabled", "Disabled"})
_KMS_KEY_MANAGERS = frozenset({"AWS", "CUSTOMER"})
_KMS_KEY_STATES = frozenset(
    {
        "Creating",
        "Enabled",
        "Disabled",
        "PendingDeletion",
        "PendingImport",
        "PendingReplicaDeletion",
        "Unavailable",
        "Updating",
    }
)
_KMS_KEY_ORIGINS = frozenset({"AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"})
_KMS_KEY_USAGES = frozenset(
    {"SIGN_VERIFY", "ENCRYPT_DECRYPT", "GENERATE_VERIFY_MAC", "KEY_AGREEMENT"}
)
_KMS_KEY_SPECS = frozenset(
    {
        "RSA_2048",
        "RSA_3072",
        "RSA_4096",
        "ECC_NIST_P256",
        "ECC_NIST_P384",
        "ECC_NIST_P521",
        "ECC_SECG_P256K1",
        "SYMMETRIC_DEFAULT",
        "HMAC_224",
        "HMAC_256",
        "HMAC_384",
        "HMAC_512",
        "SM2",
        "ML_DSA_44",
        "ML_DSA_65",
        "ML_DSA_87",
        "ECC_NIST_EDWARDS25519",
    }
)
_KMS_KEY_SPEC_USAGES = {
    "SYMMETRIC_DEFAULT": frozenset({"ENCRYPT_DECRYPT"}),
    "HMAC_224": frozenset({"GENERATE_VERIFY_MAC"}),
    "HMAC_256": frozenset({"GENERATE_VERIFY_MAC"}),
    "HMAC_384": frozenset({"GENERATE_VERIFY_MAC"}),
    "HMAC_512": frozenset({"GENERATE_VERIFY_MAC"}),
    "RSA_2048": frozenset({"ENCRYPT_DECRYPT", "SIGN_VERIFY"}),
    "RSA_3072": frozenset({"ENCRYPT_DECRYPT", "SIGN_VERIFY"}),
    "RSA_4096": frozenset({"ENCRYPT_DECRYPT", "SIGN_VERIFY"}),
    "ECC_NIST_P256": frozenset({"SIGN_VERIFY", "KEY_AGREEMENT"}),
    "ECC_NIST_P384": frozenset({"SIGN_VERIFY", "KEY_AGREEMENT"}),
    "ECC_NIST_P521": frozenset({"SIGN_VERIFY", "KEY_AGREEMENT"}),
    "ECC_SECG_P256K1": frozenset({"SIGN_VERIFY"}),
    "ECC_NIST_EDWARDS25519": frozenset({"SIGN_VERIFY"}),
    "ML_DSA_44": frozenset({"SIGN_VERIFY"}),
    "ML_DSA_65": frozenset({"SIGN_VERIFY"}),
    "ML_DSA_87": frozenset({"SIGN_VERIFY"}),
    "SM2": frozenset({"ENCRYPT_DECRYPT", "SIGN_VERIFY", "KEY_AGREEMENT"}),
}
_S3_5E_COLLECTORS = frozenset(
    {
        "kms.keys",
        "s3.account-public-access-block",
        "s3.bucket-acl",
        "s3.bucket-encryption",
        "s3.bucket-location",
        "s3.bucket-ownership-controls",
        "s3.bucket-policy",
        "s3.bucket-policy-status",
        "s3.bucket-public-access-block",
        "s3.bucket-tags",
        "s3.bucket-versioning",
        "s3.buckets",
    }
)

_CLOUDTRAIL_ALLOWED_STATES = frozenset(
    {
        EvidenceSourceState.PRESENT,
        EvidenceSourceState.UNAVAILABLE,
        EvidenceSourceState.MALFORMED,
        EvidenceSourceState.CONFLICT,
        EvidenceSourceState.RESOURCE_DISAPPEARED,
    }
)
_CLOUDTRAIL_BASIC_READ_WRITE_TYPES = frozenset({"All", "ReadOnly", "WriteOnly"})
_CLOUDTRAIL_MANAGEMENT_EVENT_EXCLUSIONS = frozenset({"kms.amazonaws.com", "rdsdata.amazonaws.com"})
_CLOUDTRAIL_ADVANCED_OPERATOR_FIELDS = (
    "equals",
    "starts_with",
    "ends_with",
    "not_equals",
    "not_starts_with",
    "not_ends_with",
)

_SOURCE_ARTIFACT_NAMESPACE = UUID("a524b9a2-bd87-57f0-8317-03e43a36e260")

CollectionAccountId = Annotated[str, Field(pattern=r"^[0-9]{12}$")]
ContractKey = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")]
Version = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$"),
]


@dataclass(frozen=True, slots=True)
class S3BucketRegionEvidence:
    """Reconstructed 5E bucket-location manifest used for scope admission."""

    complete: bool
    bucket_regions: tuple[tuple[str, str], ...]

    def region_for(self, bucket_name: str) -> str | None:
        """Return one authoritative bucket home Region, when collection established it."""

        return dict(self.bucket_regions).get(bucket_name)


@dataclass(frozen=True, slots=True)
class _CloudTrailManifest:
    """Validated 5F source family used by graph and resource replay checks."""

    discovery: SourceEvidenceOutcome
    invocation_region: str
    admitted_arns: tuple[str, ...]
    sources_by_arn: Mapping[str, Mapping[str, tuple[SourceEvidenceOutcome, object]]]
    admission_incomplete: bool


class EvidenceCardinality(StrEnum):
    """Shape of the normalized response promised by a declared evidence source."""

    SINGLE = "SINGLE"
    COLLECTION = "COLLECTION"


_CLOUDTRAIL_SOURCE_IDENTITIES = {
    "cloudtrail.trails.discovery": (
        "cloudtrail.trails",
        "cloudtrail:ListTrails",
        EvidenceCollectionPhase.DISCOVERY,
        EvidenceCardinality.COLLECTION,
        False,
    ),
    "cloudtrail.trail.identity": (
        "cloudtrail.trails",
        "cloudtrail:ListTrails",
        EvidenceCollectionPhase.ENRICHMENT,
        EvidenceCardinality.SINGLE,
        True,
    ),
    "cloudtrail.trail.configuration": (
        "cloudtrail.trail-configuration",
        "cloudtrail:GetTrail",
        EvidenceCollectionPhase.ENRICHMENT,
        EvidenceCardinality.SINGLE,
        False,
    ),
    "cloudtrail.trail.status": (
        "cloudtrail.trail-status",
        "cloudtrail:GetTrailStatus",
        EvidenceCollectionPhase.ENRICHMENT,
        EvidenceCardinality.SINGLE,
        False,
    ),
    "cloudtrail.trail.event-selectors": (
        "cloudtrail.trail-event-selectors",
        "cloudtrail:GetEventSelectors",
        EvidenceCollectionPhase.ENRICHMENT,
        EvidenceCardinality.SINGLE,
        False,
    ),
    "cloudtrail.trail.tags": (
        "cloudtrail.trail-tags",
        "cloudtrail:ListTags",
        EvidenceCollectionPhase.ENRICHMENT,
        EvidenceCardinality.SINGLE,
        False,
    ),
}
_CLOUDTRAIL_RESOURCE_KINDS = frozenset(_CLOUDTRAIL_SOURCE_IDENTITIES) - {
    "cloudtrail.trails.discovery"
}
_CLOUDTRAIL_NON_AUTHORITATIVE_EXTERNAL_KINDS = _CLOUDTRAIL_RESOURCE_KINDS - {
    "cloudtrail.trail.identity"
}


class ResourceOwnerMode(StrEnum):
    """Closed owner class that an identity-authoritative source may establish."""

    COLLECTION_ACCOUNT = "COLLECTION_ACCOUNT"
    AWS_MANAGED = "AWS_MANAGED"
    EXTERNAL_ACCOUNT = "EXTERNAL_ACCOUNT"


def validate_s3_bucket_evidence_value(
    *,
    evidence_kind: str,
    state: EvidenceSourceState,
    value: object,
) -> object:
    """Validate one canonical 5E per-bucket value and return its resource projection."""

    validators = {
        "s3.bucket-acl": _validate_s3_acl_value,
        "s3.bucket-encryption": _validate_s3_encryption_value,
        "s3.bucket-ownership-controls": _validate_s3_ownership_controls_value,
        "s3.bucket-policy": _validate_s3_policy_value,
        "s3.bucket-policy-status": _validate_s3_policy_status_value,
        "s3.bucket-public-access-block": _validate_s3_public_access_block_value,
        "s3.bucket-tags": _validate_s3_tags_value,
        "s3.bucket-versioning": _validate_s3_versioning_value,
    }
    try:
        validator = validators[evidence_kind]
    except KeyError as error:
        raise ValueError("unknown S3 per-bucket evidence kind") from error

    expected_absence_values: dict[str, object] = {
        "s3.bucket-encryption": None,
        "s3.bucket-ownership-controls": None,
        "s3.bucket-policy": None,
        "s3.bucket-policy-status": {"policy_present": False, "is_public": False},
        "s3.bucket-public-access-block": {field: False for field in _S3_PUBLIC_ACCESS_BLOCK_FIELDS},
        "s3.bucket-tags": [],
        "s3.bucket-versioning": {"status": None, "mfa_delete": None},
    }
    if state is EvidenceSourceState.EXPECTED_ABSENCE:
        if (
            evidence_kind not in expected_absence_values
            or value != expected_absence_values[evidence_kind]
        ):
            raise ValueError("S3 expected-absence value is invalid")
        return None if value is None else validator(value)
    if value is None:
        if state is EvidenceSourceState.PRESENT:
            raise ValueError("PRESENT S3 evidence requires a normalized value")
        return None
    retained_failure_value = bool(
        (evidence_kind == "s3.bucket-encryption" and state is EvidenceSourceState.MALFORMED)
        or (
            evidence_kind in {"s3.bucket-acl", "s3.bucket-policy", "s3.bucket-policy-status"}
            and state is EvidenceSourceState.CONFLICT
        )
    )
    if state is not EvidenceSourceState.PRESENT and not retained_failure_value:
        raise ValueError("failed S3 evidence cannot retain a normalized value")
    normalized = validator(value)
    if state is EvidenceSourceState.PRESENT:
        if evidence_kind == "s3.bucket-policy-status" and not normalized["policy_present"]:
            raise ValueError("PRESENT S3 policy status must identify a present policy")
        if evidence_kind == "s3.bucket-versioning" and all(
            item is None for item in normalized.values()
        ):
            raise ValueError("unversioned S3 evidence must use EXPECTED_ABSENCE")
    return normalized


def s3_policy_evidence_conflicts(*, policy_value: object, status_value: object) -> bool:
    """Return whether two otherwise complete policy sources contain a direct contradiction."""

    normalized_policy = None if policy_value is None else _validate_s3_policy_value(policy_value)
    normalized_status = _validate_s3_policy_status_value(status_value)
    return bool(
        (normalized_policy is None and normalized_status["is_public"])
        or (normalized_policy is not None and normalized_status["policy_present"] is False)
        or (
            normalized_policy is not None
            and normalized_status["is_public"] is False
            and _s3_policy_has_unconditional_public_grant(normalized_policy)
        )
    )


def validate_s3_policy_source_coherence(
    *,
    policy_outcome: SourceEvidenceOutcome,
    policy_value: object,
    status_outcome: SourceEvidenceOutcome,
    status_value: object,
) -> None:
    """Require detected policy/status contradictions to be retained as paired conflicts."""

    conflict_state = EvidenceSourceState.CONFLICT
    if policy_outcome.state is conflict_state or status_outcome.state is conflict_state:
        if policy_outcome.state is not conflict_state or status_outcome.state is not conflict_state:
            raise ValueError("S3 policy coherence conflict must cover both source outcomes")
        if not s3_policy_evidence_conflicts(
            policy_value=policy_value,
            status_value=status_value,
        ):
            raise ValueError("S3 policy coherence conflict has no contradictory facts")
        return

    complete_states = {
        EvidenceSourceState.PRESENT,
        EvidenceSourceState.EXPECTED_ABSENCE,
    }
    if (
        policy_outcome.state in complete_states
        and status_outcome.state in complete_states
        and s3_policy_evidence_conflicts(
            policy_value=policy_value,
            status_value=status_value,
        )
    ):
        raise ValueError("contradictory S3 policy sources must use CONFLICT outcomes")


def s3_acl_public_access_conflicts(
    *,
    acl_value: object,
    account_public_access_block_value: object | None,
    bucket_public_access_block_value: object | None,
) -> bool:
    """Return whether an effective ACL contradicts a proven IgnorePublicAcls setting."""

    normalized_acl = _validate_s3_acl_value(acl_value)
    blocks = tuple(
        _validate_s3_public_access_block_value(value)
        for value in (
            account_public_access_block_value,
            bucket_public_access_block_value,
        )
        if value is not None
    )
    return bool(
        _s3_acl_has_public_group_grant(normalized_acl)
        and any(block["IgnorePublicAcls"] for block in blocks)
    )


def s3_acl_ownership_conflicts(
    *,
    acl_value: object,
    ownership_controls_value: object | None,
) -> bool:
    """Return whether BucketOwnerEnforced contradicts the effective ACL returned by S3."""

    if ownership_controls_value is None:
        return False
    normalized_acl = _validate_s3_acl_value(acl_value)
    ownership = _validate_s3_ownership_controls_value(ownership_controls_value)
    if not any(rule["object_ownership"] == "BucketOwnerEnforced" for rule in ownership["rules"]):
        return False
    grants = normalized_acl["grants"]
    owner = normalized_acl["owner"]
    if not isinstance(grants, list) or not isinstance(owner, Mapping):  # pragma: no cover
        raise TypeError("validated S3 ACL has an invalid shape")
    if len(grants) != 1 or not isinstance(grants[0], Mapping):
        return True
    grant = grants[0]
    grantee = grant.get("grantee")
    return not bool(
        isinstance(grantee, Mapping)
        and grantee.get("type") == "CanonicalUser"
        and grantee.get("id") == owner.get("id")
        and grant.get("permission") == "FULL_CONTROL"
    )


def validate_s3_acl_source_coherence(
    *,
    acl_outcome: SourceEvidenceOutcome,
    acl_value: object,
    account_public_access_block_outcome: SourceEvidenceOutcome,
    account_public_access_block_value: object | None,
    bucket_public_access_block_outcome: SourceEvidenceOutcome,
    bucket_public_access_block_value: object | None,
    ownership_controls_outcome: SourceEvidenceOutcome,
    ownership_controls_value: object | None,
) -> None:
    """Require impossible effective ACL combinations to remain incomplete evidence."""

    complete_states = {
        EvidenceSourceState.PRESENT,
        EvidenceSourceState.EXPECTED_ABSENCE,
    }
    account_value = (
        account_public_access_block_value
        if account_public_access_block_outcome.state in complete_states
        else None
    )
    bucket_value = (
        bucket_public_access_block_value
        if bucket_public_access_block_outcome.state in complete_states
        else None
    )
    ownership_value = (
        ownership_controls_value if ownership_controls_outcome.state in complete_states else None
    )
    conflicts = bool(
        s3_acl_public_access_conflicts(
            acl_value=acl_value,
            account_public_access_block_value=account_value,
            bucket_public_access_block_value=bucket_value,
        )
        or s3_acl_ownership_conflicts(
            acl_value=acl_value,
            ownership_controls_value=ownership_value,
        )
    )
    if acl_outcome.state is EvidenceSourceState.CONFLICT:
        if not conflicts:
            raise ValueError("S3 ACL coherence conflict has no contradictory facts")
        return
    if acl_outcome.state is EvidenceSourceState.PRESENT and conflicts:
        raise ValueError("contradictory S3 ACL evidence must use a CONFLICT outcome")


def s3_encryption_kms_references(value: object) -> tuple[str, ...]:
    """Return explicit KMS references from one fully validated normalized S3 value."""

    normalized = _validate_s3_encryption_value(value)
    return tuple(
        sorted(
            {
                rule["kms_key_reference"]
                for rule in normalized["rules"]
                if rule["kms_key_reference"] is not None
            }
        )
    )


def s3_encryption_has_invalid_kms_reference(
    value: object,
    *,
    bucket_region: str,
    partition: str,
) -> bool:
    """Return whether retained normalized encryption contains a non-canonical KMS reference."""

    references = s3_encryption_kms_references(value)
    for reference in references:
        try:
            _s3_kms_reference_region(
                reference=reference,
                bucket_region=bucket_region,
                partition=partition,
            )
        except ValueError:
            return True
    return False


def validate_kms_key_evidence_value(
    *,
    state: EvidenceSourceState,
    value: object,
) -> dict[str, object] | None:
    """Validate the exact normalized DescribeKey payload emitted by the 5E collector."""

    if state is not EvidenceSourceState.PRESENT:
        if value is not None:
            raise ValueError("failed KMS DescribeKey evidence cannot retain a key value")
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "aws_account_id",
        "region",
        "key_id",
        "arn",
        "key_manager",
        "enabled",
        "multi_region",
        "creation_date",
        "key_state",
        "origin",
        "key_usage",
        "key_spec",
    }:
        raise ValueError("KMS DescribeKey value has an invalid schema")
    account_id = value["aws_account_id"]
    region = value["region"]
    key_id = value["key_id"]
    arn = value["arn"]
    if (
        not isinstance(account_id, str)
        or len(account_id) != 12
        or not account_id.isascii()
        or not account_id.isdigit()
        or not _is_safe_non_empty_string(region)
        or not _is_safe_non_empty_string(key_id)
        or not _is_safe_non_empty_string(arn)
    ):
        raise ValueError("KMS DescribeKey value has an invalid identity")
    arn_parts = arn.split(":", maxsplit=5)
    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or not arn_parts[1]
        or arn_parts[2:] != ["kms", region, account_id, f"key/{key_id}"]
    ):
        raise ValueError("KMS DescribeKey value has an inconsistent ARN")
    if value["key_manager"] not in _KMS_KEY_MANAGERS:
        raise ValueError("KMS DescribeKey value has an invalid manager")
    for field in ("enabled", "multi_region"):
        if value[field] is not None and not isinstance(value[field], bool):
            raise ValueError("KMS DescribeKey value has an invalid boolean fact")
    creation_date = value["creation_date"]
    if creation_date is not None:
        if not isinstance(creation_date, str):
            raise ValueError("KMS DescribeKey value has an invalid creation date")
        try:
            parsed_creation_date = datetime.fromisoformat(creation_date)
        except ValueError as error:
            raise ValueError("KMS DescribeKey value has an invalid creation date") from error
        if (
            parsed_creation_date.tzinfo is None
            or parsed_creation_date.utcoffset() is None
            or parsed_creation_date.astimezone(UTC).isoformat() != creation_date
        ):
            raise ValueError("KMS DescribeKey value has an invalid creation date")
    enum_fields = {
        "key_state": _KMS_KEY_STATES,
        "origin": _KMS_KEY_ORIGINS,
        "key_usage": _KMS_KEY_USAGES,
        "key_spec": _KMS_KEY_SPECS,
    }
    for field, allowed in enum_fields.items():
        if value[field] is not None and value[field] not in allowed:
            raise ValueError("KMS DescribeKey value has an invalid enum fact")
    key_state = value["key_state"]
    enabled = value["enabled"]
    if enabled is not None and key_state is not None and enabled is not (key_state == "Enabled"):
        raise ValueError("KMS DescribeKey enabled state contradicts its key state")
    key_spec = value["key_spec"]
    key_usage = value["key_usage"]
    if (
        key_spec is not None
        and key_usage is not None
        and key_usage not in _KMS_KEY_SPEC_USAGES[key_spec]
    ):
        raise ValueError("KMS DescribeKey key usage contradicts its key spec")
    return dict(value)


class ScanSourceContract(BaseModel):
    """One concrete, versioned source promised for one scan execution."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    contract_key: ContractKey
    contract_version: Version
    source_outcome_id: UUID
    scan_id: UUID
    collection_account_id: CollectionAccountId
    phase: EvidenceCollectionPhase
    subject: EvidenceSubject
    evidence_kind: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    collector: str = Field(min_length=1, pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$")
    collector_version: Version
    source_api: str = Field(
        min_length=3,
        pattern=r"^[a-z0-9-]+:[A-Za-z][A-Za-z0-9]*$",
    )
    cardinality: EvidenceCardinality
    owner_mode: ResourceOwnerMode = ResourceOwnerMode.COLLECTION_ACCOUNT
    identity_authoritative: bool = False
    allows_supplemental_region: bool = False
    schema_version: Literal["1.0.0"] = SOURCE_CONTRACT_SCHEMA_VERSION

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        """Bind the declaration to its scan, subject, and deterministic outcome identity."""

        if self.phase is EvidenceCollectionPhase.DISCOVERY:
            if not isinstance(self.subject, AccountEvidenceSubject):
                raise ValueError("discovery source contracts require an account evidence subject")
            if self.subject.aws_account_id != self.collection_account_id:
                raise ValueError(
                    "discovery subject account must match the source contract collection account"
                )
        elif not isinstance(self.subject, ResourceEvidenceSubject):
            raise ValueError("enrichment source contracts require a resource evidence subject")

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
                raise ValueError("resource subject must identify the source contract scan")

        expected_owner_mode = ResourceOwnerMode.COLLECTION_ACCOUNT
        if isinstance(self.subject, ResourceEvidenceSubject):
            if self.subject.aws_account_id == "aws":
                expected_owner_mode = ResourceOwnerMode.AWS_MANAGED
            elif self.subject.aws_account_id != self.collection_account_id:
                expected_owner_mode = ResourceOwnerMode.EXTERNAL_ACCOUNT
        if self.owner_mode is not expected_owner_mode:
            raise ValueError("owner_mode does not match the declared evidence subject owner")

        if (
            self.owner_mode is not ResourceOwnerMode.COLLECTION_ACCOUNT
            and not self.identity_authoritative
            and not _is_cloudtrail_non_authoritative_external_enrichment_source(self)
        ):
            raise ValueError("exceptional owner modes require identity-authoritative evidence")
        if (
            self.phase is EvidenceCollectionPhase.DISCOVERY
            and self.allows_supplemental_region
            and not _is_access_analyzer_discovery_source(self)
        ):
            raise ValueError(
                "only controlled Access Analyzer discovery can authorize supplemental Regions"
            )

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
            raise ValueError("source_outcome_id does not match the declared source contract")
        return self

    @classmethod
    def for_scan(
        cls,
        *,
        contract_key: str,
        contract_version: str,
        scan_id: UUID,
        collection_account_id: str,
        phase: EvidenceCollectionPhase,
        subject: AccountEvidenceSubject | ResourceEvidenceSubject,
        evidence_kind: str,
        collector: str,
        collector_version: str,
        source_api: str,
        cardinality: EvidenceCardinality,
        owner_mode: ResourceOwnerMode = ResourceOwnerMode.COLLECTION_ACCOUNT,
        identity_authoritative: bool = False,
        allows_supplemental_region: bool = False,
    ) -> Self:
        """Build a declaration using the canonical source-outcome identifier."""

        return cls(
            contract_key=contract_key,
            contract_version=contract_version,
            source_outcome_id=calculate_source_outcome_id(
                scan_id=scan_id,
                collection_account_id=collection_account_id,
                phase=phase,
                subject=subject,
                evidence_kind=evidence_kind,
                collector=collector,
                collector_version=collector_version,
                source_api=source_api,
            ),
            scan_id=scan_id,
            collection_account_id=collection_account_id,
            phase=phase,
            subject=subject,
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=collector_version,
            source_api=source_api,
            cardinality=cardinality,
            owner_mode=owner_mode,
            identity_authoritative=identity_authoritative,
            allows_supplemental_region=allows_supplemental_region,
        )

    def matches_outcome(self, outcome: SourceEvidenceOutcome) -> bool:
        """Return whether an outcome is the exact result of this declaration."""

        return all(
            (
                outcome.source_outcome_id == self.source_outcome_id,
                outcome.scan_id == self.scan_id,
                outcome.collection_account_id == self.collection_account_id,
                outcome.phase is self.phase,
                outcome.subject == self.subject,
                outcome.evidence_kind == self.evidence_kind,
                outcome.collector == self.collector,
                outcome.collector_version == self.collector_version,
                outcome.source_api == self.source_api,
            )
        )


def validate_s3_source_contract_manifest(
    *,
    outcomes: Iterable[SourceEvidenceOutcome],
    contracts: Iterable[ScanSourceContract],
) -> None:
    """Require the exact source declarations emitted by the 5E S3 collector."""

    selected_outcomes = tuple(
        outcome for outcome in outcomes if outcome.collector in _S3_5E_COLLECTORS
    )
    outcome_ids = {outcome.source_outcome_id for outcome in selected_outcomes}
    selected_contracts = tuple(
        contract for contract in contracts if contract.source_outcome_id in outcome_ids
    )
    contracts_by_outcome = {contract.source_outcome_id: contract for contract in selected_contracts}
    if (
        not selected_outcomes
        or len(outcome_ids) != len(selected_outcomes)
        or len(selected_contracts) != len(selected_outcomes)
        or len(contracts_by_outcome) != len(selected_outcomes)
    ):
        raise ValueError("S3 source contract manifest is incomplete or ambiguous")

    for outcome in selected_outcomes:
        validate_s3_source_state(outcome)
        validate_s3_source_identity(outcome)
        contract = contracts_by_outcome[outcome.source_outcome_id]
        subject = outcome.subject
        expected_owner = ResourceOwnerMode.COLLECTION_ACCOUNT
        if isinstance(subject, ResourceEvidenceSubject):
            if subject.aws_account_id == "aws":
                expected_owner = ResourceOwnerMode.AWS_MANAGED
            elif subject.aws_account_id != outcome.collection_account_id:
                expected_owner = ResourceOwnerMode.EXTERNAL_ACCOUNT
        expected_authoritative = bool(
            outcome.state is EvidenceSourceState.PRESENT
            and outcome.collector in {"kms.keys", "s3.bucket-location"}
        )
        expected_cardinality = (
            EvidenceCardinality.COLLECTION
            if outcome.collector == "s3.buckets"
            else EvidenceCardinality.SINGLE
        )
        if (
            not contract.matches_outcome(outcome)
            or contract.contract_key != outcome.evidence_kind
            or contract.contract_version != "1.0.0"
            or contract.cardinality is not expected_cardinality
            or contract.owner_mode is not expected_owner
            or contract.identity_authoritative is not expected_authoritative
            or contract.allows_supplemental_region
        ):
            raise ValueError("S3 source contract manifest is invalid")


def validate_s3_source_state(outcome: SourceEvidenceOutcome) -> None:
    """Reject 5E source states that the corresponding live producer cannot emit."""

    common_failure_states = {
        EvidenceSourceState.UNAVAILABLE,
        EvidenceSourceState.MALFORMED,
        EvidenceSourceState.RESOURCE_DISAPPEARED,
    }
    optional_bucket_sources = {
        "s3.bucket-encryption",
        "s3.bucket-ownership-controls",
        "s3.bucket-policy",
        "s3.bucket-policy-status",
        "s3.bucket-public-access-block",
        "s3.bucket-tags",
        "s3.bucket-versioning",
    }
    if outcome.collector == "kms.keys":
        allowed = {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.UNAVAILABLE,
            EvidenceSourceState.MALFORMED,
            EvidenceSourceState.CONFLICT,
        }
    elif outcome.collector in {"s3.buckets", "s3.bucket-location"}:
        allowed = {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.CONFLICT,
            *common_failure_states,
        }
    elif outcome.collector == "s3.account-public-access-block":
        allowed = {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.EXPECTED_ABSENCE,
            *common_failure_states,
        }
    elif outcome.collector == "s3.bucket-acl":
        allowed = {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.CONFLICT,
            *common_failure_states,
        }
    elif outcome.collector in {"s3.bucket-policy", "s3.bucket-policy-status"}:
        allowed = {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.EXPECTED_ABSENCE,
            EvidenceSourceState.CONFLICT,
            *common_failure_states,
        }
    elif outcome.collector in optional_bucket_sources:
        allowed = {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.EXPECTED_ABSENCE,
            *common_failure_states,
        }
    else:
        raise ValueError("unknown 5E S3 source collector")
    if outcome.state not in allowed:
        raise ValueError("5E S3 source state is invalid")


def validate_s3_source_identity(outcome: SourceEvidenceOutcome) -> None:
    """Validate the immutable source identity for every 5E S3/KMS outcome family."""

    subject = outcome.subject
    per_bucket_apis = {
        "s3.bucket-acl": "s3:GetBucketAcl",
        "s3.bucket-encryption": "s3:GetEncryptionConfiguration",
        "s3.bucket-ownership-controls": "s3:GetBucketOwnershipControls",
        "s3.bucket-policy": "s3:GetBucketPolicy",
        "s3.bucket-policy-status": "s3:GetBucketPolicyStatus",
        "s3.bucket-public-access-block": "s3:GetBucketPublicAccessBlock",
        "s3.bucket-tags": "s3:GetBucketTagging",
        "s3.bucket-versioning": "s3:GetBucketVersioning",
    }
    common_account_subject = bool(
        isinstance(subject, AccountEvidenceSubject)
        and subject.aws_account_id == outcome.collection_account_id
        and subject.scope is ResourceScope.GLOBAL
    )
    common_bucket_subject = bool(
        isinstance(subject, ResourceEvidenceSubject)
        and subject.aws_account_id == outcome.collection_account_id
        and subject.service == "s3"
        and subject.resource_type == "s3_bucket"
        and subject.scope is ResourceScope.REGIONAL
    )
    valid = False
    if outcome.collector == "s3.buckets":
        valid = all(
            (
                outcome.phase is EvidenceCollectionPhase.DISCOVERY,
                common_account_subject,
                outcome.evidence_kind == "s3.buckets.discovery",
                outcome.collector_version == "1.0.0",
                outcome.source_api == "s3:ListAllMyBuckets",
            )
        )
    elif outcome.collector == "s3.account-public-access-block":
        valid = all(
            (
                outcome.phase is EvidenceCollectionPhase.DISCOVERY,
                common_account_subject,
                outcome.evidence_kind == "s3.account-public-access-block",
                outcome.collector_version == "1.0.0",
                outcome.source_api == "s3:GetAccountPublicAccessBlock",
            )
        )
    elif outcome.collector == "s3.bucket-location":
        resource_scoped = outcome.state in {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.RESOURCE_DISAPPEARED,
        }
        if resource_scoped:
            valid = all(
                (
                    outcome.phase is EvidenceCollectionPhase.ENRICHMENT,
                    common_bucket_subject,
                    outcome.evidence_kind == "s3.bucket-location",
                    outcome.collector_version == "1.0.0",
                    outcome.source_api == "s3:GetBucketLocation",
                )
            )
        else:
            prefix = "s3.bucket-location."
            digest = outcome.evidence_kind.removeprefix(prefix)
            valid = all(
                (
                    outcome.phase is EvidenceCollectionPhase.DISCOVERY,
                    common_account_subject,
                    outcome.evidence_kind.startswith(prefix),
                    len(digest) == 64,
                    all(character in "0123456789abcdef" for character in digest),
                    outcome.collector_version == "1.0.0",
                    outcome.source_api == "s3:GetBucketLocation",
                )
            )
    elif outcome.collector in per_bucket_apis:
        valid = all(
            (
                outcome.phase is EvidenceCollectionPhase.ENRICHMENT,
                common_bucket_subject,
                outcome.evidence_kind == outcome.collector,
                outcome.collector_version == "1.0.0",
                outcome.source_api == per_bucket_apis[outcome.collector],
            )
        )
    elif outcome.collector == "kms.keys":
        prefix = "kms.key."
        digest = outcome.evidence_kind.removeprefix(prefix)
        present_subject = bool(
            isinstance(subject, ResourceEvidenceSubject)
            and subject.service == "kms"
            and subject.resource_type == "kms_key"
            and subject.scope is ResourceScope.REGIONAL
        )
        valid = all(
            (
                outcome.phase is EvidenceCollectionPhase.ENRICHMENT,
                (
                    present_subject
                    if outcome.state is EvidenceSourceState.PRESENT
                    else common_bucket_subject
                ),
                outcome.evidence_kind.startswith(prefix),
                len(digest) == 64,
                all(character in "0123456789abcdef" for character in digest),
                outcome.collector_version == "1.0.0",
                outcome.source_api == "kms:DescribeKey",
            )
        )
    if not valid:
        raise ValueError("5E S3 source identity is invalid")


def _is_access_analyzer_discovery_source(contract: ScanSourceContract) -> bool:
    """Recognize only the two approved 5D Regional discovery source families."""

    if (
        not isinstance(contract.subject, AccountEvidenceSubject)
        or contract.subject.scope is not ResourceScope.REGIONAL
        or contract.collector_version != "1.0.0"
    ):
        return False
    if (
        contract.contract_key == "access-analyzer.analyzers.discovery"
        and contract.evidence_kind == contract.contract_key
        and contract.collector == "access-analyzer.analyzers"
        and contract.source_api == "access-analyzer:ListAnalyzers"
    ):
        return True
    prefix = "access-analyzer.findings.discovery."
    digest = contract.evidence_kind.removeprefix(prefix)
    return all(
        (
            contract.contract_key == contract.evidence_kind,
            contract.evidence_kind.startswith(prefix),
            len(digest) == 64,
            all(character in "0123456789abcdef" for character in digest),
            contract.collector == "access-analyzer.findings",
            contract.source_api == "access-analyzer:ListFindings",
        )
    )


def _is_cloudtrail_non_authoritative_external_enrichment_source(
    contract: ScanSourceContract,
) -> bool:
    """Recognize the closed 5F sources whose identity is proved by paired ListTrails evidence."""

    subject = contract.subject
    expected = _CLOUDTRAIL_SOURCE_IDENTITIES.get(contract.evidence_kind)
    return bool(
        contract.evidence_kind in _CLOUDTRAIL_NON_AUTHORITATIVE_EXTERNAL_KINDS
        and expected is not None
        and contract.phase is expected[2]
        and contract.cardinality is expected[3]
        and contract.collector == expected[0]
        and contract.collector_version == "1.0.0"
        and contract.source_api == expected[1]
        and contract.contract_key == contract.evidence_kind
        and contract.contract_version == "1.0.0"
        and isinstance(subject, ResourceEvidenceSubject)
        and subject.service == "cloudtrail"
        and subject.resource_type == "cloudtrail_trail"
        and subject.scope is ResourceScope.REGIONAL
        and contract.owner_mode is ResourceOwnerMode.EXTERNAL_ACCOUNT
        and not contract.identity_authoritative
        and not contract.allows_supplemental_region
    )


class SourceEvidenceArtifact(BaseModel):
    """One immutable normalized JSON artifact referenced by a source outcome."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        arbitrary_types_allowed=True,
    )

    artifact_id: UUID
    scan_id: UUID
    collection_account_id: CollectionAccountId
    evidence_reference: str = Field(
        min_length=14,
        max_length=512,
        pattern=r"^normalized://[^\r\n]+$",
    )
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_schema: str = Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")
    evidence_schema_version: Version
    collected_at: datetime
    normalized_payload: Any
    schema_version: Literal["1.0.0"] = SOURCE_ARTIFACT_SCHEMA_VERSION

    @field_validator("normalized_payload", mode="before")
    @classmethod
    def validate_and_freeze_payload(cls, value: object) -> _FrozenJsonObject:
        """Accept an object-shaped finite JSON value and freeze every nested container."""

        if not isinstance(value, Mapping):
            raise ValueError("normalized evidence payload must be a JSON object")
        normalized = _canonical_json_value(value)
        _reject_sensitive_keys(normalized)
        frozen = _freeze_json(normalized)
        if not isinstance(frozen, _FrozenJsonObject):  # pragma: no cover - root checked above
            raise TypeError("normalized evidence payload must be an object")
        return frozen

    @field_serializer("normalized_payload")
    def serialize_payload(self, value: _FrozenJsonObject) -> dict[str, object]:
        """Serialize the private immutable representation as ordinary JSON."""

        thawed = _thaw_json(value)
        if not isinstance(thawed, dict):  # pragma: no cover - model invariant
            raise TypeError("normalized evidence payload must be an object")
        return thawed

    @model_validator(mode="after")
    def validate_artifact(self) -> Self:
        """Bind the identifier and digest to the normalized artifact content."""

        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("source artifact collected_at must be timezone-aware")

        expected_id = calculate_source_artifact_id(
            scan_id=self.scan_id,
            evidence_reference=self.evidence_reference,
        )
        if self.artifact_id != expected_id:
            raise ValueError("artifact_id does not match scan and evidence reference")

        expected_digest = calculate_evidence_sha256(self.normalized_payload)
        if self.evidence_sha256 != expected_digest:
            raise ValueError("evidence_sha256 does not match normalized payload")
        return self

    @classmethod
    def for_payload(
        cls,
        *,
        scan_id: UUID,
        collection_account_id: str,
        evidence_reference: str,
        evidence_schema: str,
        evidence_schema_version: str,
        collected_at: datetime,
        normalized_payload: Mapping[str, object],
    ) -> Self:
        """Normalize an artifact and calculate its deterministic identity and digest."""

        payload = _canonical_json_value(normalized_payload)
        return cls(
            artifact_id=calculate_source_artifact_id(
                scan_id=scan_id,
                evidence_reference=evidence_reference,
            ),
            scan_id=scan_id,
            collection_account_id=collection_account_id,
            evidence_reference=evidence_reference,
            evidence_sha256=calculate_evidence_sha256(payload),
            evidence_schema=evidence_schema,
            evidence_schema_version=evidence_schema_version,
            collected_at=collected_at,
            normalized_payload=payload,
        )


class EvidenceGraph(BaseModel):
    """Complete, canonical evidence graph produced for one inventory snapshot."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
    )

    scan_id: UUID
    collection_account_id: CollectionAccountId
    collected_at: datetime
    source_contracts: tuple[ScanSourceContract, ...]
    artifacts: tuple[SourceEvidenceArtifact, ...]
    source_outcomes: tuple[SourceEvidenceOutcome, ...]
    relationships: tuple[ResourceRelationship, ...]
    schema_version: Literal["1.0.0"] = EVIDENCE_GRAPH_SCHEMA_VERSION

    @model_validator(mode="after")
    def validate_graph(self) -> Self:
        """Canonicalize duplicates and validate complete declared-source provenance."""

        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("evidence graph collected_at must be timezone-aware")

        contracts = _deduplicate_records(
            self.source_contracts,
            key=lambda item: item.source_outcome_id,
            conflict_message="conflicting duplicate source contract",
        )
        artifacts = _deduplicate_records(
            self.artifacts,
            key=lambda item: item.artifact_id,
            conflict_message="conflicting duplicate source artifact",
        )
        outcomes = _deduplicate_records(
            self.source_outcomes,
            key=lambda item: item.source_outcome_id,
            conflict_message="conflicting duplicate source outcome",
        )
        raw_relationships = self.relationships
        relationships = deduplicate_relationships(raw_relationships)
        object.__setattr__(self, "source_contracts", contracts)
        object.__setattr__(self, "artifacts", artifacts)
        object.__setattr__(self, "source_outcomes", outcomes)
        object.__setattr__(self, "relationships", relationships)

        if not contracts or not artifacts or not outcomes:
            raise ValueError(
                "graph-enabled snapshots require source contracts, artifacts, and outcomes"
            )

        contract_by_id = {item.source_outcome_id: item for item in contracts}
        outcome_by_id = {item.source_outcome_id: item for item in outcomes}
        if set(contract_by_id) != set(outcome_by_id):
            raise ValueError("every declared source must have exactly one source outcome")

        artifact_by_reference: dict[str, SourceEvidenceArtifact] = {}
        for artifact in artifacts:
            self._validate_common_observation(artifact)
            previous = artifact_by_reference.get(artifact.evidence_reference)
            if previous is not None and previous.artifact_id != artifact.artifact_id:
                raise ValueError("evidence references must be unique within a scan")
            artifact_by_reference[artifact.evidence_reference] = artifact

        referenced_artifact_ids: set[UUID] = set()
        for outcome_id, contract in contract_by_id.items():
            self._validate_common_observation(contract)
            outcome = outcome_by_id[outcome_id]
            self._validate_common_observation(outcome)
            if not contract.matches_outcome(outcome):
                raise ValueError("source outcome does not match its declared source contract")
            artifact = artifact_by_reference.get(outcome.evidence_reference)
            if artifact is None:
                raise ValueError("source outcome references an artifact absent from the graph")
            if artifact.evidence_sha256 != outcome.evidence_sha256:
                raise ValueError("source outcome digest does not match its referenced artifact")
            if artifact.collected_at != outcome.collected_at:
                raise ValueError("source outcome and artifact collection times must match")
            referenced_artifact_ids.add(artifact.artifact_id)

        if referenced_artifact_ids != {item.artifact_id for item in artifacts}:
            raise ValueError("unreferenced source artifacts are not permitted")

        if any(
            outcome.collector == "s3.buckets" and outcome.evidence_kind == "s3.buckets.discovery"
            for outcome in outcomes
        ):
            validate_s3_source_contract_manifest(
                outcomes=outcomes,
                contracts=contracts,
            )
            _validate_complete_s3_source_artifacts(
                outcomes=outcomes,
                contracts=contracts,
                artifacts=artifacts,
            )

        cloudtrail_manifest: _CloudTrailManifest | None = None
        if any(
            outcome.collector
            in {identity[0] for identity in _CLOUDTRAIL_SOURCE_IDENTITIES.values()}
            for outcome in outcomes
        ):
            cloudtrail_manifest = _validate_cloudtrail_manifest(
                outcomes=outcomes,
                contracts=contracts,
                artifacts=artifacts,
            )

        outcomes_by_provenance = index_source_outcomes_by_provenance(outcomes)
        for relationship in relationships:
            self._validate_common_observation(relationship)
            matches = outcomes_by_provenance.get(source_provenance_key(relationship.provenance), ())
            if len(matches) != 1:
                raise ValueError(
                    "relationship provenance must identify exactly one declared source outcome"
                )
            outcome = matches[0]
            if outcome.state is not EvidenceSourceState.PRESENT:
                raise ValueError("relationships require PRESENT source evidence")
        _validate_s3_kms_relationship_manifest(
            scan_id=self.scan_id,
            collection_account_id=self.collection_account_id,
            outcomes=outcomes,
            artifacts=artifacts,
            relationships=relationships,
            raw_relationships=raw_relationships,
        )
        if cloudtrail_manifest is not None:
            _validate_cloudtrail_relationship_manifest(
                scan_id=self.scan_id,
                collection_account_id=self.collection_account_id,
                manifest=cloudtrail_manifest,
                contracts=contracts,
                artifacts=artifacts,
                outcomes=outcomes,
                relationships=relationships,
                raw_relationships=raw_relationships,
            )
        return self

    def _validate_common_observation(self, item: object) -> None:
        scan_id = getattr(item, "scan_id", None)
        account_id = getattr(item, "collection_account_id", None)
        collected_at = getattr(item, "collected_at", self.collected_at)
        if scan_id != self.scan_id:
            raise ValueError("all evidence graph records must identify the graph scan")
        if account_id != self.collection_account_id:
            raise ValueError("all evidence graph records must identify the collection account")
        if collected_at != self.collected_at:
            raise ValueError("all evidence graph records must use the graph collection time")

    def canonical_document(self) -> dict[str, object]:
        """Serialize graph history with every absolute timestamp normalized to UTC."""

        artifact_documents = []
        for artifact in self.artifacts:
            document = artifact.model_dump(mode="json")
            document["collected_at"] = artifact.collected_at.astimezone(UTC).isoformat()
            artifact_documents.append(document)

        outcome_documents = []
        for outcome in self.source_outcomes:
            document = outcome.model_dump(mode="json")
            document["collected_at"] = outcome.collected_at.astimezone(UTC).isoformat()
            outcome_documents.append(document)

        relationship_documents = []
        for relationship in self.relationships:
            document = relationship.model_dump(mode="json")
            provenance = relationship.provenance.model_dump(mode="json")
            provenance["collected_at"] = relationship.provenance.collected_at.astimezone(
                UTC
            ).isoformat()
            document["provenance"] = provenance
            relationship_documents.append(document)

        return {
            "scan_id": str(self.scan_id),
            "collection_account_id": self.collection_account_id,
            "collected_at": self.collected_at.astimezone(UTC).isoformat(),
            "source_contracts": [item.model_dump(mode="json") for item in self.source_contracts],
            "artifacts": artifact_documents,
            "source_outcomes": outcome_documents,
            "relationships": relationship_documents,
            "schema_version": self.schema_version,
        }

    @property
    def source_manifest_schema_version(self) -> str:
        """Return the schema version used to canonicalize the declared-source manifest."""

        return SOURCE_CONTRACT_SCHEMA_VERSION

    @property
    def source_manifest_sha256(self) -> str:
        """Return a deterministic digest of every source promised by this graph."""

        document = {
            "schema_version": SOURCE_CONTRACT_SCHEMA_VERSION,
            "source_contracts": [item.model_dump(mode="json") for item in self.source_contracts],
        }
        return _sha256_json(document)

    def contracts_for_relationship(
        self, relationship: ResourceRelationship
    ) -> tuple[ScanSourceContract, ...]:
        """Return the single source declaration whose evidence established an edge."""

        outcome_ids = {
            outcome.source_outcome_id
            for outcome in self.source_outcomes
            if _provenance_matches_outcome(relationship.provenance, outcome)
        }
        return tuple(
            contract
            for contract in self.source_contracts
            if contract.source_outcome_id in outcome_ids
        )


def validate_cloudtrail_source_contract_manifest(
    *,
    outcomes: Iterable[SourceEvidenceOutcome],
    contracts: Iterable[ScanSourceContract],
    artifacts: Iterable[SourceEvidenceArtifact],
) -> bool:
    """Validate the exact dynamic 5F manifest and return whether admission was incomplete."""

    return _validate_cloudtrail_manifest(
        outcomes=tuple(outcomes),
        contracts=tuple(contracts),
        artifacts=tuple(artifacts),
    ).admission_incomplete


def _validate_cloudtrail_manifest(
    *,
    outcomes: tuple[SourceEvidenceOutcome, ...],
    contracts: tuple[ScanSourceContract, ...],
    artifacts: tuple[SourceEvidenceArtifact, ...],
) -> _CloudTrailManifest:
    selected = tuple(
        outcome
        for outcome in outcomes
        if outcome.collector in {identity[0] for identity in _CLOUDTRAIL_SOURCE_IDENTITIES.values()}
    )
    discovery_sources = tuple(
        outcome for outcome in selected if outcome.evidence_kind == "cloudtrail.trails.discovery"
    )
    if len(discovery_sources) != 1:
        raise ValueError("CloudTrail evidence requires exactly one global discovery source")
    discovery = discovery_sources[0]
    contract_by_id = {contract.source_outcome_id: contract for contract in contracts}
    artifacts_by_reference = _artifacts_by_reference(artifacts)
    discovery_contract = contract_by_id.get(discovery.source_outcome_id)
    if discovery_contract is None:
        raise ValueError("CloudTrail discovery has no declared source contract")
    _validate_cloudtrail_source_identity(
        outcome=discovery,
        contract=discovery_contract,
        collection_account_id=discovery.collection_account_id,
    )
    if not isinstance(discovery.subject, AccountEvidenceSubject) or (
        discovery.subject.scope is not ResourceScope.GLOBAL
    ):
        raise ValueError("CloudTrail discovery must use the global collection account")
    discovery_payload = _cloudtrail_payload(
        outcome=discovery,
        artifacts_by_reference=artifacts_by_reference,
    )
    expected_discovery_keys = {
        "collection_account_id",
        "invocation_region",
        "trail_arns",
        "trail_count",
        "discarded_item_count",
        "admission_complete",
        "unadmitted_resources",
        "complete",
        "failure_category",
    }
    trail_arns = discovery_payload.get("trail_arns")
    discarded_item_count = discovery_payload.get("discarded_item_count")
    unadmitted_resources = discovery_payload.get("unadmitted_resources")
    if (
        set(discovery_payload) != expected_discovery_keys
        or discovery_payload.get("collection_account_id") != discovery.collection_account_id
        or not _valid_normalized_region(discovery_payload.get("invocation_region"))
        or not isinstance(trail_arns, list)
        or not all(_is_safe_non_empty_string(item) for item in trail_arns)
        or trail_arns != sorted(set(trail_arns))
        or discovery_payload.get("trail_count") != len(trail_arns)
        or not isinstance(discarded_item_count, int)
        or isinstance(discarded_item_count, bool)
        or discarded_item_count < 0
        or not isinstance(discovery_payload.get("admission_complete"), bool)
        or not isinstance(unadmitted_resources, list)
    ):
        raise ValueError("CloudTrail discovery evidence is malformed")
    _validate_cloudtrail_completion(outcome=discovery, payload=discovery_payload)
    if discovery.state is EvidenceSourceState.PRESENT and discarded_item_count != 0:
        raise ValueError("successful CloudTrail discovery cannot discard malformed items")
    parsed_arns = {arn: _parse_cloudtrail_trail_arn(arn) for arn in trail_arns}
    unadmitted_arns: set[str] = set()
    canonical_unadmitted: list[dict[str, object]] = []
    for item in unadmitted_resources:
        if not isinstance(item, Mapping) or set(item) != {
            "account_id",
            "service",
            "resource_type",
            "scope",
            "region",
            "resource_id",
        }:
            raise ValueError("CloudTrail unadmitted-resource evidence is malformed")
        arn = item["resource_id"]
        if not isinstance(arn, str) or arn not in parsed_arns:
            raise ValueError("CloudTrail unadmitted resource was not discovered")
        _, region, owner, _ = parsed_arns[arn]
        expected_item = {
            "account_id": owner,
            "service": "cloudtrail",
            "resource_type": "cloudtrail_trail",
            "scope": ResourceScope.REGIONAL.value,
            "region": region,
            "resource_id": arn,
        }
        if dict(item) != expected_item or owner == discovery.collection_account_id:
            raise ValueError("CloudTrail unadmitted resource identity is invalid")
        if arn in unadmitted_arns:
            raise ValueError("CloudTrail unadmitted resource is duplicated")
        unadmitted_arns.add(arn)
        canonical_unadmitted.append(expected_item)
    if canonical_unadmitted != sorted(
        canonical_unadmitted,
        key=lambda item: (
            str(item["account_id"]),
            str(item["service"]),
            str(item["resource_type"]),
            str(item["scope"]),
            str(item["region"]),
            str(item["resource_id"]),
        ),
    ) or discovery_payload["admission_complete"] is bool(unadmitted_arns):
        raise ValueError("CloudTrail admission metadata is inconsistent")

    admitted_arns = tuple(arn for arn in trail_arns if arn not in unadmitted_arns)
    sources_by_arn: dict[str, dict[str, tuple[SourceEvidenceOutcome, object]]] = {}
    for outcome in selected:
        if outcome is discovery:
            continue
        contract = contract_by_id.get(outcome.source_outcome_id)
        if contract is None:
            raise ValueError("CloudTrail outcome has no declared source contract")
        _validate_cloudtrail_source_identity(
            outcome=outcome,
            contract=contract,
            collection_account_id=discovery.collection_account_id,
        )
        subject = outcome.subject
        if not isinstance(subject, ResourceEvidenceSubject):
            raise ValueError("CloudTrail enrichment requires a resource subject")
        trail_arn = subject.aws_resource_id
        if trail_arn not in admitted_arns:
            raise ValueError("CloudTrail source is not admitted by discovery")
        _, region, owner, _ = parsed_arns[trail_arn]
        if (
            subject.aws_account_id != owner
            or subject.service != "cloudtrail"
            or subject.resource_type != "cloudtrail_trail"
            or subject.scope is not ResourceScope.REGIONAL
            or subject.region != region
        ):
            raise ValueError("CloudTrail source subject contradicts its trail ARN")
        payload = _cloudtrail_payload(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
        )
        trail_sources = sources_by_arn.setdefault(trail_arn, {})
        if outcome.evidence_kind in trail_sources:
            raise ValueError("CloudTrail per-trail source is duplicated")
        trail_sources[outcome.evidence_kind] = (outcome, payload)

    if set(sources_by_arn) != set(admitted_arns):
        raise ValueError("CloudTrail per-trail source manifest is incomplete")
    for trail_arn in admitted_arns:
        sources = sources_by_arn[trail_arn]
        if set(sources) != _CLOUDTRAIL_RESOURCE_KINDS:
            raise ValueError("CloudTrail per-trail source manifest is incomplete or unknown")
        identity_outcome, identity_payload = sources["cloudtrail.trail.identity"]
        if identity_outcome.state is not EvidenceSourceState.PRESENT:
            raise ValueError("CloudTrail admitted trails require PRESENT authoritative identity")
        partition, region, owner, arn_name = parsed_arns[trail_arn]
        if (
            not isinstance(identity_payload, Mapping)
            or set(identity_payload)
            != {
                "collection_account_id",
                "owner_account_id",
                "partition",
                "trail_arn",
                "name",
                "home_region",
                "complete",
                "failure_category",
            }
            or identity_payload.get("collection_account_id") != discovery.collection_account_id
            or identity_payload.get("owner_account_id") != owner
            or identity_payload.get("partition") != partition
            or identity_payload.get("trail_arn") != trail_arn
            or identity_payload.get("name") != arn_name
            or identity_payload.get("home_region") != region
        ):
            raise ValueError("CloudTrail identity evidence is malformed")
        _validate_cloudtrail_completion(outcome=identity_outcome, payload=identity_payload)
        for evidence_kind in _CLOUDTRAIL_NON_AUTHORITATIVE_EXTERNAL_KINDS:
            source_outcome, payload = sources[evidence_kind]
            _validate_cloudtrail_enrichment_payload(
                evidence_kind=evidence_kind,
                outcome=source_outcome,
                payload=payload,
                trail_arn=trail_arn,
                home_region=region,
            )
        if owner != discovery.collection_account_id:
            configuration_outcome, configuration_payload = sources["cloudtrail.trail.configuration"]
            if configuration_outcome.state is EvidenceSourceState.PRESENT:
                configuration = (
                    configuration_payload.get("value")
                    if isinstance(configuration_payload, Mapping)
                    else None
                )
                if (
                    not isinstance(configuration, Mapping)
                    or configuration.get("is_organization_trail") is not True
                ):
                    raise ValueError(
                        "CloudTrail external-owner configuration requires organization context"
                    )
            for evidence_kind in _CLOUDTRAIL_NON_AUTHORITATIVE_EXTERNAL_KINDS:
                contract = contract_by_id[sources[evidence_kind][0].source_outcome_id]
                if contract.identity_authoritative:
                    raise ValueError(
                        "CloudTrail external enrichment must rely on paired identity evidence"
                    )

    return _CloudTrailManifest(
        discovery=discovery,
        invocation_region=str(discovery_payload["invocation_region"]),
        admitted_arns=admitted_arns,
        sources_by_arn=sources_by_arn,
        admission_incomplete=bool(unadmitted_arns),
    )


def _validate_cloudtrail_source_identity(
    *,
    outcome: SourceEvidenceOutcome,
    contract: ScanSourceContract,
    collection_account_id: str,
) -> None:
    expected = _CLOUDTRAIL_SOURCE_IDENTITIES.get(outcome.evidence_kind)
    if expected is None:
        raise ValueError("CloudTrail source identity is unknown")
    collector, source_api, phase, cardinality, identity_authoritative = expected
    allowed_states = _CLOUDTRAIL_ALLOWED_STATES
    if outcome.evidence_kind == "cloudtrail.trails.discovery":
        allowed_states = allowed_states - {EvidenceSourceState.RESOURCE_DISAPPEARED}
    if (
        contract.contract_key != outcome.evidence_kind
        or contract.contract_version != "1.0.0"
        or contract.evidence_kind != outcome.evidence_kind
        or contract.collector != collector
        or contract.collector_version != "1.0.0"
        or contract.source_api != source_api
        or contract.phase is not phase
        or contract.cardinality is not cardinality
        or contract.identity_authoritative is not identity_authoritative
        or contract.allows_supplemental_region
        or outcome.collector != collector
        or outcome.collector_version != "1.0.0"
        or outcome.source_api != source_api
        or outcome.phase is not phase
        or outcome.collection_account_id != collection_account_id
        or outcome.state not in allowed_states
    ):
        raise ValueError("CloudTrail source identity is invalid")


def _cloudtrail_payload(
    *,
    outcome: SourceEvidenceOutcome,
    artifacts_by_reference: Mapping[str, SourceEvidenceArtifact],
) -> dict[str, object]:
    artifact = artifacts_by_reference.get(outcome.evidence_reference)
    if (
        artifact is None
        or artifact.evidence_schema != outcome.evidence_kind
        or artifact.evidence_schema_version != "1.0.0"
        or artifact.scan_id != outcome.scan_id
        or artifact.collection_account_id != outcome.collection_account_id
        or artifact.collected_at != outcome.collected_at
        or artifact.evidence_sha256 != outcome.evidence_sha256
    ):
        raise ValueError("CloudTrail source artifact does not match its outcome")
    payload = artifact.model_dump(mode="json")["normalized_payload"]
    if not isinstance(payload, dict):  # pragma: no cover - artifact root invariant
        raise ValueError("CloudTrail source artifact payload is malformed")
    return payload


def _validate_cloudtrail_completion(
    *, outcome: SourceEvidenceOutcome, payload: Mapping[str, object]
) -> None:
    expected_complete = outcome.state is EvidenceSourceState.PRESENT
    expected_failure = (
        outcome.failure_category.value if outcome.failure_category is not None else None
    )
    if (
        payload.get("complete") is not expected_complete
        or payload.get("failure_category") != expected_failure
    ):
        raise ValueError("CloudTrail source completion metadata is inconsistent")


def _validate_cloudtrail_enrichment_payload(
    *,
    evidence_kind: str,
    outcome: SourceEvidenceOutcome,
    payload: object,
    trail_arn: str,
    home_region: str,
) -> None:
    if (
        not isinstance(payload, Mapping)
        or set(payload) != {"trail_arn", "home_region", "value", "complete", "failure_category"}
        or payload.get("trail_arn") != trail_arn
        or payload.get("home_region") != home_region
    ):
        raise ValueError("CloudTrail enrichment evidence is malformed")
    _validate_cloudtrail_completion(outcome=outcome, payload=payload)
    value = payload["value"]
    if outcome.state is not EvidenceSourceState.PRESENT:
        if value is not None:
            raise ValueError("incomplete CloudTrail evidence must not retain a value")
        return
    if value is None:
        raise ValueError("PRESENT CloudTrail evidence requires a value")
    validators = {
        "cloudtrail.trail.configuration": _validate_cloudtrail_configuration_value,
        "cloudtrail.trail.status": _validate_cloudtrail_status_value,
        "cloudtrail.trail.event-selectors": _validate_cloudtrail_selector_value,
        "cloudtrail.trail.tags": _validate_cloudtrail_tags_value,
    }
    normalized = validators[evidence_kind](value)
    if evidence_kind == "cloudtrail.trail.configuration":
        _, _, _, trail_name = _parse_cloudtrail_trail_arn(trail_arn)
        if normalized["name"] != trail_name:
            raise ValueError("CloudTrail configuration name contradicts its trail identity")
        log_group = normalized["cloudwatch_logs_log_group_arn"]
        log_role = normalized["cloudwatch_logs_role_arn"]
        if (
            (log_group is None) != (log_role is None)
            or (log_group is not None and not _is_safe_non_empty_string(log_group))
            or (log_role is not None and not _is_safe_non_empty_string(log_role))
        ):
            raise ValueError("CloudTrail CloudWatch delivery evidence is inconsistent")
        kms_key_id = normalized["kms_key_id"]
        if kms_key_id is not None:
            trail_partition, _, _, _ = _parse_cloudtrail_trail_arn(trail_arn)
            key_partition, _, _, _ = _parse_kms_key_arn(kms_key_id)
            if key_partition != trail_partition:
                raise ValueError("CloudTrail KMS key identity contradicts its trail identity")


def _validate_cloudtrail_configuration_value(value: object) -> dict[str, object]:
    keys = {
        "name",
        "s3_bucket_name",
        "s3_key_prefix",
        "include_global_service_events",
        "is_multi_region_trail",
        "log_file_validation_enabled",
        "cloudwatch_logs_log_group_arn",
        "cloudwatch_logs_role_arn",
        "kms_key_id",
        "is_organization_trail",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError("CloudTrail configuration evidence is malformed")
    if value["name"] is not None and not _is_safe_non_empty_string(value["name"]):
        raise ValueError("CloudTrail configuration evidence is malformed")
    for field in {
        "s3_bucket_name",
        "s3_key_prefix",
        "cloudwatch_logs_log_group_arn",
        "cloudwatch_logs_role_arn",
        "kms_key_id",
    }:
        if value[field] is not None and not isinstance(value[field], str):
            raise ValueError("CloudTrail configuration evidence is malformed")
    for field in {
        "include_global_service_events",
        "is_multi_region_trail",
        "log_file_validation_enabled",
        "is_organization_trail",
    }:
        if value[field] is not None and not isinstance(value[field], bool):
            raise ValueError("CloudTrail configuration evidence is malformed")
    if value["s3_bucket_name"] is not None and not _is_safe_non_empty_string(
        value["s3_bucket_name"]
    ):
        raise ValueError("CloudTrail destination bucket must be non-empty")
    if value["kms_key_id"] is not None:
        _parse_kms_key_arn(value["kms_key_id"])
    return dict(value)


def _validate_cloudtrail_status_value(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"is_logging", "status"}
        or not isinstance(value["is_logging"], bool)
        or not isinstance(value["status"], Mapping)
        or "ResponseMetadata" in value["status"]
        or value["status"].get("IsLogging") is not value["is_logging"]
    ):
        raise ValueError("CloudTrail status evidence is malformed")
    return {"is_logging": value["is_logging"], "status": dict(value["status"])}


def _validate_cloudtrail_selector_value(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"selector_form", "basic_selectors", "advanced_selectors"}
        or value["selector_form"] not in {"BASIC", "ADVANCED"}
        or not isinstance(value["basic_selectors"], list)
        or not isinstance(value["advanced_selectors"], list)
    ):
        raise ValueError("CloudTrail event-selector evidence is malformed")
    basic = value["basic_selectors"]
    advanced = value["advanced_selectors"]
    if (value["selector_form"] == "BASIC") != bool(basic) or bool(basic) == bool(advanced):
        raise ValueError("CloudTrail event-selector form is inconsistent")
    normalized_basic = [_validate_cloudtrail_basic_selector(item) for item in basic]
    normalized_advanced = [_validate_cloudtrail_advanced_selector(item) for item in advanced]
    for values in (normalized_basic, normalized_advanced):
        documents = [_canonical_json(item) for item in values]
        if documents != sorted(set(documents)):
            raise ValueError("CloudTrail event selectors are not canonical")
    return dict(value)


def _validate_cloudtrail_basic_selector(value: object) -> dict[str, object]:
    fields = {
        "raw_presence",
        "include_management_events",
        "read_write_type",
        "exclude_management_event_sources",
        "data_resources",
    }
    presence_fields = {
        "include_management_events",
        "read_write_type",
        "exclude_management_event_sources",
        "data_resources",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("CloudTrail basic selector is malformed")
    raw_presence = value["raw_presence"]
    exclusions = value["exclude_management_event_sources"]
    data_resources = value["data_resources"]
    if (
        not isinstance(raw_presence, Mapping)
        or set(raw_presence) != presence_fields
        or not all(isinstance(item, bool) for item in raw_presence.values())
        or not isinstance(value["include_management_events"], bool)
        or value["read_write_type"] not in _CLOUDTRAIL_BASIC_READ_WRITE_TYPES
        or not isinstance(exclusions, list)
        or exclusions != sorted(set(exclusions))
        or not all(item in _CLOUDTRAIL_MANAGEMENT_EVENT_EXCLUSIONS for item in exclusions)
        or not isinstance(data_resources, list)
    ):
        raise ValueError("CloudTrail basic selector is malformed")
    defaults = {
        "include_management_events": True,
        "read_write_type": "All",
        "exclude_management_event_sources": [],
        "data_resources": [],
    }
    if any(
        not raw_presence[field] and value[field] != default for field, default in defaults.items()
    ):
        raise ValueError("CloudTrail basic selector default provenance is inconsistent")
    normalized_data = []
    for item in data_resources:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"type", "values"}
            or not _is_safe_non_empty_string(item["type"])
            or not isinstance(item["values"], list)
            or not item["values"]
            or item["values"] != sorted(set(item["values"]))
            or not all(_is_safe_non_empty_string(entry) for entry in item["values"])
        ):
            raise ValueError("CloudTrail data-resource selector is malformed")
        normalized_data.append(dict(item))
    documents = [_canonical_json(item) for item in normalized_data]
    if documents != sorted(set(documents)):
        raise ValueError("CloudTrail data-resource selectors are not canonical")
    return dict(value)


def _validate_cloudtrail_advanced_selector(value: object) -> dict[str, object]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"name", "field_selectors"}
        or (value["name"] is not None and not _is_safe_non_empty_string(value["name"]))
        or not isinstance(value["field_selectors"], list)
        or not value["field_selectors"]
    ):
        raise ValueError("CloudTrail advanced selector is malformed")
    normalized_fields = []
    for item in value["field_selectors"]:
        expected = {"field", *_CLOUDTRAIL_ADVANCED_OPERATOR_FIELDS}
        if (
            not isinstance(item, Mapping)
            or set(item) != expected
            or not _is_safe_non_empty_string(item["field"])
        ):
            raise ValueError("CloudTrail advanced field selector is malformed")
        has_value = False
        for operator in _CLOUDTRAIL_ADVANCED_OPERATOR_FIELDS:
            entries = item[operator]
            if (
                not isinstance(entries, list)
                or entries != sorted(set(entries))
                or not all(_is_safe_non_empty_string(entry) for entry in entries)
            ):
                raise ValueError("CloudTrail advanced field selector is malformed")
            has_value |= bool(entries)
        if not has_value:
            raise ValueError("CloudTrail advanced field selector requires an operator value")
        normalized_fields.append(dict(item))
    documents = [_canonical_json(item) for item in normalized_fields]
    if documents != sorted(set(documents)):
        raise ValueError("CloudTrail advanced field selectors are not canonical")
    return dict(value)


def _validate_cloudtrail_tags_value(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        raise ValueError("CloudTrail tag evidence must be a list")
    tags: dict[str, str] = {}
    entries: list[dict[str, str]] = []
    for item in value:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"key", "value"}
            or not _is_safe_non_empty_string(item["key"])
            or not isinstance(item["value"], str)
            or item["key"] in tags
        ):
            raise ValueError("CloudTrail tag evidence is malformed")
        tags[item["key"]] = item["value"]
        entries.append(dict(item))
    if entries != sorted(entries, key=lambda item: item["key"]):
        raise ValueError("CloudTrail tag evidence is not canonical")
    return tags


def _parse_cloudtrail_trail_arn(value: str) -> tuple[str, str, str, str]:
    if not isinstance(value, str):
        raise ValueError("CloudTrail trail ARN is malformed")
    parts = value.split(":", 5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or not re.fullmatch(r"aws(?:-[a-z0-9]+)*", parts[1])
        or parts[2] != "cloudtrail"
        or not _valid_normalized_region(parts[3])
        or not re.fullmatch(r"[0-9]{12}", parts[4])
        or not parts[5].startswith("trail/")
        or not _CLOUDTRAIL_NAME_PATTERN.fullmatch(parts[5].removeprefix("trail/"))
        or _IP_SHAPED_NAME_PATTERN.fullmatch(parts[5].removeprefix("trail/")) is not None
    ):
        raise ValueError("CloudTrail trail ARN is malformed")
    return parts[1], parts[3], parts[4], parts[5].removeprefix("trail/")


def _parse_kms_key_arn(value: object) -> tuple[str, str, str, str]:
    if not isinstance(value, str):
        raise ValueError("CloudTrail KMS key reference must be a full key ARN")
    parts = value.split(":", 5)
    resource = parts[5] if len(parts) == 6 else ""
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or not re.fullmatch(r"aws(?:-[a-z0-9]+)*", parts[1])
        or parts[2] != "kms"
        or not _valid_normalized_region(parts[3])
        or not re.fullmatch(r"[0-9]{12}", parts[4])
        or not resource.startswith("key/")
        or not _is_safe_non_empty_string(resource.removeprefix("key/"))
    ):
        raise ValueError("CloudTrail KMS key reference must be a full key ARN")
    return parts[1], parts[3], parts[4], resource.removeprefix("key/")


def reconstruct_s3_bucket_region_evidence(
    *,
    outcomes: Iterable[SourceEvidenceOutcome],
    artifacts: Iterable[SourceEvidenceArtifact],
    contracts: Iterable[ScanSourceContract] = (),
) -> S3BucketRegionEvidence | None:
    """Reconstruct exact 5E ListBuckets/location coverage without using its outer rollup.

    ``None`` identifies accepted pre-5E graphs, which have no direct S3 source family. A
    represented manifest is complete only when ListBuckets is present and every discovered name
    has exactly one successful, identity-authoritative GetBucketLocation observation.
    """

    all_outcomes = tuple(outcomes)
    bucket_sources = tuple(item for item in all_outcomes if item.collector == "s3.buckets")
    location_sources = tuple(
        item for item in all_outcomes if item.collector == "s3.bucket-location"
    )
    if not bucket_sources and not location_sources:
        return None
    if len(bucket_sources) != 1:
        raise ValueError("S3 evidence requires exactly one ListBuckets source")

    artifacts_by_reference = _artifacts_by_reference(artifacts)
    contracts_by_outcome = {item.source_outcome_id: item for item in contracts}
    discovery = bucket_sources[0]
    if (
        discovery.phase is not EvidenceCollectionPhase.DISCOVERY
        or not isinstance(discovery.subject, AccountEvidenceSubject)
        or discovery.subject.aws_account_id != discovery.collection_account_id
        or discovery.subject.scope is not ResourceScope.GLOBAL
        or discovery.state is EvidenceSourceState.EXPECTED_ABSENCE
        or discovery.evidence_kind != "s3.buckets.discovery"
        or discovery.collector_version != "1.0.0"
        or discovery.source_api != "s3:ListAllMyBuckets"
    ):
        raise ValueError("S3 ListBuckets source identity is invalid")
    discovery_artifact = _matching_s3_artifact(
        outcome=discovery,
        artifacts_by_reference=artifacts_by_reference,
        expected_schema="s3.buckets.discovery",
    )
    discovery_payload = discovery_artifact.model_dump(mode="json")["normalized_payload"]
    if not isinstance(discovery_payload, dict):  # pragma: no cover - artifact invariant
        raise ValueError("S3 ListBuckets manifest is malformed")
    bucket_names = discovery_payload.get("bucket_names")
    buckets = discovery_payload.get("buckets")
    if (
        set(discovery_payload)
        != {
            "account_id",
            "buckets",
            "bucket_names",
            "resource_count",
            "discarded_item_count",
            "complete",
            "failure_category",
        }
        or discovery_payload.get("account_id") != discovery.collection_account_id
        or not isinstance(bucket_names, list)
        or not all(isinstance(item, str) and item for item in bucket_names)
        or bucket_names != sorted(set(bucket_names))
        or not isinstance(buckets, list)
        or len(buckets) != len(bucket_names)
        or not isinstance(discovery_payload.get("resource_count"), int)
        or isinstance(discovery_payload.get("resource_count"), bool)
        or discovery_payload.get("resource_count") != len(bucket_names)
        or not isinstance(discovery_payload.get("discarded_item_count"), int)
        or isinstance(discovery_payload.get("discarded_item_count"), bool)
        or discovery_payload["discarded_item_count"] < 0
        or (
            discovery.state is EvidenceSourceState.PRESENT
            and discovery_payload["discarded_item_count"] != 0
        )
    ):
        raise ValueError("S3 ListBuckets manifest is malformed")
    listed_names: list[str] = []
    bucket_metadata: dict[str, tuple[str, str | None]] = {}
    for bucket in buckets:
        if not isinstance(bucket, dict) or set(bucket) != {
            "bucket_name",
            "bucket_arn",
            "creation_date",
            "list_bucket_region",
        }:
            raise ValueError("S3 ListBuckets manifest is malformed")
        bucket_name = bucket.get("bucket_name")
        bucket_arn = bucket.get("bucket_arn")
        list_bucket_region = bucket.get("list_bucket_region")
        arn_parts = bucket_arn.split(":", maxsplit=5) if isinstance(bucket_arn, str) else []
        if (
            not isinstance(bucket_name, str)
            or not bucket_name
            or any(separator in bucket_name for separator in ("\x00", "\x1f", "\r", "\n"))
            or len(arn_parts) != 6
            or arn_parts[0] != "arn"
            or not arn_parts[1]
            or any(
                not (
                    character.isascii()
                    and (character.islower() or character.isdigit() or character == "-")
                )
                for character in arn_parts[1]
            )
            or arn_parts[2:] != ["s3", "", "", bucket_name]
            or (list_bucket_region is not None and not _valid_normalized_region(list_bucket_region))
            or not _is_canonical_utc_datetime_or_none(bucket.get("creation_date"))
        ):
            raise ValueError("S3 ListBuckets manifest is malformed")
        listed_names.append(bucket_name)
        bucket_metadata[bucket_name] = (bucket_arn, list_bucket_region)
    if sorted(listed_names) != bucket_names or len(listed_names) != len(set(listed_names)):
        raise ValueError("S3 ListBuckets manifest is ambiguous")
    _validate_s3_completion_metadata(discovery, discovery_payload)

    locations: dict[str, str] = {}
    observed_names: list[str] = []
    for outcome in location_sources:
        artifact = _matching_s3_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema="s3.bucket-location",
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict) or set(payload) != {
            "account_id",
            "bucket_name",
            "bucket_arn",
            "list_bucket_region",
            "legacy_bucket_region",
            "location_constraint",
            "bucket_region",
            "resource_not_found",
            "complete",
            "failure_category",
        }:
            raise ValueError("S3 bucket-location evidence is malformed")
        bucket_name = payload.get("bucket_name")
        if (
            payload.get("account_id") != outcome.collection_account_id
            or not isinstance(bucket_name, str)
            or not bucket_name
            or bucket_name not in bucket_metadata
            or (payload.get("bucket_arn"), payload.get("list_bucket_region"))
            != bucket_metadata[bucket_name]
        ):
            raise ValueError("S3 bucket-location evidence is malformed")
        observed_names.append(bucket_name)
        _validate_s3_completion_metadata(outcome, payload)
        legacy_bucket_region = payload.get("legacy_bucket_region")
        resource_not_found = payload["resource_not_found"]
        if (
            legacy_bucket_region is not None and not _valid_normalized_region(legacy_bucket_region)
        ) or (
            payload.get("list_bucket_region") is not None
            and legacy_bucket_region != payload.get("list_bucket_region")
        ):
            raise ValueError("S3 bucket-location legacy identity is invalid")
        if not isinstance(resource_not_found, bool) or (
            resource_not_found
            and outcome.state
            not in {EvidenceSourceState.RESOURCE_DISAPPEARED, EvidenceSourceState.CONFLICT}
        ):
            raise ValueError("S3 bucket-location disappearance metadata is invalid")

        if outcome.state is EvidenceSourceState.PRESENT:
            if (
                outcome.phase is not EvidenceCollectionPhase.ENRICHMENT
                or not isinstance(outcome.subject, ResourceEvidenceSubject)
                or outcome.evidence_kind != "s3.bucket-location"
                or outcome.collector_version != "1.0.0"
                or outcome.source_api != "s3:GetBucketLocation"
                or outcome.subject.aws_account_id != outcome.collection_account_id
                or outcome.subject.service != "s3"
                or outcome.subject.resource_type != "s3_bucket"
                or outcome.subject.aws_resource_id != bucket_name
                or outcome.subject.scope is not ResourceScope.REGIONAL
                or not _valid_normalized_region(outcome.subject.region)
                or payload.get("bucket_region") != outcome.subject.region
                or (
                    legacy_bucket_region is not None
                    and legacy_bucket_region != outcome.subject.region
                )
                or not _location_constraint_matches_region(
                    payload.get("location_constraint"),
                    outcome.subject.region,
                )
                or (
                    payload.get("list_bucket_region") is not None
                    and payload.get("list_bucket_region") != outcome.subject.region
                )
            ):
                raise ValueError("successful S3 bucket-location identity is invalid")
            contract = contracts_by_outcome.get(outcome.source_outcome_id)
            if contracts_by_outcome and (
                contract is None
                or not contract.identity_authoritative
                or contract.subject != outcome.subject
            ):
                raise ValueError(
                    "successful S3 bucket-location evidence is not identity-authoritative"
                )
            locations[bucket_name] = outcome.subject.region
            continue

        if outcome.state is EvidenceSourceState.RESOURCE_DISAPPEARED:
            if (
                not resource_not_found
                or outcome.phase is not EvidenceCollectionPhase.ENRICHMENT
                or not isinstance(outcome.subject, ResourceEvidenceSubject)
                or outcome.subject.aws_account_id != outcome.collection_account_id
                or outcome.subject.service != "s3"
                or outcome.subject.resource_type != "s3_bucket"
                or outcome.subject.aws_resource_id != bucket_name
                or outcome.subject.scope is not ResourceScope.REGIONAL
                or outcome.subject.region != legacy_bucket_region
                or outcome.evidence_kind != "s3.bucket-location"
                or outcome.collector_version != "1.0.0"
                or outcome.source_api != "s3:GetBucketLocation"
                or payload.get("location_constraint") is not None
                or payload.get("bucket_region") is not None
            ):
                raise ValueError("disappeared S3 bucket-location identity is invalid")
            contract = contracts_by_outcome.get(outcome.source_outcome_id)
            if contracts_by_outcome and (
                contract is None
                or contract.identity_authoritative
                or contract.subject != outcome.subject
            ):
                raise ValueError(
                    "disappeared S3 bucket-location evidence must remain non-authoritative"
                )
            continue

        expected_kind = (
            "s3.bucket-location." + hashlib.sha256(bucket_name.encode("utf-8")).hexdigest()
        )
        if (
            outcome.state is EvidenceSourceState.EXPECTED_ABSENCE
            or outcome.phase is not EvidenceCollectionPhase.DISCOVERY
            or not isinstance(outcome.subject, AccountEvidenceSubject)
            or outcome.subject.aws_account_id != outcome.collection_account_id
            or outcome.subject.scope is not ResourceScope.GLOBAL
            or outcome.evidence_kind != expected_kind
            or outcome.collector_version != "1.0.0"
            or outcome.source_api != "s3:GetBucketLocation"
            or not _valid_failed_location_constraint(
                payload.get("location_constraint"), outcome.state
            )
            or payload.get("bucket_region") is not None
        ):
            raise ValueError("failed S3 bucket-location identity is invalid")

    if sorted(observed_names) != bucket_names or len(observed_names) != len(set(observed_names)):
        raise ValueError("S3 bucket-location manifest is incomplete or unknown")
    discovery_complete = discovery.state is EvidenceSourceState.PRESENT
    location_complete = len(locations) == len(bucket_names)
    return S3BucketRegionEvidence(
        complete=discovery_complete and location_complete,
        bucket_regions=tuple(sorted(locations.items())),
    )


def _artifacts_by_reference(
    artifacts: Iterable[SourceEvidenceArtifact],
) -> dict[str, SourceEvidenceArtifact]:
    indexed: dict[str, SourceEvidenceArtifact] = {}
    for artifact in artifacts:
        if artifact.evidence_reference in indexed:
            raise ValueError("evidence references must be unique")
        indexed[artifact.evidence_reference] = artifact
    return indexed


def _matching_s3_artifact(
    *,
    outcome: SourceEvidenceOutcome,
    artifacts_by_reference: Mapping[str, SourceEvidenceArtifact],
    expected_schema: str,
) -> SourceEvidenceArtifact:
    artifact = artifacts_by_reference.get(outcome.evidence_reference)
    if artifact is None:
        raise ValueError("S3 source outcome has no bound artifact")
    if (
        artifact.evidence_schema != expected_schema
        or artifact.evidence_schema_version != "1.0.0"
        or artifact.scan_id != outcome.scan_id
        or artifact.collection_account_id != outcome.collection_account_id
        or artifact.collected_at != outcome.collected_at
        or artifact.evidence_sha256 != outcome.evidence_sha256
    ):
        raise ValueError("S3 source artifact does not match its outcome")
    return artifact


def validate_s3_account_public_access_block_artifact(
    *,
    outcome: SourceEvidenceOutcome,
    artifact: SourceEvidenceArtifact,
) -> dict[str, bool] | None:
    """Validate the exact normalized account-level S3 Public Access Block artifact."""

    payload = artifact.model_dump(mode="json")["normalized_payload"]
    if not isinstance(payload, dict) or set(payload) != {
        "account_id",
        "configured",
        "public_access_block",
        "complete",
        "expected_absence",
        "failure_category",
    }:
        raise ValueError("S3 account Public Access Block artifact is malformed")
    _validate_s3_completion_metadata(outcome, payload)
    expected_absence = outcome.state is EvidenceSourceState.EXPECTED_ABSENCE
    try:
        block = validate_s3_bucket_evidence_value(
            evidence_kind="s3.bucket-public-access-block",
            state=outcome.state,
            value=payload["public_access_block"],
        )
    except ValueError as error:
        raise ValueError("S3 account Public Access Block artifact is malformed") from error
    if (
        payload["account_id"] != outcome.collection_account_id
        or payload["configured"] is not (outcome.state is EvidenceSourceState.PRESENT)
        or payload["expected_absence"] is not expected_absence
    ):
        raise ValueError("S3 account Public Access Block artifact is inconsistent")
    if block is not None and not isinstance(block, dict):  # pragma: no cover - validator invariant
        raise TypeError("S3 account Public Access Block projection must be a mapping")
    return block


def validate_s3_per_bucket_source_artifact(
    *,
    outcome: SourceEvidenceOutcome,
    artifact: SourceEvidenceArtifact,
    bucket_regions: Mapping[str, str],
) -> tuple[object, object]:
    """Validate one exact per-bucket artifact against its source subject and discovery proof."""

    subject = outcome.subject
    if not isinstance(subject, ResourceEvidenceSubject):
        raise ValueError("S3 per-bucket artifact requires a resource subject")
    payload = artifact.model_dump(mode="json")["normalized_payload"]
    if not isinstance(payload, dict) or set(payload) != {
        "account_id",
        "bucket_name",
        "bucket_arn",
        "bucket_region",
        "value",
        "legacy_projection",
        "complete",
        "expected_absence",
        "failure_category",
    }:
        raise ValueError("S3 per-bucket artifact is malformed")
    bucket_arn = payload["bucket_arn"]
    arn_parts = bucket_arn.split(":", maxsplit=5) if isinstance(bucket_arn, str) else []
    if (
        payload["account_id"] != subject.aws_account_id
        or payload["bucket_name"] != subject.aws_resource_id
        or payload["bucket_region"] != subject.region
        or bucket_regions.get(subject.aws_resource_id) != subject.region
        or len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or not arn_parts[1]
        or any(
            not (
                character.isascii()
                and (character.islower() or character.isdigit() or character == "-")
            )
            for character in arn_parts[1]
        )
        or arn_parts[2:] != ["s3", "", "", subject.aws_resource_id]
    ):
        raise ValueError("S3 per-bucket artifact identity is inconsistent")
    _validate_s3_completion_metadata(outcome, payload)
    if payload["expected_absence"] is not (outcome.state is EvidenceSourceState.EXPECTED_ABSENCE):
        raise ValueError("S3 per-bucket artifact absence state is inconsistent")
    try:
        projected_value = validate_s3_bucket_evidence_value(
            evidence_kind=outcome.evidence_kind,
            state=outcome.state,
            value=payload["value"],
        )
    except ValueError as error:
        raise ValueError("S3 per-bucket artifact value is malformed") from error
    legacy_projection = payload["legacy_projection"]
    legacy_families = {
        "s3.bucket-encryption",
        "s3.bucket-public-access-block",
    }
    if outcome.evidence_kind not in legacy_families:
        if legacy_projection is not None:
            raise ValueError("S3 per-bucket artifact has an unknown legacy projection")
    elif outcome.state is EvidenceSourceState.EXPECTED_ABSENCE:
        if legacy_projection is not None:
            raise ValueError("S3 expected absence cannot retain a legacy projection")
    elif outcome.state is EvidenceSourceState.PRESENT:
        if outcome.evidence_kind == "s3.bucket-encryption":
            try:
                normalized_legacy = normalize_s3_legacy_encryption_value(legacy_projection)
            except ValueError as error:
                raise ValueError("S3 legacy encryption projection is malformed") from error
            if normalized_legacy != projected_value:
                raise ValueError("S3 encryption projections are inconsistent")
        elif not isinstance(legacy_projection, dict) or any(
            legacy_projection.get(field) != projected_value[field]
            for field in _S3_PUBLIC_ACCESS_BLOCK_FIELDS
        ):
            raise ValueError("S3 Public Access Block projections are inconsistent")
    elif outcome.state is not EvidenceSourceState.MALFORMED and legacy_projection is not None:
        raise ValueError("failed S3 evidence cannot retain a legacy projection")
    if (
        outcome.evidence_kind == "s3.bucket-encryption"
        and outcome.state is EvidenceSourceState.MALFORMED
        and payload["value"] is not None
        and not s3_encryption_has_invalid_kms_reference(
            payload["value"],
            bucket_region=subject.region,
            partition=arn_parts[1],
        )
    ):
        raise ValueError("retained malformed S3 encryption has no invalid KMS reference")
    return projected_value, legacy_projection


def _validate_complete_s3_source_artifacts(
    *,
    outcomes: tuple[SourceEvidenceOutcome, ...],
    contracts: tuple[ScanSourceContract, ...],
    artifacts: tuple[SourceEvidenceArtifact, ...],
) -> None:
    """Validate the complete 5E S3 source family during graph construction and replay."""

    account_outcomes = tuple(
        outcome for outcome in outcomes if outcome.collector == "s3.account-public-access-block"
    )
    if len(account_outcomes) != 1:
        raise ValueError("S3 evidence requires exactly one account Public Access Block source")
    artifacts_by_reference = _artifacts_by_reference(artifacts)
    region_evidence = reconstruct_s3_bucket_region_evidence(
        outcomes=outcomes,
        artifacts=artifacts,
        contracts=contracts,
    )
    if region_evidence is None:  # pragma: no cover - account source implies 5E discovery
        raise ValueError("S3 evidence omitted its discovery manifest")
    bucket_regions = dict(region_evidence.bucket_regions)
    account_outcome = account_outcomes[0]
    account_artifact = _matching_s3_artifact(
        outcome=account_outcome,
        artifacts_by_reference=artifacts_by_reference,
        expected_schema="s3.account-public-access-block",
    )
    account_block = validate_s3_account_public_access_block_artifact(
        outcome=account_outcome,
        artifact=account_artifact,
    )
    per_bucket_collectors = {
        "s3.bucket-acl",
        "s3.bucket-encryption",
        "s3.bucket-ownership-controls",
        "s3.bucket-policy",
        "s3.bucket-policy-status",
        "s3.bucket-public-access-block",
        "s3.bucket-tags",
        "s3.bucket-versioning",
    }
    actual: list[tuple[str, str]] = []
    sources_by_bucket: dict[
        str,
        dict[str, tuple[SourceEvidenceOutcome, object]],
    ] = {}
    for outcome in outcomes:
        if outcome.collector not in per_bucket_collectors:
            continue
        artifact = _matching_s3_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema=outcome.evidence_kind,
        )
        projected_value, _legacy_projection = validate_s3_per_bucket_source_artifact(
            outcome=outcome,
            artifact=artifact,
            bucket_regions=bucket_regions,
        )
        if not isinstance(outcome.subject, ResourceEvidenceSubject):  # pragma: no cover
            raise TypeError("S3 per-bucket source must have a resource subject")
        bucket_name = outcome.subject.aws_resource_id
        actual.append((outcome.collector, bucket_name))
        sources_by_bucket.setdefault(bucket_name, {})[outcome.collector] = (
            outcome,
            projected_value,
        )
    expected = {
        (collector, bucket_name)
        for collector in per_bucket_collectors
        for bucket_name in bucket_regions
    }
    if len(actual) != len(set(actual)) or set(actual) != expected:
        raise ValueError("S3 per-bucket artifact manifest is incomplete or unknown")
    for bucket_name in bucket_regions:
        sources = sources_by_bucket[bucket_name]
        policy_outcome, policy_value = sources["s3.bucket-policy"]
        status_outcome, status_value = sources["s3.bucket-policy-status"]
        validate_s3_policy_source_coherence(
            policy_outcome=policy_outcome,
            policy_value=policy_value,
            status_outcome=status_outcome,
            status_value=status_value,
        )
        acl_outcome, acl_value = sources["s3.bucket-acl"]
        bucket_block_outcome, bucket_block = sources["s3.bucket-public-access-block"]
        ownership_outcome, ownership_value = sources["s3.bucket-ownership-controls"]
        if acl_value is not None:
            validate_s3_acl_source_coherence(
                acl_outcome=acl_outcome,
                acl_value=acl_value,
                account_public_access_block_outcome=account_outcome,
                account_public_access_block_value=account_block,
                bucket_public_access_block_outcome=bucket_block_outcome,
                bucket_public_access_block_value=bucket_block,
                ownership_controls_outcome=ownership_outcome,
                ownership_controls_value=ownership_value,
            )


def _validate_s3_completion_metadata(
    outcome: SourceEvidenceOutcome,
    payload: Mapping[str, object],
) -> None:
    expected_complete = outcome.state in {
        EvidenceSourceState.PRESENT,
        EvidenceSourceState.EXPECTED_ABSENCE,
    }
    expected_failure = (
        outcome.failure_category.value if outcome.failure_category is not None else None
    )
    if (
        payload.get("complete") is not expected_complete
        or payload.get("failure_category") != expected_failure
    ):
        raise ValueError("S3 source completion metadata disagrees with its outcome")


def _location_constraint_matches_region(value: object, region: str) -> bool:
    """Reapply the canonical S3 location mapping during historical validation."""

    if value is None:
        return region == "us-east-1"
    if value == "us-east-1":
        return False
    if not isinstance(value, str) or not value:
        return False
    if any(separator in value for separator in ("\x00", "\x1f", "\r", "\n")):
        return False
    if value == "EU":
        return region == "eu-west-1"
    return value == region


def _valid_failed_location_constraint(value: object, state: EvidenceSourceState) -> bool:
    """Allow a validated direct location only when another identity source conflicted."""

    if value is None:
        return True
    if state is not EvidenceSourceState.CONFLICT or not isinstance(value, str):
        return False
    if value == "EU":
        return True
    return bool(_AWS_REGION_PATTERN.fullmatch(value)) and not any(
        separator in value for separator in ("\x00", "\x1f", "\r", "\n")
    )


def _valid_normalized_region(value: object) -> bool:
    """Validate a normalized AWS Region retained only for legacy resource identity."""

    return (
        isinstance(value, str)
        and bool(_AWS_REGION_PATTERN.fullmatch(value))
        and not any(separator in value for separator in ("\x00", "\x1f", "\r", "\n"))
    )


def _is_canonical_utc_datetime_or_none(value: object) -> bool:
    """Accept only the exact UTC ISO form emitted by the live response boundary."""

    if value is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return bool(
        parsed.tzinfo is not None
        and parsed.utcoffset() is not None
        and parsed.astimezone(UTC).isoformat() == value
    )


def _validate_s3_kms_relationship_manifest(
    *,
    scan_id: UUID,
    collection_account_id: str,
    outcomes: tuple[SourceEvidenceOutcome, ...],
    artifacts: tuple[SourceEvidenceArtifact, ...],
    relationships: tuple[ResourceRelationship, ...],
    raw_relationships: tuple[ResourceRelationship, ...],
) -> None:
    """Require exact 5E S3-to-KMS topology for every explicit encryption reference."""

    if not any(
        outcome.collector == "s3.buckets" and outcome.evidence_kind == "s3.buckets.discovery"
        for outcome in outcomes
    ):
        return

    artifacts_by_reference = _artifacts_by_reference(artifacts)
    expected_kms_source_buckets: dict[str, set[str]] = {}
    bucket_subjects: dict[str, ResourceEvidenceSubject] = {}
    for encryption_outcome in outcomes:
        if encryption_outcome.collector != "s3.bucket-encryption":
            continue
        subject = encryption_outcome.subject
        if not isinstance(subject, ResourceEvidenceSubject) or subject.region is None:
            raise ValueError("S3 encryption reference source identity is invalid")
        bucket_subjects[subject.aws_resource_id] = subject
        if encryption_outcome.state is not EvidenceSourceState.PRESENT:
            continue
        encryption_artifact = _matching_s3_artifact(
            outcome=encryption_outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema="s3.bucket-encryption",
        )
        encryption_payload = encryption_artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(encryption_payload, dict):  # pragma: no cover - artifact invariant
            raise ValueError("S3 encryption relationship metadata is malformed")
        bucket_arn = encryption_payload.get("bucket_arn")
        if not isinstance(bucket_arn, str):
            raise ValueError("S3 encryption relationship metadata is malformed")
        partition = _s3_bucket_partition(
            bucket_arn=bucket_arn,
            bucket_name=subject.aws_resource_id,
        )
        for reference in s3_encryption_kms_references(encryption_payload.get("value")):
            lookup_region = _s3_kms_reference_region(
                reference=reference,
                bucket_region=subject.region,
                partition=partition,
            )
            evidence_kind = (
                "kms.key." + hashlib.sha256(f"{lookup_region}\x00{reference}".encode()).hexdigest()
            )
            expected_kms_source_buckets.setdefault(evidence_kind, set()).add(
                subject.aws_resource_id
            )

    kms_outcomes_by_kind: dict[str, list[SourceEvidenceOutcome]] = {}
    canonical_kms_subjects: dict[tuple[str, str], dict[UUID, ResourceEvidenceSubject]] = {}
    canonical_kms_values: dict[tuple[str, str], dict[str, object]] = {}
    kms_values_by_outcome: dict[UUID, dict[str, object] | None] = {}
    for outcome in outcomes:
        if outcome.collector != "kms.keys":
            continue
        if outcome.state not in {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.UNAVAILABLE,
            EvidenceSourceState.MALFORMED,
            EvidenceSourceState.CONFLICT,
        }:
            raise ValueError("KMS DescribeKey outcome state is invalid")
        artifact = _matching_s3_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema="kms.key",
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict) or set(payload) != {
            "region",
            "supplied_reference",
            "source_bucket_names",
            "key",
            "complete",
            "failure_category",
        }:
            raise ValueError("KMS DescribeKey evidence metadata is malformed")
        try:
            _validate_s3_completion_metadata(outcome, payload)
        except ValueError as error:
            raise ValueError("KMS DescribeKey evidence metadata is malformed") from error
        region = payload["region"]
        supplied_reference = payload["supplied_reference"]
        source_bucket_names = payload["source_bucket_names"]
        expected_bucket_names = sorted(
            expected_kms_source_buckets.get(outcome.evidence_kind, set())
        )
        if (
            not _valid_normalized_region(region)
            or not _is_safe_non_empty_string(supplied_reference)
            or not isinstance(source_bucket_names, list)
            or source_bucket_names != expected_bucket_names
            or not source_bucket_names
            or outcome.evidence_kind
            != "kms.key." + hashlib.sha256(f"{region}\x00{supplied_reference}".encode()).hexdigest()
        ):
            raise ValueError("KMS DescribeKey evidence metadata is malformed")
        if (
            outcome.state is not EvidenceSourceState.PRESENT
            and outcome.subject != bucket_subjects.get(source_bucket_names[0])
        ):
            raise ValueError("failed KMS DescribeKey subject is not its canonical source bucket")
        try:
            key = validate_kms_key_evidence_value(
                state=outcome.state,
                value=payload["key"],
            )
        except ValueError as error:
            raise ValueError("KMS DescribeKey evidence metadata is malformed") from error
        kms_values_by_outcome[outcome.source_outcome_id] = key
        kms_outcomes_by_kind.setdefault(outcome.evidence_kind, []).append(outcome)
        if (
            outcome.state is EvidenceSourceState.PRESENT
            and isinstance(outcome.subject, ResourceEvidenceSubject)
            and outcome.subject.service == "kms"
            and outcome.subject.resource_type == "kms_key"
            and outcome.subject.region is not None
        ):
            if key is None:  # pragma: no cover - state validator invariant
                raise ValueError("PRESENT KMS DescribeKey evidence omitted its key")
            canonical_identity = (outcome.subject.region, outcome.subject.aws_resource_id)
            existing_key = canonical_kms_values.get(canonical_identity)
            if existing_key is not None and existing_key != key:
                raise ValueError("canonical KMS DescribeKey evidence is conflicting")
            canonical_kms_values[canonical_identity] = key
            canonical_kms_subjects.setdefault(
                canonical_identity,
                {},
            )[outcome.subject.resource_snapshot_id] = outcome.subject

    expected: dict[UUID, ResourceRelationship] = {}
    expected_reference_counts: dict[UUID, int] = {}
    for encryption_outcome in outcomes:
        if encryption_outcome.collector != "s3.bucket-encryption":
            continue
        subject = encryption_outcome.subject
        if not isinstance(subject, ResourceEvidenceSubject):
            raise ValueError("S3 encryption relationships require a bucket source subject")
        artifact = _matching_s3_artifact(
            outcome=encryption_outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema="s3.bucket-encryption",
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):  # pragma: no cover - artifact invariant
            raise ValueError("S3 encryption relationship metadata is malformed")
        value = payload.get("value")
        try:
            validate_s3_bucket_evidence_value(
                evidence_kind="s3.bucket-encryption",
                state=encryption_outcome.state,
                value=value,
            )
        except ValueError as error:
            raise ValueError("S3 encryption relationship metadata is malformed") from error
        if encryption_outcome.state is not EvidenceSourceState.PRESENT:
            continue
        bucket_arn = payload.get("bucket_arn")
        if not isinstance(bucket_arn, str):
            raise ValueError("S3 encryption relationship metadata is malformed")
        partition = _s3_bucket_partition(bucket_arn=bucket_arn, bucket_name=subject.aws_resource_id)
        if subject.region is None:  # pragma: no cover - Regional subject invariant
            raise ValueError("S3 encryption relationship source has no Region")

        source = RelationshipEndpoint.for_aws_resource(
            aws_account_id=subject.aws_account_id,
            service=subject.service,
            resource_type=subject.resource_type,
            aws_resource_id=subject.aws_resource_id,
            scope=subject.scope,
            region=subject.region,
            observed_in_scan_id=scan_id,
        )
        provenance = RelationshipProvenance(
            collector=encryption_outcome.collector,
            collector_version=encryption_outcome.collector_version,
            source=encryption_outcome.source,
            source_api=encryption_outcome.source_api,
            evidence_reference=encryption_outcome.evidence_reference,
            collected_at=encryption_outcome.collected_at,
        )
        references = s3_encryption_kms_references(value)
        for reference in references:
            lookup_region = _s3_kms_reference_region(
                reference=reference,
                bucket_region=subject.region,
                partition=partition,
            )
            evidence_kind = (
                "kms.key." + hashlib.sha256(f"{lookup_region}\x00{reference}".encode()).hexdigest()
            )
            matching_kms_outcomes = kms_outcomes_by_kind.get(evidence_kind, [])
            if len(matching_kms_outcomes) != 1:
                raise ValueError(
                    "S3 encryption reference requires exactly one matching DescribeKey outcome"
                )
            kms_outcome = matching_kms_outcomes[0]
            if (
                kms_outcome.source_api != "kms:DescribeKey"
                or kms_outcome.collector_version != "1.0.0"
            ):
                raise ValueError("S3 encryption reference has invalid DescribeKey provenance")
            kms_artifact = _matching_s3_artifact(
                outcome=kms_outcome,
                artifacts_by_reference=artifacts_by_reference,
                expected_schema="kms.key",
            )
            kms_payload = kms_artifact.model_dump(mode="json")["normalized_payload"]
            source_bucket_names = (
                kms_payload.get("source_bucket_names") if isinstance(kms_payload, dict) else None
            )
            if (
                not isinstance(kms_payload, dict)
                or kms_payload.get("region") != lookup_region
                or kms_payload.get("supplied_reference") != reference
                or not isinstance(source_bucket_names, list)
                or subject.aws_resource_id not in source_bucket_names
            ):
                raise ValueError("S3 encryption reference and DescribeKey evidence disagree")

            target: RelationshipEndpoint | UnresolvedRelationshipTarget
            resolution: RelationshipResolution
            if kms_outcome.state is EvidenceSourceState.PRESENT:
                kms_subject = kms_outcome.subject
                key = kms_values_by_outcome[kms_outcome.source_outcome_id]
                key_arn = key.get("arn") if key is not None else None
                key_id = key.get("key_id") if key is not None else None
                key_account_id = key.get("aws_account_id") if key is not None else None
                if (
                    not isinstance(kms_subject, ResourceEvidenceSubject)
                    or kms_subject.service != "kms"
                    or kms_subject.resource_type != "kms_key"
                    or kms_subject.region != lookup_region
                    or kms_subject.aws_resource_id != key_arn
                    or kms_subject.aws_account_id != key_account_id
                    or not kms_reference_matches_key_identity(
                        supplied_reference=reference,
                        lookup_region=lookup_region,
                        collection_account_id=collection_account_id,
                        partition=partition,
                        key_arn=key_arn,
                        key_id=key_id,
                        key_account_id=key_account_id,
                    )
                ):
                    raise ValueError("successful DescribeKey relationship identity is invalid")
                target = _relationship_endpoint_for_subject(kms_subject, scan_id=scan_id)
                resolution = RelationshipResolution.RESOLVED
            else:
                candidates = canonical_kms_subjects.get((lookup_region, reference), {})
                if len(candidates) > 1:
                    raise ValueError("S3 encryption reference resolves ambiguously")
                if candidates:
                    target = _relationship_endpoint_for_subject(
                        next(iter(candidates.values())),
                        scan_id=scan_id,
                    )
                    resolution = RelationshipResolution.RESOLVED
                else:
                    target = UnresolvedRelationshipTarget.for_aws_reference(
                        service="kms",
                        resource_type="kms_key",
                        aws_resource_id=reference,
                        scope=ResourceScope.REGIONAL,
                        region=lookup_region,
                    )
                    resolution = RelationshipResolution.TARGET_IDENTITY_INCOMPLETE

            relationship = ResourceRelationship.for_observation(
                scan_id=scan_id,
                collection_account_id=collection_account_id,
                relationship_type=RelationshipType.ENCRYPTED_WITH,
                source=source,
                target=target,
                resolution=resolution,
                provenance=provenance,
            )
            existing = expected.get(relationship.observation_id)
            if existing is not None and existing != relationship:
                raise ValueError("S3 encryption references produce conflicting relationships")
            expected[relationship.observation_id] = relationship
            expected_reference_counts[relationship.observation_id] = (
                expected_reference_counts.get(relationship.observation_id, 0) + 1
            )

    raw_s3_kms = tuple(item for item in raw_relationships if _is_s3_kms_relationship(item))
    raw_counts: dict[UUID, int] = {}
    for relationship in raw_s3_kms:
        raw_counts[relationship.observation_id] = raw_counts.get(relationship.observation_id, 0) + 1
    if any(
        count > expected_reference_counts.get(observation_id, 0)
        for observation_id, count in raw_counts.items()
    ):
        raise ValueError("S3 encryption relationship manifest contains duplicates")
    actual = {item.observation_id: item for item in relationships if _is_s3_kms_relationship(item)}
    if actual != expected:
        raise ValueError("S3 encryption relationship manifest is incomplete or inconsistent")


def _s3_bucket_partition(*, bucket_arn: str, bucket_name: str) -> str:
    parts = bucket_arn.split(":", maxsplit=5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or not parts[1]
        or parts[2:] != ["s3", "", "", bucket_name]
    ):
        raise ValueError("S3 encryption bucket ARN is malformed")
    return parts[1]


def _s3_kms_reference_region(*, reference: str, bucket_region: str, partition: str) -> str:
    if any(separator in reference for separator in ("\x00", "\x1f", "\r", "\n")):
        raise ValueError("S3 encryption KMS reference is malformed")
    if not reference.startswith("arn:"):
        return bucket_region
    parts = reference.split(":", maxsplit=5)
    resource_parts = parts[5].split("/", maxsplit=1) if len(parts) == 6 else []
    if (
        len(parts) != 6
        or parts[:3] != ["arn", partition, "kms"]
        or not parts[3]
        or len(parts[4]) != 12
        or not parts[4].isascii()
        or not parts[4].isdigit()
        or len(resource_parts) != 2
        or resource_parts[0] not in {"alias", "key"}
        or not resource_parts[1]
    ):
        raise ValueError("S3 encryption KMS reference is malformed")
    return parts[3]


def kms_reference_matches_key_identity(
    *,
    supplied_reference: object,
    lookup_region: object,
    collection_account_id: object,
    partition: object,
    key_arn: object,
    key_id: object,
    key_account_id: object,
) -> bool:
    """Bind a KMS DescribeKey identity to the exact S3-supplied reference semantics."""

    string_values = (
        supplied_reference,
        lookup_region,
        collection_account_id,
        partition,
        key_arn,
        key_id,
        key_account_id,
    )
    if not all(isinstance(value, str) and value for value in string_values):
        return False
    if any(
        separator in value for value in string_values for separator in ("\x00", "\x1f", "\r", "\n")
    ):
        return False
    if (
        len(collection_account_id) != 12
        or not collection_account_id.isascii()
        or not collection_account_id.isdigit()
        or len(key_account_id) != 12
        or not key_account_id.isascii()
        or not key_account_id.isdigit()
    ):
        return False

    key_arn_parts = key_arn.split(":", maxsplit=5)
    if (
        len(key_arn_parts) != 6
        or key_arn_parts[:3] != ["arn", partition, "kms"]
        or key_arn_parts[3] != lookup_region
        or key_arn_parts[4] != key_account_id
        or key_arn_parts[5] != f"key/{key_id}"
    ):
        return False

    if supplied_reference.startswith("arn:"):
        reference_parts = supplied_reference.split(":", maxsplit=5)
        resource_parts = (
            reference_parts[5].split("/", maxsplit=1) if len(reference_parts) == 6 else []
        )
        if (
            len(reference_parts) != 6
            or reference_parts[:3] != ["arn", partition, "kms"]
            or reference_parts[3] != lookup_region
            or reference_parts[4] != key_account_id
            or len(resource_parts) != 2
            or resource_parts[0] not in {"alias", "key"}
            or not resource_parts[1]
        ):
            return False
        return resource_parts[0] == "alias" or supplied_reference == key_arn

    if key_account_id != collection_account_id:
        return False
    if supplied_reference.startswith("alias/"):
        return len(supplied_reference) > len("alias/")
    return supplied_reference == key_id


def _relationship_endpoint_for_subject(
    subject: ResourceEvidenceSubject,
    *,
    scan_id: UUID,
) -> RelationshipEndpoint:
    return RelationshipEndpoint.for_aws_resource(
        aws_account_id=subject.aws_account_id,
        service=subject.service,
        resource_type=subject.resource_type,
        aws_resource_id=subject.aws_resource_id,
        scope=subject.scope,
        region=subject.region,
        observed_in_scan_id=scan_id,
    )


def _is_s3_kms_relationship(relationship: ResourceRelationship) -> bool:
    return bool(
        relationship.relationship_type is RelationshipType.ENCRYPTED_WITH
        and relationship.source.service == "s3"
        and relationship.source.resource_type == "s3_bucket"
        and relationship.target.service == "kms"
        and relationship.target.resource_type == "kms_key"
    )


def _validate_cloudtrail_relationship_manifest(
    *,
    scan_id: UUID,
    collection_account_id: str,
    manifest: _CloudTrailManifest,
    contracts: tuple[ScanSourceContract, ...],
    artifacts: tuple[SourceEvidenceArtifact, ...],
    outcomes: tuple[SourceEvidenceOutcome, ...],
    relationships: tuple[ResourceRelationship, ...],
    raw_relationships: tuple[ResourceRelationship, ...],
) -> None:
    """Bind every 5F destination edge to one PRESENT configuration observation."""

    actual = tuple(
        relationship
        for relationship in relationships
        if relationship.source.service == "cloudtrail"
        and relationship.source.resource_type == "cloudtrail_trail"
    )
    raw_actual = tuple(
        relationship
        for relationship in raw_relationships
        if relationship.source.service == "cloudtrail"
        and relationship.source.resource_type == "cloudtrail_trail"
    )
    if len(raw_actual) != len({item.observation_id for item in raw_actual}):
        raise ValueError("CloudTrail relationship observation is duplicated")

    expected: dict[tuple[str, RelationshipType], tuple[SourceEvidenceOutcome, str]] = {}
    for trail_arn, sources in manifest.sources_by_arn.items():
        configuration_outcome, payload = sources["cloudtrail.trail.configuration"]
        if configuration_outcome.state is not EvidenceSourceState.PRESENT:
            continue
        if not isinstance(payload, Mapping):  # pragma: no cover - manifest invariant
            raise TypeError("CloudTrail configuration payload must be an object")
        configuration = payload["value"]
        if not isinstance(configuration, Mapping):  # pragma: no cover - manifest invariant
            raise TypeError("CloudTrail configuration value must be an object")
        bucket_name = configuration["s3_bucket_name"]
        kms_key_id = configuration["kms_key_id"]
        if bucket_name is not None:
            expected[(trail_arn, RelationshipType.DELIVERS_TO_BUCKET)] = (
                configuration_outcome,
                bucket_name,
            )
        if kms_key_id is not None:
            expected[(trail_arn, RelationshipType.ENCRYPTED_WITH)] = (
                configuration_outcome,
                kms_key_id,
            )

    actual_by_key: dict[tuple[str, RelationshipType], ResourceRelationship] = {}
    for relationship in actual:
        key = (relationship.source.aws_resource_id, relationship.relationship_type)
        if key in actual_by_key or key not in expected:
            raise ValueError("CloudTrail relationship manifest is duplicated or unexpected")
        outcome, reference = expected[key]
        subject = outcome.subject
        if (
            not isinstance(subject, ResourceEvidenceSubject)
            or relationship.scan_id != scan_id
            or relationship.collection_account_id != collection_account_id
            or relationship.source.resource_snapshot_id != subject.resource_snapshot_id
            or not _resource_endpoint_matches_subject(relationship.source, subject)
            or not _provenance_matches_outcome(relationship.provenance, outcome)
        ):
            raise ValueError("CloudTrail relationship provenance is invalid")
        if relationship.relationship_type is RelationshipType.DELIVERS_TO_BUCKET:
            _validate_cloudtrail_bucket_relationship(relationship, reference)
        elif relationship.relationship_type is RelationshipType.ENCRYPTED_WITH:
            _validate_cloudtrail_kms_relationship(
                relationship,
                reference,
                contracts=contracts,
                artifacts=artifacts,
                outcomes=outcomes,
            )
        else:  # pragma: no cover - expected key invariant
            raise ValueError("CloudTrail relationship type is invalid")
        actual_by_key[key] = relationship
    if set(actual_by_key) != set(expected):
        raise ValueError("CloudTrail relationship manifest is incomplete")


def _resource_endpoint_matches_subject(
    endpoint: RelationshipEndpoint,
    subject: ResourceEvidenceSubject,
) -> bool:
    return (
        endpoint.aws_account_id,
        endpoint.service,
        endpoint.resource_type,
        endpoint.aws_resource_id,
        endpoint.scope,
        endpoint.region,
    ) == (
        subject.aws_account_id,
        subject.service,
        subject.resource_type,
        subject.aws_resource_id,
        subject.scope,
        subject.region,
    )


def _validate_cloudtrail_bucket_relationship(
    relationship: ResourceRelationship,
    bucket_name: str,
) -> None:
    target = relationship.target
    if (
        target.service != "s3"
        or target.resource_type != "s3_bucket"
        or target.aws_resource_id != bucket_name
        or target.scope is not ResourceScope.REGIONAL
    ):
        raise ValueError("CloudTrail bucket relationship target is invalid")
    if isinstance(target, UnresolvedRelationshipTarget):
        if (
            target.aws_account_id is not None
            or target.region is not None
            or relationship.resolution is not RelationshipResolution.TARGET_IDENTITY_INCOMPLETE
        ):
            raise ValueError("CloudTrail bucket relationship resolution is invalid")
    elif relationship.resolution is not RelationshipResolution.RESOLVED:
        raise ValueError("CloudTrail bucket relationship resolution is invalid")


def _validate_cloudtrail_kms_relationship(
    relationship: ResourceRelationship,
    kms_key_arn: str,
    *,
    contracts: tuple[ScanSourceContract, ...],
    artifacts: tuple[SourceEvidenceArtifact, ...],
    outcomes: tuple[SourceEvidenceOutcome, ...],
) -> None:
    _, region, owner, _ = _parse_kms_key_arn(kms_key_arn)
    target = relationship.target
    if (
        not isinstance(target, RelationshipEndpoint)
        or target.aws_account_id != owner
        or target.service != "kms"
        or target.resource_type != "kms_key"
        or target.aws_resource_id != kms_key_arn
        or target.scope is not ResourceScope.REGIONAL
        or target.region != region
    ):
        raise ValueError("CloudTrail KMS relationship target is invalid")
    expected_resolution = _cloudtrail_kms_resolution_from_outcomes(
        kms_key_arn=kms_key_arn,
        contracts=contracts,
        artifacts=artifacts,
        outcomes=outcomes,
    )
    if relationship.resolution is not expected_resolution or (
        expected_resolution is RelationshipResolution.RESOLVED
    ) is (target.resource_snapshot_id is None):
        raise ValueError("CloudTrail KMS relationship resolution is invalid")


def _cloudtrail_kms_resolution_from_outcomes(
    *,
    kms_key_arn: str,
    contracts: tuple[ScanSourceContract, ...],
    artifacts: tuple[SourceEvidenceArtifact, ...],
    outcomes: tuple[SourceEvidenceOutcome, ...],
) -> RelationshipResolution:
    """Reconstruct the exact runtime resolution of one canonical CloudTrail KMS target."""

    _, region, owner, _ = _parse_kms_key_arn(kms_key_arn)
    s3_outcomes = tuple(outcome for outcome in outcomes if outcome.collector in _S3_5E_COLLECTORS)
    region_evidence = None
    if s3_outcomes:
        region_evidence = reconstruct_s3_bucket_region_evidence(
            contracts=contracts,
            outcomes=outcomes,
            artifacts=artifacts,
        )
        if region_evidence is None:
            raise ValueError("CloudTrail KMS target requires a valid S3 collection manifest")

    matching_key_subjects = tuple(
        outcome
        for outcome in outcomes
        if outcome.collector == "kms.keys"
        and outcome.state is EvidenceSourceState.PRESENT
        and isinstance(outcome.subject, ResourceEvidenceSubject)
        and outcome.subject.aws_account_id == owner
        and outcome.subject.service == "kms"
        and outcome.subject.resource_type == "kms_key"
        and outcome.subject.aws_resource_id == kms_key_arn
        and outcome.subject.scope is ResourceScope.REGIONAL
        and outcome.subject.region == region
    )
    if matching_key_subjects:
        return RelationshipResolution.RESOLVED

    evidence_kind = "kms.key." + hashlib.sha256(f"{region}\x00{kms_key_arn}".encode()).hexdigest()
    matching_outcomes = tuple(
        outcome for outcome in outcomes if outcome.evidence_kind == evidence_kind
    )
    if (
        any(outcome.collector != "kms.keys" for outcome in matching_outcomes)
        or len(matching_outcomes) > 1
    ):
        raise ValueError("CloudTrail KMS target evidence is ambiguous")
    if matching_outcomes:
        outcome = matching_outcomes[0]
        if outcome.state is EvidenceSourceState.PRESENT:
            raise ValueError("CloudTrail KMS target evidence contradicts its canonical identity")
        if outcome.failure_category is EvidenceFailureCategory.ACCESS_DENIED:
            return RelationshipResolution.TARGET_ACCESS_DENIED
        return RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE

    complete_states = {EvidenceSourceState.PRESENT, EvidenceSourceState.EXPECTED_ABSENCE}
    if not s3_outcomes:
        return RelationshipResolution.TARGET_NOT_COLLECTED
    if region_evidence is None:  # pragma: no cover - guarded above
        raise TypeError("S3 outcomes require reconstructed Region evidence")
    if (
        all(outcome.state in complete_states for outcome in s3_outcomes)
        and region_evidence.complete
    ):
        return RelationshipResolution.TARGET_NOT_COLLECTED
    return RelationshipResolution.TARGET_EVIDENCE_INCOMPLETE


def validate_graph_resources(
    *,
    graph: EvidenceGraph,
    resources: tuple[NormalizedResource, ...],
    requested_region: str,
) -> None:
    """Bind graph subjects/endpoints and exceptional ownership to top-level resources."""

    resource_by_snapshot_id: dict[UUID, NormalizedResource] = {}
    for resource in resources:
        expected_scope = canonical_resource_scope(resource.service, resource.resource_type)
        if expected_scope is not None and resource.scope is not expected_scope:
            raise ValueError(
                f"{resource.service}/{resource.resource_type} top-level resources must use "
                f"{expected_scope.value} scope"
            )
        snapshot_id = resource_snapshot_id(
            scan_id=graph.scan_id,
            account_id=resource.account_id,
            service=resource.service,
            resource_type=resource.resource_type,
            scope=resource.scope,
            region=resource.region,
            aws_resource_id=resource.aws_resource_id,
        )
        existing = resource_by_snapshot_id.get(snapshot_id)
        if existing is not None and existing != resource:
            raise ValueError("conflicting resources share a snapshot identity")
        resource_by_snapshot_id[snapshot_id] = resource

    s3_region_evidence = reconstruct_s3_bucket_region_evidence(
        contracts=graph.source_contracts,
        outcomes=graph.source_outcomes,
        artifacts=graph.artifacts,
    )
    if s3_region_evidence is not None:
        bucket_regions = {region for _, region in s3_region_evidence.bucket_regions}
    else:
        bucket_regions = {
            resource.region
            for resource in resources
            if resource.account_id == graph.collection_account_id
            and resource.service == "s3"
            and resource.resource_type == "s3_bucket"
            and resource.scope is ResourceScope.REGIONAL
            and resource.region is not None
        }
    access_analyzer_regions: list[str] = []
    for contract in graph.source_contracts:
        if (
            contract.phase is EvidenceCollectionPhase.DISCOVERY
            and isinstance(contract.subject, AccountEvidenceSubject)
            and contract.subject.scope is ResourceScope.REGIONAL
        ):
            region = contract.subject.region
            if (
                contract.contract_key == "access-analyzer.analyzers.discovery"
                and _is_access_analyzer_discovery_source(contract)
            ):
                access_analyzer_regions.append(region)
            if region == requested_region:
                if contract.allows_supplemental_region:
                    raise ValueError(
                        "requested-Region discovery cannot claim supplemental-Region permission"
                    )
                continue
            if not contract.allows_supplemental_region:
                raise ValueError(
                    "Regional discovery source contracts must match the inventory invocation Region"
                )
            if region not in bucket_regions:
                raise ValueError(
                    "Access Analyzer supplemental discovery requires a same-scan S3 bucket Region"
                )

    if access_analyzer_regions:
        expected_access_analyzer_regions = {requested_region, *bucket_regions}
        if (
            len(access_analyzer_regions) != len(expected_access_analyzer_regions)
            or set(access_analyzer_regions) != expected_access_analyzer_regions
        ):
            raise ValueError(
                "Access Analyzer Regional coverage must exactly match the requested Region and "
                "same-scan S3 bucket Regions"
            )

    proof_by_snapshot: dict[UUID, list[ScanSourceContract]] = {}
    resolved_relationship_snapshots: set[UUID] = set()
    resolved_s3_kms_targets: set[UUID] = set()
    contract_by_id = {item.source_outcome_id: item for item in graph.source_contracts}
    outcome_by_id = {item.source_outcome_id: item for item in graph.source_outcomes}
    artifact_by_reference = {item.evidence_reference: item for item in graph.artifacts}
    _validate_s3_and_kms_resource_readback(
        graph=graph,
        resources_by_snapshot=resource_by_snapshot_id,
        artifacts_by_reference=artifact_by_reference,
    )
    _validate_cloudtrail_resource_readback(
        graph=graph,
        resources_by_snapshot=resource_by_snapshot_id,
        requested_region=requested_region,
    )
    kms_source_buckets_by_snapshot: dict[UUID, set[str]] = {}
    for outcome_id, outcome in outcome_by_id.items():
        if outcome.state is not EvidenceSourceState.PRESENT:
            continue
        contract = contract_by_id[outcome_id]
        if isinstance(outcome.subject, ResourceEvidenceSubject):
            _require_resource_subject(outcome.subject, resource_by_snapshot_id)
            proof_by_snapshot.setdefault(outcome.subject.resource_snapshot_id, []).append(contract)
            if _is_authoritative_kms_key_source(contract):
                artifact = artifact_by_reference[outcome.evidence_reference]
                payload = artifact.model_dump(mode="json")["normalized_payload"]
                source_bucket_names = (
                    payload.get("source_bucket_names") if isinstance(payload, dict) else None
                )
                if (
                    not isinstance(source_bucket_names, list)
                    or not source_bucket_names
                    or not all(isinstance(item, str) and item for item in source_bucket_names)
                    or source_bucket_names != sorted(set(source_bucket_names))
                ):
                    raise ValueError(
                        "KMS DescribeKey evidence has invalid source-bucket provenance"
                    )
                kms_source_buckets_by_snapshot.setdefault(
                    outcome.subject.resource_snapshot_id,
                    set(),
                ).update(source_bucket_names)

    outcomes_by_provenance = index_source_outcomes_by_provenance(graph.source_outcomes)
    for relationship in graph.relationships:
        _require_relationship_endpoint(
            relationship.source,
            resource_by_snapshot_id,
        )
        if relationship.resolution is RelationshipResolution.RESOLVED:
            if not isinstance(relationship.target, RelationshipEndpoint):  # pragma: no cover
                raise ValueError("resolved relationship target must have a stable identity")
            _require_relationship_endpoint(
                relationship.target,
                resource_by_snapshot_id,
            )
            target_snapshot_id = relationship.target.resource_snapshot_id
            if target_snapshot_id is None:  # pragma: no cover - relationship invariant
                raise ValueError("resolved relationship target must identify a snapshot")
            source_snapshot_id = relationship.source.resource_snapshot_id
            if source_snapshot_id is None:  # pragma: no cover - relationship invariant
                raise ValueError("relationship source must identify a snapshot")
            resolved_relationship_snapshots.update((source_snapshot_id, target_snapshot_id))
            provenance_outcomes = outcomes_by_provenance.get(
                source_provenance_key(relationship.provenance), ()
            )
            if (
                relationship.relationship_type is RelationshipType.ENCRYPTED_WITH
                and relationship.source.service == "s3"
                and relationship.source.resource_type == "s3_bucket"
                and relationship.target.service == "kms"
                and relationship.target.resource_type == "kms_key"
                and len(provenance_outcomes) == 1
                and _is_s3_encryption_reference_source(provenance_outcomes[0])
                and isinstance(provenance_outcomes[0].subject, ResourceEvidenceSubject)
                and provenance_outcomes[0].subject.resource_snapshot_id == source_snapshot_id
                and relationship.source.aws_resource_id
                in kms_source_buckets_by_snapshot.get(target_snapshot_id, set())
            ):
                resolved_s3_kms_targets.add(target_snapshot_id)

    for outcome in graph.source_outcomes:
        if isinstance(outcome.subject, ResourceEvidenceSubject):
            _require_resource_subject(outcome.subject, resource_by_snapshot_id)

    for snapshot_id, resource in resource_by_snapshot_id.items():
        _validate_resource_admission(
            resource=resource,
            contracts=proof_by_snapshot.get(snapshot_id, []),
            collection_account_id=graph.collection_account_id,
            requested_region=requested_region,
            referenced_by_resolved_relationship=snapshot_id in resolved_relationship_snapshots,
            referenced_by_resolved_s3_encryption=snapshot_id in resolved_s3_kms_targets,
            s3_region_evidence=s3_region_evidence,
        )


def _validate_cloudtrail_resource_readback(
    *,
    graph: EvidenceGraph,
    resources_by_snapshot: Mapping[UUID, NormalizedResource],
    requested_region: str,
) -> None:
    """Rebuild each canonical trail from its immutable 5F source artifacts."""

    cloudtrail_outcomes = tuple(
        outcome
        for outcome in graph.source_outcomes
        if outcome.collector in {identity[0] for identity in _CLOUDTRAIL_SOURCE_IDENTITIES.values()}
    )
    if not cloudtrail_outcomes:
        return
    manifest = _validate_cloudtrail_manifest(
        outcomes=graph.source_outcomes,
        contracts=graph.source_contracts,
        artifacts=graph.artifacts,
    )
    if manifest.invocation_region != requested_region:
        raise ValueError("CloudTrail discovery invocation Region contradicts the scan request")
    cloudtrail_resources = tuple(
        resource
        for resource in resources_by_snapshot.values()
        if (resource.service, resource.resource_type) == ("cloudtrail", "cloudtrail_trail")
    )
    actual_trails = {resource.aws_resource_id: resource for resource in cloudtrail_resources}
    if len(cloudtrail_resources) != len(actual_trails) or set(actual_trails) != set(
        manifest.admitted_arns
    ):
        raise ValueError("CloudTrail canonical resource manifest contradicts discovery")

    for trail_arn in manifest.admitted_arns:
        resource = actual_trails[trail_arn]
        sources = manifest.sources_by_arn[trail_arn]
        identity_outcome, identity_payload = sources["cloudtrail.trail.identity"]
        if not isinstance(identity_payload, Mapping):  # pragma: no cover - manifest invariant
            raise TypeError("CloudTrail identity payload must be an object")
        configuration_outcome, configuration_payload = sources["cloudtrail.trail.configuration"]
        status_outcome, status_payload = sources["cloudtrail.trail.status"]
        selectors_outcome, selectors_payload = sources["cloudtrail.trail.event-selectors"]
        tags_outcome, tags_payload = sources["cloudtrail.trail.tags"]
        if not all(
            isinstance(payload, Mapping)
            for payload in (
                configuration_payload,
                status_payload,
                selectors_payload,
                tags_payload,
            )
        ):
            raise TypeError("CloudTrail enrichment payload must be an object")

        configuration_value = (
            configuration_payload["value"]
            if configuration_outcome.state is EvidenceSourceState.PRESENT
            else None
        )
        status_value = (
            status_payload["value"] if status_outcome.state is EvidenceSourceState.PRESENT else None
        )
        selectors_value = (
            selectors_payload["value"]
            if selectors_outcome.state is EvidenceSourceState.PRESENT
            else None
        )
        tags_value = (
            tags_payload["value"] if tags_outcome.state is EvidenceSourceState.PRESENT else None
        )
        if configuration_value is not None and not isinstance(configuration_value, Mapping):
            raise TypeError("CloudTrail configuration value must be an object")
        if status_value is not None and not isinstance(status_value, Mapping):
            raise TypeError("CloudTrail status value must be an object")

        expected_configuration = {
            "home_region": identity_payload["home_region"],
            "s3_bucket_name": (
                configuration_value["s3_bucket_name"] if configuration_value is not None else None
            ),
            "s3_key_prefix": (
                configuration_value["s3_key_prefix"] if configuration_value is not None else None
            ),
            "include_global_service_events": (
                configuration_value["include_global_service_events"]
                if configuration_value is not None
                else None
            ),
            "is_multi_region_trail": (
                configuration_value["is_multi_region_trail"]
                if configuration_value is not None
                else None
            ),
            "log_file_validation_enabled": (
                configuration_value["log_file_validation_enabled"]
                if configuration_value is not None
                else None
            ),
            "cloudwatch_logs_log_group_arn": (
                configuration_value["cloudwatch_logs_log_group_arn"]
                if configuration_value is not None
                else None
            ),
            "cloudwatch_logs_role_arn": (
                configuration_value["cloudwatch_logs_role_arn"]
                if configuration_value is not None
                else None
            ),
            "kms_key_id": (
                configuration_value["kms_key_id"] if configuration_value is not None else None
            ),
            "is_organization_trail": (
                configuration_value["is_organization_trail"]
                if configuration_value is not None
                else None
            ),
            "is_logging": (status_value["is_logging"] if status_value is not None else None),
            "status": status_value["status"] if status_value is not None else None,
            "event_selectors": selectors_value,
            "source_states": {
                "identity": identity_outcome.state.value,
                "configuration": configuration_outcome.state.value,
                "status": status_outcome.state.value,
                "event_selectors": selectors_outcome.state.value,
                "tags": tags_outcome.state.value,
            },
        }
        expected_raw = {
            "summary": {
                "TrailARN": trail_arn,
                "Name": identity_payload["name"],
                "HomeRegion": identity_payload["home_region"],
            },
            "trail": configuration_value,
            "status": status_value["status"] if status_value is not None else None,
            "event_selectors": selectors_value,
        }
        expected_tags = (
            _validate_cloudtrail_tags_value(tags_value) if tags_value is not None else {}
        )
        if (
            resource.account_id != identity_payload["owner_account_id"]
            or resource.scope is not ResourceScope.REGIONAL
            or resource.region != identity_payload["home_region"]
            or resource.arn != trail_arn
            or resource.name != identity_payload["name"]
            or resource.tags != expected_tags
            or resource.configuration != expected_configuration
            or resource.raw_configuration != expected_raw
        ):
            raise ValueError("CloudTrail canonical resource contradicts its source artifacts")


def _validate_s3_and_kms_resource_readback(
    *,
    graph: EvidenceGraph,
    resources_by_snapshot: Mapping[UUID, NormalizedResource],
    artifacts_by_reference: Mapping[str, SourceEvidenceArtifact],
) -> None:
    """Bind canonical 5E artifacts to the exact normalized resources rules will read."""

    discovery_outcomes = tuple(
        outcome
        for outcome in graph.source_outcomes
        if outcome.collector == "s3.buckets" and outcome.evidence_kind == "s3.buckets.discovery"
    )
    if not discovery_outcomes:
        return
    if len(discovery_outcomes) != 1:
        raise ValueError("S3 resource readback requires one discovery source")
    discovery = discovery_outcomes[0]
    discovery_artifact = _matching_s3_artifact(
        outcome=discovery,
        artifacts_by_reference=artifacts_by_reference,
        expected_schema="s3.buckets.discovery",
    )
    discovery_payload = discovery_artifact.model_dump(mode="json")["normalized_payload"]
    buckets = discovery_payload.get("buckets") if isinstance(discovery_payload, dict) else None
    if not isinstance(buckets, list):
        raise ValueError("S3 resource readback discovery metadata is malformed")
    discovery_by_name: dict[str, dict[str, object]] = {}
    for bucket in buckets:
        if not isinstance(bucket, dict) or not isinstance(bucket.get("bucket_name"), str):
            raise ValueError("S3 resource readback discovery metadata is malformed")
        discovery_by_name[bucket["bucket_name"]] = bucket

    account_outcomes = tuple(
        outcome
        for outcome in graph.source_outcomes
        if outcome.collector == "s3.account-public-access-block"
    )
    if not account_outcomes:
        # Synthetic/accepted pre-5E graphs may contain S3 identity or relationship proofs
        # without the complete 5E source family. Persistence requires the full manifest before
        # admitting the 5E operational collector.
        return
    if len(account_outcomes) != 1:
        raise ValueError("S3 resource readback requires one account Public Access Block source")
    account_outcome = account_outcomes[0]
    account_artifact = _matching_s3_artifact(
        outcome=account_outcome,
        artifacts_by_reference=artifacts_by_reference,
        expected_schema="s3.account-public-access-block",
    )
    account_payload = account_artifact.model_dump(mode="json")["normalized_payload"]
    if not isinstance(account_payload, dict):
        raise ValueError("S3 account Public Access Block readback is malformed")
    try:
        account_block = validate_s3_bucket_evidence_value(
            evidence_kind="s3.bucket-public-access-block",
            state=account_outcome.state,
            value=account_payload.get("public_access_block"),
        )
    except ValueError as error:
        raise ValueError("S3 account Public Access Block readback is malformed") from error

    source_projection = {
        "s3.bucket-acl": ("acl", "acl"),
        "s3.bucket-encryption": ("encryption", "encryption"),
        "s3.bucket-ownership-controls": ("ownership_controls", "ownership_controls"),
        "s3.bucket-policy": ("policy", "policy"),
        "s3.bucket-policy-status": ("policy_status", "policy_status"),
        "s3.bucket-public-access-block": ("public_access_block", "public_access_block"),
        "s3.bucket-tags": (None, "tags"),
        "s3.bucket-versioning": ("versioning", "versioning"),
    }
    sources_by_snapshot: dict[
        UUID,
        dict[str, tuple[SourceEvidenceOutcome, object, object]],
    ] = {}
    for outcome in graph.source_outcomes:
        if outcome.collector not in source_projection:
            continue
        if not isinstance(outcome.subject, ResourceEvidenceSubject):
            raise ValueError("S3 per-bucket readback requires a resource subject")
        artifact = _matching_s3_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema=outcome.evidence_kind,
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):
            raise ValueError("S3 per-bucket readback metadata is malformed")
        _validate_s3_completion_metadata(outcome, payload)
        if payload.get("expected_absence") is not (
            outcome.state is EvidenceSourceState.EXPECTED_ABSENCE
        ):
            raise ValueError("S3 per-bucket readback absence state is inconsistent")
        try:
            projected_value = validate_s3_bucket_evidence_value(
                evidence_kind=outcome.evidence_kind,
                state=outcome.state,
                value=payload.get("value"),
            )
        except ValueError as error:
            raise ValueError("S3 per-bucket readback value is malformed") from error
        legacy_projection = payload.get("legacy_projection")
        if (
            outcome.evidence_kind
            not in {
                "s3.bucket-encryption",
                "s3.bucket-public-access-block",
            }
            and legacy_projection is not None
        ):
            raise ValueError("S3 source has an unexpected legacy projection")
        bucket_sources = sources_by_snapshot.setdefault(
            outcome.subject.resource_snapshot_id,
            {},
        )
        if outcome.collector in bucket_sources:
            raise ValueError("S3 per-bucket readback source is duplicated")
        bucket_sources[outcome.collector] = (
            outcome,
            projected_value,
            legacy_projection,
        )

    expected_sources = set(source_projection)
    for snapshot_id, sources in sources_by_snapshot.items():
        if set(sources) != expected_sources:
            raise ValueError("S3 per-bucket readback source manifest is incomplete")
        resource = resources_by_snapshot.get(snapshot_id)
        if resource is None or (resource.service, resource.resource_type) != (
            "s3",
            "s3_bucket",
        ):
            raise ValueError("S3 per-bucket readback has no canonical resource")
        discovery_bucket = discovery_by_name.get(resource.aws_resource_id)
        if discovery_bucket is None:
            raise ValueError("S3 per-bucket readback has no discovery identity")
        configuration = resource.configuration
        expected_configuration_keys = {
            "creation_date",
            "bucket_region",
            "default_encryption",
            "public_access_block",
            "account_public_access_block",
            "policy",
            "policy_status",
            "acl",
            "versioning",
            "encryption",
            "ownership_controls",
            "source_states",
        }
        if (
            set(configuration) != expected_configuration_keys
            or resource.raw_configuration != configuration
            or resource.arn != discovery_bucket.get("bucket_arn")
            or resource.name != resource.aws_resource_id
            or configuration.get("creation_date") != discovery_bucket.get("creation_date")
            or configuration.get("bucket_region") != resource.region
            or configuration.get("account_public_access_block") != account_block
        ):
            raise ValueError("S3 canonical resource contradicts its source artifacts")
        expected_states = {
            "account_public_access_block": account_outcome.state.value,
        }
        for evidence_kind, (configuration_key, state_key) in source_projection.items():
            outcome, projected_value, legacy_projection = sources[evidence_kind]
            expected_states[state_key] = outcome.state.value
            if evidence_kind == "s3.bucket-tags":
                expected_tags = projected_value if isinstance(projected_value, dict) else {}
                if resource.tags != expected_tags:
                    raise ValueError("S3 canonical tags contradict their source artifact")
                continue
            if evidence_kind == "s3.bucket-public-access-block":
                configured_block = configuration.get("public_access_block")
                if configured_block != legacy_projection:
                    raise ValueError(
                        "S3 bucket Public Access Block contradicts its legacy projection"
                    )
                if outcome.state is EvidenceSourceState.PRESENT:
                    if not isinstance(configured_block, Mapping) or any(
                        configured_block.get(field) != projected_value[field]
                        for field in _S3_PUBLIC_ACCESS_BLOCK_FIELDS
                    ):
                        raise ValueError(
                            "S3 bucket Public Access Block contradicts its source artifact"
                        )
                continue
            if configuration_key is None:  # pragma: no cover - tags handled above
                raise TypeError("S3 source projection omitted its configuration key")
            if configuration.get(configuration_key) != projected_value:
                raise ValueError("S3 canonical resource contradicts its source artifact")
        if configuration.get("source_states") != expected_states:
            raise ValueError("S3 canonical source-state readback is inconsistent")
        encryption_outcome, encryption_value, encryption_legacy_projection = sources[
            "s3.bucket-encryption"
        ]
        default_encryption = configuration.get("default_encryption")
        if default_encryption != encryption_legacy_projection:
            raise ValueError("S3 legacy encryption readback contradicts source evidence")
        if default_encryption is not None and encryption_value is not None:
            try:
                normalized_default = normalize_s3_legacy_encryption_value(default_encryption)
            except ValueError as error:
                raise ValueError("S3 legacy encryption readback is malformed") from error
            if normalized_default != encryption_value:
                raise ValueError("S3 legacy encryption readback contradicts source evidence")

    canonical_kms_values: dict[UUID, dict[str, object]] = {}
    for outcome in graph.source_outcomes:
        if outcome.collector != "kms.keys" or outcome.state is not EvidenceSourceState.PRESENT:
            continue
        if not isinstance(outcome.subject, ResourceEvidenceSubject):
            raise ValueError("KMS readback requires a canonical resource subject")
        artifact = _matching_s3_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema="kms.key",
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):
            raise ValueError("KMS readback metadata is malformed")
        key = validate_kms_key_evidence_value(
            state=outcome.state,
            value=payload.get("key"),
        )
        if key is None:  # pragma: no cover - PRESENT validator invariant
            raise ValueError("KMS readback omitted its key")
        existing = canonical_kms_values.get(outcome.subject.resource_snapshot_id)
        if existing is not None and existing != key:
            raise ValueError("canonical KMS readback evidence is conflicting")
        canonical_kms_values[outcome.subject.resource_snapshot_id] = key
    for snapshot_id, key in canonical_kms_values.items():
        resource = resources_by_snapshot.get(snapshot_id)
        if (
            resource is None
            or (resource.service, resource.resource_type) != ("kms", "kms_key")
            or resource.arn != key["arn"]
            or resource.name is not None
            or resource.tags
            or resource.configuration != key
            or resource.raw_configuration != key
        ):
            raise ValueError("canonical KMS resource contradicts DescribeKey evidence")


def _validate_s3_tags_value(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        raise ValueError("S3 tag evidence must be a list")
    tags: dict[str, str] = {}
    ordered_keys: list[str] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"key", "value"}:
            raise ValueError("S3 tag evidence has an invalid entry")
        key = item["key"]
        tag_value = item["value"]
        if not isinstance(key, str) or not key or not isinstance(tag_value, str) or key in tags:
            raise ValueError("S3 tag evidence has an invalid entry")
        tags[key] = tag_value
        ordered_keys.append(key)
    if ordered_keys != sorted(ordered_keys):
        raise ValueError("S3 tag evidence is not canonical")
    return tags


def _validate_s3_public_access_block_value(value: object) -> dict[str, bool]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _S3_PUBLIC_ACCESS_BLOCK_FIELDS
        or not all(isinstance(item, bool) for item in value.values())
    ):
        raise ValueError("S3 Public Access Block evidence is malformed")
    return {field: value[field] for field in sorted(_S3_PUBLIC_ACCESS_BLOCK_FIELDS)}


def _validate_s3_policy_status_value(value: object) -> dict[str, bool]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"policy_present", "is_public"}
        or not isinstance(value["policy_present"], bool)
        or not isinstance(value["is_public"], bool)
    ):
        raise ValueError("S3 policy-status evidence is malformed")
    return {
        "policy_present": value["policy_present"],
        "is_public": value["is_public"],
    }


def _validate_s3_acl_value(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"owner", "grants"}:
        raise ValueError("S3 ACL evidence is malformed")
    owner = value["owner"]
    grants = value["grants"]
    if not isinstance(owner, Mapping) or set(owner) != {"id", "display_name"}:
        raise ValueError("S3 ACL owner evidence is malformed")
    if not _is_safe_non_empty_string(owner["id"]) or (
        owner["display_name"] is not None and not isinstance(owner["display_name"], str)
    ):
        raise ValueError("S3 ACL owner evidence is malformed")
    if not isinstance(grants, list):
        raise ValueError("S3 ACL grant evidence is malformed")
    normalized_grants: list[dict[str, object]] = []
    for grant in grants:
        if not isinstance(grant, Mapping) or set(grant) != {"grantee", "permission"}:
            raise ValueError("S3 ACL grant evidence is malformed")
        grantee = grant["grantee"]
        permission = grant["permission"]
        if (
            not isinstance(grantee, Mapping)
            or not {"type"}.issubset(grantee)
            or not set(grantee).issubset({"type", "id", "uri", "email_address", "display_name"})
            or grantee["type"] not in _S3_ACL_GRANTEE_TYPES
            or permission not in _S3_ACL_PERMISSIONS
        ):
            raise ValueError("S3 ACL grant evidence is malformed")
        if frozenset(grantee) not in _S3_ACL_GRANTEE_FIELD_SETS[grantee["type"]] or any(
            not _is_safe_non_empty_string(item) for key, item in grantee.items() if key != "type"
        ):
            raise ValueError("S3 ACL grantee evidence is malformed")
        normalized_grants.append({"grantee": dict(grantee), "permission": permission})
    if grants != sorted(grants, key=_canonical_json):
        raise ValueError("S3 ACL grant evidence is not canonical")
    return {
        "owner": {"id": owner["id"], "display_name": owner["display_name"]},
        "grants": normalized_grants,
    }


def _s3_acl_has_public_group_grant(acl: Mapping[str, object]) -> bool:
    grants = acl["grants"]
    if not isinstance(grants, list):  # pragma: no cover - validated caller invariant
        raise TypeError("validated S3 ACL grants must be a list")
    return any(
        isinstance(grant, Mapping)
        and isinstance(grant.get("grantee"), Mapping)
        and grant["grantee"].get("type") == "Group"
        and grant["grantee"].get("uri") in _S3_PUBLIC_ACL_GROUP_URIS
        for grant in grants
    )


def _validate_s3_versioning_value(value: object) -> dict[str, str | None]:
    if not isinstance(value, Mapping) or set(value) != {"status", "mfa_delete"}:
        raise ValueError("S3 versioning evidence is malformed")
    status = value["status"]
    mfa_delete = value["mfa_delete"]
    if (
        (status is not None and status not in _S3_VERSIONING_STATUSES)
        or (mfa_delete is not None and mfa_delete not in _S3_MFA_DELETE_STATUSES)
        or (status is None and mfa_delete is not None)
    ):
        raise ValueError("S3 versioning evidence is malformed")
    return {"status": status, "mfa_delete": mfa_delete}


def _validate_s3_ownership_controls_value(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"rules"}:
        raise ValueError("S3 ownership-control evidence is malformed")
    rules = value["rules"]
    if not isinstance(rules, list) or len(rules) != 1:
        raise ValueError("S3 ownership-control evidence is malformed")
    normalized: list[dict[str, str]] = []
    for rule in rules:
        if (
            not isinstance(rule, Mapping)
            or set(rule) != {"object_ownership"}
            or rule["object_ownership"] not in _S3_OBJECT_OWNERSHIP_VALUES
        ):
            raise ValueError("S3 ownership-control evidence is malformed")
        normalized.append({"object_ownership": rule["object_ownership"]})
    if rules != sorted(rules, key=lambda item: item["object_ownership"]):
        raise ValueError("S3 ownership-control evidence is not canonical")
    return {"rules": normalized}


def _validate_s3_encryption_value(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"rules"}:
        raise ValueError("S3 encryption evidence is malformed")
    rules = value["rules"]
    if not isinstance(rules, list) or not rules:
        raise ValueError("S3 encryption evidence is malformed")
    normalized: list[dict[str, object]] = []
    for rule in rules:
        if not isinstance(rule, Mapping) or set(rule) != {
            "sse_algorithm",
            "kms_key_reference",
            "kms_reference_explicit",
            "key_management",
            "bucket_key_enabled",
            "blocked_encryption_types",
        }:
            raise ValueError("S3 encryption rule evidence is malformed")
        algorithm = rule["sse_algorithm"]
        reference = rule["kms_key_reference"]
        blocked_types = rule["blocked_encryption_types"]
        if (
            algorithm is not None
            and algorithm not in _S3_ENCRYPTION_ALGORITHMS
            or reference is not None
            and not _is_safe_non_empty_string(reference)
            or not isinstance(blocked_types, list)
            or any(item not in _S3_BLOCKED_ENCRYPTION_TYPES for item in blocked_types)
            or blocked_types
            and (len(blocked_types) != 1 or blocked_types != sorted(blocked_types))
            or algorithm is None
            and not blocked_types
        ):
            raise ValueError("S3 encryption rule evidence is malformed")
        if reference is not None and algorithm not in _S3_KMS_ENCRYPTION_ALGORITHMS:
            raise ValueError("S3 encryption KMS reference contradicts its algorithm")
        expected_management = None if algorithm is None else "SERVICE_SPECIFIC"
        if algorithm == "AES256":
            expected_management = "S3_MANAGED"
        elif algorithm in _S3_KMS_ENCRYPTION_ALGORITHMS and reference is None:
            expected_management = "IMPLICIT_AWS_MANAGED_KMS"
        elif algorithm in _S3_KMS_ENCRYPTION_ALGORITHMS:
            expected_management = "EXPLICIT_KMS_REFERENCE"
        if (
            not isinstance(rule["kms_reference_explicit"], bool)
            or rule["kms_reference_explicit"] is not (reference is not None)
            or rule["key_management"] != expected_management
            or (
                rule["bucket_key_enabled"] is not None
                and not isinstance(rule["bucket_key_enabled"], bool)
            )
            or (rule["bucket_key_enabled"] is True and algorithm != "aws:kms")
        ):
            raise ValueError("S3 encryption rule evidence is inconsistent")
        normalized.append(dict(rule))
    if rules != sorted(rules, key=_canonical_json):
        raise ValueError("S3 encryption rule evidence is not canonical")
    return {"rules": normalized}


def normalize_s3_legacy_encryption_value(value: object) -> dict[str, object]:
    """Normalize the accepted S3-900 response shape for semantic readback binding."""

    if not isinstance(value, Mapping):
        raise ValueError("legacy S3 encryption configuration must be an object")
    rules = value.get("Rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("legacy S3 encryption configuration has no rules")
    normalized: list[dict[str, object]] = []
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise ValueError("legacy S3 encryption rule is malformed")
        defaults = rule.get("ApplyServerSideEncryptionByDefault")
        algorithm = None
        reference = None
        if defaults is not None:
            if not isinstance(defaults, Mapping):
                raise ValueError("legacy S3 encryption defaults are malformed")
            algorithm = defaults.get("SSEAlgorithm")
            reference = defaults.get("KMSMasterKeyID")
            if algorithm not in _S3_ENCRYPTION_ALGORITHMS or (
                reference is not None and not _is_safe_non_empty_string(reference)
            ):
                raise ValueError("legacy S3 encryption defaults are malformed")
        if reference is not None and algorithm not in _S3_KMS_ENCRYPTION_ALGORITHMS:
            raise ValueError("legacy S3 encryption reference contradicts its algorithm")
        blocked = rule.get("BlockedEncryptionTypes")
        blocked_types: list[str] = []
        if blocked is not None:
            if not isinstance(blocked, Mapping) or set(blocked) != {"EncryptionType"}:
                raise ValueError("legacy S3 blocked-encryption configuration is malformed")
            raw_types = blocked["EncryptionType"]
            if (
                not isinstance(raw_types, list)
                or len(raw_types) != 1
                or any(item not in _S3_BLOCKED_ENCRYPTION_TYPES for item in raw_types)
            ):
                raise ValueError("legacy S3 blocked-encryption configuration is malformed")
            blocked_types = sorted(raw_types)
        if algorithm is None and not blocked_types:
            raise ValueError("legacy S3 encryption rule is empty")
        bucket_key_enabled = rule.get("BucketKeyEnabled")
        if (
            bucket_key_enabled is not None
            and not isinstance(bucket_key_enabled, bool)
            or bucket_key_enabled is True
            and algorithm != "aws:kms"
        ):
            raise ValueError("legacy S3 bucket-key configuration is malformed")
        key_management = None if algorithm is None else "SERVICE_SPECIFIC"
        if algorithm == "AES256":
            key_management = "S3_MANAGED"
        elif algorithm in _S3_KMS_ENCRYPTION_ALGORITHMS and reference is None:
            key_management = "IMPLICIT_AWS_MANAGED_KMS"
        elif algorithm in _S3_KMS_ENCRYPTION_ALGORITHMS:
            key_management = "EXPLICIT_KMS_REFERENCE"
        normalized.append(
            {
                "sse_algorithm": algorithm,
                "kms_key_reference": reference,
                "kms_reference_explicit": reference is not None,
                "key_management": key_management,
                "bucket_key_enabled": bucket_key_enabled,
                "blocked_encryption_types": blocked_types,
            }
        )
    normalized.sort(key=_canonical_json)
    return {"rules": normalized}


def _validate_s3_policy_value(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"document", "sha256"}:
        raise ValueError("S3 policy evidence is malformed")
    document = value["document"]
    digest = value["sha256"]
    if (
        not isinstance(document, Mapping)
        or set(document) != {"Version", "Id", "Statement"}
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or digest != _sha256_json(document)
        or (document["Version"] is not None and not isinstance(document["Version"], str))
        or (document["Id"] is not None and not isinstance(document["Id"], str))
        or not isinstance(document["Statement"], list)
        or not document["Statement"]
    ):
        raise ValueError("S3 policy evidence is malformed")
    for statement in document["Statement"]:
        _validate_s3_policy_statement(statement)
    return {"document": dict(document), "sha256": digest}


def _s3_policy_has_unconditional_public_grant(policy: Mapping[str, object]) -> bool:
    document = policy["document"]
    if not isinstance(document, Mapping):  # pragma: no cover - validated caller invariant
        raise TypeError("validated S3 policy document must be a mapping")
    statements = document["Statement"]
    if not isinstance(statements, list):  # pragma: no cover - validated caller invariant
        raise TypeError("validated S3 policy statements must be a list")
    for statement in statements:
        if not isinstance(statement, Mapping):  # pragma: no cover - validated caller invariant
            raise TypeError("validated S3 policy statement must be a mapping")
        if (
            statement.get("Effect") != "Allow"
            or "Condition" in statement
            or "Principal" not in statement
            or "Action" not in statement
            or "Resource" not in statement
        ):
            continue
        principal = statement["Principal"]
        principal_values: object = principal
        if isinstance(principal, Mapping):
            principal_values = principal.get("AWS")
        if not _s3_policy_value_contains(principal_values, "*"):
            continue
        actions = _s3_policy_values(statement["Action"])
        resources = _s3_policy_values(statement["Resource"])
        if any(action == "*" or action.casefold().startswith("s3:") for action in actions) and any(
            resource == "*" or resource.startswith("arn:") and ":s3:::" in resource
            for resource in resources
        ):
            return True
    return False


def _s3_policy_value_contains(value: object, expected: str) -> bool:
    return expected in _s3_policy_values(value)


def _s3_policy_values(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    return ()


def _validate_s3_policy_statement(statement: object) -> None:
    allowed = {
        "Sid",
        "Effect",
        "Principal",
        "NotPrincipal",
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
        "Condition",
    }
    if (
        not isinstance(statement, Mapping)
        or not set(statement).issubset(allowed)
        or statement.get("Effect") not in {"Allow", "Deny"}
        or sum(key in statement for key in ("Principal", "NotPrincipal")) != 1
        or sum(key in statement for key in ("Action", "NotAction")) != 1
        or sum(key in statement for key in ("Resource", "NotResource")) != 1
        or ("Sid" in statement and not _is_non_empty_string(statement["Sid"]))
    ):
        raise ValueError("S3 policy statement evidence is malformed")
    principal_key = "Principal" if "Principal" in statement else "NotPrincipal"
    principal = statement[principal_key]
    if isinstance(principal, Mapping):
        if not principal or any(
            not _is_non_empty_string(key) or not _valid_policy_string_or_list(item)
            for key, item in principal.items()
        ):
            raise ValueError("S3 policy principal evidence is malformed")
    elif not _is_non_empty_string(principal):
        raise ValueError("S3 policy principal evidence is malformed")
    for alternatives in (("Action", "NotAction"), ("Resource", "NotResource")):
        key = next(item for item in alternatives if item in statement)
        if not _valid_policy_string_or_list(statement[key]):
            raise ValueError("S3 policy statement evidence is malformed")
    if "Condition" in statement:
        condition = statement["Condition"]
        if not isinstance(condition, Mapping) or not condition:
            raise ValueError("S3 policy condition evidence is malformed")
        for operator, entries in condition.items():
            if (
                not _is_non_empty_string(operator)
                or not isinstance(entries, Mapping)
                or not entries
                or any(
                    not _is_non_empty_string(key) or not _valid_policy_string_or_list(item)
                    for key, item in entries.items()
                )
            ):
                raise ValueError("S3 policy condition evidence is malformed")


def _valid_policy_string_or_list(value: object) -> bool:
    if _is_non_empty_string(value):
        return True
    return bool(
        isinstance(value, list) and value and all(_is_non_empty_string(item) for item in value)
    )


def _is_non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _is_safe_non_empty_string(value: object) -> bool:
    return bool(
        _is_non_empty_string(value)
        and not any(separator in value for separator in ("\x00", "\x1f", "\r", "\n"))
    )


def calculate_source_artifact_id(*, scan_id: UUID, evidence_reference: str) -> UUID:
    """Identify a normalized artifact by scan and its opaque reference."""

    document = {
        "evidence_reference": evidence_reference,
        "scan_id": str(scan_id),
    }
    return uuid5(_SOURCE_ARTIFACT_NAMESPACE, _canonical_json(document))


def calculate_evidence_sha256(payload: object) -> str:
    """Digest one normalized JSON payload using the canonical repository encoding."""

    return _sha256_json(_thaw_json(payload))


class _FrozenJsonObject(dict[str, object]):
    """JSON mapping that rejects in-place mutation while retaining standard serialization."""

    def _immutable(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("normalized evidence payload is immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable


def _canonical_json_value(value: object) -> object:
    try:
        encoded = _canonical_json(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("normalized evidence payload must contain finite JSON values") from exc
    return json.loads(encoded)


def _canonical_json(value: object) -> str:
    return json.dumps(
        _thaw_json(value),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _freeze_json(value: object) -> object:
    if isinstance(value, dict):
        return _FrozenJsonObject({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _reject_sensitive_keys(value: object) -> None:
    forbidden = {
        "accesskeyid",
        "accesstoken",
        "authorization",
        "authorizationtoken",
        "authtoken",
        "awsaccesskeyid",
        "awssecretaccesskey",
        "awssecuritytoken",
        "awssessiontoken",
        "clientsecret",
        "idtoken",
        "password",
        "privatekey",
        "refreshtoken",
        "secretaccesskey",
        "secretkey",
        "securitytoken",
        "sessiontoken",
    }
    if isinstance(value, Mapping):
        for key, item in value.items():
            canonical_key = "".join(
                character
                for character in key.casefold()
                if "a" <= character <= "z" or "0" <= character <= "9"
            )
            if canonical_key in forbidden:
                raise ValueError("normalized evidence payload contains a forbidden sensitive key")
            _reject_sensitive_keys(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _reject_sensitive_keys(item)


def _deduplicate_records[T](
    records: Iterable[T],
    *,
    key: Any,
    conflict_message: str,
) -> tuple[T, ...]:
    deduplicated: dict[UUID, T] = {}
    for record in records:
        record_id = key(record)
        existing = deduplicated.get(record_id)
        if existing is None:
            deduplicated[record_id] = record
        elif existing != record:
            raise ValueError(conflict_message)
    ordered_ids = sorted(deduplicated, key=lambda item: item.hex)
    return tuple(deduplicated[item_id] for item_id in ordered_ids)


type SourceProvenanceKey = tuple[str, str, str, str, str, datetime]


def source_provenance_key(
    observation: RelationshipProvenance | SourceEvidenceOutcome,
) -> SourceProvenanceKey:
    """Key the exact existing equality fields without ambiguous string serialization."""

    return (
        observation.collector,
        observation.collector_version,
        observation.source,
        observation.source_api,
        observation.evidence_reference,
        observation.collected_at,
    )


def index_source_outcomes_by_provenance(
    outcomes: Iterable[SourceEvidenceOutcome],
) -> dict[SourceProvenanceKey, list[SourceEvidenceOutcome]]:
    """Index once per operation, retaining every match so ambiguity still fails closed."""

    indexed: dict[SourceProvenanceKey, list[SourceEvidenceOutcome]] = {}
    for outcome in outcomes:
        indexed.setdefault(source_provenance_key(outcome), []).append(outcome)
    return indexed


def _provenance_matches_outcome(
    provenance: RelationshipProvenance,
    outcome: SourceEvidenceOutcome,
) -> bool:
    return source_provenance_key(provenance) == source_provenance_key(outcome)


def _require_resource_subject(
    subject: ResourceEvidenceSubject,
    resources: Mapping[UUID, NormalizedResource],
) -> NormalizedResource:
    resource = resources.get(subject.resource_snapshot_id)
    if resource is None or not _resource_matches_subject(resource, subject):
        raise ValueError("resource evidence subject requires an exact top-level resource snapshot")
    return resource


def _require_relationship_endpoint(
    endpoint: RelationshipEndpoint,
    resources: Mapping[UUID, NormalizedResource],
) -> NormalizedResource:
    if endpoint.resource_snapshot_id is None:
        raise ValueError("relationship endpoint requires a resource snapshot")
    resource = resources.get(endpoint.resource_snapshot_id)
    if resource is None or not _resource_matches_endpoint(resource, endpoint):
        raise ValueError("relationship endpoint requires an exact top-level resource snapshot")
    return resource


def _resource_matches_subject(
    resource: NormalizedResource,
    subject: ResourceEvidenceSubject,
) -> bool:
    return (
        resource.account_id,
        resource.service,
        resource.resource_type,
        resource.aws_resource_id,
        resource.scope,
        resource.region,
    ) == (
        subject.aws_account_id,
        subject.service,
        subject.resource_type,
        subject.aws_resource_id,
        subject.scope,
        subject.region,
    )


def _resource_matches_endpoint(
    resource: NormalizedResource,
    endpoint: RelationshipEndpoint,
) -> bool:
    return (
        resource.account_id,
        resource.service,
        resource.resource_type,
        resource.aws_resource_id,
        resource.scope,
        resource.region,
    ) == (
        endpoint.aws_account_id,
        endpoint.service,
        endpoint.resource_type,
        endpoint.aws_resource_id,
        endpoint.scope,
        endpoint.region,
    )


def _validate_resource_admission(
    *,
    resource: NormalizedResource,
    contracts: Iterable[ScanSourceContract],
    collection_account_id: str,
    requested_region: str,
    referenced_by_resolved_relationship: bool,
    referenced_by_resolved_s3_encryption: bool,
    s3_region_evidence: S3BucketRegionEvidence | None,
) -> None:
    contracts_tuple = tuple(contracts)
    required_owner_mode = ResourceOwnerMode.COLLECTION_ACCOUNT
    if resource.account_id == "aws":
        required_owner_mode = ResourceOwnerMode.AWS_MANAGED
    elif resource.account_id != collection_account_id:
        required_owner_mode = ResourceOwnerMode.EXTERNAL_ACCOUNT

    if required_owner_mode is not ResourceOwnerMode.COLLECTION_ACCOUNT and not any(
        contract.identity_authoritative and contract.owner_mode is required_owner_mode
        for contract in contracts_tuple
    ):
        raise ValueError("resource owner requires matching identity-authoritative evidence")

    if (
        required_owner_mode is ResourceOwnerMode.EXTERNAL_ACCOUNT
        and not referenced_by_resolved_relationship
    ):
        raise ValueError("external-account resources require an exact resolved relationship")

    if (resource.service, resource.resource_type) == ("kms", "kms_key"):
        if not any(_is_authoritative_kms_key_source(contract) for contract in contracts_tuple):
            raise ValueError("KMS keys require authoritative same-scan DescribeKey evidence")
        if not referenced_by_resolved_s3_encryption:
            raise ValueError("KMS keys require an exact resolved S3 encryption relationship")

    if (
        s3_region_evidence is not None
        and resource.account_id == collection_account_id
        and (resource.service, resource.resource_type) == ("s3", "s3_bucket")
    ):
        authoritative_region = s3_region_evidence.region_for(resource.aws_resource_id)
        if authoritative_region is not None and authoritative_region != resource.region:
            raise ValueError(
                "S3 bucket Region contradicts authoritative same-scan location evidence"
            )
        if authoritative_region is None and contracts_tuple:
            raise ValueError("5E S3 bucket evidence requires authoritative same-scan location")

    legacy_supplemental_region = not contracts_tuple and (
        resource.service,
        resource.resource_type,
    ) in {
        ("cloudtrail", "cloudtrail_trail"),
        ("s3", "s3_bucket"),
    }
    if (
        resource.scope is ResourceScope.REGIONAL
        and resource.region != requested_region
        and not legacy_supplemental_region
        and not (
            (resource.service, resource.resource_type) == ("s3", "s3_bucket")
            and resource.account_id == collection_account_id
            and s3_region_evidence is not None
            and s3_region_evidence.region_for(resource.aws_resource_id) == resource.region
        )
        and not (
            (resource.service, resource.resource_type) == ("kms", "kms_key")
            and any(_is_authoritative_kms_key_source(contract) for contract in contracts_tuple)
            and referenced_by_resolved_s3_encryption
        )
        and not (
            (resource.service, resource.resource_type) == ("cloudtrail", "cloudtrail_trail")
            and any(
                _is_authoritative_cloudtrail_identity_source(contract)
                for contract in contracts_tuple
            )
        )
        and not any(contract.allows_supplemental_region for contract in contracts_tuple)
    ):
        raise ValueError("resource Region requires declared supplemental-Region evidence")


def _is_authoritative_kms_key_source(contract: ScanSourceContract) -> bool:
    """Recognize only the 5E DescribeKey identity proof for a canonical KMS key."""

    subject = contract.subject
    prefix = "kms.key."
    digest = contract.evidence_kind.removeprefix(prefix)
    return all(
        (
            contract.phase is EvidenceCollectionPhase.ENRICHMENT,
            isinstance(subject, ResourceEvidenceSubject),
            subject.service == "kms" if isinstance(subject, ResourceEvidenceSubject) else False,
            subject.resource_type == "kms_key"
            if isinstance(subject, ResourceEvidenceSubject)
            else False,
            contract.contract_key == contract.evidence_kind,
            contract.evidence_kind.startswith(prefix),
            len(digest) == 64,
            all(character in "0123456789abcdef" for character in digest),
            contract.collector == "kms.keys",
            contract.collector_version == "1.0.0",
            contract.source_api == "kms:DescribeKey",
            contract.identity_authoritative,
        )
    )


def _is_authoritative_cloudtrail_identity_source(contract: ScanSourceContract) -> bool:
    """Recognize only 5F ListTrails proof for one exact trail subject/home Region."""

    subject = contract.subject
    expected = _CLOUDTRAIL_SOURCE_IDENTITIES["cloudtrail.trail.identity"]
    return bool(
        isinstance(subject, ResourceEvidenceSubject)
        and subject.service == "cloudtrail"
        and subject.resource_type == "cloudtrail_trail"
        and subject.scope is ResourceScope.REGIONAL
        and contract.contract_key == "cloudtrail.trail.identity"
        and contract.contract_version == "1.0.0"
        and contract.evidence_kind == "cloudtrail.trail.identity"
        and contract.collector == expected[0]
        and contract.collector_version == "1.0.0"
        and contract.source_api == expected[1]
        and contract.phase is EvidenceCollectionPhase.ENRICHMENT
        and contract.cardinality is EvidenceCardinality.SINGLE
        and contract.identity_authoritative
        and not contract.allows_supplemental_region
    )


def _is_s3_encryption_reference_source(outcome: SourceEvidenceOutcome) -> bool:
    subject = outcome.subject
    return all(
        (
            outcome.state is EvidenceSourceState.PRESENT,
            outcome.phase is EvidenceCollectionPhase.ENRICHMENT,
            isinstance(subject, ResourceEvidenceSubject),
            subject.service == "s3" if isinstance(subject, ResourceEvidenceSubject) else False,
            subject.resource_type == "s3_bucket"
            if isinstance(subject, ResourceEvidenceSubject)
            else False,
            outcome.evidence_kind == "s3.bucket-encryption",
            outcome.collector == "s3.bucket-encryption",
            outcome.collector_version == "1.0.0",
            outcome.source_api == "s3:GetEncryptionConfiguration",
        )
    )
