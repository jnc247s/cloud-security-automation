"""S3 bucket inventory and Sprint 5E fact-only evidence collection."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import (
    EvidenceCardinality,
    kms_reference_matches_key_identity,
    s3_acl_ownership_conflicts,
    s3_acl_public_access_conflicts,
    s3_encryption_kms_references,
    s3_policy_evidence_conflicts,
    validate_kms_key_evidence_value,
    validate_s3_bucket_evidence_value,
)
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipType,
    UnresolvedRelationshipTarget,
)
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
)
from app.aws.client import AWSClientProvider
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceConflictError,
    CollectorEvidenceError,
    CollectorResult,
    RelationshipReference,
    ResourceCollector,
    SourceObservation,
    build_source_observation,
    collection_status_for,
    iter_paginated_items,
    require_boolean,
    require_datetime,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    require_string,
    should_skip_exact_duplicate,
    source_failure,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import NormalizedResource, ResourceScope

_MISSING_TAG_CODES = {"NoSuchTagSet"}
_MISSING_ENCRYPTION_CODES = {"ServerSideEncryptionConfigurationNotFoundError"}
_MISSING_PUBLIC_ACCESS_BLOCK_CODES = {"NoSuchPublicAccessBlockConfiguration"}
_MISSING_POLICY_CODES = {"NoSuchBucketPolicy"}
_MISSING_OWNERSHIP_CONTROLS_CODES = {"OwnershipControlsNotFoundError"}
_RESOURCE_DISAPPEARED_CODES = {"NoSuchBucket", "NotFound", "404"}
_AWS_REGION_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+-[0-9]+$", re.ASCII)
_S3_ENCRYPTION_ALGORITHMS = {
    "AES256",
    "aws:backup",
    "aws:fsx",
    "aws:kms",
    "aws:kms:dsse",
}
_KMS_ENCRYPTION_ALGORITHMS = {"aws:kms", "aws:kms:dsse"}
_BLOCKED_ENCRYPTION_TYPES = {"NONE", "SSE-C"}
_PUBLIC_ACCESS_BLOCK_FIELDS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)
_ACL_PERMISSIONS = {"FULL_CONTROL", "WRITE", "WRITE_ACP", "READ", "READ_ACP"}
_ACL_GRANTEE_TYPES = {"CanonicalUser", "AmazonCustomerByEmail", "Group"}
_ACL_GRANTEE_IDENTITY_FIELDS = {"ID", "URI", "EmailAddress", "DisplayName"}
_ACL_GRANTEE_ALLOWED_FIELDS = {
    "CanonicalUser": {"ID", "DisplayName"},
    "AmazonCustomerByEmail": {"EmailAddress"},
    "Group": {"URI"},
}
_VERSIONING_STATUSES = {"Enabled", "Suspended"}
_MFA_DELETE_STATUSES = {"Enabled", "Disabled"}
_OBJECT_OWNERSHIP_VALUES = {
    "BucketOwnerPreferred",
    "ObjectWriter",
    "BucketOwnerEnforced",
}
_KMS_KEY_MANAGERS = {"AWS", "CUSTOMER"}
_EXPECTED_FAILURES = (BotoCoreError, ClientError, CollectorEvidenceError)
_COLLECTOR_VERSION = "1.0.0"
_CONTRACT_VERSION = "1.0.0"
_EVIDENCE_SCHEMA_VERSION = "1.0.0"


class S3BucketCollector(ResourceCollector):
    """Collect account buckets and selected configuration facts."""

    collector_name = "s3_buckets"

    def __init__(
        self,
        client_provider: AWSClientProvider,
        *,
        collection_bundle: S3CollectionBundle | None = None,
    ) -> None:
        super().__init__(client_provider)
        self.collection_bundle = collection_bundle

    def collect(self) -> list[NormalizedResource]:
        """Preserve the accepted graphless Sprint 1 collector behavior exactly."""

        discovery_client = self.client_provider.client("s3")
        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []
        seen_buckets: dict[str, dict[str, Any]] = {}

        for bucket in iter_paginated_items(
            discovery_client,
            "list_buckets",
            "Buckets",
            PaginationConfig={"PageSize": 1000},
        ):
            bucket_name = require_non_empty_string(
                require_member(
                    bucket,
                    "Name",
                    operation_name="list_buckets",
                    fact_path="Buckets[].Name",
                ),
                operation_name="list_buckets",
                fact_path="Buckets[].Name",
            )
            self._validate_bucket_summary(bucket)
            if should_skip_exact_duplicate(
                seen_buckets,
                bucket_name,
                bucket,
                operation_name="list_buckets",
                fact_path="Buckets[].duplicate_identity",
            ):
                continue
            bucket_region = self._resolve_bucket_region(
                discovery_client,
                bucket,
                account_id,
            )
            regional_client = self.client_provider.client(
                "s3",
                region_name=bucket_region,
            )
            tags = self._get_tags(regional_client, bucket_name, account_id)
            encryption = self._get_optional_configuration(
                regional_client,
                operation_name="get_bucket_encryption",
                result_key="ServerSideEncryptionConfiguration",
                missing_codes=_MISSING_ENCRYPTION_CODES,
                bucket_name=bucket_name,
                account_id=account_id,
            )
            if encryption is not None:
                self._validate_encryption(encryption)
            public_access_block = self._get_optional_configuration(
                regional_client,
                operation_name="get_public_access_block",
                result_key="PublicAccessBlockConfiguration",
                missing_codes=_MISSING_PUBLIC_ACCESS_BLOCK_CODES,
                bucket_name=bucket_name,
                account_id=account_id,
            )
            if public_access_block is not None:
                self._validate_public_access_block(public_access_block)

            configuration = {
                "creation_date": to_json_safe(bucket.get("CreationDate")),
                "bucket_region": bucket_region,
                "default_encryption": to_json_safe(encryption),
                "public_access_block": to_json_safe(public_access_block),
            }

            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="s3",
                    resource_type="s3_bucket",
                    aws_resource_id=bucket_name,
                    arn=f"arn:{self.client_provider.partition}:s3:::{bucket_name}",
                    name=bucket_name,
                    scope=ResourceScope.REGIONAL,
                    region=bucket_region,
                    tags=tags,
                    configuration=configuration,
                    raw_configuration={
                        "bucket": to_json_safe(bucket),
                        "default_encryption": to_json_safe(encryption),
                        "public_access_block": to_json_safe(public_access_block),
                    },
                )
            )

        return resources

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Project the shared 5E bundle without changing the legacy completeness gate."""

        if self.collection_bundle is None:
            return super().collect_with_context(context)
        collected = self.collection_bundle.collect(context)
        return CollectorResult(
            resources=collected.bucket_resources,
            status=collected.legacy_status,
        )

    @staticmethod
    def _validate_bucket_summary(bucket: dict[str, Any]) -> None:
        """Validate optional discovery facts when AWS supplied them."""

        if bucket.get("CreationDate") is not None:
            require_datetime(
                bucket["CreationDate"],
                operation_name="list_buckets",
                fact_path="Buckets[].CreationDate",
            )
        if "BucketRegion" in bucket:
            require_non_empty_string(
                bucket["BucketRegion"],
                operation_name="list_buckets",
                fact_path="Buckets[].BucketRegion",
            )

    def _resolve_bucket_region(
        self,
        client: Any,
        bucket: dict[str, Any],
        account_id: str,
    ) -> str:
        if "BucketRegion" in bucket:
            return _normalize_location_constraint(
                bucket["BucketRegion"],
                operation_name="list_buckets",
                fact_path="Buckets[].BucketRegion",
                allow_null=False,
            )

        bucket_name = require_non_empty_string(
            require_member(
                bucket,
                "Name",
                operation_name="list_buckets",
                fact_path="Buckets[].Name",
            ),
            operation_name="list_buckets",
            fact_path="Buckets[].Name",
        )
        return _normalize_head_bucket_region(
            client.head_bucket(
                Bucket=bucket_name,
                ExpectedBucketOwner=account_id,
            )
        )

    @staticmethod
    def _get_tags(client: Any, bucket_name: str, account_id: str) -> dict[str, str]:
        try:
            response = client.get_bucket_tagging(
                Bucket=bucket_name,
                ExpectedBucketOwner=account_id,
            )
        except ClientError as error:
            if _error_code(error) in _MISSING_TAG_CODES:
                return {}
            raise

        response = require_mapping(
            response,
            operation_name="get_bucket_tagging",
            fact_path="response",
        )
        tag_set = require_list(
            require_member(
                response,
                "TagSet",
                operation_name="get_bucket_tagging",
                fact_path="TagSet",
            ),
            operation_name="get_bucket_tagging",
            fact_path="TagSet",
        )
        return tags_to_dict(
            tag_set,
            operation_name="get_bucket_tagging",
            fact_path="TagSet",
        )

    @staticmethod
    def _get_optional_configuration(
        client: Any,
        *,
        operation_name: str,
        result_key: str,
        missing_codes: set[str],
        bucket_name: str,
        account_id: str,
    ) -> dict[str, Any] | None:
        try:
            response = getattr(client, operation_name)(
                Bucket=bucket_name,
                ExpectedBucketOwner=account_id,
            )
        except ClientError as error:
            if _error_code(error) in missing_codes:
                return None
            raise

        response = require_mapping(
            response,
            operation_name=operation_name,
            fact_path="response",
        )
        return require_mapping(
            require_member(
                response,
                result_key,
                operation_name=operation_name,
                fact_path=result_key,
            ),
            operation_name=operation_name,
            fact_path=result_key,
        )

    @staticmethod
    def _validate_encryption(configuration: dict[str, Any]) -> None:
        rules = require_list(
            require_member(
                configuration,
                "Rules",
                operation_name="get_bucket_encryption",
                fact_path="ServerSideEncryptionConfiguration.Rules",
            ),
            operation_name="get_bucket_encryption",
            fact_path="ServerSideEncryptionConfiguration.Rules",
        )
        if not rules:
            raise CollectorEvidenceError(
                "get_bucket_encryption",
                "ServerSideEncryptionConfiguration.Rules",
            )
        for rule_index, raw_rule in enumerate(rules):
            rule_path = f"ServerSideEncryptionConfiguration.Rules[{rule_index}]"
            rule = require_mapping(
                raw_rule,
                operation_name="get_bucket_encryption",
                fact_path=rule_path,
            )
            if "ApplyServerSideEncryptionByDefault" in rule:
                defaults = require_mapping(
                    rule["ApplyServerSideEncryptionByDefault"],
                    operation_name="get_bucket_encryption",
                    fact_path=f"{rule_path}.ApplyServerSideEncryptionByDefault",
                )
                algorithm_path = f"{rule_path}.ApplyServerSideEncryptionByDefault.SSEAlgorithm"
                algorithm = require_non_empty_string(
                    require_member(
                        defaults,
                        "SSEAlgorithm",
                        operation_name="get_bucket_encryption",
                        fact_path=algorithm_path,
                    ),
                    operation_name="get_bucket_encryption",
                    fact_path=algorithm_path,
                )
                if algorithm not in _S3_ENCRYPTION_ALGORITHMS:
                    raise CollectorEvidenceError(
                        "get_bucket_encryption",
                        algorithm_path,
                    )
                if "KMSMasterKeyID" in defaults:
                    require_non_empty_string(
                        defaults["KMSMasterKeyID"],
                        operation_name="get_bucket_encryption",
                        fact_path=(
                            f"{rule_path}.ApplyServerSideEncryptionByDefault.KMSMasterKeyID"
                        ),
                    )
            if "BucketKeyEnabled" in rule:
                require_boolean(
                    rule["BucketKeyEnabled"],
                    operation_name="get_bucket_encryption",
                    fact_path=f"{rule_path}.BucketKeyEnabled",
                )

    @staticmethod
    def _validate_public_access_block(configuration: dict[str, Any]) -> None:
        for field_name in _PUBLIC_ACCESS_BLOCK_FIELDS:
            if field_name in configuration:
                require_boolean(
                    configuration[field_name],
                    operation_name="get_public_access_block",
                    fact_path=f"PublicAccessBlockConfiguration.{field_name}",
                )


def _error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", "Unknown"))


@dataclass(frozen=True, slots=True)
class _SourceValue:
    """One independently collected and normalized AWS response."""

    value: object | None = None
    error: BaseException | None = None
    expected_absence: bool = False
    details: Mapping[str, object] | None = None


def _reconcile_policy_sources(
    policy: _SourceValue,
    policy_status: _SourceValue,
) -> tuple[_SourceValue, _SourceValue]:
    """Retain contradictory policy facts as paired fail-closed source outcomes."""

    if policy.error is not None or policy_status.error is not None:
        return policy, policy_status
    if not s3_policy_evidence_conflicts(
        policy_value=policy.value,
        status_value=policy_status.value,
    ):
        return policy, policy_status
    conflict = CollectorEvidenceConflictError(
        "get_bucket_policy_status",
        "PolicyStatus.coherence",
    )
    return (
        _SourceValue(value=policy.value, error=conflict, details=policy.details),
        _SourceValue(
            value=policy_status.value,
            error=conflict,
            details=policy_status.details,
        ),
    )


def _reconcile_acl_sources(
    *,
    acl: _SourceValue,
    account_public_access_block: _SourceValue,
    bucket_public_access_block: _SourceValue,
    ownership_controls: _SourceValue,
) -> _SourceValue:
    """Retain impossible effective ACL combinations as fail-closed evidence."""

    if acl.error is not None or acl.value is None:
        return acl
    account_block = (
        account_public_access_block.value if account_public_access_block.error is None else None
    )
    bucket_block = (
        bucket_public_access_block.value if bucket_public_access_block.error is None else None
    )
    ownership = ownership_controls.value if ownership_controls.error is None else None
    if not (
        s3_acl_public_access_conflicts(
            acl_value=acl.value,
            account_public_access_block_value=account_block,
            bucket_public_access_block_value=bucket_block,
        )
        or s3_acl_ownership_conflicts(
            acl_value=acl.value,
            ownership_controls_value=ownership,
        )
    ):
        return acl
    return _SourceValue(
        value=acl.value,
        error=CollectorEvidenceConflictError("get_bucket_acl", "Grants.coherence"),
        details=acl.details,
    )


@dataclass(frozen=True, slots=True)
class _BucketRecord:
    """All source-independent evidence retained for one discovered bucket."""

    bucket_name: str
    bucket_arn: str
    summary: Mapping[str, object]
    list_bucket_region: str | None
    evidence_admitted: bool
    location: _SourceValue
    legacy_region: _SourceValue
    tags: _SourceValue | None = None
    public_access_block: _SourceValue | None = None
    policy: _SourceValue | None = None
    policy_status: _SourceValue | None = None
    acl: _SourceValue | None = None
    versioning: _SourceValue | None = None
    encryption: _SourceValue | None = None
    ownership_controls: _SourceValue | None = None
    kms_references: tuple[str, ...] = ()
    resource: NormalizedResource | None = None
    evidence_resource: NormalizedResource | None = None


@dataclass(slots=True)
class _KMSLookup:
    """A deduplicated DescribeKey lookup and the buckets that supplied its reference."""

    region: str
    supplied_reference: str
    bucket_names: tuple[str, ...]
    result: _SourceValue
    resource: NormalizedResource | None


@dataclass(frozen=True, slots=True)
class _BundleResult:
    """Immutable projection shared by the legacy and graph-aware S3 collectors."""

    discovery: _SourceValue
    account_public_access_block: _SourceValue
    bucket_records: tuple[_BucketRecord, ...]
    kms_lookups: tuple[_KMSLookup, ...]
    bucket_resources: tuple[NormalizedResource, ...]
    evidence_only_bucket_resources: tuple[NormalizedResource, ...]
    kms_resources: tuple[NormalizedResource, ...]
    legacy_status: CollectionStatus


class S3CollectionBundle:
    """Collect the 5E S3/KMS API bundle once for each immutable scan context.

    Inventory constructs one bundle and injects it into both S3 projections. The cache is keyed by
    scan ID so reusing an InventoryService for a later scan never reuses historical AWS facts.
    """

    def __init__(self, client_provider: AWSClientProvider) -> None:
        self.client_provider = client_provider
        self._scan_id: UUID | None = None
        self._result: _BundleResult | None = None

    def collect(self, context: CollectionContext) -> _BundleResult:
        """Return the one complete collection bundle for ``context.scan_id``."""

        if context.collection_account_id != self.client_provider.account_id:
            raise ValueError("collection context account does not match the AWS client provider")
        if context.region != self.client_provider.region_name:
            raise ValueError("collection context Region does not match the AWS client provider")
        if self._scan_id == context.scan_id and self._result is not None:
            return self._result

        result = self._collect(context)
        self._scan_id = context.scan_id
        self._result = result
        return result

    def _collect(self, context: CollectionContext) -> _BundleResult:
        discovery_client = self.client_provider.client("s3")
        discovery = self._collect_bucket_summaries(discovery_client, context)
        account_bpa = self._collect_account_public_access_block(context)

        summaries = discovery.value if isinstance(discovery.value, tuple) else ()
        admitted_names = {
            str(summary["bucket_name"]) for summary in summaries if isinstance(summary, Mapping)
        }
        legacy_summaries = (
            discovery.details.get("legacy_summaries") if discovery.details is not None else None
        )
        if not isinstance(legacy_summaries, tuple):  # pragma: no cover - bundle invariant
            raise TypeError("S3 discovery omitted its legacy execution summaries")
        records: list[_BucketRecord] = []
        kms_reference_buckets: dict[tuple[str, str], set[str]] = {}

        for summary in legacy_summaries:
            if not isinstance(summary, Mapping):  # pragma: no cover - internal invariant
                raise TypeError("normalized bucket summary must be a mapping")
            bucket_name = str(summary["bucket_name"])
            bucket_arn = str(summary["bucket_arn"])
            evidence_admitted = bucket_name in admitted_names
            list_region = summary.get("list_bucket_region")
            if list_region is not None and not isinstance(list_region, str):  # pragma: no cover
                raise TypeError("normalized ListBuckets Region must be a string")
            location = (
                self._collect_bucket_location(
                    client=discovery_client,
                    bucket_name=bucket_name,
                    account_id=context.collection_account_id,
                    list_bucket_region=list_region,
                )
                if evidence_admitted
                else _SourceValue(
                    error=CollectorEvidenceConflictError(
                        "list_buckets", "Buckets[].duplicate_identity"
                    )
                )
            )

            legacy_region = self._collect_legacy_bucket_region(
                client=discovery_client,
                bucket_name=bucket_name,
                account_id=context.collection_account_id,
                list_bucket_region=list_region,
            )
            direct_region = location.value if location.error is None else None
            if direct_region is not None and not isinstance(direct_region, str):  # pragma: no cover
                raise TypeError("normalized GetBucketLocation Region must be a string")
            legacy_bucket_region = legacy_region.value if legacy_region.error is None else None
            if legacy_bucket_region is not None and not isinstance(
                legacy_bucket_region, str
            ):  # pragma: no cover
                raise TypeError("normalized legacy bucket Region must be a string")
            if (
                direct_region is not None
                and legacy_bucket_region is not None
                and direct_region != legacy_bucket_region
            ):
                location = _SourceValue(
                    error=CollectorEvidenceConflictError(
                        "get_bucket_location", "LocationConstraint"
                    ),
                    details=location.details,
                )
                direct_region = None

            collection_region = legacy_bucket_region or direct_region
            if collection_region is None:
                records.append(
                    _BucketRecord(
                        bucket_name=bucket_name,
                        bucket_arn=bucket_arn,
                        summary=summary,
                        list_bucket_region=list_region,
                        evidence_admitted=evidence_admitted,
                        location=location,
                        legacy_region=legacy_region,
                    )
                )
                continue

            regional_client = self.client_provider.client("s3", region_name=collection_region)
            tags = self._collect_tags(
                regional_client,
                bucket_name=bucket_name,
                account_id=context.collection_account_id,
            )
            encryption = None
            public_access_block = None
            if evidence_admitted or _legacy_source_error(tags) is None:
                encryption = self._collect_optional_mapping(
                    regional_client,
                    operation_name="get_bucket_encryption",
                    result_key="ServerSideEncryptionConfiguration",
                    missing_codes=_MISSING_ENCRYPTION_CODES,
                    bucket_name=bucket_name,
                    account_id=context.collection_account_id,
                    normalizer=_normalize_encryption,
                    legacy_validator=S3BucketCollector._validate_encryption,
                )
            if evidence_admitted or (
                encryption is not None and _legacy_source_error(encryption) is None
            ):
                public_access_block = self._collect_optional_mapping(
                    regional_client,
                    operation_name="get_public_access_block",
                    result_key="PublicAccessBlockConfiguration",
                    missing_codes=_MISSING_PUBLIC_ACCESS_BLOCK_CODES,
                    bucket_name=bucket_name,
                    account_id=context.collection_account_id,
                    normalizer=_normalize_public_access_block,
                    absence_value={field: False for field in _PUBLIC_ACCESS_BLOCK_FIELDS},
                    legacy_validator=S3BucketCollector._validate_public_access_block,
                )
            policy = None
            policy_status = None
            acl = None
            versioning = None
            ownership_controls = None
            if direct_region is not None:
                policy = self._collect_policy(
                    regional_client,
                    bucket_name=bucket_name,
                    account_id=context.collection_account_id,
                )
                policy_status = self._collect_optional_mapping(
                    regional_client,
                    operation_name="get_bucket_policy_status",
                    result_key="PolicyStatus",
                    missing_codes=_MISSING_POLICY_CODES,
                    bucket_name=bucket_name,
                    account_id=context.collection_account_id,
                    normalizer=_normalize_policy_status,
                    absence_value={"policy_present": False, "is_public": False},
                )
                acl = self._collect_whole_response(
                    regional_client,
                    operation_name="get_bucket_acl",
                    bucket_name=bucket_name,
                    account_id=context.collection_account_id,
                    normalizer=_normalize_acl,
                )
                versioning = self._collect_whole_response(
                    regional_client,
                    operation_name="get_bucket_versioning",
                    bucket_name=bucket_name,
                    account_id=context.collection_account_id,
                    normalizer=_normalize_versioning,
                )
                ownership_controls = self._collect_optional_mapping(
                    regional_client,
                    operation_name="get_bucket_ownership_controls",
                    result_key="OwnershipControls",
                    missing_codes=_MISSING_OWNERSHIP_CONTROLS_CODES,
                    bucket_name=bucket_name,
                    account_id=context.collection_account_id,
                    normalizer=_normalize_ownership_controls,
                )
                policy, policy_status = _reconcile_policy_sources(policy, policy_status)
                acl = _reconcile_acl_sources(
                    acl=acl,
                    account_public_access_block=account_bpa,
                    bucket_public_access_block=public_access_block,
                    ownership_controls=ownership_controls,
                )

            if evidence_admitted and (encryption is None or public_access_block is None):
                raise TypeError("admitted S3 bucket omitted a legacy-compatible source")
            kms_references = (
                _kms_references(encryption)
                if direct_region is not None and encryption is not None
                else ()
            )
            reference_regions: dict[str, str] = {}
            for reference in kms_references:
                try:
                    reference_regions[reference] = _kms_reference_region(
                        reference,
                        bucket_region=direct_region,
                        partition=self.client_provider.partition,
                    )
                except CollectorEvidenceError as error:
                    # The legacy control only consumes the normalized rule set, while 5E requires
                    # a stricter canonical KMS reference. Retain the valid S3 rule facts but close
                    # the 5E encryption outcome without attempting DescribeKey in a guessed Region.
                    encryption = _SourceValue(
                        value=encryption.value,
                        error=error,
                        details={**(encryption.details or {}), "legacy_complete": True},
                    )
                    kms_references = ()
                    reference_regions.clear()
                    break

            for reference in kms_references:
                kms_region = reference_regions[reference]
                kms_reference_buckets.setdefault((kms_region, reference), set()).add(bucket_name)

            evidence_resource = None
            if direct_region is not None:
                if any(
                    source is None
                    for source in (policy, policy_status, acl, versioning, ownership_controls)
                ):  # pragma: no cover - branch invariant
                    raise TypeError("located S3 bucket omitted an enrichment source")
                evidence_resource = _bucket_resource(
                    context=context,
                    partition=self.client_provider.partition,
                    summary=summary,
                    bucket_region=direct_region,
                    tags=tags,
                    account_public_access_block=account_bpa,
                    public_access_block=public_access_block,
                    policy=policy,
                    policy_status=policy_status,
                    acl=acl,
                    versioning=versioning,
                    encryption=encryption,
                    ownership_controls=ownership_controls,
                )
            resource = None
            if legacy_bucket_region is not None and evidence_admitted:
                if (
                    tags is None or encryption is None or public_access_block is None
                ):  # pragma: no cover
                    raise TypeError("admitted S3 bucket omitted a legacy-compatible source")
                resource = evidence_resource or _legacy_bucket_resource(
                    context=context,
                    partition=self.client_provider.partition,
                    summary=summary,
                    bucket_region=legacy_bucket_region,
                    tags=tags,
                    encryption=encryption,
                    public_access_block=public_access_block,
                )
            records.append(
                _BucketRecord(
                    bucket_name=bucket_name,
                    bucket_arn=bucket_arn,
                    summary=summary,
                    list_bucket_region=list_region,
                    evidence_admitted=evidence_admitted,
                    location=location,
                    legacy_region=legacy_region,
                    tags=tags,
                    public_access_block=public_access_block,
                    policy=policy,
                    policy_status=policy_status,
                    acl=acl,
                    versioning=versioning,
                    encryption=encryption,
                    ownership_controls=ownership_controls,
                    kms_references=kms_references,
                    resource=resource,
                    evidence_resource=evidence_resource,
                )
            )

        lookups = self._collect_kms_keys(
            context=context,
            reference_buckets=kms_reference_buckets,
        )
        legacy_status = _legacy_collection_status(
            _legacy_first_error(discovery=discovery, records=records)
        )
        legacy_candidate_resources = tuple(
            sorted(
                (record.resource for record in records if record.resource is not None),
                key=lambda item: item.identity,
            )
        )
        bucket_resources = (
            legacy_candidate_resources if legacy_status is CollectionStatus.SUCCEEDED else ()
        )
        bucket_resource_identities = {resource.identity for resource in bucket_resources}
        evidence_only_bucket_resources = tuple(
            sorted(
                (
                    record.evidence_resource
                    for record in records
                    if record.evidence_resource is not None
                    and record.evidence_resource.identity not in bucket_resource_identities
                ),
                key=lambda item: item.identity,
            )
        )
        kms_resources_by_identity: dict[
            tuple[str, str, str, str, str, str], NormalizedResource
        ] = {}
        conflicted_kms_identities: set[tuple[str, str, str, str, str, str]] = set()
        for lookup in lookups:
            resource = lookup.resource
            if resource is None:
                continue
            identity = resource.identity
            if identity in conflicted_kms_identities:
                lookup.result = _SourceValue(
                    error=CollectorEvidenceConflictError("describe_key", "KeyMetadata.Arn")
                )
                lookup.resource = None
                continue
            existing = kms_resources_by_identity.get(identity)
            if existing is not None and existing != resource:
                conflict = CollectorEvidenceConflictError("describe_key", "KeyMetadata.Arn")
                conflicted_kms_identities.add(identity)
                for related in lookups:
                    if related.resource is not None and related.resource.identity == identity:
                        related.result = _SourceValue(error=conflict)
                        related.resource = None
                kms_resources_by_identity.pop(identity, None)
                continue
            kms_resources_by_identity[identity] = resource

        return _BundleResult(
            discovery=discovery,
            account_public_access_block=account_bpa,
            bucket_records=tuple(records),
            kms_lookups=tuple(lookups),
            bucket_resources=bucket_resources,
            evidence_only_bucket_resources=evidence_only_bucket_resources,
            kms_resources=tuple(
                sorted(kms_resources_by_identity.values(), key=lambda item: item.identity)
            ),
            legacy_status=legacy_status,
        )

    def _collect_bucket_summaries(
        self,
        client: Any,
        context: CollectionContext,
    ) -> _SourceValue:
        summaries: dict[str, Mapping[str, object]] = {}
        blocked_names: set[str] = set()
        errors: list[BaseException] = []
        legacy_sequence: list[tuple[str, object]] = []
        legacy_summaries: list[Mapping[str, object]] = []
        discarded_item_count = 0
        try:
            for raw_bucket in _iter_bucket_summaries_strict(
                client,
                PaginationConfig={"PageSize": 1000},
            ):
                try:
                    bucket = require_mapping(
                        raw_bucket,
                        operation_name="list_buckets",
                        fact_path="Buckets[]",
                    )
                    bucket_name = _required_safe_string(
                        bucket,
                        "Name",
                        operation_name="list_buckets",
                        fact_path="Buckets[].Name",
                    )
                    S3BucketCollector._validate_bucket_summary(bucket)
                    creation_date = None
                    if bucket.get("CreationDate") is not None:
                        creation_date = (
                            require_datetime(
                                bucket["CreationDate"],
                                operation_name="list_buckets",
                                fact_path="Buckets[].CreationDate",
                            )
                            .astimezone(UTC)
                            .isoformat()
                        )
                    list_region = bucket.get("BucketRegion")
                    if list_region is not None:
                        list_region = _normalize_location_constraint(
                            list_region,
                            operation_name="list_buckets",
                            fact_path="Buckets[].BucketRegion",
                            allow_null=False,
                        )
                    summary: Mapping[str, object] = {
                        "bucket_name": bucket_name,
                        "bucket_arn": (f"arn:{self.client_provider.partition}:s3:::{bucket_name}"),
                        "creation_date": creation_date,
                        "list_bucket_region": list_region,
                    }
                    if bucket_name in blocked_names:
                        discarded_item_count += 1
                        continue
                    existing = summaries.get(bucket_name)
                    if existing is None:
                        summaries[bucket_name] = summary
                        legacy_sequence.append(("bucket", bucket_name))
                        legacy_summaries.append(summary)
                    elif existing != summary:
                        summaries.pop(bucket_name, None)
                        blocked_names.add(bucket_name)
                        discarded_item_count += 2
                        conflict = CollectorEvidenceConflictError(
                            "list_buckets", "Buckets[].duplicate_identity"
                        )
                        errors.append(conflict)
                        legacy_sequence.append(("error", conflict))
                except CollectorEvidenceError as caught:
                    discarded_item_count += 1
                    errors.append(caught)
                    legacy_sequence.append(("error", caught))
        except _EXPECTED_FAILURES as caught:
            errors.append(caught)
            legacy_sequence.append(("error", caught))
        return _SourceValue(
            value=tuple(summaries[key] for key in sorted(summaries)),
            error=_preferred_error(errors),
            details={
                "discarded_item_count": discarded_item_count,
                "legacy_sequence": tuple(legacy_sequence),
                "legacy_summaries": tuple(legacy_summaries),
            },
        )

    def _collect_account_public_access_block(
        self,
        context: CollectionContext,
    ) -> _SourceValue:
        client = self.client_provider.client("s3control")
        try:
            response = require_mapping(
                client.get_public_access_block(AccountId=context.collection_account_id),
                operation_name="get_public_access_block",
                fact_path="response",
            )
            configuration = require_mapping(
                require_member(
                    response,
                    "PublicAccessBlockConfiguration",
                    operation_name="get_public_access_block",
                    fact_path="PublicAccessBlockConfiguration",
                ),
                operation_name="get_public_access_block",
                fact_path="PublicAccessBlockConfiguration",
            )
            return _SourceValue(value=_normalize_public_access_block(configuration))
        except ClientError as error:
            if _error_code(error) in _MISSING_PUBLIC_ACCESS_BLOCK_CODES:
                return _SourceValue(
                    value={field: False for field in _PUBLIC_ACCESS_BLOCK_FIELDS},
                    expected_absence=True,
                )
            return _SourceValue(error=error)
        except (BotoCoreError, CollectorEvidenceError) as error:
            return _SourceValue(error=error)

    @staticmethod
    def _collect_bucket_location(
        *,
        client: Any,
        bucket_name: str,
        account_id: str,
        list_bucket_region: str | None,
    ) -> _SourceValue:
        try:
            response = require_mapping(
                client.get_bucket_location(
                    Bucket=bucket_name,
                    ExpectedBucketOwner=account_id,
                ),
                operation_name="get_bucket_location",
                fact_path="response",
            )
            raw_constraint = response.get("LocationConstraint")
            if raw_constraint == "us-east-1":
                raise CollectorEvidenceError("get_bucket_location", "LocationConstraint")
            region = _normalize_location_constraint(
                raw_constraint,
                operation_name="get_bucket_location",
                fact_path="LocationConstraint",
                allow_null=True,
            )
            if list_bucket_region is not None and region != list_bucket_region:
                raise CollectorEvidenceConflictError("get_bucket_location", "LocationConstraint")
            return _SourceValue(
                value=region,
                details={"location_constraint": raw_constraint},
            )
        except _EXPECTED_FAILURES as error:
            return _SourceValue(error=error)

    @staticmethod
    def _collect_legacy_bucket_region(
        *,
        client: Any,
        bucket_name: str,
        account_id: str,
        list_bucket_region: str | None,
    ) -> _SourceValue:
        """Preserve the accepted ListBuckets-or-HeadBucket legacy Region route."""

        if list_bucket_region is not None:
            return _SourceValue(value=list_bucket_region)
        try:
            response = client.head_bucket(
                Bucket=bucket_name,
                ExpectedBucketOwner=account_id,
            )
            return _SourceValue(value=_normalize_head_bucket_region(response))
        except _EXPECTED_FAILURES as error:
            return _SourceValue(error=error)

    @staticmethod
    def _collect_tags(client: Any, *, bucket_name: str, account_id: str) -> _SourceValue:
        try:
            response = require_mapping(
                client.get_bucket_tagging(
                    Bucket=bucket_name,
                    ExpectedBucketOwner=account_id,
                ),
                operation_name="get_bucket_tagging",
                fact_path="response",
            )
            tags = tags_to_dict(
                require_list(
                    require_member(
                        response,
                        "TagSet",
                        operation_name="get_bucket_tagging",
                        fact_path="TagSet",
                    ),
                    operation_name="get_bucket_tagging",
                    fact_path="TagSet",
                ),
                operation_name="get_bucket_tagging",
                fact_path="TagSet",
            )
            return _SourceValue(value=tags)
        except ClientError as error:
            if _error_code(error) in _MISSING_TAG_CODES:
                return _SourceValue(value={}, expected_absence=True)
            return _SourceValue(error=error)
        except (BotoCoreError, CollectorEvidenceError) as error:
            return _SourceValue(error=error)

    @staticmethod
    def _collect_optional_mapping(
        client: Any,
        *,
        operation_name: str,
        result_key: str,
        missing_codes: set[str],
        bucket_name: str,
        account_id: str,
        normalizer: Any,
        absence_value: object | None = None,
        legacy_validator: Any | None = None,
    ) -> _SourceValue:
        try:
            response = require_mapping(
                getattr(client, operation_name)(
                    Bucket=bucket_name,
                    ExpectedBucketOwner=account_id,
                ),
                operation_name=operation_name,
                fact_path="response",
            )
            value = require_mapping(
                require_member(
                    response,
                    result_key,
                    operation_name=operation_name,
                    fact_path=result_key,
                ),
                operation_name=operation_name,
                fact_path=result_key,
            )
            details = None
            if legacy_validator is not None:
                legacy_error = None
                try:
                    legacy_validator(dict(value))
                except CollectorEvidenceError as error:
                    legacy_error = error
                details = {
                    "legacy_error": legacy_error,
                    "legacy_value": to_json_safe(value),
                }
            try:
                normalized = normalizer(value)
            except CollectorEvidenceError as error:
                return _SourceValue(error=error, details=details)
            return _SourceValue(value=normalized, details=details)
        except ClientError as error:
            if _error_code(error) in missing_codes:
                return _SourceValue(value=absence_value, expected_absence=True)
            return _SourceValue(error=error)
        except (BotoCoreError, CollectorEvidenceError) as error:
            return _SourceValue(error=error)

    @staticmethod
    def _collect_whole_response(
        client: Any,
        *,
        operation_name: str,
        bucket_name: str,
        account_id: str,
        normalizer: Any,
    ) -> _SourceValue:
        try:
            response = require_mapping(
                getattr(client, operation_name)(
                    Bucket=bucket_name,
                    ExpectedBucketOwner=account_id,
                ),
                operation_name=operation_name,
                fact_path="response",
            )
            value, expected_absence = normalizer(response)
            return _SourceValue(value=value, expected_absence=expected_absence)
        except _EXPECTED_FAILURES as error:
            return _SourceValue(error=error)

    @staticmethod
    def _collect_policy(client: Any, *, bucket_name: str, account_id: str) -> _SourceValue:
        try:
            response = require_mapping(
                client.get_bucket_policy(
                    Bucket=bucket_name,
                    ExpectedBucketOwner=account_id,
                ),
                operation_name="get_bucket_policy",
                fact_path="response",
            )
            encoded = require_non_empty_string(
                require_member(
                    response,
                    "Policy",
                    operation_name="get_bucket_policy",
                    fact_path="Policy",
                ),
                operation_name="get_bucket_policy",
                fact_path="Policy",
            )
            return _SourceValue(value=_decode_bucket_policy(encoded))
        except ClientError as error:
            if _error_code(error) in _MISSING_POLICY_CODES:
                return _SourceValue(expected_absence=True)
            return _SourceValue(error=error)
        except (BotoCoreError, CollectorEvidenceError) as error:
            return _SourceValue(error=error)

    def _collect_kms_keys(
        self,
        *,
        context: CollectionContext,
        reference_buckets: Mapping[tuple[str, str], set[str]],
    ) -> list[_KMSLookup]:
        lookups: list[_KMSLookup] = []
        for (region, reference), bucket_names in sorted(reference_buckets.items()):
            try:
                client = self.client_provider.client("kms", region_name=region)
                response = require_mapping(
                    client.describe_key(KeyId=reference),
                    operation_name="describe_key",
                    fact_path="response",
                )
                metadata = require_mapping(
                    require_member(
                        response,
                        "KeyMetadata",
                        operation_name="describe_key",
                        fact_path="KeyMetadata",
                    ),
                    operation_name="describe_key",
                    fact_path="KeyMetadata",
                )
                resource, payload = _normalize_kms_key(
                    metadata,
                    region=region,
                    partition=self.client_provider.partition,
                    supplied_reference=reference,
                    collection_account_id=context.collection_account_id,
                )
                result = _SourceValue(value=payload)
            except _EXPECTED_FAILURES as error:
                resource = None
                result = _SourceValue(error=error)
            lookups.append(
                _KMSLookup(
                    region=region,
                    supplied_reference=reference,
                    bucket_names=tuple(sorted(bucket_names)),
                    result=result,
                    resource=resource,
                )
            )
        return lookups


class S3EvidenceCollector(ResourceCollector):
    """Emit the graph-aware 5E S3 and referenced-KMS factual projection."""

    collector_name = "s3_evidence"
    produces_evidence_graph = True

    def __init__(
        self,
        client_provider: AWSClientProvider,
        *,
        collection_bundle: S3CollectionBundle | None = None,
    ) -> None:
        super().__init__(client_provider)
        self.collection_bundle = collection_bundle or S3CollectionBundle(client_provider)

    def collect(self) -> list[NormalizedResource]:
        """Preserve the direct collector API for controlled offline callers."""

        context = CollectionContext(
            scan_id=uuid4(),
            collection_account_id=self.client_provider.account_id,
            region=self.client_provider.region_name,
            collected_at=datetime.now(UTC),
        )
        return list(self.collect_with_context(context).resources)

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Build independent source outcomes without making an assessment decision."""

        collected = self.collection_bundle.collect(context)
        observations: list[SourceObservation] = [
            self._discovery_observation(context, collected.discovery),
            self._account_bpa_observation(context, collected.account_public_access_block),
        ]
        encryption_observations: dict[str, SourceObservation] = {}

        for record in collected.bucket_records:
            if not record.evidence_admitted:
                continue
            location_observation = self._location_observation(context, record)
            observations.append(location_observation)
            if record.evidence_resource is None:
                continue
            sources = (
                (
                    "s3.bucket-tags",
                    "s3.bucket-tags",
                    "s3:GetBucketTagging",
                    "tags",
                    record.tags,
                ),
                (
                    "s3.bucket-public-access-block",
                    "s3.bucket-public-access-block",
                    "s3:GetBucketPublicAccessBlock",
                    "public-access-block",
                    record.public_access_block,
                ),
                (
                    "s3.bucket-policy",
                    "s3.bucket-policy",
                    "s3:GetBucketPolicy",
                    "policy",
                    record.policy,
                ),
                (
                    "s3.bucket-policy-status",
                    "s3.bucket-policy-status",
                    "s3:GetBucketPolicyStatus",
                    "policy-status",
                    record.policy_status,
                ),
                (
                    "s3.bucket-acl",
                    "s3.bucket-acl",
                    "s3:GetBucketAcl",
                    "acl",
                    record.acl,
                ),
                (
                    "s3.bucket-versioning",
                    "s3.bucket-versioning",
                    "s3:GetBucketVersioning",
                    "versioning",
                    record.versioning,
                ),
                (
                    "s3.bucket-encryption",
                    "s3.bucket-encryption",
                    "s3:GetEncryptionConfiguration",
                    "encryption",
                    record.encryption,
                ),
                (
                    "s3.bucket-ownership-controls",
                    "s3.bucket-ownership-controls",
                    "s3:GetBucketOwnershipControls",
                    "ownership-controls",
                    record.ownership_controls,
                ),
            )
            for contract_key, evidence_kind, source_api, segment, value in sources:
                if value is None:  # pragma: no cover - record invariant
                    raise TypeError("located bucket omitted an enrichment source")
                observation = self._bucket_observation(
                    context=context,
                    record=record,
                    contract_key=contract_key,
                    evidence_kind=evidence_kind,
                    source_api=source_api,
                    reference_segment=segment,
                    value=value,
                )
                observations.append(observation)
                if evidence_kind == "s3.bucket-encryption":
                    encryption_observations[record.bucket_name] = observation

        for lookup in collected.kms_lookups:
            observations.append(self._kms_observation(context, collected, lookup))

        relationships: list[RelationshipReference] = []
        lookup_by_key = {
            (lookup.region, lookup.supplied_reference): lookup for lookup in collected.kms_lookups
        }
        for record in collected.bucket_records:
            if record.evidence_resource is None or not record.kms_references:
                continue
            provenance = encryption_observations[record.bucket_name].provenance
            bucket_region = record.evidence_resource.region
            if bucket_region is None:  # pragma: no cover - resource invariant
                raise TypeError("S3 bucket resource must have a Region")
            for reference in record.kms_references:
                lookup_region = _kms_reference_region(
                    reference,
                    bucket_region=bucket_region,
                    partition=self.client_provider.partition,
                )
                lookup = lookup_by_key[(lookup_region, reference)]
                target: RelationshipEndpoint | UnresolvedRelationshipTarget
                if lookup.resource is None:
                    target = UnresolvedRelationshipTarget.for_aws_reference(
                        service="kms",
                        resource_type="kms_key",
                        aws_resource_id=reference,
                        scope=ResourceScope.REGIONAL,
                        region=lookup_region,
                    )
                else:
                    target = RelationshipEndpoint.for_aws_resource(
                        aws_account_id=lookup.resource.account_id,
                        service="kms",
                        resource_type="kms_key",
                        aws_resource_id=lookup.resource.aws_resource_id,
                        scope=ResourceScope.REGIONAL,
                        region=lookup.resource.region,
                        observed_in_scan_id=None,
                    )
                relationships.append(
                    RelationshipReference(
                        relationship_type=RelationshipType.ENCRYPTED_WITH,
                        source=RelationshipEndpoint.for_aws_resource(
                            aws_account_id=record.evidence_resource.account_id,
                            service="s3",
                            resource_type="s3_bucket",
                            aws_resource_id=record.evidence_resource.aws_resource_id,
                            scope=ResourceScope.REGIONAL,
                            region=record.evidence_resource.region,
                            observed_in_scan_id=context.scan_id,
                        ),
                        target=target,
                        provenance=provenance,
                        target_collector_name=self.collector_name,
                        target_evidence_kind=(
                            f"kms.key.{_kms_lookup_digest(lookup.region, reference)}"
                        ),
                    )
                )

        outcomes = tuple(observation.outcome for observation in observations)
        return CollectorResult(
            resources=tuple(
                sorted(
                    (*collected.evidence_only_bucket_resources, *collected.kms_resources),
                    key=lambda item: item.identity,
                )
            ),
            status=collection_status_for(outcomes),
            source_contracts=tuple(observation.contract for observation in observations),
            artifacts=tuple(observation.artifact for observation in observations),
            source_outcomes=outcomes,
            relationships=tuple(
                sorted(
                    relationships,
                    key=lambda item: (
                        item.source.identity_state,
                        item.source.aws_resource_id,
                        item.target.aws_resource_id,
                    ),
                )
            ),
        )

    def _discovery_observation(
        self,
        context: CollectionContext,
        discovery: _SourceValue,
    ) -> SourceObservation:
        summaries = discovery.value if isinstance(discovery.value, tuple) else ()
        state, category = _source_state(discovery)
        return build_source_observation(
            context=context,
            contract_key="s3.buckets.discovery",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_global_subject(context),
            evidence_kind="s3.buckets.discovery",
            collector="s3.buckets",
            collector_version=_COLLECTOR_VERSION,
            source_api="s3:ListAllMyBuckets",
            cardinality=EvidenceCardinality.COLLECTION,
            evidence_reference="normalized://aws/s3/buckets",
            evidence_schema="s3.buckets.discovery",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "buckets": list(summaries),
                "bucket_names": [item["bucket_name"] for item in summaries],
                "resource_count": len(summaries),
                "discarded_item_count": (
                    discovery.details.get("discarded_item_count", 0)
                    if discovery.details is not None
                    else 0
                ),
                "complete": discovery.error is None,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )

    def _account_bpa_observation(
        self,
        context: CollectionContext,
        value: _SourceValue,
    ) -> SourceObservation:
        state, category = _source_state(value)
        return build_source_observation(
            context=context,
            contract_key="s3.account-public-access-block",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_global_subject(context),
            evidence_kind="s3.account-public-access-block",
            collector="s3.account-public-access-block",
            collector_version=_COLLECTOR_VERSION,
            source_api="s3:GetAccountPublicAccessBlock",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference="normalized://aws/s3/account/public-access-block",
            evidence_schema="s3.account-public-access-block",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "configured": not value.expected_absence and value.error is None,
                "public_access_block": value.value,
                "complete": value.error is None,
                "expected_absence": value.expected_absence,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )

    def _location_observation(
        self,
        context: CollectionContext,
        record: _BucketRecord,
    ) -> SourceObservation:
        state, category = _source_state(record.location)
        resource_not_found = state is EvidenceSourceState.RESOURCE_DISAPPEARED
        if resource_not_found and record.resource is None:
            # ListBuckets and the follow-up now disagree, but no validated Region exists from
            # which to construct a resource subject. Preserve the sanitized not-found fact in the
            # artifact while representing the account-scoped discovery contradiction as CONFLICT.
            state = EvidenceSourceState.CONFLICT
            category = EvidenceFailureCategory.CONFLICTING_EVIDENCE
        digest = _identity_digest(record.bucket_name)
        payload = {
            "account_id": context.collection_account_id,
            "bucket_name": record.bucket_name,
            "bucket_arn": record.bucket_arn,
            "list_bucket_region": record.list_bucket_region,
            "legacy_bucket_region": (
                record.resource.region if record.resource is not None else None
            ),
            "location_constraint": (
                record.location.details.get("location_constraint")
                if record.location.details is not None
                else None
            ),
            "bucket_region": record.location.value,
            "resource_not_found": resource_not_found,
            "complete": record.location.error is None,
            "failure_category": category.value if category is not None else None,
        }
        if record.evidence_resource is None:
            if state is EvidenceSourceState.RESOURCE_DISAPPEARED and record.resource is not None:
                return build_source_observation(
                    context=context,
                    contract_key="s3.bucket-location",
                    contract_version=_CONTRACT_VERSION,
                    phase=EvidenceCollectionPhase.ENRICHMENT,
                    subject=_resource_subject(context, record.resource),
                    evidence_kind="s3.bucket-location",
                    collector="s3.bucket-location",
                    collector_version=_COLLECTOR_VERSION,
                    source_api="s3:GetBucketLocation",
                    cardinality=EvidenceCardinality.SINGLE,
                    evidence_reference=f"normalized://aws/s3/buckets/{digest}/location",
                    evidence_schema="s3.bucket-location",
                    evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
                    normalized_payload=payload,
                    state=state,
                    failure_category=category,
                )
            return build_source_observation(
                context=context,
                contract_key=f"s3.bucket-location.{digest}",
                contract_version=_CONTRACT_VERSION,
                phase=EvidenceCollectionPhase.DISCOVERY,
                subject=_global_subject(context),
                evidence_kind=f"s3.bucket-location.{digest}",
                collector="s3.bucket-location",
                collector_version=_COLLECTOR_VERSION,
                source_api="s3:GetBucketLocation",
                cardinality=EvidenceCardinality.SINGLE,
                evidence_reference=f"normalized://aws/s3/buckets/{digest}/location",
                evidence_schema="s3.bucket-location",
                evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
                normalized_payload=payload,
                state=state,
                failure_category=category,
            )
        return build_source_observation(
            context=context,
            contract_key="s3.bucket-location",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=_resource_subject(context, record.evidence_resource),
            evidence_kind="s3.bucket-location",
            collector="s3.bucket-location",
            collector_version=_COLLECTOR_VERSION,
            source_api="s3:GetBucketLocation",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=f"normalized://aws/s3/buckets/{digest}/location",
            evidence_schema="s3.bucket-location",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload=payload,
            state=state,
            failure_category=category,
            identity_authoritative=True,
        )

    def _bucket_observation(
        self,
        *,
        context: CollectionContext,
        record: _BucketRecord,
        contract_key: str,
        evidence_kind: str,
        source_api: str,
        reference_segment: str,
        value: _SourceValue,
    ) -> SourceObservation:
        if record.evidence_resource is None:  # pragma: no cover - caller invariant
            raise TypeError("bucket enrichment requires a normalized bucket")
        state, category = _source_state(value)
        artifact_value = _artifact_source_value(evidence_kind, value.value)
        legacy_projection = None
        if (
            evidence_kind in {"s3.bucket-encryption", "s3.bucket-public-access-block"}
            and value.details is not None
            and "legacy_value" in value.details
        ):
            legacy_projection = to_json_safe(value.details["legacy_value"])
        validate_s3_bucket_evidence_value(
            evidence_kind=evidence_kind,
            state=state,
            value=artifact_value,
        )
        return build_source_observation(
            context=context,
            contract_key=contract_key,
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=_resource_subject(context, record.evidence_resource),
            evidence_kind=evidence_kind,
            collector=evidence_kind,
            collector_version=_COLLECTOR_VERSION,
            source_api=source_api,
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=(
                f"normalized://aws/s3/buckets/{_identity_digest(record.bucket_name)}/"
                f"{reference_segment}"
            ),
            evidence_schema=evidence_kind,
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": record.evidence_resource.account_id,
                "bucket_name": record.bucket_name,
                "bucket_arn": record.bucket_arn,
                "bucket_region": record.evidence_resource.region,
                "value": artifact_value,
                "legacy_projection": legacy_projection,
                "complete": value.error is None,
                "expected_absence": value.expected_absence,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )

    def _kms_observation(
        self,
        context: CollectionContext,
        collected: _BundleResult,
        lookup: _KMSLookup,
    ) -> SourceObservation:
        state, category = _source_state(lookup.result)
        validate_kms_key_evidence_value(state=state, value=lookup.result.value)
        digest = _kms_lookup_digest(lookup.region, lookup.supplied_reference)
        if lookup.resource is not None:
            subject: AccountEvidenceSubject | ResourceEvidenceSubject = _resource_subject(
                context, lookup.resource
            )
        else:
            bucket_by_name = {
                record.bucket_name: record.evidence_resource
                for record in collected.bucket_records
                if record.evidence_resource is not None
            }
            first_bucket = bucket_by_name.get(lookup.bucket_names[0])
            if first_bucket is None:  # pragma: no cover - lookup construction invariant
                raise TypeError("KMS lookup has no source bucket")
            subject = _resource_subject(context, first_bucket)
        return build_source_observation(
            context=context,
            contract_key=f"kms.key.{digest}",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=subject,
            evidence_kind=f"kms.key.{digest}",
            collector="kms.keys",
            collector_version=_COLLECTOR_VERSION,
            source_api="kms:DescribeKey",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=f"normalized://aws/kms/{lookup.region}/keys/{digest}",
            evidence_schema="kms.key",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "region": lookup.region,
                "supplied_reference": lookup.supplied_reference,
                "source_bucket_names": list(lookup.bucket_names),
                "key": lookup.result.value,
                "complete": lookup.result.error is None,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
            identity_authoritative=lookup.resource is not None,
        )


def _global_subject(context: CollectionContext) -> AccountEvidenceSubject:
    return AccountEvidenceSubject(
        aws_account_id=context.collection_account_id,
        scope=ResourceScope.GLOBAL,
    )


def _iter_bucket_summaries_strict(
    client: Any,
    **paginate_options: Any,
) -> Iterator[object]:
    """Yield ListBuckets items while rejecting incomplete or looping pagination."""

    operation = "list_buckets"
    paginator = client.get_paginator(operation)
    seen_tokens: set[str] = set()
    final_token: str | None = None
    page_count = 0
    for page_index, raw_page in enumerate(paginator.paginate(**paginate_options)):
        page_count += 1
        page_path = f"pages[{page_index}]"
        page = require_mapping(
            raw_page,
            operation_name=operation,
            fact_path=page_path,
        )
        items = require_list(
            require_member(
                page,
                "Buckets",
                operation_name=operation,
                fact_path=f"{page_path}.Buckets",
            ),
            operation_name=operation,
            fact_path=f"{page_path}.Buckets",
        )
        tokens = [
            (key, page[key])
            for key in ("ContinuationToken", "NextContinuationToken", "NextToken")
            if key in page
        ]
        if len(tokens) > 1:
            raise CollectorEvidenceError(operation, f"{page_path}.pagination_token")
        if tokens:
            token_key, raw_token = tokens[0]
            token = require_non_empty_string(
                raw_token,
                operation_name=operation,
                fact_path=f"{page_path}.{token_key}",
            )
            if token in seen_tokens:
                raise CollectorEvidenceError(
                    operation,
                    f"{page_path}.{token_key}.repeated",
                )
            seen_tokens.add(token)
            final_token = token
        else:
            final_token = None
        yield from items
    if page_count == 0:
        raise CollectorEvidenceError(operation, "pages")
    if final_token is not None:
        raise CollectorEvidenceError(operation, "pages.pagination_token.unconsumed")


def _resource_subject(
    context: CollectionContext,
    resource: NormalizedResource,
) -> ResourceEvidenceSubject:
    return ResourceEvidenceSubject.for_aws_resource(
        scan_id=context.scan_id,
        aws_account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        aws_resource_id=resource.aws_resource_id,
        scope=resource.scope,
        region=resource.region,
    )


def _source_state(
    value: _SourceValue,
) -> tuple[EvidenceSourceState, EvidenceFailureCategory | None]:
    if value.error is None:
        if value.expected_absence:
            return EvidenceSourceState.EXPECTED_ABSENCE, None
        return EvidenceSourceState.PRESENT, None
    if isinstance(value.error, ClientError) and _error_code(value.error) in (
        _RESOURCE_DISAPPEARED_CODES
    ):
        return (
            EvidenceSourceState.RESOURCE_DISAPPEARED,
            EvidenceFailureCategory.RESOURCE_NOT_FOUND,
        )
    return source_failure(value.error)


def _artifact_source_value(evidence_kind: str, value: object | None) -> object | None:
    """Encode arbitrary tag names as data, not structural evidence keys."""

    if evidence_kind != "s3.bucket-tags" or value is None:
        return value
    if not isinstance(value, Mapping):  # pragma: no cover - normalized source invariant
        raise TypeError("normalized S3 tags must be a mapping")
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        raise TypeError("normalized S3 tags must contain string keys and values")
    return [{"key": key, "value": value[key]} for key in sorted(value)]


def _legacy_source_error(value: _SourceValue) -> BaseException | None:
    """Return the accepted collector error independently of stricter 5E normalization."""

    if value.details is not None and "legacy_error" in value.details:
        legacy_error = value.details["legacy_error"]
        if legacy_error is not None and not isinstance(legacy_error, BaseException):
            raise TypeError("legacy source error must be an exception")
        return legacy_error
    if value.details is not None and value.details.get("legacy_complete") is True:
        return None
    return value.error


def _legacy_source_value(value: _SourceValue) -> object | None:
    """Return the exact accepted response projection when one was retained."""

    if value.details is not None and "legacy_value" in value.details:
        return value.details["legacy_value"]
    return value.value


def _legacy_first_error(
    *,
    discovery: _SourceValue,
    records: list[_BucketRecord],
) -> BaseException | None:
    """Replay accepted direct-collector stop order over the shared 5E observations."""

    records_by_name = {record.bucket_name: record for record in records}
    sequence = discovery.details.get("legacy_sequence") if discovery.details is not None else None
    if not isinstance(sequence, tuple):  # pragma: no cover - internal bundle invariant
        return discovery.error
    for event in sequence:
        if not isinstance(event, tuple) or len(event) != 2:  # pragma: no cover
            raise TypeError("legacy S3 execution event is malformed")
        event_type, value = event
        if event_type == "error":
            if not isinstance(value, BaseException):  # pragma: no cover
                raise TypeError("legacy S3 error event must contain an exception")
            return value
        if event_type != "bucket" or not isinstance(value, str):  # pragma: no cover
            raise TypeError("legacy S3 bucket event is malformed")
        record = records_by_name.get(value)
        if record is None:
            # A later contradictory duplicate removes the identity from 5E admission. The
            # corresponding conflict event remains the first reproducible legacy failure.
            continue
        if record.legacy_region.error is not None:
            return record.legacy_region.error
        for source in (record.tags, record.encryption, record.public_access_block):
            if source is None:  # pragma: no cover - located-record invariant
                raise TypeError("legacy S3 projection omitted an accepted source")
            error = _legacy_source_error(source)
            if error is not None:
                return error
    return None


def _legacy_collection_status(error: BaseException | None) -> CollectionStatus:
    """Project the first failure that would stop the accepted direct collector."""

    if error is None:
        return CollectionStatus.SUCCEEDED
    if isinstance(error, BotoCoreError | ClientError):
        return CollectionStatus.FAILED
    return CollectionStatus.PARTIAL


def _preferred_error(errors: list[BaseException]) -> BaseException | None:
    for expected_type in (CollectorEvidenceConflictError, CollectorEvidenceError):
        for error in errors:
            if isinstance(error, expected_type):
                return error
    return errors[0] if errors else None


def _required_safe_string(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str:
    value = require_non_empty_string(
        require_member(
            container,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if any(separator in value for separator in ("\x00", "\x1f", "\r", "\n")):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def _normalize_location_constraint(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
    allow_null: bool,
) -> str:
    if value is None:
        if not allow_null:
            raise CollectorEvidenceError(operation_name, fact_path)
        return "us-east-1"
    region = require_non_empty_string(
        value,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if region == "EU":
        return "eu-west-1"
    if (
        len(region) > 64
        or not _AWS_REGION_PATTERN.fullmatch(region)
        or any(separator in region for separator in ("\x00", "\x1f", "\r", "\n"))
    ):
        raise CollectorEvidenceError(operation_name, fact_path)
    return region


def _normalize_head_bucket_region(response_value: object) -> str:
    response = require_mapping(
        response_value,
        operation_name="head_bucket",
        fact_path="response",
    )
    direct_region = None
    if "BucketRegion" in response:
        direct_region = _normalize_location_constraint(
            response["BucketRegion"],
            operation_name="head_bucket",
            fact_path="BucketRegion",
            allow_null=False,
        )

    header_region = None
    if "ResponseMetadata" in response:
        response_metadata = require_mapping(
            response["ResponseMetadata"],
            operation_name="head_bucket",
            fact_path="ResponseMetadata",
        )
        if "HTTPHeaders" in response_metadata:
            response_headers = require_mapping(
                response_metadata["HTTPHeaders"],
                operation_name="head_bucket",
                fact_path="ResponseMetadata.HTTPHeaders",
            )
            if "x-amz-bucket-region" in response_headers:
                header_region = _normalize_location_constraint(
                    response_headers["x-amz-bucket-region"],
                    operation_name="head_bucket",
                    fact_path="ResponseMetadata.HTTPHeaders.x-amz-bucket-region",
                    allow_null=False,
                )

    if direct_region and header_region and direct_region != header_region:
        raise CollectorEvidenceError("head_bucket", "BucketRegion")
    region = direct_region or header_region
    if region is None:
        raise CollectorEvidenceError("head_bucket", "BucketRegion")
    return region


def _normalize_public_access_block(configuration: Mapping[str, Any]) -> dict[str, bool]:
    return {
        field: require_boolean(
            require_member(
                configuration,
                field,
                operation_name="get_public_access_block",
                fact_path=f"PublicAccessBlockConfiguration.{field}",
            ),
            operation_name="get_public_access_block",
            fact_path=f"PublicAccessBlockConfiguration.{field}",
        )
        for field in _PUBLIC_ACCESS_BLOCK_FIELDS
    }


def _normalize_policy_status(configuration: Mapping[str, Any]) -> dict[str, bool]:
    return {
        "policy_present": True,
        "is_public": require_boolean(
            require_member(
                configuration,
                "IsPublic",
                operation_name="get_bucket_policy_status",
                fact_path="PolicyStatus.IsPublic",
            ),
            operation_name="get_bucket_policy_status",
            fact_path="PolicyStatus.IsPublic",
        ),
    }


def _normalize_acl(response: Mapping[str, Any]) -> tuple[dict[str, object], bool]:
    operation = "get_bucket_acl"
    owner = require_mapping(
        require_member(
            response,
            "Owner",
            operation_name=operation,
            fact_path="Owner",
        ),
        operation_name=operation,
        fact_path="Owner",
    )
    owner_id = _required_safe_string(
        owner,
        "ID",
        operation_name=operation,
        fact_path="Owner.ID",
    )
    display_name = None
    if "DisplayName" in owner:
        display_name = require_string(
            owner["DisplayName"],
            operation_name=operation,
            fact_path="Owner.DisplayName",
        )
    grants = require_list(
        require_member(
            response,
            "Grants",
            operation_name=operation,
            fact_path="Grants",
        ),
        operation_name=operation,
        fact_path="Grants",
    )
    normalized_grants: list[dict[str, object]] = []
    for index, raw_grant in enumerate(grants):
        grant_path = f"Grants[{index}]"
        grant = require_mapping(
            raw_grant,
            operation_name=operation,
            fact_path=grant_path,
        )
        grantee = require_mapping(
            require_member(
                grant,
                "Grantee",
                operation_name=operation,
                fact_path=f"{grant_path}.Grantee",
            ),
            operation_name=operation,
            fact_path=f"{grant_path}.Grantee",
        )
        grantee_type = _required_safe_string(
            grantee,
            "Type",
            operation_name=operation,
            fact_path=f"{grant_path}.Grantee.Type",
        )
        if grantee_type not in _ACL_GRANTEE_TYPES:
            raise CollectorEvidenceError(operation, f"{grant_path}.Grantee.Type")
        invalid_identity_fields = (
            set(grantee).intersection(_ACL_GRANTEE_IDENTITY_FIELDS)
            - _ACL_GRANTEE_ALLOWED_FIELDS[grantee_type]
        )
        if invalid_identity_fields:
            raise CollectorEvidenceError(operation, f"{grant_path}.Grantee")
        normalized_grantee: dict[str, object] = {"type": grantee_type}
        for source_key, result_key in (
            ("ID", "id"),
            ("URI", "uri"),
            ("EmailAddress", "email_address"),
            ("DisplayName", "display_name"),
        ):
            if source_key in grantee:
                normalized_grantee[result_key] = _required_safe_string(
                    grantee,
                    source_key,
                    operation_name=operation,
                    fact_path=f"{grant_path}.Grantee.{source_key}",
                )
        required_identity_field = {
            "CanonicalUser": "id",
            "AmazonCustomerByEmail": "email_address",
            "Group": "uri",
        }[grantee_type]
        if required_identity_field not in normalized_grantee:
            raise CollectorEvidenceError(
                operation,
                f"{grant_path}.Grantee.{required_identity_field}",
            )
        permission = _required_safe_string(
            grant,
            "Permission",
            operation_name=operation,
            fact_path=f"{grant_path}.Permission",
        )
        if permission not in _ACL_PERMISSIONS:
            raise CollectorEvidenceError(operation, f"{grant_path}.Permission")
        normalized_grants.append({"grantee": normalized_grantee, "permission": permission})
    normalized_grants.sort(key=_canonical_json)
    return (
        {
            "owner": {"id": owner_id, "display_name": display_name},
            "grants": normalized_grants,
        },
        False,
    )


def _normalize_versioning(response: Mapping[str, Any]) -> tuple[dict[str, object], bool]:
    status = None
    if "Status" in response:
        status = require_non_empty_string(
            response["Status"],
            operation_name="get_bucket_versioning",
            fact_path="Status",
        )
        if status not in _VERSIONING_STATUSES:
            raise CollectorEvidenceError("get_bucket_versioning", "Status")
    mfa_delete = None
    if "MFADelete" in response:
        mfa_delete = require_non_empty_string(
            response["MFADelete"],
            operation_name="get_bucket_versioning",
            fact_path="MFADelete",
        )
        if mfa_delete not in _MFA_DELETE_STATUSES:
            raise CollectorEvidenceError("get_bucket_versioning", "MFADelete")
    if status is None and mfa_delete is not None:
        raise CollectorEvidenceError("get_bucket_versioning", "MFADelete")
    return (
        {"status": status, "mfa_delete": mfa_delete},
        status is None and mfa_delete is None,
    )


def _normalize_ownership_controls(configuration: Mapping[str, Any]) -> dict[str, object]:
    rules = require_list(
        require_member(
            configuration,
            "Rules",
            operation_name="get_bucket_ownership_controls",
            fact_path="OwnershipControls.Rules",
        ),
        operation_name="get_bucket_ownership_controls",
        fact_path="OwnershipControls.Rules",
    )
    if len(rules) != 1:
        raise CollectorEvidenceError("get_bucket_ownership_controls", "OwnershipControls.Rules")
    normalized: list[dict[str, str]] = []
    for index, raw_rule in enumerate(rules):
        path = f"OwnershipControls.Rules[{index}]"
        rule = require_mapping(
            raw_rule,
            operation_name="get_bucket_ownership_controls",
            fact_path=path,
        )
        value = _required_safe_string(
            rule,
            "ObjectOwnership",
            operation_name="get_bucket_ownership_controls",
            fact_path=f"{path}.ObjectOwnership",
        )
        if value not in _OBJECT_OWNERSHIP_VALUES:
            raise CollectorEvidenceError("get_bucket_ownership_controls", f"{path}.ObjectOwnership")
        normalized.append({"object_ownership": value})
    normalized.sort(key=lambda item: item["object_ownership"])
    return {"rules": normalized}


def _normalize_encryption(configuration: Mapping[str, Any]) -> dict[str, object]:
    operation = "get_bucket_encryption"
    rules = require_list(
        require_member(
            configuration,
            "Rules",
            operation_name=operation,
            fact_path="ServerSideEncryptionConfiguration.Rules",
        ),
        operation_name=operation,
        fact_path="ServerSideEncryptionConfiguration.Rules",
    )
    if not rules:
        raise CollectorEvidenceError(operation, "ServerSideEncryptionConfiguration.Rules")
    normalized_rules: list[dict[str, object]] = []
    for index, raw_rule in enumerate(rules):
        path = f"ServerSideEncryptionConfiguration.Rules[{index}]"
        rule = require_mapping(raw_rule, operation_name=operation, fact_path=path)
        if not set(rule).issubset(
            {
                "ApplyServerSideEncryptionByDefault",
                "BucketKeyEnabled",
                "BlockedEncryptionTypes",
            }
        ):
            raise CollectorEvidenceError(operation, path)
        algorithm = None
        kms_reference = None
        if "ApplyServerSideEncryptionByDefault" in rule:
            defaults = require_mapping(
                rule["ApplyServerSideEncryptionByDefault"],
                operation_name=operation,
                fact_path=f"{path}.ApplyServerSideEncryptionByDefault",
            )
            if not set(defaults).issubset({"SSEAlgorithm", "KMSMasterKeyID"}):
                raise CollectorEvidenceError(
                    operation,
                    f"{path}.ApplyServerSideEncryptionByDefault",
                )
            algorithm = _required_safe_string(
                defaults,
                "SSEAlgorithm",
                operation_name=operation,
                fact_path=f"{path}.ApplyServerSideEncryptionByDefault.SSEAlgorithm",
            )
            if algorithm not in _S3_ENCRYPTION_ALGORITHMS:
                raise CollectorEvidenceError(
                    operation,
                    f"{path}.ApplyServerSideEncryptionByDefault.SSEAlgorithm",
                )
            if "KMSMasterKeyID" in defaults:
                kms_reference = _required_safe_string(
                    defaults,
                    "KMSMasterKeyID",
                    operation_name=operation,
                    fact_path=f"{path}.ApplyServerSideEncryptionByDefault.KMSMasterKeyID",
                )
                if algorithm not in _KMS_ENCRYPTION_ALGORITHMS:
                    raise CollectorEvidenceError(
                        operation,
                        f"{path}.ApplyServerSideEncryptionByDefault.KMSMasterKeyID",
                    )
        blocked_encryption_types: list[str] = []
        if "BlockedEncryptionTypes" in rule:
            blocked = require_mapping(
                rule["BlockedEncryptionTypes"],
                operation_name=operation,
                fact_path=f"{path}.BlockedEncryptionTypes",
            )
            if set(blocked) != {"EncryptionType"}:
                raise CollectorEvidenceError(operation, f"{path}.BlockedEncryptionTypes")
            raw_types = require_list(
                blocked["EncryptionType"],
                operation_name=operation,
                fact_path=f"{path}.BlockedEncryptionTypes.EncryptionType",
            )
            if (
                len(raw_types) != 1
                or not all(isinstance(value, str) for value in raw_types)
                or set(raw_types) - _BLOCKED_ENCRYPTION_TYPES
            ):
                raise CollectorEvidenceError(
                    operation,
                    f"{path}.BlockedEncryptionTypes.EncryptionType",
                )
            blocked_encryption_types = sorted(raw_types)
        if algorithm is None and not blocked_encryption_types:
            raise CollectorEvidenceError(operation, path)
        bucket_key_enabled = None
        if "BucketKeyEnabled" in rule:
            bucket_key_enabled = require_boolean(
                rule["BucketKeyEnabled"],
                operation_name=operation,
                fact_path=f"{path}.BucketKeyEnabled",
            )
            if bucket_key_enabled and algorithm != "aws:kms":
                raise CollectorEvidenceError(operation, f"{path}.BucketKeyEnabled")
        normalized_rules.append(
            {
                "sse_algorithm": algorithm,
                "kms_key_reference": kms_reference,
                "kms_reference_explicit": kms_reference is not None,
                "key_management": _key_management(algorithm, kms_reference),
                "bucket_key_enabled": bucket_key_enabled,
                "blocked_encryption_types": blocked_encryption_types,
            }
        )
    normalized_rules.sort(key=_canonical_json)
    return {"rules": normalized_rules}


def _key_management(algorithm: str | None, kms_reference: str | None) -> str | None:
    if algorithm is None:
        return None
    if algorithm == "AES256":
        return "S3_MANAGED"
    if algorithm in _KMS_ENCRYPTION_ALGORITHMS and kms_reference is None:
        return "IMPLICIT_AWS_MANAGED_KMS"
    if algorithm in _KMS_ENCRYPTION_ALGORITHMS:
        return "EXPLICIT_KMS_REFERENCE"
    return "SERVICE_SPECIFIC"


def _kms_references(encryption: _SourceValue) -> tuple[str, ...]:
    if encryption.error is not None or not isinstance(encryption.value, Mapping):
        return ()
    return s3_encryption_kms_references(encryption.value)


def _bucket_resource(
    *,
    context: CollectionContext,
    partition: str,
    summary: Mapping[str, object],
    bucket_region: str,
    tags: _SourceValue,
    account_public_access_block: _SourceValue,
    public_access_block: _SourceValue,
    policy: _SourceValue,
    policy_status: _SourceValue,
    acl: _SourceValue,
    versioning: _SourceValue,
    encryption: _SourceValue,
    ownership_controls: _SourceValue,
) -> NormalizedResource:
    bucket_name = str(summary["bucket_name"])
    normalized_tags = tags.value if isinstance(tags.value, dict) else {}
    configuration = {
        "creation_date": summary.get("creation_date"),
        "bucket_region": bucket_region,
        # Preserve the accepted S3-900 input shape alongside the explicit 5E facts.
        "default_encryption": _legacy_encryption(encryption),
        "public_access_block": (
            None
            if public_access_block.expected_absence
            else _legacy_source_value(public_access_block)
        ),
        "account_public_access_block": account_public_access_block.value,
        "policy": policy.value,
        "policy_status": policy_status.value,
        "acl": acl.value,
        "versioning": versioning.value,
        "encryption": encryption.value,
        "ownership_controls": ownership_controls.value,
        "source_states": {
            "tags": _source_state(tags)[0].value,
            "account_public_access_block": _source_state(account_public_access_block)[0].value,
            "public_access_block": _source_state(public_access_block)[0].value,
            "policy": _source_state(policy)[0].value,
            "policy_status": _source_state(policy_status)[0].value,
            "acl": _source_state(acl)[0].value,
            "versioning": _source_state(versioning)[0].value,
            "encryption": _source_state(encryption)[0].value,
            "ownership_controls": _source_state(ownership_controls)[0].value,
        },
    }
    return NormalizedResource(
        account_id=context.collection_account_id,
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id=bucket_name,
        arn=f"arn:{partition}:s3:::{bucket_name}",
        name=bucket_name,
        scope=ResourceScope.REGIONAL,
        region=bucket_region,
        tags=normalized_tags,
        configuration=configuration,
        raw_configuration=configuration,
    )


def _legacy_bucket_resource(
    *,
    context: CollectionContext,
    partition: str,
    summary: Mapping[str, object],
    bucket_region: str,
    tags: _SourceValue,
    encryption: _SourceValue,
    public_access_block: _SourceValue,
) -> NormalizedResource:
    """Project only the accepted S3-900 resource facts when 5E location is unavailable."""

    bucket_name = str(summary["bucket_name"])
    normalized_tags = tags.value if isinstance(tags.value, dict) else {}
    default_encryption = _legacy_encryption(encryption)
    legacy_public_access_block = (
        None if public_access_block.expected_absence else _legacy_source_value(public_access_block)
    )
    raw_bucket: dict[str, object] = {"Name": bucket_name}
    if summary.get("creation_date") is not None:
        raw_bucket["CreationDate"] = summary["creation_date"]
    if summary.get("list_bucket_region") is not None:
        raw_bucket["BucketRegion"] = summary["list_bucket_region"]
    configuration = {
        "creation_date": summary.get("creation_date"),
        "bucket_region": bucket_region,
        "default_encryption": default_encryption,
        "public_access_block": legacy_public_access_block,
    }
    return NormalizedResource(
        account_id=context.collection_account_id,
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id=bucket_name,
        arn=f"arn:{partition}:s3:::{bucket_name}",
        name=bucket_name,
        scope=ResourceScope.REGIONAL,
        region=bucket_region,
        tags=normalized_tags,
        configuration=configuration,
        raw_configuration={
            "bucket": raw_bucket,
            "default_encryption": default_encryption,
            "public_access_block": legacy_public_access_block,
        },
    )


def _legacy_encryption(encryption: _SourceValue) -> object:
    """Project normalized 5E encryption back into the accepted S3-900 shape."""

    if encryption.expected_absence:
        return None
    retained = _legacy_source_value(encryption)
    if encryption.details is not None and "legacy_value" in encryption.details:
        return retained
    legacy_complete = (
        encryption.details is not None and encryption.details.get("legacy_complete") is True
    )
    if encryption.error is not None and not legacy_complete:
        return None
    if not isinstance(encryption.value, Mapping):  # pragma: no cover - normalized above
        return None
    rules = encryption.value.get("rules")
    if not isinstance(rules, list):  # pragma: no cover - normalized above
        return None
    projected: list[dict[str, object]] = []
    for raw_rule in rules:
        if not isinstance(raw_rule, Mapping):  # pragma: no cover - normalized above
            continue
        rule: dict[str, object] = {}
        if raw_rule.get("sse_algorithm") is not None:
            defaults: dict[str, object] = {"SSEAlgorithm": raw_rule["sse_algorithm"]}
            if raw_rule.get("kms_key_reference") is not None:
                defaults["KMSMasterKeyID"] = raw_rule["kms_key_reference"]
            rule["ApplyServerSideEncryptionByDefault"] = defaults
        if raw_rule.get("bucket_key_enabled") is not None:
            rule["BucketKeyEnabled"] = raw_rule["bucket_key_enabled"]
        blocked_types = raw_rule.get("blocked_encryption_types")
        if isinstance(blocked_types, list) and blocked_types:
            rule["BlockedEncryptionTypes"] = {"EncryptionType": blocked_types}
        projected.append(rule)
    return {"Rules": projected}


def _decode_bucket_policy(encoded: str) -> dict[str, object]:
    """Decode one policy strictly and reject duplicate keys or lossy JSON values."""

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        document = json.loads(
            encoded,
            object_pairs_hook=object_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise CollectorEvidenceError("get_bucket_policy", "Policy") from error
    if not isinstance(document, dict):
        raise CollectorEvidenceError("get_bucket_policy", "Policy")
    unknown_top_level = set(document) - {"Version", "Id", "Statement"}
    if unknown_top_level or "Statement" not in document:
        raise CollectorEvidenceError("get_bucket_policy", "Policy")
    if "Version" in document and not isinstance(document["Version"], str):
        raise CollectorEvidenceError("get_bucket_policy", "Policy.Version")
    if "Id" in document and not isinstance(document["Id"], str):
        raise CollectorEvidenceError("get_bucket_policy", "Policy.Id")
    raw_statements = document["Statement"]
    if isinstance(raw_statements, Mapping):
        statements = [raw_statements]
    elif isinstance(raw_statements, list) and raw_statements:
        statements = raw_statements
    else:
        raise CollectorEvidenceError("get_bucket_policy", "Policy.Statement")
    normalized_statements: list[dict[str, object]] = []
    for index, raw_statement in enumerate(statements):
        path = f"Policy.Statement[{index}]"
        if not isinstance(raw_statement, Mapping):
            raise CollectorEvidenceError("get_bucket_policy", path)
        unknown = set(raw_statement) - {
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
        if unknown:
            raise CollectorEvidenceError("get_bucket_policy", path)
        effect = _policy_required_string(raw_statement, "Effect", path)
        if effect not in {"Allow", "Deny"}:
            raise CollectorEvidenceError("get_bucket_policy", f"{path}.Effect")
        for alternatives in (
            ("Principal", "NotPrincipal"),
            ("Action", "NotAction"),
            ("Resource", "NotResource"),
        ):
            if sum(key in raw_statement for key in alternatives) != 1:
                raise CollectorEvidenceError("get_bucket_policy", path)
        statement: dict[str, object] = {"Effect": effect}
        if "Sid" in raw_statement:
            statement["Sid"] = _policy_required_string(raw_statement, "Sid", path)
        for key in (
            "Principal",
            "NotPrincipal",
        ):
            if key in raw_statement:
                statement[key] = _normalize_policy_principal(
                    raw_statement[key],
                    operation_name="get_bucket_policy",
                    fact_path=f"{path}.{key}",
                )
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            if key in raw_statement:
                statement[key] = _normalize_policy_string_or_list(
                    raw_statement[key],
                    operation_name="get_bucket_policy",
                    fact_path=f"{path}.{key}",
                )
        if "Condition" in raw_statement:
            if not isinstance(raw_statement["Condition"], Mapping):
                raise CollectorEvidenceError("get_bucket_policy", f"{path}.Condition")
            statement["Condition"] = _normalize_policy_condition(
                raw_statement["Condition"],
                operation_name="get_bucket_policy",
                fact_path=f"{path}.Condition",
            )
        normalized_statements.append(statement)
    normalized_document: dict[str, object] = {
        "Version": document.get("Version"),
        "Id": document.get("Id"),
        "Statement": normalized_statements,
    }
    canonical = _canonical_json(normalized_document)
    return {
        "document": normalized_document,
        "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def _policy_required_string(
    statement: Mapping[str, object],
    key: str,
    path: str,
) -> str:
    return require_non_empty_string(
        require_member(
            statement,
            key,
            operation_name="get_bucket_policy",
            fact_path=f"{path}.{key}",
        ),
        operation_name="get_bucket_policy",
        fact_path=f"{path}.{key}",
    )


def _normalize_policy_principal(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> object:
    if isinstance(value, str):
        return require_non_empty_string(
            value,
            operation_name=operation_name,
            fact_path=fact_path,
        )
    if not isinstance(value, Mapping) or not value:
        raise CollectorEvidenceError(operation_name, fact_path)
    result: dict[str, object] = {}
    for raw_key, item in value.items():
        key = require_non_empty_string(
            raw_key,
            operation_name=operation_name,
            fact_path=f"{fact_path}.key",
        )
        result[key] = _normalize_policy_string_or_list(
            item,
            operation_name=operation_name,
            fact_path=f"{fact_path}.{key}",
        )
    return {key: result[key] for key in sorted(result)}


def _normalize_policy_string_or_list(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> str | list[str]:
    if isinstance(value, str):
        return require_non_empty_string(
            value,
            operation_name=operation_name,
            fact_path=fact_path,
        )
    if not isinstance(value, list) or not value:
        raise CollectorEvidenceError(operation_name, fact_path)
    return [
        require_non_empty_string(
            item,
            operation_name=operation_name,
            fact_path=f"{fact_path}[{index}]",
        )
        for index, item in enumerate(value)
    ]


def _normalize_policy_condition(
    value: Mapping[str, object],
    *,
    operation_name: str,
    fact_path: str,
) -> dict[str, object]:
    if not value:
        raise CollectorEvidenceError(operation_name, fact_path)
    normalized: dict[str, object] = {}
    for raw_operator, raw_conditions in value.items():
        operator = require_non_empty_string(
            raw_operator,
            operation_name=operation_name,
            fact_path=f"{fact_path}.operator",
        )
        if not isinstance(raw_conditions, Mapping) or not raw_conditions:
            raise CollectorEvidenceError(operation_name, f"{fact_path}.{operator}")
        conditions: dict[str, object] = {}
        for raw_key, raw_value in raw_conditions.items():
            key = require_non_empty_string(
                raw_key,
                operation_name=operation_name,
                fact_path=f"{fact_path}.{operator}.key",
            )
            conditions[key] = _normalize_policy_string_or_list(
                raw_value,
                operation_name=operation_name,
                fact_path=f"{fact_path}.{operator}.{key}",
            )
        normalized[operator] = {key: conditions[key] for key in sorted(conditions)}
    return {key: normalized[key] for key in sorted(normalized)}


def _kms_reference_region(reference: str, *, bucket_region: str, partition: str) -> str:
    if not reference.startswith("arn:"):
        return _normalize_location_constraint(
            bucket_region,
            operation_name="get_bucket_encryption",
            fact_path="ServerSideEncryptionConfiguration.bucket_region",
            allow_null=False,
        )
    parts = reference.split(":", maxsplit=5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or parts[1] != partition
        or parts[2] != "kms"
        or not parts[3]
        or len(parts[4]) != 12
        or not parts[4].isascii()
        or not parts[4].isdigit()
        or not (parts[5].startswith("key/") or parts[5].startswith("alias/"))
        or not parts[5].split("/", maxsplit=1)[1]
    ):
        raise CollectorEvidenceError(
            "get_bucket_encryption",
            "ServerSideEncryptionConfiguration.Rules[].KMSMasterKeyID",
        )
    return _normalize_location_constraint(
        parts[3],
        operation_name="get_bucket_encryption",
        fact_path="ServerSideEncryptionConfiguration.Rules[].KMSMasterKeyID.region",
        allow_null=False,
    )


def _normalize_kms_key(
    metadata: Mapping[str, Any],
    *,
    region: str,
    partition: str,
    supplied_reference: str,
    collection_account_id: str,
) -> tuple[NormalizedResource, dict[str, object]]:
    operation = "describe_key"
    account_id = _required_safe_string(
        metadata,
        "AWSAccountId",
        operation_name=operation,
        fact_path="KeyMetadata.AWSAccountId",
    )
    if len(account_id) != 12 or not account_id.isascii() or not account_id.isdigit():
        raise CollectorEvidenceError(operation, "KeyMetadata.AWSAccountId")
    key_id = _required_safe_string(
        metadata,
        "KeyId",
        operation_name=operation,
        fact_path="KeyMetadata.KeyId",
    )
    arn = _required_safe_string(
        metadata,
        "Arn",
        operation_name=operation,
        fact_path="KeyMetadata.Arn",
    )
    parts = arn.split(":", maxsplit=5)
    if (
        len(parts) != 6
        or parts[:3] != ["arn", partition, "kms"]
        or parts[3] != region
        or parts[4] != account_id
        or parts[5] != f"key/{key_id}"
    ):
        raise CollectorEvidenceError(operation, "KeyMetadata.Arn")
    if not kms_reference_matches_key_identity(
        supplied_reference=supplied_reference,
        lookup_region=region,
        collection_account_id=collection_account_id,
        partition=partition,
        key_arn=arn,
        key_id=key_id,
        key_account_id=account_id,
    ):
        raise CollectorEvidenceError(operation, "KeyMetadata.RequestedKeyId")
    key_manager = _required_safe_string(
        metadata,
        "KeyManager",
        operation_name=operation,
        fact_path="KeyMetadata.KeyManager",
    )
    if key_manager not in _KMS_KEY_MANAGERS:
        raise CollectorEvidenceError(operation, "KeyMetadata.KeyManager")
    enabled = None
    if "Enabled" in metadata:
        enabled = require_boolean(
            metadata["Enabled"],
            operation_name=operation,
            fact_path="KeyMetadata.Enabled",
        )
    multi_region = None
    if "MultiRegion" in metadata:
        multi_region = require_boolean(
            metadata["MultiRegion"],
            operation_name=operation,
            fact_path="KeyMetadata.MultiRegion",
        )
    creation_date = None
    if "CreationDate" in metadata:
        creation_date = (
            require_datetime(
                metadata["CreationDate"],
                operation_name=operation,
                fact_path="KeyMetadata.CreationDate",
            )
            .astimezone(UTC)
            .isoformat()
        )
    optional_strings: dict[str, str | None] = {}
    for source_key, result_key in (
        ("KeyState", "key_state"),
        ("Origin", "origin"),
        ("KeyUsage", "key_usage"),
        ("KeySpec", "key_spec"),
    ):
        optional_strings[result_key] = (
            _required_safe_string(
                metadata,
                source_key,
                operation_name=operation,
                fact_path=f"KeyMetadata.{source_key}",
            )
            if source_key in metadata
            else None
        )
    payload: dict[str, object] = {
        "aws_account_id": account_id,
        "region": region,
        "key_id": key_id,
        "arn": arn,
        "key_manager": key_manager,
        "enabled": enabled,
        "multi_region": multi_region,
        "creation_date": creation_date,
        **optional_strings,
    }
    try:
        validate_kms_key_evidence_value(
            state=EvidenceSourceState.PRESENT,
            value=payload,
        )
    except ValueError as error:
        raise CollectorEvidenceError(operation, "KeyMetadata") from error
    resource = NormalizedResource(
        account_id=account_id,
        service="kms",
        resource_type="kms_key",
        aws_resource_id=arn,
        arn=arn,
        name=None,
        scope=ResourceScope.REGIONAL,
        region=region,
        configuration=payload,
        raw_configuration=payload,
    )
    return resource, payload


def _identity_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _kms_lookup_digest(region: str, reference: str) -> str:
    if any(separator in component for component in (region, reference) for separator in ("\x00",)):
        raise ValueError("KMS lookup identity components must not contain NUL bytes")
    return hashlib.sha256(f"{region}\x00{reference}".encode()).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
