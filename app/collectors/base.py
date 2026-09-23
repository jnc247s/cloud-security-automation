"""Shared contracts and normalization helpers for AWS resource collectors."""

import base64
import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from app.assessment.evidence_graph import (
    EvidenceCardinality,
    ResourceOwnerMode,
    ScanSourceContract,
    SourceEvidenceArtifact,
    kms_reference_matches_key_identity,
    normalize_s3_legacy_encryption_value,
    reconstruct_s3_bucket_region_evidence,
    s3_encryption_kms_references,
    validate_cloudtrail_source_contract_manifest,
    validate_kms_key_evidence_value,
    validate_s3_acl_source_coherence,
    validate_s3_bucket_evidence_value,
    validate_s3_policy_source_coherence,
    validate_s3_source_contract_manifest,
)
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipProvenance,
    RelationshipType,
    UnresolvedRelationshipTarget,
)
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
    SourceEvidenceOutcome,
)
from app.aws.client import AWSClientProvider
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import NormalizedResource, ResourceScope

_ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthorizationError",
        "UnauthorizedOperation",
    }
)
_AUTHENTICATION_CODES = frozenset(
    {
        "AuthFailure",
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidClientTokenId",
        "InvalidSignatureException",
        "SignatureDoesNotMatch",
        "UnrecognizedClientException",
    }
)
_THROTTLING_CODES = frozenset(
    {
        "RequestLimitExceeded",
        "SlowDown",
        "ThrottledException",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
    }
)
_UNSUPPORTED_CODES = frozenset(
    {
        "InvalidAction",
        "NotImplemented",
        "UnsupportedOperation",
        "UnsupportedOperationException",
    }
)
_S3_PUBLIC_ACCESS_BLOCK_FIELDS = frozenset(
    {
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    }
)
_S3_INCOMPLETE_SOURCE_STATES = frozenset(
    {
        EvidenceSourceState.UNAVAILABLE,
        EvidenceSourceState.MALFORMED,
        EvidenceSourceState.RESOURCE_DISAPPEARED,
    }
)
_S3_ACCOUNT_PUBLIC_ACCESS_BLOCK_STATES = frozenset(
    {
        EvidenceSourceState.PRESENT,
        EvidenceSourceState.EXPECTED_ABSENCE,
        *_S3_INCOMPLETE_SOURCE_STATES,
    }
)
_S3_PER_BUCKET_SOURCE_STATES = {
    "s3.bucket-acl": frozenset(
        {
            EvidenceSourceState.PRESENT,
            EvidenceSourceState.CONFLICT,
            *_S3_INCOMPLETE_SOURCE_STATES,
        }
    ),
    **{
        collector: frozenset(
            {
                EvidenceSourceState.PRESENT,
                EvidenceSourceState.EXPECTED_ABSENCE,
                *_S3_INCOMPLETE_SOURCE_STATES,
            }
        )
        for collector in (
            "s3.bucket-encryption",
            "s3.bucket-ownership-controls",
            "s3.bucket-public-access-block",
            "s3.bucket-tags",
            "s3.bucket-versioning",
        )
    },
    **{
        collector: frozenset(
            {
                EvidenceSourceState.PRESENT,
                EvidenceSourceState.EXPECTED_ABSENCE,
                EvidenceSourceState.CONFLICT,
                *_S3_INCOMPLETE_SOURCE_STATES,
            }
        )
        for collector in ("s3.bucket-policy", "s3.bucket-policy-status")
    },
}

_GRAPH_COLLECTOR_SOURCES = {
    "access_analyzer_evidence": frozenset(
        {
            "access-analyzer.analyzers",
            "access-analyzer.finding-details",
            "access-analyzer.findings",
        }
    ),
    "cloudtrail_evidence": frozenset(
        {
            "cloudtrail.trails",
            "cloudtrail.trail-configuration",
            "cloudtrail.trail-status",
            "cloudtrail.trail-event-selectors",
            "cloudtrail.trail-tags",
        }
    ),
    "ec2_ebs_evidence": frozenset({"ec2.instances", "ec2.volumes", "ec2.ebs-defaults"}),
    "iam_account_evidence": frozenset({"iam.account-summary"}),
    "iam_users": frozenset({"iam.users", "iam.groups", "iam.roles", "iam.policies"}),
    "s3_evidence": frozenset(
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
    ),
    "security_groups": frozenset({"ec2.security-groups"}),
    "vpc_network_evidence": frozenset({"ec2.vpcs", "ec2.subnets", "ec2.flow-logs"}),
}
_REQUIRED_GRAPH_DISCOVERY_SOURCES = {
    # Access Analyzer has one declaration per bucket-backed Region and one per analyzer. Its
    # dynamic manifest is validated separately by _access_analyzer_coverage_is_incomplete.
    "access_analyzer_evidence": frozenset(),
    # CloudTrail has one global discovery plus a dynamic five-source manifest per trail.
    "cloudtrail_evidence": frozenset(),
    "ec2_ebs_evidence": frozenset(
        {
            (
                "ec2.instances.discovery",
                "ec2.instances",
                "1.0.0",
                "ec2:DescribeInstances",
            ),
            (
                "ec2.volumes.discovery",
                "ec2.volumes",
                "1.0.0",
                "ec2:DescribeVolumes",
            ),
            (
                "ec2.ebs-encryption-default",
                "ec2.ebs-defaults",
                "1.0.0",
                "ec2:GetEbsEncryptionByDefault",
            ),
            (
                "ec2.ebs-default-kms-key",
                "ec2.ebs-defaults",
                "1.0.0",
                "ec2:GetEbsDefaultKmsKeyId",
            ),
        }
    ),
    "security_groups": frozenset(
        {
            (
                "ec2.security-groups.discovery",
                "ec2.security-groups",
                "2.0.0",
                "ec2:DescribeSecurityGroups",
            )
        }
    ),
    "iam_account_evidence": frozenset(
        {
            (
                "iam.account-summary",
                "iam.account-summary",
                "1.0.0",
                "iam:GetAccountSummary",
            )
        }
    ),
    "iam_users": frozenset(
        {
            ("iam.users.discovery", "iam.users", "2.0.0", "iam:ListUsers"),
            ("iam.groups.discovery", "iam.groups", "2.0.0", "iam:ListGroups"),
            ("iam.roles.discovery", "iam.roles", "2.0.0", "iam:ListRoles"),
            (
                "iam.customer-managed-policies.discovery",
                "iam.policies",
                "2.0.0",
                "iam:ListPolicies",
            ),
        }
    ),
    # S3 has a dynamic per-bucket/per-reference manifest validated separately.
    "s3_evidence": frozenset(),
    "vpc_network_evidence": frozenset(
        {
            ("ec2.vpcs.discovery", "ec2.vpcs", "1.0.0", "ec2:DescribeVpcs"),
            (
                "ec2.subnets.discovery",
                "ec2.subnets",
                "1.0.0",
                "ec2:DescribeSubnets",
            ),
            (
                "ec2.flow-logs.discovery",
                "ec2.flow-logs",
                "1.0.0",
                "ec2:DescribeFlowLogs",
            ),
        }
    ),
}
_ADMISSION_AWARE_DISCOVERY_SOURCES = {
    "ec2.security-groups.discovery": (
        "security_group",
        "ec2.security-groups",
        "ec2:DescribeSecurityGroups",
    ),
    "ec2.vpcs.discovery": ("vpc", "ec2.vpcs", "ec2:DescribeVpcs"),
    "ec2.subnets.discovery": ("subnet", "ec2.subnets", "ec2:DescribeSubnets"),
    "ec2.flow-logs.discovery": (
        "vpc_flow_log",
        "ec2.flow-logs",
        "ec2:DescribeFlowLogs",
    ),
}
GRAPH_AWARE_COLLECTOR_NAMES = frozenset(_GRAPH_COLLECTOR_SOURCES)


@dataclass(frozen=True, slots=True)
class CollectionContext:
    """One immutable execution identity shared by every graph-aware collector."""

    scan_id: UUID
    collection_account_id: str
    region: str
    collected_at: datetime
    supplemental_regions: tuple[str, ...] = ()
    supplemental_region_source_complete: bool = True

    def __post_init__(self) -> None:
        """Keep the bucket-derived execution scope canonical and unambiguous."""

        if (
            not isinstance(self.region, str)
            or not self.region.strip()
            or any(
                not isinstance(region, str) or not region.strip()
                for region in self.supplemental_regions
            )
            or self.supplemental_regions != tuple(sorted(set(self.supplemental_regions)))
            or self.region in self.supplemental_regions
            or not isinstance(self.supplemental_region_source_complete, bool)
        ):
            raise ValueError(
                "supplemental Regions must be sorted, unique, non-empty, and exclude the "
                "requested Region"
            )


@dataclass(frozen=True, slots=True)
class SourceObservation:
    """One declared source and its normalized, digest-bound result."""

    contract: ScanSourceContract
    artifact: SourceEvidenceArtifact
    outcome: SourceEvidenceOutcome
    provenance: RelationshipProvenance


@dataclass(frozen=True, slots=True)
class RelationshipReference:
    """Collector-produced edge awaiting target resolution after all collectors run."""

    relationship_type: RelationshipType
    source: RelationshipEndpoint
    target: RelationshipEndpoint | UnresolvedRelationshipTarget
    provenance: RelationshipProvenance
    target_collector_name: str | None = None
    target_evidence_kind: str | None = None

    def __post_init__(self) -> None:
        if self.source.resource_snapshot_id is None:
            raise ValueError("relationship source must be observed in the current scan")
        if (
            isinstance(self.target, RelationshipEndpoint)
            and self.target.resource_snapshot_id is not None
        ):
            raise ValueError("relationship target resolution belongs to the inventory service")


@dataclass(frozen=True, slots=True)
class CollectorResult:
    """Backward-compatible collector output plus an optional evidence-graph fragment."""

    resources: tuple[NormalizedResource, ...] = ()
    status: CollectionStatus = CollectionStatus.SUCCEEDED
    source_contracts: tuple[ScanSourceContract, ...] = ()
    artifacts: tuple[SourceEvidenceArtifact, ...] = ()
    source_outcomes: tuple[SourceEvidenceOutcome, ...] = ()
    relationships: tuple[RelationshipReference, ...] = ()


class ResourceCollector(ABC):
    """Base class for fact-only AWS resource collectors."""

    collector_name: str
    produces_evidence_graph = False

    def __init__(self, client_provider: AWSClientProvider) -> None:
        self.client_provider = client_provider

    @abstractmethod
    def collect(self) -> list[NormalizedResource]:
        """Collect and normalize resources without making security decisions."""

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Collect with graph context while preserving the established collector API."""

        del context
        return CollectorResult(resources=tuple(self.collect()))


class CollectorEvidenceError(RuntimeError):
    """Raised when an AWS response omits or malforms a required collection fact."""

    def __init__(self, operation_name: str, fact_path: str) -> None:
        self.operation_name = operation_name
        self.fact_path = fact_path
        super().__init__(f"collector evidence is incomplete at {operation_name}.{fact_path}")


class CollectorEvidenceConflictError(CollectorEvidenceError):
    """Raised when one stable AWS identity has contradictory observations."""


def build_source_observation(
    *,
    context: CollectionContext,
    contract_key: str,
    contract_version: str,
    phase: EvidenceCollectionPhase,
    subject: AccountEvidenceSubject | ResourceEvidenceSubject,
    evidence_kind: str,
    collector: str,
    collector_version: str,
    source_api: str,
    cardinality: EvidenceCardinality,
    evidence_reference: str,
    evidence_schema: str,
    evidence_schema_version: str,
    normalized_payload: Mapping[str, object],
    state: EvidenceSourceState,
    failure_category: EvidenceFailureCategory | None = None,
    identity_authoritative: bool = False,
    allows_supplemental_region: bool = False,
) -> SourceObservation:
    """Build one exact contract/artifact/outcome/provenance group."""

    owner_mode = ResourceOwnerMode.COLLECTION_ACCOUNT
    if isinstance(subject, ResourceEvidenceSubject):
        if subject.aws_account_id == "aws":
            owner_mode = ResourceOwnerMode.AWS_MANAGED
        elif subject.aws_account_id != context.collection_account_id:
            owner_mode = ResourceOwnerMode.EXTERNAL_ACCOUNT

    artifact = SourceEvidenceArtifact.for_payload(
        scan_id=context.scan_id,
        collection_account_id=context.collection_account_id,
        evidence_reference=evidence_reference,
        evidence_schema=evidence_schema,
        evidence_schema_version=evidence_schema_version,
        collected_at=context.collected_at,
        normalized_payload=normalized_payload,
    )
    contract = ScanSourceContract.for_scan(
        contract_key=contract_key,
        contract_version=contract_version,
        scan_id=context.scan_id,
        collection_account_id=context.collection_account_id,
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
    outcome = SourceEvidenceOutcome.for_observation(
        scan_id=context.scan_id,
        collection_account_id=context.collection_account_id,
        phase=phase,
        subject=subject,
        evidence_kind=evidence_kind,
        state=state,
        failure_category=failure_category,
        collector=collector,
        collector_version=collector_version,
        source_api=source_api,
        collected_at=context.collected_at,
        evidence_reference=artifact.evidence_reference,
        evidence_sha256=artifact.evidence_sha256,
    )
    return SourceObservation(
        contract=contract,
        artifact=artifact,
        outcome=outcome,
        provenance=RelationshipProvenance(
            collector=collector,
            collector_version=collector_version,
            source_api=source_api,
            evidence_reference=artifact.evidence_reference,
            collected_at=context.collected_at,
        ),
    )


def source_failure(error: BaseException) -> tuple[EvidenceSourceState, EvidenceFailureCategory]:
    """Map a provider or evidence-boundary failure to a sanitized closed outcome."""

    if isinstance(error, CollectorEvidenceConflictError):
        return EvidenceSourceState.CONFLICT, EvidenceFailureCategory.CONFLICTING_EVIDENCE
    if isinstance(error, CollectorEvidenceError):
        return EvidenceSourceState.MALFORMED, EvidenceFailureCategory.MALFORMED_RESPONSE
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code")
        if code in _ACCESS_DENIED_CODES:
            category = EvidenceFailureCategory.ACCESS_DENIED
        elif code in _AUTHENTICATION_CODES:
            category = EvidenceFailureCategory.AUTHENTICATION_FAILED
        elif code in _THROTTLING_CODES:
            category = EvidenceFailureCategory.THROTTLED
        elif code in _UNSUPPORTED_CODES:
            category = EvidenceFailureCategory.UNSUPPORTED_OPERATION
        else:
            category = EvidenceFailureCategory.SERVICE_ERROR
        return EvidenceSourceState.UNAVAILABLE, category
    if isinstance(error, ConnectTimeoutError | ReadTimeoutError | EndpointConnectionError):
        return EvidenceSourceState.UNAVAILABLE, EvidenceFailureCategory.TIMEOUT
    if isinstance(error, BotoCoreError):
        return EvidenceSourceState.UNAVAILABLE, EvidenceFailureCategory.SERVICE_ERROR
    raise TypeError("unsupported source failure type")


def collection_status_for(outcomes: Iterable[SourceEvidenceOutcome]) -> CollectionStatus:
    """Roll source outcomes up without erasing their result-sensitive detail."""

    states = tuple(outcome.state for outcome in outcomes)
    complete_states = {EvidenceSourceState.PRESENT, EvidenceSourceState.EXPECTED_ABSENCE}
    if states and all(state in complete_states for state in states):
        return CollectionStatus.SUCCEEDED
    if states and all(state is EvidenceSourceState.UNAVAILABLE for state in states):
        return CollectionStatus.FAILED
    return CollectionStatus.PARTIAL


def graph_collection_status_for(
    *,
    collector_name: str,
    outcomes: Iterable[SourceEvidenceOutcome],
    artifacts: Iterable[SourceEvidenceArtifact],
    contracts: Iterable[ScanSourceContract] = (),
) -> CollectionStatus:
    """Reconstruct one graph collector's coverage from persisted evidence only."""

    try:
        source_collectors = _GRAPH_COLLECTOR_SOURCES[collector_name]
    except KeyError as error:
        raise ValueError("unknown graph-aware collector") from error

    selected_outcomes = tuple(
        outcome for outcome in outcomes if outcome.collector in source_collectors
    )
    contracts_tuple = tuple(contracts)
    if not selected_outcomes:
        raise ValueError("graph-aware collector has no source outcomes")
    artifacts_by_reference: dict[str, SourceEvidenceArtifact] = {}
    for artifact in artifacts:
        if artifact.evidence_reference in artifacts_by_reference:
            raise ValueError("evidence references must be unique for coverage reconstruction")
        artifacts_by_reference[artifact.evidence_reference] = artifact

    if collector_name == "access_analyzer_evidence":
        discovery_incomplete = _access_analyzer_coverage_is_incomplete(
            outcomes=selected_outcomes,
            artifacts_by_reference=artifacts_by_reference,
        )
    elif collector_name == "cloudtrail_evidence":
        discovery_incomplete = validate_cloudtrail_source_contract_manifest(
            outcomes=selected_outcomes,
            contracts=contracts_tuple,
            artifacts=artifacts_by_reference.values(),
        )
    elif collector_name == "s3_evidence":
        validate_s3_source_contract_manifest(
            outcomes=selected_outcomes,
            contracts=contracts_tuple,
        )
        region_evidence = reconstruct_s3_bucket_region_evidence(
            outcomes=selected_outcomes,
            artifacts=artifacts_by_reference.values(),
            contracts=contracts_tuple,
        )
        if region_evidence is None:  # pragma: no cover - selected source invariant
            raise ValueError("S3 evidence has no bucket discovery manifest")
        discovery_incomplete = not region_evidence.complete
        _validate_s3_evidence_manifest(
            outcomes=selected_outcomes,
            artifacts_by_reference=artifacts_by_reference,
            bucket_regions=dict(region_evidence.bucket_regions),
        )
    else:
        required_discovery_sources = _REQUIRED_GRAPH_DISCOVERY_SOURCES[collector_name]
        actual_discovery_sources = [
            (
                outcome.evidence_kind,
                outcome.collector,
                outcome.collector_version,
                outcome.source_api,
            )
            for outcome in selected_outcomes
            if outcome.phase is EvidenceCollectionPhase.DISCOVERY
        ]
        if set(actual_discovery_sources) != required_discovery_sources or len(
            actual_discovery_sources
        ) != len(required_discovery_sources):
            raise ValueError("graph-aware collector discovery manifest is incomplete or unknown")
        discovery_incomplete = False

    admission_incomplete = False
    for outcome in selected_outcomes:
        expected_source = _ADMISSION_AWARE_DISCOVERY_SOURCES.get(outcome.evidence_kind)
        if expected_source is None:
            continue
        expected_resource_type, expected_collector, expected_source_api = expected_source
        if outcome.phase is not EvidenceCollectionPhase.DISCOVERY or not isinstance(
            outcome.subject, AccountEvidenceSubject
        ):
            raise ValueError("admission metadata requires a Regional discovery outcome")
        if outcome.collector != expected_collector or outcome.source_api != expected_source_api:
            raise ValueError("admission-aware discovery source identity is invalid")
        artifact = artifacts_by_reference.get(outcome.evidence_reference)
        if artifact is None:
            raise ValueError("admission-aware discovery outcome has no bound artifact")
        if (
            artifact.evidence_schema != outcome.evidence_kind
            or artifact.evidence_schema_version != "1.0.0"
            or artifact.scan_id != outcome.scan_id
            or artifact.collection_account_id != outcome.collection_account_id
            or artifact.collected_at != outcome.collected_at
            or artifact.evidence_sha256 != outcome.evidence_sha256
        ):
            raise ValueError("admission-aware discovery artifact does not match its outcome")
        admission_incomplete |= _admission_projection_is_incomplete(
            outcome=outcome,
            artifact=artifact,
            expected_resource_type=expected_resource_type,
        )

    source_status = collection_status_for(selected_outcomes)
    if source_status is CollectionStatus.SUCCEEDED and (
        admission_incomplete or discovery_incomplete
    ):
        return CollectionStatus.PARTIAL
    return source_status


def validate_access_analyzer_s3_region_source_status(
    *,
    outcomes: Iterable[SourceEvidenceOutcome],
    artifacts: Iterable[SourceEvidenceArtifact],
    s3_status: CollectionStatus,
    contracts: Iterable[ScanSourceContract] = (),
) -> bool:
    """Bind Analyzer coverage to exact 5E Region evidence or the pre-5E rollup."""

    if not isinstance(s3_status, CollectionStatus):
        raise TypeError("S3 collector status must use the canonical collection status")
    all_outcomes = tuple(outcomes)
    selected_outcomes = tuple(
        outcome
        for outcome in all_outcomes
        if outcome.collector in _GRAPH_COLLECTOR_SOURCES["access_analyzer_evidence"]
    )
    if not selected_outcomes:
        raise ValueError("Access Analyzer graph sources are absent")
    artifacts_by_reference: dict[str, SourceEvidenceArtifact] = {}
    for artifact in artifacts:
        if artifact.evidence_reference in artifacts_by_reference:
            raise ValueError("evidence references must be unique for coverage reconstruction")
        artifacts_by_reference[artifact.evidence_reference] = artifact
    source_complete = not _access_analyzer_coverage_is_incomplete(
        outcomes=selected_outcomes,
        artifacts_by_reference=artifacts_by_reference,
    )
    region_evidence = reconstruct_s3_bucket_region_evidence(
        outcomes=all_outcomes,
        artifacts=artifacts_by_reference.values(),
        contracts=contracts,
    )
    expected_complete = (
        region_evidence.complete
        if region_evidence is not None
        else s3_status is CollectionStatus.SUCCEEDED
    )
    if source_complete is not expected_complete:
        raise ValueError("Access Analyzer Region coverage disagrees with S3 discovery status")
    return source_complete


def has_graph_collection_sources(
    *,
    collector_name: str,
    outcomes: Iterable[SourceEvidenceOutcome],
) -> bool:
    """Return whether a graph contains sources owned by one operational collector."""

    try:
        source_collectors = _GRAPH_COLLECTOR_SOURCES[collector_name]
    except KeyError as error:
        raise ValueError("unknown graph-aware collector") from error
    return any(outcome.collector in source_collectors for outcome in outcomes)


def graph_collectors_for_outcomes(
    outcomes: Iterable[SourceEvidenceOutcome],
) -> frozenset[str]:
    """Return operational graph collectors represented by persisted source outcomes."""

    outcome_collectors = {outcome.collector for outcome in outcomes}
    return frozenset(
        collector_name
        for collector_name, source_collectors in _GRAPH_COLLECTOR_SOURCES.items()
        if outcome_collectors & source_collectors
    )


def graph_collection_validation_required(
    *,
    collector_name: str,
    requested_collectors: Iterable[str],
    outcomes: Iterable[SourceEvidenceOutcome],
) -> bool:
    """Preserve accepted history while requiring every integrated graph producer."""

    if collector_name not in GRAPH_AWARE_COLLECTOR_NAMES:
        return False
    if has_graph_collection_sources(collector_name=collector_name, outcomes=outcomes):
        return True
    requested = frozenset(requested_collectors)
    if collector_name in {
        "access_analyzer_evidence",
        "cloudtrail_evidence",
        "ec2_ebs_evidence",
        "iam_account_evidence",
        "s3_evidence",
        "vpc_network_evidence",
    }:
        return collector_name in requested
    if collector_name == "iam_users":
        return "iam_account_evidence" in requested
    return collector_name == "security_groups" and "vpc_network_evidence" in requested


def _validate_s3_evidence_manifest(
    *,
    outcomes: tuple[SourceEvidenceOutcome, ...],
    artifacts_by_reference: Mapping[str, SourceEvidenceArtifact],
    bucket_regions: Mapping[str, str],
) -> None:
    """Validate the dynamic 5E source set without coupling it to the outer rollup."""

    account_sources = tuple(
        item for item in outcomes if item.collector == "s3.account-public-access-block"
    )
    if len(account_sources) != 1:
        raise ValueError("S3 evidence requires exactly one account Public Access Block source")
    account_source = account_sources[0]
    if (
        account_source.phase is not EvidenceCollectionPhase.DISCOVERY
        or not isinstance(account_source.subject, AccountEvidenceSubject)
        or account_source.subject.aws_account_id != account_source.collection_account_id
        or account_source.subject.scope is not ResourceScope.GLOBAL
        or account_source.evidence_kind != "s3.account-public-access-block"
        or account_source.collector_version != "1.0.0"
        or account_source.source_api != "s3:GetAccountPublicAccessBlock"
        or account_source.state not in _S3_ACCOUNT_PUBLIC_ACCESS_BLOCK_STATES
    ):
        raise ValueError("S3 account Public Access Block source identity is invalid")
    account_artifact = _require_matching_source_artifact(
        outcome=account_source,
        artifacts_by_reference=artifacts_by_reference,
        expected_schema="s3.account-public-access-block",
    )
    account_payload = account_artifact.model_dump(mode="json")["normalized_payload"]
    if not isinstance(account_payload, dict):  # pragma: no cover - artifact invariant
        raise ValueError("S3 account Public Access Block metadata is malformed")
    _validate_source_completion_metadata(outcome=account_source, payload=account_payload)
    account_block = account_payload.get("public_access_block")
    expected_absence = account_source.state is EvidenceSourceState.EXPECTED_ABSENCE
    if (
        account_payload.get("account_id") != account_source.collection_account_id
        or account_payload.get("configured")
        is not (account_source.state is EvidenceSourceState.PRESENT)
        or account_payload.get("expected_absence") is not expected_absence
        or (
            account_source.state
            in {EvidenceSourceState.PRESENT, EvidenceSourceState.EXPECTED_ABSENCE}
            and (
                not isinstance(account_block, dict)
                or set(account_block) != _S3_PUBLIC_ACCESS_BLOCK_FIELDS
                or not all(isinstance(value, bool) for value in account_block.values())
                or (expected_absence and any(account_block.values()))
            )
        )
        or (
            account_source.state
            not in {EvidenceSourceState.PRESENT, EvidenceSourceState.EXPECTED_ABSENCE}
            and account_block is not None
        )
    ):
        raise ValueError("S3 account Public Access Block evidence is malformed")

    per_bucket_sources = {
        "s3.bucket-acl": "s3:GetBucketAcl",
        "s3.bucket-encryption": "s3:GetEncryptionConfiguration",
        "s3.bucket-ownership-controls": "s3:GetBucketOwnershipControls",
        "s3.bucket-policy": "s3:GetBucketPolicy",
        "s3.bucket-policy-status": "s3:GetBucketPolicyStatus",
        "s3.bucket-public-access-block": "s3:GetBucketPublicAccessBlock",
        "s3.bucket-tags": "s3:GetBucketTagging",
        "s3.bucket-versioning": "s3:GetBucketVersioning",
    }
    actual_sources: list[tuple[str, str]] = []
    sources_by_bucket: dict[
        str,
        dict[str, tuple[SourceEvidenceOutcome, object]],
    ] = {}
    bucket_subjects: dict[str, ResourceEvidenceSubject] = {}
    for outcome in outcomes:
        expected_api = per_bucket_sources.get(outcome.collector)
        if expected_api is None:
            continue
        subject = outcome.subject
        if (
            outcome.phase is not EvidenceCollectionPhase.ENRICHMENT
            or not isinstance(subject, ResourceEvidenceSubject)
            or subject.aws_account_id != outcome.collection_account_id
            or subject.service != "s3"
            or subject.resource_type != "s3_bucket"
            or subject.scope is not ResourceScope.REGIONAL
            or bucket_regions.get(subject.aws_resource_id) != subject.region
            or outcome.evidence_kind != outcome.collector
            or outcome.collector_version != "1.0.0"
            or outcome.source_api != expected_api
            or outcome.state not in _S3_PER_BUCKET_SOURCE_STATES[outcome.collector]
        ):
            raise ValueError("S3 per-bucket source identity is invalid")
        artifact = _require_matching_source_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema=outcome.evidence_kind,
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):  # pragma: no cover - artifact invariant
            raise ValueError("S3 per-bucket evidence metadata is malformed")
        _validate_source_completion_metadata(outcome=outcome, payload=payload)
        bucket_arn = payload.get("bucket_arn")
        bucket_arn_parts = bucket_arn.split(":", maxsplit=5) if isinstance(bucket_arn, str) else []
        if (
            payload.get("account_id") != subject.aws_account_id
            or payload.get("bucket_name") != subject.aws_resource_id
            or payload.get("bucket_region") != subject.region
            or len(bucket_arn_parts) != 6
            or bucket_arn_parts[0] != "arn"
            or not bucket_arn_parts[1]
            or any(
                not (
                    character.isascii()
                    and (character.islower() or character.isdigit() or character == "-")
                )
                for character in bucket_arn_parts[1]
            )
            or bucket_arn_parts[2:] != ["s3", "", "", subject.aws_resource_id]
            or payload.get("expected_absence")
            is not (outcome.state is EvidenceSourceState.EXPECTED_ABSENCE)
        ):
            raise ValueError("S3 per-bucket evidence identity is inconsistent")
        try:
            projected_value = validate_s3_bucket_evidence_value(
                evidence_kind=outcome.evidence_kind,
                state=outcome.state,
                value=payload.get("value"),
            )
        except ValueError as error:
            raise ValueError("S3 per-bucket evidence value is malformed") from error
        if "legacy_projection" not in payload:
            raise ValueError("S3 per-bucket evidence omitted its legacy projection")
        legacy_projection = payload["legacy_projection"]
        if outcome.evidence_kind not in {
            "s3.bucket-encryption",
            "s3.bucket-public-access-block",
        }:
            if legacy_projection is not None:
                raise ValueError("S3 per-bucket evidence has an unknown legacy projection")
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
        actual_sources.append((outcome.collector, subject.aws_resource_id))
        sources_by_bucket.setdefault(subject.aws_resource_id, {})[outcome.collector] = (
            outcome,
            projected_value,
        )
        bucket_subjects[subject.aws_resource_id] = subject

    expected_sources = {
        (collector, bucket_name)
        for collector in per_bucket_sources
        for bucket_name in bucket_regions
    }
    if len(actual_sources) != len(set(actual_sources)) or set(actual_sources) != expected_sources:
        raise ValueError("S3 per-bucket evidence manifest is incomplete or unknown")
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
                account_public_access_block_outcome=account_source,
                account_public_access_block_value=account_block,
                bucket_public_access_block_outcome=bucket_block_outcome,
                bucket_public_access_block_value=bucket_block,
                ownership_controls_outcome=ownership_outcome,
                ownership_controls_value=ownership_value,
            )

    expected_kms_sources: dict[str, set[str]] = {}
    expected_kms_partitions: dict[str, set[str]] = {}
    for outcome in outcomes:
        if outcome.collector != "s3.bucket-encryption":
            continue
        subject = outcome.subject
        if not isinstance(subject, ResourceEvidenceSubject):  # pragma: no cover - checked above
            raise ValueError("S3 encryption evidence requires a bucket subject")
        artifact = _require_matching_source_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema="s3.bucket-encryption",
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):  # pragma: no cover - artifact invariant
            raise ValueError("S3 encryption metadata is malformed")
        bucket_arn = payload.get("bucket_arn")
        bucket_arn_parts = bucket_arn.split(":", maxsplit=5) if isinstance(bucket_arn, str) else []
        if (
            len(bucket_arn_parts) != 6
            or bucket_arn_parts[0] != "arn"
            or not bucket_arn_parts[1]
            or any(
                not (
                    character.isascii()
                    and (character.islower() or character.isdigit() or character == "-")
                )
                for character in bucket_arn_parts[1]
            )
            or bucket_arn_parts[2:] != ["s3", "", "", subject.aws_resource_id]
        ):
            raise ValueError("S3 encryption bucket ARN is malformed")
        partition = bucket_arn_parts[1]
        value = payload.get("value")
        if outcome.state is not EvidenceSourceState.PRESENT:
            continue
        try:
            references = s3_encryption_kms_references(value)
        except ValueError as error:
            raise ValueError("S3 encryption metadata is malformed") from error
        for reference in references:
            lookup_region = subject.region
            if reference.startswith("arn:"):
                arn_parts = reference.split(":", maxsplit=5)
                resource_parts = arn_parts[5].split("/", maxsplit=1) if len(arn_parts) == 6 else []
                if (
                    len(arn_parts) != 6
                    or arn_parts[:3] != ["arn", partition, "kms"]
                    or not arn_parts[3]
                    or len(arn_parts[4]) != 12
                    or not arn_parts[4].isascii()
                    or not arn_parts[4].isdigit()
                    or len(resource_parts) != 2
                    or resource_parts[0] not in {"alias", "key"}
                    or not resource_parts[1]
                ):
                    raise ValueError("S3 encryption KMS reference is malformed")
                lookup_region = arn_parts[3]
            if lookup_region is None:  # pragma: no cover - Regional subject invariant
                raise ValueError("S3 encryption KMS reference has no Region")
            if any(separator in lookup_region for separator in ("\x00", "\x1f", "\r", "\n")):
                raise ValueError("S3 encryption KMS reference has an invalid Region")
            digest = hashlib.sha256(f"{lookup_region}\x00{reference}".encode()).hexdigest()
            evidence_kind = f"kms.key.{digest}"
            expected_kms_sources.setdefault(evidence_kind, set()).add(subject.aws_resource_id)
            expected_kms_partitions.setdefault(evidence_kind, set()).add(partition)

    kms_sources: dict[str, set[str]] = {}
    canonical_kms_values: dict[tuple[str, str], dict[str, object]] = {}
    for outcome in outcomes:
        if outcome.collector != "kms.keys":
            continue
        digest = outcome.evidence_kind.removeprefix("kms.key.")
        if (
            outcome.phase is not EvidenceCollectionPhase.ENRICHMENT
            or outcome.state
            not in {
                EvidenceSourceState.PRESENT,
                EvidenceSourceState.UNAVAILABLE,
                EvidenceSourceState.MALFORMED,
                EvidenceSourceState.CONFLICT,
            }
            or not isinstance(outcome.subject, ResourceEvidenceSubject)
            or not outcome.evidence_kind.startswith("kms.key.")
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or outcome.collector_version != "1.0.0"
            or outcome.source_api != "kms:DescribeKey"
            or outcome.evidence_kind in kms_sources
        ):
            raise ValueError("KMS DescribeKey source identity is invalid")
        artifact = _require_matching_source_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema="kms.key",
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):  # pragma: no cover - artifact invariant
            raise ValueError("KMS DescribeKey evidence metadata is malformed")
        _validate_source_completion_metadata(outcome=outcome, payload=payload)
        region = payload.get("region")
        supplied_reference = payload.get("supplied_reference")
        source_bucket_names = payload.get("source_bucket_names")
        if (
            not isinstance(region, str)
            or not region
            or any(separator in region for separator in ("\x00", "\x1f", "\r", "\n"))
            or not isinstance(supplied_reference, str)
            or not supplied_reference
            or any(separator in supplied_reference for separator in ("\x00", "\x1f", "\r", "\n"))
            or not isinstance(source_bucket_names, list)
            or not source_bucket_names
            or not all(isinstance(item, str) and item for item in source_bucket_names)
            or source_bucket_names != sorted(set(source_bucket_names))
            or any(item not in bucket_regions for item in source_bucket_names)
            or outcome.evidence_kind
            != "kms.key." + hashlib.sha256(f"{region}\x00{supplied_reference}".encode()).hexdigest()
        ):
            raise ValueError("KMS DescribeKey evidence metadata is malformed")
        subject = outcome.subject
        try:
            key = validate_kms_key_evidence_value(
                state=outcome.state,
                value=payload.get("key"),
            )
        except ValueError as error:
            raise ValueError("KMS DescribeKey evidence metadata is malformed") from error
        if outcome.state is EvidenceSourceState.PRESENT:
            if (
                not isinstance(subject, ResourceEvidenceSubject)
                or subject.service != "kms"
                or subject.resource_type != "kms_key"
                or subject.scope is not ResourceScope.REGIONAL
                or subject.region != region
                or key is None
            ):
                raise ValueError("successful KMS DescribeKey identity is invalid")
            key_arn = key.get("arn")
            key_id = key.get("key_id")
            key_account_id = key.get("aws_account_id")
            key_arn_parts = key_arn.split(":", maxsplit=5) if isinstance(key_arn, str) else []
            if (
                not isinstance(key_id, str)
                or not key_id
                or any(separator in key_id for separator in ("\x1f", "\r", "\n"))
                or not isinstance(key_account_id, str)
                or len(key_account_id) != 12
                or not key_account_id.isascii()
                or not key_account_id.isdigit()
                or key.get("region") != region
                or key.get("key_manager") not in {"AWS", "CUSTOMER"}
                or len(key_arn_parts) != 6
                or key_arn_parts[0] != "arn"
                or not key_arn_parts[1]
                or any(separator in key_arn for separator in ("\x1f", "\r", "\n"))
                or expected_kms_partitions.get(outcome.evidence_kind) != {key_arn_parts[1]}
                or key_arn_parts[2:] != ["kms", region, key_account_id, f"key/{key_id}"]
                or subject.aws_account_id != key_account_id
                or subject.aws_resource_id != key_arn
                or not kms_reference_matches_key_identity(
                    supplied_reference=supplied_reference,
                    lookup_region=region,
                    collection_account_id=outcome.collection_account_id,
                    partition=key_arn_parts[1] if len(key_arn_parts) == 6 else None,
                    key_arn=key_arn,
                    key_id=key_id,
                    key_account_id=key_account_id,
                )
            ):
                raise ValueError("successful KMS DescribeKey metadata is inconsistent")
            canonical_identity = (region, key_arn)
            existing_key = canonical_kms_values.get(canonical_identity)
            if existing_key is not None and existing_key != key:
                raise ValueError("canonical KMS DescribeKey evidence is conflicting")
            canonical_kms_values[canonical_identity] = key
        elif (
            not isinstance(subject, ResourceEvidenceSubject)
            or subject != bucket_subjects.get(source_bucket_names[0])
            or key is not None
        ):
            raise ValueError("failed KMS DescribeKey subject is invalid")
        kms_sources[outcome.evidence_kind] = set(source_bucket_names)

    if kms_sources != expected_kms_sources:
        raise ValueError("KMS DescribeKey evidence manifest is incomplete or unknown")

    recognized_collectors = {
        "kms.keys",
        "s3.account-public-access-block",
        "s3.bucket-location",
        "s3.buckets",
        *per_bucket_sources,
    }
    if any(outcome.collector not in recognized_collectors for outcome in outcomes):
        raise ValueError("S3 evidence manifest contains an unknown source")


def _access_analyzer_coverage_is_incomplete(
    *,
    outcomes: tuple[SourceEvidenceOutcome, ...],
    artifacts_by_reference: Mapping[str, SourceEvidenceArtifact],
) -> bool:
    """Validate the dynamic per-Region Analyzer manifest and its S3 coverage input."""

    analyzer_outcomes: list[SourceEvidenceOutcome] = []
    findings_outcomes: list[SourceEvidenceOutcome] = []
    summary_outcomes: list[SourceEvidenceOutcome] = []
    detail_outcomes: list[SourceEvidenceOutcome] = []
    for outcome in outcomes:
        if outcome.collector == "access-analyzer.analyzers":
            if (
                outcome.phase is not EvidenceCollectionPhase.DISCOVERY
                or outcome.evidence_kind != "access-analyzer.analyzers.discovery"
                or outcome.collector_version != "1.0.0"
                or outcome.source_api != "access-analyzer:ListAnalyzers"
            ):
                raise ValueError("Access Analyzer source identity is invalid")
            analyzer_outcomes.append(outcome)
        elif outcome.collector == "access-analyzer.findings":
            if outcome.phase is EvidenceCollectionPhase.DISCOVERY:
                prefix = "access-analyzer.findings.discovery."
                digest = outcome.evidence_kind.removeprefix(prefix)
                if (
                    not outcome.evidence_kind.startswith(prefix)
                    or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)
                    or outcome.collector_version != "1.0.0"
                    or outcome.source_api != "access-analyzer:ListFindings"
                ):
                    raise ValueError("Access Analyzer source identity is invalid")
                findings_outcomes.append(outcome)
            elif (
                outcome.phase is EvidenceCollectionPhase.ENRICHMENT
                and outcome.evidence_kind == "access-analyzer.finding-summary"
                and outcome.collector_version == "1.0.0"
                and outcome.source_api == "access-analyzer:ListFindings"
            ):
                summary_outcomes.append(outcome)
            else:
                raise ValueError("Access Analyzer source identity is invalid")
        elif outcome.collector == "access-analyzer.finding-details":
            if (
                outcome.phase is not EvidenceCollectionPhase.ENRICHMENT
                or outcome.evidence_kind != "access-analyzer.finding-details"
                or outcome.collector_version != "1.0.0"
                or outcome.source_api != "access-analyzer:GetFinding"
            ):
                raise ValueError("Access Analyzer source identity is invalid")
            detail_outcomes.append(outcome)
        else:
            raise ValueError("Access Analyzer source identity is invalid")

    if not analyzer_outcomes:
        raise ValueError("Access Analyzer discovery manifest is incomplete")

    declared_regions: list[str] = []
    required_regions: tuple[str, ...] | None = None
    region_source_complete: bool | None = None
    relevant_analyzers: dict[str, str] = {}
    for outcome in analyzer_outcomes:
        if not isinstance(outcome.subject, AccountEvidenceSubject):
            raise ValueError("Access Analyzer discovery requires an account subject")
        region = outcome.subject.region
        if outcome.subject.scope is not ResourceScope.REGIONAL or region is None:
            raise ValueError("Access Analyzer discovery requires a Regional subject")
        artifact = _require_matching_source_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):  # pragma: no cover - artifact model invariant
            raise ValueError("Access Analyzer discovery metadata is malformed")
        payload_regions = payload.get("required_regions")
        payload_region_source_complete = payload.get("s3_region_discovery_complete")
        analyzer_arns = payload.get("relevant_analyzer_arns")
        if (
            payload.get("account_id") != outcome.collection_account_id
            or payload.get("region") != region
            or not isinstance(payload_regions, list)
            or not payload_regions
            or not all(isinstance(item, str) and item for item in payload_regions)
            or payload_regions != sorted(set(payload_regions))
            or not isinstance(payload_region_source_complete, bool)
            or not isinstance(payload.get("analyzers"), list)
            or not isinstance(analyzer_arns, list)
            or not all(isinstance(item, str) and item for item in analyzer_arns)
            or analyzer_arns != sorted(set(analyzer_arns))
        ):
            raise ValueError("Access Analyzer discovery metadata is malformed")
        _validate_source_completion_metadata(outcome=outcome, payload=payload)

        regional_manifest = tuple(payload_regions)
        if required_regions is None:
            required_regions = regional_manifest
            region_source_complete = payload_region_source_complete
        elif (
            required_regions != regional_manifest
            or region_source_complete is not payload_region_source_complete
        ):
            raise ValueError("Access Analyzer Regional manifests disagree")
        declared_regions.append(region)
        for analyzer_arn in analyzer_arns:
            if analyzer_arn in relevant_analyzers:
                raise ValueError("Access Analyzer identity appears in multiple Regions")
            relevant_analyzers[analyzer_arn] = region

    if required_regions is None or tuple(sorted(declared_regions)) != required_regions:
        raise ValueError("Access Analyzer Regional discovery manifest is incomplete")

    observed_analyzers: dict[str, str] = {}
    for outcome in findings_outcomes:
        if not isinstance(outcome.subject, AccountEvidenceSubject):
            raise ValueError("Access Analyzer findings discovery requires an account subject")
        region = outcome.subject.region
        if outcome.subject.scope is not ResourceScope.REGIONAL or region is None:
            raise ValueError("Access Analyzer findings discovery requires a Regional subject")
        artifact = _require_matching_source_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema="access-analyzer.findings.discovery",
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):  # pragma: no cover - artifact model invariant
            raise ValueError("Access Analyzer findings metadata is malformed")
        analyzer = payload.get("analyzer")
        analyzer_arn = analyzer.get("arn") if isinstance(analyzer, dict) else None
        finding_ids = payload.get("finding_ids")
        resource_arns = payload.get("resource_arns")
        if (
            payload.get("account_id") != outcome.collection_account_id
            or payload.get("region") != region
            or not isinstance(analyzer_arn, str)
            or not analyzer_arn
            or not isinstance(finding_ids, list)
            or not all(isinstance(item, str) and item for item in finding_ids)
            or finding_ids != sorted(set(finding_ids))
            or not isinstance(resource_arns, list)
            or not all(isinstance(item, str) and item for item in resource_arns)
            or len(resource_arns) != len(finding_ids)
        ):
            raise ValueError("Access Analyzer findings metadata is malformed")
        expected_kind = (
            "access-analyzer.findings.discovery."
            + hashlib.sha256(analyzer_arn.encode("utf-8")).hexdigest()
        )
        if outcome.evidence_kind != expected_kind:
            raise ValueError("Access Analyzer findings identity is ambiguous")
        _validate_source_completion_metadata(outcome=outcome, payload=payload)
        if analyzer_arn in observed_analyzers:
            raise ValueError("Access Analyzer findings source is duplicated")
        observed_analyzers[analyzer_arn] = region

    if observed_analyzers != relevant_analyzers:
        raise ValueError("Access Analyzer findings manifest is incomplete or unknown")
    expected_findings = {
        (analyzer_arn, finding_id): region
        for outcome in findings_outcomes
        for analyzer_arn, finding_id, region in _finding_manifest_entries(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
        )
    }
    summary_subjects = _finding_enrichment_subjects(
        outcomes=summary_outcomes,
        artifacts_by_reference=artifacts_by_reference,
        expected_findings=expected_findings,
        expected_schema="access-analyzer.finding-summary",
    )
    detail_subjects = _finding_enrichment_subjects(
        outcomes=detail_outcomes,
        artifacts_by_reference=artifacts_by_reference,
        expected_findings=expected_findings,
        expected_schema="access-analyzer.finding-details",
    )
    if summary_subjects != detail_subjects or set(summary_subjects) != set(expected_findings):
        raise ValueError("Access Analyzer finding enrichment manifest is incomplete or unknown")
    return region_source_complete is False


def _require_matching_source_artifact(
    *,
    outcome: SourceEvidenceOutcome,
    artifacts_by_reference: Mapping[str, SourceEvidenceArtifact],
    expected_schema: str | None = None,
) -> SourceEvidenceArtifact:
    artifact = artifacts_by_reference.get(outcome.evidence_reference)
    if artifact is None:
        raise ValueError("source outcome has no bound artifact")
    if (
        artifact.evidence_schema != (expected_schema or outcome.evidence_kind)
        or artifact.evidence_schema_version != "1.0.0"
        or artifact.scan_id != outcome.scan_id
        or artifact.collection_account_id != outcome.collection_account_id
        or artifact.collected_at != outcome.collected_at
        or artifact.evidence_sha256 != outcome.evidence_sha256
    ):
        raise ValueError("source artifact does not match its outcome")
    return artifact


def _finding_manifest_entries(
    *,
    outcome: SourceEvidenceOutcome,
    artifacts_by_reference: Mapping[str, SourceEvidenceArtifact],
) -> tuple[tuple[str, str, str], ...]:
    """Return the exact analyzer/finding identities promised by one discovery source."""

    artifact = _require_matching_source_artifact(
        outcome=outcome,
        artifacts_by_reference=artifacts_by_reference,
        expected_schema="access-analyzer.findings.discovery",
    )
    payload = artifact.model_dump(mode="json")["normalized_payload"]
    if not isinstance(payload, dict):  # pragma: no cover - artifact model invariant
        raise ValueError("Access Analyzer findings metadata is malformed")
    analyzer = payload.get("analyzer")
    analyzer_arn = analyzer.get("arn") if isinstance(analyzer, dict) else None
    region = outcome.subject.region if isinstance(outcome.subject, AccountEvidenceSubject) else None
    finding_ids = payload.get("finding_ids")
    if (
        not isinstance(analyzer_arn, str)
        or not analyzer_arn
        or not isinstance(region, str)
        or not isinstance(finding_ids, list)
    ):
        raise ValueError("Access Analyzer findings metadata is malformed")
    return tuple((analyzer_arn, finding_id, region) for finding_id in finding_ids)


def _finding_enrichment_subjects(
    *,
    outcomes: Iterable[SourceEvidenceOutcome],
    artifacts_by_reference: Mapping[str, SourceEvidenceArtifact],
    expected_findings: Mapping[tuple[str, str], str],
    expected_schema: str,
) -> dict[tuple[str, str], UUID]:
    """Bind each discovered finding to one exact resource enrichment subject."""

    subjects: dict[tuple[str, str], UUID] = {}
    for outcome in outcomes:
        if not isinstance(outcome.subject, ResourceEvidenceSubject):
            raise ValueError("Access Analyzer finding enrichment requires a resource subject")
        artifact = _require_matching_source_artifact(
            outcome=outcome,
            artifacts_by_reference=artifacts_by_reference,
            expected_schema=expected_schema,
        )
        payload = artifact.model_dump(mode="json")["normalized_payload"]
        if not isinstance(payload, dict):  # pragma: no cover - artifact model invariant
            raise ValueError("Access Analyzer finding enrichment metadata is malformed")
        analyzer_arn = payload.get("analyzer_arn")
        finding_id = payload.get("finding_id")
        if not isinstance(analyzer_arn, str) or not isinstance(finding_id, str):
            raise ValueError("Access Analyzer finding enrichment identity is invalid")
        identity = (analyzer_arn, finding_id)
        expected_region = expected_findings.get(identity)
        if (
            expected_region is None
            or outcome.subject.service != "access-analyzer"
            or outcome.subject.resource_type != "access_analyzer_finding"
            or outcome.subject.scope is not ResourceScope.REGIONAL
            or outcome.subject.region != expected_region
            or identity in subjects
        ):
            raise ValueError("Access Analyzer finding enrichment identity is invalid")
        subjects[identity] = outcome.subject.resource_snapshot_id
    return subjects


def _validate_source_completion_metadata(
    *,
    outcome: SourceEvidenceOutcome,
    payload: Mapping[str, object],
) -> None:
    complete = payload.get("complete")
    failure_category = payload.get("failure_category")
    expected_complete = outcome.state in {
        EvidenceSourceState.PRESENT,
        EvidenceSourceState.EXPECTED_ABSENCE,
    }
    expected_failure = (
        outcome.failure_category.value if outcome.failure_category is not None else None
    )
    if (
        not isinstance(complete, bool)
        or complete is not expected_complete
        or failure_category != expected_failure
    ):
        raise ValueError("source completion metadata disagrees with its outcome")


def _admission_projection_is_incomplete(
    *,
    outcome: SourceEvidenceOutcome,
    artifact: SourceEvidenceArtifact,
    expected_resource_type: str,
) -> bool:
    """Validate canonical 5B admission metadata without changing AWS source truth."""

    payload = artifact.model_dump(mode="json")["normalized_payload"]
    if not isinstance(payload, dict):  # pragma: no cover - artifact model invariant
        raise ValueError("admission-aware discovery payload must be an object")
    resource_ids = payload.get("resource_ids")
    resource_count = payload.get("resource_count")
    discarded_item_count = payload.get("discarded_item_count")
    admission_complete = payload.get("admission_complete")
    unadmitted_resources = payload.get("unadmitted_resources")
    complete = payload.get("complete")
    failure_category = payload.get("failure_category")
    if (
        not isinstance(resource_ids, list)
        or not all(isinstance(item, str) and item for item in resource_ids)
        or resource_ids != sorted(set(resource_ids))
        or not isinstance(resource_count, int)
        or isinstance(resource_count, bool)
        or resource_count != len(resource_ids)
        or not isinstance(discarded_item_count, int)
        or isinstance(discarded_item_count, bool)
        or discarded_item_count < 0
        or not isinstance(admission_complete, bool)
        or not isinstance(unadmitted_resources, list)
        or not isinstance(complete, bool)
    ):
        raise ValueError("admission-aware discovery metadata is malformed")
    expected_complete = outcome.state in {
        EvidenceSourceState.PRESENT,
        EvidenceSourceState.EXPECTED_ABSENCE,
    }
    expected_failure = (
        outcome.failure_category.value if outcome.failure_category is not None else None
    )
    if complete is not expected_complete or failure_category != expected_failure:
        raise ValueError("discovery payload disagrees with its source outcome")

    region = outcome.subject.region
    if outcome.subject.scope is not ResourceScope.REGIONAL or region is None:
        raise ValueError("5B admission metadata requires a Regional discovery subject")
    if (
        payload.get("account_id") != outcome.collection_account_id
        or payload.get("region") != region
    ):
        raise ValueError("discovery payload scope disagrees with its source outcome")
    expected_keys = {
        "account_id",
        "service",
        "resource_type",
        "scope",
        "region",
        "resource_id",
    }
    canonical_identities: list[tuple[str, str, str, str, str, str]] = []
    for item in unadmitted_resources:
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise ValueError("unadmitted resource identity is malformed")
        identity = tuple(item[key] for key in sorted(expected_keys))
        if not all(isinstance(value, str) for value in identity):
            raise ValueError("unadmitted resource identity is malformed")
        account_id = item["account_id"]
        resource_id = item["resource_id"]
        if (
            len(account_id) != 12
            or not account_id.isascii()
            or not account_id.isdigit()
            or account_id == outcome.collection_account_id
            or item["service"] != "ec2"
            or item["resource_type"] != expected_resource_type
            or item["scope"] != ResourceScope.REGIONAL.value
            or item["region"] != region
            or not resource_id
            or any(separator in resource_id for separator in ("\x1f", "\r", "\n"))
            or resource_id not in resource_ids
        ):
            raise ValueError("unadmitted resource identity contradicts discovery scope")
        canonical_identities.append(
            (
                account_id,
                item["service"],
                item["resource_type"],
                item["scope"],
                item["region"],
                resource_id,
            )
        )
    if canonical_identities != sorted(set(canonical_identities)):
        raise ValueError("unadmitted resource identities must be sorted and unique")
    if len({identity[5] for identity in canonical_identities}) != len(canonical_identities):
        raise ValueError("unadmitted resource IDs must be unique within one discovery source")
    if admission_complete is not (not canonical_identities):
        raise ValueError("admission completeness disagrees with unadmitted resources")
    return not admission_complete


def require_mapping(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> dict[str, Any]:
    """Return one AWS object or reject a malformed response without echoing it."""

    if not isinstance(value, Mapping):
        raise CollectorEvidenceError(operation_name, fact_path)
    return dict(value)


def require_list(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> list[Any]:
    """Return one AWS list while preserving a valid known-empty list."""

    if not isinstance(value, list):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def require_member(
    value: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> Any:
    """Return a required member, distinguishing an absent key from other values."""

    if key not in value:
        raise CollectorEvidenceError(operation_name, fact_path)
    return value[key]


def require_string(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> str:
    """Return a string value without coercing another primitive into evidence."""

    if not isinstance(value, str):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def require_non_empty_string(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> str:
    """Return a non-blank string without rewriting the value supplied by AWS."""

    result = require_string(
        value,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if not result.strip():
        raise CollectorEvidenceError(operation_name, fact_path)
    return result


def require_boolean(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> bool:
    """Return an actual boolean rather than accepting truthy integer evidence."""

    if not isinstance(value, bool):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def require_integer(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> int:
    """Return an integer while rejecting booleans and coercible strings."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def require_datetime(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> datetime:
    """Return a boto3 timestamp without accepting stringified substitutes."""

    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise CollectorEvidenceError(operation_name, fact_path)
    return value


def should_skip_exact_duplicate(
    seen: dict[str, dict[str, Any]],
    identity: str,
    item: Mapping[str, Any],
    *,
    operation_name: str,
    fact_path: str,
) -> bool:
    """Skip an exact repeated item and reject conflicting data for one stable identity."""

    candidate = dict(item)
    if identity not in seen:
        seen[identity] = candidate
        return False
    if seen[identity] != candidate:
        raise CollectorEvidenceConflictError(operation_name, fact_path)
    return True


def iter_paginated_items(
    client: Any,
    operation_name: str,
    result_key: str,
    **paginate_options: Any,
) -> Iterator[dict[str, Any]]:
    """Yield dictionary items from every page of a boto3 paginator."""

    paginator = client.get_paginator(operation_name)
    for page_index, raw_page in enumerate(paginator.paginate(**paginate_options)):
        page = require_mapping(
            raw_page,
            operation_name=operation_name,
            fact_path=f"pages[{page_index}]",
        )
        item_path = f"pages[{page_index}].{result_key}"
        items = require_list(
            require_member(
                page,
                result_key,
                operation_name=operation_name,
                fact_path=item_path,
            ),
            operation_name=operation_name,
            fact_path=item_path,
        )
        for item_index, item in enumerate(items):
            yield require_mapping(
                item,
                operation_name=operation_name,
                fact_path=f"{item_path}[{item_index}]",
            )


def tags_to_dict(
    tags: object,
    *,
    operation_name: str,
    fact_path: str,
    allow_missing_value: bool = False,
) -> dict[str, str]:
    """Validate and normalize AWS tag entries into a stable string dictionary."""

    if isinstance(tags, str | bytes | Mapping) or not isinstance(tags, Iterable):
        raise CollectorEvidenceError(operation_name, fact_path)
    normalized_tags: dict[str, str] = {}
    for tag_index, raw_tag in enumerate(tags):
        tag_path = f"{fact_path}[{tag_index}]"
        tag = require_mapping(
            raw_tag,
            operation_name=operation_name,
            fact_path=tag_path,
        )
        key = require_non_empty_string(
            require_member(
                tag,
                "Key",
                operation_name=operation_name,
                fact_path=f"{tag_path}.Key",
            ),
            operation_name=operation_name,
            fact_path=f"{tag_path}.Key",
        )
        if "Value" not in tag:
            if not allow_missing_value:
                raise CollectorEvidenceError(operation_name, f"{tag_path}.Value")
            value = ""
        else:
            value = require_string(
                tag["Value"],
                operation_name=operation_name,
                fact_path=f"{tag_path}.Value",
            )
        if key in normalized_tags and normalized_tags[key] != value:
            raise CollectorEvidenceError(operation_name, f"{tag_path}.Key")
        normalized_tags[key] = value
    return normalized_tags


def to_json_safe(value: Any) -> Any:
    """Recursively convert common boto3 response values to JSON-safe values."""

    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, Mapping):
        return {str(key): to_json_safe(item) for key, item in value.items()}
    if isinstance(value, Iterable):
        return [to_json_safe(item) for item in value]
    return str(value)
