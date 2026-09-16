"""Shared contracts and normalization helpers for AWS resource collectors."""

import base64
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
    }
)

_GRAPH_COLLECTOR_SOURCES = {
    "ec2_ebs_evidence": frozenset({"ec2.instances", "ec2.volumes", "ec2.ebs-defaults"}),
    "security_groups": frozenset({"ec2.security-groups"}),
    "vpc_network_evidence": frozenset({"ec2.vpcs", "ec2.subnets", "ec2.flow-logs"}),
}
_REQUIRED_GRAPH_DISCOVERY_SOURCES = {
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
) -> CollectionStatus:
    """Reconstruct one graph collector's coverage from persisted evidence only."""

    try:
        source_collectors = _GRAPH_COLLECTOR_SOURCES[collector_name]
    except KeyError as error:
        raise ValueError("unknown graph-aware collector") from error

    selected_outcomes = tuple(
        outcome for outcome in outcomes if outcome.collector in source_collectors
    )
    if not selected_outcomes:
        raise ValueError("graph-aware collector has no source outcomes")
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

    artifacts_by_reference: dict[str, SourceEvidenceArtifact] = {}
    for artifact in artifacts:
        if artifact.evidence_reference in artifacts_by_reference:
            raise ValueError("evidence references must be unique for coverage reconstruction")
        artifacts_by_reference[artifact.evidence_reference] = artifact

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
    if source_status is CollectionStatus.SUCCEEDED and admission_incomplete:
        return CollectionStatus.PARTIAL
    return source_status


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
    if collector_name in {"ec2_ebs_evidence", "vpc_network_evidence"}:
        return collector_name in requested
    return collector_name == "security_groups" and "vpc_network_evidence" in requested


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
