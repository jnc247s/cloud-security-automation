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
from app.schemas.resource import NormalizedResource

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
