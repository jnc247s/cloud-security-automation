"""Validated source declarations, artifacts, outcomes, and resource relationships.

The graph is the immutable Sprint 5 hand-off between fact-only collectors and the existing
assessment/persistence boundaries.  It deliberately contains no control, severity, finding, or
remediation decisions.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
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
    ResourceRelationship,
    deduplicate_relationships,
)
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
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

_SOURCE_ARTIFACT_NAMESPACE = UUID("a524b9a2-bd87-57f0-8317-03e43a36e260")

CollectionAccountId = Annotated[str, Field(pattern=r"^[0-9]{12}$")]
ContractKey = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")]
Version = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$"),
]


class EvidenceCardinality(StrEnum):
    """Shape of the normalized response promised by a declared evidence source."""

    SINGLE = "SINGLE"
    COLLECTION = "COLLECTION"


class ResourceOwnerMode(StrEnum):
    """Closed owner class that an identity-authoritative source may establish."""

    COLLECTION_ACCOUNT = "COLLECTION_ACCOUNT"
    AWS_MANAGED = "AWS_MANAGED"
    EXTERNAL_ACCOUNT = "EXTERNAL_ACCOUNT"


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
        ):
            raise ValueError("exceptional owner modes require identity-authoritative evidence")
        if self.phase is EvidenceCollectionPhase.DISCOVERY and self.allows_supplemental_region:
            raise ValueError("discovery source contracts cannot authorize supplemental Regions")

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
        relationships = deduplicate_relationships(self.relationships)
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

        for relationship in relationships:
            self._validate_common_observation(relationship)
            matches = [
                (contract_by_id[outcome.source_outcome_id], outcome)
                for outcome in outcomes
                if _provenance_matches_outcome(relationship.provenance, outcome)
            ]
            if len(matches) != 1:
                raise ValueError(
                    "relationship provenance must identify exactly one declared source outcome"
                )
            _, outcome = matches[0]
            if outcome.state is not EvidenceSourceState.PRESENT:
                raise ValueError("relationships require PRESENT source evidence")
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


def validate_graph_resources(
    *,
    graph: EvidenceGraph,
    resources: tuple[NormalizedResource, ...],
    requested_region: str,
) -> None:
    """Bind graph subjects/endpoints and exceptional ownership to top-level resources."""

    for contract in graph.source_contracts:
        if (
            contract.phase is EvidenceCollectionPhase.DISCOVERY
            and isinstance(contract.subject, AccountEvidenceSubject)
            and contract.subject.scope is ResourceScope.REGIONAL
            and contract.subject.region != requested_region
        ):
            raise ValueError(
                "Regional discovery source contracts must match the inventory invocation Region"
            )

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

    proof_by_snapshot: dict[UUID, list[ScanSourceContract]] = {}
    resolved_relationship_snapshots: set[UUID] = set()
    contract_by_id = {item.source_outcome_id: item for item in graph.source_contracts}
    outcome_by_id = {item.source_outcome_id: item for item in graph.source_outcomes}
    for outcome_id, outcome in outcome_by_id.items():
        if outcome.state is not EvidenceSourceState.PRESENT:
            continue
        contract = contract_by_id[outcome_id]
        if isinstance(outcome.subject, ResourceEvidenceSubject):
            _require_resource_subject(outcome.subject, resource_by_snapshot_id)
            proof_by_snapshot.setdefault(outcome.subject.resource_snapshot_id, []).append(contract)

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


def _provenance_matches_outcome(
    provenance: RelationshipProvenance,
    outcome: SourceEvidenceOutcome,
) -> bool:
    return all(
        (
            provenance.collector == outcome.collector,
            provenance.collector_version == outcome.collector_version,
            provenance.source == outcome.source,
            provenance.source_api == outcome.source_api,
            provenance.evidence_reference == outcome.evidence_reference,
            provenance.collected_at == outcome.collected_at,
        )
    )


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
        and not any(contract.allows_supplemental_region for contract in contracts_tuple)
    ):
        raise ValueError("resource Region requires declared supplemental-Region evidence")
