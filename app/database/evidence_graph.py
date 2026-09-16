"""Strict conversion between the evidence-graph domain and append-only rows."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.evidence_graph import (
    EvidenceCardinality,
    EvidenceGraph,
    ResourceOwnerMode,
)
from app.assessment.evidence_graph import (
    ScanSourceContract as DomainSourceContract,
)
from app.assessment.evidence_graph import (
    SourceEvidenceArtifact as DomainSourceArtifact,
)
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipProvenance,
    ResourceRelationship,
    UnresolvedRelationshipTarget,
)
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    ResourceEvidenceSubject,
)
from app.assessment.source_outcomes import (
    SourceEvidenceOutcome as DomainSourceOutcome,
)
from app.collectors.base import (
    GRAPH_AWARE_COLLECTOR_NAMES,
    graph_collection_status_for,
    graph_collection_validation_required,
    graph_collectors_for_outcomes,
    validate_access_analyzer_s3_region_source_status,
)
from app.models.evidence_graph import (
    ResourceRelationshipObservation,
    ScanSourceContract,
    SourceEvidenceArtifact,
    SourceEvidenceOutcome,
)
from app.models.scan import ScanScopeManifest
from app.schemas.inventory import CollectionStatus
from app.schemas.resource import ResourceScope


class EvidenceGraphPersistenceError(ValueError):
    """Persisted graph content cannot reconstruct the accepted domain contract."""


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _subject(document: dict[str, object]) -> AccountEvidenceSubject | ResourceEvidenceSubject:
    if document.get("subject_kind") == "account":
        return AccountEvidenceSubject.model_validate_json(json.dumps(document))
    if document.get("subject_kind") == "resource":
        return ResourceEvidenceSubject.model_validate_json(json.dumps(document))
    raise EvidenceGraphPersistenceError("persisted evidence subject kind is invalid")


def persist_evidence_graph(session: Session, graph: EvidenceGraph) -> None:
    """Append one validated graph; the caller owns transaction and terminalization."""

    validated = EvidenceGraph.model_validate_json(graph.model_dump_json())
    for contract in validated.source_contracts:
        subject_document = contract.subject.model_dump(mode="json")
        resource_subject = (
            contract.subject if isinstance(contract.subject, ResourceEvidenceSubject) else None
        )
        session.add(
            ScanSourceContract(
                source_outcome_id=contract.source_outcome_id,
                scan_id=contract.scan_id,
                collection_account_id=contract.collection_account_id,
                contract_key=contract.contract_key,
                contract_version=contract.contract_version,
                phase=contract.phase,
                subject_kind=contract.subject.subject_kind,
                subject=subject_document,
                subject_resource_id=(
                    resource_subject.stable_resource_id if resource_subject is not None else None
                ),
                subject_resource_snapshot_id=(
                    resource_subject.resource_snapshot_id if resource_subject is not None else None
                ),
                evidence_kind=contract.evidence_kind,
                collector=contract.collector,
                collector_version=contract.collector_version,
                source_api=contract.source_api,
                cardinality=contract.cardinality.value,
                owner_mode=contract.owner_mode.value,
                identity_authoritative=contract.identity_authoritative,
                allows_supplemental_region=contract.allows_supplemental_region,
                schema_version=contract.schema_version,
            )
        )

    for artifact in validated.artifacts:
        artifact_document = artifact.model_dump(mode="json")
        session.add(
            SourceEvidenceArtifact(
                artifact_id=artifact.artifact_id,
                scan_id=artifact.scan_id,
                collection_account_id=artifact.collection_account_id,
                evidence_reference=artifact.evidence_reference,
                evidence_sha256=artifact.evidence_sha256,
                evidence_schema=artifact.evidence_schema,
                evidence_schema_version=artifact.evidence_schema_version,
                collected_at=artifact.collected_at,
                normalized_payload=artifact_document["normalized_payload"],
                schema_version=artifact.schema_version,
            )
        )

    # Database triggers validate provenance by querying already-persisted parent
    # rows.  Keep these phases explicit instead of relying on SQLAlchemy's
    # dependency sorter, which cannot infer the trigger-only dependencies.
    session.flush()

    artifact_by_reference = {
        artifact.evidence_reference: artifact for artifact in validated.artifacts
    }
    for outcome in validated.source_outcomes:
        subject_document = outcome.subject.model_dump(mode="json")
        resource_subject = (
            outcome.subject if isinstance(outcome.subject, ResourceEvidenceSubject) else None
        )
        artifact = artifact_by_reference[outcome.evidence_reference]
        session.add(
            SourceEvidenceOutcome(
                source_outcome_id=outcome.source_outcome_id,
                scan_id=outcome.scan_id,
                collection_account_id=outcome.collection_account_id,
                phase=outcome.phase,
                subject_kind=outcome.subject.subject_kind,
                subject=subject_document,
                subject_resource_id=(
                    resource_subject.stable_resource_id if resource_subject is not None else None
                ),
                subject_resource_snapshot_id=(
                    resource_subject.resource_snapshot_id if resource_subject is not None else None
                ),
                subject_scope=outcome.subject.scope,
                subject_region=outcome.subject.region,
                evidence_kind=outcome.evidence_kind,
                state=outcome.state,
                failure_category=outcome.failure_category,
                collector=outcome.collector,
                collector_version=outcome.collector_version,
                source=outcome.source,
                source_api=outcome.source_api,
                collected_at=outcome.collected_at,
                artifact_id=artifact.artifact_id,
                evidence_reference=outcome.evidence_reference,
                evidence_sha256=outcome.evidence_sha256,
                schema_version=outcome.schema_version,
            )
        )

    session.flush()

    for relationship in validated.relationships:
        target = relationship.target
        stable_target = target if isinstance(target, RelationshipEndpoint) else None
        partial_target = target if isinstance(target, UnresolvedRelationshipTarget) else None
        matching_outcomes = [
            outcome
            for outcome in validated.source_outcomes
            if outcome.collector == relationship.provenance.collector
            and outcome.collector_version == relationship.provenance.collector_version
            and outcome.source == relationship.provenance.source
            and outcome.source_api == relationship.provenance.source_api
            and outcome.evidence_reference == relationship.provenance.evidence_reference
            and outcome.collected_at == relationship.provenance.collected_at
        ]
        if len(matching_outcomes) != 1:  # defensive; domain validation already proves this
            raise EvidenceGraphPersistenceError(
                "relationship provenance does not resolve to one source outcome"
            )
        outcome = matching_outcomes[0]
        session.add(
            ResourceRelationshipObservation(
                observation_id=relationship.observation_id,
                relationship_id=relationship.relationship_id,
                scan_id=relationship.scan_id,
                collection_account_id=relationship.collection_account_id,
                relationship_type=relationship.relationship_type,
                resolution=relationship.resolution,
                source_provider=relationship.source.provider,
                source_aws_account_id=relationship.source.aws_account_id,
                source_service=relationship.source.service,
                source_resource_type=relationship.source.resource_type,
                source_aws_resource_id=relationship.source.aws_resource_id,
                source_scope=relationship.source.scope,
                source_region=relationship.source.region,
                source_resource_id=relationship.source.stable_resource_id,
                source_resource_snapshot_id=relationship.source.resource_snapshot_id,
                target_identity_state=target.identity_state,
                target_provider=target.provider,
                target_aws_account_id=target.aws_account_id,
                target_service=target.service,
                target_resource_type=target.resource_type,
                target_aws_resource_id=target.aws_resource_id,
                target_scope=target.scope.value if target.scope is not None else None,
                target_region=target.region,
                target_resource_id=(
                    stable_target.stable_resource_id if stable_target is not None else None
                ),
                target_resource_snapshot_id=(
                    stable_target.resource_snapshot_id if stable_target is not None else None
                ),
                target_reference_id=(
                    partial_target.reference_id if partial_target is not None else None
                ),
                source_outcome_id=outcome.source_outcome_id,
                provenance_collector=relationship.provenance.collector,
                provenance_collector_version=relationship.provenance.collector_version,
                provenance_source=relationship.provenance.source,
                provenance_source_api=relationship.provenance.source_api,
                evidence_reference=relationship.provenance.evidence_reference,
                collected_at=relationship.provenance.collected_at,
                schema_version=relationship.schema_version,
            )
        )

    session.flush()


def source_artifact_from_record(record: SourceEvidenceArtifact) -> DomainSourceArtifact:
    return DomainSourceArtifact(
        artifact_id=record.artifact_id,
        scan_id=record.scan_id,
        collection_account_id=record.collection_account_id,
        evidence_reference=record.evidence_reference,
        evidence_sha256=record.evidence_sha256,
        evidence_schema=record.evidence_schema,
        evidence_schema_version=record.evidence_schema_version,
        collected_at=_utc(record.collected_at),
        normalized_payload=dict(record.normalized_payload),
        schema_version=record.schema_version,
    )


def source_outcome_from_record(record: SourceEvidenceOutcome) -> DomainSourceOutcome:
    return DomainSourceOutcome(
        source_outcome_id=record.source_outcome_id,
        scan_id=record.scan_id,
        collection_account_id=record.collection_account_id,
        phase=record.phase,
        subject=_subject(dict(record.subject)),
        evidence_kind=record.evidence_kind,
        state=record.state,
        failure_category=record.failure_category,
        collector=record.collector,
        collector_version=record.collector_version,
        source=record.source,
        source_api=record.source_api,
        collected_at=_utc(record.collected_at),
        evidence_reference=record.evidence_reference,
        evidence_sha256=record.evidence_sha256,
        schema_version=record.schema_version,
    )


def source_contract_from_record(record: ScanSourceContract) -> DomainSourceContract:
    return DomainSourceContract(
        contract_key=record.contract_key,
        contract_version=record.contract_version,
        source_outcome_id=record.source_outcome_id,
        scan_id=record.scan_id,
        collection_account_id=record.collection_account_id,
        phase=record.phase,
        subject=_subject(dict(record.subject)),
        evidence_kind=record.evidence_kind,
        collector=record.collector,
        collector_version=record.collector_version,
        source_api=record.source_api,
        cardinality=EvidenceCardinality(record.cardinality),
        owner_mode=ResourceOwnerMode(record.owner_mode),
        identity_authoritative=record.identity_authoritative,
        allows_supplemental_region=record.allows_supplemental_region,
        schema_version=record.schema_version,
    )


def relationship_from_record(
    record: ResourceRelationshipObservation,
) -> ResourceRelationship:
    source = RelationshipEndpoint(
        provider=record.source_provider,
        aws_account_id=record.source_aws_account_id,
        service=record.source_service,
        resource_type=record.source_resource_type,
        aws_resource_id=record.source_aws_resource_id,
        scope=record.source_scope,
        region=record.source_region,
        stable_resource_id=record.source_resource_id,
        resource_snapshot_id=record.source_resource_snapshot_id,
    )
    if record.target_identity_state == "stable":
        if record.target_scope is None or record.target_resource_id is None:
            raise EvidenceGraphPersistenceError("persisted stable target is incomplete")
        target: RelationshipEndpoint | UnresolvedRelationshipTarget = RelationshipEndpoint(
            provider=record.target_provider,
            aws_account_id=record.target_aws_account_id,
            service=record.target_service,
            resource_type=record.target_resource_type,
            aws_resource_id=record.target_aws_resource_id,
            scope=ResourceScope(record.target_scope),
            region=record.target_region,
            stable_resource_id=record.target_resource_id,
            resource_snapshot_id=record.target_resource_snapshot_id,
        )
    else:
        if record.target_reference_id is None:
            raise EvidenceGraphPersistenceError("persisted unresolved target is incomplete")
        target = UnresolvedRelationshipTarget(
            provider=record.target_provider,
            aws_account_id=record.target_aws_account_id,
            service=record.target_service,
            resource_type=record.target_resource_type,
            aws_resource_id=record.target_aws_resource_id,
            scope=ResourceScope(record.target_scope) if record.target_scope is not None else None,
            region=record.target_region,
            reference_id=record.target_reference_id,
        )
    return ResourceRelationship(
        relationship_id=record.relationship_id,
        observation_id=record.observation_id,
        scan_id=record.scan_id,
        collection_account_id=record.collection_account_id,
        relationship_type=record.relationship_type,
        source=source,
        target=target,
        resolution=record.resolution,
        provenance=RelationshipProvenance(
            collector=record.provenance_collector,
            collector_version=record.provenance_collector_version,
            source=record.provenance_source,
            source_api=record.provenance_source_api,
            evidence_reference=record.evidence_reference,
            collected_at=_utc(record.collected_at),
        ),
        schema_version=record.schema_version,
    )


def load_evidence_graph(session: Session, scan_id: UUID) -> EvidenceGraph | None:
    """Reconstruct and revalidate one immutable graph from persisted rows."""

    manifest = session.scalar(select(ScanScopeManifest).where(ScanScopeManifest.scan_id == scan_id))
    contracts = session.scalars(
        select(ScanSourceContract)
        .where(ScanSourceContract.scan_id == scan_id)
        .order_by(ScanSourceContract.source_outcome_id)
    ).all()
    artifacts = session.scalars(
        select(SourceEvidenceArtifact)
        .where(SourceEvidenceArtifact.scan_id == scan_id)
        .order_by(SourceEvidenceArtifact.artifact_id)
    ).all()
    outcomes = session.scalars(
        select(SourceEvidenceOutcome)
        .where(SourceEvidenceOutcome.scan_id == scan_id)
        .order_by(SourceEvidenceOutcome.source_outcome_id)
    ).all()
    relationships = session.scalars(
        select(ResourceRelationshipObservation)
        .where(ResourceRelationshipObservation.scan_id == scan_id)
        .order_by(ResourceRelationshipObservation.observation_id)
    ).all()
    if not contracts and not artifacts and not outcomes and not relationships:
        if manifest is not None and (
            manifest.source_manifest_schema_version is not None
            or manifest.source_manifest_checksum is not None
        ):
            raise EvidenceGraphPersistenceError(
                "persisted source manifest has no evidence graph records"
            )
        return None
    if manifest is None:
        raise EvidenceGraphPersistenceError("persisted evidence graph has no scan scope manifest")
    if manifest.source_manifest_schema_version is None or manifest.source_manifest_checksum is None:
        raise EvidenceGraphPersistenceError(
            "persisted evidence graph has an incomplete source manifest digest"
        )
    if not contracts:
        raise EvidenceGraphPersistenceError("persisted evidence graph has no source manifest")
    first = contracts[0]
    try:
        graph = EvidenceGraph(
            scan_id=scan_id,
            collection_account_id=first.collection_account_id,
            collected_at=_utc(artifacts[0].collected_at),
            source_contracts=tuple(source_contract_from_record(item) for item in contracts),
            artifacts=tuple(source_artifact_from_record(item) for item in artifacts),
            source_outcomes=tuple(source_outcome_from_record(item) for item in outcomes),
            relationships=tuple(relationship_from_record(item) for item in relationships),
        )
    except (IndexError, TypeError, ValueError) as error:
        raise EvidenceGraphPersistenceError(
            "persisted evidence graph violates its canonical contract"
        ) from error
    if manifest.source_manifest_schema_version != graph.source_manifest_schema_version:
        raise EvidenceGraphPersistenceError(
            "persisted source manifest schema version does not match the evidence graph"
        )
    if manifest.source_manifest_checksum != graph.source_manifest_sha256:
        raise EvidenceGraphPersistenceError(
            "persisted source manifest checksum does not match the evidence graph"
        )
    collector_outcomes = manifest.collector_outcomes
    requested_collectors = manifest.requested_collectors
    if not isinstance(collector_outcomes, dict) or not isinstance(requested_collectors, list):
        raise EvidenceGraphPersistenceError("persisted collector scope is invalid")
    if (
        any(not isinstance(name, str) or not name for name in requested_collectors)
        or len(requested_collectors) != len(set(requested_collectors))
        or any(not isinstance(name, str) or not name for name in collector_outcomes)
    ):
        raise EvidenceGraphPersistenceError("persisted collector scope is invalid")
    if set(requested_collectors) != set(collector_outcomes):
        raise EvidenceGraphPersistenceError("persisted collector scope is inconsistent")
    represented_collectors = graph_collectors_for_outcomes(graph.source_outcomes)
    if not represented_collectors.issubset(requested_collectors):
        raise EvidenceGraphPersistenceError(
            "persisted graph source outcomes have no collector coverage"
        )
    for collector_name in GRAPH_AWARE_COLLECTOR_NAMES:
        if not graph_collection_validation_required(
            collector_name=collector_name,
            requested_collectors=requested_collectors,
            outcomes=graph.source_outcomes,
        ):
            continue
        stored_status = collector_outcomes.get(collector_name)
        if stored_status is None:
            raise EvidenceGraphPersistenceError("persisted graph collector has no coverage outcome")
        try:
            if collector_name == "access_analyzer_evidence":
                s3_status = collector_outcomes.get("s3_buckets")
                if not isinstance(s3_status, str):
                    raise ValueError("Access Analyzer coverage requires an S3 outcome")
                validate_access_analyzer_s3_region_source_status(
                    outcomes=graph.source_outcomes,
                    artifacts=graph.artifacts,
                    s3_status=CollectionStatus(s3_status),
                )
            reconstructed_status = graph_collection_status_for(
                collector_name=collector_name,
                outcomes=graph.source_outcomes,
                artifacts=graph.artifacts,
            )
        except ValueError as error:
            raise EvidenceGraphPersistenceError(
                "persisted graph cannot reconstruct collector coverage"
            ) from error
        if stored_status != reconstructed_status.value:
            raise EvidenceGraphPersistenceError(
                "persisted collector coverage disagrees with graph evidence"
            )
    return graph
