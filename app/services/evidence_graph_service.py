"""Authorized read service for immutable source outcomes and resource relationships."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.assessment.source_outcomes import EvidenceCollectionPhase, EvidenceSourceState
from app.models.evidence_graph import (
    ResourceRelationshipObservation,
    ScanSourceContract,
    SourceEvidenceArtifact,
    SourceEvidenceOutcome,
)
from app.schemas.api_views import (
    Page,
    ResourceRelationshipView,
    SourceEvidenceOutcomeDetailView,
    SourceEvidenceOutcomeView,
)
from app.services.errors import EntityNotFoundError
from app.services.projections import (
    relationship_view,
    source_outcome_detail_view,
    source_outcome_view,
)


class EvidenceGraphService:
    """Query the generic evidence graph without service-specific traversal logic."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_relationships(
        self,
        *,
        collection_account_id: str | None = None,
        scan_id: UUID | None = None,
        relationship_id: UUID | None = None,
        source_resource_id: UUID | None = None,
        target_resource_id: UUID | None = None,
        target_reference_id: UUID | None = None,
        relationship_type: RelationshipType | None = None,
        resolution: RelationshipResolution | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[ResourceRelationshipView]:
        model = ResourceRelationshipObservation
        filters = {
            model.collection_account_id: collection_account_id,
            model.scan_id: scan_id,
            model.relationship_id: relationship_id,
            model.source_resource_id: source_resource_id,
            model.target_resource_id: target_resource_id,
            model.target_reference_id: target_reference_id,
            model.relationship_type: relationship_type,
            model.resolution: resolution,
        }
        predicates = [column == value for column, value in filters.items() if value is not None]
        total = (
            self._session.scalar(select(func.count()).select_from(model).where(*predicates)) or 0
        )
        records = self._session.scalars(
            select(model)
            .where(*predicates)
            .order_by(model.collected_at, model.observation_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(relationship_view(item) for item in records),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_relationship(self, observation_id: UUID) -> ResourceRelationshipView:
        record = self._session.get(ResourceRelationshipObservation, observation_id)
        if record is None:
            raise EntityNotFoundError("relationship observation", observation_id)
        return relationship_view(record)

    def list_source_outcomes(
        self,
        *,
        collection_account_id: str | None = None,
        scan_id: UUID | None = None,
        contract_key: str | None = None,
        collector: str | None = None,
        phase: EvidenceCollectionPhase | None = None,
        subject_resource_id: UUID | None = None,
        evidence_kind: str | None = None,
        state: EvidenceSourceState | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[SourceEvidenceOutcomeView]:
        model = SourceEvidenceOutcome
        filters = {
            model.collection_account_id: collection_account_id,
            model.scan_id: scan_id,
            model.collector: collector,
            model.phase: phase,
            model.subject_resource_id: subject_resource_id,
            model.evidence_kind: evidence_kind,
            model.state: state,
        }
        predicates = [column == value for column, value in filters.items() if value is not None]
        statement = select(model).where(*predicates)
        count_statement = select(func.count()).select_from(model).where(*predicates)
        if contract_key is not None:
            join_condition = (ScanSourceContract.source_outcome_id == model.source_outcome_id) & (
                ScanSourceContract.scan_id == model.scan_id
            )
            statement = statement.join(ScanSourceContract, join_condition).where(
                ScanSourceContract.contract_key == contract_key
            )
            count_statement = count_statement.join(ScanSourceContract, join_condition).where(
                ScanSourceContract.contract_key == contract_key
            )
        total = self._session.scalar(count_statement) or 0
        records = self._session.scalars(
            statement.order_by(model.collected_at, model.source_outcome_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(source_outcome_view(item) for item in records),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_source_outcome(self, source_outcome_id: UUID) -> SourceEvidenceOutcomeDetailView:
        outcome = self._session.get(SourceEvidenceOutcome, source_outcome_id)
        if outcome is None:
            raise EntityNotFoundError("source evidence outcome", source_outcome_id)
        artifact = self._session.get(SourceEvidenceArtifact, outcome.artifact_id)
        if artifact is None:  # a database FK should make this unreachable
            raise EntityNotFoundError("source evidence artifact", outcome.artifact_id)
        return source_outcome_detail_view(outcome, artifact)
