"""Read-only normalized AWS source-outcome API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.assessment.source_outcomes import EvidenceCollectionPhase, EvidenceSourceState
from app.database.session import get_db
from app.schemas.api_views import (
    Page,
    SourceEvidenceOutcomeDetailView,
    SourceEvidenceOutcomeView,
)
from app.security.authorization import Capability, require_capability
from app.services.evidence_graph_service import EvidenceGraphService

router = APIRouter(
    prefix="/source-outcomes",
    tags=["source-outcomes"],
    dependencies=[Depends(require_capability(Capability.READ))],
)
SessionDependency = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[SourceEvidenceOutcomeView])
def list_source_outcomes(
    db: SessionDependency,
    collection_account_id: Annotated[
        str | None,
        Query(pattern=r"^[0-9]{12}$"),
    ] = None,
    scan_id: UUID | None = None,
    contract_key: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    collector: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    phase: EvidenceCollectionPhase | None = None,
    subject_resource_id: UUID | None = None,
    evidence_kind: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    state: EvidenceSourceState | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[SourceEvidenceOutcomeView]:
    """List declared source results without exposing raw provider failures."""

    return EvidenceGraphService(db).list_source_outcomes(
        collection_account_id=collection_account_id,
        scan_id=scan_id,
        contract_key=contract_key,
        collector=collector,
        phase=phase,
        subject_resource_id=subject_resource_id,
        evidence_kind=evidence_kind,
        state=state,
        limit=limit,
        offset=offset,
    )


@router.get("/{source_outcome_id}", response_model=SourceEvidenceOutcomeDetailView)
def get_source_outcome(
    source_outcome_id: UUID,
    db: SessionDependency,
) -> SourceEvidenceOutcomeDetailView:
    """Return one outcome with its sanitized normalized artifact."""

    return EvidenceGraphService(db).get_source_outcome(source_outcome_id)
