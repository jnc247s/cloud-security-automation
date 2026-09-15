"""Read-only generic resource-relationship API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.database.session import get_db
from app.schemas.api_views import Page, ResourceRelationshipView
from app.security.authorization import Capability, require_capability
from app.services.evidence_graph_service import EvidenceGraphService

router = APIRouter(
    prefix="/relationships",
    tags=["relationships"],
    dependencies=[Depends(require_capability(Capability.READ))],
)
SessionDependency = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[ResourceRelationshipView])
def list_relationships(
    db: SessionDependency,
    collection_account_id: Annotated[
        str | None,
        Query(pattern=r"^[0-9]{12}$"),
    ] = None,
    scan_id: UUID | None = None,
    relationship_id: UUID | None = None,
    source_resource_id: UUID | None = None,
    target_resource_id: UUID | None = None,
    target_reference_id: UUID | None = None,
    relationship_type: RelationshipType | None = None,
    resolution: RelationshipResolution | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ResourceRelationshipView]:
    """List immutable directional observations with bounded filters."""

    return EvidenceGraphService(db).list_relationships(
        collection_account_id=collection_account_id,
        scan_id=scan_id,
        relationship_id=relationship_id,
        source_resource_id=source_resource_id,
        target_resource_id=target_resource_id,
        target_reference_id=target_reference_id,
        relationship_type=relationship_type,
        resolution=resolution,
        limit=limit,
        offset=offset,
    )


@router.get("/{observation_id}", response_model=ResourceRelationshipView)
def get_relationship(
    observation_id: UUID,
    db: SessionDependency,
) -> ResourceRelationshipView:
    """Return one relationship observation and its controlled provenance."""

    return EvidenceGraphService(db).get_relationship(observation_id)
