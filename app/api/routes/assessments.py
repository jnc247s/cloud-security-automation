"""Read-only technical assessment API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.assessment.models import AssessmentResult
from app.database.session import get_db
from app.schemas.api_views import AssessmentDetailView, AssessmentView, Page
from app.security.authorization import Capability, require_capability
from app.services.assessment_service import AssessmentService

router = APIRouter(
    prefix="/assessments",
    tags=["assessments"],
    dependencies=[Depends(require_capability(Capability.READ))],
)
SessionDependency = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[AssessmentView])
def list_assessments(
    db: SessionDependency,
    scan_id: UUID | None = None,
    resource_id: UUID | None = None,
    control_id: UUID | None = None,
    result: AssessmentResult | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AssessmentView]:
    """List four-state technical results using provenance filters."""

    return AssessmentService(db).list_assessments(
        scan_id=scan_id,
        resource_id=resource_id,
        control_id=control_id,
        result=result,
        limit=limit,
        offset=offset,
    )


@router.get("/{assessment_id}", response_model=AssessmentDetailView)
def get_assessment(assessment_id: UUID, db: SessionDependency) -> AssessmentDetailView:
    """Return a result with evidence, finding, and framework provenance."""

    return AssessmentService(db).get_assessment(assessment_id)
