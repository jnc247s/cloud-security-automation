"""Read-only operational finding API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.enums import FindingStatus
from app.schemas.api_views import FindingDetailView, FindingView, Page
from app.security.authorization import Capability, require_capability
from app.services.finding_service import FindingService

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
    dependencies=[Depends(require_capability(Capability.READ))],
)
SessionDependency = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[FindingView])
def list_findings(
    db: SessionDependency,
    account_id: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    resource_id: UUID | None = None,
    control_id: UUID | None = None,
    status: FindingStatus | None = None,
    region: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[FindingView]:
    """List current operational finding state."""

    return FindingService(db).list_findings(
        account_id=account_id,
        resource_id=resource_id,
        control_id=control_id,
        status=status,
        region=region,
        limit=limit,
        offset=offset,
    )


@router.get("/{finding_id}", response_model=FindingDetailView)
def get_finding(finding_id: UUID, db: SessionDependency) -> FindingDetailView:
    """Return one finding with immutable occurrences and explicit exceptions."""

    return FindingService(db).get_finding(finding_id)
