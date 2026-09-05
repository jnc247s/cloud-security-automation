"""Read-only operational exception API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.enums import ExceptionStatus
from app.schemas.api_views import FindingExceptionView, Page
from app.security.authorization import Capability, require_capability
from app.services.exception_service import ExceptionService

router = APIRouter(
    prefix="/exceptions",
    tags=["exceptions"],
    dependencies=[Depends(require_capability(Capability.READ))],
)
SessionDependency = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[FindingExceptionView])
def list_exceptions(
    db: SessionDependency,
    finding_id: UUID | None = None,
    resource_id: UUID | None = None,
    control_id: UUID | None = None,
    status: ExceptionStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[FindingExceptionView]:
    """List explicit, time-bounded handling decisions."""

    return ExceptionService(db).list_exceptions(
        finding_id=finding_id,
        resource_id=resource_id,
        control_id=control_id,
        status=status,
        limit=limit,
        offset=offset,
    )
