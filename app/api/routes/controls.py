"""Read-only internal control catalog API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.api_views import ControlView, Page
from app.schemas.finding import ControlCategory, Severity
from app.security.authorization import Capability, require_capability
from app.services.control_service import ControlService

router = APIRouter(
    prefix="/controls",
    tags=["controls"],
    dependencies=[Depends(require_capability(Capability.READ))],
)
SessionDependency = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[ControlView])
def list_controls(
    db: SessionDependency,
    category: ControlCategory | None = None,
    severity: Severity | None = None,
    resource_type: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    catalog_key: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ControlView]:
    """List stable controls and all available versioned definitions."""

    return ControlService(db).list_controls(
        category=category,
        severity=severity,
        resource_type=resource_type,
        catalog_key=catalog_key,
        limit=limit,
        offset=offset,
    )


@router.get("/{control_id}", response_model=ControlView)
def get_control(control_id: UUID, db: SessionDependency) -> ControlView:
    """Return a control with exact definitions and framework mappings."""

    return ControlService(db).get_control(control_id)
