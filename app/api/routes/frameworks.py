"""Read-only external framework catalog API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.api_views import FrameworkView, Page
from app.security.authorization import Capability, require_capability
from app.services.framework_service import FrameworkService

router = APIRouter(
    prefix="/frameworks",
    tags=["frameworks"],
    dependencies=[Depends(require_capability(Capability.READ))],
)
SessionDependency = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[FrameworkView])
def list_frameworks(
    db: SessionDependency,
    framework_key: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    version: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[FrameworkView]:
    """List immutable framework versions and their mapped references."""

    return FrameworkService(db).list_frameworks(
        framework_key=framework_key,
        version=version,
        limit=limit,
        offset=offset,
    )


@router.get("/{framework_id}", response_model=FrameworkView)
def get_framework(framework_id: UUID, db: SessionDependency) -> FrameworkView:
    """Return one exact framework hierarchy and its control mappings."""

    return FrameworkService(db).get_framework(framework_id)
