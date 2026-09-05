"""Read-only resource inventory API."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.api_views import Page, ResourceSnapshotView, ResourceView
from app.security.authorization import Capability, require_capability
from app.services.resource_service import ResourceService

router = APIRouter(
    prefix="/resources",
    tags=["resources"],
    dependencies=[Depends(require_capability(Capability.READ))],
)
SessionDependency = Annotated[Session, Depends(get_db)]


@router.get("", response_model=Page[ResourceView])
def list_resources(
    db: SessionDependency,
    account_id: Annotated[str | None, Query(min_length=1, max_length=32)] = None,
    service: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    resource_type: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    region: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ResourceView]:
    """List stable resource identities using bounded pagination."""

    return ResourceService(db).list_resources(
        account_id=account_id,
        service=service,
        resource_type=resource_type,
        region=region,
        limit=limit,
        offset=offset,
    )


@router.get("/{resource_id}", response_model=ResourceView)
def get_resource(resource_id: UUID, db: SessionDependency) -> ResourceView:
    """Return one stable resource identity and its latest observation."""

    return ResourceService(db).get_resource(resource_id)


@router.get("/{resource_id}/history", response_model=Page[ResourceSnapshotView])
def get_resource_history(
    resource_id: UUID,
    db: SessionDependency,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ResourceSnapshotView]:
    """List immutable observations for one resource, newest first."""

    return ResourceService(db).get_resource_history(
        resource_id,
        limit=limit,
        offset=offset,
    )
