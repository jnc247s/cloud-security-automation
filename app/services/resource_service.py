"""Authorized-query service for stable resources and snapshot history."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.resource import Resource, ResourceSnapshot
from app.schemas.api_views import Page, ResourceSnapshotView, ResourceView
from app.services.errors import EntityNotFoundError
from app.services.projections import resource_snapshot_view, resource_view


class ResourceService:
    """Serve resource identity and immutable historical observations."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_resources(
        self,
        *,
        account_id: str | None = None,
        service: str | None = None,
        resource_type: str | None = None,
        region: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[ResourceView]:
        predicates = []
        if account_id is not None:
            predicates.append(Resource.aws_account_id == account_id)
        if service is not None:
            predicates.append(Resource.service == service)
        if resource_type is not None:
            predicates.append(Resource.resource_type == resource_type)
        if region is not None:
            predicates.append(Resource.region == region)

        total = (
            self._session.scalar(select(func.count()).select_from(Resource).where(*predicates)) or 0
        )
        resources = self._session.scalars(
            select(Resource)
            .where(*predicates)
            .options(selectinload(Resource.snapshots))
            .order_by(Resource.resource_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(resource_view(item) for item in resources),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_resource(self, resource_id: UUID) -> ResourceView:
        resource = self._session.scalar(
            select(Resource)
            .where(Resource.resource_id == resource_id)
            .options(selectinload(Resource.snapshots))
        )
        if resource is None:
            raise EntityNotFoundError("resource", resource_id)
        return resource_view(resource)

    def get_resource_history(
        self,
        resource_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[ResourceSnapshotView]:
        if self._session.get(Resource, resource_id) is None:
            raise EntityNotFoundError("resource", resource_id)
        predicate = ResourceSnapshot.resource_id == resource_id
        total = (
            self._session.scalar(
                select(func.count()).select_from(ResourceSnapshot).where(predicate)
            )
            or 0
        )
        snapshots = self._session.scalars(
            select(ResourceSnapshot)
            .where(predicate)
            .order_by(ResourceSnapshot.observed_at.desc(), ResourceSnapshot.snapshot_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(resource_snapshot_view(item) for item in snapshots),
            total=total,
            limit=limit,
            offset=offset,
        )
