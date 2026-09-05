"""Authorized-query service for immutable external framework versions."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.control import (
    ControlFrameworkMapping,
    ControlVersion,
    Framework,
    FrameworkReference,
)
from app.schemas.api_views import FrameworkView, Page
from app.services.errors import EntityNotFoundError
from app.services.projections import framework_view


def _framework_options():
    return (
        selectinload(Framework.references)
        .selectinload(FrameworkReference.control_mappings)
        .selectinload(ControlFrameworkMapping.control_version)
        .selectinload(ControlVersion.control),
    )


class FrameworkService:
    """Expose framework hierarchy and its auditable control mappings."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_frameworks(
        self,
        *,
        framework_key: str | None = None,
        version: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[FrameworkView]:
        predicates = []
        if framework_key is not None:
            predicates.append(Framework.framework_key == framework_key)
        if version is not None:
            predicates.append(Framework.version == version)

        total = (
            self._session.scalar(select(func.count()).select_from(Framework).where(*predicates))
            or 0
        )
        frameworks = self._session.scalars(
            select(Framework)
            .where(*predicates)
            .options(*_framework_options())
            .order_by(Framework.framework_key, Framework.version, Framework.framework_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(framework_view(item) for item in frameworks),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_framework(self, framework_id: UUID) -> FrameworkView:
        framework = self._session.scalar(
            select(Framework)
            .where(Framework.framework_id == framework_id)
            .options(*_framework_options())
        )
        if framework is None:
            raise EntityNotFoundError("framework", framework_id)
        return framework_view(framework)
