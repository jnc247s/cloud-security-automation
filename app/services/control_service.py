"""Authorized-query service for versioned internal controls."""

from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session, selectinload

from app.models.control import (
    Control,
    ControlCatalog,
    ControlFrameworkMapping,
    ControlVersion,
    FrameworkReference,
)
from app.schemas.api_views import ControlView, Page
from app.schemas.finding import ControlCategory, Severity
from app.services.errors import EntityNotFoundError
from app.services.projections import control_view


def _control_options():
    return (
        selectinload(Control.versions).selectinload(ControlVersion.catalog),
        selectinload(Control.versions)
        .selectinload(ControlVersion.framework_mappings)
        .selectinload(ControlFrameworkMapping.framework_reference)
        .selectinload(FrameworkReference.framework),
    )


class ControlService:
    """Expose stable controls, exact definitions, and framework mappings."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_controls(
        self,
        *,
        category: ControlCategory | None = None,
        severity: Severity | None = None,
        resource_type: str | None = None,
        catalog_key: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[ControlView]:
        version_predicates = []
        if category is not None:
            version_predicates.append(ControlVersion.category == category)
        if severity is not None:
            version_predicates.append(ControlVersion.severity == severity)
        if resource_type is not None:
            version_predicates.append(ControlVersion.resource_type == resource_type)
        if catalog_key is not None:
            version_predicates.append(
                ControlVersion.catalog.has(ControlCatalog.catalog_key == catalog_key)
            )
        predicates = [Control.versions.any(and_(*version_predicates))] if version_predicates else []

        total = (
            self._session.scalar(select(func.count()).select_from(Control).where(*predicates)) or 0
        )
        controls = self._session.scalars(
            select(Control)
            .where(*predicates)
            .options(*_control_options())
            .order_by(Control.control_key, Control.control_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(control_view(item) for item in controls),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_control(self, control_id: UUID) -> ControlView:
        control = self._session.scalar(
            select(Control).where(Control.control_id == control_id).options(*_control_options())
        )
        if control is None:
            raise EntityNotFoundError("control", control_id)
        return control_view(control)
