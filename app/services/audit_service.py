"""Authorized-query service for append-only audit evidence."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent
from app.models.enums import AuditEventType
from app.schemas.api_views import AuditEventView, Page
from app.services.errors import EntityNotFoundError
from app.services.projections import audit_event_view


class AuditService:
    """Read append-only governance and lifecycle events."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_events(
        self,
        *,
        event_type: AuditEventType | None = None,
        actor_id: str | None = None,
        target_type: str | None = None,
        target_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[AuditEventView]:
        predicates = []
        if event_type is not None:
            predicates.append(AuditEvent.event_type == event_type)
        if actor_id is not None:
            predicates.append(AuditEvent.actor_id == actor_id)
        if target_type is not None:
            predicates.append(AuditEvent.target_type == target_type)
        if target_id is not None:
            predicates.append(AuditEvent.target_id == target_id)

        total = (
            self._session.scalar(select(func.count()).select_from(AuditEvent).where(*predicates))
            or 0
        )
        events = self._session.scalars(
            select(AuditEvent)
            .where(*predicates)
            .order_by(AuditEvent.timestamp.desc(), AuditEvent.event_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(audit_event_view(item) for item in events),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_event(self, event_id: UUID) -> AuditEventView:
        event = self._session.get(AuditEvent, event_id)
        if event is None:
            raise EntityNotFoundError("audit event", event_id)
        return audit_event_view(event)
