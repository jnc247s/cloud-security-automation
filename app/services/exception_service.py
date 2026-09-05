"""Authorized-query service for explicit operational exceptions."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import ExceptionStatus
from app.models.exception import FindingException
from app.schemas.api_views import FindingExceptionView, Page
from app.services.errors import EntityNotFoundError
from app.services.projections import exception_view


class ExceptionService:
    """Expose exception decisions independently from technical results."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_exceptions(
        self,
        *,
        finding_id: UUID | None = None,
        resource_id: UUID | None = None,
        control_id: UUID | None = None,
        status: ExceptionStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[FindingExceptionView]:
        predicates = []
        if finding_id is not None:
            predicates.append(FindingException.finding_id == finding_id)
        if resource_id is not None:
            predicates.append(FindingException.resource_id == resource_id)
        if control_id is not None:
            predicates.append(FindingException.control_id == control_id)
        if status is not None:
            predicates.append(FindingException.status == status)

        total = (
            self._session.scalar(
                select(func.count()).select_from(FindingException).where(*predicates)
            )
            or 0
        )
        exceptions = self._session.scalars(
            select(FindingException)
            .where(*predicates)
            .order_by(FindingException.created_at.desc(), FindingException.exception_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(exception_view(item) for item in exceptions),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_exception(self, exception_id: UUID) -> FindingExceptionView:
        exception = self._session.get(FindingException, exception_id)
        if exception is None:
            raise EntityNotFoundError("exception", exception_id)
        return exception_view(exception)
