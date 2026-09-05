"""Authorized-query service for operational findings and their history."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.enums import FindingStatus
from app.models.finding import Finding
from app.schemas.api_views import FindingDetailView, FindingView, Page
from app.services.errors import EntityNotFoundError
from app.services.projections import finding_detail_view, finding_view


def _finding_options():
    return (selectinload(Finding.occurrences), selectinload(Finding.exceptions))


class FindingService:
    """Expose current finding state without losing occurrence history."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_findings(
        self,
        *,
        account_id: str | None = None,
        resource_id: UUID | None = None,
        control_id: UUID | None = None,
        status: FindingStatus | None = None,
        region: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[FindingView]:
        predicates = []
        if account_id is not None:
            predicates.append(Finding.aws_account_id == account_id)
        if resource_id is not None:
            predicates.append(Finding.resource_id == resource_id)
        if control_id is not None:
            predicates.append(Finding.control_id == control_id)
        if status is not None:
            predicates.append(Finding.status == status)
        if region is not None:
            predicates.append(Finding.region == region)

        total = (
            self._session.scalar(select(func.count()).select_from(Finding).where(*predicates)) or 0
        )
        findings = self._session.scalars(
            select(Finding)
            .where(*predicates)
            .options(*_finding_options())
            .order_by(Finding.last_detected_at.desc(), Finding.finding_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(finding_view(item) for item in findings),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_finding(self, finding_id: UUID) -> FindingDetailView:
        finding = self._session.scalar(
            select(Finding).where(Finding.finding_id == finding_id).options(*_finding_options())
        )
        if finding is None:
            raise EntityNotFoundError("finding", finding_id)
        return finding_detail_view(finding)
