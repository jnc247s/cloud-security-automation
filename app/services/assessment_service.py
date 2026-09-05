"""Authorized-query service for immutable technical assessments."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.assessment.models import AssessmentResult
from app.models.assessment import ControlAssessment
from app.models.control import ControlFrameworkMapping, ControlVersion, FrameworkReference
from app.schemas.api_views import AssessmentDetailView, AssessmentView, Page
from app.services.errors import EntityNotFoundError
from app.services.projections import assessment_detail_view, assessment_view


def _assessment_options():
    return (
        selectinload(ControlAssessment.evidence_artifacts),
        selectinload(ControlAssessment.finding_occurrence),
        selectinload(ControlAssessment.control_version)
        .selectinload(ControlVersion.framework_mappings)
        .selectinload(ControlFrameworkMapping.framework_reference)
        .selectinload(FrameworkReference.framework),
    )


class AssessmentService:
    """Expose four-state results with evidence and framework provenance."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_assessments(
        self,
        *,
        scan_id: UUID | None = None,
        resource_id: UUID | None = None,
        control_id: UUID | None = None,
        result: AssessmentResult | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[AssessmentView]:
        predicates = []
        if scan_id is not None:
            predicates.append(ControlAssessment.scan_id == scan_id)
        if resource_id is not None:
            predicates.append(ControlAssessment.resource_id == resource_id)
        if control_id is not None:
            predicates.append(ControlAssessment.control_id == control_id)
        if result is not None:
            predicates.append(ControlAssessment.assessment_result == result)

        total = (
            self._session.scalar(
                select(func.count()).select_from(ControlAssessment).where(*predicates)
            )
            or 0
        )
        assessments = self._session.scalars(
            select(ControlAssessment)
            .where(*predicates)
            .options(*_assessment_options())
            .order_by(ControlAssessment.evaluated_at.desc(), ControlAssessment.assessment_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return Page(
            items=tuple(assessment_view(item) for item in assessments),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_assessment(self, assessment_id: UUID) -> AssessmentDetailView:
        assessment = self._session.scalar(
            select(ControlAssessment)
            .where(ControlAssessment.assessment_id == assessment_id)
            .options(*_assessment_options())
        )
        if assessment is None:
            raise EntityNotFoundError("assessment", assessment_id)
        return assessment_detail_view(assessment)
