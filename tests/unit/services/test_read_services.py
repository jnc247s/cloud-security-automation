"""Focused coverage for the Sprint 4 read/query service boundary."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.models import AssessmentResult
from app.database.persistence import persist_scan_result
from app.models.assessment import ControlAssessment
from app.models.audit import AuditEvent
from app.models.enums import ExceptionStatus, FindingStatus
from app.models.exception import FindingException
from app.models.finding import Finding
from app.models.resource import Resource
from app.services.assessment_service import AssessmentService
from app.services.audit_service import AuditService
from app.services.control_service import ControlService
from app.services.errors import EntityNotFoundError
from app.services.exception_service import ExceptionService
from app.services.finding_service import FindingService
from app.services.framework_service import FrameworkService
from app.services.resource_service import ResourceService
from tests.unit.database.conftest import db_session as db_session
from tests.unit.database.conftest import migrated_engine as migrated_engine
from tests.unit.database.factories import scan_bundle


def _persist_fixture(db_session: Session) -> None:
    persist_scan_result(db_session, **scan_bundle())
    db_session.commit()


def test_resource_and_assessment_services_expose_history_and_provenance(
    db_session: Session,
) -> None:
    _persist_fixture(db_session)
    resource = db_session.scalars(select(Resource)).one()
    assessment = db_session.scalars(select(ControlAssessment)).one()

    resources = ResourceService(db_session).list_resources(
        account_id="123456789012",
        service="ec2",
        limit=1,
    )
    history = ResourceService(db_session).get_resource_history(resource.resource_id)
    assessment_detail = AssessmentService(db_session).get_assessment(assessment.assessment_id)

    assert resources.total == 1
    assert resources.items[0].latest_snapshot is not None
    assert history.total == 1
    assert history.items[0].resource_id == resource.resource_id
    assert assessment_detail.assessment_result is AssessmentResult.FAIL
    assert assessment_detail.evidence_count == len(assessment_detail.evidence)
    assert assessment_detail.evidence
    assert assessment_detail.framework_mappings
    assert assessment_detail.finding_id is not None


def test_finding_exception_catalog_framework_and_audit_services(
    db_session: Session,
) -> None:
    _persist_fixture(db_session)
    finding = db_session.scalars(select(Finding)).one()
    created_at = datetime.now(UTC)
    exception = FindingException(
        finding_id=finding.finding_id,
        resource_id=finding.resource_id,
        control_id=finding.control_id,
        reason="Risk accepted for the migration window",
        approved_by="test-approver",
        created_at=created_at,
        expires_at=created_at + timedelta(days=7),
        status=ExceptionStatus.ACTIVE,
    )
    db_session.add(exception)
    db_session.commit()

    finding_page = FindingService(db_session).list_findings(status=FindingStatus.OPEN)
    finding_detail = FindingService(db_session).get_finding(finding.finding_id)
    exceptions = ExceptionService(db_session).list_exceptions(
        finding_id=finding.finding_id,
        status=ExceptionStatus.ACTIVE,
    )
    controls = ControlService(db_session).list_controls(resource_type="security_group")
    frameworks = FrameworkService(db_session).list_frameworks(framework_key="nist-csf")
    event = db_session.scalars(select(AuditEvent).order_by(AuditEvent.timestamp)).first()
    assert event is not None
    events = AuditService(db_session).list_events(target_id=event.target_id)

    assert finding_page.total == 1
    assert finding_detail.occurrences
    assert finding_detail.active_exception_ids == (exception.exception_id,)
    assert exceptions.items[0].approved_by == "test-approver"
    assert controls.items[0].versions[0].framework_mappings
    assert frameworks.items[0].references
    assert any(reference.control_mappings for reference in frameworks.items[0].references)
    assert events.total >= 1


@pytest.mark.parametrize(
    ("service", "method", "entity"),
    [
        (ResourceService, "get_resource", "resource"),
        (AssessmentService, "get_assessment", "assessment"),
        (FindingService, "get_finding", "finding"),
        (ControlService, "get_control", "control"),
        (FrameworkService, "get_framework", "framework"),
        (ExceptionService, "get_exception", "exception"),
        (AuditService, "get_event", "audit event"),
    ],
)
def test_detail_queries_raise_consistent_not_found_errors(
    db_session: Session,
    service: type,
    method: str,
    entity: str,
) -> None:
    missing_id = uuid4()

    with pytest.raises(EntityNotFoundError, match=entity):
        getattr(service(db_session), method)(missing_id)
