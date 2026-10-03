"""Same reporting contracts on disposable PostgreSQL, including authenticated HTTP."""

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from app.assessment.models import AssessmentResult
from app.schemas.inventory import CollectionStatus
from app.services.technical_posture_service import TechnicalPostureService
from tests.api.test_technical_posture_api import (
    exercise_lifecycle_http,
    exercise_provenance_error,
    exercise_read_role,
)
from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine
from tests.unit.services.test_technical_posture_service import (
    exercise_collection_state,
    exercise_empty_enablement,
    exercise_external_owner,
    exercise_history,
    exercise_result_state,
    exercise_scaling,
    exercise_supplemental_region,
    exercise_unfinished,
    persist,
    scaled_bundle,
)

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("result", AssessmentResult)
def test_each_result_and_disabled_controls(postgres_engine, result):
    with Session(postgres_engine) as session:
        exercise_result_state(session, result)


@pytest.mark.parametrize("status", CollectionStatus)
def test_collection_status_and_retained_results(postgres_engine, status):
    with Session(postgres_engine) as session:
        exercise_collection_state(session, status)


def test_unfinished_and_no_bundle_failure(postgres_engine):
    with Session(postgres_engine) as session:
        exercise_unfinished(session)


def test_empty_enablement(postgres_engine):
    with Session(postgres_engine) as session:
        exercise_empty_enablement(session)


def test_external_owner(postgres_engine):
    with Session(postgres_engine) as session:
        exercise_external_owner(session)


def test_supplemental_region(postgres_engine):
    with Session(postgres_engine) as session:
        exercise_supplemental_region(session)


def test_all_retained_releases(postgres_engine):
    exercise_history(postgres_engine)


@pytest.mark.parametrize("size", [16, 32])
def test_fixed_query_count(postgres_engine, size):
    exercise_scaling(postgres_engine, size)


@pytest.mark.parametrize("size", [128, 512])
def test_representative_postgres_aggregate_plans(postgres_engine, size, record_property):
    with Session(postgres_engine) as session:
        scan_id = persist(session, scaled_bundle(size))
    queries = []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if "FROM control_assessments" in statement:
            queries.append((statement, parameters))

    event.listen(postgres_engine, "before_cursor_execute", capture)
    try:
        with Session(postgres_engine) as session:
            report = TechnicalPostureService(session).get_technical_posture(scan_id)
            assert report.assessment_counts.fail_count == size
    finally:
        event.remove(postgres_engine, "before_cursor_execute", capture)
    assert len(queries) == 2  # Control totals and assessed-target groups, not detail reads.
    with postgres_engine.connect() as connection:
        for index, (statement, parameters) in enumerate(queries):
            plan = connection.exec_driver_sql(
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + statement, parameters
            ).scalar_one()[0]
            assert plan["Plan"]["Actual Rows"] == 1
            assert plan["Plan"]["Actual Loops"] == 1
            # Diagnostic timing only; correctness does not depend on host-speed thresholds.
            record_property(f"aggregate_{index}_execution_ms", plan["Execution Time"])
            record_property(f"aggregate_{index}_node", plan["Plan"]["Node Type"])


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
def test_real_production_authenticated_http(postgres_engine, monkeypatch, role):
    exercise_read_role(postgres_engine, monkeypatch, role)


@pytest.mark.parametrize("state", ["RUNNING", "FAILED_NO_BUNDLE", "PARTIAL", "FAILED_RETAINED"])
def test_real_production_http_lifecycle(postgres_engine, monkeypatch, state):
    exercise_lifecycle_http(postgres_engine, monkeypatch, state)


def test_sanitized_provenance_conflict(postgres_engine, monkeypatch):
    exercise_provenance_error(postgres_engine, monkeypatch)
