"""Exact history, real signed HTTP and measured plans on disposable PostgreSQL."""

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.models.resource import Resource
from app.services.resource_service import ResourceService
from tests.api.test_dashboard_investigation_api import exercise_reads
from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine
from tests.unit.database.factories import scan_bundle
from tests.unit.services.test_investigation_history import exercise_history
from tests.unit.services.test_technical_posture_service import persist, scaled_bundle

pytestmark = pytest.mark.integration


def test_history_contract(postgres_engine):
    exercise_history(postgres_engine)


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
def test_real_authenticated_reads(postgres_engine, monkeypatch, tmp_path, role):
    exercise_reads(postgres_engine, monkeypatch, tmp_path, role)


def test_exact_history_uses_existing_indexes(postgres_engine, record_property):
    with Session(postgres_engine) as db:
        persist(db, scaled_bundle(512))
        old = persist(db, scan_bundle())
        resource_id = db.scalars(
            select(Resource.resource_id).where(Resource.aws_resource_id == "sg-history")
        ).one()
    queries = []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        if "FROM resource_snapshots" in statement:
            queries.append((statement, parameters))

    event.listen(postgres_engine, "before_cursor_execute", capture)
    try:
        with Session(postgres_engine) as db:
            assert ResourceService(db).get_resource_history(resource_id, scan_id=old).total == 1
    finally:
        event.remove(postgres_engine, "before_cursor_execute", capture)
    assert len(queries) == 2
    with postgres_engine.connect() as connection:
        connection.exec_driver_sql("ANALYZE resource_snapshots")
        for index, (statement, parameters) in enumerate(queries):
            plan = connection.exec_driver_sql(
                "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + statement, parameters
            ).scalar_one()[0]
            assert plan["Plan"]["Actual Rows"] == 1
            assert "Index" in str(plan["Plan"])
            record_property(f"history_{index}_plan", plan["Plan"])
