"""Exact-scan history is additive and never substitutes a newer observation."""

from uuid import uuid4

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.models.resource import Resource
from app.services.errors import EntityNotFoundError
from app.services.resource_service import ResourceService
from tests.unit.database.factories import scan_bundle
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.unit.services.test_technical_posture_service import persist


def exercise_history(engine):
    with Session(engine) as db:
        old = persist(db, scan_bundle(tags={"history": "old"}))
        newer = persist(db, scan_bundle(public_ssh=False, tags={"history": "new"}))
        resource_id = db.scalars(select(Resource.resource_id)).one()
    queries = []

    def capture(_connection, _cursor, statement, parameters, _context, _many):
        queries.append((statement, parameters))

    event.listen(engine, "before_cursor_execute", capture)
    try:
        with Session(engine) as db:
            old_page = ResourceService(db).get_resource_history(resource_id, scan_id=old)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert len(queries) == 3
    assert all(statement.lstrip().startswith("SELECT") for statement, _ in queries)
    assert old_page.total == 1
    assert old_page.items[0].scan_id == old
    assert old_page.items[0].tags == {"history": "old"}
    with Session(engine) as db:
        service = ResourceService(db)
        assert service.get_resource_history(resource_id).total == 2
        assert service.get_resource_history(resource_id, limit=1).limit == 1
        assert service.get_resource_history(resource_id, scan_id=newer).items[0].tags == {
            "history": "new"
        }
        assert service.get_resource_history(resource_id, scan_id=old, offset=1).items == ()
        assert service.get_resource_history(resource_id, scan_id=old, offset=1).total == 1
        assert service.get_resource_history(resource_id, scan_id=uuid4()).total == 0
        with pytest.raises(EntityNotFoundError):
            service.get_resource_history(uuid4(), scan_id=old)


def test_exact_scan_history_and_unchanged_unfiltered_contract(migrated_engine):
    exercise_history(migrated_engine)
