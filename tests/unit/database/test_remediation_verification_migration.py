"""0010 retains accepted history and refuses incompatible downgrade before DDL."""

from uuid import uuid4

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.persistence import append_audit_event
from app.models import AuditEvent, Scan
from app.models.enums import AuditEventType
from app.models.remediation_verification import (
    RemediationVerification,
    RemediationVerificationReceipt,
)
from tests.unit.database.test_migrations import _migration_config
from tests.unit.database.test_remediation_worker_migration import snapshot
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.verification_fixtures import VerificationHarness


def test_populated_0009_upgrade_preserves_all_existing_rows(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), "20261008_0009")
    before = snapshot(migrated_engine)
    with migrated_engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        command.check(_migration_config(connection))
    after = snapshot(migrated_engine)
    for table, rows in before[1].items():
        if table != "alembic_version":
            assert after[1][table] == rows
    assert harness.request().value.receipt is None


@pytest.mark.parametrize("completed", [False, True])
@pytest.mark.parametrize("destination", ["20261008_0009", "base"])
def test_verification_history_blocks_whole_downgrade_path(migrated_engine, completed, destination):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    if completed:
        harness.run(value.content.scan_id)
    before = snapshot(migrated_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261013_0010"):
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), destination)
    assert snapshot(migrated_engine) == before


@pytest.mark.parametrize(
    "event_type",
    [
        AuditEventType.REMEDIATION_VERIFICATION_REQUESTED,
        AuditEventType.REMEDIATION_VERIFICATION_COMPLETED,
    ],
)
def test_verification_audit_alone_blocks_downgrade(migrated_engine, event_type):
    with Session(migrated_engine) as session, session.begin():
        from tests.remediation_fixtures import NOW

        append_audit_event(
            session,
            event_type,
            "remediation_verification",
            uuid4(),
            NOW,
            actor_type="system",
            actor_id="offline-audit",
        )
    before = snapshot(migrated_engine)
    with pytest.raises(CommandError, match="blocked before revision 20261013_0010"):
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), "base")
    assert snapshot(migrated_engine) == before


@pytest.mark.parametrize("destination", ["20261008_0009", "base"])
def test_offline_verification_downgrade_requires_online_check(migrated_engine, destination):
    with migrated_engine.begin() as connection:
        with pytest.raises(
            CommandError, match="Offline downgrade blocked before revision 20261013_0010"
        ):
            command.downgrade(
                _migration_config(connection), "20261013_0010:" + destination, sql=True
            )


@pytest.mark.parametrize("model", [RemediationVerification, RemediationVerificationReceipt])
@pytest.mark.parametrize("mutation", ["update", "delete"])
def test_verification_history_is_immutable(migrated_engine, model, mutation):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    harness.run(value.content.scan_id)
    before = snapshot(migrated_engine)
    statement = (
        delete(model) if mutation == "delete" else update(model).values(created_at=harness.clock())
    )
    with pytest.raises(IntegrityError, match="immutable"):
        with migrated_engine.begin() as connection:
            connection.execute(statement)
    assert snapshot(migrated_engine) == before


def test_receipt_cannot_be_inserted_for_a_running_scan(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    before = snapshot(migrated_engine)
    with pytest.raises(IntegrityError, match="provenance is invalid"):
        with Session(migrated_engine) as session, session.begin():
            audit = append_audit_event(
                session,
                AuditEventType.REMEDIATION_VERIFICATION_COMPLETED,
                "remediation_verification",
                value.content.verification_id,
                harness.clock(),
                actor_type="system",
                actor_id="scan-executor",
            )
            session.flush()
            session.add(
                RemediationVerificationReceipt(
                    verification_id=value.content.verification_id,
                    audit_event_id=audit.event_id,
                    outcome="VERIFIED",
                    content={},
                    content_sha256="f" * 64,
                    created_at=harness.clock(),
                )
            )
    assert snapshot(migrated_engine) == before


def test_verification_link_protects_its_pending_scan_identity(migrated_engine):
    harness = VerificationHarness(migrated_engine)
    value = harness.request().value
    with pytest.raises(IntegrityError):
        with migrated_engine.begin() as connection:
            connection.execute(delete(Scan).where(Scan.scan_id == value.content.scan_id))
    with Session(migrated_engine) as session:
        assert (
            session.scalar(
                select(AuditEvent).where(
                    AuditEvent.target_id == value.content.scan_id,
                    AuditEvent.event_type == AuditEventType.SCAN_STARTED,
                )
            )
            is not None
        )
