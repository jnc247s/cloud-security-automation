"""Portable Alembic upgrade, drift, and downgrade verification."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import create_engine, event, func, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.config import Settings
from app.database.persistence import fail_pending_scan, persist_scan_result
from app.models import ControlAssessment, ResourceSnapshot, Scan
from app.models.enums import ScanStatus
from app.schemas.scan import ScanCreateRequest
from app.services.scan_service import ScanService
from tests.unit.database.factories import scan_bundle

_CURRENT_REVISION = "20260904_0002"
_PREVIOUS_REVISION = "20260903_0001"
_COMPLETED_IDENTITY_CONSTRAINT = "ck_scans_completed_evidence_identity_present"


class _RecordingExecutor:
    def __init__(self) -> None:
        self.scan_ids: list[UUID] = []

    def submit(self, scan_id: UUID) -> None:
        self.scan_ids.append(scan_id)


def _migration_config(connection) -> Config:
    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"
    config.attributes["connection"] = connection
    return config


def _sqlite_migration_state(engine: Engine) -> dict:
    with engine.connect() as connection:
        inspector = inspect(connection)
        table_names = inspector.get_table_names()
        return {
            "revision": connection.scalar(text("SELECT version_num FROM alembic_version")),
            "scan_columns": {
                column["name"]: column["nullable"] for column in inspector.get_columns("scans")
            },
            "scan_constraints": tuple(
                sorted(
                    (constraint["name"], constraint["sqltext"])
                    for constraint in inspector.get_check_constraints("scans")
                )
            ),
            "scan_rows": tuple(
                dict(row)
                for row in connection.execute(
                    text("SELECT * FROM scans ORDER BY scan_id")
                ).mappings()
            ),
            "table_counts": {
                table_name: connection.scalar(text(f'SELECT COUNT(*) FROM "{table_name}"'))
                for table_name in table_names
                if table_name != "alembic_version"
            },
            "scan_triggers": tuple(
                tuple(row)
                for row in connection.execute(
                    text(
                        "SELECT name, sql FROM sqlite_master "
                        "WHERE type = 'trigger' AND lower(sql) LIKE '%scans%' "
                        "ORDER BY name"
                    )
                )
            ),
        }


def _create_pending_scan(
    engine: Engine,
    *,
    fail: bool,
    aws_account_id: str | None,
    inventory_sha256: str | None,
) -> UUID:
    settings = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        database_url="sqlite://",
        aws_region="us-east-1",
    )
    executor = _RecordingExecutor()
    with Session(engine, expire_on_commit=False) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(),
            executor,
            actor_id="migration-test-admin",
        )
        assert executor.scan_ids == [pending.scan_id]
        if aws_account_id is not None or inventory_sha256 is not None:
            scan = session.get(Scan, pending.scan_id)
            assert scan is not None
            scan.aws_account_id = aws_account_id
            scan.inventory_sha256 = inventory_sha256
            session.commit()
        if fail:
            fail_pending_scan(
                session,
                scan_id=pending.scan_id,
                completed_at=datetime.now(UTC),
                failure_code="AWS_IDENTITY_UNAVAILABLE",
                failure_message="AWS identity could not be verified.",
            )
            session.commit()
        return pending.scan_id


def test_sqlite_migration_round_trip_has_no_metadata_drift(migrated_engine: Engine) -> None:
    with migrated_engine.begin() as connection:
        config = _migration_config(connection)
        command.check(config)
        command.downgrade(config, "base")
        assert inspect(connection).get_table_names() == ["alembic_version"]
        command.upgrade(config, "head")
        command.check(config)


def test_pending_scan_migration_preserves_existing_sprint3_history() -> None:
    """The table rebuild must retain populated immutable history and its guards."""

    engine = create_engine("sqlite://", poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record) -> None:
        connection.execute("PRAGMA foreign_keys=ON")

    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), _PREVIOUS_REVISION)

    bundle = scan_bundle()
    with Session(engine) as session, session.begin():
        persisted = persist_scan_result(session, **bundle)
        scan_id = persisted.scan_id

    with engine.begin() as connection:
        migration_config = _migration_config(connection)
        command.upgrade(migration_config, "head")
        command.check(migration_config)

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        assert scan.inventory_sha256 is not None
        assert session.scalar(select(func.count()).select_from(ResourceSnapshot)) == 1
        assert session.scalar(select(func.count()).select_from(ControlAssessment)) == 1
    engine.dispose()


def test_pending_scan_downgrade_preserves_compatible_populated_history(
    migrated_engine: Engine,
) -> None:
    bundle = scan_bundle()
    with Session(migrated_engine) as session, session.begin():
        persisted = persist_scan_result(session, **bundle)
        scan_id = persisted.scan_id

    before = _sqlite_migration_state(migrated_engine)
    assert before["scan_rows"][0]["aws_account_id"] is not None
    assert before["scan_rows"][0]["inventory_sha256"] is not None
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), _PREVIOUS_REVISION)
    after = _sqlite_migration_state(migrated_engine)

    assert before["revision"] == _CURRENT_REVISION
    assert after["revision"] == _PREVIOUS_REVISION
    assert after["scan_columns"]["aws_account_id"] is False
    assert after["scan_columns"]["inventory_sha256"] is False
    assert _COMPLETED_IDENTITY_CONSTRAINT not in {name for name, _ in after["scan_constraints"]}
    assert after["scan_rows"] == before["scan_rows"]
    assert after["table_counts"] == before["table_counts"]
    assert after["scan_triggers"] == before["scan_triggers"]
    assert len(after["scan_rows"]) == 1
    assert after["scan_rows"][0]["scan_id"] in {str(scan_id), scan_id.hex}


@pytest.mark.parametrize(
    ("status", "fail", "aws_account_id", "inventory_sha256", "target_revision"),
    (
        (ScanStatus.RUNNING, False, None, None, "base"),
        (ScanStatus.FAILED, True, None, None, _PREVIOUS_REVISION),
        (ScanStatus.RUNNING, False, "123456789012", None, _PREVIOUS_REVISION),
        (ScanStatus.RUNNING, False, None, "f" * 64, _PREVIOUS_REVISION),
    ),
    ids=(
        "running-both-missing",
        "failed-both-missing",
        "running-digest-missing",
        "running-account-missing",
    ),
)
def test_pending_scan_downgrade_blocks_incompatible_history_without_changes(
    migrated_engine: Engine,
    status: ScanStatus,
    fail: bool,
    aws_account_id: str | None,
    inventory_sha256: str | None,
    target_revision: str,
) -> None:
    scan_id = _create_pending_scan(
        migrated_engine,
        fail=fail,
        aws_account_id=aws_account_id,
        inventory_sha256=inventory_sha256,
    )
    before = _sqlite_migration_state(migrated_engine)
    assert before["scan_rows"][0]["aws_account_id"] == aws_account_id
    assert before["scan_rows"][0]["inventory_sha256"] == inventory_sha256

    with pytest.raises(CommandError, match="Downgrade blocked before revision") as error:
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), target_revision)

    after = _sqlite_migration_state(migrated_engine)
    assert after == before
    assert after["revision"] == _CURRENT_REVISION
    assert after["scan_columns"]["aws_account_id"] is True
    assert after["scan_columns"]["inventory_sha256"] is True
    assert _COMPLETED_IDENTITY_CONSTRAINT in {name for name, _ in after["scan_constraints"]}
    assert after["scan_rows"][0]["status"] == status.value
    error_message = str(error.value)
    assert "No schema or data changes were applied" in error_message
    assert "docs/operations/known-limitations.md" in error_message
    assert str(scan_id) not in error_message
    assert scan_id.hex not in error_message

    with migrated_engine.begin() as connection:
        command.check(_migration_config(connection))


def test_pending_scan_downgrade_cannot_be_generated_offline(
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"

    with pytest.raises(CommandError, match="Offline downgrade blocked before revision"):
        command.downgrade(
            config,
            f"{_CURRENT_REVISION}:{_PREVIOUS_REVISION}",
            sql=True,
        )

    captured = capsys.readouterr()
    assert "ALTER TABLE" not in captured.out
    assert "ALTER TABLE" not in captured.err


def test_cli_managed_connection_blocks_incompatible_downgrade(tmp_path: Path) -> None:
    database_url = f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = database_url
    command.upgrade(config, "head")

    engine = create_engine(database_url)
    try:
        scan_id = _create_pending_scan(
            engine,
            fail=False,
            aws_account_id=None,
            inventory_sha256=None,
        )
        before = _sqlite_migration_state(engine)

        with pytest.raises(CommandError, match="Downgrade blocked before revision") as error:
            command.downgrade(config, _PREVIOUS_REVISION)

        assert _sqlite_migration_state(engine) == before
        assert str(scan_id) not in str(error.value)
        assert scan_id.hex not in str(error.value)
    finally:
        engine.dispose()
