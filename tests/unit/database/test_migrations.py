"""Portable Alembic upgrade, drift, and downgrade verification."""

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from sqlalchemy import create_engine, event, func, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.config import Settings
from app.database.persistence import fail_pending_scan, persist_scan_result
from app.models import ControlAssessment, ResourceSnapshot, Scan
from app.models.enums import ScanStatus
from app.schemas.scan import ScanCreateRequest
from app.services.scan_service import ScanService
from tests.unit.database.factories import scan_bundle

_CURRENT_REVISION = "20260924_0004"
_PENDING_SCAN_REVISION = "20260904_0002"
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


def _insert_present_resource_source(
    connection,
    *,
    scan_id: UUID,
    outcome_id: UUID,
    artifact_id: UUID,
    resource_id: UUID,
    snapshot_id: UUID,
    owner_id: str,
    service: str,
    resource_type: str,
    aws_resource_id: str,
    scope: str,
    region: str | None,
    owner_mode: str,
    allows_supplemental_region: bool,
) -> tuple[str, datetime]:
    """Insert a direct-SQL PRESENT resource source before its deferred snapshot."""

    collected_at = datetime.now(UTC)
    evidence_reference = f"normalized://migration/{outcome_id}"
    subject = json.dumps(
        {
            "subject_kind": "resource",
            "provider": "aws",
            "aws_account_id": owner_id,
            "service": service,
            "resource_type": resource_type,
            "aws_resource_id": aws_resource_id,
            "scope": scope,
            "region": region,
            "stable_resource_id": str(resource_id),
            "resource_snapshot_id": str(snapshot_id),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    connection.execute(
        text(
            "INSERT INTO resources (resource_id, provider, aws_account_id, aws_resource_id, "
            "arn, service, resource_type, scope, region) VALUES ("
            ":resource_id, 'aws', :owner_id, :aws_resource_id, NULL, :service, "
            ":resource_type, :scope, :resource_region)"
        ),
        {
            "resource_id": resource_id.hex,
            "owner_id": owner_id,
            "aws_resource_id": aws_resource_id,
            "service": service,
            "resource_type": resource_type,
            "scope": scope,
            "resource_region": region or "global",
        },
    )
    connection.execute(
        text(
            "INSERT INTO scan_source_contracts ("
            "source_outcome_id, scan_id, collection_account_id, contract_key, "
            "contract_version, phase, subject_kind, subject, subject_resource_id, "
            "subject_resource_snapshot_id, evidence_kind, collector, collector_version, "
            "source_api, cardinality, owner_mode, identity_authoritative, "
            "allows_supplemental_region, schema_version) VALUES ("
            ":outcome_id, :scan_id, '123456789012', :contract_key, '1.0.0', "
            "'ENRICHMENT', 'resource', :subject, :resource_id, :snapshot_id, :evidence_kind, "
            "'MigrationTestCollector', '1.0.0', :source_api, 'SINGLE', :owner_mode, 1, "
            ":allows_supplemental_region, '1.0.0')"
        ),
        {
            "outcome_id": outcome_id.hex,
            "scan_id": scan_id.hex,
            "contract_key": f"{service}.{resource_type}",
            "subject": subject,
            "resource_id": resource_id.hex,
            "snapshot_id": snapshot_id.hex,
            "evidence_kind": f"{service}.{resource_type}",
            "source_api": f"{service}:GetEvidence",
            "owner_mode": owner_mode,
            "allows_supplemental_region": int(allows_supplemental_region),
        },
    )
    connection.execute(
        text(
            "INSERT INTO source_evidence_artifacts ("
            "artifact_id, scan_id, collection_account_id, evidence_reference, "
            "evidence_sha256, evidence_schema, evidence_schema_version, collected_at, "
            "normalized_payload, schema_version) VALUES ("
            ":artifact_id, :scan_id, '123456789012', :reference, :digest, "
            "'migration.test', '1.0.0', :collected_at, :payload, '1.0.0')"
        ),
        {
            "artifact_id": artifact_id.hex,
            "scan_id": scan_id.hex,
            "reference": evidence_reference,
            "digest": "a" * 64,
            "collected_at": collected_at,
            "payload": json.dumps({"identity": aws_resource_id}),
        },
    )
    connection.execute(
        text(
            "INSERT INTO source_evidence_outcomes ("
            "source_outcome_id, scan_id, collection_account_id, phase, subject_kind, subject, "
            "subject_resource_id, subject_resource_snapshot_id, subject_scope, subject_region, "
            "evidence_kind, state, failure_category, collector, collector_version, source, "
            "source_api, collected_at, artifact_id, evidence_reference, evidence_sha256, "
            "schema_version) VALUES ("
            ":outcome_id, :scan_id, '123456789012', 'ENRICHMENT', 'resource', :subject, "
            ":resource_id, :snapshot_id, :scope, :region, :evidence_kind, 'PRESENT', NULL, "
            "'MigrationTestCollector', '1.0.0', 'aws-api', :source_api, :collected_at, "
            ":artifact_id, :reference, :digest, '1.0.0')"
        ),
        {
            "outcome_id": outcome_id.hex,
            "scan_id": scan_id.hex,
            "subject": subject,
            "resource_id": resource_id.hex,
            "snapshot_id": snapshot_id.hex,
            "scope": scope,
            "region": region,
            "evidence_kind": f"{service}.{resource_type}",
            "source_api": f"{service}:GetEvidence",
            "collected_at": collected_at,
            "artifact_id": artifact_id.hex,
            "reference": evidence_reference,
            "digest": "a" * 64,
        },
    )
    return evidence_reference, collected_at


def _insert_snapshot(
    connection,
    *,
    scan_id: UUID,
    resource_id: UUID,
    snapshot_id: UUID,
    scope: str,
    region: str | None,
) -> None:
    connection.execute(
        text(
            "INSERT INTO resource_snapshots ("
            "snapshot_id, resource_id, scan_id, scope, region, arn, name, tags, "
            "normalized_configuration, state_sha256, observed_at) VALUES ("
            ":snapshot_id, :resource_id, :scan_id, :scope, :region, NULL, NULL, '{}', '{}', "
            ":digest, :observed_at)"
        ),
        {
            "snapshot_id": snapshot_id.hex,
            "resource_id": resource_id.hex,
            "scan_id": scan_id.hex,
            "scope": scope,
            "region": region,
            "digest": "b" * 64,
            "observed_at": datetime.now(UTC),
        },
    )


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
        command.upgrade(_migration_config(connection), "head")

    bundle = scan_bundle()
    with Session(engine) as session, session.begin():
        persisted = persist_scan_result(session, **bundle)
        scan_id = persisted.scan_id

    with engine.begin() as connection:
        migration_config = _migration_config(connection)
        # Seed legacy-compatible data with today's writer, then place it at the historical
        # revision. Current ORM models deliberately cannot write an obsolete schema.
        command.downgrade(migration_config, _PREVIOUS_REVISION)
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

    # First return through the empty, compatible evidence-graph revision so
    # this assertion remains focused on the established 0002 downgrade.
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), _PENDING_SCAN_REVISION)
    before = _sqlite_migration_state(migrated_engine)
    assert before["scan_rows"][0]["aws_account_id"] is not None
    assert before["scan_rows"][0]["inventory_sha256"] is not None
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), _PREVIOUS_REVISION)
    after = _sqlite_migration_state(migrated_engine)

    assert before["revision"] == _PENDING_SCAN_REVISION
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
            f"{_PENDING_SCAN_REVISION}:{_PREVIOUS_REVISION}",
            sql=True,
        )

    captured = capsys.readouterr()
    assert "ALTER TABLE" not in captured.out
    assert "ALTER TABLE" not in captured.err


def test_evidence_graph_schema_is_current_and_matches_metadata(
    migrated_engine: Engine,
) -> None:
    with migrated_engine.begin() as connection:
        inspector = inspect(connection)
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            _CURRENT_REVISION
        )
        assert {
            "scan_source_contracts",
            "source_evidence_artifacts",
            "source_evidence_outcomes",
            "resource_relationship_observations",
        }.issubset(inspector.get_table_names())
        scope_columns = {column["name"] for column in inspector.get_columns("scan_scope_manifests")}
        assert {
            "source_manifest_schema_version",
            "source_manifest_checksum",
        }.issubset(scope_columns)
        command.check(_migration_config(connection))


def test_evidence_graph_downgrade_preserves_compatible_legacy_history(
    migrated_engine: Engine,
) -> None:
    bundle = scan_bundle()
    with Session(migrated_engine) as session, session.begin():
        persisted = persist_scan_result(session, **bundle)
        scan_id = persisted.scan_id

    before = _sqlite_migration_state(migrated_engine)
    with migrated_engine.begin() as connection:
        command.downgrade(_migration_config(connection), _PENDING_SCAN_REVISION)
    after = _sqlite_migration_state(migrated_engine)

    assert after["revision"] == _PENDING_SCAN_REVISION
    assert after["scan_rows"] == before["scan_rows"]
    assert after["scan_rows"][0]["scan_id"] in {str(scan_id), scan_id.hex}
    for table_name, row_count in after["table_counts"].items():
        assert before["table_counts"][table_name] == row_count
    with migrated_engine.connect() as connection:
        inspector = inspect(connection)
        assert not {
            "scan_source_contracts",
            "source_evidence_artifacts",
            "source_evidence_outcomes",
            "resource_relationship_observations",
        }.intersection(inspector.get_table_names())
        assert "source_manifest_checksum" not in {
            column["name"] for column in inspector.get_columns("scan_scope_manifests")
        }


def test_evidence_graph_downgrade_blocks_retained_rows_without_changes(
    migrated_engine: Engine,
) -> None:
    scan_id = _create_pending_scan(
        migrated_engine,
        fail=False,
        aws_account_id="123456789012",
        inventory_sha256="f" * 64,
    )
    outcome_id = uuid4()
    with migrated_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO scan_source_contracts ("
                "source_outcome_id, scan_id, collection_account_id, contract_key, "
                "contract_version, phase, subject_kind, subject, subject_resource_id, "
                "subject_resource_snapshot_id, evidence_kind, collector, collector_version, "
                "source_api, cardinality, owner_mode, identity_authoritative, "
                "allows_supplemental_region, schema_version"
                ") VALUES ("
                ":source_outcome_id, :scan_id, '123456789012', 'ec2.instances', '1.0.0', "
                "'DISCOVERY', 'account', :subject, NULL, NULL, 'ec2.instances', "
                "'EC2Collector', '1.0.0', 'ec2:DescribeInstances', 'COLLECTION', "
                "'COLLECTION_ACCOUNT', 1, 0, '1.0.0'"
                ")"
            ),
            {
                "source_outcome_id": outcome_id.hex,
                "scan_id": scan_id.hex,
                "subject": json.dumps(
                    {
                        "subject_kind": "account",
                        "provider": "aws",
                        "aws_account_id": "123456789012",
                        "scope": "regional",
                        "region": "us-east-1",
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            },
        )

    with pytest.raises(IntegrityError, match="evidence graph is incomplete"):
        with migrated_engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE scans SET status = 'FAILED', completed_at = :completed_at, "
                    "result_checksum = :result_checksum WHERE scan_id = :scan_id"
                ),
                {
                    "completed_at": datetime.now(UTC),
                    "result_checksum": "e" * 64,
                    "scan_id": scan_id.hex,
                },
            )

    before = _sqlite_migration_state(migrated_engine)
    with pytest.raises(CommandError, match="retained source-evidence") as error:
        with migrated_engine.begin() as connection:
            command.downgrade(_migration_config(connection), _PENDING_SCAN_REVISION)

    assert _sqlite_migration_state(migrated_engine) == before
    assert str(scan_id) not in str(error.value)
    assert scan_id.hex not in str(error.value)
    assert str(outcome_id) not in str(error.value)
    assert outcome_id.hex not in str(error.value)


def test_snapshot_guard_accepts_exact_aws_managed_identity_without_relationship(
    migrated_engine: Engine,
) -> None:
    scan_id = _create_pending_scan(
        migrated_engine,
        fail=False,
        aws_account_id="123456789012",
        inventory_sha256="f" * 64,
    )
    resource_id, snapshot_id = uuid4(), uuid4()
    with migrated_engine.begin() as connection:
        _insert_present_resource_source(
            connection,
            scan_id=scan_id,
            outcome_id=uuid4(),
            artifact_id=uuid4(),
            resource_id=resource_id,
            snapshot_id=snapshot_id,
            owner_id="aws",
            service="iam",
            resource_type="iam_aws_managed_policy",
            aws_resource_id="arn:aws:iam::aws:policy/ReadOnlyAccess",
            scope="global",
            region=None,
            owner_mode="AWS_MANAGED",
            allows_supplemental_region=False,
        )
        _insert_snapshot(
            connection,
            scan_id=scan_id,
            resource_id=resource_id,
            snapshot_id=snapshot_id,
            scope="global",
            region=None,
        )
    with migrated_engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM resource_snapshots")) == 1


def test_snapshot_guard_rejects_external_owner_without_resolved_relationship(
    migrated_engine: Engine,
) -> None:
    scan_id = _create_pending_scan(
        migrated_engine,
        fail=False,
        aws_account_id="123456789012",
        inventory_sha256="f" * 64,
    )
    resource_id, snapshot_id = uuid4(), uuid4()
    with pytest.raises(IntegrityError, match="owner or scope"):
        with migrated_engine.begin() as connection:
            _insert_present_resource_source(
                connection,
                scan_id=scan_id,
                outcome_id=uuid4(),
                artifact_id=uuid4(),
                resource_id=resource_id,
                snapshot_id=snapshot_id,
                owner_id="210987654321",
                service="ec2",
                resource_type="security_group",
                aws_resource_id="sg-external",
                scope="regional",
                region="us-east-1",
                owner_mode="EXTERNAL_ACCOUNT",
                allows_supplemental_region=False,
            )
            _insert_snapshot(
                connection,
                scan_id=scan_id,
                resource_id=resource_id,
                snapshot_id=snapshot_id,
                scope="regional",
                region="us-east-1",
            )
    with migrated_engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM resource_snapshots")) == 0


def test_snapshot_guard_accepts_external_owner_with_exact_proof_and_resolved_relationship(
    migrated_engine: Engine,
) -> None:
    scan_id = _create_pending_scan(
        migrated_engine,
        fail=False,
        aws_account_id="123456789012",
        inventory_sha256="f" * 64,
    )
    source_resource_id, source_snapshot_id = uuid4(), uuid4()
    target_resource_id, target_snapshot_id = uuid4(), uuid4()
    outcome_id, artifact_id = uuid4(), uuid4()
    relationship_id, observation_id = uuid4(), uuid4()
    with migrated_engine.begin() as connection:
        evidence_reference, collected_at = _insert_present_resource_source(
            connection,
            scan_id=scan_id,
            outcome_id=outcome_id,
            artifact_id=artifact_id,
            resource_id=target_resource_id,
            snapshot_id=target_snapshot_id,
            owner_id="210987654321",
            service="ec2",
            resource_type="security_group",
            aws_resource_id="sg-external",
            scope="regional",
            region="us-east-1",
            owner_mode="EXTERNAL_ACCOUNT",
            allows_supplemental_region=False,
        )
        connection.execute(
            text(
                "INSERT INTO resources (resource_id, provider, aws_account_id, "
                "aws_resource_id, arn, service, resource_type, scope, region) VALUES ("
                ":resource_id, 'aws', '123456789012', 'finding-1', NULL, "
                "'access-analyzer', 'access_analyzer_finding', 'regional', 'us-east-1')"
            ),
            {"resource_id": source_resource_id.hex},
        )
        connection.execute(
            text(
                "INSERT INTO resource_relationship_observations ("
                "observation_id, relationship_id, scan_id, collection_account_id, "
                "relationship_type, resolution, source_provider, source_aws_account_id, "
                "source_service, source_resource_type, source_aws_resource_id, source_scope, "
                "source_region, source_resource_id, source_resource_snapshot_id, "
                "target_identity_state, target_provider, target_aws_account_id, "
                "target_service, target_resource_type, target_aws_resource_id, target_scope, "
                "target_region, target_resource_id, target_resource_snapshot_id, "
                "target_reference_id, source_outcome_id, provenance_collector, "
                "provenance_collector_version, provenance_source, provenance_source_api, "
                "evidence_reference, collected_at, schema_version) VALUES ("
                ":observation_id, :relationship_id, :scan_id, '123456789012', "
                "'references_resource', 'RESOLVED', 'aws', '123456789012', "
                "'access-analyzer', 'access_analyzer_finding', 'finding-1', 'regional', "
                "'us-east-1', :source_resource_id, :source_snapshot_id, 'stable', 'aws', "
                "'210987654321', 'ec2', 'security_group', 'sg-external', 'regional', "
                "'us-east-1', :target_resource_id, :target_snapshot_id, NULL, :outcome_id, "
                "'MigrationTestCollector', '1.0.0', 'aws-api', 'ec2:GetEvidence', "
                ":evidence_reference, :collected_at, '1.0.0')"
            ),
            {
                "observation_id": observation_id.hex,
                "relationship_id": relationship_id.hex,
                "scan_id": scan_id.hex,
                "source_resource_id": source_resource_id.hex,
                "source_snapshot_id": source_snapshot_id.hex,
                "target_resource_id": target_resource_id.hex,
                "target_snapshot_id": target_snapshot_id.hex,
                "outcome_id": outcome_id.hex,
                "evidence_reference": evidence_reference,
                "collected_at": collected_at,
            },
        )
        _insert_snapshot(
            connection,
            scan_id=scan_id,
            resource_id=source_resource_id,
            snapshot_id=source_snapshot_id,
            scope="regional",
            region="us-east-1",
        )
        _insert_snapshot(
            connection,
            scan_id=scan_id,
            resource_id=target_resource_id,
            snapshot_id=target_snapshot_id,
            scope="regional",
            region="us-east-1",
        )

    with migrated_engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM resource_snapshots")) == 2


def test_snapshot_guard_accepts_exact_supplemental_region_source(
    migrated_engine: Engine,
) -> None:
    scan_id = _create_pending_scan(
        migrated_engine,
        fail=False,
        aws_account_id="123456789012",
        inventory_sha256="f" * 64,
    )
    resource_id, snapshot_id = uuid4(), uuid4()
    with migrated_engine.begin() as connection:
        _insert_present_resource_source(
            connection,
            scan_id=scan_id,
            outcome_id=uuid4(),
            artifact_id=uuid4(),
            resource_id=resource_id,
            snapshot_id=snapshot_id,
            owner_id="123456789012",
            service="ec2",
            resource_type="ec2_instance",
            aws_resource_id="i-supplemental",
            scope="regional",
            region="us-west-2",
            owner_mode="COLLECTION_ACCOUNT",
            allows_supplemental_region=True,
        )
        _insert_snapshot(
            connection,
            scan_id=scan_id,
            resource_id=resource_id,
            snapshot_id=snapshot_id,
            scope="regional",
            region="us-west-2",
        )
    with migrated_engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM resource_snapshots")) == 1


def test_snapshot_guard_does_not_inherit_supplemental_region_from_another_resource(
    migrated_engine: Engine,
) -> None:
    scan_id = _create_pending_scan(
        migrated_engine,
        fail=False,
        aws_account_id="123456789012",
        inventory_sha256="f" * 64,
    )
    proven_resource_id, proven_snapshot_id = uuid4(), uuid4()
    unproven_resource_id, unproven_snapshot_id = uuid4(), uuid4()
    with pytest.raises(IntegrityError, match="owner or scope"):
        with migrated_engine.begin() as connection:
            _insert_present_resource_source(
                connection,
                scan_id=scan_id,
                outcome_id=uuid4(),
                artifact_id=uuid4(),
                resource_id=proven_resource_id,
                snapshot_id=proven_snapshot_id,
                owner_id="123456789012",
                service="ec2",
                resource_type="ec2_instance",
                aws_resource_id="i-proven",
                scope="regional",
                region="us-west-2",
                owner_mode="COLLECTION_ACCOUNT",
                allows_supplemental_region=True,
            )
            _insert_snapshot(
                connection,
                scan_id=scan_id,
                resource_id=proven_resource_id,
                snapshot_id=proven_snapshot_id,
                scope="regional",
                region="us-west-2",
            )
            connection.execute(
                text(
                    "INSERT INTO resources (resource_id, provider, aws_account_id, "
                    "aws_resource_id, arn, service, resource_type, scope, region) VALUES ("
                    ":resource_id, 'aws', '123456789012', 'i-unproven', NULL, 'ec2', "
                    "'ec2_instance', 'regional', 'us-west-2')"
                ),
                {"resource_id": unproven_resource_id.hex},
            )
            _insert_snapshot(
                connection,
                scan_id=scan_id,
                resource_id=unproven_resource_id,
                snapshot_id=unproven_snapshot_id,
                scope="regional",
                region="us-west-2",
            )

    with migrated_engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM resource_snapshots")) == 0


def test_evidence_graph_downgrade_cannot_be_generated_offline(
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"

    with pytest.raises(CommandError, match="Offline downgrade blocked before revision 20260915"):
        command.downgrade(
            config,
            f"20260915_0003:{_PENDING_SCAN_REVISION}",
            sql=True,
        )

    captured = capsys.readouterr()
    assert "DROP TABLE" not in captured.out
    assert "DROP TABLE" not in captured.err


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
