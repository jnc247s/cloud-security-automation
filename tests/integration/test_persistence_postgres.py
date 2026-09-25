"""PostgreSQL migration, integrity, and concurrency checks in isolated test schemas."""

import base64
import hashlib
import json
import os
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event
from time import monotonic
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import pytest
from alembic import command
from alembic.config import Config
from alembic.util import CommandError
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, inspect, select, text, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app import __version__
from app.assessment.controls import build_default_control_catalog
from app.assessment.models import AssessmentResult
from app.assessment.profiles import create_default_assessment_profile
from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.config import Settings, get_settings
from app.database import session as database_session
from app.database.evidence_graph import load_evidence_graph
from app.database.persistence import fail_pending_scan, persist_scan_result
from app.main import create_app
from app.models import (
    AuditEvent,
    Control,
    ControlAssessment,
    EvidenceArtifact,
    Finding,
    FindingOccurrence,
    PersistedAssessmentProfile,
    Resource,
    ResourceRelationshipObservation,
    ResourceSnapshot,
    Scan,
    ScanScopeManifest,
    SourceEvidenceArtifact,
)
from app.models.enums import AuditEventType, FindingStatus, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.scan import ScanCreateRequest
from app.security.authentication import DEVELOPMENT_BEARER_MARKER
from app.services.errors import AssessmentProfileConflictError
from app.services.evidence_graph_service import EvidenceGraphService
from app.services.inventory_service import InventoryService
from app.services.scan_executor import InProcessScanExecutor, _scope_for
from app.services.scan_service import ScanService
from tests.fakes import (
    FakeAWSClient,
    FakeClientProvider,
    FakePaginator,
    empty_access_analyzer_client,
    empty_ec2_client,
    empty_iam_client,
)
from tests.unit.database.factories import (
    exceptional_owner_graph_scan_bundle,
    graph_scan_bundle,
    scaled_graph_scan_bundle,
    scan_bundle,
)

pytestmark = pytest.mark.integration

_CURRENT_REVISION = "20260924_0004"
_PENDING_SCAN_REVISION = "20260904_0002"
_PREVIOUS_REVISION = "20260903_0001"
_COMPLETED_IDENTITY_CONSTRAINT = "ck_scans_completed_evidence_identity_present"


class _RecordingExecutor:
    def __init__(self) -> None:
        self.scan_ids: list[UUID] = []

    def submit(self, scan_id: UUID) -> None:
        self.scan_ids.append(scan_id)

    def resume_pending(self) -> int:
        return 0

    def shutdown(self, *, wait: bool = True) -> None:
        del wait


class _CollectionGatePaginator(FakePaginator):
    """Hold one fake AWS call until the HTTP request has returned."""

    def __init__(self, pages, *, entered: Event, release: Event) -> None:
        super().__init__(pages)
        self._entered = entered
        self._release = release

    def paginate(self, **kwargs):
        self.calls.append(kwargs)
        self._entered.set()
        if not self._release.wait(timeout=30):
            raise AssertionError("acceptance-test AWS gate was not released")
        yield from self.pages


def _scan_settings(postgres_engine: Engine, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "app_env": "test",
        "auth_mode": "development",
        "database_url": str(postgres_engine.url),
        "aws_region": "us-east-1",
    }
    values.update(overrides)
    return Settings(
        _env_file=None,
        **values,
    )


def _empty_provider(region: str = "us-east-1") -> FakeClientProvider:
    return FakeClientProvider(
        {
            ("accessanalyzer", region): empty_access_analyzer_client(),
            ("ec2", region): empty_ec2_client(),
            ("s3", region): FakeAWSClient(
                paginators={"list_buckets": FakePaginator([{"Buckets": []}])}
            ),
            ("s3control", region): FakeAWSClient(
                responses={
                    "get_public_access_block": [
                        {
                            "PublicAccessBlockConfiguration": {
                                "BlockPublicAcls": True,
                                "IgnorePublicAcls": True,
                                "BlockPublicPolicy": True,
                                "RestrictPublicBuckets": True,
                            }
                        }
                    ]
                }
            ),
            ("iam", region): empty_iam_client(),
            ("cloudtrail", region): FakeAWSClient(
                paginators={"list_trails": FakePaginator([{"Trails": []}])}
            ),
        },
        region_name=region,
    )


def _iam_acceptance_client() -> tuple[FakeAWSClient, dict[str, FakePaginator]]:
    """Build complete deterministic global IAM evidence for the HTTP acceptance path."""

    account_id = "123456789012"
    created_at = datetime(2024, 1, 1, tzinfo=UTC)
    local_policy_arn = f"arn:aws:iam::{account_id}:policy/Admin"
    aws_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    user = {
        "Path": "/engineering/",
        "UserName": "alice",
        "UserId": "AIDAACCEPTANCEALICE",
        "Arn": f"arn:aws:iam::{account_id}:user/engineering/alice",
        "CreateDate": created_at,
    }
    group = {
        "Path": "/",
        "GroupName": "admins",
        "GroupId": "AGPAACCEPTANCEADMINS",
        "Arn": f"arn:aws:iam::{account_id}:group/admins",
        "CreateDate": created_at,
    }
    role = {
        "Path": "/",
        "RoleName": "reader",
        "RoleId": "AROAACCEPTANCEREADER",
        "Arn": f"arn:aws:iam::{account_id}:role/reader",
        "CreateDate": created_at,
        "MaxSessionDuration": 3600,
    }
    local_policy = {
        "PolicyName": "Admin",
        "PolicyId": "ANPAACCEPTANCELOCAL",
        "Arn": local_policy_arn,
        "Path": "/",
        "DefaultVersionId": "v1",
        "IsAttachable": True,
        "AttachmentCount": 2,
        "PermissionsBoundaryUsageCount": 1,
    }
    allow_document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    trust_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    paginators = {
        "list_users": FakePaginator([{"Users": [user]}]),
        "list_groups": FakePaginator([{"Groups": [group]}]),
        "list_roles": FakePaginator([{"Roles": [role]}]),
        "list_policies": FakePaginator([{"Policies": [local_policy]}]),
        "list_user_tags": FakePaginator([{"Tags": [{"Key": "Owner", "Value": "security"}]}]),
        "list_mfa_devices": FakePaginator(
            [
                {
                    "MFADevices": [
                        {
                            "UserName": "alice",
                            "SerialNumber": f"arn:aws:iam::{account_id}:mfa/alice",
                            "EnableDate": created_at,
                        }
                    ]
                }
            ]
        ),
        "list_access_keys": FakePaginator(
            [
                {
                    "AccessKeyMetadata": [
                        {
                            "UserName": "alice",
                            "AccessKeyId": "AKIAEXAMPLEONLY",
                            "Status": "Active",
                            "CreateDate": created_at,
                        }
                    ]
                }
            ]
        ),
        "list_attached_user_policies": FakePaginator(
            [
                {
                    "AttachedPolicies": [
                        {"PolicyName": "Admin", "PolicyArn": local_policy_arn},
                        {"PolicyName": "ReadOnlyAccess", "PolicyArn": aws_policy_arn},
                    ]
                }
            ]
        ),
        "list_user_policies": FakePaginator([{"PolicyNames": ["Emergency"]}]),
        "get_group": FakePaginator([{"Group": group, "Users": [user]}]),
        "list_attached_group_policies": FakePaginator([{"AttachedPolicies": []}]),
        "list_group_policies": FakePaginator([{"PolicyNames": []}]),
        "list_role_tags": FakePaginator([{"Tags": [{"Key": "Owner", "Value": "platform"}]}]),
        "list_attached_role_policies": FakePaginator(
            [{"AttachedPolicies": [{"PolicyName": "Admin", "PolicyArn": local_policy_arn}]}]
        ),
        "list_role_policies": FakePaginator([{"PolicyNames": ["Emergency"]}]),
        "list_policy_tags": FakePaginator([{"Tags": [{"Key": "Owner", "Value": "security"}]}]),
    }
    client = FakeAWSClient(
        paginators=paginators,
        responses={
            "get_account_summary": [
                {
                    "SummaryMap": {
                        "AccountAccessKeysPresent": 0,
                        "AccountMFAEnabled": 1,
                    }
                }
            ],
            "get_access_key_last_used": [
                {
                    "UserName": "alice",
                    "AccessKeyLastUsed": {"ServiceName": "N/A", "Region": "N/A"},
                }
            ],
            "get_user": [
                {
                    "User": {
                        **user,
                        "PermissionsBoundary": {
                            "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                            "PermissionsBoundaryArn": aws_policy_arn,
                        },
                    }
                }
            ],
            "get_user_policy": [
                {
                    "UserName": "alice",
                    "PolicyName": "Emergency",
                    "PolicyDocument": allow_document,
                }
            ],
            "get_role": [
                {
                    "Role": {
                        **role,
                        "AssumeRolePolicyDocument": trust_document,
                        "PermissionsBoundary": {
                            "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                            "PermissionsBoundaryArn": local_policy_arn,
                        },
                    }
                }
            ],
            "get_role_policy": [
                {
                    "RoleName": "reader",
                    "PolicyName": "Emergency",
                    "PolicyDocument": allow_document,
                }
            ],
            "get_policy": [
                {"Policy": local_policy},
                {
                    "Policy": {
                        "PolicyName": "ReadOnlyAccess",
                        "PolicyId": "ANPAAWSMANAGED",
                        "Arn": aws_policy_arn,
                        "Path": "/",
                        "DefaultVersionId": "v5",
                        "IsAttachable": True,
                    }
                },
            ],
            "get_policy_version": [
                {
                    "PolicyVersion": {
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                        "CreateDate": created_at,
                        "Document": allow_document,
                    }
                },
                {
                    "PolicyVersion": {
                        "VersionId": "v5",
                        "IsDefaultVersion": True,
                        "CreateDate": created_at,
                        "Document": allow_document,
                    }
                },
            ],
        },
    )
    return client, paginators


def migration_config(connection) -> Config:
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    config.attributes["database_url"] = str(connection.engine.url)
    config.attributes["connection"] = connection
    return config


def _postgres_migration_state(engine: Engine) -> dict:
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
                        "SELECT tgname, pg_get_triggerdef(oid) "
                        "FROM pg_trigger "
                        "WHERE tgrelid = CAST('scans' AS regclass) AND NOT tgisinternal "
                        "ORDER BY tgname"
                    )
                )
            ),
        }


@pytest.fixture
def postgres_engine() -> Iterator[Engine]:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.fail("TEST_DATABASE_URL must use PostgreSQL")
    # Only this generated schema is created/dropped. Existing schemas and data are untouched.
    schema = "sprint4_test_" + uuid4().hex
    admin_engine = create_engine(database_url, connect_args={"connect_timeout": 5})
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(
        database_url,
        connect_args={"connect_timeout": 5, "options": f"-csearch_path={schema}"},
        pool_pre_ping=True,
    )
    try:
        with engine.begin() as connection:
            command.upgrade(migration_config(connection), "head")
        yield engine
    finally:
        engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()


@contextmanager
def _count_sql_statements(engine: Engine) -> Iterator[list[str]]:
    statements: list[str] = []

    def observe(_connection, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", observe)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", observe)


@pytest.mark.parametrize("size", [16, 32])
def test_postgres_generic_graph_reads_have_constant_query_counts(
    postgres_engine: Engine, size: int
) -> None:
    bundle = scaled_graph_scan_bundle(
        size, scan_id=uuid5(NAMESPACE_URL, f"https://example.test/postgres-closure/{size}")
    )
    graph = bundle["snapshot"].evidence_graph
    with Session(postgres_engine) as session, session.begin():
        persist_scan_result(session, **bundle)

    relationships = sorted(graph.relationships, key=lambda edge: edge.observation_id)
    outcomes = sorted(graph.source_outcomes, key=lambda outcome: outcome.source_outcome_id)
    artifacts = {artifact.evidence_reference: artifact for artifact in graph.artifacts}
    for limit in (1, 8, 16):
        # Each measured operation starts with a cold identity map. Count through
        # projection serialization too, so lazy/N+1 loads cannot escape the gate.
        with Session(postgres_engine) as session, _count_sql_statements(postgres_engine) as sql:
            page = EvidenceGraphService(session).list_relationships(
                scan_id=graph.scan_id,
                collection_account_id=graph.collection_account_id,
                limit=limit,
                offset=1,
            )
            document = page.model_dump(mode="json")
        assert len(sql) == 2, f"relationship list used {len(sql)} statements at size={size}"
        assert document["total"] == size
        assert [item.observation_id for item in page.items] == [
            edge.observation_id for edge in relationships[1 : 1 + limit]
        ]

        for contract_key in (None, "closure.ec2_instance"):
            expected = [
                outcome
                for outcome in outcomes
                if contract_key is None or outcome.evidence_kind == contract_key
            ]
            with (
                Session(postgres_engine) as session,
                _count_sql_statements(postgres_engine) as sql,
            ):
                page = EvidenceGraphService(session).list_source_outcomes(
                    scan_id=graph.scan_id,
                    collection_account_id=graph.collection_account_id,
                    contract_key=contract_key,
                    limit=limit,
                    offset=1,
                )
                document = page.model_dump(mode="json")
            assert len(sql) == 2, f"source list used {len(sql)} statements at size={size}"
            assert document["total"] == len(expected)
            assert [item.source_outcome_id for item in page.items] == [
                outcome.source_outcome_id for outcome in expected[1 : 1 + limit]
            ]

    for edge in (relationships[0], relationships[-1]):
        with Session(postgres_engine) as session, _count_sql_statements(postgres_engine) as sql:
            detail = EvidenceGraphService(session).get_relationship(edge.observation_id)
            detail.model_dump(mode="json")
        assert len(sql) == 1, f"relationship detail used {len(sql)} statements at size={size}"
        assert detail.observation_id == edge.observation_id
        assert detail.source.stable_resource_id == edge.source.stable_resource_id
        assert detail.target.resource_snapshot_id == edge.target.resource_snapshot_id

    for outcome in (outcomes[0], outcomes[-1]):
        with Session(postgres_engine) as session, _count_sql_statements(postgres_engine) as sql:
            detail = EvidenceGraphService(session).get_source_outcome(outcome.source_outcome_id)
            detail.model_dump(mode="json")
        assert len(sql) == 2, f"source detail used {len(sql)} statements at size={size}"
        assert detail.source_outcome_id == outcome.source_outcome_id
        assert detail.artifact.artifact_id == artifacts[outcome.evidence_reference].artifact_id
        assert detail.artifact.evidence_sha256 == outcome.evidence_sha256


def test_postgres_migration_round_trip_and_jsonb(postgres_engine: Engine) -> None:
    with postgres_engine.begin() as connection:
        config = migration_config(connection)
        command.check(config)
        columns = {
            column["name"]: column
            for column in inspect(connection).get_columns("resource_snapshots")
        }
        assert isinstance(columns["normalized_configuration"]["type"], JSONB)
        assert isinstance(columns["tags"]["type"], JSONB)
        source_columns = {
            column["name"]: column
            for column in inspect(connection).get_columns(SourceEvidenceArtifact.__tablename__)
        }
        assert isinstance(source_columns["normalized_payload"]["type"], JSONB)
        command.downgrade(config, "base")
        assert inspect(connection).get_table_names() == ["alembic_version"]
        command.upgrade(config, "head")
        command.check(config)


def test_postgres_pending_scan_downgrade_preserves_compatible_populated_history(
    postgres_engine: Engine,
) -> None:
    bundle = scan_bundle()
    with Session(postgres_engine) as session, session.begin():
        persisted = persist_scan_result(session, **bundle)
        scan_id = persisted.scan_id

    with postgres_engine.begin() as connection:
        command.downgrade(migration_config(connection), _PENDING_SCAN_REVISION)
    before = _postgres_migration_state(postgres_engine)
    assert before["scan_rows"][0]["aws_account_id"] is not None
    assert before["scan_rows"][0]["inventory_sha256"] is not None
    with postgres_engine.begin() as connection:
        command.downgrade(migration_config(connection), _PREVIOUS_REVISION)
    after = _postgres_migration_state(postgres_engine)

    assert before["revision"] == _PENDING_SCAN_REVISION
    assert after["revision"] == _PREVIOUS_REVISION
    assert after["scan_columns"]["aws_account_id"] is False
    assert after["scan_columns"]["inventory_sha256"] is False
    assert _COMPLETED_IDENTITY_CONSTRAINT not in {name for name, _ in after["scan_constraints"]}
    assert after["scan_rows"] == before["scan_rows"]
    assert after["table_counts"] == before["table_counts"]
    assert after["scan_triggers"] == before["scan_triggers"]
    assert len(after["scan_rows"]) == 1
    assert after["scan_rows"][0]["scan_id"] == scan_id


@pytest.mark.parametrize(
    ("status", "aws_account_id", "inventory_sha256", "target_revision"),
    (
        (ScanStatus.RUNNING, None, None, "base"),
        (ScanStatus.FAILED, None, None, _PREVIOUS_REVISION),
        (ScanStatus.RUNNING, "123456789012", None, _PREVIOUS_REVISION),
        (ScanStatus.RUNNING, None, "f" * 64, _PREVIOUS_REVISION),
    ),
    ids=(
        "running-both-missing",
        "failed-both-missing",
        "running-digest-missing",
        "running-account-missing",
    ),
)
def test_postgres_pending_scan_downgrade_blocks_incompatible_history_without_changes(
    postgres_engine: Engine,
    status: ScanStatus,
    aws_account_id: str | None,
    inventory_sha256: str | None,
    target_revision: str,
) -> None:
    settings = _scan_settings(postgres_engine)
    with Session(postgres_engine, expire_on_commit=False) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(),
            _RecordingExecutor(),
            actor_id="migration-test-admin",
        )
        if aws_account_id is not None or inventory_sha256 is not None:
            scan = session.get(Scan, pending.scan_id)
            assert scan is not None
            scan.aws_account_id = aws_account_id
            scan.inventory_sha256 = inventory_sha256
            session.commit()
        if status is ScanStatus.FAILED:
            fail_pending_scan(
                session,
                scan_id=pending.scan_id,
                completed_at=datetime.now(UTC),
                failure_code="AWS_IDENTITY_UNAVAILABLE",
                failure_message="AWS identity could not be verified.",
            )
            session.commit()

    before = _postgres_migration_state(postgres_engine)
    assert before["scan_rows"][0]["aws_account_id"] == aws_account_id
    assert before["scan_rows"][0]["inventory_sha256"] == inventory_sha256
    with pytest.raises(CommandError, match="Downgrade blocked before revision") as error:
        with postgres_engine.begin() as connection:
            command.downgrade(migration_config(connection), target_revision)

    after = _postgres_migration_state(postgres_engine)
    assert after == before
    assert after["revision"] == _CURRENT_REVISION
    assert after["scan_columns"]["aws_account_id"] is True
    assert after["scan_columns"]["inventory_sha256"] is True
    assert _COMPLETED_IDENTITY_CONSTRAINT in {name for name, _ in after["scan_constraints"]}
    assert after["scan_rows"][0]["status"] == status.value
    error_message = str(error.value)
    assert "No schema or data changes were applied" in error_message
    assert "docs/operations/known-limitations.md" in error_message
    assert str(pending.scan_id) not in error_message
    assert pending.scan_id.hex not in error_message

    with postgres_engine.begin() as connection:
        command.check(migration_config(connection))


def test_postgres_evidence_graph_round_trip_is_immutable_and_blocks_lossy_downgrade(
    postgres_engine: Engine,
) -> None:
    bundle = graph_scan_bundle(
        observed_at=datetime(2026, 9, 15, 7, tzinfo=timezone(timedelta(hours=-5)))
    )
    expected_graph = bundle["snapshot"].evidence_graph
    assert expected_graph is not None
    scan_id = bundle["snapshot"].scan_id

    with Session(postgres_engine) as session, session.begin():
        persist_scan_result(session, **bundle)

    retry = graph_scan_bundle(
        observed_at=bundle["snapshot"].collected_at.astimezone(UTC),
        scan_id=scan_id,
    )
    retry["started_at"] = bundle["started_at"]
    retry["completed_at"] = bundle["completed_at"]
    with Session(postgres_engine) as session, session.begin():
        assert persist_scan_result(session, **retry).scan_id == scan_id

    before = _postgres_migration_state(postgres_engine)
    with Session(postgres_engine) as session:
        assert load_evidence_graph(session, scan_id) == expected_graph
        assert (
            session.scalar(select(func.count()).select_from(ResourceRelationshipObservation)) == 1
        )
        with pytest.raises(IntegrityError, match="historical records are immutable"):
            session.execute(
                update(ResourceRelationshipObservation).values(schema_version="rewritten")
            )
        session.rollback()
        assert load_evidence_graph(session, scan_id) == expected_graph
        with pytest.raises(IntegrityError, match="historical records are immutable"):
            session.execute(
                update(ScanScopeManifest)
                .where(ScanScopeManifest.scan_id == scan_id)
                .values(source_manifest_checksum="0" * 64)
            )
        session.rollback()
        assert load_evidence_graph(session, scan_id) == expected_graph

    with pytest.raises(CommandError, match="Downgrade blocked before revision") as error:
        with postgres_engine.begin() as connection:
            command.downgrade(migration_config(connection), _PENDING_SCAN_REVISION)

    after = _postgres_migration_state(postgres_engine)
    assert after == before
    assert after["revision"] == _CURRENT_REVISION
    error_message = str(error.value)
    assert "No schema or data changes were applied" in error_message
    assert "docs/operations/known-limitations.md" in error_message
    assert str(scan_id) not in error_message
    assert scan_id.hex not in error_message

    with Session(postgres_engine) as session:
        assert load_evidence_graph(session, scan_id) == expected_graph
    with postgres_engine.begin() as connection:
        command.check(migration_config(connection))


def test_postgres_evidence_graph_writer_completes_before_downgrade_preflight(
    postgres_engine: Engine,
) -> None:
    bundle = graph_scan_bundle()
    scan_id = bundle["snapshot"].scan_id
    graph_inserted = Event()
    release_writer = Event()
    downgrade_lock_attempted = Event()

    def write_graph() -> None:
        with postgres_engine.connect() as connection:

            @event.listens_for(connection, "after_cursor_execute")
            def pause_after_graph_insert(
                _connection,
                _cursor,
                statement,
                _parameters,
                _context,
                _executemany,
            ) -> None:
                if (
                    "INSERT INTO resource_relationship_observations" in statement
                    and not graph_inserted.is_set()
                ):
                    graph_inserted.set()
                    if not release_writer.wait(timeout=15):
                        raise AssertionError("downgrade test did not release the graph writer")

            with Session(connection) as session, session.begin():
                persist_scan_result(session, **bundle)

    def downgrade_graph() -> None:
        with postgres_engine.begin() as connection:

            @event.listens_for(connection, "before_cursor_execute")
            def observe_downgrade_lock(
                _connection,
                _cursor,
                statement,
                _parameters,
                _context,
                _executemany,
            ) -> None:
                if statement.startswith("LOCK TABLE scans, scan_scope_manifests"):
                    downgrade_lock_attempted.set()

            command.downgrade(migration_config(connection), _PENDING_SCAN_REVISION)

    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(write_graph)
        assert graph_inserted.wait(timeout=10), "graph writer did not reach relationship insert"
        downgrade = pool.submit(downgrade_graph)
        try:
            assert downgrade_lock_attempted.wait(timeout=10), "downgrade did not attempt its lock"
            assert not downgrade.done(), "downgrade lock did not wait for the active graph writer"
        finally:
            release_writer.set()
        writer.result(timeout=15)
        with pytest.raises(CommandError, match="retained source-evidence"):
            downgrade.result(timeout=15)

    with postgres_engine.begin() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == (
            _CURRENT_REVISION
        )
        command.check(migration_config(connection))
    with Session(postgres_engine) as session:
        assert load_evidence_graph(session, scan_id) == bundle["snapshot"].evidence_graph


@pytest.mark.parametrize(
    "scenario",
    ("aws-managed", "external-owner", "supplemental-region"),
)
def test_postgres_accepts_only_explicit_exceptional_owner_and_scope_provenance(
    postgres_engine: Engine,
    scenario: str,
) -> None:
    bundle = exceptional_owner_graph_scan_bundle(scenario)
    expected_graph = bundle["snapshot"].evidence_graph
    assert expected_graph is not None
    scan_id = bundle["snapshot"].scan_id

    with Session(postgres_engine) as session, session.begin():
        persist_scan_result(session, **bundle)

    with Session(postgres_engine) as session:
        assert load_evidence_graph(session, scan_id) == expected_graph
        owners = set(
            session.scalars(
                select(Resource.aws_account_id).where(Resource.snapshots.any(scan_id=scan_id))
            )
        )
    if scenario == "aws-managed":
        assert "aws" in owners
    elif scenario == "external-owner":
        assert "210987654321" in owners
    else:
        assert any(resource.region == "us-west-2" for resource in bundle["snapshot"].resources)


def test_postgres_history_and_append_only_audit(postgres_engine: Engine) -> None:
    bundle = scan_bundle()
    with Session(postgres_engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with Session(postgres_engine) as session:
        observed = session.scalar(select(ResourceSnapshot.observed_at))
        assert observed.tzinfo is not None
        assert observed == bundle["snapshot"].collected_at
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 3
        with pytest.raises(IntegrityError, match="immutable"):
            session.execute(update(AuditEvent).values(actor_id="rewritten"))
        session.rollback()
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 3


def test_postgres_finalizes_a_committed_pending_scan(postgres_engine: Engine) -> None:
    """Exercise the Sprint 4 pre-created RUNNING row against PostgreSQL guards."""

    settings = _scan_settings(postgres_engine)
    executor = _RecordingExecutor()
    with Session(postgres_engine, expire_on_commit=False) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(),
            executor,
            actor_id="integration-admin",
        )
    assert executor.scan_ids == [pending.scan_id]

    snapshot = InventoryService(_empty_provider()).collect(scan_id=pending.scan_id)
    collected_at = snapshot.collected_at
    profile = create_default_assessment_profile(
        version=settings.assessment_profile_version,
        required_tags=settings.required_tag_names,
        stale_key_days=settings.stale_access_key_days,
    )
    catalog = build_default_control_catalog()
    assessments = RuleEngine(build_default_registry()).assess(snapshot, profile)
    scope = _scope_for(snapshot, profile, catalog)

    with Session(postgres_engine) as session, session.begin():
        scan = session.get(Scan, pending.scan_id)
        assert scan is not None
        persist_scan_result(
            session,
            snapshot=snapshot,
            scope=scope,
            profile=profile,
            catalog=catalog,
            assessments=assessments,
            started_at=scan.started_at,
            completed_at=collected_at + timedelta(seconds=1),
            scanner_version=__version__,
            actor_type="system",
            actor_id="scan-executor",
        )

    with Session(postgres_engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan is not None
        assert scan.status is ScanStatus.COMPLETED
        assert scan.aws_account_id == "123456789012"
        assert scan.inventory_sha256 is not None
        assert scan.result_checksum is not None
        assert scan.scope_manifest is not None
        event_types = tuple(
            session.scalars(
                select(AuditEvent.event_type)
                .where(AuditEvent.target_type == "scan", AuditEvent.target_id == pending.scan_id)
                .order_by(AuditEvent.timestamp)
            )
        )
        assert event_types == (AuditEventType.SCAN_STARTED, AuditEventType.SCAN_COMPLETED)


def test_postgres_profile_roll_forward_and_restart_preserve_exact_provenance(
    postgres_engine: Engine,
) -> None:
    original_settings = _scan_settings(
        postgres_engine,
        assessment_profile_version="1.0.0",
        required_tags="Owner",
        stale_access_key_days=45,
    )
    recorder = _RecordingExecutor()
    with Session(postgres_engine, expire_on_commit=False) as session:
        original = ScanService(session, original_settings).start_scan(
            ScanCreateRequest(), recorder, actor_id="integration-admin"
        )
        repeated = ScanService(session, original_settings).start_scan(
            ScanCreateRequest(), recorder, actor_id="integration-admin"
        )
    assert recorder.scan_ids == [original.scan_id, repeated.scan_id]
    assert original.assessment_profile_checksum == repeated.assessment_profile_checksum

    restarted_settings = _scan_settings(
        postgres_engine,
        assessment_profile_version="1.1.0",
        required_tags="DataClassification",
        stale_access_key_days=120,
    )
    session_factory = sessionmaker(bind=postgres_engine, expire_on_commit=False)
    restarted_executor = InProcessScanExecutor(
        session_factory=session_factory,
        settings=restarted_settings,
        provider_factory=lambda region: _empty_provider(region),
        max_workers=1,
        max_outstanding=2,
    )
    try:
        assert restarted_executor.resume_pending() == 2
    finally:
        restarted_executor.shutdown(wait=True)

    with Session(postgres_engine) as session:
        stored_profiles = tuple(session.scalars(select(PersistedAssessmentProfile)))
        assert len(stored_profiles) == 1
        original_profile = stored_profiles[0]
        assert original_profile.version == "1.0.0"
        assert original_profile.required_tags == ["Owner"]
        assert original_profile.stale_key_days == 45
        for scan_id in (original.scan_id, repeated.scan_id):
            scan = session.get(Scan, scan_id)
            assert scan is not None
            assert scan.status is ScanStatus.COMPLETED
            assert scan.assessment_profile_version == "1.0.0"
            assert scan.assessment_profile_checksum == original_profile.content_checksum
            assert scan.scope_manifest is not None
            assert scan.scope_manifest.assessment_profile_version == "1.0.0"
            profile_ids = set(
                session.scalars(
                    select(ControlAssessment.assessment_profile_version_id).where(
                        ControlAssessment.scan_id == scan_id
                    )
                )
            )
            assert profile_ids == {original_profile.profile_version_id}

    conflicting_settings = _scan_settings(
        postgres_engine,
        assessment_profile_version="1.0.0",
        required_tags="DataClassification",
        stale_access_key_days=120,
    )
    with Session(postgres_engine) as session:
        with pytest.raises(AssessmentProfileConflictError):
            ScanService(session, conflicting_settings).start_scan(
                ScanCreateRequest(), _RecordingExecutor(), actor_id="integration-admin"
            )
        assert session.scalar(select(func.count()).select_from(Scan)) == 2
        assert session.scalar(select(func.count()).select_from(PersistedAssessmentProfile)) == 1

    with Session(postgres_engine, expire_on_commit=False) as session:
        replacement = ScanService(session, restarted_settings).start_scan(
            ScanCreateRequest(), _RecordingExecutor(), actor_id="integration-admin"
        )
    replacement_executor = InProcessScanExecutor(
        session_factory=session_factory,
        settings=restarted_settings,
        provider_factory=lambda region: _empty_provider(region),
        max_workers=1,
        max_outstanding=1,
    )
    try:
        replacement_executor._execute(replacement.scan_id)
    finally:
        replacement_executor.shutdown(wait=True)

    with Session(postgres_engine) as session:
        profiles = {
            profile.version: profile
            for profile in session.scalars(
                select(PersistedAssessmentProfile).order_by(PersistedAssessmentProfile.version)
            )
        }
        assert set(profiles) == {"1.0.0", "1.1.0"}
        assert profiles["1.0.0"].required_tags == ["Owner"]
        assert profiles["1.1.0"].required_tags == ["DataClassification"]
        assert profiles["1.0.0"].content_checksum != profiles["1.1.0"].content_checksum
        for original_scan_id in (original.scan_id, repeated.scan_id):
            historical_scan = session.get(Scan, original_scan_id)
            assert historical_scan is not None
            assert historical_scan.assessment_profile_version == "1.0.0"
            historical_profile_ids = set(
                session.scalars(
                    select(ControlAssessment.assessment_profile_version_id).where(
                        ControlAssessment.scan_id == original_scan_id
                    )
                )
            )
            assert historical_profile_ids == {profiles["1.0.0"].profile_version_id}
        new_scan = session.get(Scan, replacement.scan_id)
        assert new_scan is not None
        assert new_scan.status is ScanStatus.COMPLETED
        assert new_scan.assessment_profile_version == "1.1.0"
        assert new_scan.assessment_profile_checksum == profiles["1.1.0"].content_checksum
        new_assessment_profile_ids = set(
            session.scalars(
                select(ControlAssessment.assessment_profile_version_id).where(
                    ControlAssessment.scan_id == replacement.scan_id
                )
            )
        )
        assert new_assessment_profile_ids == {profiles["1.1.0"].profile_version_id}


def test_postgres_allows_bounded_failure_before_aws_identity(postgres_engine: Engine) -> None:
    settings = _scan_settings(postgres_engine)
    with Session(postgres_engine, expire_on_commit=False) as session:
        pending = ScanService(session, settings).start_scan(
            ScanCreateRequest(),
            _RecordingExecutor(),
            actor_id="integration-admin",
        )
        fail_pending_scan(
            session,
            scan_id=pending.scan_id,
            completed_at=datetime.now(UTC),
            failure_code="AWS_IDENTITY_UNAVAILABLE",
            failure_message="AWS identity could not be verified.",
        )
        session.commit()

    with Session(postgres_engine) as session:
        scan = session.get(Scan, pending.scan_id)
        assert scan is not None
        assert scan.status is ScanStatus.FAILED
        assert scan.aws_account_id is None
        assert scan.inventory_sha256 is None
        assert scan.result_checksum is not None
        failure_event = session.scalar(
            select(AuditEvent).where(
                AuditEvent.target_id == pending.scan_id,
                AuditEvent.event_type == AuditEventType.SCAN_FAILED,
            )
        )
        assert failure_event is not None
        assert failure_event.event_metadata["failure_code"] == "AWS_IDENTITY_UNAVAILABLE"


def test_postgres_concurrent_failures_deduplicate_without_losing_occurrences(
    postgres_engine: Engine,
) -> None:
    first = scan_bundle()
    second = scan_bundle(observed_at=first["snapshot"].collected_at + timedelta(minutes=1))
    barrier = Barrier(2)

    def write(bundle) -> None:
        with Session(postgres_engine) as session, session.begin():
            barrier.wait(timeout=10)
            persist_scan_result(session, **bundle)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(write, bundle) for bundle in (first, second)]
        for future in futures:
            future.result(timeout=30)
    with Session(postgres_engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 2
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        assert session.scalar(select(func.count()).select_from(FindingOccurrence)) == 2


def test_postgres_concurrent_identical_scan_retry_is_idempotent(postgres_engine: Engine) -> None:
    bundle = scan_bundle()
    barrier = Barrier(2)

    def write() -> None:
        with Session(postgres_engine) as session, session.begin():
            barrier.wait(timeout=10)
            persist_scan_result(session, **bundle)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(write) for _ in range(2)]
        for future in futures:
            future.result(timeout=30)
    with Session(postgres_engine) as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 1
        assert session.scalar(select(func.count()).select_from(FindingOccurrence)) == 1
        assert session.scalar(select(func.count()).select_from(AuditEvent)) == 3


def _development_settings(
    monkeypatch: pytest.MonkeyPatch,
    postgres_engine: Engine,
    *,
    subject: str,
    role: str,
) -> Settings:
    """Configure the supported development bearer backend for one real identity."""

    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("AUTH_MODE", "development")
    monkeypatch.setenv("DEV_IDENTITY_SUBJECT", subject)
    monkeypatch.setenv("DEV_IDENTITY_ROLES", role)
    monkeypatch.setenv(
        "DATABASE_URL",
        postgres_engine.url.render_as_string(hide_password=False),
    )
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("REQUIRED_TAGS", "Owner,Environment")
    monkeypatch.setenv("STALE_ACCESS_KEY_DAYS", "90")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    get_settings.cache_clear()
    return get_settings()


def _poll_terminal_scan(
    client: TestClient,
    scan_id: UUID,
    headers: dict[str, str],
    *,
    timeout_seconds: float = 20,
) -> dict:
    """Poll the public API to a terminal scan state under a monotonic deadline."""

    deadline = monotonic() + timeout_seconds
    poll_interval = Event()
    attempts = 0
    last_document: dict | None = None
    terminal_states = {"COMPLETED", "FAILED", "PARTIAL"}
    while monotonic() < deadline:
        response = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
        assert response.status_code == 200, response.text
        last_document = response.json()
        attempts += 1
        if last_document["status"] in terminal_states:
            return last_document
        poll_interval.wait(timeout=0.01)

    pytest.fail(
        f"scan {scan_id} did not reach a terminal state within {timeout_seconds}s "
        f"after {attempts} API polls; last response was {last_document}"
    )


@pytest.mark.parametrize("profile_schema", ["legacy", "extended"])
def test_authenticated_http_scan_persists_and_exposes_sprint_0_to_5f_graph(
    postgres_engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    profile_schema: str,
) -> None:
    """Prove the accepted HTTP-to-PostgreSQL scan workflow with only AWS replaced."""

    session_factory = sessionmaker(
        bind=postgres_engine,
        autoflush=False,
        expire_on_commit=False,
    )
    monkeypatch.setattr(database_session, "SessionLocal", session_factory)
    headers = {"Authorization": f"Bearer {DEVELOPMENT_BEARER_MARKER}"}
    if profile_schema == "extended":
        from tests.foundation_fixtures import extended_profile

        profile = extended_profile(version="1.0.0")
        policy_path = tmp_path / "assessment-policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "catalog_id": "aws-cloud-security-controls",
                    "catalog_version": "0.2.1",
                    "profile": profile.model_dump(mode="json"),
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("ASSESSMENT_PROFILE_FILE", str(policy_path))

    try:
        analyst_settings = _development_settings(
            monkeypatch,
            postgres_engine,
            subject="acceptance-analyst",
            role="ANALYST",
        )
        analyst_application = create_app(
            executor_factory=lambda: InProcessScanExecutor(
                session_factory=session_factory,
                settings=analyst_settings,
                provider_factory=lambda region: FakeClientProvider({}, region_name=region),
                max_workers=1,
                max_outstanding=1,
            )
        )
        assert analyst_application.dependency_overrides == {}
        with TestClient(analyst_application) as analyst_client:
            denied = analyst_client.post(
                "/api/v1/scans",
                headers=headers,
                json={"region": "us-east-1"},
            )
        assert denied.status_code == 403
        assert denied.json()["detail"] == {
            "code": "insufficient_capability",
            "message": "The EXECUTE capability is required.",
        }
        with Session(postgres_engine) as session:
            assert session.scalar(select(func.count()).select_from(Scan)) == 0

        admin_settings = _development_settings(
            monkeypatch,
            postgres_engine,
            subject="acceptance-admin",
            role="ADMIN",
        )
        collection_entered = Event()
        collection_release = Event()
        security_group_pages = _CollectionGatePaginator(
            [
                {
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-acceptance-public-ssh",
                            "OwnerId": "123456789012",
                            "GroupName": "acceptance-public-ssh",
                            "Description": "Deterministic offline acceptance fixture",
                            "VpcId": "vpc-acceptance",
                            "IpPermissions": [
                                {
                                    "IpProtocol": "tcp",
                                    "FromPort": 22,
                                    "ToPort": 22,
                                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                    "Ipv6Ranges": [],
                                    "PrefixListIds": [],
                                    "UserIdGroupPairs": [],
                                }
                            ],
                            "IpPermissionsEgress": [],
                            "Tags": [
                                {"Key": "Owner", "Value": "security"},
                                {"Key": "Environment", "Value": "acceptance"},
                            ],
                        }
                    ]
                }
            ],
            entered=collection_entered,
            release=collection_release,
        )
        instance_pages = FakePaginator(
            [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-acceptance",
                                    "InstanceType": "t3.micro",
                                    "State": {"Name": "running"},
                                    "PrivateIpAddress": "10.0.1.10",
                                    "PublicIpAddress": "198.51.100.10",
                                    "VpcId": "vpc-acceptance",
                                    "SubnetId": "subnet-acceptance",
                                    "SecurityGroups": [{"GroupId": "sg-acceptance-public-ssh"}],
                                    "NetworkInterfaces": [
                                        {
                                            "NetworkInterfaceId": "eni-acceptance",
                                            "Groups": [{"GroupId": "sg-acceptance-public-ssh"}],
                                            "Association": {"PublicIp": "198.51.100.10"},
                                            "PrivateIpAddresses": [
                                                {
                                                    "PrivateIpAddress": "10.0.1.10",
                                                    "Association": {"PublicIp": "198.51.100.10"},
                                                }
                                            ],
                                        }
                                    ],
                                    "BlockDeviceMappings": [
                                        {"Ebs": {"VolumeId": "vol-acceptance"}}
                                    ],
                                    "MetadataOptions": {
                                        "State": "applied",
                                        "HttpEndpoint": "enabled",
                                        "HttpTokens": "required",
                                    },
                                    "Tags": [
                                        {"Key": "Owner", "Value": "security"},
                                        {"Key": "Environment", "Value": "acceptance"},
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]
        )
        volume_pages = FakePaginator(
            [
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-acceptance",
                            "State": "in-use",
                            "Encrypted": True,
                            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/test",
                            "Attachments": [
                                {
                                    "InstanceId": "i-acceptance",
                                    "State": "attached",
                                    "Device": "/dev/xvda",
                                    "DeleteOnTermination": True,
                                }
                            ],
                            "Tags": [{"Key": "Owner", "Value": "security"}],
                        }
                    ]
                }
            ]
        )
        vpc_pages = FakePaginator(
            [
                {
                    "Vpcs": [
                        {
                            "VpcId": "vpc-acceptance",
                            "OwnerId": "123456789012",
                            "State": "available",
                            "CidrBlock": "10.0.0.0/16",
                            "DhcpOptionsId": "dopt-acceptance",
                            "InstanceTenancy": "default",
                            "IsDefault": False,
                            "Tags": [
                                {"Key": "Owner", "Value": "security"},
                                {"Key": "Environment", "Value": "acceptance"},
                            ],
                        }
                    ]
                }
            ]
        )
        subnet_pages = FakePaginator(
            [
                {
                    "Subnets": [
                        {
                            "SubnetId": "subnet-acceptance",
                            "SubnetArn": (
                                "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-acceptance"
                            ),
                            "OwnerId": "123456789012",
                            "VpcId": "vpc-acceptance",
                            "State": "available",
                            "CidrBlock": "10.0.1.0/24",
                            "AvailabilityZone": "us-east-1a",
                            "AvailabilityZoneId": "use1-az1",
                            "AvailableIpAddressCount": 250,
                            "MapPublicIpOnLaunch": False,
                            "AssignIpv6AddressOnCreation": False,
                            "DefaultForAz": False,
                            "Ipv6Native": False,
                            "Tags": [{"Key": "Owner", "Value": "security"}],
                        }
                    ]
                }
            ]
        )
        flow_log_pages = FakePaginator(
            [
                {
                    "FlowLogs": [
                        {
                            "FlowLogId": "fl-acceptance",
                            "ResourceId": "vpc-acceptance",
                            "FlowLogStatus": "ACTIVE",
                            "TrafficType": "ALL",
                            "LogDestinationType": "cloud-watch-logs",
                            "LogGroupName": "acceptance-vpc-flow-logs",
                            "LogDestination": (
                                "arn:aws:logs:us-east-1:123456789012:log-group:"
                                "acceptance-vpc-flow-logs"
                            ),
                            "DeliverLogsPermissionArn": (
                                "arn:aws:iam::123456789012:role/flow-log-delivery"
                            ),
                            "DeliverLogsStatus": "SUCCESS",
                            "MaxAggregationInterval": 60,
                            "Tags": [{"Key": "Owner", "Value": "security"}],
                        }
                    ]
                }
            ]
        )
        bucket_name = "acceptance-analyzer-bucket"
        kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/acceptance-key"
        s3_pages = FakePaginator(
            [
                {
                    "Buckets": [
                        {
                            "Name": bucket_name,
                            "CreationDate": datetime(2026, 9, 16, 16, tzinfo=UTC),
                            "BucketRegion": "us-east-1",
                        }
                    ]
                }
            ]
        )
        s3_client = FakeAWSClient(
            paginators={"list_buckets": s3_pages},
            responses={
                "get_bucket_location": [{"LocationConstraint": None}],
                "get_bucket_tagging": [{"TagSet": [{"Key": "Owner", "Value": "security"}]}],
                "get_bucket_encryption": [
                    {
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "aws:kms",
                                        "KMSMasterKeyID": kms_key_arn,
                                    },
                                    "BucketKeyEnabled": True,
                                }
                            ]
                        }
                    }
                ],
                "get_public_access_block": [
                    {
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        }
                    }
                ],
                "get_bucket_policy": [
                    {
                        "Policy": json.dumps(
                            {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "DenyInsecureTransport",
                                        "Effect": "Deny",
                                        "Principal": "*",
                                        "Action": "s3:*",
                                        "Resource": [
                                            f"arn:aws:s3:::{bucket_name}",
                                            f"arn:aws:s3:::{bucket_name}/*",
                                        ],
                                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                                    }
                                ],
                            },
                            separators=(",", ":"),
                        )
                    }
                ],
                "get_bucket_policy_status": [{"PolicyStatus": {"IsPublic": False}}],
                "get_bucket_acl": [
                    {
                        "Owner": {
                            "DisplayName": "acceptance-owner",
                            "ID": "acceptance-canonical-owner-id",
                        },
                        "Grants": [
                            {
                                "Grantee": {
                                    "Type": "CanonicalUser",
                                    "ID": "acceptance-canonical-owner-id",
                                },
                                "Permission": "FULL_CONTROL",
                            }
                        ],
                    }
                ],
                "get_bucket_versioning": [{"Status": "Enabled", "MFADelete": "Disabled"}],
                "get_bucket_ownership_controls": [
                    {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}
                ],
            },
        )
        s3control_client = FakeAWSClient(
            responses={
                "get_public_access_block": [
                    {
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        }
                    }
                ]
            }
        )
        kms_client = FakeAWSClient(
            responses={
                "describe_key": [
                    {
                        "KeyMetadata": {
                            "AWSAccountId": "123456789012",
                            "KeyId": "acceptance-key",
                            "Arn": kms_key_arn,
                            "KeyManager": "CUSTOMER",
                        }
                    }
                ]
            }
        )
        analyzer_name = "acceptance-external-access"
        analyzer_arn = f"arn:aws:access-analyzer:us-east-1:123456789012:analyzer/{analyzer_name}"
        analyzer_finding_id = "acceptance-external-finding"
        analyzer_finding = {
            "analyzedAt": datetime(2026, 9, 16, 16, 5, tzinfo=UTC),
            "createdAt": datetime(2026, 9, 16, 16, tzinfo=UTC),
            "id": analyzer_finding_id,
            "resource": f"arn:aws:s3:::{bucket_name}",
            "resourceType": "AWS::S3::Bucket",
            "resourceOwnerAccount": "123456789012",
            "status": "ACTIVE",
            "updatedAt": datetime(2026, 9, 16, 16, 10, tzinfo=UTC),
            "findingType": "ExternalAccess",
        }
        analyzer_pages = FakePaginator(
            [
                {
                    "analyzers": [
                        {
                            "arn": analyzer_arn,
                            "name": analyzer_name,
                            "type": "ACCOUNT",
                            "createdAt": datetime(2026, 9, 16, 15, tzinfo=UTC),
                            "status": "ACTIVE",
                        }
                    ]
                }
            ]
        )
        analyzer_finding_pages = FakePaginator([{"findings": [analyzer_finding]}])
        analyzer_detail_pages = FakePaginator(
            [
                {
                    **analyzer_finding,
                    "findingDetails": [
                        {
                            "externalAccessDetails": {
                                "action": ["s3:GetObject"],
                                "condition": {},
                                "isPublic": True,
                                "principal": {"AWS": "*"},
                                "sources": [{"type": "POLICY"}],
                                "resourceControlPolicyRestriction": "NOT_APPLICABLE",
                            }
                        }
                    ],
                }
            ]
        )
        analyzer_client = FakeAWSClient(
            paginators={
                "list_analyzers": analyzer_pages,
                "list_findings_v2": analyzer_finding_pages,
                "get_finding_v2": analyzer_detail_pages,
            }
        )
        analyzer_digest = hashlib.sha256(analyzer_arn.encode("utf-8")).hexdigest()
        analyzer_finding_kind = f"access-analyzer.findings.discovery.{analyzer_digest}"
        analyzer_resource_id = "aa1." + base64.urlsafe_b64encode(
            json.dumps(
                [analyzer_arn, analyzer_finding_id],
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).decode("ascii").rstrip("=")
        iam_client, iam_paginators = _iam_acceptance_client()
        trail_arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/acceptance-audit"
        cloudtrail_pages = FakePaginator(
            [
                {
                    "Trails": [
                        {
                            "TrailARN": trail_arn,
                            "HomeRegion": "us-east-1",
                            "Name": "acceptance-audit",
                        }
                    ]
                }
            ]
        )
        cloudtrail_tag_pages = FakePaginator(
            [
                {
                    "ResourceTagList": [
                        {
                            "ResourceId": trail_arn,
                            "TagsList": [{"Key": "Owner", "Value": "security"}],
                        }
                    ]
                }
            ]
        )
        cloudtrail_client = FakeAWSClient(
            paginators={
                "list_trails": cloudtrail_pages,
                "list_tags": cloudtrail_tag_pages,
            },
            responses={
                "get_trail": [
                    {
                        "Trail": {
                            "Name": "acceptance-audit",
                            "TrailARN": trail_arn,
                            "HomeRegion": "us-east-1",
                            "S3BucketName": bucket_name,
                            "S3KeyPrefix": "cloudtrail",
                            "IncludeGlobalServiceEvents": True,
                            "IsMultiRegionTrail": True,
                            "LogFileValidationEnabled": True,
                            "KmsKeyId": kms_key_arn,
                            "IsOrganizationTrail": False,
                        }
                    }
                ],
                "get_trail_status": [
                    {
                        "IsLogging": True,
                        "LatestDeliveryTime": datetime(2026, 9, 16, 16, 15, tzinfo=UTC),
                    }
                ],
                "get_event_selectors": [
                    {
                        "TrailARN": trail_arn,
                        "EventSelectors": [
                            {
                                "IncludeManagementEvents": True,
                                "ReadWriteType": "All",
                                "ExcludeManagementEventSources": [],
                                "DataResources": [],
                            }
                        ],
                    }
                ],
            },
        )
        provider = FakeClientProvider(
            {
                ("accessanalyzer", "us-east-1"): analyzer_client,
                ("ec2", "us-east-1"): empty_ec2_client(
                    security_groups=security_group_pages,
                    instances=instance_pages,
                    volumes=volume_pages,
                    vpcs=vpc_pages,
                    subnets=subnet_pages,
                    flow_logs=flow_log_pages,
                ),
                ("s3", "us-east-1"): s3_client,
                ("s3control", "us-east-1"): s3control_client,
                ("kms", "us-east-1"): kms_client,
                ("iam", "us-east-1"): iam_client,
                ("cloudtrail", "us-east-1"): cloudtrail_client,
            },
            region_name="us-east-1",
            account_id="123456789012",
        )
        application = create_app(
            executor_factory=lambda: InProcessScanExecutor(
                session_factory=session_factory,
                settings=admin_settings,
                provider_factory=lambda _region: provider,
                max_workers=1,
                max_outstanding=1,
            )
        )
        assert application.dependency_overrides == {}

        with TestClient(application) as client:
            with ThreadPoolExecutor(max_workers=1) as request_pool:
                request = request_pool.submit(
                    client.post,
                    "/api/v1/scans",
                    headers=headers,
                    json={"region": "us-east-1"},
                )
                try:
                    assert collection_entered.wait(timeout=15), (
                        "the real executor did not reach the fake AWS boundary"
                    )
                    response = request.result(timeout=10)
                    assert not collection_release.is_set()
                except TimeoutError:
                    pytest.fail("POST /api/v1/scans waited for AWS collection")
                finally:
                    collection_release.set()

            assert response.status_code == 202, response.text
            submitted = response.json()
            assert submitted["status"] == "RUNNING"
            scan_id = UUID(submitted["scan_id"])

            terminal = _poll_terminal_scan(client, scan_id, headers)
            assert terminal["status"] == "COMPLETED", terminal
            assert terminal["aws_account_id"] == "123456789012"
            assert terminal["requested_regions"] == ["us-east-1"]
            assert terminal["successful_regions"] == ["us-east-1"]
            assert terminal["requested_services"] == [
                "access-analyzer",
                "cloudtrail",
                "cloudtrail-evidence",
                "ec2",
                "iam",
                "kms",
                "s3",
            ]
            assert terminal["scope"]["requested_collectors"] == [
                "access_analyzer_evidence",
                "cloudtrail_evidence",
                "cloudtrail_trails",
                "ec2_ebs_evidence",
                "iam_account_evidence",
                "iam_users",
                "s3_buckets",
                "s3_evidence",
                "security_groups",
                "vpc_network_evidence",
            ]
            assert set(terminal["successful_collectors"]) == {
                "access_analyzer_evidence",
                "cloudtrail_evidence",
                "cloudtrail_trails",
                "ec2_ebs_evidence",
                "iam_account_evidence",
                "iam_users",
                "s3_buckets",
                "s3_evidence",
                "security_groups",
                "vpc_network_evidence",
            }
            assert terminal["scope"]["enabled_controls"] == [
                "IAM-001",
                "LOG-001",
                "NET-001",
                "NET-002",
                "S3-900",
            ]
            assert set(terminal["scope"]["collector_outcomes"].values()) == {"SUCCEEDED"}
            assert set(terminal["scope"]["collector_outcomes"]) == set(
                terminal["scope"]["requested_collectors"]
            )

            assert provider.client_requests == [
                ("ec2", "us-east-1"),
                ("ec2", "us-east-1"),
                ("ec2", "us-east-1"),
                ("s3", "us-east-1"),
                ("s3control", "us-east-1"),
                ("s3", "us-east-1"),
                ("kms", "us-east-1"),
                ("accessanalyzer", "us-east-1"),
                ("iam", "us-east-1"),
                ("iam", "us-east-1"),
                ("cloudtrail", "us-east-1"),
            ]
            assert security_group_pages.calls == [{}]
            assert instance_pages.calls == [{}]
            assert volume_pages.calls == [{}]
            assert vpc_pages.calls == [{}]
            assert subnet_pages.calls == [{}]
            assert flow_log_pages.calls == [{}]
            assert s3_pages.calls == [{"PaginationConfig": {"PageSize": 1000}}]
            assert [call.operation_name for call in s3_client.calls] == [
                "get_bucket_location",
                "get_bucket_tagging",
                "get_bucket_encryption",
                "get_public_access_block",
                "get_bucket_policy",
                "get_bucket_policy_status",
                "get_bucket_acl",
                "get_bucket_versioning",
                "get_bucket_ownership_controls",
            ]
            assert s3_client.calls[0].parameters == {
                "Bucket": bucket_name,
                "ExpectedBucketOwner": "123456789012",
            }
            assert [call.operation_name for call in s3control_client.calls] == [
                "get_public_access_block"
            ]
            assert s3control_client.calls[0].parameters == {"AccountId": "123456789012"}
            assert [call.operation_name for call in kms_client.calls] == ["describe_key"]
            assert kms_client.calls[0].parameters == {"KeyId": kms_key_arn}
            assert analyzer_pages.calls == [{}]
            assert analyzer_finding_pages.calls == [
                {
                    "analyzerArn": analyzer_arn,
                    "filter": {
                        "findingType": {"eq": ["ExternalAccess"]},
                        "resourceType": {"eq": ["AWS::S3::Bucket"]},
                    },
                }
            ]
            assert analyzer_detail_pages.calls == [
                {"analyzerArn": analyzer_arn, "id": analyzer_finding_id}
            ]
            assert iam_client.paginator_requests == [
                "list_users",
                "list_groups",
                "list_roles",
                "list_policies",
                "list_user_tags",
                "list_mfa_devices",
                "list_access_keys",
                "list_attached_user_policies",
                "list_user_policies",
                "get_group",
                "list_attached_group_policies",
                "list_group_policies",
                "list_role_tags",
                "list_attached_role_policies",
                "list_role_policies",
                "list_policy_tags",
            ]
            assert iam_paginators["list_policies"].calls == [{"Scope": "Local"}]
            assert iam_paginators["get_group"].calls == [{"GroupName": "admins"}]
            assert [call.operation_name for call in iam_client.calls] == [
                "get_account_summary",
                "get_access_key_last_used",
                "get_user",
                "get_user_policy",
                "get_role",
                "get_role_policy",
                "get_policy",
                "get_policy_version",
                "get_policy",
                "get_policy_version",
            ]
            assert cloudtrail_pages.calls == [{}]
            assert cloudtrail_tag_pages.calls == [{"ResourceIdList": [trail_arn]}]
            assert [call.operation_name for call in cloudtrail_client.calls] == [
                "get_trail",
                "get_trail_status",
                "get_event_selectors",
            ]

            with Session(postgres_engine) as session:
                persisted_scan = session.get(Scan, scan_id)
                assert persisted_scan is not None
                assert persisted_scan.status is ScanStatus.COMPLETED
                assert persisted_scan.aws_account_id == "123456789012"
                assert persisted_scan.inventory_sha256 == terminal["inventory_sha256"]
                assert persisted_scan.result_checksum == terminal["result_checksum"]

                resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "ec2",
                        Resource.resource_type == "security_group",
                        Resource.aws_resource_id == "sg-acceptance-public-ssh",
                    )
                ).one()
                snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == resource.resource_id,
                    )
                ).one()
                assert snapshot.normalized_configuration["ingress_rules"][0]["ipv4_ranges"] == [
                    {"cidr": "0.0.0.0/0", "description": None}
                ]

                instance_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "ec2",
                        Resource.resource_type == "ec2_instance",
                        Resource.aws_resource_id == "i-acceptance",
                    )
                ).one()
                instance_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == instance_resource.resource_id,
                    )
                ).one()
                assert instance_snapshot.normalized_configuration["public_ipv4_addresses"] == [
                    "198.51.100.10"
                ]
                assert instance_snapshot.normalized_configuration["metadata_options"] == {
                    "http_endpoint": "enabled",
                    "http_tokens": "required",
                    "state": "applied",
                }

                volume_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "ec2",
                        Resource.resource_type == "ebs_volume",
                        Resource.aws_resource_id == "vol-acceptance",
                    )
                ).one()
                volume_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == volume_resource.resource_id,
                    )
                ).one()
                assert volume_snapshot.normalized_configuration["encrypted"] is True
                assert volume_snapshot.normalized_configuration["attachment_instance_ids"] == [
                    "i-acceptance"
                ]

                vpc_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "ec2",
                        Resource.resource_type == "vpc",
                        Resource.aws_resource_id == "vpc-acceptance",
                    )
                ).one()
                vpc_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == vpc_resource.resource_id,
                    )
                ).one()
                assert vpc_snapshot.normalized_configuration["cidr_block"] == "10.0.0.0/16"
                assert vpc_snapshot.tags == {
                    "Environment": "acceptance",
                    "Owner": "security",
                }

                subnet_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "ec2",
                        Resource.resource_type == "subnet",
                        Resource.aws_resource_id == "subnet-acceptance",
                    )
                ).one()
                subnet_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == subnet_resource.resource_id,
                    )
                ).one()
                assert subnet_snapshot.normalized_configuration["vpc_id"] == "vpc-acceptance"
                assert subnet_snapshot.normalized_configuration["map_public_ip_on_launch"] is False

                flow_log_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "ec2",
                        Resource.resource_type == "vpc_flow_log",
                        Resource.aws_resource_id == "fl-acceptance",
                    )
                ).one()
                flow_log_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == flow_log_resource.resource_id,
                    )
                ).one()
                assert flow_log_snapshot.normalized_configuration == {
                    "deliver_cross_account_role": None,
                    "deliver_logs_permission_arn": (
                        "arn:aws:iam::123456789012:role/flow-log-delivery"
                    ),
                    "deliver_logs_status": "SUCCESS",
                    "flow_log_status": "ACTIVE",
                    "log_destination": (
                        "arn:aws:logs:us-east-1:123456789012:log-group:acceptance-vpc-flow-logs"
                    ),
                    "log_destination_type": "cloud-watch-logs",
                    "log_group_name": "acceptance-vpc-flow-logs",
                    "max_aggregation_interval": 60,
                    "resource_id": "vpc-acceptance",
                    "traffic_type": "ALL",
                }

                bucket_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "s3",
                        Resource.resource_type == "s3_bucket",
                        Resource.aws_resource_id == bucket_name,
                    )
                ).one()
                bucket_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == bucket_resource.resource_id,
                    )
                ).one()
                assert bucket_snapshot.normalized_configuration["bucket_region"] == "us-east-1"
                assert (
                    bucket_snapshot.normalized_configuration["default_encryption"]["Rules"][0][
                        "ApplyServerSideEncryptionByDefault"
                    ]["SSEAlgorithm"]
                    == "aws:kms"
                )

                kms_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "kms",
                        Resource.resource_type == "kms_key",
                        Resource.aws_resource_id == kms_key_arn,
                    )
                ).one()
                kms_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == kms_resource.resource_id,
                    )
                ).one()
                assert kms_resource.arn == kms_key_arn
                assert kms_resource.region == "us-east-1"
                assert kms_snapshot.normalized_configuration["key_manager"] == "CUSTOMER"

                trail_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "cloudtrail",
                        Resource.resource_type == "cloudtrail_trail",
                        Resource.aws_resource_id == trail_arn,
                    )
                ).one()
                trail_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == trail_resource.resource_id,
                    )
                ).one()
                assert trail_resource.arn == trail_arn
                assert trail_resource.region == "us-east-1"
                assert trail_snapshot.tags == {"Owner": "security"}
                assert trail_snapshot.normalized_configuration["is_logging"] is True
                assert trail_snapshot.normalized_configuration["is_multi_region_trail"] is True
                assert trail_snapshot.normalized_configuration["s3_bucket_name"] == bucket_name
                assert trail_snapshot.normalized_configuration["kms_key_id"] == kms_key_arn

                analyzer_resource = session.scalars(
                    select(Resource).where(
                        Resource.aws_account_id == "123456789012",
                        Resource.service == "access-analyzer",
                        Resource.resource_type == "access_analyzer_finding",
                        Resource.aws_resource_id == analyzer_resource_id,
                    )
                ).one()
                analyzer_snapshot = session.scalars(
                    select(ResourceSnapshot).where(
                        ResourceSnapshot.scan_id == scan_id,
                        ResourceSnapshot.resource_id == analyzer_resource.resource_id,
                    )
                ).one()
                assert analyzer_snapshot.normalized_configuration["summary"] == {
                    "analyzer_arn": analyzer_arn,
                    "finding_id": analyzer_finding_id,
                    "finding_type": "ExternalAccess",
                    "resource_arn": f"arn:aws:s3:::{bucket_name}",
                    "resource_type": "AWS::S3::Bucket",
                    "resource_owner_account": "123456789012",
                    "status": "ACTIVE",
                    "analyzed_at": "2026-09-16T16:05:00+00:00",
                    "created_at": "2026-09-16T16:00:00+00:00",
                    "updated_at": "2026-09-16T16:10:00+00:00",
                    "analysis_error_present": False,
                }
                external_access = analyzer_snapshot.normalized_configuration["finding_details"][0][
                    "external_access_details"
                ]
                assert external_access["is_public"] is True
                assert external_access["principal"] == {"AWS": "*"}
                assert external_access["action"] == ["s3:GetObject"]

                iam_rows = session.execute(
                    select(Resource, ResourceSnapshot)
                    .join(
                        ResourceSnapshot,
                        ResourceSnapshot.resource_id == Resource.resource_id,
                    )
                    .where(
                        Resource.service == "iam",
                        ResourceSnapshot.scan_id == scan_id,
                    )
                ).all()
                iam_records = {
                    (
                        iam_resource.aws_account_id,
                        iam_resource.resource_type,
                        iam_resource.aws_resource_id,
                    ): (iam_resource, iam_snapshot)
                    for iam_resource, iam_snapshot in iam_rows
                }
                expected_user_inline_id = (
                    '{"owner_account_id":"123456789012",'
                    '"owner_resource_id":"AIDAACCEPTANCEALICE",'
                    '"owner_resource_type":"iam_user","policy_name":"Emergency"}'
                )
                expected_role_inline_id = (
                    '{"owner_account_id":"123456789012",'
                    '"owner_resource_id":"AROAACCEPTANCEREADER",'
                    '"owner_resource_type":"iam_role","policy_name":"Emergency"}'
                )
                expected_local_version_id = (
                    '{"policy_arn":"arn:aws:iam::123456789012:policy/Admin","version_id":"v1"}'
                )
                expected_aws_version_id = (
                    '{"policy_arn":"arn:aws:iam::aws:policy/ReadOnlyAccess","version_id":"v5"}'
                )
                expected_iam_identities = {
                    ("123456789012", "iam_access_key", "AKIAEXAMPLEONLY"),
                    (
                        "123456789012",
                        "iam_customer_managed_policy",
                        "arn:aws:iam::123456789012:policy/Admin",
                    ),
                    ("123456789012", "iam_group", "AGPAACCEPTANCEADMINS"),
                    ("123456789012", "iam_inline_policy", expected_user_inline_id),
                    ("123456789012", "iam_inline_policy", expected_role_inline_id),
                    (
                        "123456789012",
                        "iam_managed_policy_version",
                        expected_local_version_id,
                    ),
                    (
                        "123456789012",
                        "iam_mfa_device",
                        "arn:aws:iam::123456789012:mfa/alice",
                    ),
                    ("123456789012", "iam_role", "AROAACCEPTANCEREADER"),
                    ("123456789012", "iam_user", "AIDAACCEPTANCEALICE"),
                    (
                        "aws",
                        "iam_aws_managed_policy",
                        "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    ),
                    ("aws", "iam_managed_policy_version", expected_aws_version_id),
                }
                assert set(iam_records) == expected_iam_identities
                iam_user_snapshot = iam_records[
                    ("123456789012", "iam_user", "AIDAACCEPTANCEALICE")
                ][1]
                assert iam_user_snapshot.tags == {"Owner": "security"}
                assert (
                    iam_user_snapshot.normalized_configuration["mfa_devices"][0]["SerialNumber"]
                    == "arn:aws:iam::123456789012:mfa/alice"
                )
                assert (
                    iam_user_snapshot.normalized_configuration["access_keys"][0]["LastUsed"] is None
                )
                iam_access_key_snapshot = iam_records[
                    ("123456789012", "iam_access_key", "AKIAEXAMPLEONLY")
                ][1]
                assert (
                    iam_access_key_snapshot.normalized_configuration["last_used_state"]
                    == "no_recorded_use"
                )
                iam_role_snapshot = iam_records[
                    ("123456789012", "iam_role", "AROAACCEPTANCEREADER")
                ][1]
                assert (
                    iam_role_snapshot.normalized_configuration["trust_policy_document"][
                        "Statement"
                    ][0]["Action"]
                    == "sts:AssumeRole"
                )

                source_graph = load_evidence_graph(session, scan_id)
                assert source_graph is not None
                assert source_graph.scan_id == scan_id
                assert source_graph.collection_account_id == "123456789012"
                expected_present_once = {
                    "access-analyzer.analyzers.discovery",
                    "access-analyzer.finding-details",
                    "access-analyzer.finding-summary",
                    analyzer_finding_kind,
                    "cloudtrail.trail.configuration",
                    "cloudtrail.trail.event-selectors",
                    "cloudtrail.trail.identity",
                    "cloudtrail.trail.status",
                    "cloudtrail.trail.tags",
                    "cloudtrail.trails.discovery",
                    "ec2.ebs-encryption-default",
                    "ec2.flow-logs.discovery",
                    "ec2.instance",
                    "ec2.instances.discovery",
                    "ec2.security-group",
                    "ec2.security-groups.discovery",
                    "ec2.subnet",
                    "ec2.subnets.discovery",
                    "ec2.vpc",
                    "ec2.vpc-flow-log",
                    "ec2.vpcs.discovery",
                    "ec2.volume",
                    "ec2.volumes.discovery",
                    "iam.access-key",
                    "iam.account-summary",
                    "iam.customer-managed-policies.discovery",
                    "iam.customer-managed-policy",
                    "iam.customer-managed-policy.tags",
                    "iam.group",
                    "iam.group.attached-managed-policies",
                    "iam.group.inline-policies",
                    "iam.group.members",
                    "iam.groups.discovery",
                    "iam.managed-policy.reference",
                    "iam.mfa-device",
                    "iam.role",
                    "iam.role.attached-managed-policies",
                    "iam.role.inline-policies",
                    "iam.role.profile",
                    "iam.role.tags",
                    "iam.roles.discovery",
                    "iam.user",
                    "iam.user.access-keys",
                    "iam.user.attached-managed-policies",
                    "iam.user.inline-policies",
                    "iam.user.mfa-devices",
                    "iam.user.profile",
                    "iam.user.tags",
                    "iam.users.discovery",
                    "s3.account-public-access-block",
                    "s3.bucket-acl",
                    "s3.bucket-encryption",
                    "s3.bucket-location",
                    "s3.bucket-ownership-controls",
                    "s3.bucket-policy",
                    "s3.bucket-policy-status",
                    "s3.bucket-public-access-block",
                    "s3.bucket-tags",
                    "s3.bucket-versioning",
                    "s3.buckets.discovery",
                }
                expected_present_twice = {
                    "iam.inline-policy.document",
                    "iam.inline-policy.reference",
                    "iam.managed-policy-version.document",
                    "iam.managed-policy-version.reference",
                    "iam.managed-policy.metadata",
                }
                expected_source_states = Counter(
                    {(evidence_kind, "PRESENT"): 1 for evidence_kind in expected_present_once}
                )
                expected_source_states.update(
                    {(evidence_kind, "PRESENT"): 2 for evidence_kind in expected_present_twice}
                )
                expected_source_states.update(
                    {
                        ("ec2.ebs-default-kms-key", "EXPECTED_ABSENCE"): 1,
                        ("iam.access-key.last-used", "EXPECTED_ABSENCE"): 1,
                    }
                )
                kms_evidence_kind = (
                    "kms.key." + hashlib.sha256(f"us-east-1\0{kms_key_arn}".encode()).hexdigest()
                )
                expected_source_states[(kms_evidence_kind, "PRESENT")] = 1
                expected_kind_counts = Counter()
                for (evidence_kind, _state), count in expected_source_states.items():
                    expected_kind_counts[evidence_kind] += count
                assert len(source_graph.source_contracts) == 73
                assert len(source_graph.artifacts) == 73
                assert len(source_graph.source_outcomes) == 73
                assert (
                    Counter(contract.contract_key for contract in source_graph.source_contracts)
                    == expected_kind_counts
                )
                assert (
                    Counter(
                        (outcome.evidence_kind, outcome.state.value)
                        for outcome in source_graph.source_outcomes
                    )
                    == expected_source_states
                )
                assert {
                    contract.source_outcome_id for contract in source_graph.source_contracts
                } == {outcome.source_outcome_id for outcome in source_graph.source_outcomes}
                assert {artifact.evidence_reference for artifact in source_graph.artifacts} == {
                    outcome.evidence_reference for outcome in source_graph.source_outcomes
                }

                source_outcomes_by_kind = {
                    outcome.evidence_kind: outcome for outcome in source_graph.source_outcomes
                }
                source_artifacts_by_reference = {
                    artifact.evidence_reference: artifact for artifact in source_graph.artifacts
                }
                instance_source_outcome = source_outcomes_by_kind["ec2.instance"]
                volume_source_outcome = source_outcomes_by_kind["ec2.volume"]
                instance_source_artifact = source_artifacts_by_reference[
                    instance_source_outcome.evidence_reference
                ]
                volume_source_artifact = source_artifacts_by_reference[
                    volume_source_outcome.evidence_reference
                ]
                vpc_source_outcome = source_outcomes_by_kind["ec2.vpc"]
                subnet_source_outcome = source_outcomes_by_kind["ec2.subnet"]
                flow_log_source_outcome = source_outcomes_by_kind["ec2.vpc-flow-log"]
                assert instance_source_artifact.normalized_payload["resource_id"] == (
                    "i-acceptance"
                )
                assert volume_source_artifact.normalized_payload["resource_id"] == (
                    "vol-acceptance"
                )
                assert (
                    source_artifacts_by_reference[
                        vpc_source_outcome.evidence_reference
                    ].normalized_payload["resource_id"]
                    == "vpc-acceptance"
                )
                assert (
                    source_artifacts_by_reference[
                        subnet_source_outcome.evidence_reference
                    ].normalized_payload["resource_id"]
                    == "subnet-acceptance"
                )
                assert (
                    source_artifacts_by_reference[
                        flow_log_source_outcome.evidence_reference
                    ].normalized_payload["resource_id"]
                    == "fl-acceptance"
                )
                account_summary_outcome = source_outcomes_by_kind["iam.account-summary"]
                assert source_artifacts_by_reference[
                    account_summary_outcome.evidence_reference
                ].normalized_payload == {
                    "account_id": "123456789012",
                    "account_access_keys_present": False,
                    "account_mfa_enabled": True,
                    "complete": True,
                    "failure_category": None,
                }
                iam_user_outcome = source_outcomes_by_kind["iam.user"]
                iam_user_resource, iam_user_snapshot = iam_records[
                    ("123456789012", "iam_user", "AIDAACCEPTANCEALICE")
                ]
                assert iam_user_outcome.subject.stable_resource_id == (
                    iam_user_resource.resource_id
                )
                assert iam_user_outcome.subject.resource_snapshot_id == (
                    iam_user_snapshot.snapshot_id
                )

                analyzer_outcome = source_outcomes_by_kind["access-analyzer.analyzers.discovery"]
                analyzer_artifact = source_artifacts_by_reference[
                    analyzer_outcome.evidence_reference
                ]
                assert analyzer_artifact.normalized_payload["required_regions"] == ("us-east-1",)
                assert analyzer_artifact.normalized_payload["s3_region_discovery_complete"] is True
                finding_outcome = source_outcomes_by_kind["access-analyzer.finding-details"]
                finding_artifact = source_artifacts_by_reference[finding_outcome.evidence_reference]
                assert finding_outcome.subject.stable_resource_id == (analyzer_resource.resource_id)
                assert finding_outcome.subject.resource_snapshot_id == (
                    analyzer_snapshot.snapshot_id
                )
                assert finding_artifact.normalized_payload["finding_id"] == (analyzer_finding_id)
                assert (
                    finding_artifact.normalized_payload["finding_details"][0][
                        "external_access_details"
                    ]["is_public"]
                    is True
                )

                trail_identity_outcome = source_outcomes_by_kind["cloudtrail.trail.identity"]
                trail_configuration_outcome = source_outcomes_by_kind[
                    "cloudtrail.trail.configuration"
                ]
                trail_selector_outcome = source_outcomes_by_kind["cloudtrail.trail.event-selectors"]
                assert trail_identity_outcome.subject.stable_resource_id == (
                    trail_resource.resource_id
                )
                assert trail_identity_outcome.subject.resource_snapshot_id == (
                    trail_snapshot.snapshot_id
                )
                assert (
                    source_artifacts_by_reference[
                        trail_configuration_outcome.evidence_reference
                    ].normalized_payload["value"]["s3_bucket_name"]
                    == bucket_name
                )
                assert (
                    source_artifacts_by_reference[
                        trail_selector_outcome.evidence_reference
                    ].normalized_payload["value"]["basic_selectors"][0]["read_write_type"]
                    == "All"
                )

                assert len(source_graph.relationships) == 23
                source_relationships = {
                    (
                        relationship.relationship_type,
                        relationship.source.resource_type,
                        relationship.source.aws_resource_id,
                    ): relationship
                    for relationship in source_graph.relationships
                    if relationship.source.service == "ec2"
                }
                assert set(source_relationships) == {
                    (
                        RelationshipType.ATTACHED_TO_SECURITY_GROUP,
                        "ec2_instance",
                        "i-acceptance",
                    ),
                    (RelationshipType.USES_VOLUME, "ec2_instance", "i-acceptance"),
                    (RelationshipType.IN_SUBNET, "ec2_instance", "i-acceptance"),
                    (RelationshipType.IN_VPC, "ec2_instance", "i-acceptance"),
                    (
                        RelationshipType.IN_VPC,
                        "security_group",
                        "sg-acceptance-public-ssh",
                    ),
                    (RelationshipType.CONTAINS_SUBNET, "vpc", "vpc-acceptance"),
                    (RelationshipType.HAS_FLOW_LOG, "vpc", "vpc-acceptance"),
                }
                assert all(
                    relationship.resolution is RelationshipResolution.RESOLVED
                    for relationship in source_graph.relationships
                )
                analyzer_relationship = next(
                    relationship
                    for relationship in source_graph.relationships
                    if relationship.source.service == "access-analyzer"
                )
                assert analyzer_relationship.relationship_type is (
                    RelationshipType.REFERENCES_RESOURCE
                )
                assert analyzer_relationship.source.stable_resource_id == (
                    analyzer_resource.resource_id
                )
                assert analyzer_relationship.source.resource_snapshot_id == (
                    analyzer_snapshot.snapshot_id
                )
                assert analyzer_relationship.target.stable_resource_id == (
                    bucket_resource.resource_id
                )
                assert analyzer_relationship.target.resource_snapshot_id == (
                    bucket_snapshot.snapshot_id
                )
                kms_relationship = next(
                    relationship
                    for relationship in source_graph.relationships
                    if relationship.source.service == "s3"
                    and relationship.relationship_type is RelationshipType.ENCRYPTED_WITH
                )
                assert kms_relationship.resolution is RelationshipResolution.RESOLVED
                assert kms_relationship.source.stable_resource_id == bucket_resource.resource_id
                assert kms_relationship.source.resource_snapshot_id == bucket_snapshot.snapshot_id
                assert kms_relationship.target.stable_resource_id == kms_resource.resource_id
                assert kms_relationship.target.resource_snapshot_id == kms_snapshot.snapshot_id
                assert kms_relationship.provenance.evidence_reference == (
                    source_outcomes_by_kind["s3.bucket-encryption"].evidence_reference
                )
                trail_relationships = {
                    relationship.relationship_type: relationship
                    for relationship in source_graph.relationships
                    if relationship.source.service == "cloudtrail"
                }
                assert set(trail_relationships) == {
                    RelationshipType.DELIVERS_TO_BUCKET,
                    RelationshipType.ENCRYPTED_WITH,
                }
                trail_bucket_relationship = trail_relationships[RelationshipType.DELIVERS_TO_BUCKET]
                assert trail_bucket_relationship.resolution is RelationshipResolution.RESOLVED
                assert trail_bucket_relationship.source.stable_resource_id == (
                    trail_resource.resource_id
                )
                assert trail_bucket_relationship.source.resource_snapshot_id == (
                    trail_snapshot.snapshot_id
                )
                assert trail_bucket_relationship.target.stable_resource_id == (
                    bucket_resource.resource_id
                )
                assert trail_bucket_relationship.target.resource_snapshot_id == (
                    bucket_snapshot.snapshot_id
                )
                trail_kms_relationship = trail_relationships[RelationshipType.ENCRYPTED_WITH]
                assert trail_kms_relationship.resolution is RelationshipResolution.RESOLVED
                assert trail_kms_relationship.target.stable_resource_id == kms_resource.resource_id
                assert trail_kms_relationship.target.resource_snapshot_id == (
                    kms_snapshot.snapshot_id
                )
                volume_relationship = source_relationships[
                    (RelationshipType.USES_VOLUME, "ec2_instance", "i-acceptance")
                ]
                assert volume_relationship.resolution is RelationshipResolution.RESOLVED
                assert volume_relationship.target.stable_resource_id == (
                    volume_resource.resource_id
                )
                assert volume_relationship.target.resource_snapshot_id == (
                    volume_snapshot.snapshot_id
                )
                expected_edges = {
                    (
                        RelationshipType.ATTACHED_TO_SECURITY_GROUP,
                        "ec2_instance",
                        "i-acceptance",
                    ): resource.resource_id,
                    (RelationshipType.IN_SUBNET, "ec2_instance", "i-acceptance"): (
                        subnet_resource.resource_id
                    ),
                    (RelationshipType.IN_VPC, "ec2_instance", "i-acceptance"): (
                        vpc_resource.resource_id
                    ),
                    (
                        RelationshipType.IN_VPC,
                        "security_group",
                        "sg-acceptance-public-ssh",
                    ): vpc_resource.resource_id,
                    (RelationshipType.CONTAINS_SUBNET, "vpc", "vpc-acceptance"): (
                        subnet_resource.resource_id
                    ),
                    (RelationshipType.HAS_FLOW_LOG, "vpc", "vpc-acceptance"): (
                        flow_log_resource.resource_id
                    ),
                }
                for edge, expected_target_id in expected_edges.items():
                    assert source_relationships[edge].target.stable_resource_id == (
                        expected_target_id
                    )

                iam_relationships = {
                    (
                        relationship.relationship_type,
                        relationship.source.aws_account_id,
                        relationship.source.resource_type,
                        relationship.source.aws_resource_id,
                        relationship.target.aws_account_id,
                        relationship.target.resource_type,
                        relationship.target.aws_resource_id,
                    ): relationship
                    for relationship in source_graph.relationships
                    if relationship.source.service == "iam"
                }
                assert set(iam_relationships) == {
                    (
                        RelationshipType.HAS_MFA_DEVICE,
                        "123456789012",
                        "iam_user",
                        "AIDAACCEPTANCEALICE",
                        "123456789012",
                        "iam_mfa_device",
                        "arn:aws:iam::123456789012:mfa/alice",
                    ),
                    (
                        RelationshipType.HAS_ACCESS_KEY,
                        "123456789012",
                        "iam_user",
                        "AIDAACCEPTANCEALICE",
                        "123456789012",
                        "iam_access_key",
                        "AKIAEXAMPLEONLY",
                    ),
                    (
                        RelationshipType.MEMBER_OF_GROUP,
                        "123456789012",
                        "iam_user",
                        "AIDAACCEPTANCEALICE",
                        "123456789012",
                        "iam_group",
                        "AGPAACCEPTANCEADMINS",
                    ),
                    (
                        RelationshipType.ATTACHED_INLINE_POLICY,
                        "123456789012",
                        "iam_user",
                        "AIDAACCEPTANCEALICE",
                        "123456789012",
                        "iam_inline_policy",
                        expected_user_inline_id,
                    ),
                    (
                        RelationshipType.ATTACHED_INLINE_POLICY,
                        "123456789012",
                        "iam_role",
                        "AROAACCEPTANCEREADER",
                        "123456789012",
                        "iam_inline_policy",
                        expected_role_inline_id,
                    ),
                    (
                        RelationshipType.ATTACHED_MANAGED_POLICY,
                        "123456789012",
                        "iam_user",
                        "AIDAACCEPTANCEALICE",
                        "123456789012",
                        "iam_customer_managed_policy",
                        "arn:aws:iam::123456789012:policy/Admin",
                    ),
                    (
                        RelationshipType.ATTACHED_MANAGED_POLICY,
                        "123456789012",
                        "iam_role",
                        "AROAACCEPTANCEREADER",
                        "123456789012",
                        "iam_customer_managed_policy",
                        "arn:aws:iam::123456789012:policy/Admin",
                    ),
                    (
                        RelationshipType.PERMISSIONS_BOUNDARY,
                        "123456789012",
                        "iam_role",
                        "AROAACCEPTANCEREADER",
                        "123456789012",
                        "iam_customer_managed_policy",
                        "arn:aws:iam::123456789012:policy/Admin",
                    ),
                    (
                        RelationshipType.ATTACHED_MANAGED_POLICY,
                        "123456789012",
                        "iam_user",
                        "AIDAACCEPTANCEALICE",
                        "aws",
                        "iam_aws_managed_policy",
                        "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    ),
                    (
                        RelationshipType.PERMISSIONS_BOUNDARY,
                        "123456789012",
                        "iam_user",
                        "AIDAACCEPTANCEALICE",
                        "aws",
                        "iam_aws_managed_policy",
                        "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    ),
                    (
                        RelationshipType.SELECTS_DEFAULT_VERSION,
                        "123456789012",
                        "iam_customer_managed_policy",
                        "arn:aws:iam::123456789012:policy/Admin",
                        "123456789012",
                        "iam_managed_policy_version",
                        expected_local_version_id,
                    ),
                    (
                        RelationshipType.SELECTS_DEFAULT_VERSION,
                        "aws",
                        "iam_aws_managed_policy",
                        "arn:aws:iam::aws:policy/ReadOnlyAccess",
                        "aws",
                        "iam_managed_policy_version",
                        expected_aws_version_id,
                    ),
                }
                for relationship in iam_relationships.values():
                    source_key = (
                        relationship.source.aws_account_id,
                        relationship.source.resource_type,
                        relationship.source.aws_resource_id,
                    )
                    target_key = (
                        relationship.target.aws_account_id,
                        relationship.target.resource_type,
                        relationship.target.aws_resource_id,
                    )
                    assert (
                        relationship.source.stable_resource_id
                        == iam_records[source_key][0].resource_id
                    )
                    assert (
                        relationship.source.resource_snapshot_id
                        == iam_records[source_key][1].snapshot_id
                    )
                    assert (
                        relationship.target.stable_resource_id
                        == iam_records[target_key][0].resource_id
                    )
                    assert (
                        relationship.target.resource_snapshot_id
                        == iam_records[target_key][1].snapshot_id
                    )

                assessed_control_keys = set(
                    session.scalars(
                        select(Control.control_key)
                        .join(
                            ControlAssessment,
                            ControlAssessment.control_id == Control.control_id,
                        )
                        .where(ControlAssessment.scan_id == scan_id)
                    )
                )
                assert assessed_control_keys == {
                    "IAM-001",
                    "LOG-001",
                    "NET-001",
                    "NET-002",
                    "S3-900",
                }
                control = session.scalars(
                    select(Control).where(Control.control_key == "NET-001")
                ).one()
                assessment = session.scalars(
                    select(ControlAssessment).where(
                        ControlAssessment.scan_id == scan_id,
                        ControlAssessment.resource_id == resource.resource_id,
                        ControlAssessment.control_id == control.control_id,
                    )
                ).one()
                assert assessment.assessment_result is AssessmentResult.FAIL
                assert assessment.resource_snapshot_id == snapshot.snapshot_id

                evidence = session.scalars(
                    select(EvidenceArtifact).where(
                        EvidenceArtifact.assessment_id == assessment.assessment_id
                    )
                ).one()
                assert evidence.resource_snapshot_id == snapshot.snapshot_id
                assert evidence.control_id == control.control_id
                assert evidence.collector == "security_groups"
                assert evidence.source_api == "ec2:DescribeSecurityGroups"
                assert evidence.payload["target_port"] == 22
                assert evidence.payload["matched_ingress"][0]["cidr"] == "0.0.0.0/0"

                finding = session.scalars(
                    select(Finding).where(
                        Finding.resource_id == resource.resource_id,
                        Finding.control_id == control.control_id,
                    )
                ).one()
                assert finding.status is FindingStatus.OPEN
                occurrence = session.scalars(
                    select(FindingOccurrence).where(
                        FindingOccurrence.finding_id == finding.finding_id,
                        FindingOccurrence.assessment_id == assessment.assessment_id,
                    )
                ).one()
                assert occurrence.scan_id == scan_id
                assert occurrence.resource_snapshot_id == snapshot.snapshot_id

                scan_events = tuple(
                    session.scalars(
                        select(AuditEvent)
                        .where(
                            AuditEvent.target_type == "scan",
                            AuditEvent.target_id == scan_id,
                        )
                        .order_by(AuditEvent.timestamp, AuditEvent.event_id)
                    )
                )
                assert [
                    (event.event_type, event.actor_type, event.actor_id) for event in scan_events
                ] == [
                    (AuditEventType.SCAN_STARTED, "authenticated_user", "acceptance-admin"),
                    (AuditEventType.SCAN_COMPLETED, "system", "scan-executor"),
                ]
                finding_event = session.scalars(
                    select(AuditEvent).where(
                        AuditEvent.target_type == "finding",
                        AuditEvent.target_id == finding.finding_id,
                        AuditEvent.event_type == AuditEventType.FINDING_OPENED,
                    )
                ).one()
                assert finding_event.actor_type == "system"
                assert finding_event.actor_id == "scan-executor"
                assert finding_event.event_metadata["assessment_id"] == str(
                    assessment.assessment_id
                )

                resource_id = resource.resource_id
                snapshot_id = snapshot.snapshot_id
                instance_resource_id = instance_resource.resource_id
                instance_snapshot_id = instance_snapshot.snapshot_id
                volume_resource_id = volume_resource.resource_id
                volume_snapshot_id = volume_snapshot.snapshot_id
                vpc_resource_id = vpc_resource.resource_id
                vpc_snapshot_id = vpc_snapshot.snapshot_id
                subnet_resource_id = subnet_resource.resource_id
                subnet_snapshot_id = subnet_snapshot.snapshot_id
                flow_log_resource_id = flow_log_resource.resource_id
                flow_log_snapshot_id = flow_log_snapshot.snapshot_id
                bucket_resource_id = bucket_resource.resource_id
                bucket_snapshot_id = bucket_snapshot.snapshot_id
                kms_resource_id = kms_resource.resource_id
                kms_snapshot_id = kms_snapshot.snapshot_id
                trail_resource_id = trail_resource.resource_id
                trail_snapshot_id = trail_snapshot.snapshot_id
                analyzer_resource_uuid = analyzer_resource.resource_id
                analyzer_snapshot_id = analyzer_snapshot.snapshot_id
                iam_resource_ids = {
                    identity: (iam_resource.resource_id, iam_snapshot.snapshot_id)
                    for identity, (iam_resource, iam_snapshot) in iam_records.items()
                }
                source_outcome_ids = {
                    item.source_outcome_id for item in source_graph.source_outcomes
                }
                source_artifact_ids = {
                    item.evidence_reference: item.artifact_id for item in source_graph.artifacts
                }
                relationship_observation_ids = {
                    item.observation_id for item in source_graph.relationships
                }
                relationship_ids = {item.relationship_id for item in source_graph.relationships}
                control_id = control.control_id
                assessment_id = assessment.assessment_id
                control_version_id = assessment.control_version_id
                evidence_id = evidence.evidence_id
                finding_id = finding.finding_id
                occurrence_id = occurrence.occurrence_id

            scan_detail = client.get(f"/api/v1/scans/{scan_id}", headers=headers)
            assert scan_detail.status_code == 200
            assert scan_detail.json() == terminal

            resource_page = client.get(
                "/api/v1/resources",
                headers=headers,
                params={
                    "account_id": "123456789012",
                    "service": "ec2",
                    "resource_type": "security_group",
                    "region": "us-east-1",
                },
            )
            assert resource_page.status_code == 200
            assert resource_page.json()["total"] == 1
            resource_document = resource_page.json()["items"][0]
            assert resource_document["resource_id"] == str(resource_id)
            assert resource_document["aws_resource_id"] == "sg-acceptance-public-ssh"
            assert resource_document["latest_snapshot"]["snapshot_id"] == str(snapshot_id)
            assert resource_document["latest_snapshot"]["scan_id"] == str(scan_id)

            resource_detail = client.get(f"/api/v1/resources/{resource_id}", headers=headers)
            assert resource_detail.status_code == 200
            assert resource_detail.json() == resource_document
            history = client.get(
                f"/api/v1/resources/{resource_id}/history",
                headers=headers,
            )
            assert history.status_code == 200
            assert history.json()["total"] == 1
            assert history.json()["items"][0]["snapshot_id"] == str(snapshot_id)
            assert history.json()["items"][0]["scan_id"] == str(scan_id)

            instance_page = client.get(
                "/api/v1/resources",
                headers=headers,
                params={
                    "account_id": "123456789012",
                    "service": "ec2",
                    "resource_type": "ec2_instance",
                    "region": "us-east-1",
                },
            )
            assert instance_page.status_code == 200
            assert instance_page.json()["total"] == 1
            instance_document = instance_page.json()["items"][0]
            assert instance_document["resource_id"] == str(instance_resource_id)
            assert instance_document["aws_resource_id"] == "i-acceptance"
            assert instance_document["latest_snapshot"]["snapshot_id"] == str(instance_snapshot_id)
            assert instance_document["latest_snapshot"]["scan_id"] == str(scan_id)
            instance_detail = client.get(
                f"/api/v1/resources/{instance_resource_id}",
                headers=headers,
            )
            assert instance_detail.status_code == 200
            assert instance_detail.json() == instance_document
            instance_history = client.get(
                f"/api/v1/resources/{instance_resource_id}/history",
                headers=headers,
            )
            assert instance_history.status_code == 200
            assert instance_history.json()["total"] == 1
            assert instance_history.json()["items"][0]["snapshot_id"] == str(instance_snapshot_id)

            volume_page = client.get(
                "/api/v1/resources",
                headers=headers,
                params={
                    "account_id": "123456789012",
                    "service": "ec2",
                    "resource_type": "ebs_volume",
                    "region": "us-east-1",
                },
            )
            assert volume_page.status_code == 200
            assert volume_page.json()["total"] == 1
            volume_document = volume_page.json()["items"][0]
            assert volume_document["resource_id"] == str(volume_resource_id)
            assert volume_document["aws_resource_id"] == "vol-acceptance"
            assert volume_document["latest_snapshot"]["snapshot_id"] == str(volume_snapshot_id)
            assert volume_document["latest_snapshot"]["scan_id"] == str(scan_id)
            volume_detail = client.get(
                f"/api/v1/resources/{volume_resource_id}",
                headers=headers,
            )
            assert volume_detail.status_code == 200
            assert volume_detail.json() == volume_document
            volume_history = client.get(
                f"/api/v1/resources/{volume_resource_id}/history",
                headers=headers,
            )
            assert volume_history.status_code == 200
            assert volume_history.json()["total"] == 1
            assert volume_history.json()["items"][0]["snapshot_id"] == str(volume_snapshot_id)

            for (
                network_resource_type,
                network_aws_id,
                network_resource_id,
                network_snapshot_id,
            ) in (
                ("vpc", "vpc-acceptance", vpc_resource_id, vpc_snapshot_id),
                ("subnet", "subnet-acceptance", subnet_resource_id, subnet_snapshot_id),
                (
                    "vpc_flow_log",
                    "fl-acceptance",
                    flow_log_resource_id,
                    flow_log_snapshot_id,
                ),
            ):
                network_page = client.get(
                    "/api/v1/resources",
                    headers=headers,
                    params={
                        "account_id": "123456789012",
                        "service": "ec2",
                        "resource_type": network_resource_type,
                        "region": "us-east-1",
                    },
                )
                assert network_page.status_code == 200
                assert network_page.json()["total"] == 1
                network_document = network_page.json()["items"][0]
                assert network_document["resource_id"] == str(network_resource_id)
                assert network_document["aws_resource_id"] == network_aws_id
                assert network_document["latest_snapshot"]["snapshot_id"] == str(
                    network_snapshot_id
                )
                network_detail = client.get(
                    f"/api/v1/resources/{network_resource_id}",
                    headers=headers,
                )
                assert network_detail.status_code == 200
                assert network_detail.json() == network_document
                network_history = client.get(
                    f"/api/v1/resources/{network_resource_id}/history",
                    headers=headers,
                )
                assert network_history.status_code == 200
                assert network_history.json()["total"] == 1
                assert network_history.json()["items"][0]["snapshot_id"] == str(network_snapshot_id)

            for (
                evidence_service,
                evidence_resource_type,
                evidence_aws_id,
                evidence_resource_id,
                evidence_snapshot_id,
            ) in (
                (
                    "s3",
                    "s3_bucket",
                    bucket_name,
                    bucket_resource_id,
                    bucket_snapshot_id,
                ),
                (
                    "access-analyzer",
                    "access_analyzer_finding",
                    analyzer_resource_id,
                    analyzer_resource_uuid,
                    analyzer_snapshot_id,
                ),
                (
                    "kms",
                    "kms_key",
                    kms_key_arn,
                    kms_resource_id,
                    kms_snapshot_id,
                ),
                (
                    "cloudtrail",
                    "cloudtrail_trail",
                    trail_arn,
                    trail_resource_id,
                    trail_snapshot_id,
                ),
            ):
                evidence_page = client.get(
                    "/api/v1/resources",
                    headers=headers,
                    params={
                        "account_id": "123456789012",
                        "service": evidence_service,
                        "resource_type": evidence_resource_type,
                        "region": "us-east-1",
                    },
                )
                assert evidence_page.status_code == 200
                assert evidence_page.json()["total"] == 1
                evidence_document = evidence_page.json()["items"][0]
                assert evidence_document["resource_id"] == str(evidence_resource_id)
                assert evidence_document["aws_resource_id"] == evidence_aws_id
                assert evidence_document["latest_snapshot"]["snapshot_id"] == str(
                    evidence_snapshot_id
                )
                assert evidence_document["latest_snapshot"]["scan_id"] == str(scan_id)
                evidence_detail = client.get(
                    f"/api/v1/resources/{evidence_resource_id}",
                    headers=headers,
                )
                assert evidence_detail.status_code == 200
                assert evidence_detail.json() == evidence_document
                evidence_history = client.get(
                    f"/api/v1/resources/{evidence_resource_id}/history",
                    headers=headers,
                )
                assert evidence_history.status_code == 200
                assert evidence_history.json()["total"] == 1
                assert evidence_history.json()["items"][0]["snapshot_id"] == str(
                    evidence_snapshot_id
                )
                assert evidence_history.json()["items"][0]["scan_id"] == str(scan_id)

            for (
                iam_owner,
                iam_resource_type,
                iam_aws_resource_id,
            ), (iam_resource_id, iam_snapshot_id) in iam_resource_ids.items():
                iam_page = client.get(
                    "/api/v1/resources",
                    headers=headers,
                    params={
                        "account_id": iam_owner,
                        "service": "iam",
                        "resource_type": iam_resource_type,
                    },
                )
                assert iam_page.status_code == 200
                matching_documents = [
                    item
                    for item in iam_page.json()["items"]
                    if item["aws_resource_id"] == iam_aws_resource_id
                ]
                assert len(matching_documents) == 1
                iam_document = matching_documents[0]
                assert iam_document["resource_id"] == str(iam_resource_id)
                assert iam_document["scope"] == "global"
                assert iam_document["region"] == "global"
                assert iam_document["latest_snapshot"]["snapshot_id"] == str(iam_snapshot_id)
                assert iam_document["latest_snapshot"]["scan_id"] == str(scan_id)
                assert iam_document["latest_snapshot"]["region"] is None

                iam_detail = client.get(
                    f"/api/v1/resources/{iam_resource_id}",
                    headers=headers,
                )
                assert iam_detail.status_code == 200
                assert iam_detail.json() == iam_document
                iam_history = client.get(
                    f"/api/v1/resources/{iam_resource_id}/history",
                    headers=headers,
                )
                assert iam_history.status_code == 200
                assert iam_history.json()["total"] == 1
                assert iam_history.json()["items"][0]["snapshot_id"] == str(iam_snapshot_id)
                assert iam_history.json()["items"][0]["scan_id"] == str(scan_id)

            source_outcome_page = client.get(
                "/api/v1/source-outcomes",
                headers=headers,
                params={"scan_id": str(scan_id), "limit": 100},
            )
            assert source_outcome_page.status_code == 200
            source_outcome_document = source_outcome_page.json()
            assert source_outcome_document["total"] == 73
            assert {
                UUID(item["source_outcome_id"]) for item in source_outcome_document["items"]
            } == source_outcome_ids
            assert (
                Counter(
                    (item["evidence_kind"], item["state"])
                    for item in source_outcome_document["items"]
                )
                == expected_source_states
            )
            source_outcome_details_by_kind = {}
            for source_outcome in source_outcome_document["items"]:
                source_outcome_detail = client.get(
                    f"/api/v1/source-outcomes/{source_outcome['source_outcome_id']}",
                    headers=headers,
                )
                assert source_outcome_detail.status_code == 200
                source_outcome_detail_document = source_outcome_detail.json()
                assert (
                    source_outcome_detail_document["source_outcome_id"]
                    == (source_outcome["source_outcome_id"])
                )
                assert source_outcome_detail_document["scan_id"] == str(scan_id)
                assert source_outcome_detail_document["artifact"]["artifact_id"] == str(
                    source_artifact_ids[source_outcome["evidence_reference"]]
                )
                assert (
                    source_outcome_detail_document["artifact"]["evidence_reference"]
                    == source_outcome["evidence_reference"]
                )
                assert (
                    source_outcome_detail_document["artifact"]["evidence_sha256"]
                    == (source_outcome["evidence_sha256"])
                )
                source_outcome_details_by_kind[source_outcome["evidence_kind"]] = (
                    source_outcome_detail_document
                )
            instance_outcome_detail = source_outcome_details_by_kind["ec2.instance"]
            assert instance_outcome_detail["subject"]["stable_resource_id"] == str(
                instance_resource_id
            )
            assert instance_outcome_detail["subject"]["resource_snapshot_id"] == str(
                instance_snapshot_id
            )
            assert (
                instance_outcome_detail["artifact"]["normalized_payload"]["resource_id"]
                == "i-acceptance"
            )
            volume_outcome_detail = source_outcome_details_by_kind["ec2.volume"]
            assert volume_outcome_detail["subject"]["stable_resource_id"] == str(volume_resource_id)
            assert volume_outcome_detail["subject"]["resource_snapshot_id"] == str(
                volume_snapshot_id
            )
            assert (
                volume_outcome_detail["artifact"]["normalized_payload"]["resource_id"]
                == "vol-acceptance"
            )
            for evidence_kind, expected_resource_id, expected_stable_id in (
                ("ec2.vpc", "vpc-acceptance", vpc_resource_id),
                ("ec2.subnet", "subnet-acceptance", subnet_resource_id),
                ("ec2.vpc-flow-log", "fl-acceptance", flow_log_resource_id),
                (
                    "ec2.security-group",
                    "sg-acceptance-public-ssh",
                    resource_id,
                ),
            ):
                detail = source_outcome_details_by_kind[evidence_kind]
                assert detail["subject"]["stable_resource_id"] == str(expected_stable_id)
                assert detail["artifact"]["normalized_payload"]["resource_id"] == (
                    expected_resource_id
                )
            encryption_default_detail = source_outcome_details_by_kind["ec2.ebs-encryption-default"]
            assert encryption_default_detail["artifact"]["normalized_payload"] == {
                "account_id": "123456789012",
                "region": "us-east-1",
                "ebs_encryption_by_default": False,
                "complete": True,
                "failure_category": None,
            }
            default_kms_detail = source_outcome_details_by_kind["ec2.ebs-default-kms-key"]
            assert default_kms_detail["artifact"]["normalized_payload"] == {
                "account_id": "123456789012",
                "region": "us-east-1",
                "default_kms_key_id": None,
                "complete": True,
                "expected_absence": True,
                "failure_category": None,
            }
            account_summary_detail = source_outcome_details_by_kind["iam.account-summary"]
            assert account_summary_detail["subject"] == {
                "subject_kind": "account",
                "provider": "aws",
                "aws_account_id": "123456789012",
                "scope": "global",
                "region": None,
            }
            assert account_summary_detail["artifact"]["normalized_payload"] == {
                "account_id": "123456789012",
                "account_access_keys_present": False,
                "account_mfa_enabled": True,
                "complete": True,
                "failure_category": None,
            }
            iam_user_detail = source_outcome_details_by_kind["iam.user"]
            iam_user_resource_id, iam_user_snapshot_id = iam_resource_ids[
                ("123456789012", "iam_user", "AIDAACCEPTANCEALICE")
            ]
            assert iam_user_detail["subject"]["stable_resource_id"] == str(iam_user_resource_id)
            assert iam_user_detail["subject"]["resource_snapshot_id"] == str(iam_user_snapshot_id)
            assert iam_user_detail["artifact"]["normalized_payload"]["resource_id"] == (
                "AIDAACCEPTANCEALICE"
            )
            analyzer_detail = source_outcome_details_by_kind["access-analyzer.analyzers.discovery"]
            assert analyzer_detail["subject"] == {
                "subject_kind": "account",
                "provider": "aws",
                "aws_account_id": "123456789012",
                "scope": "regional",
                "region": "us-east-1",
            }
            assert analyzer_detail["artifact"]["normalized_payload"]["relevant_analyzer_arns"] == [
                analyzer_arn
            ]
            finding_detail = source_outcome_details_by_kind["access-analyzer.finding-details"]
            assert finding_detail["subject"]["stable_resource_id"] == str(analyzer_resource_uuid)
            assert finding_detail["subject"]["resource_snapshot_id"] == str(analyzer_snapshot_id)
            assert finding_detail["artifact"]["normalized_payload"]["finding_id"] == (
                analyzer_finding_id
            )
            bucket_location_detail = source_outcome_details_by_kind["s3.bucket-location"]
            assert bucket_location_detail["subject"]["stable_resource_id"] == str(
                bucket_resource_id
            )
            assert bucket_location_detail["subject"]["resource_snapshot_id"] == str(
                bucket_snapshot_id
            )
            assert bucket_location_detail["artifact"]["normalized_payload"]["bucket_region"] == (
                "us-east-1"
            )
            bucket_policy_detail = source_outcome_details_by_kind["s3.bucket-policy"]
            assert bucket_policy_detail["subject"]["stable_resource_id"] == str(bucket_resource_id)
            assert bucket_policy_detail["artifact"]["normalized_payload"]["complete"] is True
            kms_detail = source_outcome_details_by_kind[kms_evidence_kind]
            assert kms_detail["subject"]["stable_resource_id"] == str(kms_resource_id)
            assert kms_detail["subject"]["resource_snapshot_id"] == str(kms_snapshot_id)
            assert kms_detail["artifact"]["normalized_payload"]["supplied_reference"] == (
                kms_key_arn
            )
            trail_identity_detail = source_outcome_details_by_kind["cloudtrail.trail.identity"]
            assert trail_identity_detail["subject"]["stable_resource_id"] == str(trail_resource_id)
            assert trail_identity_detail["subject"]["resource_snapshot_id"] == str(
                trail_snapshot_id
            )
            trail_selector_detail = source_outcome_details_by_kind[
                "cloudtrail.trail.event-selectors"
            ]
            assert trail_selector_detail["artifact"]["normalized_payload"]["complete"] is True

            relationship_page = client.get(
                "/api/v1/relationships",
                headers=headers,
                params={"scan_id": str(scan_id)},
            )
            assert relationship_page.status_code == 200
            relationship_document = relationship_page.json()
            assert relationship_document["total"] == 23
            assert {
                UUID(item["observation_id"]) for item in relationship_document["items"]
            } == relationship_observation_ids
            assert {
                UUID(item["relationship_id"]) for item in relationship_document["items"]
            } == relationship_ids
            relationship_items = {
                (
                    item["relationship_type"],
                    item["source"]["resource_type"],
                    item["source"]["aws_resource_id"],
                ): item
                for item in relationship_document["items"]
                if item["source"]["service"] == "ec2"
            }
            uses_volume = relationship_items[("uses_volume", "ec2_instance", "i-acceptance")]
            assert uses_volume["resolution"] == "RESOLVED"
            assert uses_volume["source"]["stable_resource_id"] == str(instance_resource_id)
            assert uses_volume["target"]["stable_resource_id"] == str(volume_resource_id)
            analyzer_reference = next(
                item
                for item in relationship_document["items"]
                if item["source"]["service"] == "access-analyzer"
            )
            assert analyzer_reference["relationship_type"] == "references_resource"
            assert analyzer_reference["resolution"] == "RESOLVED"
            assert analyzer_reference["source"]["stable_resource_id"] == str(analyzer_resource_uuid)
            assert analyzer_reference["source"]["resource_snapshot_id"] == str(analyzer_snapshot_id)
            assert analyzer_reference["target"]["stable_resource_id"] == str(bucket_resource_id)
            assert analyzer_reference["target"]["resource_snapshot_id"] == str(bucket_snapshot_id)
            kms_reference = next(
                item
                for item in relationship_document["items"]
                if item["source"]["service"] == "s3"
                and item["relationship_type"] == "encrypted_with"
            )
            assert kms_reference["resolution"] == "RESOLVED"
            assert kms_reference["source"]["stable_resource_id"] == str(bucket_resource_id)
            assert kms_reference["source"]["resource_snapshot_id"] == str(bucket_snapshot_id)
            assert kms_reference["target"]["stable_resource_id"] == str(kms_resource_id)
            assert kms_reference["target"]["resource_snapshot_id"] == str(kms_snapshot_id)
            assert (
                kms_reference["provenance"]["evidence_reference"]
                == (source_outcome_details_by_kind["s3.bucket-encryption"]["evidence_reference"])
            )
            cloudtrail_references = {
                item["relationship_type"]: item
                for item in relationship_document["items"]
                if item["source"]["service"] == "cloudtrail"
            }
            assert set(cloudtrail_references) == {"delivers_to_bucket", "encrypted_with"}
            assert cloudtrail_references["delivers_to_bucket"]["source"][
                "stable_resource_id"
            ] == str(trail_resource_id)
            assert cloudtrail_references["delivers_to_bucket"]["target"][
                "stable_resource_id"
            ] == str(bucket_resource_id)
            assert cloudtrail_references["encrypted_with"]["target"]["stable_resource_id"] == str(
                kms_resource_id
            )
            for item in relationship_document["items"]:
                relationship_detail = client.get(
                    f"/api/v1/relationships/{item['observation_id']}",
                    headers=headers,
                )
                assert relationship_detail.status_code == 200
                assert relationship_detail.json() == item
            expected_api_targets = {
                (
                    "attached_to_security_group",
                    "ec2_instance",
                    "i-acceptance",
                ): resource_id,
                ("in_subnet", "ec2_instance", "i-acceptance"): subnet_resource_id,
                ("in_vpc", "ec2_instance", "i-acceptance"): vpc_resource_id,
                (
                    "in_vpc",
                    "security_group",
                    "sg-acceptance-public-ssh",
                ): vpc_resource_id,
                ("contains_subnet", "vpc", "vpc-acceptance"): subnet_resource_id,
                ("has_flow_log", "vpc", "vpc-acceptance"): flow_log_resource_id,
            }
            for edge, expected_target_id in expected_api_targets.items():
                item = relationship_items[edge]
                assert item["resolution"] == "RESOLVED"
                assert item["target"]["identity_state"] == "stable"
                assert item["target"]["stable_resource_id"] == str(expected_target_id)
                assert item["target"]["resource_snapshot_id"] is not None

            iam_api_relationships = {
                (
                    item["relationship_type"],
                    item["source"]["aws_account_id"],
                    item["source"]["resource_type"],
                    item["source"]["aws_resource_id"],
                    item["target"]["aws_account_id"],
                    item["target"]["resource_type"],
                    item["target"]["aws_resource_id"],
                ): item
                for item in relationship_document["items"]
                if item["source"]["service"] == "iam"
            }
            assert set(iam_api_relationships) == {
                (
                    relationship_type.value,
                    source_owner,
                    source_type,
                    source_id,
                    target_owner,
                    target_type,
                    target_id,
                )
                for (
                    relationship_type,
                    source_owner,
                    source_type,
                    source_id,
                    target_owner,
                    target_type,
                    target_id,
                ) in iam_relationships
            }
            for edge, item in iam_api_relationships.items():
                source_key = (edge[1], edge[2], edge[3])
                target_key = (edge[4], edge[5], edge[6])
                assert item["resolution"] == "RESOLVED"
                assert item["source"]["stable_resource_id"] == str(iam_resource_ids[source_key][0])
                assert item["source"]["resource_snapshot_id"] == str(
                    iam_resource_ids[source_key][1]
                )
                assert item["target"]["stable_resource_id"] == str(iam_resource_ids[target_key][0])
                assert item["target"]["resource_snapshot_id"] == str(
                    iam_resource_ids[target_key][1]
                )

            assessment_page = client.get(
                "/api/v1/assessments",
                headers=headers,
                params={
                    "scan_id": str(scan_id),
                    "resource_id": str(resource_id),
                    "control_id": str(control_id),
                    "result": "FAIL",
                },
            )
            assert assessment_page.status_code == 200
            assert assessment_page.json()["total"] == 1
            assert assessment_page.json()["items"][0]["assessment_id"] == str(assessment_id)
            assert assessment_page.json()["items"][0]["evidence_count"] == 1

            assessment_detail = client.get(
                f"/api/v1/assessments/{assessment_id}",
                headers=headers,
            )
            assert assessment_detail.status_code == 200
            assessment_document = assessment_detail.json()
            assert assessment_document["resource_snapshot_id"] == str(snapshot_id)
            assert assessment_document["resource_id"] == str(resource_id)
            assert assessment_document["control_id"] == str(control_id)
            assert assessment_document["control_version_id"] == str(control_version_id)
            assert assessment_document["assessment_result"] == "FAIL"
            assert assessment_document["finding_id"] == str(finding_id)
            assert assessment_document["finding_occurrence_id"] == str(occurrence_id)
            assert [item["evidence_id"] for item in assessment_document["evidence"]] == [
                str(evidence_id)
            ]
            assert assessment_document["evidence"][0]["payload"]["target_port"] == 22
            mapping = assessment_document["framework_mappings"][0]
            assert mapping["control_version_id"] == str(control_version_id)
            assert mapping["framework_key"] == "nist-csf"
            assert mapping["framework_version"] == "2.0"
            assert mapping["reference_key"] == "PR.IR-01"

            finding_page = client.get(
                "/api/v1/findings",
                headers=headers,
                params={
                    "resource_id": str(resource_id),
                    "control_id": str(control_id),
                    "status": "OPEN",
                },
            )
            assert finding_page.status_code == 200
            assert finding_page.json()["total"] == 1
            assert finding_page.json()["items"][0]["finding_id"] == str(finding_id)
            finding_detail = client.get(f"/api/v1/findings/{finding_id}", headers=headers)
            assert finding_detail.status_code == 200
            finding_document = finding_detail.json()
            assert finding_document["resource_id"] == str(resource_id)
            assert finding_document["control_id"] == str(control_id)
            assert finding_document["occurrences"] == [
                {
                    "occurrence_id": str(occurrence_id),
                    "finding_id": str(finding_id),
                    "assessment_id": str(assessment_id),
                    "scan_id": str(scan_id),
                    "resource_snapshot_id": str(snapshot_id),
                    "resource_id": str(resource_id),
                    "control_version_id": str(control_version_id),
                    "control_id": str(control_id),
                    "assessment_result": "FAIL",
                    "detected_at": finding_document["occurrences"][0]["detected_at"],
                }
            ]

            control_detail = client.get(f"/api/v1/controls/{control_id}", headers=headers)
            assert control_detail.status_code == 200
            assert control_detail.json()["control_key"] == "NET-001"
            control_version = next(
                item
                for item in control_detail.json()["versions"]
                if item["control_version_id"] == str(control_version_id)
            )
            assert [item["mapping_id"] for item in control_version["framework_mappings"]] == [
                mapping["mapping_id"]
            ]

            framework_detail = client.get(
                f"/api/v1/frameworks/{mapping['framework_id']}",
                headers=headers,
            )
            assert framework_detail.status_code == 200
            framework_document = framework_detail.json()
            assert framework_document["framework_key"] == "nist-csf"
            assert framework_document["version"] == "2.0"
            reference = next(
                item
                for item in framework_document["references"]
                if item["framework_reference_id"] == mapping["framework_reference_id"]
            )
            assert reference["reference_key"] == "PR.IR-01"
            framework_mapping = next(
                item
                for item in reference["control_mappings"]
                if item["mapping_id"] == mapping["mapping_id"]
            )
            assert framework_mapping["control_id"] == str(control_id)
            assert framework_mapping["control_key"] == "NET-001"
            assert framework_mapping["control_version_id"] == str(control_version_id)
    finally:
        get_settings.cache_clear()
