"""Portable resource identity and per-scan historical-state constraints."""

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import (
    CheckConstraint,
    Column,
    MetaData,
    Table,
    UniqueConstraint,
    Uuid,
    create_engine,
    select,
)
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app.models.resource import GLOBAL_REGION_SENTINEL, Resource, ResourceSnapshot
from app.schemas.resource import ResourceScope


@pytest.fixture
def resource_database() -> Generator[tuple[Connection, Table, Table, Table]]:
    """Exercise these tables independently of the rest of the evolving ORM graph."""

    metadata = MetaData()
    scans = Table("scans", metadata, Column("scan_id", Uuid, primary_key=True))
    resources = Resource.__table__.to_metadata(metadata)
    snapshots = ResourceSnapshot.__table__.to_metadata(metadata)
    engine = create_engine("sqlite+pysqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        metadata.create_all(connection)
        yield connection, resources, snapshots, scans
    engine.dispose()


def resource_values(**overrides: Any) -> dict[str, Any]:
    return {
        "resource_id": uuid4(),
        "provider": "aws",
        "aws_account_id": "123456789012",
        "service": "ec2",
        "resource_type": "security_group",
        "aws_resource_id": "sg-shared-id",
        "scope": ResourceScope.REGIONAL,
        "region": "us-east-1",
        **overrides,
    }


def snapshot_values(resource_id: UUID, scan_id: UUID, **overrides: Any) -> dict[str, Any]:
    return {
        "snapshot_id": uuid4(),
        "resource_id": resource_id,
        "scan_id": scan_id,
        "scope": ResourceScope.REGIONAL,
        "region": "us-east-1",
        "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-shared-id",
        "name": "original name",
        "tags": {"Environment": "test"},
        "normalized_configuration": {"ingress_permissions": []},
        "state_sha256": "a" * 64,
        "observed_at": datetime(2026, 9, 3, 12, tzinfo=UTC),
        **overrides,
    }


def test_stable_identity_includes_scope_and_non_nullable_region() -> None:
    identity_constraint = next(
        constraint
        for constraint in Resource.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
        and constraint.name == "uq_resources_stable_identity"
    )

    assert tuple(identity_constraint.columns.keys()) == (
        "provider",
        "aws_account_id",
        "service",
        "resource_type",
        "scope",
        "region",
        "aws_resource_id",
    )
    assert not Resource.__table__.c.region.nullable
    assert {"name", "tags", "normalized_configuration", "observed_at"}.isdisjoint(
        Resource.__table__.c.keys()
    )


def test_same_aws_id_in_different_regions_is_not_conflated(resource_database) -> None:
    connection, resources, _, _ = resource_database
    first = resource_values()
    second = resource_values(region="us-west-2")

    connection.execute(resources.insert(), [first, second])

    observed = connection.execute(select(resources.c.region, resources.c.scope)).all()
    assert set(observed) == {
        ("us-east-1", ResourceScope.REGIONAL),
        ("us-west-2", ResourceScope.REGIONAL),
    }
    with pytest.raises(IntegrityError):
        connection.execute(resources.insert(), {**first, "resource_id": uuid4()})


def test_global_identity_uses_a_non_null_deduplication_sentinel(resource_database) -> None:
    connection, resources, _, _ = resource_database
    values = resource_values(scope=ResourceScope.GLOBAL, region=GLOBAL_REGION_SENTINEL)
    connection.execute(resources.insert(), values)

    with pytest.raises(IntegrityError):
        connection.execute(resources.insert(), {**values, "resource_id": uuid4()})


@pytest.mark.parametrize(
    "overrides",
    [
        {"region": None},
        {"region": " "},
        {"aws_resource_id": " "},
        {"scope": ResourceScope.GLOBAL, "region": "us-east-1"},
        {"scope": ResourceScope.REGIONAL, "region": GLOBAL_REGION_SENTINEL},
    ],
)
def test_invalid_stable_identity_is_rejected(resource_database, overrides) -> None:
    connection, resources, _, _ = resource_database

    with pytest.raises(IntegrityError):
        connection.execute(resources.insert(), resource_values(**overrides))


def test_later_snapshots_preserve_original_names_tags_configuration_and_arn(
    resource_database,
) -> None:
    connection, resources, snapshots, scans = resource_database
    values = resource_values()
    first_scan_id, second_scan_id = uuid4(), uuid4()
    connection.execute(resources.insert(), values)
    connection.execute(scans.insert(), [{"scan_id": first_scan_id}, {"scan_id": second_scan_id}])
    first = snapshot_values(values["resource_id"], first_scan_id)
    second = snapshot_values(
        values["resource_id"],
        second_scan_id,
        name="changed name",
        arn="arn:aws:ec2:us-east-1:123456789012:security-group/observed-new-arn",
        tags={"Environment": "production"},
        normalized_configuration={"ingress_permissions": [{"IpProtocol": "tcp"}]},
        state_sha256="b" * 64,
        observed_at=datetime(2026, 9, 4, 12, tzinfo=UTC),
    )
    connection.execute(snapshots.insert(), [first, second])

    history = (
        connection.execute(select(snapshots).order_by(snapshots.c.observed_at)).mappings().all()
    )

    assert len(history) == 2
    for observed, expected in zip(history, (first, second), strict=True):
        for field in ("scan_id", "resource_id", "arn", "name", "tags", "normalized_configuration"):
            assert observed[field] == expected[field]
    with pytest.raises(IntegrityError):
        connection.execute(snapshots.insert(), {**first, "snapshot_id": uuid4()})


def test_global_snapshot_preserves_null_observed_region(resource_database) -> None:
    connection, resources, snapshots, scans = resource_database
    values = resource_values(scope=ResourceScope.GLOBAL, region=GLOBAL_REGION_SENTINEL)
    scan_id = uuid4()
    connection.execute(resources.insert(), values)
    connection.execute(scans.insert(), {"scan_id": scan_id})
    connection.execute(
        snapshots.insert(),
        snapshot_values(values["resource_id"], scan_id, scope=ResourceScope.GLOBAL, region=None),
    )

    assert connection.execute(select(snapshots.c.region)).scalar_one() is None


@pytest.mark.parametrize("missing_parent", ["resource", "scan"])
def test_snapshot_cannot_reference_a_missing_resource_or_scan(
    resource_database, missing_parent
) -> None:
    connection, resources, snapshots, scans = resource_database
    values = resource_values()
    scan_id = uuid4()
    if missing_parent != "resource":
        connection.execute(resources.insert(), values)
    if missing_parent != "scan":
        connection.execute(scans.insert(), {"scan_id": scan_id})

    with pytest.raises(IntegrityError):
        connection.execute(snapshots.insert(), snapshot_values(values["resource_id"], scan_id))


def test_snapshot_constraint_supports_same_resource_same_scan_assessment_foreign_keys() -> None:
    constraint_columns = {
        tuple(constraint.columns.keys())
        for constraint in ResourceSnapshot.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert ("snapshot_id", "scan_id", "resource_id") in constraint_columns


def test_scope_and_json_types_are_portable() -> None:
    for table in (Resource.__table__, ResourceSnapshot.__table__):
        assert not table.c.scope.type.native_enum
        assert table.c.scope.type.validate_strings
        constraint = next(
            constraint
            for constraint in table.constraints
            if isinstance(constraint, CheckConstraint)
            and constraint.name == f"ck_{table.name}_{table.c.scope.type.name}"
        )
        allowed_values = str(constraint.sqltext.compile(compile_kwargs={"literal_binds": True}))
        assert "'global'" in allowed_values
        assert "'regional'" in allowed_values
    configuration_type = ResourceSnapshot.__table__.c.normalized_configuration.type

    assert str(configuration_type.compile(dialect=postgresql.dialect())) == "JSONB"
    assert str(configuration_type.compile(dialect=sqlite.dialect())) == "JSON"
