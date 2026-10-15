"""Ownership-guarded test schemas; no application import or production database fallback."""

import os
from contextlib import contextmanager
from uuid import UUID

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError
from sqlalchemy.schema import CreateSchema, DropSchema


def fixture_database(raw: str) -> URL:
    try:
        url = make_url(raw)
        if (
            url.drivername != "postgresql+psycopg"
            or url.host != "127.0.0.1"
            or url.database != "cloudsec_test"
            or url.query
            or (url.port is not None and not 1 <= url.port <= 65535)
        ):
            raise ValueError
        return url
    except (ValueError, TypeError, ArgumentError):
        raise ValueError(
            "Operation fixture requires the explicit loopback disposable database"
        ) from None


def fixture_schema(instance: str) -> str:
    try:
        identifier = UUID(instance)
        if str(identifier) != instance or identifier.version != 4:
            raise ValueError
    except (ValueError, AttributeError, TypeError):
        raise ValueError("Invalid operation fixture ownership identifier") from None
    return "cloudsec_dashboard_ops_" + identifier.hex


@contextmanager
def owned_schema(raw: str, instance: str):
    """Commit short DDL before serving; never hold a transaction over browser/HTTP work."""
    if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
        raise RuntimeError("Operation fixture requires disposable browser validation")
    url, schema = fixture_database(raw), fixture_schema(instance)
    marker = "cloudsec.dashboard.ops:" + instance
    engine = create_engine(url, connect_args={"connect_timeout": 5})
    created = False
    try:
        with engine.begin() as connection:
            if (
                connection.execute(text("SELECT current_database()")).scalar_one()
                != "cloudsec_test"
            ):
                raise RuntimeError("Unexpected operation fixture database")
            connection.execute(CreateSchema(schema))  # Never replace an existing namespace.
            # Both interpolated values are closed UUID-derived identifiers, not arbitrary input.
            connection.exec_driver_sql(f"COMMENT ON SCHEMA {schema} IS '{marker}'")
        created = True
        yield url.update_query_dict({"options": "-csearch_path=" + schema})
    finally:
        try:
            if created:
                with engine.begin() as connection:
                    actual = connection.execute(
                        text(
                            "SELECT pg_catalog.obj_description(oid, 'pg_namespace') "
                            "FROM pg_catalog.pg_namespace WHERE nspname=:schema"
                        ),
                        {"schema": schema},
                    ).scalar_one_or_none()
                    if actual != marker:
                        raise RuntimeError(
                            "Refusing cleanup of an unowned operation fixture schema"
                        )
                    connection.execute(DropSchema(schema, cascade=True))
        finally:
            engine.dispose()
