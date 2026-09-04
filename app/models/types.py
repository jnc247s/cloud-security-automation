"""Reusable portable SQLAlchemy types for the PostgreSQL-backed persistence model."""

from enum import Enum as PythonEnum
from typing import Any

from sqlalchemy import JSON, CheckConstraint, Enum
from sqlalchemy.dialects.postgresql import JSONB


def json_document_type() -> JSON:
    """Use JSONB on PostgreSQL while retaining SQLite migration-test portability."""

    return JSON().with_variant(JSONB(), "postgresql")


def string_enum_type(enum_type: type[PythonEnum], *, name: str, length: int) -> Enum:
    """Store enum values as constrained strings without PostgreSQL type lifecycle coupling."""

    return Enum(
        enum_type,
        name=name,
        native_enum=False,
        create_constraint=False,
        validate_strings=True,
        values_callable=lambda members: [str(member.value) for member in members],
        length=length,
    )


def enum_check_constraint(
    column: str, enum_type: type[PythonEnum], *, name: str
) -> CheckConstraint:
    """Create an explicit CHECK that Alembic can compare on every supported dialect."""

    values = ", ".join("'" + str(member.value).replace("'", "''") + "'" for member in enum_type)
    return CheckConstraint(f"{column} IN ({values})", name=name)


JsonObject = dict[str, Any]
JsonArray = list[Any]
