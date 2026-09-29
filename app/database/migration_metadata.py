"""Dialect-rendered CHECK names for Alembic comparison, without changing ORM metadata."""

from sqlalchemy import CheckConstraint, MetaData
from sqlalchemy.engine import Dialect
from sqlalchemy.schema import conv

AUTOGENERATE_PLUGINS = ("alembic.autogenerate.*", "alembic.ext.checkconstraint_byname")


def comparison_metadata(metadata: MetaData, dialect: Dialect) -> MetaData:
    """Compare the names actually emitted by SQLAlchemy on this database.

    Alembic's name-only CHECK comparator does not render naming-convention truncation.
    Use a private copy so autogeneration cannot mutate application metadata or migrations.
    Constraint expressions and all other objects remain available to normal comparison.
    """
    result = MetaData(naming_convention=metadata.naming_convention)
    for table in metadata.sorted_tables:
        table.to_metadata(result)
    for table in result.tables.values():
        for constraint in table.constraints:
            if isinstance(constraint, CheckConstraint) and isinstance(constraint.name, str):
                constraint.name = conv(
                    dialect.identifier_preparer.truncate_and_render_constraint_name(
                        constraint.name, _alembic_quote=False
                    )
                )
    return result
