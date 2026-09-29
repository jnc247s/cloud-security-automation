"""Dialect-name normalization preserves schema semantics and shared model metadata."""

import pytest
from sqlalchemy import CheckConstraint, Column, Integer, MetaData, Table
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from app.database.base import NAMING_CONVENTION
from app.database.migration_metadata import comparison_metadata


@pytest.mark.parametrize("dialect", [postgresql.dialect(), sqlite.dialect()])
def test_comparison_names_match_emitted_ddl_without_mutation(dialect):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    table = Table(
        "resource_relationship_observations",
        metadata,
        Column("collector_version", Integer),
        CheckConstraint("collector_version > 0", name="collector_version_not_blank"),
    )
    original = next(c for c in table.constraints if isinstance(c, CheckConstraint))
    original_name = original.name
    original_ddl = str(CreateTable(table).compile(dialect=dialect))
    copied = comparison_metadata(metadata, dialect)
    copied_table = copied.tables[table.name]
    check = next(c for c in copied_table.constraints if isinstance(c, CheckConstraint))
    assert check is not original
    assert str(check.sqltext) == str(original.sqltext)
    assert str(CreateTable(copied_table).compile(dialect=dialect)) == original_ddl
    assert original.name == original_name
    assert len(check.name) <= dialect.max_identifier_length
    assert (check.name != original_name) is (dialect.name == "postgresql")
