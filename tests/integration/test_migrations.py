"""Integration test for the complete Alembic migration chain."""

from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect

from alembic import command


def test_migrations_upgrade_and_downgrade(tmp_path: Path) -> None:
    repository_root = Path(__file__).parents[2]
    database_path = tmp_path / "migration-test.sqlite"
    configuration = Config(str(repository_root / "alembic.ini"))
    configuration.set_main_option("script_location", str(repository_root / "alembic"))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database_path.as_posix()}")

    command.upgrade(configuration, "head")
    command.check(configuration)

    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    assert set(inspect(engine).get_table_names()) == {
        "alembic_version",
        "findings",
        "resources",
        "scan_resources",
        "scans",
    }
    engine.dispose()

    command.downgrade(configuration, "base")

    downgraded_engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    assert inspect(downgraded_engine).get_table_names() == ["alembic_version"]
    downgraded_engine.dispose()
