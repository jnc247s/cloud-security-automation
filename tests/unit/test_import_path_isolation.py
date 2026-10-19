"""Real migration setup must not leave import-search work for another test."""

import sys
from contextlib import nullcontext
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory

from tests.conftest import preserved_import_path


@pytest.mark.parametrize("raises", [False, True])
def test_import_path_restores_exact_order_and_identity_after_real_migration_setup(raises):
    original_list, original = sys.path, sys.path.copy()
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    assert config.get_prepend_sys_paths_list() == ["."]
    expected = (
        pytest.raises(RuntimeError, match="^Synthetic migration-scope failure$")
        if raises
        else nullcontext()
    )

    with expected, preserved_import_path():
        for _ in range(3):
            ScriptDirectory.from_config(config)
        # Actual Alembic behavior is exercised, not patched or disabled inside the scope.
        assert sys.path[:3] == ["."] * 3
        assert sys.path[3:] == original
        if raises:
            raise RuntimeError("Synthetic migration-scope failure")

    assert sys.path is original_list
    assert sys.path == original
