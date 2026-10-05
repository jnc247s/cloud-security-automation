"""Combined dashboard acceptance on isolated SQLite; real production-mode signed OIDC."""

import pytest

from tests.sprint7_acceptance import exercise_dashboard_story
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
def test_whole_dashboard_retained_story(migrated_engine, monkeypatch, tmp_path, role):
    exercise_dashboard_story(migrated_engine, monkeypatch, tmp_path, role)
