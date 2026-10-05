"""The same whole-dashboard signed HTTP contract on an explicitly disposable PostgreSQL DB."""

import pytest

from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine
from tests.sprint7_acceptance import exercise_dashboard_story

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
def test_whole_dashboard_retained_story(postgres_engine, monkeypatch, tmp_path, role):
    exercise_dashboard_story(postgres_engine, monkeypatch, tmp_path, role)
