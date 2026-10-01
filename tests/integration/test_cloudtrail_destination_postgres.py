"""6F.2 acceptance against an explicitly disposable PostgreSQL database."""

import pytest

from tests.cloudtrail_destination_http import exercise_destination_http
from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_cloudtrail_destination import (
    FORGERIES,
    PREREQUISITE_FORGERIES,
    exercise_history,
    exercise_lifecycle,
    exercise_mixed_destinations,
    exercise_recovery,
    exercise_rejection,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


@pytest.mark.parametrize("kind", FORGERIES)
def test_rejection(postgres_engine, kind):
    exercise_rejection(postgres_engine, kind)


@pytest.mark.parametrize("kind", PREREQUISITE_FORGERIES)
def test_prerequisite_rejection(postgres_engine, kind):
    exercise_rejection(postgres_engine, kind, prerequisite=True)


def test_history(postgres_engine):
    exercise_history(postgres_engine)


def test_mixed_destinations(postgres_engine, monkeypatch):
    exercise_mixed_destinations(postgres_engine, monkeypatch)


def test_lifecycle(postgres_engine):
    exercise_lifecycle(postgres_engine)


def test_recovery(postgres_engine, tmp_path):
    exercise_recovery(postgres_engine, tmp_path)


def test_http(postgres_engine, monkeypatch, tmp_path):
    exercise_destination_http(postgres_engine, monkeypatch, tmp_path)
