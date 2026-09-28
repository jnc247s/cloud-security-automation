"""Authoritative disposable PostgreSQL 6D.1 acceptance using existing schema isolation."""

import pytest

from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.network_http_acceptance import exercise_network_http
from tests.unit.database.test_network_controls import (
    exercise_network_empty_policy,
    exercise_network_history,
    exercise_network_lifecycle,
    exercise_network_recovery,
    exercise_network_rejection,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_postgres_network_history(postgres_engine):
    exercise_network_history(postgres_engine)


@pytest.mark.parametrize("kind", ["na", "pass", "source", "edge", "facts", "policy"])
def test_postgres_network_rejection(postgres_engine, kind):
    exercise_network_rejection(postgres_engine, kind)


def test_postgres_network_empty_policy(postgres_engine):
    exercise_network_empty_policy(postgres_engine)


def test_postgres_network_recovery(postgres_engine, tmp_path):
    exercise_network_recovery(postgres_engine, tmp_path)


def test_postgres_network_http(postgres_engine, monkeypatch, tmp_path):
    exercise_network_http(postgres_engine, monkeypatch, tmp_path)


def test_postgres_network_lifecycle(postgres_engine):
    exercise_network_lifecycle(postgres_engine)
