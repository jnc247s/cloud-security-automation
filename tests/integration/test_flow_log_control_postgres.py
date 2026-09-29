"""Authoritative isolated PostgreSQL acceptance for NET-006."""

import pytest

from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.network_http_acceptance import exercise_network_http
from tests.unit.database.test_flow_log_control import (
    exercise_flow_history,
    exercise_flow_lifecycle,
    exercise_flow_rejection,
)
from tests.unit.database.test_network_controls import exercise_network_recovery

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_postgres_flow_history(postgres_engine):
    exercise_flow_history(postgres_engine)


@pytest.mark.parametrize(
    "kind", ["na", "fail", "insufficient", "edge", "source", "facts", "version"]
)
def test_postgres_flow_rejection(postgres_engine, kind):
    exercise_flow_rejection(postgres_engine, kind)


def test_postgres_flow_lifecycle(postgres_engine):
    exercise_flow_lifecycle(postgres_engine)


def test_postgres_flow_recovery(postgres_engine, tmp_path):
    exercise_network_recovery(postgres_engine, tmp_path, flow_logs=True)


def test_postgres_flow_http(postgres_engine, monkeypatch, tmp_path):
    exercise_network_http(postgres_engine, monkeypatch, tmp_path, flow_logs=True)
