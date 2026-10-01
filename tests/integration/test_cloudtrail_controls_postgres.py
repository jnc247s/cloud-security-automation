"""Disposable PostgreSQL acceptance gate for the 6F.1 CloudTrail workflow."""

import pytest

from tests.cloudtrail_http import exercise_logging_http
from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_cloudtrail_controls import (
    BOOLEAN_PROOF_PATHS,
    FORGERIES,
    exercise_false_pass,
    exercise_history,
    exercise_lifecycle,
    exercise_numeric_proof_rejection,
    exercise_recovery,
    exercise_rejection,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_history(postgres_engine):
    exercise_history(postgres_engine)


@pytest.mark.parametrize("control_id", ["LOG-002", "LOG-003"])
@pytest.mark.parametrize("kind", FORGERIES)
def test_rejection(postgres_engine, control_id, kind):
    exercise_rejection(postgres_engine, control_id, kind)


@pytest.mark.parametrize("control_id", ["LOG-002", "LOG-003"])
@pytest.mark.parametrize("state", ["failed", "empty", "unknown"])
def test_false_pass(postgres_engine, control_id, state):
    exercise_false_pass(postgres_engine, control_id, state)


@pytest.mark.parametrize("control_id,path", BOOLEAN_PROOF_PATHS)
@pytest.mark.parametrize("numeric_type", [int, float])
def test_numeric_proof_rejection(postgres_engine, control_id, path, numeric_type):
    exercise_numeric_proof_rejection(postgres_engine, control_id, path, numeric_type)


def test_lifecycle(postgres_engine):
    exercise_lifecycle(postgres_engine)


def test_recovery(postgres_engine, tmp_path):
    exercise_recovery(postgres_engine, tmp_path)


def test_http(postgres_engine, monkeypatch, tmp_path):
    exercise_logging_http(postgres_engine, monkeypatch, tmp_path)
