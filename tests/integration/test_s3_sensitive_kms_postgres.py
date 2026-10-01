"""Authoritative disposable PostgreSQL gate for the S3-004 workflow."""

import pytest

from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.s3_configuration_http import exercise_s3_http
from tests.unit.database.test_s3_sensitive_kms import (
    FORGERIES,
    exercise_false_pass,
    exercise_history,
    exercise_lifecycle,
    exercise_policy_substitution,
    exercise_recovery,
    exercise_rejection,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_history(postgres_engine):
    exercise_history(postgres_engine)


@pytest.mark.parametrize("kind", FORGERIES)
def test_rejection(postgres_engine, kind):
    exercise_rejection(postgres_engine, kind)


def test_lifecycle(postgres_engine):
    exercise_lifecycle(postgres_engine)


@pytest.mark.parametrize("state", ["failed", "non-sensitive", "unknown"])
def test_false_pass(postgres_engine, state):
    exercise_false_pass(postgres_engine, state)


def test_policy_substitution(postgres_engine):
    exercise_policy_substitution(postgres_engine)


def test_recovery(postgres_engine, tmp_path):
    exercise_recovery(postgres_engine, tmp_path)


def test_http(postgres_engine, monkeypatch, tmp_path):
    exercise_s3_http(postgres_engine, monkeypatch, tmp_path, sensitive_kms=True)
