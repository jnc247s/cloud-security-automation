"""Authoritative IAM-004 acceptance in a disposable PostgreSQL schema."""

import pytest

from tests.iam_http_acceptance import exercise_iam_http
from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_iam_policy import (
    exercise_policy_forgery,
    exercise_policy_history,
    exercise_policy_recovery,
    exercise_policy_version_history,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_postgres_policy_history(postgres_engine):
    exercise_policy_history(postgres_engine)


def test_postgres_policy_forgery(postgres_engine):
    exercise_policy_forgery(postgres_engine)


def test_postgres_policy_recovery(postgres_engine, tmp_path):
    exercise_policy_recovery(postgres_engine, tmp_path)


def test_postgres_policy_http(postgres_engine, monkeypatch, tmp_path):
    exercise_iam_http(postgres_engine, monkeypatch, tmp_path, policy_control=True)


def test_postgres_policy_version_history(postgres_engine):
    exercise_policy_version_history(postgres_engine)
