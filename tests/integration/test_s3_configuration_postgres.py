"""Authoritative isolated PostgreSQL acceptance for S3-001 and S3-003."""

import pytest

from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.s3_configuration_http import exercise_s3_http
from tests.unit.database.test_s3_configuration import (
    exercise_s3_history,
    exercise_s3_lifecycle,
    exercise_s3_recovery,
    exercise_s3_rejection,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_postgres_s3_history(postgres_engine):
    exercise_s3_history(postgres_engine)


@pytest.mark.parametrize("kind", ["na", "fail", "insufficient", "source", "facts", "version"])
def test_postgres_s3_rejection(postgres_engine, kind):
    exercise_s3_rejection(postgres_engine, kind)


def test_postgres_s3_lifecycle(postgres_engine):
    exercise_s3_lifecycle(postgres_engine)


def test_postgres_s3_recovery(postgres_engine, tmp_path):
    exercise_s3_recovery(postgres_engine, tmp_path)


def test_postgres_s3_http(postgres_engine, monkeypatch, tmp_path):
    exercise_s3_http(postgres_engine, monkeypatch, tmp_path)
