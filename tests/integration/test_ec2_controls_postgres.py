"""Authoritative 6C persistence and HTTP checks on disposable PostgreSQL."""

import pytest

from tests.ec2_http_acceptance import exercise_ec2_http
from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_ec2_controls import (
    exercise_ec2_history,
    exercise_ec2_recovery,
    exercise_ec2_regions_and_empty,
    exercise_ec2_rejection,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_postgres_ec2_history(postgres_engine):
    exercise_ec2_history(postgres_engine)


@pytest.mark.parametrize("kind", ["na", "region", "source", "facts"])
def test_postgres_ec2_atomic_rejection(postgres_engine, kind):
    exercise_ec2_rejection(postgres_engine, kind)


def test_postgres_ec2_regions_empty(postgres_engine):
    exercise_ec2_regions_and_empty(postgres_engine)


def test_postgres_ec2_recovery(postgres_engine, tmp_path):
    exercise_ec2_recovery(postgres_engine, tmp_path)


def test_postgres_ec2_http(postgres_engine, monkeypatch, tmp_path):
    exercise_ec2_http(postgres_engine, monkeypatch, tmp_path)
