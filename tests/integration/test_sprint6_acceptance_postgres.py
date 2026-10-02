"""Identical whole-sprint acceptance using explicitly disposable PostgreSQL."""

import pytest

from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.sprint6_fixtures import CATALOG_CHECKSUMS
from tests.unit.database.test_sprint6_acceptance import (
    exercise_release_history,
    exercise_release_recovery,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_release_history(postgres_engine):
    exercise_release_history(postgres_engine)


@pytest.mark.parametrize("version", CATALOG_CHECKSUMS)
def test_release_recovery(postgres_engine, tmp_path, version):
    exercise_release_recovery(postgres_engine, tmp_path, version)


def test_whole_sprint_http(postgres_engine, monkeypatch, tmp_path):
    from tests.sprint6_http import exercise_sprint6_http

    exercise_sprint6_http(postgres_engine, monkeypatch, tmp_path)
