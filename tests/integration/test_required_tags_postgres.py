"""GOV-001 acceptance against explicitly configured disposable PostgreSQL."""

import pytest

from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_required_tags import (
    COVERAGE_FORGERIES,
    FORGERIES,
    exercise_coverage_history,
    exercise_coverage_rejection,
    exercise_history,
    exercise_lifecycle,
    exercise_population_cost,
    exercise_recovery,
    exercise_rejection,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


@pytest.mark.parametrize("kind", FORGERIES)
def test_atomic_rejection(postgres_engine, kind):
    exercise_rejection(postgres_engine, kind)


@pytest.mark.parametrize("kind", COVERAGE_FORGERIES)
def test_coverage_atomic_rejection(postgres_engine, kind):
    exercise_coverage_rejection(postgres_engine, kind)


def test_coverage_history(postgres_engine):
    exercise_coverage_history(postgres_engine)


@pytest.mark.parametrize("instance_count", [1, 2, 4, 8, 16])
def test_population_cost(postgres_engine, monkeypatch, instance_count):
    exercise_population_cost(postgres_engine, monkeypatch, instance_count)


def test_history(postgres_engine):
    exercise_history(postgres_engine)


def test_lifecycle(postgres_engine):
    exercise_lifecycle(postgres_engine)


def test_recovery(postgres_engine, tmp_path):
    exercise_recovery(postgres_engine, tmp_path)


def test_http(postgres_engine, monkeypatch, tmp_path):
    from tests.governance_http import exercise_governance_http

    exercise_governance_http(postgres_engine, monkeypatch, tmp_path)
