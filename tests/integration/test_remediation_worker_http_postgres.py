"""Signed authority, migrated PostgreSQL, real offline worker/SDK and authenticated history."""

import pytest

from tests.integration.test_persistence_postgres import postgres_engine as postgres_engine
from tests.worker_http import CASES, exercise_worker_http

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("outcome,baseline_key", CASES)
def test_signed_http_worker_postgres_history(
    postgres_engine, monkeypatch, tmp_path, outcome, baseline_key
):
    exercise_worker_http(
        postgres_engine, monkeypatch, tmp_path, outcome=outcome, baseline_key=baseline_key
    )
