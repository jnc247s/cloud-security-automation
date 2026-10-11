"""Production-mode signed bearer workflow and real offline worker on migrated SQLite."""

import pytest

from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.worker_http import CASES, exercise_worker_http


@pytest.mark.parametrize("outcome,baseline_key", CASES)
def test_signed_http_worker_history(migrated_engine, monkeypatch, tmp_path, outcome, baseline_key):
    exercise_worker_http(
        migrated_engine, monkeypatch, tmp_path, outcome=outcome, baseline_key=baseline_key
    )
