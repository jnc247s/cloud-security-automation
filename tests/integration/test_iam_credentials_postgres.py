"""Authoritative 6B.1 acceptance on an explicitly disposable PostgreSQL schema."""

import pytest

from tests.iam_http_acceptance import exercise_iam_http
from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_iam_credentials import (
    exercise_iam_empty_history,
    exercise_iam_false_na,
    exercise_iam_forged_proof,
    exercise_iam_history,
    exercise_iam_recovery,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_postgres_iam_history(postgres_engine):
    exercise_iam_history(postgres_engine)


def test_postgres_iam_forged_proof_is_atomic(postgres_engine):
    exercise_iam_forged_proof(postgres_engine)


def test_postgres_iam_empty_keys(postgres_engine):
    exercise_iam_empty_history(postgres_engine)


def test_postgres_iam_http_acceptance(postgres_engine, monkeypatch, tmp_path):
    exercise_iam_http(postgres_engine, monkeypatch, tmp_path)


def test_postgres_pending_iam_scan_recovery(postgres_engine, tmp_path):
    exercise_iam_recovery(postgres_engine, tmp_path)


@pytest.mark.parametrize("control_id", ["IAM-002", "IAM-003", "IAM-005", "IAM-006"])
def test_postgres_iam_false_na_is_atomic(postgres_engine, control_id):
    exercise_iam_false_na(postgres_engine, control_id)
