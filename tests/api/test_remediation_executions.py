"""Signed bearer offline acceptance of generic execution admission and READ history."""

from tests.execution_http import exercise_execution_http
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine


def test_signed_execution_admission_without_aws(migrated_engine, monkeypatch, tmp_path):
    exercise_execution_http(migrated_engine, monkeypatch, tmp_path)
