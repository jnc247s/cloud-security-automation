"""Real signed authorization and generic verification routes on migrated SQLite."""

from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.verification_http import exercise_verification_http


def test_signed_verification_http(migrated_engine, monkeypatch, tmp_path):
    exercise_verification_http(migrated_engine, monkeypatch, tmp_path)
