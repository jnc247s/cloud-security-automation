"""Migration-backed local signed-bearer remediation API acceptance."""

from tests.remediation_http import exercise_remediation_http
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine


def test_signed_remediation_authority_without_execution(migrated_engine, monkeypatch, tmp_path):
    exercise_remediation_http(migrated_engine, monkeypatch, tmp_path)
