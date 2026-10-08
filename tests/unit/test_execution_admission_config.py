"""Explicit default-off scope is independent of all scanner configuration."""

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.remediation.execution_contracts import AdmissionScope


def settings(**values):
    return Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        remediation_admission_enabled=False,
        remediation_account_id=None,
        remediation_region=None,
        **values,
    )


def test_admission_defaults_off_without_scanner_scope_fallback():
    configured = settings(aws_region="us-west-2", aws_profile="read-only-scanner")
    assert configured.remediation_admission == AdmissionScope()


@pytest.mark.parametrize("scope", [{}, {"account_id": "123456789012"}, {"region": "us-east-1"}])
def test_enabled_admission_requires_both_scope_fields(scope):
    with pytest.raises(ValidationError, match="explicit account and Region"):
        AdmissionScope(enabled=True, **scope)


@pytest.mark.parametrize(
    "field, value",
    [
        ("remediation_account_id", "12345678901"),
        ("remediation_account_id", "1234567890123"),
        ("remediation_account_id", "１２３４５６７８９０１２"),
        ("remediation_account_id", " 123456789012 "),
        ("remediation_region", "global"),
        ("remediation_region", "US-EAST-1"),
        ("remediation_region", "https://endpoint.example.test"),
        ("remediation_region", "us-east-1 "),
    ],
)
def test_settings_reject_malformed_scope(field, value):
    values = dict(
        remediation_admission_enabled=False, remediation_account_id=None, remediation_region=None
    )
    values[field] = value
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_environment_opt_in_is_explicit_and_does_not_reconfigure_scanner(monkeypatch):
    monkeypatch.setenv("REMEDIATION_ADMISSION_ENABLED", "true")
    monkeypatch.setenv("REMEDIATION_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("REMEDIATION_REGION", "us-west-2")
    configured = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        aws_region="us-east-1",
        aws_profile="read-only",
    )
    assert configured.remediation_admission == AdmissionScope(
        enabled=True, account_id="123456789012", region="us-west-2"
    )
    assert configured.aws_region == "us-east-1" and configured.aws_profile == "read-only"


def test_enabled_settings_fail_startup_without_scope():
    with pytest.raises(ValidationError, match="explicit account and Region"):
        Settings(
            _env_file=None,
            remediation_admission_enabled=True,
            remediation_account_id=None,
            remediation_region=None,
        )


@pytest.mark.parametrize("enabled", ["true", 1, "yes"])
def test_internal_scope_requires_an_actual_boolean(enabled):
    with pytest.raises(ValidationError):
        AdmissionScope(enabled=enabled, account_id="123456789012", region="us-east-1")
