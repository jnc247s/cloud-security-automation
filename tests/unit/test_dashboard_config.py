"""Opt-in browser startup fails closed; accepted API defaults are preserved."""

import pytest
from pydantic import ValidationError

from app.config import Settings


def values(**changes):
    return {
        "_env_file": None,
        "app_env": "production",
        "auth_mode": "oidc",
        "oidc_issuer": "https://identity.example.test",
        "oidc_audience": "https://api.example.test",
        "oidc_jwks_url": "https://identity.example.test/jwks",
        "dashboard_enabled": True,
        "dashboard_origin": "https://console.example.test",
        "dashboard_client_id": "test-client",
        "dashboard_client_secret": "not-a-real-credential",
        **changes,
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"auth_mode": "development"},
        {"dashboard_origin": None},
        {"dashboard_client_id": None},
        {"dashboard_client_secret": None},
        {"dashboard_client_secret": ""},
        {"dashboard_origin": "https://console.example.test/"},
        {"dashboard_origin": "https://console.example.test?next=evil"},
        {"dashboard_origin": "https://user:password@console.example.test"},
        {"dashboard_origin": "http://localhost:8000", "oidc_allow_insecure_http": True},
        {"dashboard_client_id": "https://api.example.test"},
        {"dashboard_scopes": "openid offline_access"},
        {"dashboard_scopes": "profile"},
        {"oidc_audience": "unbound-api-audience"},
        {"oidc_jwks_url": "https://user:password@identity.example.test/jwks"},
        {"oidc_audience": "https://api.example.test?token=sensitive"},
        {
            "app_env": "staging",
            "dashboard_origin": "http://localhost:8000",
            "oidc_allow_insecure_http": True,
        },
    ],
)
def test_rejects_incomplete_or_insecure_configuration(changes):
    with pytest.raises(ValidationError):
        Settings(**values(**changes))


def test_valid_config_keeps_credential_server_only_and_hides_invalid_input():
    settings = Settings(**values())
    assert "not-a-real-credential" not in repr(settings)
    with pytest.raises(ValidationError) as error:
        Settings(**values(dashboard_origin=None))
    assert "not-a-real-credential" not in str(error.value)


def test_explicit_local_oidc_allowed_but_no_development_fallback():
    assert Settings(
        **values(
            app_env="test", oidc_allow_insecure_http=True, dashboard_origin="http://127.0.0.1:8000"
        )
    ).dashboard_enabled
    with pytest.raises(ValidationError):
        Settings(**values(app_env="test", auth_mode="development"))


def test_disabled_dashboard_preserves_default_api_configuration():
    settings = Settings(
        _env_file=None, app_env="test", auth_mode="development", dashboard_enabled=False
    )
    assert not settings.dashboard_enabled and settings.oidc_roles_claim == "roles"
    assert not settings.dashboard_remediation_enabled


@pytest.mark.parametrize("enabled", [False, True])
def test_browser_remediation_opt_in_is_independent_from_backend_write_and_scan_flags(enabled):
    settings = Settings(**values(dashboard_remediation_enabled=enabled))
    assert settings.dashboard_remediation_enabled is enabled
    assert not settings.remediation_admission_enabled
    assert not settings.remediation_verification_enabled
    assert settings.remediation_account_id is None and settings.remediation_region is None


@pytest.mark.parametrize("auth_mode", ["oidc", "development"])
def test_remediation_cannot_enable_a_disabled_dashboard_or_development_fallback(auth_mode):
    with pytest.raises(ValidationError):
        Settings(
            **values(
                app_env="test",
                auth_mode=auth_mode,
                dashboard_enabled=False,
                dashboard_remediation_enabled=True,
            )
        )
    with pytest.raises(ValidationError):
        Settings(
            **values(app_env="test", auth_mode="development", dashboard_remediation_enabled=True)
        )
