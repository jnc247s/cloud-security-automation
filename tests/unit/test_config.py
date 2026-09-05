"""Tests for centralized application configuration."""

import pytest
from pydantic import ValidationError

from app.config import Settings


def test_settings_normalize_foundation_values() -> None:
    settings = Settings(
        log_level="debug",
        required_tags="Owner, Environment, Application",
    )

    assert settings.log_level == "DEBUG"
    assert settings.required_tag_names == ("Owner", "Environment", "Application")


def test_settings_reject_unknown_log_level() -> None:
    with pytest.raises(ValidationError):
        Settings(log_level="verbose")


def test_settings_reject_development_identity_in_production() -> None:
    with pytest.raises(ValidationError, match="AUTH_MODE must be oidc"):
        Settings(app_env="production", auth_mode="development")


def test_settings_reject_development_identity_outside_local_environments() -> None:
    with pytest.raises(ValidationError, match="only allowed for an explicit local"):
        Settings(app_env="staging", auth_mode="development")


def test_settings_require_complete_oidc_configuration() -> None:
    with pytest.raises(ValidationError, match="OIDC_AUDIENCE, OIDC_ISSUER, OIDC_JWKS_URL"):
        Settings(auth_mode="oidc")


def test_settings_normalize_complete_oidc_configuration() -> None:
    settings = Settings(
        app_env="PRODUCTION",
        auth_mode="OIDC",
        oidc_issuer="https://identity.example.test",
        oidc_audience="cloud-security-control-plane",
        oidc_jwks_url="https://identity.example.test/.well-known/jwks.json",
        oidc_algorithms="rs256, ES256,rs256",
    )

    assert settings.app_env == "production"
    assert settings.auth_mode == "oidc"
    assert settings.oidc_algorithm_names == ("RS256", "ES256")


def test_settings_reject_symmetric_or_unsigned_oidc_algorithms() -> None:
    with pytest.raises(ValidationError, match="unsupported"):
        Settings(oidc_algorithms="RS256,HS256,none")


def test_settings_reject_blank_identity_and_roles_claim_names() -> None:
    with pytest.raises(ValidationError, match="cannot be blank"):
        Settings(dev_identity_subject="   ")
    with pytest.raises(ValidationError, match="cannot be blank"):
        Settings(oidc_roles_claim="   ")


def test_settings_reject_insecure_oidc_urls_by_default() -> None:
    with pytest.raises(ValidationError, match="must use HTTPS"):
        Settings(
            auth_mode="oidc",
            oidc_issuer="http://localhost:9000",
            oidc_audience="cloud-security-control-plane",
            oidc_jwks_url="http://localhost:9000/jwks.json",
        )


def test_settings_allow_explicit_local_oidc_http_outside_production() -> None:
    settings = Settings(
        app_env="test",
        auth_mode="oidc",
        oidc_issuer="http://localhost:9000",
        oidc_audience="cloud-security-control-plane",
        oidc_jwks_url="http://127.0.0.1:9000/jwks.json",
        oidc_allow_insecure_http=True,
    )

    assert settings.oidc_allow_insecure_http is True
