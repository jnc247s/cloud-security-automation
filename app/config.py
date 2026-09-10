"""Centralized environment-based application configuration."""

from functools import lru_cache
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.assessment.profiles import DEFAULT_PROFILE_VERSION


class Settings(BaseSettings):
    """Application settings loaded from environment variables or a local .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = "development"
    database_url: str = (
        "postgresql+psycopg://cloudsec:cloudsec_dev_password@localhost:5432/cloudsec"
    )
    log_level: str = "INFO"
    aws_region: str = "us-east-1"
    aws_profile: str | None = None
    assessment_profile_version: str = Field(
        default=DEFAULT_PROFILE_VERSION,
        max_length=64,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$",
    )
    stale_access_key_days: int = Field(default=90, ge=1)
    required_tags: str = "Owner,Environment"
    auth_mode: str = "development"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_algorithms: str = "RS256"
    oidc_roles_claim: str = "roles"
    oidc_allow_insecure_http: bool = False
    dev_identity_subject: str = "local-developer"
    dev_identity_roles: str = "ADMIN"

    @field_validator("app_env", "auth_mode", mode="before")
    @classmethod
    def normalize_environment_values(cls, value: object) -> object:
        """Normalize environment and authentication mode names."""

        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        """Normalize and validate the configured Python logging level."""

        normalized_value = value.upper()
        allowed_levels = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
        if normalized_value not in allowed_levels:
            message = f"LOG_LEVEL must be one of: {', '.join(sorted(allowed_levels))}"
            raise ValueError(message)
        return normalized_value

    @field_validator("aws_profile", mode="before")
    @classmethod
    def normalize_aws_profile(cls, value: object) -> object:
        """Treat an empty AWS profile as an instruction to use the default credential chain."""

        if isinstance(value, str):
            normalized_value = value.strip()
            return normalized_value or None
        return value

    @field_validator("assessment_profile_version", mode="before")
    @classmethod
    def normalize_assessment_profile_version(cls, value: object) -> object:
        """Normalize the operator-selected semantic profile version."""

        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator(
        "oidc_issuer",
        "oidc_audience",
        "oidc_jwks_url",
        mode="before",
    )
    @classmethod
    def normalize_optional_auth_value(cls, value: object) -> object:
        """Treat blank optional OIDC settings as unset."""

        if isinstance(value, str):
            normalized_value = value.strip()
            return normalized_value or None
        return value

    @field_validator("dev_identity_subject", "oidc_roles_claim")
    @classmethod
    def validate_required_auth_value(cls, value: str) -> str:
        """Reject blank identity and claim names."""

        normalized_value = value.strip()
        if not normalized_value:
            raise ValueError("authentication identity and claim names cannot be blank")
        return normalized_value

    @field_validator("oidc_algorithms")
    @classmethod
    def validate_oidc_algorithms(cls, value: str) -> str:
        """Require an explicit asymmetric JWT algorithm allowlist."""

        algorithms = tuple(item.strip().upper() for item in value.split(",") if item.strip())
        allowed_algorithms = {
            "ES256",
            "ES384",
            "ES512",
            "PS256",
            "PS384",
            "PS512",
            "RS256",
            "RS384",
            "RS512",
        }
        if not algorithms:
            raise ValueError("OIDC_ALGORITHMS must contain at least one algorithm")
        unsupported = sorted(set(algorithms) - allowed_algorithms)
        if unsupported:
            message = f"OIDC_ALGORITHMS contains unsupported values: {', '.join(unsupported)}"
            raise ValueError(message)
        return ",".join(dict.fromkeys(algorithms))

    @field_validator("dev_identity_roles")
    @classmethod
    def validate_dev_identity_roles(cls, value: str) -> str:
        """Normalize and validate roles assigned to the development identity."""

        roles = tuple(item.strip().upper() for item in value.split(",") if item.strip())
        allowed_roles = {"ADMIN", "ANALYST", "APPROVER", "VIEWER"}
        if not roles:
            raise ValueError("DEV_IDENTITY_ROLES must contain at least one role")
        unsupported = sorted(set(roles) - allowed_roles)
        if unsupported:
            message = f"DEV_IDENTITY_ROLES contains unsupported values: {', '.join(unsupported)}"
            raise ValueError(message)
        return ",".join(dict.fromkeys(roles))

    @model_validator(mode="after")
    def validate_authentication_configuration(self) -> "Settings":
        """Reject insecure production auth and incomplete OIDC configuration."""

        allowed_auth_modes = {"development", "oidc"}
        if self.auth_mode not in allowed_auth_modes:
            message = f"AUTH_MODE must be one of: {', '.join(sorted(allowed_auth_modes))}"
            raise ValueError(message)
        if self.app_env in {"production", "prod"} and self.auth_mode != "oidc":
            raise ValueError("AUTH_MODE must be oidc when APP_ENV is production")
        local_environments = {"dev", "development", "local", "test", "testing"}
        if self.auth_mode == "development" and self.app_env not in local_environments:
            raise ValueError(
                "AUTH_MODE=development is only allowed for an explicit local or test APP_ENV"
            )
        if self.auth_mode == "oidc":
            required_values = {
                "OIDC_AUDIENCE": self.oidc_audience,
                "OIDC_ISSUER": self.oidc_issuer,
                "OIDC_JWKS_URL": self.oidc_jwks_url,
            }
            missing_values = sorted(name for name, value in required_values.items() if not value)
            if missing_values:
                message = f"OIDC authentication requires: {', '.join(missing_values)}"
                raise ValueError(message)
            self._validate_oidc_url("OIDC_ISSUER", self.oidc_issuer)
            self._validate_oidc_url("OIDC_JWKS_URL", self.oidc_jwks_url)
        return self

    def _validate_oidc_url(self, name: str, value: str | None) -> None:
        """Require HTTPS OIDC endpoints, with an explicit local-only exception."""

        assert value is not None
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"{name} must be an absolute URL")
        if parsed.scheme == "https":
            return
        local_hosts = {"127.0.0.1", "::1", "localhost"}
        insecure_local_allowed = (
            self.oidc_allow_insecure_http
            and self.app_env not in {"production", "prod"}
            and parsed.scheme == "http"
            and parsed.hostname in local_hosts
        )
        if not insecure_local_allowed:
            message = (
                f"{name} must use HTTPS; insecure HTTP is only allowed explicitly "
                "for local development"
            )
            raise ValueError(message)

    @property
    def required_tag_names(self) -> tuple[str, ...]:
        """Return the configured comma-separated tag names as normalized values."""

        return tuple(tag.strip() for tag in self.required_tags.split(",") if tag.strip())

    @property
    def oidc_algorithm_names(self) -> tuple[str, ...]:
        """Return the configured JWT signature algorithm allowlist."""

        return tuple(item for item in self.oidc_algorithms.split(",") if item)

    @property
    def dev_identity_role_names(self) -> tuple[str, ...]:
        """Return the roles assigned to the fixed local development identity."""

        return tuple(item for item in self.dev_identity_roles.split(",") if item)


@lru_cache
def get_settings() -> Settings:
    """Return one cached settings instance for the application process."""

    return Settings()
