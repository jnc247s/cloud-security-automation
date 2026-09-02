"""Centralized environment-based application configuration."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    stale_access_key_days: int = Field(default=90, ge=1)
    required_tags: str = "Owner,Environment"

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

    @property
    def required_tag_names(self) -> tuple[str, ...]:
        """Return the configured comma-separated tag names as normalized values."""

        return tuple(tag.strip() for tag in self.required_tags.split(",") if tag.strip())


@lru_cache
def get_settings() -> Settings:
    """Return one cached settings instance for the application process."""

    return Settings()
