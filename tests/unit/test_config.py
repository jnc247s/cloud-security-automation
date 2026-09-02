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
