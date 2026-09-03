"""Tests for environment-driven boto3 session creation."""

from unittest.mock import Mock

from app.aws import sessions
from app.config import Settings


def test_create_aws_session_uses_region_and_default_credential_chain(monkeypatch) -> None:
    """An omitted profile must not override boto3's normal credential lookup."""

    created_session = object()
    session_constructor = Mock(return_value=created_session)
    monkeypatch.setattr(sessions.boto3, "Session", session_constructor)
    settings = Settings(aws_region="us-west-2", aws_profile=None, _env_file=None)

    result = sessions.create_aws_session(settings)

    assert result is created_session
    session_constructor.assert_called_once_with(region_name="us-west-2")


def test_create_aws_session_passes_explicit_profile(monkeypatch) -> None:
    """A configured profile is forwarded without adding static credentials."""

    created_session = object()
    session_constructor = Mock(return_value=created_session)
    monkeypatch.setattr(sessions.boto3, "Session", session_constructor)
    settings = Settings(
        aws_region="eu-west-1",
        aws_profile="security-audit",
        _env_file=None,
    )

    result = sessions.create_aws_session(settings)

    assert result is created_session
    session_constructor.assert_called_once_with(
        region_name="eu-west-1",
        profile_name="security-audit",
    )


def test_create_aws_session_treats_blank_profile_as_unset(monkeypatch) -> None:
    """Whitespace-only profiles use the standard credential chain."""

    session_constructor = Mock(return_value=object())
    monkeypatch.setattr(sessions.boto3, "Session", session_constructor)
    settings = Settings(aws_region="us-east-2", aws_profile="   ", _env_file=None)

    sessions.create_aws_session(settings)

    session_constructor.assert_called_once_with(region_name="us-east-2")
