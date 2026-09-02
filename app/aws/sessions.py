"""Lazy boto3 session creation using environment-backed application settings."""

import boto3
from boto3.session import Session

from app.config import Settings, get_settings


def create_aws_session(settings: Settings | None = None) -> Session:
    """Create a boto3 session without accepting or embedding static credentials."""

    resolved_settings = settings or get_settings()
    session_options = {"region_name": resolved_settings.aws_region}

    if resolved_settings.aws_profile:
        session_options["profile_name"] = resolved_settings.aws_profile

    return boto3.Session(**session_options)
