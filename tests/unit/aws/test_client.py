"""Tests for cached AWS client and identity access."""

from unittest.mock import Mock, call

import pytest

from app.aws import client as client_module
from app.aws.client import AWSIdentityEvidenceError, Boto3ClientProvider
from app.config import Settings


def test_from_settings_creates_no_clients_or_api_requests(monkeypatch) -> None:
    """Provider construction creates the session but leaves AWS access lazy."""

    session = Mock()
    session_factory = Mock(return_value=session)
    monkeypatch.setattr(client_module, "create_aws_session", session_factory)
    settings = Settings(aws_region="ap-southeast-2", _env_file=None)

    provider = Boto3ClientProvider.from_settings(settings)

    assert provider.region_name == "ap-southeast-2"
    session_factory.assert_called_once_with(settings)
    session.client.assert_not_called()


def test_client_is_cached_by_service_and_region() -> None:
    """Repeated lookups reuse clients while regional overrides remain isolated."""

    session = Mock()
    session.client.side_effect = lambda *_args, **_kwargs: object()
    provider = Boto3ClientProvider(session=session, region_name="us-east-1")

    default_client = provider.client("ec2")
    repeated_client = provider.client("ec2")
    regional_client = provider.client("ec2", region_name="us-west-2")

    assert repeated_client is default_client
    assert regional_client is not default_client
    assert session.client.call_count == 2
    first_call = session.client.call_args_list[0]
    second_call = session.client.call_args_list[1]
    assert first_call.args == ("ec2",)
    assert first_call.kwargs["region_name"] == "us-east-1"
    assert first_call.kwargs["config"] is second_call.kwargs["config"]
    assert second_call.args == ("ec2",)
    assert second_call.kwargs["region_name"] == "us-west-2"


def test_identity_and_sts_client_are_resolved_once() -> None:
    """All identity accessors share one STS response and one cached client."""

    sts_client = Mock()
    sts_client.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:sts::123456789012:assumed-role/scanner/run-1",
        "UserId": "AROAXAMPLE:run-1",
    }
    session = Mock()
    session.client.return_value = sts_client
    provider = Boto3ClientProvider(session=session, region_name="us-east-1")

    identity = provider.identity

    assert identity.account_id == "123456789012"
    assert identity.caller_arn == "arn:aws:sts::123456789012:assumed-role/scanner/run-1"
    assert identity.user_id == "AROAXAMPLE:run-1"
    assert identity.partition == "aws"
    assert provider.identity is identity
    assert provider.account_id == "123456789012"
    assert provider.partition == "aws"
    assert provider.client("sts") is sts_client
    assert session.client.call_count == 1
    assert session.client.call_args.args == ("sts",)
    assert session.client.call_args.kwargs["region_name"] == "us-east-1"
    sts_client.get_caller_identity.assert_called_once_with()


@pytest.mark.parametrize(
    ("caller_arn", "expected_partition"),
    [
        ("arn:aws-us-gov:iam::123456789012:user/scanner", "aws-us-gov"),
        ("arn:aws-cn:iam::123456789012:user/scanner", "aws-cn"),
    ],
)
def test_identity_derives_partition_from_valid_caller_arn(
    caller_arn: str,
    expected_partition: str,
) -> None:
    """Partitions come from valid ARNs and malformed values use the AWS default."""

    sts_client = Mock()
    sts_client.get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": caller_arn,
        "UserId": "AIDAEXAMPLE",
    }
    session = Mock()
    session.client.return_value = sts_client
    provider = Boto3ClientProvider(session=session, region_name="us-gov-west-1")

    assert provider.partition == expected_partition


@pytest.mark.parametrize(
    "response",
    (
        None,
        [],
        {},
        {"Account": None, "Arn": "arn:aws:iam::123456789012:user/scanner", "UserId": "id"},
        {"Account": 123456789012, "Arn": "arn:aws:iam::123456789012:user/scanner", "UserId": "id"},
        {"Account": "", "Arn": "arn:aws:iam::123456789012:user/scanner", "UserId": "id"},
        {"Account": "123456789012", "Arn": None, "UserId": "id"},
        {"Account": "123456789012", "Arn": "malformed-sensitive-arn", "UserId": "id"},
        {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/scanner",
            "UserId": None,
        },
    ),
)
def test_rejects_malformed_sts_identity_without_coercion_or_sensitive_values(
    response: object,
) -> None:
    sts_client = Mock()
    sts_client.get_caller_identity.return_value = response
    session = Mock()
    session.client.return_value = sts_client
    provider = Boto3ClientProvider(session=session, region_name="us-east-1")

    with pytest.raises(AWSIdentityEvidenceError) as error_info:
        _ = provider.identity

    assert error_info.value.operation_name == "get_caller_identity"
    assert "malformed-sensitive-arn" not in str(error_info.value)


def test_clients_for_distinct_services_have_distinct_cache_entries() -> None:
    """A region cache key must still separate AWS services."""

    session = Mock()
    ec2_client = object()
    s3_client = object()
    session.client.side_effect = [ec2_client, s3_client]
    provider = Boto3ClientProvider(session=session, region_name="us-east-1")

    assert provider.client("ec2") is ec2_client
    assert provider.client("s3") is s3_client
    assert session.client.call_args_list == [
        call("ec2", region_name="us-east-1", config=provider._client_config),
        call("s3", region_name="us-east-1", config=provider._client_config),
    ]
