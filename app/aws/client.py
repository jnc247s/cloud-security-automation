"""Centralized boto3 client creation and caller identity lookup."""

from collections.abc import Mapping
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Protocol

from boto3.session import Session
from botocore.config import Config

from app.aws.sessions import create_aws_session
from app.config import Settings, get_settings


@dataclass(frozen=True, slots=True)
class AWSIdentity:
    """Identity associated with the active AWS credential chain."""

    account_id: str
    caller_arn: str
    user_id: str
    partition: str


class AWSIdentityEvidenceError(RuntimeError):
    """Raised when STS returns an unusable caller-identity response."""

    def __init__(self, fact_path: str) -> None:
        self.operation_name = "get_caller_identity"
        self.fact_path = fact_path
        super().__init__(
            f"AWS identity evidence is incomplete at {self.operation_name}.{fact_path}"
        )


class AWSClientProvider(Protocol):
    """Minimal client-provider contract consumed by resource collectors."""

    region_name: str

    @property
    def account_id(self) -> str: ...

    @property
    def partition(self) -> str: ...

    def client(self, service_name: str, *, region_name: str | None = None) -> Any: ...


class Boto3ClientProvider:
    """Own one boto3 session and cache clients and STS identity for an inventory run."""

    def __init__(self, session: Session, region_name: str) -> None:
        self._session = session
        self.region_name = region_name
        self._clients: dict[tuple[str, str], Any] = {}
        self._client_config = Config(
            connect_timeout=5,
            read_timeout=30,
            retries={"mode": "standard", "max_attempts": 3},
            user_agent_extra="cloud-security-automation/0.1.0",
        )

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "Boto3ClientProvider":
        """Build a provider without making any AWS API calls."""

        resolved_settings = settings or get_settings()
        return cls(
            session=create_aws_session(resolved_settings),
            region_name=resolved_settings.aws_region,
        )

    def client(self, service_name: str, *, region_name: str | None = None) -> Any:
        """Return a cached low-level client for a service and region."""

        resolved_region = region_name or self.region_name
        cache_key = (service_name, resolved_region)

        if cache_key not in self._clients:
            self._clients[cache_key] = self._session.client(
                service_name,
                region_name=resolved_region,
                config=self._client_config,
            )

        return self._clients[cache_key]

    @cached_property
    def identity(self) -> AWSIdentity:
        """Resolve and cache the active caller identity exactly once."""

        response = self.client("sts").get_caller_identity()
        if not isinstance(response, Mapping):
            raise AWSIdentityEvidenceError("response")
        account_id = _required_identity_string(response, "Account")
        caller_arn = _required_identity_string(response, "Arn")
        user_id = _required_identity_string(response, "UserId")
        arn_parts = caller_arn.split(":", maxsplit=5)
        if len(arn_parts) != 6 or arn_parts[0] != "arn" or not arn_parts[1]:
            raise AWSIdentityEvidenceError("Arn")

        return AWSIdentity(
            account_id=account_id,
            caller_arn=caller_arn,
            user_id=user_id,
            partition=arn_parts[1],
        )

    @property
    def account_id(self) -> str:
        """Return the cached AWS account ID."""

        return self.identity.account_id

    @property
    def partition(self) -> str:
        """Return the AWS partition derived from the caller ARN."""

        return self.identity.partition


def _required_identity_string(response: Mapping[str, Any], key: str) -> str:
    """Validate one required STS identity field without echoing its value."""

    if key not in response:
        raise AWSIdentityEvidenceError(key)
    value = response[key]
    if not isinstance(value, str) or not value.strip():
        raise AWSIdentityEvidenceError(key)
    return value
