"""Exclusive ECS task credentials and the closed EC2-004 writer adapter.

Not imported or constructed by API/scanner startup. Network methods must only be called by
the separate worker outside SQL transactions. No generic AWS dispatch or credential fallback.
"""

import json
import os
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Protocol

from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import ContainerProvider, CredentialResolver
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    MetadataRetrievalError,
    ReadTimeoutError,
)
from botocore.loaders import Loader
from botocore.session import Session
from botocore.utils import ContainerMetadataFetcher

from app.remediation.worker_config import WorkerScope
from app.remediation.worker_contracts import RegionalObservation, WriteAcknowledgment

_FORBIDDEN_SOURCE_VARIABLES = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_CONFIG_FILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "BOTO_CONFIG",
        "AWS_ROLE_ARN",
        "AWS_ROLE_SESSION_NAME",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_CA_BUNDLE",
        "AWS_DATA_PATH",
    }
)
_RELATIVE_URI = re.compile(r"/v2/credentials/[A-Za-z0-9_-]{1,128}", re.ASCII)
_REQUEST_ID = re.compile(r"[A-Za-z0-9-]{1,128}", re.ASCII)
_TRANSIENT_CODES = frozenset(
    {
        "RequestLimitExceeded",
        "Throttling",
        "ThrottlingException",
        "ServiceUnavailable",
        "InternalError",
        "InternalFailure",
        "RequestTimeout",
    }
)


class WorkerAwsCode(StrEnum):
    DISABLED = "WORKER_DISABLED"
    INVALID_SOURCE = "INVALID_CREDENTIAL_SOURCE"
    SOURCE_UNAVAILABLE = "CREDENTIAL_SOURCE_UNAVAILABLE"
    SCOPE_MISMATCH = "WRITER_SCOPE_MISMATCH"
    READ_TRANSIENT = "READ_TRANSIENT"
    READ_DENIED = "READ_DENIED_OR_UNAVAILABLE"
    INCOMPLETE_RESPONSE = "INCOMPLETE_AWS_RESPONSE"
    WRITE_UNCERTAIN = "WRITE_UNCERTAIN"


class WorkerAwsError(RuntimeError):
    """Fixed classifications only: never retain a provider exception, response or secret."""

    def __init__(self, code: WorkerAwsCode):
        self.code = WorkerAwsCode(code)
        super().__init__(self.code.value)


class RemediationAWS(Protocol):
    """Only these fixed operations are available to the worker."""

    def verify_identity(self) -> None: ...
    def observe(self) -> RegionalObservation: ...
    def enable(self) -> WriteAcknowledgment: ...
    def close(self) -> None: ...


def _success(response) -> Mapping:
    if not isinstance(response, Mapping):
        raise WorkerAwsError(WorkerAwsCode.INCOMPLETE_RESPONSE)
    metadata = response.get("ResponseMetadata")
    if (
        not isinstance(metadata, Mapping)
        or type(metadata.get("HTTPStatusCode")) is not int
        or metadata["HTTPStatusCode"] != 200
    ):
        raise WorkerAwsError(WorkerAwsCode.INCOMPLETE_RESPONSE)
    return response


def _read(call):
    try:
        return _success(call())
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code")
        classification = (
            WorkerAwsCode.READ_TRANSIENT if code in _TRANSIENT_CODES else WorkerAwsCode.READ_DENIED
        )
        raise WorkerAwsError(classification) from None
    except (ConnectTimeoutError, ReadTimeoutError, EndpointConnectionError):
        raise WorkerAwsError(WorkerAwsCode.READ_TRANSIENT) from None
    except BotoCoreError:
        raise WorkerAwsError(WorkerAwsCode.READ_DENIED) from None


class _WorkloadSession(Session):
    """Never read host AWS configuration/credentials, even implicitly during client creation."""

    @property
    def full_config(self):
        return {"profiles": {}, "sso_sessions": {}, "services": {}}

    def get_scoped_config(self):
        return {}


class _SafeContainerFetcher(ContainerMetadataFetcher):
    """The SDK's ordinary metadata error can contain raw HTTP body; replace that boundary."""

    def _get_response(self, full_url, headers, timeout):
        try:
            response = self._session.send(AWSRequest(method="GET", url=full_url).prepare())
            if response.status_code != 200 or len(response.content) > 65536:
                raise ValueError("invalid credential response")
            value = json.loads(response.content)
            if not isinstance(value, dict) or any(
                not isinstance(value.get(key), str) or not value[key].strip()
                for key in ("AccessKeyId", "SecretAccessKey", "Token", "Expiration")
            ):
                raise ValueError("incomplete credential response")
            return value
        except (BotoCoreError, ValueError, TypeError, UnicodeError):
            raise MetadataRetrievalError(error_msg="task credential source unavailable") from None


class EbsDefaultWriter:
    """Internal closed adapter. Production construction is exclusively from_ecs()."""

    def __init__(self, scope: WorkerScope, *, sts, ec2):
        self.scope = WorkerScope.model_validate(scope.model_dump())
        if not self.scope.enabled:
            raise WorkerAwsError(WorkerAwsCode.DISABLED)
        self._sts = sts
        self._ec2 = ec2

    @classmethod
    def from_ecs(cls, scope: WorkerScope) -> "EbsDefaultWriter":
        scope = WorkerScope.model_validate(scope.model_dump())
        if not scope.enabled:
            raise WorkerAwsError(WorkerAwsCode.DISABLED)
        names = {name.upper() for name in os.environ}
        if names & _FORBIDDEN_SOURCE_VARIABLES or any(
            name == "AWS_ENDPOINT_URL" or name.startswith("AWS_ENDPOINT_URL_") for name in names
        ):
            raise WorkerAwsError(WorkerAwsCode.INVALID_SOURCE)
        relative = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        if relative is None or _RELATIVE_URI.fullmatch(relative) is None:
            raise WorkerAwsError(WorkerAwsCode.INVALID_SOURCE)
        # Pass a closed immutable source snapshot, not the mutable process environment. The
        # resolver has ONE provider; absence/failure can never fall through to scanner/IMDS.
        session = _WorkloadSession()
        # Models and endpoints are trusted installed SDK data, never ~/.aws/models or
        # AWS_DATA_PATH. A custom model could redirect an otherwise closed operation.
        session.register_component(
            "data_loader",
            Loader(
                extra_search_paths=[Loader.BUILTIN_DATA_PATH], include_default_search_paths=False
            ),
        )
        session.set_config_variable("sts_regional_endpoints", "regional")
        session.set_config_variable("csm_enabled", False)  # CSM can emit access-key identifiers.
        session.register_component(
            "credential_provider",
            CredentialResolver(
                [
                    ContainerProvider(
                        environ={"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": relative},
                        fetcher=_SafeContainerFetcher(),
                    )
                ]
            ),
        )
        config = Config(
            defaults_mode="legacy",  # No smart-defaults IMDS Region probing.
            region_name=scope.region,
            signature_version="v4",
            connect_timeout=2,
            read_timeout=5,
            retries={"mode": "standard", "total_max_attempts": 1},
            ignore_configured_endpoint_urls=True,
            use_fips_endpoint=False,
            use_dualstack_endpoint=False,
            proxies={},
        )
        sts = None
        ec2 = None
        try:
            credentials = session.get_credentials()
            if credentials is None or credentials.method != "container-role":
                raise WorkerAwsError(WorkerAwsCode.INVALID_SOURCE)
            sts = session.create_client("sts", region_name=scope.region, config=config)
            ec2 = session.create_client("ec2", region_name=scope.region, config=config)
            return cls(scope, sts=sts, ec2=ec2)
        except (BotoCoreError, ValueError, TypeError, KeyError):
            if sts is not None:
                sts.close()
            if ec2 is not None:
                ec2.close()
            raise WorkerAwsError(WorkerAwsCode.SOURCE_UNAVAILABLE) from None

    def verify_identity(self) -> None:
        response = _read(self._sts.get_caller_identity)
        arn = response.get("Arn")
        user_id = response.get("UserId")
        parts = self.scope.role_arn.split(":")
        role_name = parts[5].rsplit("/", 1)[-1]
        prefix = f"arn:{parts[1]}:sts::{self.scope.account_id}:assumed-role/{role_name}/"
        if (
            response.get("Account") != self.scope.account_id
            or not isinstance(arn, str)
            or not arn.startswith(prefix)
            or re.fullmatch(r"[A-Za-z0-9+=,.@_-]{2,64}", arn[len(prefix) :], re.ASCII) is None
            or not isinstance(user_id, str)
            or not user_id.strip()
            or self._sts.meta.region_name != self.scope.region
            or self._ec2.meta.region_name != self.scope.region
        ):
            raise WorkerAwsError(WorkerAwsCode.SCOPE_MISMATCH)

    def observe(self) -> RegionalObservation:
        # Never coerce bools or conflate a failed/malformed key read with expected absence.
        encryption = _read(self._ec2.get_ebs_encryption_by_default).get("EbsEncryptionByDefault")
        if type(encryption) is not bool:
            raise WorkerAwsError(WorkerAwsCode.INCOMPLETE_RESPONSE)
        key = _read(self._ec2.get_ebs_default_kms_key_id).get("KmsKeyId")
        if key is not None and (not isinstance(key, str) or not key.strip()):
            raise WorkerAwsError(WorkerAwsCode.INCOMPLETE_RESPONSE)
        return RegionalObservation(
            encryption_by_default=encryption,
            default_kms_key_id=key,
            default_kms_key_expected_absence=key is None,
        )

    def enable(self) -> WriteAcknowledgment:
        # Exactly one invocation, no retry decorator or SDK retry. The caller must have
        # durably committed WRITE_INTENT and rechecked its deadline immediately before this.
        try:
            response = _success(self._ec2.enable_ebs_encryption_by_default())
            request_id = response["ResponseMetadata"].get("RequestId")
            if response.get("EbsEncryptionByDefault") is not True or (
                not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None
            ):
                raise ValueError("incomplete write receipt")
            return WriteAcknowledgment(request_id=request_id)
        except (BotoCoreError, ClientError, WorkerAwsError, ValueError, TypeError, KeyError):
            raise WorkerAwsError(WorkerAwsCode.WRITE_UNCERTAIN) from None

    def close(self) -> None:
        self._sts.close()
        self._ec2.close()
