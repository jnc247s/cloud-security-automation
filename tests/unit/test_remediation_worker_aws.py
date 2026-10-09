"""Offline closed writer/scope/credential boundaries, including actual SDK retry behavior."""

import io
import json
import logging
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from botocore.awsrequest import AWSResponse
from botocore.exceptions import ClientError, MetadataRetrievalError, ReadTimeoutError
from botocore.stub import Stubber
from pydantic import ValidationError

from app.remediation.worker_aws import (
    EbsDefaultWriter,
    WorkerAwsCode,
    WorkerAwsError,
    _SafeContainerFetcher,
    _WorkloadSession,
)
from app.remediation.worker_config import WorkerScope, WorkerSettings

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/security/remediation-worker"
SCOPE = WorkerScope(enabled=True, account_id=ACCOUNT, region="us-east-1", role_arn=ROLE)
METADATA = {"HTTPStatusCode": 200, "RequestId": "00000000-0000-0000-0000-000000000001"}


@pytest.fixture
def isolated_aws_environment(monkeypatch):
    # Clear variable names without exposing ambient values or loading any credential file.
    import os

    for name in tuple(os.environ):
        if (
            name.upper().startswith(("AWS_", "REMEDIATION_WORKER_"))
            or name.upper() == "BOTO_CONFIG"
        ):
            monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/offline-test")


def client(operation_responses=None):
    value = Mock()
    value.meta = SimpleNamespace(region_name="us-east-1")
    for name, response in (operation_responses or {}).items():
        getattr(value, name).return_value = response
    return value


def writer(*, identity=None, encryption=False, key="key-id"):
    identity = identity or {
        "Account": ACCOUNT,
        "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/remediation-worker/session",
        "UserId": "ROLEID:session",
        "ResponseMetadata": METADATA,
    }
    sts = client({"get_caller_identity": identity})
    ec2 = client(
        {
            "get_ebs_encryption_by_default": {
                "EbsEncryptionByDefault": encryption,
                "ResponseMetadata": METADATA,
            },
            "get_ebs_default_kms_key_id": {"KmsKeyId": key, "ResponseMetadata": METADATA},
            "enable_ebs_encryption_by_default": {
                "EbsEncryptionByDefault": True,
                "ResponseMetadata": METADATA,
            },
        }
    )
    return EbsDefaultWriter(SCOPE, sts=sts, ec2=ec2)


def test_worker_defaults_off_without_reading_application_or_scanner_settings(
    isolated_aws_environment, monkeypatch
):
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("AWS_PROFILE", "read-only-scanner")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///not-the-worker.db")
    monkeypatch.setenv("REMEDIATION_ADMISSION_ENABLED", "true")
    configured = WorkerSettings()
    assert configured.scope == WorkerScope()
    assert configured.database_url is None
    with pytest.raises(WorkerAwsError, match="WORKER_DISABLED"):
        EbsDefaultWriter.from_ecs(configured.scope)


@pytest.mark.parametrize("missing", ["account_id", "region", "role_arn"])
def test_enabled_scope_requires_every_worker_setting(missing):
    values = SCOPE.model_dump()
    values.pop(missing)
    with pytest.raises(ValidationError, match="explicit account, Region and expected role"):
        WorkerScope(**values)


@pytest.mark.parametrize("value", ["true", 1, "yes"])
def test_worker_scope_does_not_coerce_internal_enablement(value):
    with pytest.raises(ValidationError):
        WorkerScope(**{**SCOPE.model_dump(), "enabled": value})


@pytest.mark.parametrize(
    "changes",
    [
        {"account_id": "999999999999"},
        {"region": "cn-north-1"},
        {"region": "us-gov-west-1"},
        {"account_id": "１２３４５６７８９０１２"},
        {"role_arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/remediation-worker/session"},
        {"role_arn": f"arn:aws:iam::{ACCOUNT}:user/remediation-worker"},
        {"region": "https://endpoint.example.test"},
        {"role_arn": "secret-unvalidated-input"},
        {"region": "us-east-1 "},
    ],
)
def test_mismatched_or_malformed_scope_is_rejected_without_echoing_input(changes):
    with pytest.raises(ValidationError) as error:
        WorkerScope(**{**SCOPE.model_dump(), **changes})
    assert "secret-unvalidated-input" not in str(error.value)


def test_enabled_settings_require_separate_database_url(isolated_aws_environment):
    with pytest.raises(ValidationError, match="own database URL"):
        WorkerSettings(**SCOPE.model_dump())


@pytest.mark.parametrize(
    "name",
    [
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
        "AWS_ENDPOINT_URL",
        "AWS_ENDPOINT_URL_EC2",
        "AWS_ENDPOINT_URL_STS",
        "AWS_ENDPOINT_URL_OTHER",
        "AWS_CA_BUNDLE",
        "AWS_DATA_PATH",
    ],
)
@pytest.mark.parametrize("value", ["", "secret-never-print"])
def test_forbidden_sources_rejected_before_any_credential_lookup(
    isolated_aws_environment, monkeypatch, name, value
):
    monkeypatch.setenv(name, value)
    load = Mock(side_effect=AssertionError("No credential lookup permitted"))
    monkeypatch.setattr("app.remediation.worker_aws._WorkloadSession", load)
    with pytest.raises(WorkerAwsError) as error:
        EbsDefaultWriter.from_ecs(SCOPE)
    assert error.value.code is WorkerAwsCode.INVALID_SOURCE
    assert "secret-never-print" not in str(error.value)
    load.assert_not_called()


@pytest.mark.parametrize(
    "uri",
    [
        None,
        "",
        "http://localhost/credentials",
        "//host/credentials",
        "/../credentials",
        "/v2/credentials/abc?token=secret",
        "/v2/credentials/abc#fragment",
        "/v2/credentials/abc/extra",
        "/v2/credentials/%2fescape",
        "/v2/credentials/ abc",
    ],
)
def test_invalid_ecs_uri_fails_before_lookup(isolated_aws_environment, monkeypatch, uri):
    if uri is None:
        monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    else:
        monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", uri)
    load = Mock(side_effect=AssertionError("No credential lookup permitted"))
    monkeypatch.setattr("app.remediation.worker_aws._WorkloadSession", load)
    with pytest.raises(WorkerAwsError, match="INVALID_CREDENTIAL_SOURCE"):
        EbsDefaultWriter.from_ecs(SCOPE)
    load.assert_not_called()


def factory(isolated_aws_environment, monkeypatch):
    payload = json.dumps(
        {
            "AccessKeyId": "offline-test-access-key",
            "SecretAccessKey": "offline-test-secret-key",
            "Token": "offline-test-session-token",
            "Expiration": "2099-01-01T00:00:00Z",
        }
    ).encode()
    transport = Mock(return_value=SimpleNamespace(status_code=200, content=payload))
    monkeypatch.setattr("botocore.httpsession.URLLib3Session.send", transport)
    # Fail if SDK client construction attempts to read host profiles/configuration.
    monkeypatch.setattr(
        "botocore.configloader.load_config", Mock(side_effect=AssertionError("file"))
    )
    monkeypatch.setattr(
        "botocore.configloader.raw_config_parse", Mock(side_effect=AssertionError("file"))
    )
    create_client = _WorkloadSession.create_client

    def checked_client(session, service_name, **kwargs):
        from botocore.loaders import Loader

        assert session.get_component("data_loader").search_paths == [Loader.BUILTIN_DATA_PATH]
        assert session.get_config_variable("sts_regional_endpoints") == "regional"
        assert session.get_config_variable("csm_enabled") is False
        assert kwargs["config"].ignore_configured_endpoint_urls is True
        assert kwargs["config"].defaults_mode == "legacy"
        # Even if an endpoint override appears after the initial source check, the SDK must
        # route to its normal fixed AWS endpoint. No transport occurs during construction.
        monkeypatch.setenv("AWS_ENDPOINT_URL", "https://forbidden.example.test")
        monkeypatch.setenv("AWS_DATA_PATH", "forbidden-model-path")
        monkeypatch.setenv("AWS_STS_REGIONAL_ENDPOINTS", "legacy")
        monkeypatch.setenv("AWS_CSM_ENABLED", "true")
        monkeypatch.setenv("AWS_CSM_HOST", "forbidden.example.test")
        monkeypatch.setenv("AWS_DEFAULTS_MODE", "auto")
        client = create_client(session, service_name, **kwargs)
        assert session._get_internal_component("monitor") is None
        return client

    monkeypatch.setattr(_WorkloadSession, "create_client", checked_client)
    value = EbsDefaultWriter.from_ecs(SCOPE)
    assert transport.call_count == 1
    assert transport.call_args.args[0].url == "http://169.254.170.2/v2/credentials/offline-test"
    assert value._sts.meta.region_name == value._ec2.meta.region_name == "us-east-1"
    for sdk in (value._sts, value._ec2):
        assert sdk.meta.config.retries == {"mode": "standard", "total_max_attempts": 1}
        assert sdk.meta.config.connect_timeout == 2 and sdk.meta.config.read_timeout == 5
        assert sdk.meta.config.proxies == {}
    assert value._ec2.meta.endpoint_url == "https://ec2.us-east-1.amazonaws.com"
    assert value._sts.meta.endpoint_url == "https://sts.us-east-1.amazonaws.com"
    return value


def test_real_factory_uses_exclusive_task_source_and_fixed_clients(
    isolated_aws_environment, monkeypatch
):
    value = factory(isolated_aws_environment, monkeypatch)
    with Stubber(value._sts) as sts, Stubber(value._ec2) as ec2:
        for _ in range(2):
            sts.add_response("get_caller_identity", writer()._sts.get_caller_identity(), {})
        ec2.add_response(
            "get_ebs_encryption_by_default",
            {
                "EbsEncryptionByDefault": False,
                "ResponseMetadata": METADATA,
            },
            {},
        )
        ec2.add_response(
            "get_ebs_default_kms_key_id", {"KmsKeyId": "key-id", "ResponseMetadata": METADATA}, {}
        )
        ec2.add_response(
            "enable_ebs_encryption_by_default",
            {
                "EbsEncryptionByDefault": True,
                "ResponseMetadata": METADATA,
            },
            {},
        )
        value.verify_identity()
        value.verify_identity()  # Fresh STS each time, no scanner-style cached identity.
        assert value.observe().default_kms_key_id == "key-id"
        assert value.enable().request_id == METADATA["RequestId"]
        sts.assert_no_pending_responses()
        ec2.assert_no_pending_responses()
    value.close()


def test_actual_sdk_write_timeout_cannot_retry_transport(isolated_aws_environment, monkeypatch):
    value = factory(isolated_aws_environment, monkeypatch)
    send = Mock(side_effect=ReadTimeoutError(endpoint_url="https://ec2.us-east-1.amazonaws.com"))
    monkeypatch.setattr(value._ec2._endpoint.http_session, "send", send)
    with pytest.raises(WorkerAwsError, match="WRITE_UNCERTAIN"):
        value.enable()
    assert send.call_count == 1
    value.close()


def test_actual_sdk_write_service_error_cannot_retry_transport(
    isolated_aws_environment, monkeypatch
):
    value = factory(isolated_aws_environment, monkeypatch)
    body = (
        b"<Response><Errors><Error><Code>RequestLimitExceeded</Code>"
        b"<Message>secret-provider-body</Message></Error></Errors>"
        b"<RequestID>id</RequestID></Response>"
    )

    class Raw(io.BytesIO):
        def stream(self, amt=1024, decode_content=False):
            yield self.read()

    send = Mock(side_effect=lambda request: AWSResponse(request.url, 503, {}, Raw(body)))
    monkeypatch.setattr(value._ec2._endpoint.http_session, "send", send)
    with pytest.raises(WorkerAwsError) as error:
        value.enable()
    assert error.value.code is WorkerAwsCode.WRITE_UNCERTAIN
    assert "secret-provider-body" not in str(error.value)
    assert send.call_count == 1
    value.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"Account": "999999999999"},
        {"Account": 123456789012},
        {"Arn": None},
        {"Arn": f"arn:aws:iam::{ACCOUNT}:user/remediation-worker"},
        {"Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/wrong-role/session"},
        {"Arn": f"arn:aws-cn:sts::{ACCOUNT}:assumed-role/remediation-worker/session"},
        {"Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/remediation-worker/session/extra"},
        {"UserId": None},
        {"UserId": ""},
    ],
)
def test_fresh_identity_mismatch_never_calls_ec2(changes):
    value = writer()
    value._sts.get_caller_identity.return_value.update(changes)
    with pytest.raises(WorkerAwsError, match="WRITER_SCOPE_MISMATCH"):
        value.verify_identity()
    value._ec2.get_ebs_encryption_by_default.assert_not_called()
    value._ec2.enable_ebs_encryption_by_default.assert_not_called()


def test_client_region_mismatch_blocks_identity():
    value = writer()
    value._ec2.meta.region_name = "us-west-2"
    with pytest.raises(WorkerAwsError, match="WRITER_SCOPE_MISMATCH"):
        value.verify_identity()


@pytest.mark.parametrize("encryption", [None, 0, 1, "false", "true", [], {}])
def test_encryption_read_requires_actual_boolean(encryption):
    value = writer(encryption=encryption)
    with pytest.raises(WorkerAwsError, match="INCOMPLETE_AWS_RESPONSE"):
        value.observe()
    value._ec2.get_ebs_default_kms_key_id.assert_not_called()
    value._ec2.enable_ebs_encryption_by_default.assert_not_called()


@pytest.mark.parametrize(
    "key", [None, "key-id", f"arn:aws:kms:us-east-1:{ACCOUNT}:key/example", " key-id "]
)
def test_complete_kms_context_preserves_exact_existing_contract(key):
    observation = writer(key=key).observe()
    assert observation.default_kms_key_id == key
    assert observation.default_kms_key_expected_absence is (key is None)


def test_successful_absent_kms_field_is_expected_absence():
    value = writer()
    value._ec2.get_ebs_default_kms_key_id.return_value = {"ResponseMetadata": METADATA}
    assert value.observe().default_kms_key_expected_absence is True


@pytest.mark.parametrize("key", ["", " ", 1, False, [], {}])
def test_malformed_key_is_not_expected_absence(key):
    with pytest.raises(WorkerAwsError, match="INCOMPLETE_AWS_RESPONSE"):
        writer(key=key).observe()


@pytest.mark.parametrize("operation", ["get_caller_identity", "get_ebs_default_kms_key_id"])
@pytest.mark.parametrize(
    "code, classification",
    [
        ("Throttling", WorkerAwsCode.READ_TRANSIENT),
        ("AccessDenied", WorkerAwsCode.READ_DENIED),
        ("ExpiredToken", WorkerAwsCode.READ_DENIED),
    ],
)
def test_read_errors_are_sanitized_and_not_complete_absence(operation, code, classification):
    value = writer()
    sdk = value._sts if operation == "get_caller_identity" else value._ec2
    getattr(sdk, operation).side_effect = ClientError(
        {
            "Error": {"Code": code, "Message": "secret-provider-body"},
            "ResponseMetadata": {"HTTPStatusCode": 403},
        },
        operation,
    )
    with pytest.raises(WorkerAwsError) as error:
        value.verify_identity() if operation == "get_caller_identity" else value.observe()
    assert error.value.code is classification
    assert "secret-provider-body" not in str(error.value)


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        {},
        {"ResponseMetadata": {}},
        {"ResponseMetadata": {"HTTPStatusCode": True}},
        {"ResponseMetadata": {"HTTPStatusCode": "200"}},
        {"ResponseMetadata": {"HTTPStatusCode": 500}},
    ],
)
def test_missing_or_non_success_metadata_cannot_be_complete_evidence(response):
    value = writer()
    value._ec2.get_ebs_default_kms_key_id.return_value = response
    with pytest.raises(WorkerAwsError, match="INCOMPLETE_AWS_RESPONSE"):
        value.observe()


@pytest.mark.parametrize(
    "encryption, request_id",
    [
        (False, "id"),
        (1, "id"),
        ("true", "id"),
        (None, "id"),
        (True, None),
        (True, ""),
        (True, "sensitive\nheader"),
        (True, "x" * 129),
    ],
)
def test_malformed_write_receipt_is_uncertain_not_no_effect(encryption, request_id):
    value = writer()
    value._ec2.enable_ebs_encryption_by_default.return_value = {
        "EbsEncryptionByDefault": encryption,
        "ResponseMetadata": {**METADATA, "RequestId": request_id},
    }
    with pytest.raises(WorkerAwsError, match="WRITE_UNCERTAIN"):
        value.enable()
    value._ec2.enable_ebs_encryption_by_default.assert_called_once_with()


@pytest.mark.parametrize(
    "status, body",
    [
        (500, b"secret-body"),
        (200, b"secret-invalid-json"),
        (200, b"[]"),
        (200, b"{}"),
        (200, b"\xff"),
        (200, b"x" * 65537),
    ],
    ids=["http-error", "invalid-json", "list", "missing-fields", "invalid-utf8", "oversized"],
)
def test_metadata_errors_never_log_or_echo_body(status, body, caplog):
    transport = Mock()
    transport.send.return_value = SimpleNamespace(status_code=status, content=body)
    fetcher = _SafeContainerFetcher(session=transport, sleep=lambda _: None)
    caplog.set_level(logging.DEBUG, logger="botocore.credentials")
    caplog.set_level(logging.DEBUG, logger="botocore.utils")
    with pytest.raises(MetadataRetrievalError) as error:
        fetcher.retrieve_full_uri("http://169.254.170.2/v2/credentials/offline-test")
    assert "secret-body" not in str(error.value) + caplog.text
    assert "secret-invalid-json" not in str(error.value) + caplog.text
    assert transport.send.call_count == 3  # Bounded metadata READ retries, never write retries.
