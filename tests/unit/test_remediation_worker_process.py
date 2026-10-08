"""Separate CLI rejects unsafe configuration without printing input or accessing AWS."""

import logging
import os
from unittest.mock import patch
from uuid import uuid4

import pytest

from app.remediation.worker import main


@pytest.fixture(autouse=True)
def isolated_process_environment(monkeypatch):
    for key in tuple(os.environ):
        if key.startswith("REMEDIATION_WORKER_"):
            monkeypatch.delenv(key)
    old = logging.root.manager.disable
    yield
    logging.disable(old)


@pytest.mark.parametrize("args", [[], ["synthetic-secret"], [str(uuid4()), "synthetic-secret"]])
def test_argument_errors_never_echo_input(args, capsys):
    assert main(args) == 2
    assert capsys.readouterr().out == "WORKER_INVALID_ARGUMENT\n"


def test_default_off_process_never_looks_up_database_credentials_or_application_settings(capsys):
    with (
        patch("app.remediation.worker.create_engine", side_effect=AssertionError("No DB")),
        patch("app.remediation.worker.RemediationWorker", side_effect=AssertionError("No worker")),
        patch("app.config.get_settings", side_effect=AssertionError("No scanner settings")),
    ):
        assert main([str(uuid4())]) == 0
    assert capsys.readouterr().out == "WORKER_DISABLED\n"


@pytest.mark.parametrize("url", ["synthetic-password-invalid-url", "sqlite://"])
def test_enabled_invalid_worker_database_never_constructs_provider(monkeypatch, capsys, url):
    for key, value in {
        "ENABLED": "true",
        "ACCOUNT_ID": "123456789012",
        "REGION": "us-east-1",
        "ROLE_ARN": "arn:aws:iam::123456789012:role/remediation-writer",
        "DATABASE_URL": url,
    }.items():
        monkeypatch.setenv("REMEDIATION_WORKER_" + key, value)
    with patch("app.remediation.worker.RemediationWorker", side_effect=AssertionError("No AWS")):
        assert main([str(uuid4())]) == 1
    output = capsys.readouterr()
    assert output.out in {"WORKER_CONFIGURATION_REJECTED\n", "WORKER_UNAVAILABLE\n"}
    assert output.err == "" and "synthetic-password" not in output.out


def test_configuration_error_does_not_echo_sensitive_settings(monkeypatch, capsys):
    monkeypatch.setenv("REMEDIATION_WORKER_ENABLED", "synthetic-sensitive-value")
    assert main([str(uuid4())]) == 1
    assert capsys.readouterr().out == "WORKER_UNAVAILABLE\n"


def test_worker_process_suppresses_dependency_debug_warning_and_exception_logging(capsys):
    assert main([str(uuid4())]) == 0
    for name in ("botocore.endpoint", "botocore.credentials", "sqlalchemy.engine"):
        logger = logging.getLogger(name)
        logger.debug("synthetic-sensitive-signed-headers")
        logger.warning("synthetic-sensitive-credentials", exc_info=True)
    output = capsys.readouterr()
    assert output.out == "WORKER_DISABLED\n" and output.err == ""
