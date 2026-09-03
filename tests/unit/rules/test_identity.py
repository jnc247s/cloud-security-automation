"""Tests for identity security controls."""

import pytest

from app.rules.base import RuleEvaluationError
from app.rules.identity import IAMUserWithoutMFARule
from app.schemas.finding import ControlCategory, Severity
from app.schemas.resource import ResourceScope
from tests.unit.rules.factories import ACCOUNT_ID, resource, snapshot


def _iam_user(mfa_devices: object, *, user_name: str = "alice"):
    return resource(
        service="iam",
        resource_type="iam_user",
        aws_resource_id=f"AIDA{user_name.upper()}",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:user/{user_name}",
        name=user_name,
        scope=ResourceScope.GLOBAL,
        region=None,
        configuration={
            "path": "/",
            "password_last_used": None,
            "mfa_devices": mfa_devices,
            "access_keys": [],
        },
    )


def test_iam_001_reports_user_with_explicitly_empty_mfa_devices() -> None:
    user = _iam_user([])

    findings = IAMUserWithoutMFARule().evaluate(snapshot(user))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.control_id == "IAM-001"
    assert finding.title == "IAM User Without MFA"
    assert finding.category is ControlCategory.IDENTITY
    assert finding.severity is Severity.MEDIUM
    assert finding.account_id == ACCOUNT_ID
    assert finding.service == "iam"
    assert finding.resource_type == "iam_user"
    assert finding.aws_resource_id == "AIDAALICE"
    assert finding.scope is ResourceScope.GLOBAL
    assert finding.region is None
    assert finding.evidence["user_name"] == "alice"
    assert finding.evidence["mfa_device_count"] == 0
    assert finding.impact
    assert finding.recommendation


def test_iam_001_passes_when_an_mfa_device_is_assigned() -> None:
    user = _iam_user(
        [
            {
                "SerialNumber": f"arn:aws:iam::{ACCOUNT_ID}:mfa/alice",
                "UserName": "alice",
            }
        ]
    )

    assert IAMUserWithoutMFARule().evaluate(snapshot(user)) == ()


def test_iam_001_ignores_unrelated_resource_types() -> None:
    unrelated = resource(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="example-bucket",
        configuration={},
    )

    assert IAMUserWithoutMFARule().evaluate(snapshot(unrelated)) == ()


@pytest.mark.parametrize(
    "configuration",
    [
        {},
        {"mfa_devices": None},
        {"mfa_devices": "definitely-secret-looking-value"},
        {"mfa_devices": {}},
        {"mfa_devices": [{}]},
        {"mfa_devices": [{"SerialNumber": ""}]},
    ],
)
def test_iam_001_rejects_unknown_or_malformed_mfa_facts(
    configuration: dict[str, object],
) -> None:
    user = resource(
        service="iam",
        resource_type="iam_user",
        aws_resource_id="AIDAMALFORMED",
        name="malformed-user",
        scope=ResourceScope.GLOBAL,
        region=None,
        configuration=configuration,
    )

    with pytest.raises(RuleEvaluationError) as error_info:
        IAMUserWithoutMFARule().evaluate(snapshot(user))

    error = error_info.value
    assert error.control_id == "IAM-001"
    assert error.aws_resource_id == "AIDAMALFORMED"
    assert "mfa_devices" in error.fact_path
    assert "definitely-secret-looking-value" not in str(error)
