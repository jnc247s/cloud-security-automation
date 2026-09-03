"""Tests for audit-logging security controls."""

import pytest

from app.rules.audit_logging import MissingCloudTrailRule
from app.rules.base import RuleEvaluationError
from app.schemas.finding import ControlCategory, Severity
from app.schemas.resource import ResourceScope
from tests.unit.rules.factories import ACCOUNT_ID, resource, snapshot


def _trail(name: str, is_logging: object):
    return resource(
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=(f"arn:aws:cloudtrail:us-east-1:{ACCOUNT_ID}:trail/{name}"),
        arn=f"arn:aws:cloudtrail:us-east-1:{ACCOUNT_ID}:trail/{name}",
        name=name,
        configuration={
            "home_region": "us-east-1",
            "is_multi_region_trail": True,
            "include_global_service_events": True,
            "is_logging": is_logging,
        },
    )


def test_log_001_reports_account_when_no_trails_were_collected() -> None:
    findings = MissingCloudTrailRule().evaluate(snapshot())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.control_id == "LOG-001"
    assert finding.title == "CloudTrail Missing"
    assert finding.category is ControlCategory.LOGGING
    assert finding.severity is Severity.HIGH
    assert finding.account_id == ACCOUNT_ID
    assert finding.service == "cloudtrail"
    assert finding.resource_type == "aws_account"
    assert finding.aws_resource_id == ACCOUNT_ID
    assert finding.scope is ResourceScope.GLOBAL
    assert finding.region is None
    assert finding.evidence["account_id"] == ACCOUNT_ID
    assert finding.evidence["trail_count"] == 0
    assert finding.evidence["active_trail_count"] == 0
    assert finding.impact
    assert finding.recommendation


def test_log_001_reports_account_once_when_all_trails_are_inactive() -> None:
    findings = MissingCloudTrailRule().evaluate(
        snapshot(_trail("second", False), _trail("first", False))
    )

    assert len(findings) == 1
    assert findings[0].aws_resource_id == ACCOUNT_ID
    assert findings[0].evidence["trail_count"] == 2
    assert findings[0].evidence["active_trail_count"] == 0


def test_log_001_passes_when_any_trail_is_actively_logging() -> None:
    inventory = snapshot(_trail("inactive", False), _trail("active", True))

    assert MissingCloudTrailRule().evaluate(inventory) == ()


def test_log_001_ignores_unrelated_resource_types() -> None:
    unrelated = resource(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="example-bucket",
        configuration={},
    )

    findings = MissingCloudTrailRule().evaluate(snapshot(unrelated))

    assert len(findings) == 1
    assert findings[0].evidence["trail_count"] == 0


@pytest.mark.parametrize("is_logging", [None, "true", 1, [], {}])
def test_log_001_rejects_unknown_or_malformed_logging_status(is_logging: object) -> None:
    malformed = _trail("malformed", is_logging)

    with pytest.raises(RuleEvaluationError) as error_info:
        MissingCloudTrailRule().evaluate(snapshot(malformed))

    error = error_info.value
    assert error.control_id == "LOG-001"
    assert error.aws_resource_id.endswith("trail/malformed")
    assert "is_logging" in error.fact_path
    assert "true" not in str(error)


def test_log_001_does_not_hide_malformed_status_behind_an_active_trail() -> None:
    active = _trail("active", True)
    malformed = resource(
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=f"arn:aws:cloudtrail:us-east-1:{ACCOUNT_ID}:trail/malformed",
        configuration={},
    )

    with pytest.raises(RuleEvaluationError):
        MissingCloudTrailRule().evaluate(snapshot(active, malformed))
