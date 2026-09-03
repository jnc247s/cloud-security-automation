"""Offline end-to-end test for the complete Sprint 2 control registry."""

import json

from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.finding import Severity
from app.schemas.resource import ResourceScope
from tests.unit.rules.factories import ACCOUNT_ID, REGION, resource, snapshot


def _failing_resources():
    security_group = resource(
        service="ec2",
        resource_type="security_group",
        aws_resource_id="sg-public-admin",
        name="public-admin",
        configuration={
            "vpc_id": "vpc-example",
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "ipv4_ranges": [{"cidr": "0.0.0.0/0", "description": "public SSH"}],
                    "ipv6_ranges": [],
                    "prefix_lists": [],
                    "referenced_security_groups": [],
                },
                {
                    "protocol": "tcp",
                    "from_port": 3389,
                    "to_port": 3389,
                    "ipv4_ranges": [],
                    "ipv6_ranges": [{"cidr": "::/0", "description": "public RDP"}],
                    "prefix_lists": [],
                    "referenced_security_groups": [],
                },
            ],
            "egress_rules": [],
        },
    )
    bucket = resource(
        service="s3",
        resource_type="s3_bucket",
        aws_resource_id="unencrypted-example",
        arn="arn:aws:s3:::unencrypted-example",
        name="unencrypted-example",
        configuration={"default_encryption": None},
    )
    user = resource(
        service="iam",
        resource_type="iam_user",
        aws_resource_id="AIDAEXAMPLE",
        arn=f"arn:aws:iam::{ACCOUNT_ID}:user/example",
        name="example",
        scope=ResourceScope.GLOBAL,
        region=None,
        configuration={"mfa_devices": []},
    )
    inactive_trail = resource(
        service="cloudtrail",
        resource_type="cloudtrail_trail",
        aws_resource_id=(f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail/inactive"),
        name="inactive",
        configuration={"is_logging": False},
    )
    return security_group, bucket, user, inactive_trail


def test_default_rule_engine_produces_exact_deterministic_fixture_findings() -> None:
    resources = _failing_resources()
    engine = RuleEngine(build_default_registry())

    findings = engine.evaluate(snapshot(*resources))
    reversed_findings = engine.evaluate(snapshot(*reversed(resources)))

    assert tuple(finding.control_id for finding in findings) == (
        "IAM-001",
        "LOG-001",
        "NET-001",
        "NET-002",
        "S3-900",
    )
    assert tuple(finding.severity for finding in findings) == (
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.HIGH,
        Severity.HIGH,
        Severity.MEDIUM,
    )
    assert tuple(finding.identity for finding in findings) == tuple(
        sorted(finding.identity for finding in findings)
    )
    assert json.dumps(
        [finding.model_dump(mode="json") for finding in findings],
        sort_keys=True,
    ) == json.dumps(
        [finding.model_dump(mode="json") for finding in reversed_findings],
        sort_keys=True,
    )

    findings_by_control = {finding.control_id: finding for finding in findings}
    assert findings_by_control["IAM-001"].evidence["mfa_device_count"] == 0
    assert findings_by_control["LOG-001"].evidence["trail_count"] == 1
    assert findings_by_control["LOG-001"].evidence["active_trail_count"] == 0
    assert findings_by_control["NET-001"].evidence["target_port"] == 22
    assert findings_by_control["NET-002"].evidence["target_port"] == 3389
    assert findings_by_control["S3-900"].evidence["default_encryption"] is None
