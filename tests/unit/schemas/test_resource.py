"""Tests for normalized AWS resource contracts."""

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.schemas.resource import NormalizedResource, ResourceScope


def make_resource(**overrides: object) -> NormalizedResource:
    """Build a representative regional resource with optional field overrides."""

    values: dict[str, object] = {
        "account_id": "123456789012",
        "service": "ec2",
        "resource_type": "security-group",
        "aws_resource_id": "sg-0123456789abcdef0",
        "arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
        "name": "application-ingress",
        "scope": ResourceScope.REGIONAL,
        "region": "us-east-1",
        "tags": {"Environment": "test"},
        "configuration": {"vpc_id": "vpc-0123456789abcdef0"},
        "raw_configuration": {"GroupId": "sg-0123456789abcdef0"},
    }
    values.update(overrides)
    return NormalizedResource.model_validate(values)


def test_regional_resource_requires_region() -> None:
    """Regional resources without a concrete region are ambiguous."""

    with pytest.raises(ValidationError, match="regional resources require a region"):
        make_resource(region=None)


def test_global_resource_rejects_region() -> None:
    """A global identity must not inherit the provider's configured region."""

    with pytest.raises(ValidationError, match="global resources must not define a region"):
        make_resource(scope=ResourceScope.GLOBAL, region="us-east-1")


def test_global_resource_accepts_no_region_and_uses_global_identity_scope() -> None:
    """IAM-style resources receive an explicit, stable global identity component."""

    resource = make_resource(
        service="iam",
        resource_type="user",
        aws_resource_id="AIDAEXAMPLE",
        arn="arn:aws:iam::123456789012:user/security-auditor",
        name="security-auditor",
        scope=ResourceScope.GLOBAL,
        region=None,
    )

    assert resource.region is None
    assert resource.identity == (
        "123456789012",
        "iam",
        "user",
        "global",
        "global",
        "AIDAEXAMPLE",
    )


def test_regional_identity_contains_region() -> None:
    """Otherwise-identical native IDs remain distinct across AWS regions."""

    resource = make_resource(region="eu-central-1")

    assert resource.identity == (
        "123456789012",
        "ec2",
        "security-group",
        "regional",
        "eu-central-1",
        "sg-0123456789abcdef0",
    )


def test_resource_serializes_nested_configuration_to_json() -> None:
    """Normalized resources can cross API and persistence boundaries as JSON."""

    created_at = datetime(2026, 9, 2, 12, 30, tzinfo=UTC)
    resource = make_resource(
        configuration={
            "enabled": True,
            "ports": [22, 443],
            "metadata": {"created_at": created_at},
        },
        raw_configuration={"IpPermissions": [], "Description": None},
    )

    payload = json.loads(resource.model_dump_json())

    assert payload["scope"] == "regional"
    assert payload["region"] == "us-east-1"
    assert payload["configuration"]["enabled"] is True
    assert payload["configuration"]["ports"] == [22, 443]
    assert payload["configuration"]["metadata"]["created_at"] == "2026-09-02T12:30:00Z"
    assert payload["raw_configuration"] == {"IpPermissions": [], "Description": None}
