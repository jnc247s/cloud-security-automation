"""Deterministic, AWS-free scan-result fixtures."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.assessment.controls import build_default_control_catalog
from app.assessment.profiles import DEFAULT_ASSESSMENT_PROFILE, AssessmentProfile
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput
from app.schemas.resource import NormalizedResource, ResourceScope


def scan_bundle(
    *,
    public_ssh: bool | None = True,
    malformed: bool = False,
    observed_at: datetime = datetime(2026, 9, 3, 12, tzinfo=UTC),
    scan_id: UUID | None = None,
    region: str = "us-east-1",
    collection_status: CollectionStatus = CollectionStatus.SUCCEEDED,
    tags: dict[str, str] | None = None,
) -> dict[str, Any]:
    profile_values = DEFAULT_ASSESSMENT_PROFILE.model_dump(exclude={"content_checksum"})
    profile_values.update(profile_id="test-network", enabled_controls=("NET-001",))
    profile = AssessmentProfile.model_validate(profile_values)
    catalog = build_default_control_catalog()
    configuration: dict[str, Any] = {"ingress_rules": [], "egress_rules": []}
    if public_ssh:
        configuration["ingress_rules"] = [
            {
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "ipv4_ranges": [{"cidr": "0.0.0.0/0"}],
                "ipv6_ranges": [],
                "prefix_lists": [],
                "referenced_security_groups": [],
            }
        ]
    if malformed:
        configuration = {}
    resources = (
        ()
        if public_ssh is None
        else (
            NormalizedResource(
                account_id="123456789012",
                service="ec2",
                resource_type="security_group",
                aws_resource_id="sg-history",
                name="history-test",
                scope=ResourceScope.REGIONAL,
                region=region,
                tags=tags or {},
                configuration=configuration,
                raw_configuration={"not_persisted": "raw collector details"},
            ),
        )
    )
    outcomes = (CollectorOutcome(collector_name="security_groups", status=collection_status),)
    snapshot = InventorySnapshot(
        scan_id=scan_id or uuid4(),
        account_id="123456789012",
        requested_region=region,
        collected_at=observed_at,
        collector_outcomes=outcomes,
        resources=resources,
    )
    scope = ScanScopeManifestInput(
        aws_account_id=snapshot.account_id,
        requested_regions=(region,),
        successful_regions=(region,) if collection_status is CollectionStatus.SUCCEEDED else (),
        requested_services=("ec2",),
        requested_collectors=("security_groups",),
        collector_outcomes=outcomes,
        resource_types=("security_group",),
        enabled_controls=profile.enabled_controls,
        assessment_profile_id=profile.profile_id,
        assessment_profile_version=profile.version,
        assessment_profile_checksum=profile.calculate_content_checksum(),
        control_catalog_id=catalog.catalog_id,
        control_catalog_version=catalog.version,
    )
    return {
        "snapshot": snapshot,
        "scope": scope,
        "profile": profile,
        "catalog": catalog,
        "assessments": RuleEngine(build_default_registry()).assess(snapshot, profile),
        "started_at": observed_at - timedelta(minutes=1),
        "completed_at": observed_at + timedelta(minutes=1),
        "scanner_version": "test-build",
    }
