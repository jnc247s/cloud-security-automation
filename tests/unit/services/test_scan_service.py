"""Tests for end-to-end persisted scan orchestration."""

from dataclasses import dataclass

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.models import Finding, Resource, Scan, ScanStatus
from app.rules.engine import RuleEngine
from app.rules.network import PublicSSHRule
from app.rules.registry import RuleRegistry
from app.schemas.inventory import InventorySnapshot
from app.services.scan_service import ScanService
from tests.unit.rules.factories import ACCOUNT_ID, REGION, resource, snapshot


@dataclass
class StubInventoryService:
    inventory_snapshot: InventorySnapshot | None = None
    error: Exception | None = None

    def collect(self) -> InventorySnapshot:
        if self.error is not None:
            raise self.error
        assert self.inventory_snapshot is not None
        return self.inventory_snapshot


def _failing_snapshot() -> InventorySnapshot:
    security_group = resource(
        service="ec2",
        resource_type="security_group",
        aws_resource_id="sg-runner-test",
        configuration={
            "vpc_id": "vpc-runner-test",
            "ingress_rules": [
                {
                    "protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "ipv4_ranges": [{"cidr": "0.0.0.0/0", "description": None}],
                    "ipv6_ranges": [],
                    "prefix_lists": [],
                    "referenced_security_groups": [],
                }
            ],
            "egress_rules": [],
        },
    )
    return snapshot(security_group)


def test_scan_service_persists_successful_run(
    session_factory: sessionmaker[Session],
) -> None:
    engine = RuleEngine(RuleRegistry((PublicSSHRule(),)))
    service = ScanService(
        inventory_service=StubInventoryService(_failing_snapshot()),
        rule_engine=engine,
        session_factory=session_factory,
    )

    result = service.run(account_id=ACCOUNT_ID, region=REGION)

    assert result.status is ScanStatus.COMPLETED
    assert result.resources_evaluated == 1
    assert result.controls_evaluated == 1
    assert result.findings_created == 1
    assert result.findings_resolved == 0
    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 1
        assert session.scalar(select(func.count()).select_from(Resource)) == 1
        assert session.scalar(select(func.count()).select_from(Finding)) == 1


def test_scan_service_records_failure_without_partial_data(
    session_factory: sessionmaker[Session],
) -> None:
    service = ScanService(
        inventory_service=StubInventoryService(error=RuntimeError("collector failed")),
        rule_engine=RuleEngine(RuleRegistry((PublicSSHRule(),))),
        session_factory=session_factory,
    )

    with pytest.raises(RuntimeError, match="collector failed"):
        service.run(account_id=ACCOUNT_ID, region=REGION)

    with session_factory() as session:
        scan = session.scalar(select(Scan))
        assert scan is not None
        assert scan.status is ScanStatus.FAILED
        assert scan.completed_at is not None
        assert session.scalar(select(func.count()).select_from(Resource)) == 0
        assert session.scalar(select(func.count()).select_from(Finding)) == 0
