"""End-to-end scan orchestration with durable lifecycle state."""

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from app.database.session import SessionLocal
from app.models import ScanStatus
from app.rules.engine import RuleEngine
from app.schemas.inventory import InventorySnapshot
from app.services.scan_persistence import ScanPersistenceService


class InventorySource(Protocol):
    """Minimal inventory dependency required by the scan orchestrator."""

    def collect(self) -> InventorySnapshot:
        """Return one complete normalized inventory snapshot."""


@dataclass(frozen=True, slots=True)
class ScanRunResult:
    """Safe summary returned after a persisted scan completes."""

    scan_uuid: UUID
    status: ScanStatus
    resources_evaluated: int
    controls_evaluated: int
    findings_created: int
    findings_resolved: int


class ScanService:
    """Collect, evaluate, and persist a scan while recording failure state."""

    def __init__(
        self,
        inventory_service: InventorySource,
        rule_engine: RuleEngine,
        session_factory: sessionmaker[Session] = SessionLocal,
    ) -> None:
        self.inventory_service = inventory_service
        self.rule_engine = rule_engine
        self.session_factory = session_factory

    def run(self, *, account_id: str, region: str) -> ScanRunResult:
        """Run one complete scan without leaving partial resources or findings."""

        with self.session_factory.begin() as session:
            scan = ScanPersistenceService(session).queue_scan(
                account_id=account_id,
                region=region,
            )
            scan_uuid = scan.scan_uuid

        with self.session_factory.begin() as session:
            ScanPersistenceService(session).start_scan(scan_uuid)

        try:
            snapshot = self.inventory_service.collect()
            candidates = self.rule_engine.evaluate(snapshot)
            control_ids = tuple(rule.control_id for rule in self.rule_engine.registry.rules)

            with self.session_factory.begin() as session:
                completed_scan = ScanPersistenceService(session).complete_scan(
                    scan_uuid,
                    snapshot=snapshot,
                    candidates=candidates,
                    evaluated_control_ids=control_ids,
                )
                result = ScanRunResult(
                    scan_uuid=completed_scan.scan_uuid,
                    status=completed_scan.status,
                    resources_evaluated=completed_scan.resources_evaluated,
                    controls_evaluated=completed_scan.controls_evaluated,
                    findings_created=completed_scan.findings_created,
                    findings_resolved=completed_scan.findings_resolved,
                )
        except Exception:
            with self.session_factory.begin() as session:
                ScanPersistenceService(session).fail_scan(scan_uuid)
            raise

        return result
