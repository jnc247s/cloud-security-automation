"""Application service for creating and querying asynchronous scans."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app import __version__
from app.assessment.controls import build_default_control_catalog
from app.assessment.profiles import create_default_assessment_profile
from app.config import Settings, get_settings
from app.database.catalogs import ensure_assessment_profile, ensure_control_catalog
from app.database.persistence import append_audit_event, fail_pending_scan
from app.models import AuditEvent, Scan
from app.models.enums import AuditEventType, ScanStatus
from app.schemas.scan import (
    ScanCreateRequest,
    ScanDetail,
    ScanFailure,
    ScanListResponse,
    ScanScope,
    ScanSummary,
)
from app.services.errors import EntityNotFoundError

if TYPE_CHECKING:
    from app.services.scan_executor import ScanExecutor

REQUESTED_SERVICES = ("cloudtrail", "ec2", "iam", "s3")
_GENERIC_EXECUTION_FAILURE = ScanFailure(
    code="SCAN_EXECUTION_FAILED",
    message="Scan execution failed before results could be persisted.",
)


class ScanSubmissionError(RuntimeError):
    """A durable scan could not be submitted to its configured executor."""

    def __init__(self, scan_id: UUID) -> None:
        self.scan_id = scan_id
        super().__init__(f"scan {scan_id} could not be submitted")


class ScanService:
    """Own scan transactions and expose API-ready historical projections."""

    def __init__(self, session: Session, settings: Settings | None = None) -> None:
        self.session = session
        self.settings = settings or get_settings()

    def start_scan(
        self,
        request: ScanCreateRequest,
        executor: ScanExecutor,
        *,
        actor_id: str,
    ) -> ScanDetail:
        """Persist a RUNNING identity, commit it, then submit nonblocking work."""

        try:
            scan = self._create_pending_scan(request, actor_id=actor_id)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

        try:
            executor.submit(scan.scan_id)
        except Exception as error:
            self.session.rollback()
            try:
                fail_pending_scan(
                    self.session,
                    scan_id=scan.scan_id,
                    completed_at=datetime.now(UTC),
                    failure_code="EXECUTOR_SUBMISSION_FAILED",
                    failure_message="The configured executor rejected this scan request.",
                )
                self.session.commit()
            except Exception:
                self.session.rollback()
            raise ScanSubmissionError(scan.scan_id) from error
        return self.get_scan(scan.scan_id)

    def _create_pending_scan(self, request: ScanCreateRequest, *, actor_id: str) -> Scan:
        if not actor_id.strip():
            raise ValueError("audit actor must not be blank")
        region = request.region or self.settings.aws_region
        profile = create_default_assessment_profile(
            required_tags=self.settings.required_tag_names,
            stale_key_days=self.settings.stale_access_key_days,
        )
        catalog = build_default_control_catalog()
        ensure_assessment_profile(self.session, profile)
        ensure_control_catalog(self.session, catalog)
        started_at = datetime.now(UTC)
        scan = Scan(
            scan_id=uuid4(),
            aws_account_id=None,
            requested_regions=[region],
            successful_regions=[],
            requested_services=list(REQUESTED_SERVICES),
            successful_collectors=[],
            started_at=started_at,
            completed_at=None,
            status=ScanStatus.RUNNING,
            scanner_version=__version__,
            control_catalog_id=catalog.catalog_id,
            control_catalog_version=catalog.version,
            assessment_profile_id=profile.profile_id,
            assessment_profile_version=profile.version,
            assessment_profile_checksum=profile.calculate_content_checksum(),
            inventory_sha256=None,
            result_checksum=None,
        )
        self.session.add(scan)
        self.session.flush()
        append_audit_event(
            self.session,
            AuditEventType.SCAN_STARTED,
            "scan",
            scan.scan_id,
            started_at,
            actor_type="authenticated_user",
            actor_id=actor_id,
            metadata={"requested_regions": [region]},
        )
        return scan

    def list_scans(self, *, limit: int, offset: int) -> ScanListResponse:
        """Return scans newest-first with deterministic offset pagination."""

        total = self.session.scalar(select(func.count()).select_from(Scan)) or 0
        scans = tuple(
            self.session.scalars(
                select(Scan)
                .order_by(Scan.started_at.desc(), Scan.scan_id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        failures = self._failure_events(scan.scan_id for scan in scans)
        return ScanListResponse(
            items=tuple(self._summary(scan, failures.get(scan.scan_id)) for scan in scans),
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_scan(self, scan_id: UUID) -> ScanDetail:
        """Return one scan with exact scope and sanitized terminal failure data."""

        scan = self.session.scalar(
            select(Scan).where(Scan.scan_id == scan_id).options(selectinload(Scan.scope_manifest))
        )
        if scan is None:
            raise EntityNotFoundError("scan", scan_id)
        failure_event = self._failure_events((scan.scan_id,)).get(scan.scan_id)
        summary = self._summary(scan, failure_event)
        scope = scan.scope_manifest
        return ScanDetail(
            **summary.model_dump(),
            scanner_version=scan.scanner_version,
            control_catalog_id=scan.control_catalog_id,
            control_catalog_version=scan.control_catalog_version,
            assessment_profile_id=scan.assessment_profile_id,
            assessment_profile_version=scan.assessment_profile_version,
            assessment_profile_checksum=scan.assessment_profile_checksum,
            inventory_sha256=scan.inventory_sha256,
            result_checksum=scan.result_checksum,
            scope=(
                ScanScope(
                    requested_collectors=tuple(scope.requested_collectors),
                    collector_outcomes=dict(scope.collector_outcomes),
                    resource_types=tuple(scope.resource_types),
                    enabled_controls=tuple(scope.enabled_controls),
                )
                if scope is not None
                else None
            ),
        )

    def _failure_events(self, scan_ids: Iterable[UUID]) -> dict[UUID, AuditEvent]:
        ids = tuple(scan_ids)
        if not ids:
            return {}
        events = self.session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.target_type == "scan",
                AuditEvent.target_id.in_(ids),
                AuditEvent.event_type == AuditEventType.SCAN_FAILED,
            )
            .order_by(AuditEvent.timestamp.desc(), AuditEvent.event_id.desc())
        )
        latest: dict[UUID, AuditEvent] = {}
        for event in events:
            latest.setdefault(event.target_id, event)
        return latest

    @staticmethod
    def _summary(scan: Scan, failure_event: AuditEvent | None) -> ScanSummary:
        failure = None
        if scan.status is ScanStatus.FAILED:
            metadata = failure_event.event_metadata if failure_event is not None else {}
            failure = ScanFailure(
                code=str(metadata.get("failure_code", _GENERIC_EXECUTION_FAILURE.code)),
                message=str(metadata.get("failure_message", _GENERIC_EXECUTION_FAILURE.message)),
            )
        return ScanSummary(
            scan_id=scan.scan_id,
            status=scan.status,
            aws_account_id=scan.aws_account_id,
            requested_regions=tuple(scan.requested_regions),
            successful_regions=tuple(scan.successful_regions),
            requested_services=tuple(scan.requested_services),
            successful_collectors=tuple(scan.successful_collectors),
            started_at=_as_utc(scan.started_at),
            completed_at=_as_utc(scan.completed_at) if scan.completed_at is not None else None,
            failure=failure,
        )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
