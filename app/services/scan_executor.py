"""Replaceable, bounded in-process execution for asynchronous scan requests."""

from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime
from threading import Lock
from typing import Protocol
from uuid import UUID

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.assessment.controls import ControlCatalog, build_default_control_catalog
from app.assessment.profiles import AssessmentProfile
from app.aws.client import AWSClientProvider, Boto3ClientProvider
from app.config import Settings, get_settings
from app.database.catalogs import (
    CatalogPersistenceError,
    VersionContentConflictError,
    load_assessment_profile,
)
from app.database.persistence import ScanPersistenceError, fail_pending_scan, persist_scan_result
from app.database.session import SessionLocal
from app.models import Scan
from app.models.enums import ScanStatus
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.inventory import CollectionStatus, InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput
from app.services.inventory_service import InventoryService
from app.services.scan_service import REQUESTED_SERVICES

LOGGER = logging.getLogger(__name__)
SessionFactory = Callable[[], Session]
ProviderFactory = Callable[[str], AWSClientProvider]

_REQUESTED_COLLECTORS = (
    "cloudtrail_trails",
    "iam_users",
    "s3_buckets",
    "security_groups",
)
_RESOURCE_TYPES = (
    "aws_account",
    "cloudtrail_trail",
    "iam_user",
    "s3_bucket",
    "security_group",
)


class ScanExecutor(Protocol):
    """Submission boundary that can later be backed by a durable worker system."""

    def submit(self, scan_id: UUID) -> None:
        """Schedule a previously persisted RUNNING scan without blocking."""

    def resume_pending(self) -> int:
        """Recover durable work that did not reach a terminal state."""

    def shutdown(self, *, wait: bool = True) -> None:
        """Stop accepting work and release executor resources."""


class ScanExecutorClosedError(RuntimeError):
    """Work was submitted after executor shutdown began."""


class ScanExecutorCapacityError(RuntimeError):
    """The bounded in-process executor has no safe outstanding-work capacity."""


class InProcessScanExecutor:
    """Bounded thread executor used until an external job system is justified.

    The durable RUNNING row is committed before submission. On process restart,
    ``resume_pending`` can resubmit those rows. This implementation is intentionally
    behind ``ScanExecutor`` so a future durable queue does not affect API services.
    """

    def __init__(
        self,
        *,
        session_factory: SessionFactory = SessionLocal,
        settings: Settings | None = None,
        provider_factory: ProviderFactory | None = None,
        max_workers: int = 2,
        max_outstanding: int = 32,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be positive")
        if max_outstanding < max_workers:
            raise ValueError("max_outstanding must be at least max_workers")
        self._session_factory = session_factory
        self._settings = settings or get_settings()
        self._provider_factory = provider_factory or self._build_provider
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="security-scan",
        )
        self._futures: dict[UUID, Future[None]] = {}
        self._lock = Lock()
        self._closed = False
        self._max_outstanding = max_outstanding
        self._drain_backlog = False

    def submit(self, scan_id: UUID) -> None:
        """Schedule one scan ID at most once concurrently."""

        with self._lock:
            if self._closed:
                raise ScanExecutorClosedError("scan executor is shut down")
            existing = self._futures.get(scan_id)
            if existing is not None and not existing.done():
                return
            if len(self._futures) >= self._max_outstanding:
                raise ScanExecutorCapacityError("scan executor capacity is exhausted")
            future = self._pool.submit(self._run, scan_id)
            self._futures[scan_id] = future
        # A callback added to an already-finished future runs synchronously; register
        # outside the lock so very short jobs cannot deadlock the submitter.
        future.add_done_callback(
            lambda completed, submitted_id=scan_id: self._forget(submitted_id, completed)
        )

    def resume_pending(self) -> int:
        """Best-effort resubmit durable RUNNING scans within bounded capacity."""

        with self._lock:
            if self._closed:
                return 0
            active_ids = tuple(self._futures)
            capacity = self._max_outstanding - len(active_ids)
        if capacity <= 0:
            return 0
        try:
            with self._session_factory() as session:
                query = (
                    select(Scan.scan_id)
                    .where(Scan.status == ScanStatus.RUNNING)
                    .order_by(Scan.started_at, Scan.scan_id)
                    .limit(capacity + 1)
                )
                if active_ids:
                    query = query.where(Scan.scan_id.not_in(active_ids))
                candidates = tuple(session.scalars(query))
        except Exception as error:
            LOGGER.error(
                "Unable to query pending scans during executor recovery (%s).",
                type(error).__name__,
            )
            return 0

        scan_ids = candidates[:capacity]
        with self._lock:
            self._drain_backlog = len(candidates) > capacity
        submitted = 0
        for scan_id in scan_ids:
            try:
                self.submit(scan_id)
                submitted += 1
            except ScanExecutorCapacityError:
                with self._lock:
                    self._drain_backlog = True
                break
            except ScanExecutorClosedError:
                break
        return submitted

    def shutdown(self, *, wait: bool = True) -> None:
        """Stop submissions and let accepted work reach a terminal database state."""

        with self._lock:
            self._closed = True
        self._pool.shutdown(wait=wait, cancel_futures=False)

    def _forget(self, scan_id: UUID, completed: Future[None]) -> None:
        with self._lock:
            if self._futures.get(scan_id) is completed:
                self._futures.pop(scan_id, None)
            should_drain = self._drain_backlog and not self._closed
        if should_drain:
            self.resume_pending()

    def _build_provider(self, region: str) -> AWSClientProvider:
        regional_settings = self._settings.model_copy(update={"aws_region": region})
        return Boto3ClientProvider.from_settings(regional_settings)

    def _run(self, scan_id: UUID) -> None:
        try:
            self._execute(scan_id)
        except Exception as error:
            failure_code = self._failure_code(error)
            LOGGER.error(
                "Scan %s failed with code %s (%s).",
                scan_id,
                failure_code,
                type(error).__name__,
            )
            try:
                with self._session_factory() as session, session.begin():
                    fail_pending_scan(
                        session,
                        scan_id=scan_id,
                        completed_at=datetime.now(UTC),
                        failure_code=failure_code,
                        failure_message=(
                            "Scan execution failed before results could be persisted."
                        ),
                    )
            except Exception as persistence_error:
                LOGGER.error(
                    "Unable to persist terminal failure for scan %s (%s).",
                    scan_id,
                    type(persistence_error).__name__,
                )

    def _execute(self, scan_id: UUID) -> None:
        with self._session_factory() as session:
            scan = session.get(Scan, scan_id)
            if scan is None or scan.status is not ScanStatus.RUNNING:
                return
            if len(scan.requested_regions) != 1:
                raise ScanPersistenceError("current executor requires exactly one region")
            region = str(scan.requested_regions[0])
            started_at = _as_utc(scan.started_at)
            try:
                profile = load_assessment_profile(
                    session,
                    profile_id=scan.assessment_profile_id,
                    version=scan.assessment_profile_version,
                    expected_checksum=scan.assessment_profile_checksum,
                )
            except (CatalogPersistenceError, VersionContentConflictError) as error:
                raise ScanPersistenceError(
                    "pending scan assessment profile provenance is invalid"
                ) from error
            expected_catalog = (scan.control_catalog_id, scan.control_catalog_version)

        provider = self._provider_factory(region)
        snapshot = InventoryService(provider).collect(scan_id=scan_id)
        catalog = build_default_control_catalog()
        if expected_catalog != (catalog.catalog_id, catalog.version):
            raise ScanPersistenceError("executor policy differs from pending scan provenance")
        assessments = RuleEngine(build_default_registry()).assess(snapshot, profile)
        scope = _scope_for(snapshot, profile, catalog)
        with self._session_factory() as session, session.begin():
            persist_scan_result(
                session,
                snapshot=snapshot,
                scope=scope,
                profile=profile,
                catalog=catalog,
                assessments=assessments,
                started_at=started_at,
                completed_at=datetime.now(UTC),
                scanner_version=__version__,
                actor_type="system",
                actor_id="scan-executor",
            )

    @staticmethod
    def _failure_code(error: Exception) -> str:
        if isinstance(error, ClientError | BotoCoreError):
            return "AWS_COLLECTION_FAILED"
        if isinstance(error, ScanPersistenceError):
            return "SCAN_PERSISTENCE_FAILED"
        return "SCAN_EXECUTION_FAILED"


def _scope_for(
    snapshot: InventorySnapshot,
    profile: AssessmentProfile,
    catalog: ControlCatalog,
) -> ScanScopeManifestInput:
    outcomes = tuple(snapshot.collector_outcomes)
    outcome_names = {outcome.collector_name for outcome in outcomes}
    if outcome_names != set(_REQUESTED_COLLECTORS):
        raise ScanPersistenceError("executor inventory has an unexpected collector set")
    complete = all(outcome.status is CollectionStatus.SUCCEEDED for outcome in outcomes)
    return ScanScopeManifestInput(
        aws_account_id=snapshot.account_id,
        requested_regions=(snapshot.requested_region,),
        successful_regions=(snapshot.requested_region,) if complete else (),
        requested_services=REQUESTED_SERVICES,
        requested_collectors=_REQUESTED_COLLECTORS,
        collector_outcomes=outcomes,
        resource_types=_RESOURCE_TYPES,
        enabled_controls=profile.enabled_controls,
        assessment_profile_id=profile.profile_id,
        assessment_profile_version=profile.version,
        assessment_profile_checksum=profile.calculate_content_checksum(),
        control_catalog_id=catalog.catalog_id,
        control_catalog_version=catalog.version,
    )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
