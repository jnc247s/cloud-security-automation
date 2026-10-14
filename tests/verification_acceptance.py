"""Signed authority and installed worker followed by a genuinely managed read-only scan."""

import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Event
from unittest.mock import Mock, patch
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import __version__
from app.config import get_settings
from app.database.base import Base
from app.database.integrity import canonical_json_sha256
from app.database.persistence import persist_scan_result
from app.models import AuditEvent, Control, Finding, FindingOccurrence, Resource, Scan
from app.models.enums import AuditEventType, ScanStatus
from app.models.remediation_verification import (
    RemediationVerification,
    RemediationVerificationGuard,
    RemediationVerificationReceipt,
)
from app.remediation.contracts import ACTION_ID, ACTION_VERSION, ProposalRequest
from app.remediation.verification_contracts import VerificationView
from app.remediation.worker_aws import EbsDefaultWriter
from app.remediation.worker_driver import RemediationWorker
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.scan_executor import (
    REQUESTED_SERVICES,
    InProcessScanExecutor,
    _execution_scope_for,
    _scope_for,
)
from tests.dashboard_fixtures import dashboard_client
from tests.ec2_fixtures import ec2_profile
from tests.verification_fixtures import provider
from tests.worker_http import ACCOUNT, REGION, database_state
from tests.worker_process_http import ProcessJourney


def regional_reader(*, enabled=False, key=None, kms_error=None):
    """Move empty synthetic evidence to the worker target without changing collector logic."""
    reader = provider(enabled=enabled, key=key, kms_error=kms_error)
    reader._clients = {
        (service, REGION): client for (service, _), client in reader._clients.items()
    }
    reader.region_name = REGION
    return reader


def full_scope_source(engine, *, key=None, policy=None, requested_services=REQUESTED_SERVICES):
    policy = policy or ec2_profile()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.5.0")
    collectors, resource_types = _execution_scope_for(requested_services)
    observed = datetime.now(UTC) - timedelta(seconds=2)
    with patch("app.services.inventory_service.datetime") as clock:
        clock.now.return_value = observed
        snapshot = InventoryService(
            regional_reader(key=key),
            include_access_analyzer="access-analyzer" in requested_services,
            include_cloudtrail_evidence="cloudtrail-evidence" in requested_services,
            include_s3_evidence="kms" in requested_services,
        ).collect(scan_id=uuid4())
    with Session(engine) as session, session.begin():
        persist_scan_result(
            session,
            snapshot=snapshot,
            scope=_scope_for(
                snapshot,
                policy,
                catalog,
                requested_services=requested_services,
                requested_collectors=collectors,
                resource_types=resource_types,
            ),
            profile=policy,
            catalog=catalog,
            assessments=RuleEngine(registry, catalog=catalog).assess(snapshot, policy),
            started_at=observed - timedelta(seconds=1),
            completed_at=observed + timedelta(seconds=1),
            scanner_version=__version__,
        )
    with Session(engine) as session:
        finding = session.scalar(
            select(Finding).join(Control).where(Control.control_key == "EC2-004")
        )
        occurrence = session.scalar(
            select(FindingOccurrence).where(FindingOccurrence.finding_id == finding.finding_id)
        )
        return ProposalRequest(
            finding_id=finding.finding_id,
            occurrence_id=occurrence.occurrence_id,
            action_id=ACTION_ID,
            action_version=ACTION_VERSION,
            reason="Reviewed exact full-scope offline policy and KMS compatibility.",
        )


class ManagedReader(InProcessScanExecutor):
    """Observe real submit/provider boundaries; never replace the managed execution path."""

    def __init__(self, engine, source, reader):
        self.engine, self.source, self.reader = engine, source, reader
        self.actor_subject = "verification-operator"
        self.submissions, self.boundaries = [], []
        self.entered, self.release = Event(), Event()
        self.open_executor_sessions = 0
        super().__init__(
            session_factory=self.session_factory,
            provider_factory=self.build_reader,
            settings=get_settings(),
        )

    @contextmanager
    def session_factory(self):
        self.open_executor_sessions += 1
        try:
            with Session(self.engine, expire_on_commit=False) as session:
                yield session
        finally:
            self.open_executor_sessions -= 1

    def committed_boundary(self, scan_id, boundary):
        """Separate connection sees intent and acquires locks without caller-held deadlock.

        An unrelated authorized replay can briefly own the guard after admission commits.
        Allow that transaction to finish; a submitter retaining its own locks cannot finish
        while waiting on this independent probe and therefore hits the strict SQL timeout.
        """
        with Session(self.engine) as session, session.begin():
            session.execute(text("SET LOCAL lock_timeout = '3s'"))
            session.execute(
                select(RemediationVerificationGuard)
                .where(RemediationVerificationGuard.guard_id == 1)
                .with_for_update()
            ).scalar_one()
            scan = session.execute(
                select(Scan).where(Scan.scan_id == scan_id).with_for_update()
            ).scalar_one()
            request = session.execute(
                select(RemediationVerification).where(RemediationVerification.scan_id == scan_id)
            ).scalar_one()
            finding = session.get(Finding, self.source.finding_id)
            session.execute(
                select(Resource)
                .where(Resource.resource_id == finding.resource_id)
                .with_for_update()
            ).scalar_one()
            session.execute(
                select(Finding).where(Finding.finding_id == finding.finding_id).with_for_update()
            ).scalar_one()
            assert scan.status is ScanStatus.RUNNING and scan.completed_at is None
            assert session.get(RemediationVerificationReceipt, request.verification_id) is None
            audit = session.get(AuditEvent, request.audit_event_id)
            assert audit.event_type is AuditEventType.REMEDIATION_VERIFICATION_REQUESTED
            assert audit.event_metadata["actor"]["subject"] == self.actor_subject
            start = session.execute(
                select(AuditEvent).where(
                    AuditEvent.target_id == scan_id,
                    AuditEvent.event_type == AuditEventType.SCAN_STARTED,
                )
            ).scalar_one()
            assert start.event_metadata["actor"] == audit.event_metadata["actor"]
            self.boundaries.append((boundary, scan_id, request.verification_id))

    def submit(self, scan_id):
        self.committed_boundary(scan_id, "submit")
        self.submissions.append(scan_id)
        self.entered.clear()
        self.release.clear()
        super().submit(scan_id)

    def build_reader(self, region):
        assert region == REGION and self.open_executor_sessions == 0
        assert self.submissions
        self.committed_boundary(self.submissions[-1], "provider")
        self.entered.set()
        assert self.release.wait(15), "read-only collection gate deadline expired"
        if isinstance(self.reader, BaseException):
            raise self.reader
        return self.reader() if callable(self.reader) else self.reader


@contextmanager
def full_verification_journey(
    runtime,
    engine,
    child_url,
    monkeypatch,
    tmp_path,
    *,
    key=None,
    reader,
    policy=None,
    requested_services=REQUESTED_SERVICES,
):
    source = full_scope_source(
        engine, key=key, policy=policy, requested_services=requested_services
    )
    original = database_state(engine)
    no_worker = Mock(side_effect=AssertionError("API/scanner cannot start a write worker"))
    no_writer = Mock(side_effect=AssertionError("API/scanner cannot acquire a write identity"))
    monkeypatch.setattr(RemediationWorker, "__init__", no_worker)
    monkeypatch.setattr(EbsDefaultWriter, "from_ecs", no_writer)
    for name, value in {
        "REMEDIATION_VERIFICATION_ENABLED": "true",
        "REMEDIATION_VERIFICATION_ACCOUNT_ID": ACCOUNT,
        "REMEDIATION_VERIFICATION_REGION": REGION,
    }.items():
        monkeypatch.setenv(name, value)
    managed = None
    try:
        with dashboard_client(
            engine,
            monkeypatch,
            tmp_path,
            executor_factory=lambda: ManagedReader(engine, source, reader),
        ) as (client, issuer, _, managed):
            journey = ProcessJourney(
                runtime, engine, child_url, client, issuer, managed, source, original, monkeypatch
            )
            try:
                yield journey
            finally:
                managed.release.set()
    finally:
        if managed is not None:
            managed.release.set()
        no_worker.assert_not_called()
        no_writer.assert_not_called()


def wait_for_receipt(journey, verification_id):
    deadline = time.monotonic() + 15
    route = "/api/v1/remediation-verifications/" + str(verification_id)
    while True:
        response = journey.client.get(route, headers=journey.reader)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        value = VerificationView.model_validate(response.json())
        if value.receipt is not None:
            return value
        assert time.monotonic() < deadline, "managed scan did not seal a receipt"
        time.sleep(0.05)


def unchanged_history(before, after):
    """Old immutable rows survive; only ordinary current resources/findings can change."""
    for table in Base.metadata.sorted_tables:
        if table.name in {
            "resources",
            "findings",
            "remediation_verifications",
            "remediation_verification_receipts",
        }:
            continue
        pk = tuple(column.name for column in table.primary_key)
        current = {tuple(row._mapping[name] for name in pk): row for row in after[table.name]}
        assert all(
            current.get(tuple(row._mapping[name] for name in pk)) == row
            for row in before[table.name]
        ), table.name
        if table.name.startswith("remediation_"):
            assert after[table.name] == before[table.name], "verification changed write authority"


def assert_receipt_storage(engine, view):
    with Session(engine) as session:
        request = session.get(RemediationVerification, view.content.verification_id)
        receipt = session.get(RemediationVerificationReceipt, view.content.verification_id)
        assert request.content == view.content.model_dump(mode="json")
        assert (
            request.content_sha256
            == view.verification_sha256
            == canonical_json_sha256(request.content)
        )
        assert receipt.content == view.receipt.model_dump(mode="json")
        assert (
            receipt.content_sha256 == view.receipt_sha256 == canonical_json_sha256(receipt.content)
        )
        assert receipt.audit_event_id == view.receipt_audit_event_id
        audit = session.get(AuditEvent, receipt.audit_event_id)
        assert audit.event_type is AuditEventType.REMEDIATION_VERIFICATION_COMPLETED
        assert audit.target_id == view.content.verification_id
