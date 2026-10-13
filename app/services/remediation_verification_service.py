"""Manual read-only verification admission and immutable READ projections."""

from collections.abc import Callable
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app import __version__
from app.database.catalogs import CatalogPersistenceError
from app.database.integrity import canonical_json_sha256
from app.database.persistence import append_audit_event, fail_pending_scan
from app.models import AuditEvent, FindingOccurrence, Scan, ScanScopeManifest
from app.models.enums import AuditEventType, ScanStatus
from app.models.remediation_verification import (
    RemediationVerification,
    RemediationVerificationGuard,
    RemediationVerificationReceipt,
)
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.provenance import baseline_for, utc
from app.remediation.verification_contracts import (
    MAX_VERIFICATION_ATTEMPTS,
    VerificationContent,
    VerificationReceipt,
    VerificationRequest,
    VerificationScope,
    VerificationView,
)
from app.remediation.verification_evidence import postcondition_for
from app.schemas.api_views import Page
from app.security.authentication import Principal
from app.security.authorization import Capability, capabilities_for
from app.services.errors import EntityNotFoundError, RemediationError
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_service import MutationResult, _actor, _identity


class VerificationSubmissionError(RuntimeError):
    def __init__(self, verification_id: UUID, scan_id: UUID):
        self.verification_id, self.scan_id = verification_id, scan_id
        super().__init__("The configured executor rejected the verification scan.")


def request_document(execution_id, request):
    return {"execution_id": str(execution_id), **request.model_dump(mode="json")}


def request_audit_metadata(content, digest):
    return {
        "schema_version": content.schema_version,
        "actor": content.requested_by.model_dump(mode="json"),
        "verification_id": str(content.verification_id),
        "verification_sha256": digest,
        "execution_id": str(content.execution_id),
        "scan_id": str(content.scan_id),
        "attempt": content.attempt,
    }


def start_audit_metadata(content, digest):
    return {**request_audit_metadata(content, digest), "requested_regions": [content.region]}


def receipt_audit_metadata(receipt, digest):
    return {
        "schema_version": receipt.schema_version,
        "verification_id": str(receipt.verification_id),
        "verification_sha256": receipt.verification_sha256,
        "scan_id": str(receipt.scan_id),
        "receipt_sha256": digest,
        "outcome": receipt.outcome.value,
        "reason": receipt.reason.value,
        "result_sha256": receipt.result_sha256,
    }


def verification_guard(session):
    if session.get_bind().dialect.name == "sqlite":
        connection = session.connection()
        if not connection.connection.driver_connection.in_transaction:
            session.execute(text("BEGIN IMMEDIATE"))
    guard = session.scalar(
        select(RemediationVerificationGuard)
        .where(RemediationVerificationGuard.guard_id == 1)
        .with_for_update()
    )
    if guard is None:
        raise RemediationError("remediation_provenance_conflict")


def verification_read_fence(session, *, require_singleton=False):
    """Join schema-maintenance ordering without serializing ordinary writers.

    PostgreSQL SELECT holds ACCESS SHARE until transaction end. Read the guard
    relation before scan/audit/history relations; there is no row lock. Older-
    schema ordinary callers retain the original path without the new audit lookup.
    """
    if not inspect(session.connection()).has_table(RemediationVerificationGuard.__tablename__):
        return False
    value = session.scalar(
        select(RemediationVerificationGuard.guard_id).where(
            RemediationVerificationGuard.guard_id == 1
        )
    )
    if value is None and require_singleton:
        raise RemediationError("remediation_provenance_conflict")
    return True


class RemediationVerificationService:
    def __init__(
        self,
        session: Session,
        *,
        scope: VerificationScope | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.session = session
        self.scope = VerificationScope.model_validate((scope or VerificationScope()).model_dump())
        self.execution = RemediationExecutionService(session, clock=clock)
        self.authority = self.execution.authority

    def _row(self, verification_id):
        row = self.session.get(RemediationVerification, verification_id, populate_existing=True)
        if row is None:
            raise EntityNotFoundError("remediation_verification", verification_id)
        return row

    def _history(self, execution_id):
        try:
            return self._retained_history(execution_id)
        except (ValueError, TypeError, KeyError, AttributeError, CatalogPersistenceError):
            raise RemediationError("remediation_provenance_conflict") from None

    def _retained_history(self, execution_id):
        row = self.execution._row(execution_id)
        execution = self.execution._content(row)
        events = self.execution._events(row, execution)
        acknowledgments = [event for event in events if event.content.kind.value == "ACKNOWLEDGED"]
        if (
            events[-1].content.phase is not ExecutionPhase.ACKNOWLEDGED
            or len(acknowledgments) != 1
            or acknowledgments[0].content.phase is not ExecutionPhase.ACKNOWLEDGED
        ):
            raise RemediationError("remediation_verification_ineligible")
        # This is retained authority, not renewed write eligibility/current blocking state.
        proposal = execution.proposal
        finding = self.authority._finding(proposal.finding_id)
        occurrence = self.session.get(FindingOccurrence, proposal.baseline.occurrence_id)
        if (
            occurrence is None
            or baseline_for(self.session, finding, occurrence) != proposal.baseline
        ):
            raise RemediationError("remediation_provenance_conflict")
        original = self.session.get(Scan, proposal.baseline.scan_id)
        scope = self.session.scalar(
            select(ScanScopeManifest).where(ScanScopeManifest.scan_id == original.scan_id)
        )
        from app.services.scan_executor import _execution_scope_for

        collectors, types = _execution_scope_for(tuple(original.requested_services))
        if (
            scope is None
            or tuple(scope.requested_collectors) != collectors
            or set(scope.resource_types) != set(types)
            or original.requested_regions != [proposal.region]
        ):
            raise RemediationError("remediation_provenance_conflict")
        return row, execution, acknowledgments[0], original, collectors, types

    def _content(self, row):
        try:
            content = VerificationContent.model_validate(row.content)
            execution_row, execution, acknowledgment, original, collectors, types = self._history(
                row.execution_id
            )
            actor = content.requested_by
            scan = self.session.get(Scan, row.scan_id, populate_existing=True)
            request = VerificationRequest(reason=content.reason)
            if (
                canonical_json_sha256(row.content) != row.content_sha256
                or content.verification_id != row.verification_id
                or content.execution_id != row.execution_id
                or content.execution_sha256 != execution_row.execution_sha256
                or content.acknowledgment_event_id != row.acknowledgment_event_id
                or content.acknowledgment_event_id != acknowledgment.content.event_id
                or content.acknowledgment_sha256 != acknowledgment.event_sha256
                or content.acknowledged_at != acknowledgment.content.created_at
                or content.baseline_scan_id != original.scan_id
                or content.scan_id != row.scan_id
                or content.attempt != row.attempt
                or content.account_id != execution.proposal.account_id
                or content.region != execution.proposal.region
                or content.requested_services != tuple(original.requested_services)
                or content.requested_collectors != collectors
                or content.resource_types != types
                or (content.profile_id, content.profile_version, content.profile_sha256)
                != (
                    original.assessment_profile_id,
                    original.assessment_profile_version,
                    original.assessment_profile_checksum,
                )
                or (content.catalog_id, content.catalog_version, content.catalog_sha256)
                != (
                    original.control_catalog_id,
                    original.control_catalog_version,
                    execution.proposal.baseline.catalog_sha256,
                )
                or actor.capability is not Capability.EXECUTE
                or Capability.EXECUTE
                not in capabilities_for(
                    Principal(actor.subject, frozenset(actor.roles), actor.issuer)
                )
                or (actor.issuer, actor.subject) != (row.actor_issuer, row.actor_subject)
                or _identity(actor) != row.actor_identity_sha256
                or content.idempotency_key != row.idempotency_key
                or row.request_sha256
                != canonical_json_sha256(request_document(row.execution_id, request))
                or content.created_at != utc(row.created_at)
                or content.created_at < content.acknowledged_at
                or scan is None
                or utc(scan.started_at) != content.created_at
                or scan.requested_regions != [content.region]
                or tuple(scan.requested_services) != content.requested_services
                or (
                    scan.assessment_profile_id,
                    scan.assessment_profile_version,
                    scan.assessment_profile_checksum,
                )
                != (content.profile_id, content.profile_version, content.profile_sha256)
                or (scan.control_catalog_id, scan.control_catalog_version)
                != (content.catalog_id, content.catalog_version)
            ):
                raise ValueError("verification binding mismatch")
            audit = self.session.get(AuditEvent, row.audit_event_id)
            starts = self.session.scalars(
                select(AuditEvent).where(
                    AuditEvent.target_type == "scan",
                    AuditEvent.target_id == content.scan_id,
                    AuditEvent.event_type == AuditEventType.SCAN_STARTED,
                )
            ).all()
            if (
                audit is None
                or audit.actor_type != "human"
                or audit.actor_id != _identity(actor)
                or audit.target_type != "remediation_verification"
                or audit.target_id != row.verification_id
                or audit.event_type is not AuditEventType.REMEDIATION_VERIFICATION_REQUESTED
                or utc(audit.timestamp) != content.created_at
                or audit.event_metadata != request_audit_metadata(content, row.content_sha256)
                or len(starts) != 1
                or starts[0].actor_type != "human"
                or starts[0].actor_id != _identity(actor)
                or utc(starts[0].timestamp) != content.created_at
                or starts[0].event_metadata != start_audit_metadata(content, row.content_sha256)
            ):
                raise ValueError("verification audit mismatch")
            return content, execution.proposal, scan
        except (ValueError, TypeError, KeyError, AttributeError):
            raise RemediationError("remediation_provenance_conflict") from None

    def _receipt(self, row, content, proposal, scan):
        receipt_row = self.session.get(
            RemediationVerificationReceipt, row.verification_id, populate_existing=True
        )
        if receipt_row is None:
            if scan.status is not ScanStatus.RUNNING:
                raise RemediationError("remediation_provenance_conflict")
            return None, None, None
        try:
            receipt = VerificationReceipt.model_validate(receipt_row.content)
            expected = build_receipt(self.session, row, content, proposal, scan)
            audit = self.session.get(AuditEvent, receipt_row.audit_event_id)
            if (
                receipt != expected
                or receipt_row.content_sha256 != canonical_json_sha256(receipt_row.content)
                or receipt_row.outcome != receipt.outcome.value
                or utc(receipt_row.created_at) != receipt.created_at
                or audit is None
                or audit.actor_type != "system"
                or audit.actor_id != "scan-executor"
                or audit.target_type != "remediation_verification"
                or audit.target_id != row.verification_id
                or audit.event_type is not AuditEventType.REMEDIATION_VERIFICATION_COMPLETED
                or utc(audit.timestamp) != receipt.created_at
                or audit.event_metadata
                != receipt_audit_metadata(receipt, receipt_row.content_sha256)
            ):
                raise ValueError("verification receipt mismatch")
            return receipt, receipt_row.content_sha256, receipt_row.audit_event_id
        except (ValueError, TypeError, KeyError, AttributeError):
            raise RemediationError("remediation_provenance_conflict") from None

    def _view(self, row):
        content, proposal, scan = self._content(row)
        receipt, digest, audit_id = self._receipt(row, content, proposal, scan)
        return VerificationView(
            content=content,
            verification_sha256=row.content_sha256,
            request_audit_event_id=row.audit_event_id,
            receipt=receipt,
            receipt_sha256=digest,
            receipt_audit_event_id=audit_id,
        )

    def get_verification(self, verification_id, principal):
        _actor(principal, Capability.READ)
        self.authority._require_clean_read_session()
        with self.session.no_autoflush:
            if not verification_read_fence(self.session, require_singleton=True):
                raise RemediationError("remediation_database_unavailable")
            return self._view(self._row(verification_id))

    def list_verifications(self, principal, *, execution_id=None, limit=50, offset=0):
        _actor(principal, Capability.READ)
        self.authority._require_clean_read_session()
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("invalid verification page")
        predicates = (
            [] if execution_id is None else [RemediationVerification.execution_id == execution_id]
        )
        with self.session.no_autoflush:
            if not verification_read_fence(self.session, require_singleton=True):
                raise RemediationError("remediation_database_unavailable")
            total = (
                self.session.scalar(
                    select(func.count()).select_from(RemediationVerification).where(*predicates)
                )
                or 0
            )
            rows = self.session.scalars(
                select(RemediationVerification)
                .where(*predicates)
                .order_by(
                    RemediationVerification.created_at.desc(),
                    RemediationVerification.verification_id,
                )
                .limit(limit)
                .offset(offset)
            ).all()
            return Page[VerificationView](
                items=tuple(self._view(row) for row in rows),
                total=total,
                limit=limit,
                offset=offset,
            )

    def request_verification(self, execution_id, request, principal, key, executor):
        actor = _actor(principal, Capability.EXECUTE)
        request = VerificationRequest.model_validate(request.model_dump(mode="json"))
        if not isinstance(key, UUID):
            raise ValueError("idempotency key must be a UUID")
        if (
            self.session.in_transaction()
            or self.session.new
            or self.session.dirty
            or self.session.deleted
        ):
            raise RemediationError("remediation_state_conflict")
        request_digest = canonical_json_sha256(request_document(execution_id, request))
        try:
            verification_guard(self.session)
            previous = self.session.scalar(
                select(RemediationVerification).where(
                    RemediationVerification.actor_identity_sha256 == _identity(actor),
                    RemediationVerification.idempotency_key == key,
                )
            )
            if previous is not None:
                if previous.request_sha256 != request_digest or (
                    previous.actor_issuer,
                    previous.actor_subject,
                ) != (actor.issuer, actor.subject):
                    raise RemediationError("remediation_idempotency_conflict")
                value = self._view(previous)
                self.session.commit()
                return MutationResult(value=value, replayed=True)
            if not self.scope.enabled:
                raise RemediationError("remediation_verification_disabled")
            if executor is None:
                raise RemediationError("remediation_verification_executor_unavailable")
            execution_row, execution, acknowledgment, original, collectors, types = self._history(
                execution_id
            )
            if (execution.proposal.account_id, execution.proposal.region) != (
                self.scope.account_id,
                self.scope.region,
            ):
                raise RemediationError("remediation_verification_scope_conflict")
            prior = self.session.scalars(
                select(RemediationVerification)
                .where(RemediationVerification.execution_id == execution_id)
                .order_by(RemediationVerification.attempt)
            ).all()
            # Validate every prior receipt; never free capacity from a forged terminal marker.
            prior_views = [self._view(row) for row in prior]
            if any(value.receipt is None for value in prior_views):
                raise RemediationError("remediation_verification_active")
            if len(prior) >= MAX_VERIFICATION_ATTEMPTS:
                raise RemediationError("remediation_verification_limit")
            at = self.authority._now()
            if at < acknowledgment.content.created_at:
                raise RemediationError("remediation_state_conflict")
            content = VerificationContent(
                verification_id=uuid4(),
                execution_id=execution_id,
                execution_sha256=execution_row.execution_sha256,
                acknowledgment_event_id=acknowledgment.content.event_id,
                acknowledgment_sha256=acknowledgment.event_sha256,
                acknowledged_at=acknowledgment.content.created_at,
                baseline_scan_id=original.scan_id,
                scan_id=uuid4(),
                attempt=len(prior) + 1,
                account_id=execution.proposal.account_id,
                region=execution.proposal.region,
                requested_services=tuple(original.requested_services),
                requested_collectors=collectors,
                resource_types=types,
                profile_id=original.assessment_profile_id,
                profile_version=original.assessment_profile_version,
                profile_sha256=original.assessment_profile_checksum,
                catalog_id=original.control_catalog_id,
                catalog_version=original.control_catalog_version,
                catalog_sha256=execution.proposal.baseline.catalog_sha256,
                requested_by=actor,
                idempotency_key=key,
                reason=request.reason,
                created_at=at,
            )
            digest = canonical_json_sha256(content.model_dump(mode="json"))
            self.session.add(
                Scan(
                    scan_id=content.scan_id,
                    aws_account_id=None,
                    requested_regions=[content.region],
                    successful_regions=[],
                    requested_services=list(content.requested_services),
                    successful_collectors=[],
                    started_at=at,
                    completed_at=None,
                    status=ScanStatus.RUNNING,
                    scanner_version=__version__,
                    control_catalog_id=content.catalog_id,
                    control_catalog_version=content.catalog_version,
                    assessment_profile_id=content.profile_id,
                    assessment_profile_version=content.profile_version,
                    assessment_profile_checksum=content.profile_sha256,
                    inventory_sha256=None,
                    result_checksum=None,
                )
            )
            self.session.flush()
            append_audit_event(
                self.session,
                AuditEventType.SCAN_STARTED,
                "scan",
                content.scan_id,
                at,
                actor_type="human",
                actor_id=_identity(actor),
                metadata=start_audit_metadata(content, digest),
            )
            audit = append_audit_event(
                self.session,
                AuditEventType.REMEDIATION_VERIFICATION_REQUESTED,
                "remediation_verification",
                content.verification_id,
                at,
                actor_type="human",
                actor_id=_identity(actor),
                metadata=request_audit_metadata(content, digest),
            )
            # Audit UUID defaults and trigger-only dependencies require a separate flush.
            self.session.flush()
            self.session.add(
                RemediationVerification(
                    verification_id=content.verification_id,
                    execution_id=execution_id,
                    acknowledgment_event_id=content.acknowledgment_event_id,
                    scan_id=content.scan_id,
                    audit_event_id=audit.event_id,
                    attempt=content.attempt,
                    actor_identity_sha256=_identity(actor),
                    actor_issuer=actor.issuer,
                    actor_subject=actor.subject,
                    idempotency_key=key,
                    request_sha256=request_digest,
                    content=content.model_dump(mode="json"),
                    content_sha256=digest,
                    created_at=at,
                )
            )
            self.session.commit()
        except (IntegrityError, OperationalError):
            self.session.rollback()
            raise RemediationError("remediation_database_unavailable") from None
        except Exception:
            self.session.rollback()
            raise
        # IDs are cached in an immutable contract; accessing an expired ORM row here would
        # begin a transaction across executor submission/provider construction.
        try:
            executor.submit(content.scan_id)
        except Exception as error:
            try:
                fail_pending_scan(
                    self.session,
                    scan_id=content.scan_id,
                    completed_at=self.authority._now(),
                    failure_code="EXECUTOR_SUBMISSION_FAILED",
                    failure_message="The configured executor rejected this scan request.",
                )
                self.session.commit()
            except Exception:
                self.session.rollback()
            raise VerificationSubmissionError(content.verification_id, content.scan_id) from error
        return MutationResult(
            value=self.get_verification(content.verification_id, principal), replayed=False
        )


def build_receipt(session, row, content, proposal, scan):
    if (
        scan.status is ScanStatus.RUNNING
        or scan.result_checksum is None
        or scan.completed_at is None
    ):
        raise RemediationError("remediation_provenance_conflict")
    outcome, reason, evidence = postcondition_for(session, scan, content, proposal)
    return VerificationReceipt(
        verification_id=row.verification_id,
        verification_sha256=row.content_sha256,
        scan_id=scan.scan_id,
        scan_status=scan.status,
        result_sha256=scan.result_checksum,
        inventory_sha256=scan.inventory_sha256,
        outcome=outcome,
        reason=reason,
        evidence=evidence,
        created_at=utc(scan.completed_at),
    )


def load_link(session, scan_id, *, lock=False):
    """Use the immutable start marker to preserve ordinary/older-schema scan behavior."""
    with session.no_autoflush:
        if not verification_read_fence(session):
            return None
        starts = session.scalars(
            select(AuditEvent).where(
                AuditEvent.target_type == "scan",
                AuditEvent.target_id == scan_id,
                AuditEvent.event_type == AuditEventType.SCAN_STARTED,
            )
        ).all()
        marked = [event for event in starts if "verification_id" in event.event_metadata]
        if not marked:
            return None
        verification_read_fence(session, require_singleton=True)
        if lock:
            verification_guard(session)
        if len(marked) != 1 or len(starts) != 1:
            raise RemediationError("remediation_provenance_conflict")
        row = session.scalar(
            select(RemediationVerification).where(RemediationVerification.scan_id == scan_id)
        )
        if row is None:
            raise RemediationError("remediation_provenance_conflict")
        content, proposal, scan = RemediationVerificationService(session)._content(row)
        return row, content, proposal, scan


def seal_receipt(session, link):
    """Called only inside the scan writer's transaction, after guard then scan locks."""
    if link is None:
        return
    row, content, proposal, scan = link
    service = RemediationVerificationService(session)
    existing = session.get(RemediationVerificationReceipt, row.verification_id)
    if existing is not None:
        service._receipt(row, content, proposal, scan)
        return
    receipt = build_receipt(session, row, content, proposal, scan)
    digest = canonical_json_sha256(receipt.model_dump(mode="json"))
    audit = append_audit_event(
        session,
        AuditEventType.REMEDIATION_VERIFICATION_COMPLETED,
        "remediation_verification",
        row.verification_id,
        receipt.created_at,
        actor_type="system",
        actor_id="scan-executor",
        metadata=receipt_audit_metadata(receipt, digest),
    )
    session.flush()
    session.add(
        RemediationVerificationReceipt(
            verification_id=row.verification_id,
            audit_event_id=audit.event_id,
            outcome=receipt.outcome.value,
            content=receipt.model_dump(mode="json"),
            content_sha256=digest,
            created_at=receipt.created_at,
        )
    )
    session.flush()
