"""Short, guard-first worker transactions. No AWS calls or credential construction here."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, OperationalError

from app.database.integrity import canonical_json_sha256
from app.database.persistence import append_audit_event
from app.models.enums import AuditEventType
from app.models.remediation_execution import (
    RemediationAdmissionGuard,
    RemediationExecutionEvent,
    RemediationTargetReservation,
    RemediationWorkerClaim,
)
from app.remediation.execution_contracts import (
    ExecutionBlockingReason,
    ExecutionContent,
    ExecutionPhase,
)
from app.remediation.provenance import utc
from app.remediation.worker_config import WorkerScope
from app.remediation.worker_contracts import (
    RegionalObservation,
    WorkerActor,
    WorkerBlockingReason,
    WorkerEventContent,
    WorkerEventKind,
    validate_worker_entry,
    worker_phase,
)
from app.services.errors import RemediationError
from app.services.remediation_execution_service import RemediationExecutionService

_HELD = {
    ExecutionPhase.QUEUED,
    ExecutionPhase.CLAIMED,
    ExecutionPhase.WRITE_INTENT,
    ExecutionPhase.QUARANTINED,
}


@dataclass(frozen=True, repr=False)
class WorkerClaim:
    """Private ownership nonce is never a READ response, audit field or logged value."""

    execution_id: UUID
    token: UUID
    content: ExecutionContent
    lease_until: datetime


class RemediationWorkerService:
    def __init__(self, session, *, scope: WorkerScope, clock=None):
        self.session = session
        self.scope = WorkerScope.model_validate(scope.model_dump())
        self.admission = RemediationExecutionService(session, clock=clock)
        self.actor = (
            WorkerActor(expected_role_arn=self.scope.role_arn) if self.scope.enabled else None
        )

    def _locked(self, execution_id, work):
        if not self.scope.enabled:
            raise RemediationError("remediation_execution_disabled")
        if not isinstance(execution_id, UUID):
            raise ValueError("execution ID must be a UUID")
        if (
            self.session.in_transaction()
            or self.session.new
            or self.session.dirty
            or self.session.deleted
        ):
            raise RemediationError("remediation_state_conflict")
        try:
            with self.session.begin():
                dialect = self.session.get_bind().dialect.name
                if dialect == "sqlite":
                    connection = self.session.connection()
                    if not connection.connection.driver_connection.in_transaction:
                        self.session.execute(text("BEGIN IMMEDIATE"))
                    else:
                        self.session.execute(
                            text("UPDATE alembic_version SET version_num = version_num WHERE 0")
                        )
                elif dialect != "postgresql":
                    raise RemediationError("remediation_database_unavailable")
                guard = self.session.scalar(
                    select(RemediationAdmissionGuard)
                    .where(
                        RemediationAdmissionGuard.guard_id == 1,
                    )
                    .with_for_update()
                )
                if guard is None:
                    raise RemediationError("remediation_database_unavailable")
                row = self.admission._row(execution_id)
                self.admission.authority._proposal(row.proposal_id, lock=True)
                content = self.admission._content(row)
                if (
                    content.proposal.account_id != self.scope.account_id
                    or content.proposal.region != self.scope.region
                ):
                    raise RemediationError("remediation_execution_scope_conflict")
                reservation = self.session.scalar(
                    select(RemediationTargetReservation)
                    .where(
                        RemediationTargetReservation.account_id == self.scope.account_id,
                        RemediationTargetReservation.region == self.scope.region,
                        RemediationTargetReservation.action_id == content.proposal.action_id,
                    )
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                claim = self.session.scalar(
                    select(RemediationWorkerClaim)
                    .where(
                        RemediationWorkerClaim.execution_id == execution_id,
                    )
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                history = self.admission._events(row, content)
                if (
                    reservation is None
                    or reservation.resource_id != content.proposal.resource_id
                    or (reservation.execution_id == execution_id)
                    != (history[-1].content.phase in _HELD)
                ):
                    raise RemediationError("remediation_provenance_conflict")
                if claim is not None and claim.expected_role_arn != self.scope.role_arn:
                    raise RemediationError("remediation_execution_scope_conflict")
                at = self.admission.authority._now()  # Fresh after all lock waits.
                result = work(row, content, history, claim, reservation, at)
                self.session.flush()
                self.admission._events(row, content)  # Revalidate paired history/coordination.
                return result
        except IntegrityError:
            self.session.rollback()
            raise RemediationError("remediation_state_conflict") from None
        except OperationalError:
            self.session.rollback()
            raise RemediationError("remediation_database_unavailable") from None
        except Exception:
            self.session.rollback()
            raise

    def _append(
        self,
        row,
        content,
        kind,
        at,
        *,
        reasons=(),
        observation=None,
        observed_at=None,
        request_id=None,
        polls=0,
    ):
        history = self.admission._events(row, content)
        entry = WorkerEventContent(
            event_id=uuid4(),
            execution_id=row.execution_id,
            execution_sha256=row.execution_sha256,
            sequence=len(history) + 1,
            kind=kind,
            phase=worker_phase(kind, history[-1].content.phase),
            previous_event_sha256=history[-1].event_sha256,
            actor=self.actor,
            created_at=at,
            blocking_reasons=reasons,
            observation=observation,
            observed_at=observed_at,
            request_id=request_id,
            polls=polls,
        )
        validate_worker_entry(entry, history[-1].content.phase, content)
        document = entry.model_dump(mode="json")
        digest = canonical_json_sha256(document)
        audit = append_audit_event(
            self.session,
            AuditEventType("REMEDIATION_EXECUTION_" + kind.value),
            "remediation_execution",
            row.execution_id,
            at,
            actor_type="service",
            actor_id=canonical_json_sha256(self.actor.model_dump(mode="json")),
            metadata=self.admission._audit_metadata(entry, digest),
        )
        self.session.flush()
        self.session.add(
            RemediationExecutionEvent(
                event_id=entry.event_id,
                execution_id=row.execution_id,
                audit_event_id=audit.event_id,
                sequence=entry.sequence,
                kind=kind.value,
                content=document,
                event_sha256=digest,
                previous_event_sha256=entry.previous_event_sha256,
                created_at=at,
            )
        )
        self.session.flush()
        return entry

    @staticmethod
    def _owned(token, claim):
        return claim is not None and claim.token_sha256 == canonical_json_sha256(str(token.token))

    def claim(self, execution_id) -> WorkerClaim | None:
        def work(row, content, history, claim, reservation, at):
            phase = history[-1].content.phase
            if phase not in {ExecutionPhase.QUEUED, ExecutionPhase.CLAIMED}:
                return None
            reasons = self.admission._blocking(content, at)
            at = self.admission.authority._now()
            if at >= content.expires_at and not reasons:
                reasons = (ExecutionBlockingReason.EXECUTION_EXPIRED,)
            if reasons:
                self._append(row, content, WorkerEventKind.NO_WRITE, at, reasons=reasons)
                reservation.execution_id = None
                return None
            if claim is not None and utc(claim.lease_until) > at:
                return None
            if claim is not None and claim.read_attempts >= 3:
                self._append(
                    row,
                    content,
                    WorkerEventKind.NO_WRITE,
                    at,
                    reasons=(WorkerBlockingReason.READ_BUDGET_EXHAUSTED,),
                )
                reservation.execution_id = None
                return None
            token = uuid4()
            until = min(content.expires_at, at + timedelta(seconds=30))
            self._append(row, content, WorkerEventKind.CLAIMED, at)
            if claim is None:
                claim = RemediationWorkerClaim(
                    execution_id=execution_id,
                    token_sha256=canonical_json_sha256(str(token)),
                    expected_role_arn=self.scope.role_arn,
                    generation=1,
                    read_attempts=0,
                    readback_attempts=0,
                    lease_until=until,
                )
                self.session.add(claim)
            else:
                claim.token_sha256 = canonical_json_sha256(str(token))
                claim.generation += 1
                claim.lease_until = until
            return WorkerClaim(execution_id, token, content, until)

        return self._locked(execution_id, work)

    def begin_read(self, token: WorkerClaim) -> bool:
        def work(row, content, history, claim, reservation, at):
            if (
                not self._owned(token, claim)
                or history[-1].content.phase is not ExecutionPhase.CLAIMED
            ):
                return False
            reasons = self.admission._blocking(content, at)
            at = self.admission.authority._now()
            if at >= content.expires_at and not reasons:
                reasons = (ExecutionBlockingReason.EXECUTION_EXPIRED,)
            if not reasons and claim.read_attempts >= 3:
                reasons = (WorkerBlockingReason.READ_BUDGET_EXHAUSTED,)
            if reasons:
                self._append(row, content, WorkerEventKind.NO_WRITE, at, reasons=reasons)
                reservation.execution_id = None
                return False
            if at >= utc(claim.lease_until):
                return False
            claim.read_attempts += 1
            return True

        return self._locked(token.execution_id, work)

    def no_write(
        self,
        token: WorkerClaim,
        reason: WorkerBlockingReason,
        *,
        observation=None,
        observed_at=None,
    ) -> bool:
        def work(row, content, history, claim, reservation, at):
            if (
                not self._owned(token, claim)
                or history[-1].content.phase is not ExecutionPhase.CLAIMED
            ):
                return False
            self._append(
                row,
                content,
                WorkerEventKind.NO_WRITE,
                at,
                reasons=(reason,),
                observation=observation,
                observed_at=observed_at,
            )
            reservation.execution_id = None
            return True

        return self._locked(token.execution_id, work)

    def write_intent(
        self, token: WorkerClaim, observation: RegionalObservation, observed_at
    ) -> bool:
        observation = RegionalObservation.model_validate(observation.model_dump())

        def work(row, content, history, claim, reservation, at):
            if (
                not self._owned(token, claim)
                or history[-1].content.phase is not ExecutionPhase.CLAIMED
            ):
                return False
            reasons = self.admission._blocking(content, at)
            at = self.admission.authority._now()
            if at >= content.expires_at and not reasons:
                reasons = (ExecutionBlockingReason.EXECUTION_EXPIRED,)
            if reasons:
                self._append(row, content, WorkerEventKind.NO_WRITE, at, reasons=reasons)
                reservation.execution_id = None
                return False
            if at >= utc(claim.lease_until):
                return False
            baseline = content.proposal.baseline
            if claim.read_attempts == 0 or observed_at < history[-1].content.created_at:
                raise RemediationError("remediation_state_conflict")
            if (
                observation.encryption_by_default is not False
                or observation.default_kms_key_id != baseline.default_kms_key_id
                or observation.default_kms_key_expected_absence
                != baseline.default_kms_key_expected_absence
            ):
                self._append(
                    row,
                    content,
                    WorkerEventKind.NO_WRITE,
                    at,
                    reasons=(WorkerBlockingReason.PRECONDITION_CHANGED,),
                    observation=observation,
                    observed_at=observed_at,
                )
                reservation.execution_id = None
                return False
            entry = self._append(
                row,
                content,
                WorkerEventKind.WRITE_INTENT,
                at,
                observation=observation,
                observed_at=observed_at,
            )
            claim.write_intent_event_id = entry.event_id
            return True

        return self._locked(token.execution_id, work)

    def acknowledge(self, token: WorkerClaim, request_id) -> bool:
        def work(row, content, history, claim, reservation, at):
            if not self._owned(token, claim) or claim.write_intent_event_id is None:
                return False
            if any(e.content.kind is WorkerEventKind.ACKNOWLEDGED for e in history):
                return False
            entry = self._append(
                row, content, WorkerEventKind.ACKNOWLEDGED, at, request_id=request_id
            )
            if entry.phase is ExecutionPhase.ACKNOWLEDGED:
                reservation.execution_id = None
            return True

        return self._locked(token.execution_id, work)

    def quarantine(self, execution_id, reason=WorkerBlockingReason.RECOVERY_UNCERTAIN) -> bool:
        def work(row, content, history, claim, reservation, at):
            if history[-1].content.phase is not ExecutionPhase.WRITE_INTENT:
                return False
            self._append(row, content, WorkerEventKind.QUARANTINED, at, reasons=(reason,))
            return True

        return self._locked(execution_id, work)

    def begin_readback(self, execution_id):
        def work(row, content, history, claim, reservation, at):
            if (
                history[-1].content.phase
                not in {
                    ExecutionPhase.ACKNOWLEDGED,
                    ExecutionPhase.QUARANTINED,
                }
                or claim is None
                or claim.readback_attempts >= 3
            ):
                return None
            if claim.readback_started_at is None:
                claim.readback_started_at = at
            deadline = utc(claim.readback_started_at) + timedelta(seconds=30)
            if at >= deadline:
                return None
            claim.readback_attempts += 1
            return claim.readback_attempts, deadline

        return self._locked(execution_id, work)

    def record_observation(self, execution_id, *, observation=None, observed_at=None, polls=1):
        def work(row, content, history, claim, reservation, at):
            if (
                history[-1].content.phase
                not in {
                    ExecutionPhase.ACKNOWLEDGED,
                    ExecutionPhase.QUARANTINED,
                }
                or claim is None
                or polls > claim.readback_attempts
            ):
                return False
            if any(getattr(e.content, "polls", 0) == polls for e in history):
                return False
            if observation is None:
                self._append(
                    row,
                    content,
                    WorkerEventKind.OBSERVATION_FAILED,
                    at,
                    reasons=(WorkerBlockingReason.READ_UNAVAILABLE,),
                    polls=polls,
                )
            else:
                self._append(
                    row,
                    content,
                    WorkerEventKind.OBSERVED,
                    at,
                    observation=observation,
                    observed_at=observed_at,
                    polls=polls,
                )
            return True

        return self._locked(execution_id, work)

    def inspect(self, execution_id):
        """Private worker snapshot, not a fourth human or a public authorization bypass."""
        return self._locked(
            execution_id,
            lambda row, content, history, claim, reservation, at: (
                history[-1].content.phase,
                content,
            ),
        )
