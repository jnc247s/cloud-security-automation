"""Third-human admission and versioned history. No AWS, credentials or orchestration."""

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.database.integrity import canonical_json_sha256
from app.database.persistence import append_audit_event
from app.models import AuditEvent
from app.models.enums import AuditEventType
from app.models.remediation_execution import (
    RemediationAdmissionGuard,
    RemediationExecution,
    RemediationExecutionEvent,
    RemediationTargetReservation,
    RemediationWorkerClaim,
)
from app.remediation.contracts import DecisionKind
from app.remediation.execution_contracts import (
    ADMISSION_CAPACITY,
    AdmissionScope,
    ExecutionBlockingReason,
    ExecutionContent,
    ExecutionEventContent,
    ExecutionEventKind,
    ExecutionEventView,
    ExecutionPhase,
    ExecutionRequest,
    ExecutionView,
)
from app.remediation.provenance import utc
from app.remediation.worker_contracts import (
    WorkerEventContent,
    WorkerEventKind,
    validate_worker_entry,
)
from app.schemas.api_views import Page
from app.security.authentication import Principal
from app.security.authorization import Capability, capabilities_for
from app.services.errors import EntityNotFoundError, RemediationError
from app.services.remediation_service import MutationResult, RemediationService, _actor, _identity

_PHASES = {
    ExecutionEventKind.REQUESTED: ExecutionPhase.QUEUED,
    ExecutionEventKind.EXPIRED: ExecutionPhase.EXPIRED,
    ExecutionEventKind.BLOCKED: ExecutionPhase.BLOCKED,
}


class RemediationExecutionService:
    """Own short mutation transactions on idle sessions; READ never changes history."""

    def __init__(
        self,
        session: Session,
        *,
        scope: AdmissionScope | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.session = session
        self.scope = AdmissionScope.model_validate((scope or AdmissionScope()).model_dump())
        self.authority = RemediationService(session, clock=clock)

    @staticmethod
    def _document(proposal_id, request):
        return {"proposal_id": str(proposal_id), **request.model_dump(mode="json")}

    def _row(self, execution_id):
        row = self.session.scalar(
            select(RemediationExecution)
            .where(RemediationExecution.execution_id == execution_id)
            .execution_options(populate_existing=True)
        )
        if row is None:
            raise EntityNotFoundError("remediation_execution", execution_id)
        return row

    def _content(self, row):
        try:
            content = ExecutionContent.model_validate(row.content)
            proposal = self.authority._proposal(row.proposal_id)
            accepted = self.authority._content(proposal)
            approval = next(
                d
                for d in self.authority._decisions(row.proposal_id)
                if d.decision_id == row.approval_decision_id
            )
            approval_view = self.authority._decision_view(approval)
            requester = content.requested_by
            stored_principal = Principal(
                requester.subject, frozenset(requester.roles), requester.issuer
            )
            request = ExecutionRequest(
                proposal_sha256=content.proposal_sha256,
                approval_decision_id=content.approval.decision_id,
                reason=content.reason,
            )
            if (
                canonical_json_sha256(row.content) != row.execution_sha256
                or content.execution_id != row.execution_id
                or content.proposal != accepted
                or content.proposal_sha256 != proposal.proposal_sha256
                or content.approval != approval_view
                or content.approval.kind is not DecisionKind.APPROVE
                or content.approval.proposal_sha256 != content.proposal_sha256
                or content.approval_sha256
                != canonical_json_sha256(approval_view.model_dump(mode="json"))
                or requester.capability is not Capability.EXECUTE
                or Capability.EXECUTE not in capabilities_for(stored_principal)
                or (requester.issuer, requester.subject)
                in {
                    (accepted.proposer.issuer, accepted.proposer.subject),
                    (approval.actor_issuer, approval.actor_subject),
                }
                or requester.issuer != row.actor_issuer
                or requester.subject != row.actor_subject
                or _identity(requester) != row.actor_identity_sha256
                or content.idempotency_key != row.idempotency_key
                or canonical_json_sha256(self._document(row.proposal_id, request))
                != row.request_sha256
                or content.created_at != utc(row.created_at)
                or content.expires_at != utc(row.expires_at)
                or content.created_at < approval_view.created_at
                or content.created_at >= accepted.expires_at
                or content.expires_at
                != min(accepted.expires_at, content.created_at + timedelta(minutes=5))
            ):
                raise ValueError("execution binding mismatch")
            return content
        except (ValueError, TypeError, KeyError, StopIteration):
            raise RemediationError("remediation_provenance_conflict") from None

    @staticmethod
    def _audit_metadata(content, digest):
        return {
            "schema_version": content.schema_version,
            "actor": content.actor.model_dump(mode="json"),
            "execution_id": str(content.execution_id),
            "execution_sha256": content.execution_sha256,
            "execution_event_id": str(content.event_id),
            "event_sha256": digest,
            "sequence": content.sequence,
            "kind": content.kind.value,
        }

    def _events(self, row, content=None):
        content = content or self._content(row)
        rows = self.session.scalars(
            select(RemediationExecutionEvent)
            .where(RemediationExecutionEvent.execution_id == row.execution_id)
            .order_by(RemediationExecutionEvent.sequence)
            .execution_options(populate_existing=True)
        ).all()
        previous = None
        result = []
        try:
            if not rows:
                raise ValueError("missing execution journal")
            for index, event in enumerate(rows, 1):
                worker = event.content.get("schema_version") == "2.0.0"
                entry = (
                    WorkerEventContent.model_validate(event.content)
                    if worker
                    else ExecutionEventContent.model_validate(event.content)
                )
                if worker:
                    if not result:
                        raise ValueError("missing human admission event")
                    validate_worker_entry(entry, result[-1].content.phase, content)
                    actor_type = "service"
                    actor_id = canonical_json_sha256(entry.actor.model_dump(mode="json"))
                else:
                    actor_type = "human"
                    actor_id = _identity(entry.actor)
                    if (
                        entry.phase is not _PHASES[entry.kind]
                        or entry.actor.capability is not Capability.EXECUTE
                        or (
                            index == 1
                            and (
                                entry.kind is not ExecutionEventKind.REQUESTED
                                or entry.blocking_reasons
                                or entry.actor != content.requested_by
                                or entry.created_at != content.created_at
                            )
                        )
                        or (
                            index == 2
                            and (
                                entry.kind is ExecutionEventKind.REQUESTED
                                or not entry.blocking_reasons
                                or result[-1].content.phase is not ExecutionPhase.QUEUED
                            )
                        )
                        or (
                            entry.kind is ExecutionEventKind.EXPIRED
                            and (
                                entry.created_at < content.expires_at
                                or ExecutionBlockingReason.EXECUTION_EXPIRED
                                not in entry.blocking_reasons
                            )
                        )
                    ):
                        raise ValueError("human execution journal mismatch")
                audit = self.session.get(AuditEvent, event.audit_event_id)
                if (
                    canonical_json_sha256(event.content) != event.event_sha256
                    or entry.event_id != event.event_id
                    or entry.execution_id != row.execution_id
                    or entry.execution_sha256 != row.execution_sha256
                    or entry.sequence != index
                    or event.sequence != index
                    or entry.kind.value != event.kind
                    or entry.previous_event_sha256 != previous
                    or event.previous_event_sha256 != previous
                    or entry.created_at != utc(event.created_at)
                    or entry.created_at
                    < (result[-1].content.created_at if result else content.created_at)
                    or audit is None
                    or audit.actor_type != actor_type
                    or audit.actor_id != actor_id
                    or audit.target_type != "remediation_execution"
                    or audit.target_id != row.execution_id
                    or audit.event_type.value != "REMEDIATION_EXECUTION_" + entry.kind.value
                    or utc(audit.timestamp) != entry.created_at
                    or audit.event_metadata != self._audit_metadata(entry, event.event_sha256)
                ):
                    raise ValueError("execution journal mismatch")
                result.append(
                    ExecutionEventView(
                        content=entry,
                        event_sha256=event.event_sha256,
                        audit_event_id=event.audit_event_id,
                    )
                )
                previous = event.event_sha256
            claim = self.session.get(
                RemediationWorkerClaim, row.execution_id, populate_existing=True
            )
            claimed = [e for e in result if e.content.kind is WorkerEventKind.CLAIMED]
            intents = [e for e in result if e.content.kind is WorkerEventKind.WRITE_INTENT]
            if bool(claimed) != (claim is not None) or len(intents) > 1:
                raise ValueError("worker coordination mismatch")
            if claim is not None and (
                claim.generation != len(claimed)
                or bool(intents) != (claim.write_intent_event_id is not None)
                or (intents and claim.write_intent_event_id != intents[0].content.event_id)
                or any(
                    e.content.actor.expected_role_arn != claim.expected_role_arn
                    for e in result
                    if isinstance(e.content, WorkerEventContent)
                )
            ):
                raise ValueError("worker claim history mismatch")
            observed = [
                e.content
                for e in result
                if isinstance(e.content, WorkerEventContent)
                and e.content.kind
                in {
                    WorkerEventKind.OBSERVED,
                    WorkerEventKind.OBSERVATION_FAILED,
                }
            ]
            if observed and (claim is None or claim.readback_started_at is None):
                raise ValueError("missing readback budget")
            if len({e.polls for e in observed}) != len(observed) or any(
                e.polls > claim.readback_attempts
                or (
                    e.observed_at is not None
                    and not utc(claim.readback_started_at)
                    <= e.observed_at
                    < utc(claim.readback_started_at) + timedelta(seconds=30)
                )
                for e in observed
            ):
                raise ValueError("readback budget mismatch")
            return tuple(result)
        except (ValueError, TypeError, KeyError):
            raise RemediationError("remediation_provenance_conflict") from None

    def _blocking(self, content, at):
        if at < content.created_at:
            raise RemediationError("remediation_state_conflict")
        reasons = list(self.authority._blocking(content.proposal, at))
        if at >= content.expires_at:
            reasons.append(ExecutionBlockingReason.EXECUTION_EXPIRED)
        if any(
            d.kind == DecisionKind.REVOKE
            for d in self.authority._decisions(content.proposal.proposal_id)
        ):
            reasons.append(ExecutionBlockingReason.APPROVAL_REVOKED)
        return tuple(reasons)

    def _view(self, row):
        content = self._content(row)
        events = self._events(row, content)
        at = self.authority._now()
        reservation = self.session.scalar(
            select(RemediationTargetReservation)
            .where(
                RemediationTargetReservation.account_id == content.proposal.account_id,
                RemediationTargetReservation.region == content.proposal.region,
                RemediationTargetReservation.action_id == content.proposal.action_id,
            )
            .execution_options(populate_existing=True)
        )
        if reservation is None or reservation.resource_id != content.proposal.resource_id:
            raise RemediationError("remediation_provenance_conflict")
        held = reservation.execution_id == row.execution_id
        if held != (
            events[-1].content.phase
            in {
                ExecutionPhase.QUEUED,
                ExecutionPhase.CLAIMED,
                ExecutionPhase.WRITE_INTENT,
                ExecutionPhase.QUARANTINED,
            }
        ):
            raise RemediationError("remediation_provenance_conflict")
        return ExecutionView(
            content=content,
            execution_sha256=row.execution_sha256,
            phase=events[-1].content.phase,
            blocking_reasons=self._blocking(content, at),
            validity_checked_at=at,
            reservation_held=held,
            events=events,
        )

    def get_execution(self, execution_id: UUID, principal: Principal) -> ExecutionView:
        _actor(principal, Capability.READ)
        self.authority._require_clean_read_session()
        with self.session.no_autoflush:
            return self._view(self._row(execution_id))

    def list_executions(
        self,
        principal: Principal,
        *,
        proposal_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Page[ExecutionView]:
        _actor(principal, Capability.READ)
        self.authority._require_clean_read_session()
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("invalid execution page")
        predicates = (
            [] if proposal_id is None else [RemediationExecution.proposal_id == proposal_id]
        )
        with self.session.no_autoflush:
            total = self.session.scalar(
                select(func.count()).select_from(RemediationExecution).where(*predicates)
            )
            rows = self.session.scalars(
                select(RemediationExecution)
                .where(*predicates)
                .order_by(
                    RemediationExecution.created_at.desc(),
                    RemediationExecution.execution_id,
                )
                .limit(limit)
                .offset(offset)
            ).all()
            return Page[ExecutionView](
                items=tuple(self._view(row) for row in rows),
                total=total or 0,
                limit=limit,
                offset=offset,
            )

    def _journal(self, row, actor, at, kind, reasons=()):
        history = () if kind is ExecutionEventKind.REQUESTED else self._events(row)
        if history and history[-1].content.phase is not ExecutionPhase.QUEUED:
            raise RemediationError("remediation_state_conflict")
        entry = ExecutionEventContent(
            event_id=uuid4(),
            execution_id=row.execution_id,
            execution_sha256=row.execution_sha256,
            sequence=len(history) + 1,
            kind=kind,
            phase=_PHASES[kind],
            previous_event_sha256=history[-1].event_sha256 if history else None,
            actor=actor,
            created_at=at,
            blocking_reasons=reasons,
        )
        document = entry.model_dump(mode="json")
        digest = canonical_json_sha256(document)
        audit = append_audit_event(
            self.session,
            AuditEventType("REMEDIATION_EXECUTION_" + kind.value),
            "remediation_execution",
            row.execution_id,
            at,
            actor_type="human",
            actor_id=_identity(actor),
            metadata=self._audit_metadata(entry, digest),
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

    def _reap_expired(self, actor, at):
        # The singleton guard serializes all execution mutations before target locks.
        # Only validated QUEUED/no-dispatch history can release; later worker phases must not.
        reservations = self.session.scalars(
            select(RemediationTargetReservation)
            .join(
                RemediationExecution,
                RemediationExecution.execution_id == RemediationTargetReservation.execution_id,
            )
            .where(RemediationExecution.expires_at <= at)
        ).all()
        for reservation in reservations:
            row = self._row(reservation.execution_id)
            content = self._content(row)
            if (
                reservation.resource_id != content.proposal.resource_id
                or reservation.account_id != content.proposal.account_id
                or reservation.region != content.proposal.region
                or reservation.action_id != content.proposal.action_id
            ):
                raise RemediationError("remediation_provenance_conflict")
            if self._events(row, content)[-1].content.phase is not ExecutionPhase.QUEUED:
                continue  # Only the worker can terminate a fenced no-intent claim.
            self._journal(
                row,
                actor,
                at,
                ExecutionEventKind.EXPIRED,
                (ExecutionBlockingReason.EXECUTION_EXPIRED,),
            )
            reservation.execution_id = None
            self.session.flush()

    def _replay(self, actor, key, digest):
        row = self.session.scalar(
            select(RemediationExecution).where(
                RemediationExecution.actor_identity_sha256 == _identity(actor),
                RemediationExecution.idempotency_key == key,
            )
        )
        if row is None:
            return None
        if (
            row.actor_issuer != actor.issuer
            or row.actor_subject != actor.subject
            or row.request_sha256 != digest
        ):
            raise RemediationError("remediation_idempotency_conflict")
        return MutationResult(value=self._view(row), replayed=True)

    def admit(self, proposal_id: UUID, request: ExecutionRequest, principal: Principal, key: UUID):
        request = ExecutionRequest.model_validate(request.model_dump(mode="json"))
        actor = _actor(principal, Capability.EXECUTE)
        if not isinstance(key, UUID) or not isinstance(proposal_id, UUID):
            raise ValueError("execution identifiers must be UUIDs")
        if (
            self.session.in_transaction()
            or self.session.new
            or self.session.dirty
            or self.session.deleted
        ):
            raise RemediationError("remediation_state_conflict")
        digest = canonical_json_sha256(self._document(proposal_id, request))
        try:
            with self.session.begin():
                if self.session.get_bind().dialect.name == "sqlite":
                    connection = self.session.connection()
                    if not connection.connection.driver_connection.in_transaction:
                        self.session.execute(text("BEGIN IMMEDIATE"))
                    else:
                        self.session.execute(
                            text("UPDATE alembic_version SET version_num = version_num WHERE 0")
                        )
                guard = self.session.scalar(
                    select(RemediationAdmissionGuard)
                    .where(
                        RemediationAdmissionGuard.guard_id == 1,
                    )
                    .with_for_update()
                )
                if guard is None:
                    raise RemediationError("remediation_database_unavailable")
                replay = self._replay(actor, key, digest)
                if replay is not None:
                    return replay
                if not self.scope.enabled:
                    raise RemediationError("remediation_execution_disabled")
                at = self.authority._now()
                self._reap_expired(actor, at)
                proposal = self.authority._proposal(proposal_id, lock=True)
                view = self.authority._view(proposal)
                at = (
                    self.authority._now()
                )  # Waiting on locks never freezes eligibility/expiry time.
                if request.proposal_sha256 != proposal.proposal_sha256:
                    raise RemediationError("remediation_provenance_conflict")
                approvals = [d for d in view.decisions if d.kind is DecisionKind.APPROVE]
                if (
                    len(view.decisions) != 1
                    or len(approvals) != 1
                    or approvals[0].decision_id != request.approval_decision_id
                    or self.authority._blocking(view.content, at)
                ):
                    raise RemediationError("remediation_ineligible")
                approval = approvals[0]
                if (actor.issuer, actor.subject) in {
                    (view.content.proposer.issuer, view.content.proposer.subject),
                    (approval.actor.issuer, approval.actor.subject),
                }:
                    raise RemediationError("remediation_separation_required")
                if at < approval.created_at:
                    raise RemediationError("remediation_state_conflict")
                if (
                    view.content.account_id != self.scope.account_id
                    or view.content.region != self.scope.region
                ):
                    raise RemediationError("remediation_execution_scope_conflict")
                if (
                    self.session.scalar(
                        select(RemediationExecution.execution_id).where(
                            RemediationExecution.proposal_id == proposal_id,
                        )
                    )
                    is not None
                ):
                    raise RemediationError("remediation_state_conflict")
                reservation = self.session.scalar(
                    select(RemediationTargetReservation)
                    .where(
                        RemediationTargetReservation.account_id == view.content.account_id,
                        RemediationTargetReservation.region == view.content.region,
                        RemediationTargetReservation.action_id == view.content.action_id,
                    )
                    .with_for_update()
                )
                if reservation is not None and reservation.resource_id != view.content.resource_id:
                    raise RemediationError("remediation_provenance_conflict")
                if reservation is not None and reservation.execution_id is not None:
                    previous = self._row(reservation.execution_id)
                    previous_content = self._content(previous)
                    if (
                        self._events(previous, previous_content)[-1].content.phase
                        is not ExecutionPhase.QUEUED
                    ):
                        raise RemediationError("remediation_execution_target_reserved")
                    reasons = self._blocking(previous_content, at)
                    if not reasons:
                        raise RemediationError("remediation_execution_target_reserved")
                    self._journal(previous, actor, at, ExecutionEventKind.BLOCKED, reasons)
                    reservation.execution_id = None
                    self.session.flush()
                total = self.session.scalar(
                    select(func.count())
                    .select_from(RemediationTargetReservation)
                    .where(
                        RemediationTargetReservation.execution_id.is_not(None),
                    )
                )
                if total >= ADMISSION_CAPACITY:
                    raise RemediationError("remediation_execution_capacity")
                content = ExecutionContent(
                    execution_id=uuid4(),
                    proposal=view.content,
                    proposal_sha256=proposal.proposal_sha256,
                    approval=approval,
                    approval_sha256=canonical_json_sha256(approval.model_dump(mode="json")),
                    requested_by=actor,
                    idempotency_key=key,
                    reason=request.reason,
                    created_at=at,
                    expires_at=min(view.content.expires_at, at + timedelta(minutes=5)),
                )
                document = content.model_dump(mode="json")
                row = RemediationExecution(
                    execution_id=content.execution_id,
                    proposal_id=proposal_id,
                    approval_decision_id=approval.decision_id,
                    actor_identity_sha256=_identity(actor),
                    actor_issuer=actor.issuer,
                    actor_subject=actor.subject,
                    idempotency_key=key,
                    request_sha256=digest,
                    content=document,
                    execution_sha256=canonical_json_sha256(document),
                    created_at=at,
                    expires_at=content.expires_at,
                )
                self.session.add(row)
                self.session.flush()
                self._journal(row, actor, at, ExecutionEventKind.REQUESTED)
                if reservation is None:
                    reservation = RemediationTargetReservation(
                        reservation_id=uuid4(),
                        resource_id=view.content.resource_id,
                        account_id=view.content.account_id,
                        region=view.content.region,
                        action_id=view.content.action_id,
                    )
                    self.session.add(reservation)
                reservation.execution_id = row.execution_id
                self.session.flush()
                return MutationResult(value=self._view(row), replayed=False)
        except IntegrityError:
            self.session.rollback()
            raise RemediationError("remediation_state_conflict") from None
        except OperationalError:
            self.session.rollback()
            raise RemediationError("remediation_database_unavailable") from None
        except Exception:
            self.session.rollback()
            raise
