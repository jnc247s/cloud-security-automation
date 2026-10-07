"""Transactional proposal/approval service; deliberately no AWS or executor dependency."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.database.catalogs import CatalogPersistenceError
from app.database.integrity import canonical_json_sha256
from app.database.persistence import append_audit_event
from app.models import Finding, FindingOccurrence, Resource
from app.models.enums import AuditEventType
from app.models.remediation import RemediationDecision, RemediationProposal, RemediationRequest
from app.remediation.contracts import (
    ActorContext,
    ApprovalStatus,
    BlockingReason,
    DecisionKind,
    DecisionRequest,
    DecisionView,
    ProposalContent,
    ProposalRequest,
    ProposalView,
    RevocationRequest,
)
from app.remediation.provenance import baseline_for, governance_state, has_newer_assessment, utc
from app.schemas.api_views import Page
from app.security.authentication import Principal
from app.security.authorization import Capability, capabilities_for
from app.services.errors import EntityNotFoundError, RemediationError


@dataclass(frozen=True)
class MutationResult[ViewT]:
    value: ViewT
    replayed: bool


def _actor(principal: Principal, capability: Capability) -> ActorContext:
    if (
        capability not in capabilities_for(principal)
        or not principal.issuer
        or not principal.subject
    ):
        raise RemediationError("insufficient_capability")
    return ActorContext(
        issuer=principal.issuer,
        subject=principal.subject,
        roles=tuple(sorted(principal.role_names)),
        capability=capability,
    )


def _identity(actor: ActorContext) -> str:
    return canonical_json_sha256([actor.issuer, actor.subject])


class RemediationService:
    """Own mutation transactions on an idle session. Read methods never write."""

    def __init__(self, session: Session, *, clock: Callable[[], datetime] | None = None):
        self.session = session
        self.clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("remediation clock must be timezone-aware")
        return value.astimezone(UTC)

    def _finding(self, finding_id: UUID, *, lock: bool = False) -> Finding:
        resource_id = self.session.scalar(
            select(Finding.resource_id).where(Finding.finding_id == finding_id)
        )
        if resource_id is None:
            raise EntityNotFoundError("finding", finding_id)
        if lock:
            self.session.scalar(
                select(Resource).where(Resource.resource_id == resource_id).with_for_update()
            )
        statement = select(Finding).where(Finding.finding_id == finding_id)
        if lock:
            statement = statement.with_for_update()
        finding = self.session.scalar(statement.execution_options(populate_existing=True))
        if finding is None or finding.resource_id != resource_id:
            raise RemediationError("remediation_provenance_conflict")
        return finding

    def _proposal(self, proposal_id: UUID, *, lock: bool = False) -> RemediationProposal:
        if lock:
            finding_id = self.session.scalar(
                select(RemediationProposal.finding_id).where(
                    RemediationProposal.proposal_id == proposal_id
                )
            )
            if finding_id is None:
                raise EntityNotFoundError("remediation", proposal_id)
            self._finding(finding_id, lock=True)
        statement = select(RemediationProposal).where(
            RemediationProposal.proposal_id == proposal_id
        )
        if lock:
            statement = statement.with_for_update()
        row = self.session.scalar(statement.execution_options(populate_existing=True))
        if row is None:
            raise EntityNotFoundError("remediation", proposal_id)
        return row

    def _content(self, row: RemediationProposal) -> ProposalContent:
        try:
            if canonical_json_sha256(row.content) != row.proposal_sha256:
                raise ValueError("digest mismatch")
            content = ProposalContent.model_validate(row.content)
            if (
                content.proposal_id != row.proposal_id
                or content.finding_id != row.finding_id
                or content.baseline.occurrence_id != row.occurrence_id
                or content.account_id != row.account_id
                or content.proposer.issuer != row.actor_issuer
                or content.proposer.subject != row.actor_subject
                or list(content.proposer.roles) != row.actor_roles
                or content.proposer.capability is not Capability.PROPOSE
                or content.created_at != utc(row.created_at)
                or content.expires_at != utc(row.expires_at)
                or content.expires_at != content.created_at + timedelta(hours=24)
                or content.expected_encryption_by_default is not False
                or content.desired_encryption_by_default is not True
            ):
                raise ValueError("content mismatch")
            return content
        except (ValueError, TypeError, KeyError):
            raise RemediationError("remediation_provenance_conflict") from None

    def _blocking(self, content: ProposalContent, at: datetime) -> tuple[BlockingReason, ...]:
        reasons = []
        if at >= content.expires_at:
            reasons.append(BlockingReason.EXPIRED)
        finding = self._finding(content.finding_id)
        governance_digest, governance_blocking = governance_state(self.session, finding, at)
        if governance_digest != content.governance_sha256:
            reasons.append(BlockingReason.STALE_GOVERNANCE)
        reasons.extend(governance_blocking)
        if has_newer_assessment(self.session, finding, content.baseline):
            reasons.append(BlockingReason.STALE_TARGET)
        try:
            occurrence = self.session.get(FindingOccurrence, content.baseline.occurrence_id)
            if occurrence is None:
                raise ValueError("missing occurrence")
            current = baseline_for(self.session, finding, occurrence)
            if (
                current != content.baseline
                or content.resource_id != finding.resource_id
                or content.control_id != finding.control_id
                or content.account_id != finding.aws_account_id
                or content.region != finding.region
                or content.baseline.observed_at > at
            ):
                raise ValueError("baseline mismatch")
        except (ValueError, TypeError, KeyError, CatalogPersistenceError):
            reasons.append(BlockingReason.INVALID_PROVENANCE)
        return tuple(reasons)

    def _decisions(self, proposal_id: UUID):
        return self.session.scalars(
            select(RemediationDecision)
            .where(RemediationDecision.proposal_id == proposal_id)
            .order_by(RemediationDecision.created_at, RemediationDecision.decision_id)
        ).all()

    @staticmethod
    def _decision_view(row: RemediationDecision) -> DecisionView:
        return DecisionView(
            decision_id=row.decision_id,
            proposal_id=row.proposal_id,
            kind=row.kind,
            proposal_sha256=row.proposal_sha256,
            approval_decision_id=row.approval_decision_id,
            reason=row.reason,
            created_at=utc(row.created_at),
            actor=ActorContext(
                issuer=row.actor_issuer,
                subject=row.actor_subject,
                roles=tuple(row.actor_roles),
                capability=Capability.APPROVE,
            ),
        )

    def _view(self, row: RemediationProposal) -> ProposalView:
        content = self._content(row)
        decisions = self._decisions(row.proposal_id)
        kinds = {DecisionKind(decision.kind) for decision in decisions}
        status = (
            ApprovalStatus.REVOKED
            if DecisionKind.REVOKE in kinds
            else ApprovalStatus.REJECTED
            if DecisionKind.REJECT in kinds
            else ApprovalStatus.APPROVED
            if DecisionKind.APPROVE in kinds
            else ApprovalStatus.PROPOSED
        )
        at = self._now()
        return ProposalView(
            content=content,
            proposal_sha256=row.proposal_sha256,
            approval_status=status,
            blocking_reasons=self._blocking(content, at),
            validity_checked_at=at,
            decisions=tuple(self._decision_view(decision) for decision in decisions),
        )

    def get_proposal(self, proposal_id: UUID, principal: Principal) -> ProposalView:
        _actor(principal, Capability.READ)
        self._require_clean_read_session()
        with self.session.no_autoflush:
            return self._view(self._proposal(proposal_id))

    def _require_clean_read_session(self) -> None:
        # Refreshing retained provenance must neither flush nor discard a
        # caller's pending unit of work. Existing clean transactions are valid.
        if self.session.new or self.session.dirty or self.session.deleted:
            raise RemediationError("remediation_state_conflict")

    def list_proposals(
        self,
        principal: Principal,
        *,
        finding_id: UUID | None = None,
        account_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ):
        _actor(principal, Capability.READ)
        self._require_clean_read_session()
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("invalid remediation page")
        predicates = []
        if finding_id is not None:
            predicates.append(RemediationProposal.finding_id == finding_id)
        if account_id is not None:
            predicates.append(RemediationProposal.account_id == account_id)
        with self.session.no_autoflush:
            total = self.session.scalar(
                select(func.count()).select_from(RemediationProposal).where(*predicates)
            )
            rows = self.session.scalars(
                select(RemediationProposal)
                .where(*predicates)
                .order_by(RemediationProposal.created_at.desc(), RemediationProposal.proposal_id)
                .limit(limit)
                .offset(offset)
            ).all()
            return Page[ProposalView](
                items=tuple(self._view(row) for row in rows),
                total=total or 0,
                limit=limit,
                offset=offset,
            )

    def _replay(self, actor, operation, key, request_digest):
        ledger = self.session.scalar(
            select(RemediationRequest).where(
                RemediationRequest.actor_identity_sha256 == _identity(actor),
                RemediationRequest.operation == operation,
                RemediationRequest.idempotency_key == key,
            )
        )
        if ledger is None:
            return None
        if (
            ledger.actor_issuer != actor.issuer
            or ledger.actor_subject != actor.subject
            or ledger.request_sha256 != request_digest
        ):
            raise RemediationError("remediation_idempotency_conflict")
        if operation == "CREATE":
            value = self._view(self._proposal(ledger.proposal_id))
        else:
            decision = self.session.get(RemediationDecision, ledger.decision_id)
            if decision is None or decision.proposal_id != ledger.proposal_id:
                raise RemediationError("remediation_provenance_conflict")
            value = self._decision_view(decision)
        return MutationResult(value=value, replayed=True)

    def _mutate(self, operation, key, document, principal, capability, write):
        actor = _actor(principal, capability)
        if not isinstance(key, UUID):
            raise ValueError("idempotency key must be a UUID")
        if (
            self.session.in_transaction()
            or self.session.new
            or self.session.dirty
            or self.session.deleted
        ):
            raise RemediationError("remediation_state_conflict")
        digest = canonical_json_sha256(document)
        try:
            if self.session.get_bind().dialect.name == "sqlite":
                connection = self.session.connection()
                if not connection.connection.driver_connection.in_transaction:
                    self.session.execute(text("BEGIN IMMEDIATE"))
                else:
                    self.session.execute(
                        text("UPDATE alembic_version SET version_num = version_num WHERE 0")
                    )
            replay = self._replay(actor, operation, key, digest)
            if replay is not None:
                self.session.commit()
                return replay
            proposal, decision = write(actor, lambda: self._replay(actor, operation, key, digest))
            if isinstance(proposal, MutationResult):
                self.session.commit()
                return proposal
            self.session.add(
                RemediationRequest(
                    request_id=uuid4(),
                    actor_identity_sha256=_identity(actor),
                    actor_issuer=actor.issuer,
                    actor_subject=actor.subject,
                    operation=operation,
                    idempotency_key=key,
                    request_sha256=digest,
                    proposal_id=proposal.proposal_id,
                    decision_id=decision.decision_id if decision else None,
                )
            )
            self.session.flush()
            value = self._decision_view(decision) if decision else self._view(proposal)
            self.session.commit()
            return MutationResult(value=value, replayed=False)
        except IntegrityError:
            self.session.rollback()
            try:
                replay = self._replay(actor, operation, key, digest)
                if replay is not None:
                    self.session.commit()
                    return replay
            except OperationalError:
                self.session.rollback()
                raise RemediationError("remediation_database_unavailable") from None
            except Exception:
                self.session.rollback()
                raise
            self.session.rollback()
            raise RemediationError("remediation_state_conflict") from None
        except OperationalError:
            self.session.rollback()
            raise RemediationError("remediation_database_unavailable") from None
        except Exception:
            self.session.rollback()
            raise

    def _audit(self, event_type, proposal, actor, at, decision=None):
        append_audit_event(
            self.session,
            event_type,
            "remediation",
            proposal.proposal_id,
            at,
            actor_type="human",
            actor_id=_identity(actor),
            metadata={
                "schema_version": "1.0.0",
                "actor": actor.model_dump(mode="json"),
                "proposal_id": str(proposal.proposal_id),
                "proposal_sha256": proposal.proposal_sha256,
                "decision_id": str(decision.decision_id) if decision else None,
            },
        )

    def propose(self, request: ProposalRequest, principal: Principal, key: UUID):
        request = ProposalRequest.model_validate(request.model_dump(mode="json"))

        def write(actor, replay):
            finding = self._finding(request.finding_id, lock=True)
            previous = replay()
            if previous is not None:
                return previous, None
            occurrence = self.session.get(FindingOccurrence, request.occurrence_id)
            if occurrence is None:
                raise EntityNotFoundError("finding_occurrence", request.occurrence_id)
            try:
                baseline = baseline_for(self.session, finding, occurrence)
            except (ValueError, TypeError, KeyError, CatalogPersistenceError):
                raise RemediationError("remediation_provenance_conflict") from None
            at = self._now()
            governance_digest, _ = governance_state(self.session, finding, at)
            content = ProposalContent(
                proposal_id=uuid4(),
                finding_id=finding.finding_id,
                resource_id=finding.resource_id,
                control_id=finding.control_id,
                account_id=finding.aws_account_id,
                region=finding.region,
                baseline=baseline,
                governance_sha256=governance_digest,
                proposer=actor,
                reason=request.reason,
                created_at=at,
                expires_at=at + timedelta(hours=24),
            )
            if self._blocking(content, at):
                raise RemediationError("remediation_ineligible")
            document = content.model_dump(mode="json")
            proposal = RemediationProposal(
                proposal_id=content.proposal_id,
                finding_id=finding.finding_id,
                occurrence_id=occurrence.occurrence_id,
                account_id=finding.aws_account_id,
                actor_issuer=actor.issuer,
                actor_subject=actor.subject,
                actor_roles=list(actor.roles),
                content=document,
                proposal_sha256=canonical_json_sha256(document),
                created_at=at,
                expires_at=content.expires_at,
            )
            self.session.add(proposal)
            self.session.flush()
            self._audit(AuditEventType.REMEDIATION_PROPOSED, proposal, actor, at)
            return proposal, None

        return self._mutate(
            "CREATE", key, request.model_dump(mode="json"), principal, Capability.PROPOSE, write
        )

    def _decision(self, proposal, actor, kind, reason, at, approval=None):
        row = RemediationDecision(
            decision_id=uuid4(),
            proposal_id=proposal.proposal_id,
            kind=kind.value,
            proposal_sha256=proposal.proposal_sha256,
            actor_issuer=actor.issuer,
            actor_subject=actor.subject,
            actor_roles=list(actor.roles),
            reason=reason,
            created_at=at,
            approval_decision_id=approval,
        )
        self.session.add(row)
        self.session.flush()
        self._audit(
            {
                DecisionKind.APPROVE: AuditEventType.REMEDIATION_APPROVED,
                DecisionKind.REJECT: AuditEventType.REMEDIATION_REJECTED,
                DecisionKind.REVOKE: AuditEventType.REMEDIATION_REVOKED,
            }[kind],
            proposal,
            actor,
            at,
            row,
        )
        return row

    def decide(self, proposal_id: UUID, request: DecisionRequest, principal: Principal, key: UUID):
        request = DecisionRequest.model_validate(request.model_dump(mode="json"))

        def write(actor, replay):
            proposal = self._proposal(proposal_id, lock=True)
            previous = replay()
            if previous is not None:
                return previous, None
            content = self._content(proposal)
            if request.proposal_sha256 != proposal.proposal_sha256:
                raise RemediationError("remediation_provenance_conflict")
            if (actor.issuer, actor.subject) == (content.proposer.issuer, content.proposer.subject):
                raise RemediationError("remediation_separation_required")
            if self._decisions(proposal_id):
                raise RemediationError("remediation_state_conflict")
            at = self._now()
            if at < content.created_at:
                raise RemediationError("remediation_state_conflict")
            if request.decision is DecisionKind.APPROVE and self._blocking(content, at):
                raise RemediationError("remediation_ineligible")
            return proposal, self._decision(proposal, actor, request.decision, request.reason, at)

        return self._mutate(
            "DECIDE",
            key,
            {"proposal_id": str(proposal_id), **request.model_dump(mode="json")},
            principal,
            Capability.APPROVE,
            write,
        )

    def revoke(
        self, proposal_id: UUID, request: RevocationRequest, principal: Principal, key: UUID
    ):
        request = RevocationRequest.model_validate(request.model_dump(mode="json"))

        def write(actor, replay):
            proposal = self._proposal(proposal_id, lock=True)
            previous = replay()
            if previous is not None:
                return previous, None
            self._content(proposal)
            if request.proposal_sha256 != proposal.proposal_sha256:
                raise RemediationError("remediation_provenance_conflict")
            decisions = self._decisions(proposal_id)
            if len(decisions) != 1 or decisions[0].kind != DecisionKind.APPROVE:
                raise RemediationError("remediation_state_conflict")
            approval = decisions[0]
            at = self._now()
            if approval.decision_id != request.approval_decision_id or at < utc(
                approval.created_at
            ):
                raise RemediationError("remediation_state_conflict")
            return proposal, self._decision(
                proposal,
                actor,
                DecisionKind.REVOKE,
                request.reason,
                at,
                approval.decision_id,
            )

        return self._mutate(
            "REVOKE",
            key,
            {"proposal_id": str(proposal_id), **request.model_dump(mode="json")},
            principal,
            Capability.APPROVE,
            write,
        )
