"""Closed owning-parent external governance fixtures; never a new public mutation API."""

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from tests.dashboard_integrated_protocol import ControlKind, ControlMessage

GOVERNANCE_ACTOR = "integrated-fixture-risk-owner"
EXCEPTION_REASON = "A bounded external exception must block retained remediation authority."


@dataclass(frozen=True)
class AuthorityCase:
    approved: bool
    finding: str
    blocker: str
    dispositions: tuple[str, ...] = ()
    active_exception: bool = False


def authority_case(name):
    choices = {
        "admission-stale": AuthorityCase(True, "OPEN", "STALE_TARGET"),
        "governance-change": AuthorityCase(
            False, "ACKNOWLEDGED", "STALE_GOVERNANCE", ("ACKNOWLEDGED",)
        ),
        "governance-round-trip": AuthorityCase(
            True, "OPEN", "STALE_GOVERNANCE", ("FALSE_POSITIVE", "OPEN")
        ),
        "governance-exception": AuthorityCase(
            False, "OPEN", "ACTIVE_EXCEPTION", active_exception=True
        ),
    }
    if type(name) is not str or name not in choices:
        raise ValueError("Invalid integrated authority case")
    return choices[name]


def bound_authority(parent, message):
    if not authority_case(parent.scenario.name).approved:
        from tests.dashboard_integrated_staleness import _original

        return _original(parent, message)
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.integrity import canonical_json_sha256
    from app.models import AuditEvent
    from app.models.enums import AuditEventType
    from app.models.remediation import RemediationRequest
    from app.remediation.contracts import DecisionRequest, ProposalRequest
    from app.remediation.provenance import utc
    from app.services.remediation_service import RemediationService
    from tests.worker_http import database_state

    before, original = database_state(parent.engine), parent.proposal_only_before
    allowed = {
        "remediation_proposals",
        "remediation_decisions",
        "remediation_requests",
        "audit_events",
    }
    if (
        type(original) is not dict
        or set(original) != set(before)
        or any(original[name] != before[name] for name in before if name not in allowed)
        or len(before["remediation_proposals"]) != 1
        or len(before["remediation_decisions"]) != 1
        or len(before["remediation_requests"]) != 2
        or len(before["audit_events"]) != len(original["audit_events"]) + 2
        or any(row not in before["audit_events"] for row in original["audit_events"])
    ):
        raise ValueError("Invalid original approved authority binding")
    with Session(parent.engine) as session:
        view = RemediationService(session).get_proposal(message.target_id, parent._principal())
        parent._bind_proposal(view.content)
        if (
            view.approval_status.value != "APPROVED"
            or view.blocking_reasons
            or len(view.decisions) != 1
            or view.proposal_sha256 != canonical_json_sha256(view.content.model_dump(mode="json"))
        ):
            raise ValueError("Invalid original approved authority binding")
        decision, proposer = view.decisions[0], view.content.proposer
        if (
            (proposer.issuer, proposer.subject, proposer.roles, proposer.capability.value)
            != (parent.issuer, "proposer", ("ANALYST",), "PROPOSE")
            or (
                decision.actor.issuer,
                decision.actor.subject,
                decision.actor.roles,
                decision.actor.capability.value,
            )
            != (parent.issuer, "approver", ("APPROVER",), "APPROVE")
            or decision.kind.value != "APPROVE"
            or decision.approval_decision_id is not None
            or decision.proposal_id != message.target_id
            or decision.proposal_sha256 != view.proposal_sha256
            or not view.content.created_at <= decision.created_at < view.content.expires_at
        ):
            raise ValueError("Invalid original approved authority binding")
        requests = session.scalars(select(RemediationRequest)).all()
        by_operation = {item.operation: item for item in requests}
        if set(by_operation) != {"CREATE", "DECIDE"}:
            raise ValueError("Invalid original approved authority binding")
        proposed = ProposalRequest(
            finding_id=view.content.finding_id,
            occurrence_id=view.content.baseline.occurrence_id,
            action_id=view.content.action_id,
            action_version=view.content.action_version,
            reason=view.content.reason,
        )
        decided = DecisionRequest(
            proposal_sha256=view.proposal_sha256, decision="APPROVE", reason=decision.reason
        )
        expected = (
            (
                "CREATE",
                proposer,
                proposed,
                None,
                view.content.created_at,
                AuditEventType.REMEDIATION_PROPOSED,
            ),
            (
                "DECIDE",
                decision.actor,
                decided,
                decision.decision_id,
                decision.created_at,
                AuditEventType.REMEDIATION_APPROVED,
            ),
        )
        for operation, actor, request, identifier, at, event_type in expected:
            ledger = by_operation[operation]
            audit = session.execute(
                select(AuditEvent).where(
                    AuditEvent.target_id == message.target_id, AuditEvent.event_type == event_type
                )
            ).scalar_one()
            identity = canonical_json_sha256([actor.issuer, actor.subject])
            normalized = request.model_dump(mode="json")
            if operation == "DECIDE":
                normalized = {"proposal_id": str(message.target_id), **normalized}
            if (
                ledger.proposal_id != message.target_id
                or ledger.decision_id != identifier
                or ledger.idempotency_key.version != 4
                or (operation == "CREATE" and ledger.idempotency_key != message.request_id)
                or (ledger.actor_issuer, ledger.actor_subject) != (actor.issuer, actor.subject)
                or ledger.actor_identity_sha256 != identity
                or ledger.request_sha256 != canonical_json_sha256(normalized)
                or audit.actor_type != "human"
                or audit.actor_id != identity
                or audit.target_type != "remediation"
                or utc(audit.timestamp) != at
                or audit.event_metadata
                != {
                    "schema_version": "1.0.0",
                    "actor": actor.model_dump(mode="json"),
                    "proposal_id": str(message.target_id),
                    "proposal_sha256": view.proposal_sha256,
                    "decision_id": str(identifier) if identifier else None,
                }
            ):
                raise ValueError("Invalid original approved authority binding")
    return view, before


def change_bound_governance(parent, message):
    if (
        os.environ.get("DASHBOARD_BROWSER_TEST") != "1"
        or type(message) is not ControlMessage
        or message.kind is not ControlKind.CHANGE_GOVERNANCE
        or message.instance_id != UUID(parent.instance)
        or message.target_id is None
        or parent.governance_dispatched
        or parent.worker_dispatched
    ):
        raise ValueError("Integrated governance change unavailable")
    case = authority_case(parent.scenario.name)
    if parent.scenario.name == "admission-stale":
        raise ValueError("Integrated governance change unavailable")
    parent.last_stage = "GOVERNANCE_OWNERSHIP"
    parent._owned()
    parent.last_stage = "GOVERNANCE_ORIGINAL_AUTHORITY"
    original, before = bound_authority(parent, message)
    from sqlalchemy.orm import Session

    from app.database.governance import create_finding_exception, set_finding_disposition
    from app.models.enums import FindingStatus
    from app.services.remediation_service import RemediationService
    from tests.worker_http import database_state

    parent.governance_dispatched = True  # Sticky after any committed or uncertain external change.
    parent.governance_at = datetime.now(UTC)
    parent.governance_view, parent.governance_before = original, before
    steps = []
    for status in case.dispositions:
        with Session(parent.engine) as session, session.begin():
            set_finding_disposition(
                session,
                finding_id=original.content.finding_id,
                status=FindingStatus(status),
                at=parent.governance_at,
                actor_id=GOVERNANCE_ACTOR,
            )
        # Each step commits separately; a same-time status round trip must never revive authority.
        with Session(parent.engine) as session:
            view = RemediationService(session).get_proposal(message.target_id, parent._principal())
            if "STALE_GOVERNANCE" not in {reason.value for reason in view.blocking_reasons}:
                raise ValueError("Governance step revived old authority")
            steps.append(view)
    if case.active_exception:
        with Session(parent.engine) as session, session.begin():
            exception = create_finding_exception(
                session,
                finding_id=original.content.finding_id,
                reason=EXCEPTION_REASON,
                approved_by=GOVERNANCE_ACTOR,
                created_at=parent.governance_at,
                expires_at=parent.governance_at + timedelta(hours=1),
            )
            parent.governance_exception = exception.exception_id
    parent.governance_steps = tuple(steps)
    parent.governance_after = database_state(parent.engine)
    assert_governance(parent, None)
    return "GOVERNANCE_CHANGED"


def assert_governance(parent, before_reader):
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.models import AuditEvent, FindingException
    from app.remediation.provenance import utc
    from app.services.remediation_service import RemediationService
    from tests.worker_http import database_state

    parent._owned()
    case = authority_case(parent.scenario.name)
    before, after = parent.governance_before, parent.governance_after
    if (
        before_reader is not None
        or not parent.governance_dispatched
        or parent.worker_dispatched
        or parent.worker_report is not None
        or parent.worker_history is not None
        or parent.acknowledged_execution is not None
        or parent.quarantined_execution is not None
        or type(before) is not dict
        or type(after) is not dict
        or database_state(parent.engine) != after
        or set(before) != set(after)
    ):
        raise ValueError("Invalid governance no-execution proof")
    allowed = {"findings", "finding_exceptions", "audit_events"}
    if any(before[name] != after[name] for name in before if name not in allowed):
        raise ValueError("Governance changed unrelated or immutable history")
    original = parent.governance_view
    target = original.content.finding_id
    prior_findings = {row._mapping["finding_id"]: dict(row._mapping) for row in before["findings"]}
    current_findings = {row._mapping["finding_id"]: dict(row._mapping) for row in after["findings"]}
    expected = {key: dict(value) for key, value in prior_findings.items()}
    expected[target]["status"] = case.finding
    if current_findings != expected:
        raise ValueError("Governance changed unbound finding state")
    old_audits = {row._mapping["event_id"] for row in before["audit_events"]}
    if any(row not in after["audit_events"] for row in before["audit_events"]):
        raise ValueError("Governance rewrote existing audit")
    with Session(parent.engine) as session:
        current = RemediationService(session).get_proposal(
            original.content.proposal_id, parent._principal()
        )
        if (
            current.content != original.content
            or current.proposal_sha256 != original.proposal_sha256
            or current.approval_status != original.approval_status
            or current.decisions != original.decisions
            or current.approval_status.value != ("APPROVED" if case.approved else "PROPOSED")
            or case.blocker not in {reason.value for reason in current.blocking_reasons}
            or "STALE_GOVERNANCE" not in {reason.value for reason in current.blocking_reasons}
        ):
            raise ValueError("Governance revived or changed original authority")
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.event_id.not_in(old_audits))
        ).all()
        if len(events) != len(case.dispositions) + int(case.active_exception):
            raise ValueError("Unexpected governance audit count")
        for event in events:
            if (
                event.actor_type != "user"
                or event.actor_id != GOVERNANCE_ACTOR
                or utc(event.timestamp) != parent.governance_at
            ):
                raise ValueError("Invalid external governance audit attribution")
        previous = "OPEN"
        kinds = {
            "ACKNOWLEDGED": "FINDING_ACKNOWLEDGED",
            "FALSE_POSITIVE": "FINDING_FALSE_POSITIVE",
            "OPEN": "FINDING_UPDATED",
        }
        for status in case.dispositions:
            matches = [
                event
                for event in events
                if event.target_type == "finding"
                and event.target_id == target
                and event.event_type.value == kinds[status]
                and event.event_metadata == {"previous_status": previous, "status": status}
            ]
            if len(matches) != 1:
                raise ValueError("Invalid committed governance step audit")
            previous = status
        if len(parent.governance_steps) != len(case.dispositions) or any(
            step.content != original.content
            or step.proposal_sha256 != original.proposal_sha256
            or step.decisions != original.decisions
            or step.approval_status != original.approval_status
            or "STALE_GOVERNANCE" not in {reason.value for reason in step.blocking_reasons}
            for step in parent.governance_steps
        ):
            raise ValueError("Intermediate governance step changed authority")
        if not case.active_exception:
            if after["finding_exceptions"] != before["finding_exceptions"]:
                raise ValueError("Unexpected governance exception")
        else:
            if len(after["finding_exceptions"]) != len(before["finding_exceptions"]) + 1 or any(
                row not in after["finding_exceptions"] for row in before["finding_exceptions"]
            ):
                raise ValueError("Unexpected governance exception history")
            exception = session.get(FindingException, parent.governance_exception)
            if (
                (exception.finding_id, exception.resource_id, exception.control_id)
                != (target, original.content.resource_id, original.content.control_id)
                or exception.status.value != "ACTIVE"
                or exception.revoked_at is not None
                or exception.reason != EXCEPTION_REASON
                or exception.approved_by != GOVERNANCE_ACTOR
                or utc(exception.created_at) != parent.governance_at
                or utc(exception.expires_at) != parent.governance_at + timedelta(hours=1)
            ):
                raise ValueError("Invalid active governance exception")
            event = events[0]
            if (
                event.event_type.value != "EXCEPTION_CREATED"
                or event.target_type != "exception"
                or event.target_id != exception.exception_id
                or event.event_metadata
                != {
                    "finding_id": str(target),
                    "resource_id": str(exception.resource_id),
                    "control_id": str(exception.control_id),
                    "status": "ACTIVE",
                    "expires_at": utc(exception.expires_at).isoformat(),
                    "reason": EXCEPTION_REASON,
                }
            ):
                raise ValueError("Invalid exception creation audit")
    if database_state(parent.engine) != after:
        raise ValueError("Governance read changed durable history")
