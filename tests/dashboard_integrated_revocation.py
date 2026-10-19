"""Read-only parent proofs for genuine signed revocation, never cancellation or new authority."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RevocationCase:
    before_intent: bool
    phase: str


def revocation_case(name):
    choices = {
        "revoked-before-intent": RevocationCase(True, "NO_WRITE"),
        "revoked-after-ack": RevocationCase(False, "ACKNOWLEDGED"),
    }
    if type(name) is not str or name not in choices:
        raise ValueError("Invalid integrated revocation case")
    return choices[name]


def read_revocation(parent, execution, *, required):
    if os.environ.get("DASHBOARD_BROWSER_TEST") != "1" or type(required) is not bool:
        raise ValueError("Integrated revocation read unavailable")
    revocation_case(parent.scenario.name)
    parent._owned()  # Ownership precedes imports, SQL and any use of retained authority.
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.integrity import canonical_json_sha256
    from app.models.remediation import RemediationRequest
    from app.remediation.contracts import DecisionRequest, ProposalRequest, RevocationRequest
    from app.services.remediation_service import RemediationService
    from tests.worker_http import database_state

    before = database_state(parent.engine)
    with Session(parent.engine) as session:
        value = RemediationService(session).get_proposal(
            execution.content.proposal.proposal_id, parent._principal()
        )
        parent._bind_proposal(value.content)
        if (
            value.content != execution.content.proposal
            or value.proposal_sha256 != execution.content.proposal_sha256
            or len(value.decisions) != (2 if required else 1)
            or value.decisions[0] != execution.content.approval
            or value.approval_status.value != ("REVOKED" if required else "APPROVED")
        ):
            raise ValueError("Invalid retained revocation binding")
        requests = session.scalars(select(RemediationRequest)).all()
        if len(requests) != (3 if required else 2) or {row.operation for row in requests} != (
            {"CREATE", "DECIDE", "REVOKE"} if required else {"CREATE", "DECIDE"}
        ):
            raise ValueError("Invalid retained revocation request set")
        # Existing immutable authority is bound independently, not inferred from REVOKE alone.
        original_requests = (
            (
                "CREATE",
                value.content.proposer,
                ProposalRequest(
                    finding_id=value.content.finding_id,
                    occurrence_id=value.content.baseline.occurrence_id,
                    action_id=value.content.action_id,
                    action_version=value.content.action_version,
                    reason=value.content.reason,
                ),
                None,
            ),
            (
                "DECIDE",
                value.decisions[0].actor,
                DecisionRequest(
                    proposal_sha256=value.proposal_sha256,
                    decision="APPROVE",
                    reason=value.decisions[0].reason,
                ),
                value.decisions[0].decision_id,
            ),
        )
        for operation, actor, request, decision_id in original_requests:
            original = next(row for row in requests if row.operation == operation)
            body = request.model_dump(mode="json")
            if operation == "DECIDE":
                body = {"proposal_id": str(value.content.proposal_id), **body}
            if (
                original.proposal_id != value.content.proposal_id
                or original.decision_id != decision_id
                or original.idempotency_key.version != 4
                or (original.actor_issuer, original.actor_subject) != (actor.issuer, actor.subject)
                or original.actor_identity_sha256
                != canonical_json_sha256([actor.issuer, actor.subject])
                or original.request_sha256 != canonical_json_sha256(body)
            ):
                raise ValueError("Invalid retained original authority ledger")
        if not required:
            return None
        revoked = value.decisions[1]
        ledger = next(row for row in requests if row.operation == "REVOKE")
        body = RevocationRequest(
            proposal_sha256=value.proposal_sha256,
            approval_decision_id=execution.content.approval.decision_id,
            reason=revoked.reason,
        )
        actor = revoked.actor
        identity = canonical_json_sha256([parent.issuer, "approver"])
        if (
            revoked.kind.value != "REVOKE"
            or revoked.proposal_id != value.content.proposal_id
            or revoked.proposal_sha256 != value.proposal_sha256
            or revoked.approval_decision_id != execution.content.approval.decision_id
            or revoked.created_at < execution.content.created_at
            or (actor.issuer, actor.subject, actor.roles, actor.capability.value)
            != (parent.issuer, "approver", ("APPROVER",), "APPROVE")
            or ledger.proposal_id != value.content.proposal_id
            or ledger.decision_id != revoked.decision_id
            or ledger.idempotency_key.version != 4
            or (ledger.actor_issuer, ledger.actor_subject) != (parent.issuer, "approver")
            or ledger.actor_identity_sha256 != identity
            or ledger.request_sha256
            != canonical_json_sha256(
                {"proposal_id": str(value.content.proposal_id), **body.model_dump(mode="json")}
            )
        ):
            raise ValueError("Invalid retained revocation actor or request digest")
    if database_state(parent.engine) != before:
        raise ValueError("Revocation proof changed durable state")
    return revoked


def assert_revoked_no_write(parent, before_reader):
    """Exact pre-intent NO_WRITE delta, with no claim/credential/SDK/linked-scan effect."""
    from tests.worker_http import database_state

    parent._owned()
    if parent.scenario.name != "revoked-before-intent":
        raise ValueError("Invalid revoked no-write scenario")
    original, before, after = (
        parent.revocation_before,
        parent.before_worker,
        database_state(parent.engine),
    )

    def require(value):
        if not value:
            raise ValueError("Invalid integrated revoked no-write proof")

    require(type(original) is dict and type(before) is dict and type(before_reader) is dict)
    require(set(original) == set(before) == set(after) and before_reader == after)
    require(parent.worker_dispatched and parent.revoked_execution is not None)
    require(parent.acknowledged_execution is None and parent.quarantined_execution is None)
    require(parent.expired_execution is None and parent.revocation_ack_before is None)
    authority = {
        "remediation_proposals",
        "remediation_decisions",
        "remediation_requests",
        "remediation_executions",
        "remediation_execution_events",
        "remediation_admission_guard",
        "remediation_target_reservations",
        "audit_events",
    }
    require(all(original[name] == before[name] for name in original if name not in authority))
    require(
        all(
            not original[name]
            for name in authority
            - {"audit_events", "remediation_admission_guard", "remediation_target_reservations"}
        )
    )
    require(len(before["remediation_proposals"]) == len(before["remediation_executions"]) == 1)
    require(len(before["remediation_decisions"]) == 2 and len(before["remediation_requests"]) == 3)
    require(len(before["remediation_execution_events"]) == 1)
    require(len(before["audit_events"]) == len(original["audit_events"]) + 4)
    require(all(row in before["audit_events"] for row in original["audit_events"]))
    changed = {"remediation_execution_events", "remediation_target_reservations", "audit_events"}
    require(all(before[name] == after[name] for name in before if name not in changed))
    require(len(after["remediation_execution_events"]) == 2)
    require(
        all(
            row in after["remediation_execution_events"]
            for row in before["remediation_execution_events"]
        )
    )
    require(len(after["audit_events"]) == len(before["audit_events"]) + 1)
    require(all(row in after["audit_events"] for row in before["audit_events"]))
    old, new = before["remediation_target_reservations"], after["remediation_target_reservations"]
    require(len(old) == len(new) == 1)
    require(old[0].execution_id == parent.revoked_execution and new[0].execution_id is None)
    require(
        {k: v for k, v in old[0]._mapping.items() if k != "execution_id"}
        == {k: v for k, v in new[0]._mapping.items() if k != "execution_id"}
    )
    require(after["remediation_worker_claims"] == ())
    current, initial = parent._execution(parent.revoked_execution), parent.initial_execution
    parent._bind(current)
    revoked = read_revocation(parent, current, required=True)
    parent._history(initial, current)  # Existing exact full-human/service/audit/hash proof.
    require(initial.phase.value == "QUEUED" and initial.reservation_held)
    require([r.value for r in initial.blocking_reasons] == ["APPROVAL_REVOKED"])
    require(current.phase.value == "NO_WRITE" and current.reservation_held is False)
    require(
        current.content == initial.content and current.execution_sha256 == initial.execution_sha256
    )
    require(current.events == parent.worker_history.events)
    require([e.content.kind.value for e in current.events] == ["REQUESTED", "NO_WRITE"])
    require([e.content.schema_version for e in current.events] == ["1.0.0", "2.0.0"])
    require([r.value for r in current.events[-1].content.blocking_reasons] == ["APPROVAL_REVOKED"])
    require(
        initial.content.created_at <= revoked.created_at <= current.events[-1].content.created_at
    )
    report = parent.worker_report
    require(report["exit_code"] == 0 and report["stdout"] == "NO_WRITE\n")
    require(report["calls"] == report["wire_actions"] == report["lock_probes"] == [])
    require(report["enable_invocations"] == report["intent_checks"] == 0)
    require(database_state(parent.engine) == after)


def _append_proven_rows(before, after, predicate, *, exact):
    additions = tuple(row for row in after if predicate(row))
    if len(additions) != 1 or additions[0] in before or any(row not in after for row in before):
        raise ValueError("Invalid append-only signed revocation delta")
    expected = before + additions
    if exact and (len(expected) != len(after) or any(row not in expected for row in after)):
        raise ValueError("Invalid append-only signed revocation delta")
    # database_state orders by primary key, not append time; JSON-bearing rows are unhashable.
    return tuple(row for row in after if row in expected)


def history_after_revocation(parent, before_reader):
    """Account for only the proven signed append before applying unchanged scan-history proof.

    This is a private comparison snapshot, never a persisted rewrite or a modified verifier.
    """
    from app.models.enums import AuditEventType
    from tests.worker_http import database_state

    parent._owned()
    if (
        parent.scenario.name != "revoked-after-ack"
        or type(before_reader) is not dict
        or before_reader != parent.revocation_ack_before
        or not parent.worker_dispatched
        or parent.acknowledged_execution is None
    ):
        raise ValueError("Invalid integrated revoked acknowledgment proof")
    after = database_state(parent.engine)
    current = parent._execution(parent.acknowledged_execution)
    parent._bind(current)
    revoked = read_revocation(parent, current, required=True)
    parent._history(parent.worker_history, current)
    if (
        current.phase.value != "ACKNOWLEDGED"
        or current.reservation_held
        or current.content != parent.worker_history.content
        or current.events != parent.worker_history.events
        or revoked.created_at < current.events[-1].content.created_at
        or "APPROVAL_REVOKED" not in {r.value for r in current.blocking_reasons}
        or parent.worker_report["enable_invocations"] != 1
        or parent.worker_report["intent_checks"] != 1
        or len(before_reader["remediation_decisions"]) != 1
        or len(before_reader["remediation_requests"]) != 2
    ):
        raise ValueError("Revocation changed acknowledged effect or original authority")
    expected = dict(before_reader)
    for table, predicate in (
        ("remediation_decisions", lambda row: row.decision_id == revoked.decision_id),
        (
            "remediation_requests",
            lambda row: row.operation == "REVOKE" and row.decision_id == revoked.decision_id,
        ),
        (
            "audit_events",
            lambda row: (
                row.event_type == AuditEventType.REMEDIATION_REVOKED
                and row.target_id == revoked.proposal_id
            ),
        ),
    ):
        expected[table] = _append_proven_rows(
            before_reader[table], after[table], predicate, exact=table != "audit_events"
        )
    if database_state(parent.engine) != after:
        raise ValueError("Revocation history proof changed durable state")
    return expected
