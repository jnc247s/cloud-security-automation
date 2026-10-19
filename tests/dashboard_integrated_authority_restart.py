"""Fixed owned-child authority restart; no arbitrary command, target, URL or credentials."""

import os
from uuid import UUID

from tests.dashboard_integrated_bootstrap import require_test_environment
from tests.dashboard_integrated_protocol import ControlKind, ControlMessage


class RestartableAuthorityServer:
    def __init__(self, env):
        from tests.dashboard_integrated_guardian import OwnedServer

        self.instance = env.get("DASHBOARD_INTEGRATED_INSTANCE")
        require_test_environment(self.instance)
        if (
            env.get("DASHBOARD_BROWSER_TEST") != "1"
            or env.get("DASHBOARD_INTEGRATED_SCENARIO") != "cross-issuer"
            or env.get("DASHBOARD_INTEGRATED_IDENTITY_PHASE", "initial") != "initial"
        ):
            raise ValueError("Integrated authority restart rejected")
        self._env = dict(env)
        self.attempted, self.completed = False, False
        self.current = OwnedServer(self._env)

    def wait(self, expected, timeout):
        return self.current.wait(expected, timeout)

    def send(self, raw):
        return self.current.send(raw)

    def close(self, instance):
        if instance != self.instance:
            raise ValueError("Integrated authority restart rejected")
        return self.current.close(instance)

    def restart(self, message):
        from tests.dashboard_integrated_guardian import OwnedServer

        if (
            type(message) is not ControlMessage
            or message.kind is not ControlKind.RESTART_AUTHORITY
            or message.instance_id != UUID(self.instance)
            or message.target_id is None
            or self.attempted
        ):
            raise ValueError("Integrated authority restart rejected")
        self.attempted = True  # Sticky even if shutdown, startup or its reply is uncertain.
        old = self.current
        old.close(self.instance)  # Exact retained child only; never discover/adopt a listener.
        if old.child.poll() != 0:
            raise ValueError("Integrated authority restart rejected")
        replacement = {**self._env, "DASHBOARD_INTEGRATED_IDENTITY_PHASE": "secondary"}
        self.current = OwnedServer(replacement)
        if self.current is old or self.current.child is old.child:
            raise ValueError("Integrated authority restart rejected")
        self.current.wait(b"INTEGRATED_SERVER_READY", 30)
        self.completed = True


def restart_bound_authority(parent, message):
    """No SQL session or store lock spans child shutdown/startup. Parsing grants nothing."""
    if (
        os.environ.get("DASHBOARD_BROWSER_TEST") != "1"
        or type(message) is not ControlMessage
        or message.kind is not ControlKind.RESTART_AUTHORITY
        or message.instance_id != UUID(parent.instance)
        or message.target_id is None
        or parent.scenario.name != "cross-issuer"
        or not callable(parent.restart_authority)
        or parent.restart_dispatched
        or parent.worker_dispatched
        or parent.identity_restarted
        or parent.acknowledged_execution is not None
    ):
        raise ValueError("Integrated authority restart unavailable")
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.integrity import canonical_json_sha256
    from app.models import AuditEvent
    from app.models.enums import AuditEventType
    from app.models.remediation import RemediationRequest
    from app.remediation.contracts import ProposalRequest
    from app.remediation.provenance import utc
    from app.services.remediation_service import RemediationService
    from tests.worker_http import database_state

    parent.last_stage = "RESTART_OWNERSHIP"
    parent._owned()
    before = database_state(parent.engine)
    original = parent.authority_before
    allowed = {"remediation_proposals", "remediation_requests", "audit_events"}
    if (
        type(original) is not dict
        or set(original) != set(before)
        or any(original[name] != before[name] for name in before if name not in allowed)
        or len(before["remediation_proposals"]) != 1
        or len(before["remediation_requests"]) != 1
        or len(before["audit_events"]) != len(original["audit_events"]) + 1
        or any(row not in before["audit_events"] for row in original["audit_events"])
    ):
        raise ValueError("Integrated authority restart binding rejected")
    parent.last_stage = "RESTART_PROPOSAL"
    with Session(parent.engine) as session:
        view = RemediationService(session).get_proposal(message.target_id, parent._principal())
        parent._bind_proposal(view.content)
        actor = view.content.proposer
        request = session.execute(
            select(RemediationRequest).where(
                RemediationRequest.operation == "CREATE",
                RemediationRequest.idempotency_key == message.request_id,
                RemediationRequest.proposal_id == message.target_id,
            )
        ).scalar_one()
        audit = session.execute(
            select(AuditEvent).where(
                AuditEvent.target_id == message.target_id,
                AuditEvent.event_type == AuditEventType.REMEDIATION_PROPOSED,
            )
        ).scalar_one()
        proposed = ProposalRequest(
            finding_id=view.content.finding_id,
            occurrence_id=view.content.baseline.occurrence_id,
            action_id=view.content.action_id,
            action_version=view.content.action_version,
            reason=view.content.reason,
        )
        if (
            view.approval_status.value != "PROPOSED"
            or view.decisions
            or view.blocking_reasons
            or (actor.issuer, actor.subject, actor.roles, actor.capability.value)
            != (parent.issuer, "proposer", ("ANALYST",), "PROPOSE")
            or (request.actor_issuer, request.actor_subject) != (parent.issuer, "proposer")
            or request.actor_identity_sha256 != canonical_json_sha256([parent.issuer, "proposer"])
            or request.decision_id is not None
            or request.request_sha256 != canonical_json_sha256(proposed.model_dump(mode="json"))
            or audit.actor_type != "human"
            or audit.actor_id != canonical_json_sha256([parent.issuer, "proposer"])
            or audit.target_type != "remediation"
            or utc(audit.timestamp) != view.content.created_at
            or canonical_json_sha256(view.content.model_dump(mode="json")) != view.proposal_sha256
            or audit.event_metadata
            != {
                "schema_version": "1.0.0",
                "actor": actor.model_dump(mode="json"),
                "proposal_id": str(message.target_id),
                "proposal_sha256": view.proposal_sha256,
                "decision_id": None,
            }
        ):
            raise ValueError("Integrated authority restart binding rejected")
    parent.last_stage = "RESTART_DISPATCH"
    parent.restart_dispatched = True
    parent.restart_authority(message)
    parent.last_stage = "RESTART_PERSISTENCE"
    if database_state(parent.engine) != before:
        raise ValueError("Integrated authority restart changed durable history")
    parent.identity_restarted = True
    parent.restarted_proposal = message.target_id
    return "AUTHORITY_RESTARTED"
