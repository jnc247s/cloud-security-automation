"""Independent parent persistence proof shared by native and Linux browser orchestration."""

import time

from tests.dashboard_integrated_scenarios import reader_scenario


def assert_reader_sequence(managed, values, *, max_attempts):
    """Exact real submit/provider pairs and sealed predecessors; never submits or seals work."""
    if type(max_attempts) is not int or max_attempts not in {1, 3}:
        raise ValueError("Managed reader sequence limit")
    if not 1 <= len(values) <= max_attempts:
        raise ValueError("Managed reader sequence count")
    scans = [value.content.scan_id for value in values]
    identifiers = [value.content.verification_id for value in values]
    first = values[0].content
    if (
        len(set(scans)) != len(scans)
        or len(set(identifiers)) != len(identifiers)
        or managed.submissions != scans
        or managed.boundaries
        != [
            (kind, value.content.scan_id, value.content.verification_id)
            for value in values
            for kind in ("submit", "provider")
        ]
        or values[-1].receipt is not None
        or any(value.receipt is None for value in values[:-1])
        or any(
            value.content.attempt != index
            or value.content.execution_id != first.execution_id
            or value.content.baseline_scan_id != first.baseline_scan_id
            for index, value in enumerate(values, 1)
        )
    ):
        raise ValueError("Managed reader sequence binding")


def assert_integrated_receipt(parent, before_reader, *, scenario="verified"):
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from app.assessment.models import AssessmentResult
    from app.models import ControlAssessment, Finding
    from app.models.remediation import RemediationProposal, RemediationRequest
    from app.models.remediation_verification import RemediationVerification
    from tests.verification_acceptance import assert_receipt_storage, unchanged_history
    from tests.worker_http import database_state

    expected = reader_scenario(scenario)
    if expected.name.startswith("governance-"):
        from tests.dashboard_integrated_governance import assert_governance

        assert_governance(parent, before_reader)
        return
    if expected.name.startswith("stale-") or expected.name == "admission-stale":
        from tests.dashboard_integrated_staleness import assert_stale_observation

        assert_stale_observation(parent, before_reader)
        return
    if expected.worker == "none":
        _assert_no_execution(parent, before_reader, expected)
        return
    if expected.worker == "expired":
        from tests.dashboard_integrated_execution_expiry import assert_expired_execution

        assert_expired_execution(parent, before_reader, expected)
        return
    if expected.worker == "revoked":
        from tests.dashboard_integrated_revocation import assert_revoked_no_write

        assert_revoked_no_write(parent, before_reader)
        return
    if expected.attempts == 0:
        _assert_no_verification(parent, before_reader, expected)
        return
    if before_reader is None:
        raise ValueError("No installed worker acknowledgment to verify")
    if expected.name == "revoked-after-ack":
        from tests.dashboard_integrated_revocation import history_after_revocation

        before_reader = history_after_revocation(parent, before_reader)
    with Session(parent.engine) as session:
        if expected.response_loss or expected.name in {
            "capacity-session",
            "capacity-global",
            "in-flight",
            "reply-reference",
            "history-reference",
            "feature-hints",
            "history-versions",
        }:
            assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(RemediationRequest)
                    .where(RemediationRequest.operation == "CREATE")
                )
                == 1
            )
        requests = session.scalars(
            select(RemediationVerification).order_by(RemediationVerification.attempt)
        ).all()
        if len(requests) != expected.attempts:
            raise ValueError("Unexpected browser-created linked verification count")
        identifiers = [request.verification_id for request in requests]
    for ordinal, identifier in enumerate(identifiers, 1):
        view = _wait_for_receipt(parent, identifier)
        assert view.content.attempt == ordinal
        assert view.content.execution_id == parent.acknowledged_execution
        assert view.content.baseline_scan_id == parent.source.scan_id
        assert view.receipt.outcome.value == expected.outcome
        assert view.receipt.reason.value == expected.reason
        assert view.receipt.scan_status.value == expected.scan_status
        if expected.technical is None:
            assert view.receipt.evidence is None
        else:
            assert view.receipt.evidence.technical_result.value == expected.technical
        if expected.name == "verification-equal":
            assert view.content.created_at == view.content.acknowledged_at
            assert view.receipt.evidence.observed_at == view.content.acknowledged_at
            assert (
                view.receipt.evidence.observed_at
                > parent.worker_history.content.proposal.baseline.observed_at
            )
        assert_receipt_storage(parent.engine, view)
        with Session(parent.engine) as session:
            observed = session.execute(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == view.content.scan_id,
                    ControlAssessment.control_id == parent.source.control_id,
                    ControlAssessment.resource_id == parent.source.resource_id,
                )
            ).scalar_one()
            assert observed.assessment_result.value == expected.assessment
    unchanged_history(before_reader, database_state(parent.engine))
    with Session(parent.engine) as session:
        assert (
            session.get(ControlAssessment, parent.source.assessment_id).assessment_result
            is AssessmentResult.FAIL
        )
        assert session.get(Finding, parent.source.finding_id).status.value == expected.finding
    assert parent.worker_report["enable_invocations"] == 1
    assert parent.worker_report["intent_checks"] == 1


def _wait_for_receipt(parent, identifier):
    from sqlalchemy.orm import Session

    from app.security.authentication import Principal
    from app.services.remediation_verification_service import RemediationVerificationService

    deadline = time.monotonic() + 15
    while True:
        with Session(parent.engine) as session:
            view = RemediationVerificationService(session).get_verification(
                identifier, Principal("parent-receipt-reader", frozenset({"VIEWER"}), parent.issuer)
            )
        if view.receipt is not None:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Managed receipt proof deadline")
        time.sleep(0.05)
    return view


def _assert_no_execution(parent, before_reader, expected):
    """Exactly one original proposal/audit/CREATE ledger; every other persisted value unchanged."""
    from datetime import timedelta

    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.database.integrity import canonical_json_sha256
    from app.models import AuditEvent
    from app.models.enums import AuditEventType
    from app.models.remediation import RemediationProposal, RemediationRequest
    from app.remediation.contracts import ProposalContent, ProposalRequest
    from app.remediation.provenance import utc
    from app.services.remediation_service import RemediationService
    from tests.worker_http import database_state

    def reject():
        raise ValueError("Invalid integrated no-execution proof")

    parent._owned()
    if (
        expected.name
        not in {
            "proposal-expiry",
            "idle-expiry",
            "token-expiry",
            "subject-replacement",
            "issuer-rejection",
        }
        or parent.scenario != expected
        or before_reader is not None
        or parent.worker_dispatched is not False
        or parent.worker_report is not None
        or parent.worker_history is not None
        or parent.acknowledged_execution is not None
        or parent.quarantined_execution is not None
        or type(parent.proposal_only_before) is not dict
    ):
        reject()
    before, after = parent.proposal_only_before, database_state(parent.engine)
    changed = {"remediation_proposals", "remediation_requests", "audit_events"}
    if (
        set(before) != set(after)
        or any(before[name] != after[name] for name in before if name not in changed)
        or len(after["remediation_proposals"]) != 1
        or len(after["remediation_requests"]) != 1
        or len(after["audit_events"]) != len(before["audit_events"]) + 1
        or any(row not in after["audit_events"] for row in before["audit_events"])
    ):
        reject()
    with Session(parent.engine) as session:
        row = session.scalars(select(RemediationProposal)).one()
        content = ProposalContent.model_validate(row.content)
        service = (
            RemediationService(
                session, clock=lambda: content.created_at + timedelta(days=1, seconds=1)
            )
            if expected.name == "proposal-expiry"
            else RemediationService(session)
        )
        view = service.get_proposal(row.proposal_id, parent._principal())
        parent._bind_proposal(view.content)
        ledger = session.scalars(select(RemediationRequest)).one()
        audit = session.execute(
            select(AuditEvent).where(
                AuditEvent.target_type == "remediation",
                AuditEvent.target_id == row.proposal_id,
                AuditEvent.event_type == AuditEventType.REMEDIATION_PROPOSED,
            )
        ).scalar_one()
        request = ProposalRequest(
            finding_id=content.finding_id,
            occurrence_id=content.baseline.occurrence_id,
            action_id=content.action_id,
            action_version=content.action_version,
            reason=content.reason,
        )
        if (
            view.approval_status.value != "PROPOSED"
            or tuple(reason.value for reason in view.blocking_reasons)
            != (("EXPIRED",) if expected.name == "proposal-expiry" else ())
            or view.decisions != ()
            or view.proposal_sha256 != canonical_json_sha256(row.content)
            or (content.proposer.issuer, content.proposer.subject, content.proposer.roles)
            != (parent.issuer, "proposer", ("ANALYST",))
            or content.proposer.capability.value != "PROPOSE"
            or ledger.operation != "CREATE"
            or ledger.proposal_id != row.proposal_id
            or ledger.decision_id is not None
            or (ledger.actor_issuer, ledger.actor_subject) != (parent.issuer, "proposer")
            or ledger.actor_identity_sha256 != canonical_json_sha256([parent.issuer, "proposer"])
            or ledger.request_sha256 != canonical_json_sha256(request.model_dump(mode="json"))
            or audit.actor_type != "human"
            or audit.actor_id != canonical_json_sha256([parent.issuer, "proposer"])
            or utc(audit.timestamp) != content.created_at
            or audit.event_metadata
            != {
                "schema_version": "1.0.0",
                "actor": content.proposer.model_dump(mode="json"),
                "proposal_id": str(row.proposal_id),
                "proposal_sha256": view.proposal_sha256,
                "decision_id": None,
            }
        ):
            reject()
    if database_state(parent.engine) != after:
        reject()


def _assert_no_verification(parent, before_reader, expected):
    from types import SimpleNamespace

    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from app.models import ControlAssessment, Finding, Scan
    from app.models.remediation_verification import (
        RemediationVerification,
        RemediationVerificationReceipt,
    )
    from tests.worker_http import assert_history, database_state
    from tests.worker_process_harness import ENABLE

    if before_reader is None or parent.quarantined_execution is None:
        raise ValueError("No installed quarantine to prove")
    current = parent._execution(parent.quarantined_execution)
    assert current.phase.value == "QUARANTINED" and current.reservation_held
    assert parent.acknowledged_execution is None and parent.worker_dispatched
    assert current.content == parent.worker_history.content
    assert current.events == parent.worker_history.events
    assert_history(
        parent.engine, parent.worker_history, current, SimpleNamespace(issuer=parent.issuer)
    )
    assert [entry.content.kind.value for entry in current.events] == [
        "REQUESTED",
        "CLAIMED",
        "WRITE_INTENT",
        "QUARANTINED",
    ] + (["ACKNOWLEDGED", "OBSERVED"] if expected.worker == "late-ack" else ["OBSERVATION_FAILED"])
    if expected.worker == "late-ack":
        assert current.events[4].content.phase.value == "QUARANTINED"
        assert current.events[4].content.request_id == "offline-process-write"
        assert current.events[-1].content.observation.encryption_by_default is True
    with Session(parent.engine) as session:
        for model in (RemediationVerification, RemediationVerificationReceipt):
            assert session.scalar(select(func.count()).select_from(model)) == 0
        assert session.scalar(select(func.count()).select_from(Scan)) == 1
        assert (
            session.get(ControlAssessment, parent.source.assessment_id).assessment_result.value
            == "FAIL"
        )
        assert session.get(Finding, parent.source.finding_id).status.value == "OPEN"
    assert database_state(parent.engine) == before_reader
    assert parent.worker_report["stdout"] == "QUARANTINED_UNVERIFIED\n"
    assert parent.worker_report["enable_invocations"] == parent.worker_report["intent_checks"] == 1
    assert parent.worker_report["wire_actions"].count(ENABLE) == 1
