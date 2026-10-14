"""Signed observational authority remains separate from old write grants and quarantine."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.models import Finding
from app.models.enums import FindingStatus
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.verification_contracts import VerificationView
from app.remediation.worker_contracts import RegionalObservation
from app.services.remediation_worker_service import RemediationWorkerService
from tests.integration.test_remediation_worker_process_postgres import (
    offline_process_runtime as offline_process_runtime,
)
from tests.integration.test_remediation_worker_process_postgres import (
    process_database as process_database,
)
from tests.verification_acceptance import (
    assert_receipt_storage,
    full_verification_journey,
    regional_reader,
    unchanged_history,
    wait_for_receipt,
)
from tests.worker_http import SCOPE as WORKER_SCOPE
from tests.worker_http import database_state, signed_headers
from tests.worker_process_harness import ENABLE, ENCRYPTION, IDENTITY, KEY
from tests.worker_process_http import script_for

pytestmark = pytest.mark.integration


def request(journey, headers, body=None, *, execution_id=None):
    return journey.client.post(
        "/api/v1/remediation-executions/"
        + str(execution_id or journey.execution_id)
        + "/verifications",
        json=body or {"reason": "Observe only the retained acknowledged setting."},
        headers=headers,
    )


def finish(journey, response, *, outcome="VERIFIED"):
    assert response.status_code == 202, response.text
    pending = VerificationView.model_validate(response.json())
    assert journey.executor.entered.wait(15)
    journey.executor.release.set()
    complete = wait_for_receipt(journey, pending.content.verification_id)
    assert complete.receipt.outcome.value == outcome
    assert_receipt_storage(journey.engine, complete)
    return complete


def test_signed_actor_operation_and_cross_execution_key_namespaces(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=lambda: regional_reader(enabled=False),
    ) as journey:
        writer = journey.run(script_for("acknowledged", None))
        assert writer["exit_code"] == 0 and writer["enable_invocations"] == 1
        journal = journey.check(ExecutionPhase.ACKNOWLEDGED).events
        before = database_state(engine)
        key = journey.initial.content.idempotency_key
        # Same principal and UUID as EXECUTION_REQUEST is a different operation namespace.
        assert journey.initial.content.requested_by.subject == "requester"
        journey.executor.actor_subject = "requester"
        headers = signed_headers(journey.issuer, "requester", "ADMIN", key=key)
        created = request(journey, headers)
        assert created.status_code == 202, created.text
        pending = VerificationView.model_validate(created.json())
        assert (
            pending.content.requested_by.subject == "requester"
            and pending.content.idempotency_key == key
        )
        assert journey.executor.entered.wait(15)
        admitted = database_state(engine)
        conflict = request(journey, headers, execution_id=uuid4())
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "remediation_idempotency_conflict"
        lost_role = request(journey, signed_headers(journey.issuer, "requester", "VIEWER", key=key))
        assert lost_role.status_code == 403
        expired = request(
            journey,
            signed_headers(
                journey.issuer,
                "requester",
                "ADMIN",
                key=key,
                exp=datetime.now(UTC) - timedelta(seconds=1),
            ),
        )
        assert expired.status_code == 401
        normalized = request(
            journey, headers, {"reason": "  Observe only the retained acknowledged setting.  "}
        )
        assert normalized.status_code == 200 and normalized.json() == created.json()
        assert database_state(engine) == admitted
        first = finish(journey, created, outcome="NOT_VERIFIED")
        journey.executor.actor_subject = "another-verifier"
        another = signed_headers(journey.issuer, "another-verifier", "ADMIN", key=key)
        second = finish(journey, request(journey, another), outcome="NOT_VERIFIED")
        assert (
            second.content.attempt == 2
            and second.content.verification_id != first.content.verification_id
        )
        assert second.content.requested_by.subject == "another-verifier"
        assert second.content.idempotency_key == first.content.idempotency_key
        replay = request(journey, headers)
        assert replay.status_code == 200 and replay.json() == first.model_dump(mode="json")
        assert len(journey.executor.submissions) == 2 and journey.view().events == journal
        unchanged_history(before, database_state(engine))


@pytest.mark.parametrize("change", ["revoked", "expired"])
def test_signed_observation_does_not_renew_or_depend_on_old_write_eligibility(
    offline_process_runtime, process_database, monkeypatch, tmp_path, change
):
    engine, child_url = process_database
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=regional_reader(enabled=True),
    ) as journey:
        writer = journey.run(script_for("acknowledged", None))
        assert writer["exit_code"] == 0 and writer["enable_invocations"] == 1
        current = journey.check(ExecutionPhase.ACKNOWLEDGED)
        if change == "revoked":
            response = journey.client.post(
                "/api/v1/remediations/"
                + str(current.content.proposal.proposal_id)
                + "/revocations",
                json={
                    "proposal_sha256": current.content.proposal_sha256,
                    "approval_decision_id": str(current.content.approval.decision_id),
                    "reason": "End old write authority without forbidding observation.",
                },
                headers=signed_headers(journey.issuer, "approver", "APPROVER"),
            )
            assert response.status_code == 201, response.text
        before = database_state(engine)
        headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        if change == "expired":
            future = datetime.now(UTC) + timedelta(days=2)
            with (
                patch("app.services.remediation_service.datetime") as authority_clock,
                patch("app.services.inventory_service.datetime") as inventory_clock,
                patch("app.services.scan_executor.datetime") as executor_clock,
            ):
                authority_clock.now.return_value = future
                inventory_clock.now.return_value = future + timedelta(seconds=1)
                executor_clock.now.return_value = future + timedelta(seconds=2)
                complete = finish(journey, request(journey, headers))
                assert complete.content.created_at > current.content.expires_at
        else:
            complete = finish(journey, request(journey, headers))
        assert complete.content.execution_id == current.content.execution_id
        assert journey.view().events == current.events and len(journey.executor.submissions) == 1
        unchanged_history(before, database_state(engine))
        with Session(engine) as session:
            assert session.get(Finding, journey.source.finding_id).status is FindingStatus.RESOLVED


def test_signed_verification_denies_installed_worker_quarantine_even_after_true_readback(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=regional_reader(enabled=True),
    ) as journey:
        uncertain = journey.run(
            [
                [IDENTITY, "valid"],
                [ENCRYPTION, False],
                [KEY, None],
                [ENABLE, "timeout"],
                [IDENTITY, "denied"],
            ]
        )
        assert (
            uncertain["enable_invocations"] == 1
            and uncertain["stdout"] == "QUARANTINED_UNVERIFIED\n"
        )
        journey.check(ExecutionPhase.QUARANTINED, held=True)
        observed = journey.run([[IDENTITY, "valid"], [ENCRYPTION, True], [KEY, None]])
        assert observed["enable_invocations"] == 0
        current = journey.check(ExecutionPhase.QUARANTINED, held=True)
        assert current.events[-1].content.observation.encryption_by_default is True
        before = database_state(engine)
        denied = request(journey, signed_headers(journey.issuer, "verification-operator", "ADMIN"))
        assert denied.status_code == 409
        assert denied.json()["detail"]["code"] == "remediation_verification_ineligible"
        assert database_state(engine) == before and journey.executor.submissions == []


def test_signed_verification_denies_genuine_late_acknowledgment_callback(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=regional_reader(enabled=True),
    ) as journey:
        # Actual worker service callbacks with a real owned claim; no SDK write is represented here.
        def worker(method, *args):
            with Session(engine) as session:
                return getattr(RemediationWorkerService(session, scope=WORKER_SCOPE), method)(*args)

        claim = worker("claim", journey.execution_id)
        assert worker("begin_read", claim)
        assert worker(
            "write_intent",
            claim,
            RegionalObservation(
                encryption_by_default=False,
                default_kms_key_id=None,
                default_kms_key_expected_absence=True,
            ),
            datetime.now(UTC),
        )
        worker("quarantine", journey.execution_id)
        assert worker("acknowledge", claim, "offline-late-acknowledgment")
        current = journey.check(ExecutionPhase.QUARANTINED, held=True)
        assert current.events[-1].content.kind.value == "ACKNOWLEDGED"
        assert current.events[-1].content.phase is ExecutionPhase.QUARANTINED
        before = database_state(engine)
        denied = request(journey, signed_headers(journey.issuer, "verification-operator", "ADMIN"))
        assert denied.status_code == 409
        assert denied.json()["detail"]["code"] == "remediation_verification_ineligible"
        assert database_state(engine) == before and journey.executor.submissions == []
