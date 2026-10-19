"""Owned parent/signed API/installed child/managed-reader proof, not native browser acceptance."""

import json
from dataclasses import replace
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.assessment.models import AssessmentResult
from app.models import ControlAssessment, Finding
from app.models.enums import FindingStatus
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.verification_contracts import VerificationView
from tests.dashboard_integrated_coordinator import CoordinatorError, IntegratedCoordinator
from tests.dashboard_integrated_protocol import ControlProtocolError
from tests.integration.test_remediation_worker_process_postgres import (
    offline_process_runtime as offline_process_runtime,
)
from tests.integration.test_remediation_worker_process_postgres import (
    process_database as process_database,
)
from tests.verification_acceptance import (
    full_verification_journey,
    regional_reader,
    wait_for_receipt,
)
from tests.worker_http import database_state, signed_headers

pytestmark = pytest.mark.integration


def wire(coordinator, kind, target, key):
    document = {
        "schema_version": "1.0.0",
        "instance_id": coordinator.instance,
        "request_id": str(key),
        "command": kind,
    }
    if kind != "STOP":
        document[
            {
                "RUN_WORKER": "execution_id",
                "RELEASE_READER": "verification_id",
                "RESTART_AUTHORITY": "proposal_id",
                "COLLECT_STALE": "proposal_id",
                "CHANGE_GOVERNANCE": "proposal_id",
            }[kind]
        ] = str(target)
    return json.dumps(document).encode()


@pytest.fixture
def parent_journey(offline_process_runtime, process_database, monkeypatch, tmp_path):
    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=regional_reader(enabled=True),
    ) as journey:
        released = []

        def release(scan_id):
            assert journey.executor.entered.wait(5)
            assert journey.executor.submissions == [scan_id]
            released.append(scan_id)
            journey.executor.release.set()

        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            journey.source,
            instance=str(uuid4()),
            issuer=journey.issuer.issuer,
            release_reader=release,
        )
        yield parent, journey, released


def worker_command(parent, journey):
    return wire(parent, "RUN_WORKER", journey.execution_id, journey.initial.content.idempotency_key)


def request_verification(journey):
    key = uuid4()
    response = journey.client.post(
        journey.detail + "/verifications",
        headers=signed_headers(journey.issuer, "verification-operator", "ADMIN", key=key),
        json={"reason": "Observe owned installed acknowledgment through real managed submission."},
    )
    assert response.status_code == 202, response.text
    value = VerificationView.model_validate(response.json())
    assert value.receipt is None
    assert journey.executor.entered.wait(5)
    return value, key


@pytest.mark.parametrize("scenario", ["verification-equal", "verification-provenance"])
def test_closed_verification_fault_preserves_signed_authority_and_real_receipt(
    parent_journey, scenario
):
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.dashboard_integrated_scenarios import reader_scenario
    from tests.dashboard_integrated_verification_faults import VerificationFault

    parent, journey, released = parent_journey
    parent.scenario = reader_scenario(scenario)
    assert parent.handle(worker_command(parent, journey)).state == "WORKER_ACKNOWLEDGED"
    before = database_state(parent.engine)
    fault = VerificationFault(
        parent.engine, journey.source, issuer=journey.issuer.issuer, scenario=scenario
    )
    # This signed-HTTP fixture retains the actual initial API response. Native coverage captures
    # that same response in the fixed BFF transport, never by reconstructing a QUEUED view.
    fault.initial = journey.initial
    with fault.installed():
        fault._prove_ack(journey.execution_id)
        verification, key = request_verification(journey)
        fault.pending = verification
        fault.release(verification)
        reply = parent.handle(
            wire(parent, "RELEASE_READER", verification.content.verification_id, key)
        )
        assert reply.state == "READER_RELEASED"
        completed = wait_for_receipt(journey, verification.content.verification_id)
        journey.executor.shutdown(wait=True)
    fault.assert_complete()
    assert released == [completed.content.scan_id]
    assert_integrated_receipt(parent, before, scenario=scenario)


@pytest.mark.parametrize("drop_attached_output", [False, True])
def test_parent_binds_signed_grant_installed_write_and_managed_receipt(
    parent_journey, monkeypatch, drop_attached_output
):
    import subprocess

    parent, journey, released = parent_journey
    real_run, calls = parent.runtime.run_worker, []
    real_docker, captures = parent.runtime._docker, []

    def captured(*args, **kwargs):
        result = real_docker(*args, **kwargs)
        if drop_attached_output and args[:2] == ("start", "--attach"):
            captures.append(True)
            # Lose only the already completed real child's attached transport. Its immutable
            # container log, terminal status, genuine SDK/intent and storage proof remain real.
            return subprocess.CompletedProcess(result.args, result.returncode, "", result.stderr)
        return result

    monkeypatch.setattr(parent.runtime, "_docker", captured)

    def recorded(scenario, url):
        calls.append(scenario["target"]["execution_id"])
        return real_run(scenario, url)

    monkeypatch.setattr(parent.runtime, "run_worker", recorded)
    command = worker_command(parent, journey)
    reply = parent.handle(command)
    assert reply.state == "WORKER_ACKNOWLEDGED" and reply.effects_canceled is False
    assert parent.handle(command) == reply and calls == [str(journey.execution_id)]
    assert parent.worker_report["enable_invocations"] == 1
    assert parent.worker_report["intent_checks"] == 1
    assert len(captures) == int(drop_attached_output)
    if drop_attached_output:
        assert parent.runtime.last_report_capture == "RETAINED_ONLY"
    before = journey.view()
    assert before.phase is ExecutionPhase.ACKNOWLEDGED and before.reservation_held is False
    verification, key = request_verification(journey)
    release = wire(parent, "RELEASE_READER", verification.content.verification_id, key)
    assert parent.handle(release).state == "READER_RELEASED"
    assert parent.handle(release).state == "READER_RELEASED"
    assert released == [verification.content.scan_id]
    completed = wait_for_receipt(journey, verification.content.verification_id)
    assert completed.receipt.outcome.value == "VERIFIED"
    assert completed.receipt.evidence.technical_result.value == "PASS"
    assert journey.view().content == before.content and journey.view().events == before.events
    assert len(journey.executor.submissions) == 1 and len(calls) == 1
    with Session(parent.engine) as session:
        assert session.get(ControlAssessment, parent.source.assessment_id).assessment_result is (
            AssessmentResult.FAIL
        )
        assert session.get(Finding, parent.source.finding_id).status is FindingStatus.RESOLVED
    stopped = parent.handle(wire(parent, "STOP", None, uuid4()))
    assert stopped.state == "CLOSED" and stopped.effects_canceled is False
    assert parent.handle(command).state == "CLOSED" and len(calls) == 1


@pytest.mark.parametrize(
    "field",
    [
        "finding_id",
        "occurrence_id",
        "scan_id",
        "assessment_id",
        "snapshot_id",
        "resource_id",
        "control_id",
        "control_version_id",
        "operation-key",
        "execution",
        "issuer",
    ],
)
def test_wrong_fixture_or_operation_binding_denies_before_child(parent_journey, monkeypatch, field):
    parent, journey, _ = parent_journey
    attempted = []

    def forbidden(*_args, **_kwargs):
        attempted.append(True)
        raise AssertionError("Unplanned test child")

    monkeypatch.setattr(parent.runtime, "run_worker", forbidden)
    target, key = journey.execution_id, journey.initial.content.idempotency_key
    if field == "operation-key":
        key = uuid4()
    elif field == "execution":
        target = uuid4()
    elif field == "issuer":
        parent.issuer = "http://127.0.0.1:9999/foreign-test-issuer"
    else:
        parent.source = replace(parent.source, **{field: uuid4()})
    before = database_state(parent.engine)
    with pytest.raises(CoordinatorError):
        parent.handle(wire(parent, "RUN_WORKER", target, key))
    assert attempted == [] and parent.worker_report is None
    assert database_state(parent.engine) == before


@pytest.mark.parametrize("case", ["host", "port", "database", "password", "schema", "options"])
def test_parent_refuses_unowned_runtime_url_before_effect(parent_journey, case):
    parent, journey, _ = parent_journey
    url = parent.child_url
    wrong = {
        "host": lambda: url.set(host="localhost"),
        "port": lambda: url.set(port=5433),
        "database": lambda: url.set(database="cloudsec"),
        "password": lambda: url.set(password="synthetic-not-owner"),
        "schema": lambda: url.update_query_dict({"options": "-csearch_path=public"}),
        "options": lambda: url.update_query_dict({"unplanned": "value"}),
    }[case]()
    before = database_state(parent.engine)
    with pytest.raises(CoordinatorError, match="^Integrated test source rejected$"):
        IntegratedCoordinator(
            parent.runtime,
            parent.engine,
            wrong,
            journey.source,
            instance=str(uuid4()),
            issuer=journey.issuer.issuer,
            release_reader=lambda _scan: pytest.fail("Unplanned reader release"),
        )
    assert database_state(parent.engine) == before


def test_lost_installed_reply_is_sticky_and_never_resends(parent_journey, monkeypatch):
    parent, journey, _ = parent_journey
    real_run, calls = parent.runtime.run_worker, []

    def lost(scenario, url):
        calls.append(True)
        real_run(scenario, url)
        raise RuntimeError("synthetic-sensitive-post-dispatch")

    monkeypatch.setattr(parent.runtime, "run_worker", lost)
    command = worker_command(parent, journey)
    with pytest.raises(CoordinatorError) as error:
        parent.handle(command)
    assert "synthetic-sensitive" not in str(error.value)
    assert parent.handle(command).state == "UNCONFIRMED"
    assert calls == [True]
    assert parent.worker_dispatched is True
    with pytest.raises(CoordinatorError):
        parent.handle(wire(parent, "RUN_WORKER", uuid4(), uuid4()))
    assert calls == [True]
    assert journey.view().phase is ExecutionPhase.ACKNOWLEDGED
    with pytest.raises(ControlProtocolError):
        parent.handle(wire(parent, "RUN_WORKER", journey.execution_id, uuid4()))
    assert calls == [True]


@pytest.mark.parametrize("case", ["key", "verification"])
def test_reader_release_requires_exact_accepted_link(parent_journey, case):
    parent, journey, released = parent_journey
    assert parent.handle(worker_command(parent, journey)).state == "WORKER_ACKNOWLEDGED"
    value, key = request_verification(journey)
    target = value.content.verification_id
    if case == "key":
        key = uuid4()
    else:
        target = uuid4()
    before = database_state(parent.engine)
    with pytest.raises(CoordinatorError):
        parent.handle(wire(parent, "RELEASE_READER", target, key))
    assert released == []
    assert database_state(parent.engine) == before


def test_explicit_stop_does_not_need_a_capacity_slot(parent_journey):
    parent, journey, _ = parent_journey
    from tests.dashboard_integrated_protocol import parse_control

    for _ in range(32):
        command = parse_control(
            wire(parent, "RUN_WORKER", uuid4(), uuid4()), expected_instance=parent.instance
        )
        assert parent.fence.claim(command)[1]
    before = database_state(parent.engine)
    result = parent.handle(wire(parent, "STOP", None, uuid4()))
    assert result.state == "CLOSED" and result.effects_canceled is False
    assert parent.handle(worker_command(parent, journey)).state == "CLOSED"
    assert database_state(parent.engine) == before and parent.worker_report is None


@pytest.mark.parametrize("scenario", ["quarantine", "late-ack"])
def test_installed_quarantine_and_late_ack_never_admit_verification(parent_journey, scenario):
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.dashboard_integrated_scenarios import reader_scenario

    parent, journey, released = parent_journey
    parent.scenario = reader_scenario(scenario)
    command = worker_command(parent, journey)
    reply = parent.handle(command)
    assert reply.state == "WORKER_QUARANTINED" and not reply.effects_canceled
    assert parent.handle(command) == reply
    current = journey.view()
    assert current.phase is ExecutionPhase.QUARANTINED and current.reservation_held
    assert parent.acknowledged_execution is None
    assert parent.quarantined_execution == journey.execution_id
    assert parent.worker_dispatched is True
    kinds = [entry.content.kind.value for entry in current.events]
    assert kinds[:4] == ["REQUESTED", "CLAIMED", "WRITE_INTENT", "QUARANTINED"]
    assert kinds[4:] == (
        ["ACKNOWLEDGED", "OBSERVED"] if scenario == "late-ack" else ["OBSERVATION_FAILED"]
    )
    if scenario == "late-ack":
        assert current.events[4].content.phase is ExecutionPhase.QUARANTINED
        assert current.events[4].content.request_id == "offline-process-write"
        assert current.events[-1].content.observation.encryption_by_default is True
    before = database_state(parent.engine)
    denied = journey.client.post(
        journey.detail + "/verifications",
        headers=signed_headers(journey.issuer, "verification-operator", "ADMIN"),
        json={"reason": "A late receipt is not eligible normal acknowledgment."},
    )
    assert denied.status_code == 409
    assert denied.json()["detail"]["code"] == "remediation_verification_ineligible"
    assert database_state(parent.engine) == before
    assert journey.executor.submissions == [] and released == []
    assert_integrated_receipt(parent, before, scenario=scenario)


def test_parent_sequential_three_attempts_use_real_managed_boundaries(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    from app.services.remediation_verification_service import RemediationVerificationService
    from tests.dashboard_integrated_proof import assert_integrated_receipt, assert_reader_sequence

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=lambda: regional_reader(enabled=False),
    ) as journey:
        released = []

        def release(scan_id):
            assert journey.executor.entered.wait(5)
            with Session(engine) as session:
                page = RemediationVerificationService(session).list_verifications(
                    parent._principal(), execution_id=journey.execution_id
                )
            values = sorted(page.items, key=lambda value: value.content.attempt)
            assert values[-1].content.scan_id == scan_id
            assert_reader_sequence(journey.executor, values, max_attempts=3)
            released.append(scan_id)
            journey.executor.release.set()

        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            journey.source,
            instance=str(uuid4()),
            issuer=journey.issuer.issuer,
            release_reader=release,
        )
        assert parent.handle(worker_command(parent, journey)).state == "WORKER_ACKNOWLEDGED"
        before_reader = database_state(engine)
        completed = []
        for ordinal in range(1, 4):
            pending, key = request_verification(journey)
            assert pending.content.attempt == ordinal
            before = database_state(engine)
            denied = journey.client.post(
                journey.detail + "/verifications",
                headers=signed_headers(journey.issuer, "another-executor", "ADMIN"),
                json={"reason": "Active accepted scan cannot be duplicated."},
            )
            assert denied.status_code == 409
            assert denied.json()["detail"]["code"] == "remediation_verification_active"
            assert database_state(engine) == before
            assert len(journey.executor.submissions) == ordinal
            release_wire = wire(parent, "RELEASE_READER", pending.content.verification_id, key)
            assert parent.handle(release_wire).state == "READER_RELEASED"
            assert parent.handle(release_wire).state == "READER_RELEASED"
            value = wait_for_receipt(journey, pending.content.verification_id)
            assert value.receipt.outcome.value == "NOT_VERIFIED"
            completed.append(value)
            for previous in completed:
                response = journey.client.get(
                    "/api/v1/remediation-verifications/" + str(previous.content.verification_id),
                    headers=signed_headers(journey.issuer, "history-reader", "VIEWER"),
                )
                assert response.status_code == 200
                assert response.json() == previous.model_dump(mode="json")
        before = database_state(engine)
        exhausted = journey.client.post(
            journey.detail + "/verifications",
            headers=signed_headers(journey.issuer, "another-executor", "ADMIN"),
            json={"reason": "No fourth accepted attempt."},
        )
        assert exhausted.status_code == 409
        assert exhausted.json()["detail"]["code"] == "remediation_verification_limit"
        assert database_state(engine) == before
        assert len(released) == len(set(released)) == len(journey.executor.submissions) == 3
        assert_integrated_receipt(parent, before_reader, scenario="attempt-limit")


def test_loss_gate_proves_real_signed_commit_then_same_operation_replay(
    process_database, monkeypatch, tmp_path
):
    from sqlalchemy import select

    from app.models.remediation import RemediationProposal
    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_loss import CommittedProposalReplyLoss
    from tests.verification_acceptance import full_scope_source

    engine, _ = process_database
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        _,
        executor,
    ):
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "Review committed proposal before explicit original-key retry.",
                }
            ),
        )
        gate = CommittedProposalReplyLoss(engine, issuer=issuer.issuer)
        with gate.installed():
            first = submit(client, status, value)
            assert first.status_code == 200
            uncertain = first.json()
            assert uncertain["state"] == "UNCONFIRMED" and uncertain["attempts"] == 1
            assert uncertain["result"] is None and gate.losses == 1
            committed = database_state(engine)
            with Session(engine) as session:
                identifier = session.execute(select(RemediationProposal.proposal_id)).scalar_one()
            recovered = client.get("/dashboard/api/remediation-operations/" + value["operation_id"])
            assert recovered.status_code == 200 and recovered.json() == uncertain
            assert len(gate.requests) == 1 and database_state(engine) == committed
            second = submit(client, status, value)
            assert second.status_code == 200
            confirmed = second.json()
            assert confirmed["state"] == "CONFIRMED" and confirmed["attempts"] == 2
            assert confirmed["operation_id"] == value["operation_id"]
            assert confirmed["input"] == value["input"] and confirmed["actor"] == value["actor"]
            assert confirmed["result"]["result_id"] == str(identifier)
            assert len(gate.requests) == 2 and gate.requests[0] == gate.requests[1]
            assert gate.losses == 1 and database_state(engine) == committed
            assert submit(client, status, value).json() == confirmed
            assert len(gate.requests) == 2 and executor.submissions == []


@pytest.mark.parametrize("scenario", ["reply-reference", "history-reference"])
def test_substituted_reference_and_conflicting_input_cannot_replace_original_signed_commit(
    process_database, monkeypatch, tmp_path, scenario
):
    from sqlalchemy import select

    from app.models.remediation import RemediationProposal
    from tests.api.test_dashboard_operations import (
        mutation_headers,
        operation_document,
        prepare,
        submit,
    )
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_reference import (
        SPOOFED_REFERENCE,
        CommittedReferenceSubstitution,
    )
    from tests.verification_acceptance import full_scope_source

    engine, _ = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        _boundary,
        executor,
    ):
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        body = {
            "finding_id": str(source.finding_id),
            "occurrence_id": str(source.occurrence_id),
            "reason": "Untrusted references must not replace this exact committed proposal.",
        }
        value = prepare(client, status, operation_document(body=body))
        gate = CommittedReferenceSubstitution(engine, issuer=issuer.issuer, scenario=scenario)
        with gate.installed():
            first = submit(client, status, value)
            assert first.status_code == 200
            uncertain = first.json()
            assert uncertain["state"] == "UNCONFIRMED" and uncertain["attempts"] == 1
            assert uncertain["result"] is None and str(SPOOFED_REFERENCE) not in first.text
            assert gate.substitutions == 1 and gate.losses == 0 and len(gate.requests) == 1
            committed = database_state(engine)
            with Session(engine) as session:
                identifier = session.execute(select(RemediationProposal.proposal_id)).scalar_one()
            assert identifier == gate.proposal_id and identifier != SPOOFED_REFERENCE
            assert (
                client.get("/dashboard/api/remediation-operations/" + value["operation_id"]).json()
                == uncertain
            )
            # Actual closed BFF input rejects replacing the frozen body or selecting its key.
            for replacement in ({"reason": "Different body"}, {"operation_id": str(uuid4())}):
                denied = client.post(
                    "/dashboard/api/remediation-operations/" + value["operation_id"] + "/submit",
                    json=replacement,
                    headers=mutation_headers(status),
                )
                assert denied.status_code == 422
            denied = client.post(
                "/dashboard/api/remediation-operations",
                json={**operation_document(body=body), "operation_id": str(uuid4())},
                headers=mutation_headers(status),
            )
            assert denied.status_code == 422
            assert database_state(engine) == committed and len(gate.requests) == 1
            # Separate real bearer boundary: same actor/key with changed normalized reason is 409.
            conflict = client.post(
                "/api/v1/remediations",
                json={**value["input"], "reason": "Changed original intent."},
                headers=signed_headers(issuer, "proposer", "ANALYST", key=gate.requests[0][0]),
            )
            assert conflict.status_code == 409
            assert conflict.json()["detail"]["code"] == "remediation_idempotency_conflict"
            assert database_state(engine) == committed and len(gate.requests) == 1
            second = submit(client, status, value)
            assert second.status_code == 200
            confirmed = second.json()
            assert confirmed["state"] == "CONFIRMED" and confirmed["attempts"] == 2
            assert confirmed["result"]["result_id"] == str(identifier)
            for field in (
                "operation_id",
                "operation",
                "target_id",
                "input",
                "actor",
                "prepared_at",
                "expires_at",
            ):
                assert confirmed[field] == value[field]
            gate.assert_complete()
            assert database_state(engine) == committed and executor.submissions == []
            assert submit(client, status, value).json() == confirmed
            assert len(gate.requests) == 2


def test_native_inflight_gate_requires_real_commit_and_suppresses_second_bearer_dispatch(
    process_database, monkeypatch, tmp_path
):
    import time
    from concurrent.futures import ThreadPoolExecutor

    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_loss import CommittedProposalInFlight, InFlightObserver
    from tests.verification_acceptance import full_scope_source

    engine, _ = process_database
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        _,
        executor,
    ):
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": (
                        "Real signed commit, retained IN_FLIGHT and no duplicate bearer dispatch."
                    ),
                }
            ),
        )
        gate = CommittedProposalInFlight(engine, issuer=issuer.issuer)
        monkeypatch.setattr(
            client.app, "middleware_stack", InFlightObserver(client.app.middleware_stack, gate=gate)
        )
        with gate.installed(), ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(submit, client, status, value)
            deadline = time.monotonic() + 5
            while not gate.held and time.monotonic() < deadline:
                time.sleep(0.005)
            assert gate.held and not pending.done()
            committed = database_state(engine)
            current = client.get("/dashboard/api/remediation-operations/" + value["operation_id"])
            assert current.status_code == 200
            active = current.json()
            assert active["state"] == "IN_FLIGHT" and active["attempts"] == 1
            assert active["result"] is None and len(gate.requests) == 1
            duplicate = submit(client, status, value)
            assert duplicate.status_code == 200 and duplicate.json() == active
            settled = pending.result(timeout=5)
            assert settled.status_code == 200 and settled.json()["state"] == "CONFIRMED"
            assert settled.json()["attempts"] == 1
            assert settled.json()["input"] == value["input"]
            assert settled.json()["actor"] == value["actor"]
            assert submit(client, status, value).json() == settled.json()
            assert len(gate.requests) == 1 and database_state(engine) == committed
            assert executor.submissions == []
            gate.assert_complete()


@pytest.mark.parametrize("append_rejection", [False, True])
def test_elapsed_proposal_expiry_preserves_commit_denies_approval_and_has_no_execution(
    process_database, offline_process_runtime, monkeypatch, tmp_path, append_rejection
):
    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_authority_expiry import (
        CommittedProposalExpiry,
        ProposalExpiryClock,
    )
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.verification_acceptance import full_scope_source

    engine, child_url = process_database
    source = full_scope_source(engine)
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=str(uuid4()),
            issuer=issuer.issuer,
            release_reader=lambda _scan: pytest.fail("No reader"),
            scenario="proposal-expiry",
        )
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "A retained commit never renews expired proposal authority.",
                }
            ),
        )
        clock = ProposalExpiryClock(issuer.issuer)
        gate = CommittedProposalExpiry(
            engine, issuer=issuer.issuer, store=boundary.store, clock=clock
        )
        with clock.installed(), gate.installed():
            uncertain = submit(client, status, value).json()
            assert uncertain["state"] == "UNCONFIRMED" and uncertain["attempts"] == 1
            committed = database_state(engine)
            detail = "/api/v1/remediations/" + str(gate.proposal_id)
            proposal = client.get("/dashboard/api/remediations/" + str(gate.proposal_id)).json()
            assert proposal["blocking_reasons"] == ["EXPIRED"]
            assert proposal["approval_status"] == "PROPOSED" and proposal["decisions"] == []
            confirmed = submit(client, status, value).json()
            assert confirmed["state"] == "CONFIRMED" and confirmed["attempts"] == 2
            assert confirmed["result"]["result_id"] == str(gate.proposal_id)
            for field in ("operation_id", "input", "actor", "prepared_at", "expires_at"):
                assert confirmed[field] == value[field]
            denied = client.post(
                detail + "/decisions",
                headers=signed_headers(issuer, "approver", "APPROVER", key=uuid4()),
                json={
                    "proposal_sha256": proposal["proposal_sha256"],
                    "decision": "APPROVE",
                    "reason": "Expired approval must fail without a new decision.",
                },
            )
            assert denied.status_code == 409 and database_state(engine) == committed
            assert client.get("/dashboard/session").json()["authenticated"] is True
            assert executor.submissions == [] and not parent.worker_dispatched
            gate.assert_complete()
            if append_rejection:
                rejected = client.post(
                    detail + "/decisions",
                    headers=signed_headers(issuer, "approver", "APPROVER", key=uuid4()),
                    json={
                        "proposal_sha256": proposal["proposal_sha256"],
                        "decision": "REJECT",
                        "reason": "Rejection is allowed, but violates this no-decision proof.",
                    },
                )
                assert rejected.status_code == 201
                with pytest.raises(ValueError, match="Invalid integrated no-execution proof"):
                    assert_integrated_receipt(parent, None, scenario="proposal-expiry")
            else:
                assert_integrated_receipt(parent, None, scenario="proposal-expiry")


def test_elapsed_store_clock_expires_preparations_but_never_cancels_prior_commit(
    process_database, monkeypatch, tmp_path
):
    import time

    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_expiry import CommittedPreparationExpiry, PreparationExpiryClock
    from tests.verification_acceptance import full_scope_source

    engine, _ = process_database
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role, issuer.subject = "ANALYST", "proposer"
        issuer.access_overrides["exp"] = int(time.time()) + 3600
        clock = PreparationExpiryClock(issuer.issuer, 16)
        boundary.store.clock = clock
        status = sign_in(client, issuer)
        first = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "Expiry is never cancellation of an already committed proposal.",
                }
            ),
        )
        for _ in range(15):
            prepare(client, status, operation_document())
        gate = CommittedPreparationExpiry(
            engine, issuer=issuer.issuer, store=boundary.store, clock=clock
        )
        with gate.installed():
            accepted = submit(client, status, first)
            assert accepted.status_code == 200
            uncertain = accepted.json()
            assert uncertain["state"] == "UNCONFIRMED" and uncertain["attempts"] == 1
            assert uncertain["result"] is None and clock.shift == 301
            committed = database_state(engine)
            page = client.get("/dashboard/api/remediation-operations").json()["items"]
            assert len(page) == 16 and sum(value["state"] == "EXPIRED" for value in page) == 15
            denied = submit(client, status, first)
            assert denied.status_code == 409
            assert denied.json() == {
                "detail": "Preparation expired; prior effects are not canceled"
            }
            assert (
                client.get("/dashboard/api/remediation-operations/" + first["operation_id"]).json()
                == uncertain
            )
            from tests.api.test_dashboard_operations import mutation_headers

            capacity = client.post(
                "/dashboard/api/remediation-operations",
                headers=mutation_headers(status),
                json=operation_document(),
            )
            assert capacity.status_code == 503
            assert client.get("/dashboard/api/remediation-operations").json()["items"] == page
            assert client.get("/dashboard/api/remediations").json()["total"] == 1
            assert database_state(engine) == committed and executor.submissions == []
            gate.assert_complete()


def test_real_issuer_restart_keeps_same_subject_distinct_through_installed_verification(
    offline_process_runtime, process_database, monkeypatch
):
    from contextlib import ExitStack
    from types import SimpleNamespace
    from uuid import UUID

    import httpx2 as httpx
    from sqlalchemy import select
    from sqlalchemy.exc import NoResultFound

    from app.dashboard.logging import protect_identity_logs
    from app.models.remediation_verification import RemediationVerification
    from tests.dashboard_integrated_authority_restart import (
        RestartableAuthorityServer,
        restart_bound_authority,
    )
    from tests.dashboard_integrated_bootstrap import ISSUER, MARKER, ORIGIN, SECOND_ISSUER
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.dashboard_integrated_protocol import parse_control
    from tests.verification_acceptance import full_scope_source
    from tests.worker_http import assert_history
    from tests.worker_process_runtime import cleanup_preserving_primary, isolated_child_environment

    engine, child_url = process_database
    protect_identity_logs()
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source, instance = full_scope_source(engine), str(uuid4())
    schema = child_url.query["options"].removeprefix("-csearch_path=")
    assert schema in offline_process_runtime.schemas
    assert child_url == offline_process_runtime.database_url(child=True, schema=schema)
    assert engine.url == offline_process_runtime.database_url(schema=schema)
    with engine.begin() as connection:
        connection.exec_driver_sql(f"COMMENT ON SCHEMA {schema} IS '{MARKER}{instance}'")
    env = isolated_child_environment(
        {
            "DASHBOARD_BROWSER_TEST": "1",
            "DASHBOARD_INTEGRATED_INSTANCE": instance,
            "DASHBOARD_INTEGRATED_SOURCE": source.model_dump_json(),
            "DASHBOARD_INTEGRATED_SCENARIO": "cross-issuer",
            "DATABASE_URL": engine.url.render_as_string(hide_password=False),
            "PYTHONUNBUFFERED": "1",
        }
    )
    for name in tuple(env):
        if name.upper().startswith("DOCKER_"):
            env.pop(name)

    def sign_in(client, issuer_url, identity):
        status = client.get("/dashboard/session").json()
        start = client.post(
            "/dashboard/auth/login",
            headers={"Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]},
        )
        assert start.status_code == 200
        assert client.get(start.json()["authorization_url"]).status_code == 200
        approved = client.get(issuer_url + "/approve", params={"identity": identity})
        assert approved.status_code == 303
        assert client.get(approved.headers["location"]).status_code == 303
        result = client.get("/dashboard/session").json()
        assert result["authenticated"] is True and result["issuer"] == issuer_url
        return result

    def headers(status):
        return {
            "Origin": ORIGIN,
            "Sec-Fetch-Site": "same-origin",
            "X-CSRF-Token": status["csrf_token"],
            "X-Dashboard-Context": status["session_context"],
        }

    def operation(client, status, kind, body, target=None):
        document = {"schema_version": "1.0.0", "operation": kind, "input": body}
        if target is not None:
            document["target_id"] = str(target)
        prepared = client.post(
            "/dashboard/api/remediation-operations", json=document, headers=headers(status)
        )
        assert prepared.status_code == 201
        value = prepared.json()
        settled = client.post(
            "/dashboard/api/remediation-operations/" + value["operation_id"] + "/submit",
            json={},
            headers=headers(status),
        )
        assert settled.status_code == 200
        return value, settled.json()

    def read(client, status, path):
        response = client.get("/dashboard/api/" + path, headers=headers(status))
        assert response.status_code == 200
        return response.json()

    server, primary = RestartableAuthorityServer(env), None
    try:
        server.wait(b"INTEGRATED_SERVER_READY", 30)

        def release(scan_id):
            with Session(engine) as session:
                request = session.execute(
                    select(RemediationVerification).where(
                        RemediationVerification.scan_id == scan_id
                    )
                ).scalar_one()
                command = wire(
                    parent, "RELEASE_READER", request.verification_id, request.idempotency_key
                )
                key = request.idempotency_key
            server.send(command + b"\n")
            server.wait(b"INTEGRATED_READER_RELEASED=" + str(key).encode(), 6)

        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=instance,
            issuer=ISSUER,
            release_reader=release,
            scenario="cross-issuer",
            restart_authority=server.restart,
        )
        with ExitStack() as clients:
            first, approver, requester = [
                clients.enter_context(
                    httpx.Client(
                        base_url=ORIGIN, trust_env=False, follow_redirects=False, timeout=15
                    )
                )
                for _ in range(3)
            ]
            initial_status = sign_in(first, ISSUER, "proposer")
            prepared, uncertain = operation(
                first,
                initial_status,
                "PROPOSE",
                {
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "Original issuer proposal survives exact owned process loss.",
                },
            )
            assert uncertain["state"] == "UNCONFIRMED" and uncertain["attempts"] == 1
            original = read(first, initial_status, "remediations")["items"][0]
            proposal_id, digest = (
                UUID(original["content"]["proposal_id"]),
                original["proposal_sha256"],
            )
            committed, old_child = database_state(engine), server.current.child
            bad = parse_control(
                wire(parent, "RESTART_AUTHORITY", proposal_id, uuid4()), expected_instance=instance
            )
            with pytest.raises(NoResultFound):
                restart_bound_authority(parent, bad)
            assert not parent.restart_dispatched and server.current.child is old_child
            assert database_state(engine) == committed
            restart = wire(parent, "RESTART_AUTHORITY", proposal_id, UUID(prepared["operation_id"]))
            reply = parent.handle(restart)
            assert reply.state == "AUTHORITY_RESTARTED" and reply.effects_canceled is False
            assert old_child.poll() == 0 and server.current.child is not old_child
            replacement = server.current.child
            assert parent.handle(restart) == reply and server.current.child is replacement
            assert database_state(engine) == committed
            assert first.get("/dashboard/session").json()["authenticated"] is False
            admin = sign_in(first, SECOND_ISSUER, "proposer")
            assert admin["subject"] == initial_status["subject"] == "proposer" and admin[
                "roles"
            ] == ["ADMIN"]
            assert read(first, admin, "remediation-operations")["items"] == []
            assert (
                first.get(
                    "/dashboard/api/remediation-operations/" + prepared["operation_id"],
                    headers=headers(admin),
                ).status_code
                == 404
            )
            retained = read(first, admin, "remediations/" + str(proposal_id))
            assert (
                retained["content"] == original["content"] and retained["proposal_sha256"] == digest
            )
            reviewer = sign_in(approver, SECOND_ISSUER, "approver")
            assert reviewer["subject"] == "proposer" and reviewer["roles"] == ["APPROVER"]
            _, approved = operation(
                approver,
                reviewer,
                "DECIDE",
                {
                    "proposal_sha256": digest,
                    "decision": "APPROVE",
                    "reason": "Same subject at a separately verified issuer is distinct.",
                },
                proposal_id,
            )
            assert approved["state"] == "CONFIRMED"
            body = {
                "proposal_sha256": digest,
                "approval_decision_id": approved["result"]["result_id"],
                "reason": "Only a third full identity can request bounded execution.",
            }
            _, denied = operation(first, admin, "REQUEST_EXECUTION", body, proposal_id)
            assert denied["state"] == "UNCONFIRMED" and denied["result"] is None
            third = sign_in(requester, SECOND_ISSUER, "requester")
            admitted, accepted = operation(requester, third, "REQUEST_EXECUTION", body, proposal_id)
            assert accepted["state"] == "CONFIRMED"
            execution_id = UUID(accepted["result"]["result_id"])
            before = parent._execution(execution_id)
            with pytest.raises(AssertionError):
                assert_history(engine, before, before, SimpleNamespace(issuer=ISSUER))
            assert (
                parent.handle(
                    wire(parent, "RUN_WORKER", execution_id, UUID(admitted["operation_id"]))
                ).state
                == "WORKER_ACKNOWLEDGED"
            )
            before_reader = database_state(engine)
            verify, requested = operation(
                requester,
                third,
                "REQUEST_VERIFICATION",
                {"reason": "Observe retained mixed-issuer authority through the managed reader."},
                execution_id,
            )
            assert requested["state"] == "CONFIRMED"
            assert (
                parent.handle(
                    wire(
                        parent,
                        "RELEASE_READER",
                        UUID(requested["result"]["result_id"]),
                        UUID(verify["operation_id"]),
                    )
                ).state
                == "READER_RELEASED"
            )
            assert_integrated_receipt(parent, before_reader, scenario="cross-issuer")
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_preserving_primary(lambda: server.close(instance), primary)


@pytest.mark.parametrize(
    "scenario",
    ["admission-stale", "governance-change", "governance-round-trip", "governance-exception"],
)
def test_signed_governance_and_approved_staleness_preserve_history_and_deny_admission(
    offline_process_runtime, process_database, monkeypatch, tmp_path, scenario
):
    from tests.api.test_dashboard_operations import (
        mutation_headers,
        operation_document,
        prepare,
        submit,
    )
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_governance import authority_case
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.verification_acceptance import full_scope_source

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source, case = full_scope_source(engine), authority_case(scenario)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        _boundary,
        executor,
    ):
        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=str(uuid4()),
            issuer=issuer.issuer,
            release_reader=lambda _scan: pytest.fail("No reader"),
            scenario=scenario,
        )

        def switch(status, role, subject):
            assert (
                client.post("/dashboard/auth/logout", headers=mutation_headers(status)).status_code
                == 204
            )
            client.headers.pop("X-Dashboard-Context", None)
            issuer.role, issuer.subject = role, subject
            return sign_in(client, issuer)

        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        prepared = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "Retained authority cannot revive after governance or new evidence.",
                }
            ),
        )
        accepted = submit(client, status, prepared).json()
        assert accepted["state"] == "CONFIRMED"
        identifier = accepted["result"]["result_id"]
        original = client.get("/dashboard/api/remediations/" + identifier).json()
        approval_id = None
        if case.approved:
            status = switch(status, "APPROVER", "approver")
            decision = prepare(
                client,
                status,
                operation_document(
                    "DECIDE",
                    target=identifier,
                    body={
                        "proposal_sha256": original["proposal_sha256"],
                        "decision": "APPROVE",
                        "reason": "Distinct signed human approval must remain immutable.",
                    },
                ),
            )
            approved = submit(client, status, decision).json()
            assert approved["state"] == "CONFIRMED"
            approval_id = approved["result"]["result_id"]
            original = client.get("/dashboard/api/remediations/" + identifier).json()
            assert original["approval_status"] == "APPROVED" and len(original["decisions"]) == 1
        command = wire(
            parent,
            "COLLECT_STALE" if scenario == "admission-stale" else "CHANGE_GOVERNANCE",
            identifier,
            prepared["operation_id"],
        )
        reply = parent.handle(command)
        assert reply.state == (
            "STALE_OBSERVATION_PERSISTED" if scenario == "admission-stale" else "GOVERNANCE_CHANGED"
        )
        assert reply.effects_canceled is False and parent.handle(command) is reply
        captured = database_state(engine)
        status = switch(
            status,
            "ADMIN" if case.approved else "APPROVER",
            "requester" if case.approved else "approver",
        )
        current = client.get("/dashboard/api/remediations/" + identifier).json()
        assert (
            current["content"] == original["content"]
            and current["proposal_sha256"] == original["proposal_sha256"]
        )
        assert (
            current["decisions"] == original["decisions"]
            and current["approval_status"] == original["approval_status"]
        )
        assert case.blocker in current["blocking_reasons"]
        operation = "REQUEST_EXECUTION" if case.approved else "DECIDE"
        body = {
            "proposal_sha256": original["proposal_sha256"],
            "reason": "Current authority blockers must deny this request.",
        }
        body.update(
            {"approval_decision_id": approval_id} if case.approved else {"decision": "APPROVE"}
        )
        negative = prepare(
            client, status, operation_document(operation, target=identifier, body=body)
        )
        denied = submit(client, status, negative)
        assert denied.status_code == 200
        assert denied.json()["state"] == "UNCONFIRMED" and denied.json()["attempts"] == 1
        assert denied.json()["result"] is None
        assert database_state(engine) == captured and executor.submissions == []
        assert_integrated_receipt(parent, None, scenario=scenario)


@pytest.mark.parametrize("scenario", ["admission-stale", "governance-round-trip"])
@pytest.mark.parametrize("fault", ["key", "proposal", "unapproved", "actor"])
def test_approved_authority_fixture_rejects_wrong_binding_or_phase_before_effect(
    offline_process_runtime, process_database, monkeypatch, tmp_path, scenario, fault
):
    from tests.api.test_dashboard_operations import (
        mutation_headers,
        operation_document,
        prepare,
        submit,
    )
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.verification_acceptance import full_scope_source

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        _boundary,
        _executor,
    ):
        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=str(uuid4()),
            issuer=issuer.issuer,
            release_reader=lambda _scan: pytest.fail("No reader"),
            scenario=scenario,
        )
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        prepared = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "The fixture must validate the original signed authority prefix.",
                }
            ),
        )
        accepted = submit(client, status, prepared).json()
        assert accepted["state"] == "CONFIRMED"
        identifier = accepted["result"]["result_id"]
        original = client.get("/dashboard/api/remediations/" + identifier).json()
        if fault != "unapproved":
            assert (
                client.post("/dashboard/auth/logout", headers=mutation_headers(status)).status_code
                == 204
            )
            client.headers.pop("X-Dashboard-Context", None)
            issuer.role, issuer.subject = (
                "APPROVER",
                "other-approver" if fault == "actor" else "approver",
            )
            status = sign_in(client, issuer)
            decision = prepare(
                client,
                status,
                operation_document(
                    "DECIDE",
                    target=identifier,
                    body={
                        "proposal_sha256": original["proposal_sha256"],
                        "decision": "APPROVE",
                        "reason": "Valid approval with a fixture-bound expected actor.",
                    },
                ),
            )
            assert submit(client, status, decision).json()["state"] == "CONFIRMED"
        before = database_state(engine)
        command = wire(
            parent,
            "COLLECT_STALE" if scenario == "admission-stale" else "CHANGE_GOVERNANCE",
            uuid4() if fault == "proposal" else identifier,
            uuid4() if fault == "key" else prepared["operation_id"],
        )
        with pytest.raises(
            CoordinatorError, match="unconfirmed at (STALE|GOVERNANCE)_ORIGINAL_AUTHORITY"
        ):
            parent.handle(command)
        assert parent.stale_dispatched is False and parent.governance_dispatched is False
        replay = parent.handle(command)
        assert replay.state == "UNCONFIRMED" and replay.effects_canceled is False
        assert database_state(engine) == before


@pytest.mark.parametrize(
    "scenario",
    [
        "stale-newer-fail",
        "stale-newer-pass",
        "stale-newer-insufficient",
        "stale-equal-fail",
        "stale-equal-pass",
        "stale-equal-insufficient",
    ],
)
def test_real_collected_newer_or_equal_evidence_denies_signed_approval_and_preserves_history(
    offline_process_runtime, process_database, monkeypatch, tmp_path, scenario
):
    import json

    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.verification_acceptance import full_scope_source

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        _boundary,
        executor,
    ):
        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=str(uuid4()),
            issuer=issuer.issuer,
            release_reader=lambda _scan: pytest.fail("No reader"),
            scenario=scenario,
        )
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        prepared = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "Retained approval must stale after actual newly collected evidence.",
                }
            ),
        )
        submitted = submit(client, status, prepared)
        assert submitted.status_code == 200 and submitted.json()["state"] == "CONFIRMED"
        identifier = submitted.json()["result"]["result_id"]
        command = json.dumps(
            {
                "schema_version": "1.0.0",
                "instance_id": parent.instance,
                "request_id": prepared["operation_id"],
                "command": "COLLECT_STALE",
                "proposal_id": identifier,
            }
        ).encode()
        reply = parent.handle(command)
        assert reply.state == "STALE_OBSERVATION_PERSISTED" and reply.effects_canceled is False
        assert parent.handle(command) is reply
        captured = database_state(engine)
        original = parent.stale_view
        from tests.api.test_dashboard_operations import mutation_headers

        assert (
            client.post("/dashboard/auth/logout", headers=mutation_headers(status)).status_code
            == 204
        )
        client.headers.pop("X-Dashboard-Context", None)
        issuer.role, issuer.subject = "APPROVER", "approver"
        approver = sign_in(client, issuer)
        current = client.get("/dashboard/api/remediations/" + identifier).json()
        assert current["content"] == original.content.model_dump(mode="json")
        assert current["proposal_sha256"] == original.proposal_sha256
        assert "STALE_TARGET" in current["blocking_reasons"]
        decision = prepare(
            client,
            approver,
            operation_document(
                operation="DECIDE",
                target=identifier,
                body={
                    "decision": "APPROVE",
                    "proposal_sha256": original.proposal_sha256,
                    "reason": "Stale approval must be denied.",
                },
            ),
        )
        denied = submit(client, approver, decision)
        assert denied.status_code == 200
        assert denied.json()["state"] == "UNCONFIRMED" and denied.json()["attempts"] == 1
        assert denied.json()["result"] is None
        assert database_state(engine) == captured and executor.submissions == []
        assert parent.stale_scan_id != parent.source.scan_id
        assert_integrated_receipt(parent, None, scenario=scenario)


@pytest.mark.parametrize("scenario", ["stale-newer-fail", "stale-equal-pass"])
@pytest.mark.parametrize("bad_binding", ["key", "proposal"])
def test_stale_parent_rejects_unbound_original_authority_before_collecting(
    offline_process_runtime, process_database, monkeypatch, tmp_path, scenario, bad_binding
):
    import json

    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.verification_acceptance import full_scope_source

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        _boundary,
        _executor,
    ):
        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=str(uuid4()),
            issuer=issuer.issuer,
            release_reader=lambda _scan: pytest.fail("No reader"),
            scenario=scenario,
        )
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        prepared = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "The parent must reject a substituted original authority reference.",
                }
            ),
        )
        accepted = submit(client, status, prepared).json()
        assert accepted["state"] == "CONFIRMED"
        before = database_state(engine)
        command = json.dumps(
            {
                "schema_version": "1.0.0",
                "instance_id": parent.instance,
                "request_id": str(uuid4()) if bad_binding == "key" else prepared["operation_id"],
                "command": "COLLECT_STALE",
                "proposal_id": str(uuid4())
                if bad_binding == "proposal"
                else accepted["result"]["result_id"],
            }
        ).encode()
        with pytest.raises(CoordinatorError, match="unconfirmed at STALE_ORIGINAL_AUTHORITY"):
            parent.handle(command)
        assert parent.stale_dispatched is False and parent.stale_after is None
        replay = parent.handle(command)
        assert replay.state == "UNCONFIRMED" and replay.effects_canceled is False
        assert database_state(engine) == before


@pytest.mark.parametrize("scenario", ["subject-replacement", "issuer-rejection"])
def test_signed_identity_substitution_rejects_existing_session_without_migrating_authority(
    offline_process_runtime, process_database, monkeypatch, tmp_path, scenario
):
    from datetime import datetime

    from app.config import get_settings
    from app.security.authentication import get_authentication_backend
    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_identity import CommittedIdentitySubstitution
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.verification_acceptance import full_scope_source

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=str(uuid4()),
            issuer=issuer.issuer,
            release_reader=lambda _scan: pytest.fail("No reader"),
            scenario=scenario,
        )
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "Identity substitution cannot transfer authority or erase history.",
                }
            ),
        )
        gate = CommittedIdentitySubstitution(
            engine, issuer=issuer, store=boundary.store, scenario=scenario
        )
        with gate.installed():
            submitted = submit(client, status, value)
            assert submitted.status_code == 200
            uncertain = submitted.json()
            assert uncertain["state"] == "UNCONFIRMED" and uncertain["attempts"] == 1
            assert uncertain["result"] is None and uncertain["actor"] == value["actor"]
            committed = database_state(engine)
            original = client.get(
                "/api/v1/remediations/" + str(gate.proposal_id),
                headers={"Authorization": "Bearer " + gate.original_token},
            )
            assert original.status_code == 200

            def retained_read(current):
                before = original.json()
                assert datetime.fromisoformat(
                    current["validity_checked_at"]
                ) >= datetime.fromisoformat(before["validity_checked_at"])
                assert current == {**before, "validity_checked_at": current["validity_checked_at"]}

            replacement = client.get(
                "/api/v1/remediations/" + str(gate.proposal_id),
                headers={"Authorization": "Bearer " + gate.replacement_token},
            )
            assert replacement.status_code == (200 if scenario == "subject-replacement" else 401)
            if scenario == "subject-replacement":
                verified = get_authentication_backend(get_settings()).authenticate(
                    gate.replacement_token
                )
                assert (verified.issuer, verified.subject) == (issuer.issuer, "replacement-subject")
                retained_read(replacement.json())
            # The still-existing cookie is not allowed to adopt the substituted signed principal.
            assert submit(client, status, value).status_code == 401
            assert client.get("/dashboard/session").json()["authenticated"] is False
            assert len(gate.requests) == 1 and gate.losses == 1
            gate.assert_complete()
            fresh = sign_in(client, issuer)
            assert fresh["session_context"] != status["session_context"]
            assert client.get("/dashboard/api/remediation-operations").json()["items"] == []
            assert submit(client, fresh, value).status_code == 404
            history = client.get("/dashboard/api/remediations").json()
            assert history["total"] == len(history["items"]) == 1
            retained_read(history["items"][0])
            assert history["items"][0]["content"]["proposer"]["subject"] == "proposer"
            assert database_state(engine) == committed and executor.submissions == []
            assert_integrated_receipt(parent, None, scenario=scenario)
            gate.assert_complete()


@pytest.mark.parametrize("scenario", ["idle-expiry", "token-expiry"])
def test_expiry_clears_coordination_but_fresh_signed_login_reconciles_original_proposal(
    offline_process_runtime, process_database, monkeypatch, tmp_path, scenario
):
    import time

    from tests import dashboard_fixtures
    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import AUDIENCE, ISSUER, dashboard_client, sign_in
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.dashboard_integrated_session_expiry import (
        CommittedSessionExpiry,
        IdleExpiryClock,
        make_expiry_issuer,
    )
    from tests.verification_acceptance import full_scope_source

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source = full_scope_source(engine)
    controlled = make_expiry_issuer(scenario, issuer=ISSUER, audience=AUDIENCE)
    monkeypatch.setattr(dashboard_fixtures, "ControlledIssuer", lambda: controlled)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=str(uuid4()),
            issuer=issuer.issuer,
            release_reader=lambda _scan: pytest.fail("No reader"),
            scenario=scenario,
        )
        idle_clock = IdleExpiryClock(issuer.issuer) if scenario == "idle-expiry" else None
        if idle_clock is not None:
            boundary.store.clock = idle_clock
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "Session loss never cancels a genuinely committed proposal.",
                }
            ),
        )
        gate = CommittedSessionExpiry(
            engine, issuer=issuer, store=boundary.store, scenario=scenario, clock=idle_clock
        )
        with gate.installed():
            submitted = submit(client, status, value)
            assert submitted.status_code == (401 if idle_clock else 200)
            if not idle_clock:
                assert submitted.json()["state"] == "UNCONFIRMED"
                deadline = time.monotonic() + 12
                while time.time() < issuer.first_deadline:
                    assert time.monotonic() < deadline, "Real test-token expiry deadline"
                    time.sleep(0.02)
            committed = database_state(engine)
            assert client.get("/dashboard/session").json()["authenticated"] is False
            old = client.get(
                "/dashboard/api/remediation-operations/" + value["operation_id"],
                headers={"X-Dashboard-Context": status["session_context"]},
            )
            assert old.status_code == 401
            # A real signed bearer read distinguishes idle expiry from actual JWT expiry.
            bearer = client.get(
                "/api/v1/remediations/" + str(gate.proposal_id),
                headers={"Authorization": "Bearer " + issuer.first_token},
            )
            assert bearer.status_code == (200 if idle_clock else 401)
            gate.assert_complete()
            fresh = sign_in(client, issuer)
            assert (
                fresh["authenticated"] is True
                and fresh["session_context"] != status["session_context"]
            )
            assert client.get("/dashboard/api/remediation-operations").json()["items"] == []
            assert submit(client, fresh, value).status_code == 404
            history = client.get("/dashboard/api/remediations").json()
            assert history["total"] == len(history["items"]) == 1
            proposal = history["items"][0]
            assert proposal["content"]["proposal_id"] == str(gate.proposal_id)
            assert proposal["content"]["baseline"]["occurrence_id"] == str(source.occurrence_id)
            assert proposal["content"]["proposer"]["subject"] == "proposer"
            assert proposal["approval_status"] == "PROPOSED" and proposal["decisions"] == []
            assert proposal["blocking_reasons"] == []
            assert database_state(engine) == committed and executor.submissions == []
            assert_integrated_receipt(parent, None, scenario=scenario)
            gate.assert_complete()


@pytest.mark.parametrize("scenario", ["revoked-before-intent", "revoked-after-ack"])
@pytest.mark.parametrize("fault", [None, "missing", "actor"])
def test_signed_revocation_preserves_the_intent_cutoff_and_read_only_observation(
    offline_process_runtime, process_database, monkeypatch, tmp_path, scenario, fault
):
    from types import SimpleNamespace
    from uuid import UUID

    from app.config import get_settings
    from app.remediation.execution_contracts import ExecutionView
    from tests.api.test_dashboard_operations import (
        mutation_headers,
        operation_document,
        prepare,
        submit,
    )
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.dashboard_integrated_revocation import read_revocation
    from tests.verification_acceptance import ManagedReader, full_scope_source
    from tests.worker_http import ACCOUNT, REGION

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source = full_scope_source(engine)
    for name, value in {
        "REMEDIATION_VERIFICATION_ENABLED": "true",
        "REMEDIATION_VERIFICATION_ACCOUNT_ID": ACCOUNT,
        "REMEDIATION_VERIFICATION_REGION": REGION,
    }.items():
        monkeypatch.setenv(name, value)
    with dashboard_client(
        engine,
        monkeypatch,
        tmp_path,
        remediation_enabled=True,
        executor_factory=lambda: ManagedReader(engine, source, regional_reader(enabled=True)),
    ) as (client, issuer, _boundary, managed):
        managed.actor_subject = "requester"
        try:
            for name, value in {
                "REMEDIATION_ADMISSION_ENABLED": "true",
                "REMEDIATION_ACCOUNT_ID": ACCOUNT,
                "REMEDIATION_REGION": REGION,
            }.items():
                monkeypatch.setenv(name, value)
            get_settings.cache_clear()

            def release(scan_id):
                assert managed.entered.wait(5)
                assert managed.submissions == [scan_id]
                managed.release.set()

            parent = IntegratedCoordinator(
                offline_process_runtime,
                engine,
                child_url,
                source,
                instance=str(uuid4()),
                issuer=issuer.issuer,
                release_reader=release,
                scenario=scenario,
            )

            def switch(status, role, subject):
                assert (
                    client.post(
                        "/dashboard/auth/logout", headers=mutation_headers(status)
                    ).status_code
                    == 204
                )
                client.headers.pop("X-Dashboard-Context", None)
                issuer.role, issuer.subject = role, subject
                return sign_in(client, issuer)

            def accepted(status, operation, target=None, body=None):
                prepared = prepare(
                    client, status, operation_document(operation, target=target, body=body)
                )
                response = submit(client, status, prepared)
                assert response.status_code == 200
                result = response.json()
                assert result["state"] == "CONFIRMED" and result["attempts"] == 1
                return result["result"]["result_id"], prepared

            issuer.role, issuer.subject = "ANALYST", "proposer"
            status = sign_in(client, issuer)
            proposal_id, _ = accepted(
                status,
                "PROPOSE",
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": "Review the exact retained target before the revocation cutoff.",
                },
            )
            proposal = client.get("/dashboard/api/remediations/" + proposal_id).json()
            status = switch(status, "APPROVER", "approver")
            decision_id, _ = accepted(
                status,
                "DECIDE",
                proposal_id,
                {
                    "proposal_sha256": proposal["proposal_sha256"],
                    "decision": "APPROVE",
                    "reason": "Independent approval before any installed worker.",
                },
            )
            status = switch(status, "ADMIN", "requester")
            execution_id, admitted = accepted(
                status,
                "REQUEST_EXECUTION",
                proposal_id,
                {
                    "proposal_sha256": proposal["proposal_sha256"],
                    "approval_decision_id": decision_id,
                    "reason": "Third human admits one bounded grant.",
                },
            )
            route = "/dashboard/api/remediation-executions/" + execution_id
            initial = ExecutionView.model_validate(client.get(route).json())
            command = wire(parent, "RUN_WORKER", UUID(execution_id), UUID(admitted["operation_id"]))
            before_reader = None
            if scenario == "revoked-after-ack":
                assert parent.handle(command).state == "WORKER_ACKNOWLEDGED"
                assert parent.handle(command).state == "WORKER_ACKNOWLEDGED"
                before_reader = database_state(engine)
                assert parent.revocation_ack_before == before_reader
            status = switch(
                status, "APPROVER", "other-approver" if fault == "actor" else "approver"
            )
            if fault != "missing":
                _, revoked_operation = accepted(
                    status,
                    "REVOKE",
                    proposal_id,
                    {
                        "proposal_sha256": proposal["proposal_sha256"],
                        "approval_decision_id": decision_id,
                        "reason": "Revocation is not cancellation or proof of no earlier effect.",
                    },
                )
                # Same prepared key cannot append another decision or renew a grant.
                captured = database_state(engine)
                assert submit(client, status, revoked_operation).json()["state"] == "CONFIRMED"
                assert database_state(engine) == captured
            if fault:
                captured = database_state(engine)
                with pytest.raises(ValueError, match="Invalid retained revocation"):
                    read_revocation(parent, initial, required=True)
                if scenario == "revoked-before-intent":
                    with pytest.raises(CoordinatorError, match="unconfirmed at"):
                        parent.handle(command)
                    assert parent.worker_dispatched is False
                    assert parent.handle(command).state == "UNCONFIRMED"
                assert database_state(engine) == captured and managed.submissions == []
                return
            revoked = read_revocation(parent, initial, required=True)
            assert revoked.approval_decision_id == UUID(decision_id)
            if scenario == "revoked-before-intent":
                reply = parent.handle(command)
                assert reply.state == "WORKER_NO_WRITE" and reply.effects_canceled is False
                assert parent.handle(command) == reply
                current = parent._execution(UUID(execution_id))
                assert current.phase.value == "NO_WRITE" and current.reservation_held is False
                after = database_state(engine)
                assert_integrated_receipt(parent, after, scenario=scenario)
                # The separate real installed restart is also read-only and cannot dispatch.
                report = offline_process_runtime.run_worker(
                    {
                        "argv": [execution_id],
                        "responses": [],
                        "metadata": "valid",
                        "target": {
                            "execution_id": execution_id,
                            "proposal_id": proposal_id,
                            "resource_id": str(initial.content.proposal.resource_id),
                            "finding_id": str(source.finding_id),
                        },
                    },
                    child_url,
                )
                assert report["stdout"] == "NO_WRITE\n" and report["calls"] == []
                assert report["enable_invocations"] == report["intent_checks"] == 0
                assert database_state(engine) == after
                status = switch(status, "ADMIN", "requester")
                denied = prepare(
                    client,
                    status,
                    operation_document(
                        "REQUEST_VERIFICATION",
                        target=execution_id,
                        body={"reason": "NO_WRITE is not ACK."},
                    ),
                )
                result = submit(client, status, denied).json()
                assert result["state"] == "UNCONFIRMED" and result["result"] is None
                assert result["attempts"] == 1 and managed.submissions == []
                assert database_state(engine) == after
                assert_integrated_receipt(parent, after, scenario=scenario)
            else:
                current = parent._execution(UUID(execution_id))
                assert current.phase.value == "ACKNOWLEDGED" and not current.reservation_held
                assert [r.value for r in current.blocking_reasons] == ["APPROVAL_REVOKED"]
                assert current.events == parent.worker_history.events
                status = switch(status, "ADMIN", "requester")
                verification_id, verification_operation = accepted(
                    status,
                    "REQUEST_VERIFICATION",
                    execution_id,
                    {"reason": "Observe retained acknowledgment without another write."},
                )
                release_command = wire(
                    parent,
                    "RELEASE_READER",
                    UUID(verification_id),
                    UUID(verification_operation["operation_id"]),
                )
                assert parent.handle(release_command).state == "READER_RELEASED"
                assert parent.handle(release_command).state == "READER_RELEASED"
                completed = wait_for_receipt(
                    SimpleNamespace(
                        client=client, reader=signed_headers(issuer, "requester", "ADMIN")
                    ),
                    UUID(verification_id),
                )
                assert completed.receipt.outcome.value == "VERIFIED"
                assert managed.submissions == [completed.content.scan_id]
                assert_integrated_receipt(parent, before_reader, scenario=scenario)
                with pytest.raises(
                    ValueError, match="Invalid integrated revoked acknowledgment proof"
                ):
                    assert_integrated_receipt(
                        parent, {**before_reader, "findings": ()}, scenario=scenario
                    )
                assert parent.worker_report["enable_invocations"] == 1
        finally:
            managed.release.set()


def test_elapsed_execution_grant_prevents_installed_credentials_intent_and_dispatch(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    from types import SimpleNamespace
    from uuid import UUID

    from app.config import get_settings
    from app.remediation.execution_contracts import ExecutionView
    from tests.api.test_dashboard_operations import operation_document, prepare, submit
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_execution_expiry import (
        CommittedExecutionExpiry,
        ExecutionExpiryClock,
        historical_execution_source,
    )
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.worker_http import ACCOUNT, REGION, assert_history

    engine, child_url = process_database
    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    source = historical_execution_source(engine)
    original = database_state(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        for name, value in {
            "REMEDIATION_ADMISSION_ENABLED": "true",
            "REMEDIATION_ACCOUNT_ID": ACCOUNT,
            "REMEDIATION_REGION": REGION,
            "REMEDIATION_VERIFICATION_ENABLED": "true",
            "REMEDIATION_VERIFICATION_ACCOUNT_ID": ACCOUNT,
            "REMEDIATION_VERIFICATION_REGION": REGION,
        }.items():
            monkeypatch.setenv(name, value)
        get_settings.cache_clear()
        parent = IntegratedCoordinator(
            offline_process_runtime,
            engine,
            child_url,
            source,
            instance=str(uuid4()),
            issuer=issuer.issuer,
            release_reader=lambda _scan: pytest.fail("No reader"),
            scenario="execution-expiry",
        )
        clock = ExecutionExpiryClock(issuer.issuer)
        gate = CommittedExecutionExpiry(
            engine, issuer=issuer.issuer, store=boundary.store, clock=clock
        )
        with clock.installed(), gate.installed():
            issuer.role, issuer.subject = "ANALYST", "proposer"
            status = sign_in(client, issuer)
            value = prepare(
                client,
                status,
                operation_document(
                    body={
                        "finding_id": str(source.finding_id),
                        "occurrence_id": str(source.occurrence_id),
                        "reason": "Historical facts remain valid before execution admission.",
                    }
                ),
            )
            proposal_id = submit(client, status, value).json()["result"]["result_id"]
            detail = "/dashboard/api/remediations/" + proposal_id
            proposal = client.get(detail).json()
            client.cookies.clear()
            issuer.role, issuer.subject = "APPROVER", "approver"
            status = sign_in(client, issuer)
            value = prepare(
                client,
                status,
                operation_document(
                    "DECIDE",
                    target=proposal_id,
                    body={
                        "proposal_sha256": proposal["proposal_sha256"],
                        "decision": "APPROVE",
                        "reason": "Independent review of historical facts.",
                    },
                ),
            )
            decision_id = submit(client, status, value).json()["result"]["result_id"]
            client.cookies.clear()
            issuer.role, issuer.subject = "ADMIN", "requester"
            status = sign_in(client, issuer)
            body = {
                "proposal_sha256": proposal["proposal_sha256"],
                "approval_decision_id": decision_id,
                "reason": "Expire this genuine grant before any installed worker is launched.",
            }
            prepared = prepare(
                client,
                status,
                operation_document("REQUEST_EXECUTION", target=proposal_id, body=body),
            )
            admitted = submit(client, status, prepared).json()
            assert admitted["state"] == "CONFIRMED" and admitted["attempts"] == 1
            gate.assert_complete()
            execution_id = UUID(admitted["result"]["result_id"])
            route = "/dashboard/api/remediation-executions/" + str(execution_id)
            initial = ExecutionView.model_validate(client.get(route).json())
            assert initial.phase.value == "QUEUED" and initial.reservation_held
            assert [r.value for r in initial.blocking_reasons] == ["EXECUTION_EXPIRED"]
            assert initial.validity_checked_at >= initial.content.expires_at
            assert initial.content.proposal.created_at <= initial.content.created_at
            before_worker = database_state(engine)
            assert client.get("/dashboard/session").json()["authenticated"] is True
            # Cached manual repeat returns the same reference, not a new forward or grant.
            assert submit(client, status, prepared).json() == admitted
            assert database_state(engine) == before_worker and executor.submissions == []
        # Clock patch is gone. The real installed entrypoint has no injected/frozen clock.
        scenario = {
            "argv": [str(execution_id)],
            "responses": [],
            "metadata": "valid",
            "target": {
                "execution_id": str(execution_id),
                "proposal_id": proposal_id,
                "resource_id": str(initial.content.proposal.resource_id),
                "finding_id": str(source.finding_id),
            },
        }
        for attempt in range(2):
            if attempt == 0:
                command = wire(parent, "RUN_WORKER", execution_id, initial.content.idempotency_key)
                reply = parent.handle(command)
                assert reply.state == "WORKER_NO_WRITE" and reply.effects_canceled is False
                assert parent.handle(command) == reply  # Replay cannot launch a second worker.
                report = parent.worker_report
            else:
                report = offline_process_runtime.run_worker(scenario, child_url)
            assert report["exit_code"] == 0 and report["stdout"] == "NO_WRITE\n"
            assert report["calls"] == report["wire_actions"] == report["lock_probes"] == []
            assert report["enable_invocations"] == report["intent_checks"] == 0
            current = ExecutionView.model_validate(client.get(route).json())
            assert current.phase.value == "NO_WRITE" and current.reservation_held is False
            assert [e.content.kind.value for e in current.events] == ["REQUESTED", "NO_WRITE"]
            assert [r.value for r in current.events[-1].content.blocking_reasons] == [
                "EXECUTION_EXPIRED"
            ]
            assert_history(engine, initial, current, SimpleNamespace(issuer=issuer.issuer))
            if attempt == 0:
                after_worker = database_state(engine)
            else:
                assert database_state(engine) == after_worker
        replay = client.post(
            "/api/v1/remediations/" + proposal_id + "/executions",
            json=body,
            headers=signed_headers(
                issuer, "requester", "ADMIN", key=UUID(prepared["operation_id"])
            ),
        )
        assert replay.status_code == 200
        assert ExecutionView.model_validate(replay.json()).content == initial.content
        denied = client.post(
            "/api/v1/remediation-executions/" + str(execution_id) + "/verifications",
            headers=signed_headers(issuer, "requester", "ADMIN", key=uuid4()),
            json={"reason": "A no-write expiry is never an acknowledged verifiable effect."},
        )
        assert denied.status_code == 409
        assert database_state(engine) == after_worker and executor.submissions == []
        changed = {
            "remediation_proposals",
            "remediation_decisions",
            "remediation_requests",
            "remediation_executions",
            "remediation_execution_events",
            "remediation_admission_guard",
            "remediation_target_reservations",
            "audit_events",
        }
        assert set(original) == set(after_worker)
        assert all(original[name] == after_worker[name] for name in original if name not in changed)
        assert after_worker["remediation_worker_claims"] == ()
        assert len(after_worker["remediation_execution_events"]) == 2
        with Session(engine) as session:
            assert (
                session.get(
                    ControlAssessment, initial.content.proposal.baseline.assessment_id
                ).assessment_result
                is AssessmentResult.FAIL
            )
            assert session.get(Finding, source.finding_id).status is FindingStatus.OPEN
        gate.assert_complete()
        assert_integrated_receipt(parent, after_worker, scenario="execution-expiry")
        before_proof = parent.expiry_before
        parent.expiry_before = {**before_proof, "findings": ()}
        with pytest.raises(ValueError, match="Invalid integrated expired-execution proof"):
            assert_integrated_receipt(parent, after_worker, scenario="execution-expiry")
        parent.expiry_before = before_proof
        calls = parent.worker_report["calls"]
        parent.worker_report["calls"] = ["metadata"]
        with pytest.raises(ValueError, match="Invalid integrated expired-execution proof"):
            assert_integrated_receipt(parent, after_worker, scenario="execution-expiry")
        parent.worker_report["calls"] = calls
        assert_integrated_receipt(parent, after_worker, scenario="execution-expiry")


def test_signed_viewer_denies_uncertain_retry_despite_cached_admin_and_retains_commit(
    process_database, monkeypatch, tmp_path
):
    from tests.api.test_dashboard_operations import (
        mutation_headers,
        operation_document,
        prepare,
        submit,
    )
    from tests.dashboard_fixtures import dashboard_client, sign_in
    from tests.dashboard_integrated_identity import CommittedProposalCapabilityLoss
    from tests.verification_acceptance import full_scope_source

    engine, _ = process_database
    source = full_scope_source(engine)
    with dashboard_client(engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role, issuer.subject = "ANALYST", "proposer"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(source.finding_id),
                    "occurrence_id": str(source.occurrence_id),
                    "reason": (
                        "Retain original committed authority when fresh signed capability is lost."
                    ),
                }
            ),
        )
        gate = CommittedProposalCapabilityLoss(engine, issuer=issuer, store=boundary.store)
        with gate.installed():
            first = submit(client, status, value)
            assert first.status_code == 200
            uncertain = first.json()
            assert uncertain["state"] == "UNCONFIRMED" and uncertain["attempts"] == 1
            assert uncertain["result"] is None
            cached = boundary.store.get(client.cookies.get("cloudsec_session"), touch=False)
            assert cached.principal.role_names == frozenset({"ADMIN"})
            assert client.get("/dashboard/session").json()["roles"] == ["VIEWER"]
            committed = database_state(engine)
            denied = submit(client, status, value)
            assert denied.status_code == 403
            assert denied.json() == {"detail": "Dashboard operation capability required"}
            assert (
                client.get("/dashboard/api/remediation-operations/" + value["operation_id"]).json()
                == uncertain
            )
            assert client.get("/dashboard/api/remediation-operations").json()["items"] == [
                uncertain
            ]
            replacement = client.post(
                "/dashboard/api/remediation-operations",
                headers=mutation_headers(status),
                json=operation_document(),
            )
            assert replacement.status_code == 403
            history = client.get("/dashboard/api/remediations").json()
            assert history["total"] == len(history["items"]) == 1
            assert history["items"][0]["content"]["proposer"]["roles"] == ["ANALYST"]
            assert database_state(engine) == committed and executor.submissions == []
            assert len(gate.requests) == 1
            gate.assert_complete()
