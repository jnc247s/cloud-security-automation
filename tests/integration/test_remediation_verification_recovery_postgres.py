"""Signed installed-worker verification across real admission/terminal SQL fault boundaries."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.main import create_app
from app.models import Finding, Resource, Scan
from app.models.enums import AuditEventType, FindingStatus, ScanStatus
from app.models.remediation_verification import (
    RemediationVerification,
    RemediationVerificationGuard,
)
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.verification_contracts import VerificationRequest, VerificationView
from app.schemas.resource import ResourceScope
from app.services import remediation_verification_service as implementation
from app.services.errors import RemediationError
from app.services.remediation_verification_service import RemediationVerificationService
from tests.integration.test_remediation_worker_process_postgres import (
    offline_process_runtime as offline_process_runtime,
)
from tests.integration.test_remediation_worker_process_postgres import (
    process_database as process_database,
)
from tests.remediation_fixtures import ADMIN, VIEWER
from tests.verification_acceptance import (
    ManagedReader,
    assert_receipt_storage,
    full_verification_journey,
    regional_reader,
    unchanged_history,
    wait_for_receipt,
)
from tests.worker_http import ACCOUNT, REGION, database_state, signed_headers
from tests.worker_process_http import script_for

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("committed", [False, True], ids=["before-commit", "lost-commit-response"])
def test_admission_commit_fault_and_fresh_application_recovery(
    offline_process_runtime, process_database, monkeypatch, tmp_path, committed
):
    engine, child_url = process_database
    reader = regional_reader(enabled=True)
    with full_verification_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path, reader=reader
    ) as journey:
        report = journey.run(script_for("acknowledged", None))
        assert report["exit_code"] == 0 and report["enable_invocations"] == 1
        worker = journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        body = {"reason": "Observe committed intent after a lost local commit response."}
        headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        route = journey.detail + "/verifications"
        original_commit, faults = Session.commit, []

        def uncertain_commit(session):
            target = any(isinstance(row, RemediationVerification) for row in session.new)
            if target:
                faults.append(committed)
                assert len(faults) == 1
                if committed:
                    original_commit(session)
                raise RuntimeError("synthetic admission commit response lost")
            return original_commit(session)

        with patch.object(Session, "commit", uncertain_commit):
            with pytest.raises(RuntimeError, match="synthetic admission commit response lost"):
                journey.client.post(route, json=body, headers=headers)
        assert faults == [committed]
        assert journey.executor.submissions == [] and not journey.executor.entered.is_set()
        assert reader.client_requests == []
        if not committed:
            assert database_state(engine) == before, "pre-commit admission leaked durable state"
            retry = journey.client.post(route, json=body, headers=headers)
            assert retry.status_code == 202, retry.text
            pending = VerificationView.model_validate(retry.json())
            assert journey.executor.entered.wait(15)
            journey.executor.release.set()
            complete = wait_for_receipt(journey, pending.content.verification_id)
            assert complete.receipt.outcome.value == "VERIFIED"
            assert_receipt_storage(engine, complete)
            unchanged_history(before, database_state(engine))
            return
        durable = database_state(engine)
        assert len(durable["scans"]) == len(before["scans"]) + 1
        assert len(durable["audit_events"]) == len(before["audit_events"]) + 2
        assert len(durable["remediation_verifications"]) == 1
        assert durable["remediation_verification_receipts"] == ()
        replay = journey.client.post(route, json=body, headers=headers)
        assert replay.status_code == 200, replay.text
        pending = VerificationView.model_validate(replay.json())
        assert pending.receipt is None and pending.content.attempt == 1
        assert database_state(engine) == durable and journey.executor.submissions == []
        read_headers = journey.reader
        old_executor = journey.executor
        source = journey.source
    assert old_executor._closed and old_executor.submissions == []
    recovered = ManagedReader(engine, source, reader)
    application = create_app(executor_factory=lambda: recovered, resume_pending_scans=True)
    with TestClient(application) as client:
        try:
            assert recovered.entered.wait(15), "fresh startup did not resume the durable scan"
            assert recovered.submissions == [pending.content.scan_id]
            current = client.get(
                "/api/v1/remediation-verifications/" + str(pending.content.verification_id),
                headers=read_headers,
            )
            assert current.status_code == 200 and current.json() == pending.model_dump(mode="json")
            recovered.release.set()
            complete = wait_for_receipt(
                SimpleNamespace(client=client, reader=read_headers), pending.content.verification_id
            )
            assert (
                complete.content == pending.content and complete.receipt.outcome.value == "VERIFIED"
            )
            assert_receipt_storage(engine, complete)
            final_replay = client.post(route, json=body, headers=headers)
            assert final_replay.status_code == 200
            assert final_replay.json() == complete.model_dump(mode="json")
            assert recovered.submissions == [pending.content.scan_id]
            unchanged_history(before, database_state(engine))
        finally:
            recovered.release.set()
    assert reader.client_requests and report["enable_invocations"] == 1
    assert (
        database_state(engine)["remediation_execution_events"]
        == durable["remediation_execution_events"]
    )
    assert worker.events[-1].content.phase is ExecutionPhase.ACKNOWLEDGED


@pytest.mark.parametrize("persistent", [False, True], ids=["one-shot", "persistent"])
def test_receipt_audit_fault_is_atomic_and_read_cannot_repair(
    offline_process_runtime, process_database, monkeypatch, tmp_path, persistent
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
        report = journey.run(script_for("acknowledged", None))
        assert report["exit_code"] == 0 and report["enable_invocations"] == 1
        worker = journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        body = {"reason": "Check atomic result/receipt rollback on a local audit fault."}
        route = journey.detail + "/verifications"
        accepted = journey.client.post(route, json=body, headers=headers)
        assert accepted.status_code == 202
        pending = VerificationView.model_validate(accepted.json())
        assert journey.executor.entered.wait(15)
        admitted = database_state(engine)
        audits, original_audit = [], implementation.append_audit_event

        def receipt_fault(session, kind, *args, **kwargs):
            if kind is AuditEventType.REMEDIATION_VERIFICATION_COMPLETED:
                audits.append(kind)
                assert database_state(engine) == admitted, "terminal SQL leaked before commit"
                if persistent or len(audits) == 1:
                    raise RuntimeError("synthetic terminal receipt audit fault")
            return original_audit(session, kind, *args, **kwargs)

        with patch.object(implementation, "append_audit_event", receipt_fault):
            journey.executor.release.set()
            journey.executor.shutdown(wait=True)
        assert len(audits) == 2, "real managed execution and failure sealing were not exercised"
        after = database_state(engine)
        unchanged_history(before, after)
        for name in (
            "resource_snapshots",
            "control_assessments",
            "evidence_artifacts",
            "finding_occurrences",
            "resources",
            "findings",
        ):
            assert after[name] == before[name], "failed complete result escaped rollback: " + name
        replay = journey.client.post(route, json=body, headers=headers)
        assert replay.status_code == 200, replay.text
        value = VerificationView.model_validate(replay.json())
        if persistent:
            assert value == pending and value.receipt is None
            assert after == admitted, "persistent receipt failure must remain conservative RUNNING"
            denied = journey.client.post(
                route,
                json=body,
                headers=signed_headers(journey.issuer, "verification-operator", "ADMIN"),
            )
            assert denied.status_code == 409
            assert denied.json()["detail"]["code"] == "remediation_verification_active"
        else:
            assert value.receipt.scan_status is ScanStatus.FAILED
            assert value.receipt.outcome.value == "INCONCLUSIVE"
            assert value.receipt.evidence is None and value.receipt.inventory_sha256 is None
            assert_receipt_storage(engine, value)
            assert len(after["audit_events"]) == len(admitted["audit_events"]) + 2
        assert database_state(engine) == after, "READ/replay repaired or otherwise changed history"
        assert journey.executor.submissions == [pending.content.scan_id]
        assert journey.view().events == worker.events


@pytest.mark.parametrize("same_key", [True, False], ids=["identical-replay", "distinct-requests"])
def test_signed_concurrent_admission_with_real_managed_scan(
    offline_process_runtime, process_database, monkeypatch, tmp_path, same_key
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
        report = journey.run(script_for("acknowledged", None))
        assert report["exit_code"] == 0 and report["enable_invocations"] == 1
        journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        body = {"reason": "Concurrent authorized observation cannot duplicate admission."}
        shared = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        barrier = Barrier(2)

        def request(_):
            headers = (
                shared
                if same_key
                else signed_headers(journey.issuer, "verification-operator", "ADMIN")
            )
            barrier.wait(timeout=15)
            return journey.client.post(
                journey.detail + "/verifications", json=body, headers=headers
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(request, range(2)))
        assert sorted(result.status_code for result in results) == (
            [200, 202] if same_key else [202, 409]
        ), [result.json() for result in results]
        accepted = next(result for result in results if result.status_code == 202)
        pending = VerificationView.model_validate(accepted.json())
        if same_key:
            assert all(result.json() == accepted.json() for result in results)
        else:
            denied = next(result for result in results if result.status_code == 409)
            assert denied.json()["detail"]["code"] == "remediation_verification_active"
        assert journey.executor.entered.wait(15)
        assert journey.executor.submissions == [pending.content.scan_id]
        admitted = database_state(engine)
        assert len(admitted["remediation_verifications"]) == 1
        assert len(admitted["scans"]) == len(before["scans"]) + 1
        assert len(admitted["audit_events"]) == len(before["audit_events"]) + 2
        journey.executor.release.set()
        complete = wait_for_receipt(journey, pending.content.verification_id)
        assert complete.receipt.outcome.value == "VERIFIED"
        assert_receipt_storage(engine, complete)
        unchanged_history(before, database_state(engine))


def test_independent_lock_probe_still_rejects_a_retained_guard_owner(
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
        report = journey.run(script_for("acknowledged", None))
        assert report["exit_code"] == 0 and report["enable_invocations"] == 1
        journey.check(ExecutionPhase.ACKNOWLEDGED)
        historical = database_state(engine)
        accepted = journey.client.post(
            journey.detail + "/verifications",
            json={"reason": "Prove the lock probe fails closed."},
            headers=signed_headers(journey.issuer, "verification-operator", "ADMIN"),
        )
        assert accepted.status_code == 202
        pending = VerificationView.model_validate(accepted.json())
        assert journey.executor.entered.wait(15)
        before = database_state(engine)
        with Session(engine) as owner, owner.begin():
            owner.execute(select(RemediationVerificationGuard).with_for_update()).scalar_one()
            with ThreadPoolExecutor(max_workers=1) as pool:
                blocked = pool.submit(
                    journey.executor.committed_boundary, pending.content.scan_id, "retained-owner"
                )
                with pytest.raises(OperationalError) as error:
                    blocked.result(timeout=6)
                assert error.value.orig.sqlstate == "55P03", "expected PostgreSQL lock timeout"
            assert owner.in_transaction()
        assert database_state(engine) == before
        assert not any(boundary[0] == "retained-owner" for boundary in journey.executor.boundaries)
        journey.executor.committed_boundary(pending.content.scan_id, "after-owner-release")
        journey.executor.release.set()
        complete = wait_for_receipt(journey, pending.content.verification_id)
        assert complete.receipt.outcome.value == "VERIFIED"
        assert_receipt_storage(engine, complete)
        assert journey.executor.submissions == [pending.content.scan_id]
        unchanged_history(historical, database_state(engine))


@pytest.mark.parametrize("terminal", ["completed", "failed"])
def test_signed_read_is_coherent_when_receipt_commits_after_scan_was_loaded(
    offline_process_runtime, process_database, monkeypatch, tmp_path, terminal
):
    engine, child_url = process_database
    reader = regional_reader(enabled=True)
    if terminal == "failed":
        reader.account_id = "999999999999"
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=reader,
    ) as journey:
        writer = journey.run(script_for("acknowledged", None))
        assert writer["exit_code"] == 0 and writer["enable_invocations"] == 1
        journey.check(ExecutionPhase.ACKNOWLEDGED)
        accepted = journey.client.post(
            journey.detail + "/verifications",
            json={"reason": "Observe atomic terminal history across the read boundary."},
            headers=signed_headers(journey.issuer, "verification-operator", "ADMIN"),
        )
        assert accepted.status_code == 202, accepted.text
        pending = VerificationView.model_validate(accepted.json())
        assert journey.executor.entered.wait(15)
        original = implementation.RemediationVerificationService._receipt
        interleavings = []

        def after_scan_loaded(service, row, content, proposal, scan):
            if row.verification_id == pending.content.verification_id and not interleavings:
                assert scan.status is ScanStatus.RUNNING
                interleavings.append(terminal)
                journey.executor.release.set()
                journey.executor.shutdown(wait=True)
                # The writer committed outside this request's clean READ transaction.
                assert scan.status is ScanStatus.RUNNING, "fixture did not retain the old ORM scan"
                with Session(engine) as witness:
                    assert witness.get(Scan, pending.content.scan_id).status is (
                        ScanStatus.COMPLETED if terminal == "completed" else ScanStatus.FAILED
                    )
            return original(service, row, content, proposal, scan)

        with patch.object(
            implementation.RemediationVerificationService, "_receipt", after_scan_loaded
        ):
            response = journey.client.get(
                "/api/v1/remediation-verifications/" + str(pending.content.verification_id),
                headers=journey.reader,
            )
        assert interleavings == [terminal]
        assert response.status_code == 200, response.text
        complete = VerificationView.model_validate(response.json())
        assert complete.content == pending.content
        assert complete.receipt.scan_status is (
            ScanStatus.COMPLETED if terminal == "completed" else ScanStatus.FAILED
        )
        assert complete.receipt.outcome.value == (
            "VERIFIED" if terminal == "completed" else "INCONCLUSIVE"
        )
        assert_receipt_storage(engine, complete)
        assert journey.executor.submissions == [pending.content.scan_id]


def test_verified_authority_read_preserves_all_caller_work_before_sql(
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
        report = journey.run(script_for("acknowledged", None))
        assert report["exit_code"] == 0 and report["enable_invocations"] == 1
        journey.check(ExecutionPhase.ACKNOWLEDGED)
        accepted = journey.client.post(
            journey.detail + "/verifications",
            json={"reason": "Inspect caller ownership safely."},
            headers=signed_headers(journey.issuer, "verification-operator", "ADMIN"),
        )
        assert accepted.status_code == 202
        pending = VerificationView.model_validate(accepted.json())
        assert journey.executor.entered.wait(15)
        before = database_state(engine)
        for change in ("insert", "update", "delete"):
            with Session(engine) as session:
                finding = session.get(Finding, journey.source.finding_id)
                if change == "insert":
                    resource = Resource(
                        resource_id=uuid4(),
                        provider="aws",
                        aws_account_id=ACCOUNT,
                        aws_resource_id="offline-unrelated-resource",
                        arn=None,
                        service="ec2",
                        resource_type="ec2_instance",
                        scope=ResourceScope.REGIONAL,
                        region=REGION,
                    )
                    session.add(resource)
                elif change == "update":
                    finding.status = FindingStatus.ACKNOWLEDGED
                else:
                    session.delete(finding)
                transaction = session.get_transaction()
                work = (set(session.new), set(session.dirty), set(session.deleted))
                statements = []

                def capture(_connection, _cursor, statement, *_args, observed=statements):
                    observed.append(statement)

                event.listen(engine, "before_cursor_execute", capture)
                try:
                    service = RemediationVerificationService(session)
                    for operation in (
                        lambda service=service: service.get_verification(
                            pending.content.verification_id, VIEWER
                        ),
                        lambda service=service: service.list_verifications(
                            VIEWER, execution_id=journey.execution_id
                        ),
                        lambda service=service: service.request_verification(
                            journey.execution_id,
                            VerificationRequest(reason="Caller owns transaction."),
                            ADMIN,
                            uuid4(),
                            journey.executor,
                        ),
                    ):
                        with pytest.raises(RemediationError) as error:
                            operation()
                        assert error.value.code == "remediation_state_conflict"
                        assert statements == [], "caller work was flushed or SQL was issued"
                        assert session.get_transaction() is transaction and transaction.is_active
                        assert work == (set(session.new), set(session.dirty), set(session.deleted))
                finally:
                    event.remove(engine, "before_cursor_execute", capture)
            assert database_state(engine) == before
        with Session(engine) as session:
            session.get(Finding, journey.source.finding_id)
            transaction = session.get_transaction()
            service = RemediationVerificationService(session)
            assert service.get_verification(pending.content.verification_id, VIEWER) == pending
            assert service.list_verifications(VIEWER).items == (pending,)
            assert session.get_transaction() is transaction and transaction.is_active
        assert database_state(engine) == before
        assert journey.executor.submissions == [pending.content.scan_id]
        journey.executor.release.set()
        complete = wait_for_receipt(journey, pending.content.verification_id)
        assert complete.receipt.outcome.value == "VERIFIED"
