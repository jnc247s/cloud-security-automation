"""Signed managed-reader fault/proof boundaries; no history guards are disabled."""

from collections import deque
from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.orm import Session, SessionTransaction

from app.database.integrity import canonical_json_sha256
from app.main import create_app
from app.models import ControlAssessment, EvidenceArtifact, Finding, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.models.remediation_verification import RemediationVerification
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.verification_contracts import VerificationView
from app.services.scan_executor import InProcessScanExecutor, ScanExecutorCapacityError
from tests.ec2_fixtures import ec2_client
from tests.integration.test_remediation_worker_process_postgres import (
    offline_process_runtime as offline_process_runtime,
)
from tests.integration.test_remediation_worker_process_postgres import (
    process_database as process_database,
)
from tests.verification_acceptance import (
    ManagedReader,
    assert_receipt_storage,
    full_verification_journey,
    regional_reader,
    unchanged_history,
    wait_for_receipt,
)
from tests.worker_http import REGION, database_state, signed_headers
from tests.worker_process_http import script_for

pytestmark = pytest.mark.integration
BODY = {"reason": "Observe exact retained state across a synthetic local fault."}


def admit(journey, headers=None):
    return journey.client.post(
        journey.detail + "/verifications",
        json=BODY,
        headers=headers or signed_headers(journey.issuer, "verification-operator", "ADMIN"),
    )


def acknowledged(journey):
    report = journey.run(script_for("acknowledged", None))
    assert report["exit_code"] == 0 and report["enable_invocations"] == 1
    return journey.check(ExecutionPhase.ACKNOWLEDGED)


@pytest.mark.parametrize("fault", ["closed", "capacity"])
def test_signed_submission_rejection_seals_original_ids_without_provider_or_requeue(
    offline_process_runtime, process_database, monkeypatch, tmp_path, fault
):
    engine, child_url = process_database
    reader = regional_reader(enabled=True)
    with full_verification_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path, reader=reader
    ) as journey:
        worker = acknowledged(journey)
        before = database_state(engine)
        headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        if fault == "closed":
            journey.executor.shutdown(wait=True)
            response = admit(journey, headers)
        else:
            # Inject only the capacity error at the accepted submission boundary. The
            # existing executor capacity tests separately exercise real bounded load.
            with patch.object(
                InProcessScanExecutor, "submit", side_effect=ScanExecutorCapacityError("local full")
            ):
                response = admit(journey, headers)
        assert response.status_code == 503, response.text
        assert response.headers["cache-control"] == "no-store"
        detail = response.json()["detail"]
        assert detail["code"] == "verification_submission_failed"
        complete = wait_for_receipt(journey, UUID(detail["verification_id"]))
        assert str(complete.content.scan_id) == detail["scan_id"]
        assert complete.receipt.scan_status is ScanStatus.FAILED
        assert complete.receipt.outcome.value == "INCONCLUSIVE"
        assert complete.receipt.evidence is None
        assert_receipt_storage(engine, complete)
        final = database_state(engine)
        replay = admit(journey, headers)
        assert replay.status_code == 200 and replay.json() == complete.model_dump(mode="json")
        assert database_state(engine) == final and len(journey.executor.submissions) == 1
        assert not journey.executor.entered.is_set() and reader.client_requests == []
        assert journey.view().events == worker.events
        unchanged_history(before, final)


@pytest.mark.parametrize("committed", [False, True], ids=["before-commit", "lost-commit-response"])
def test_managed_terminal_commit_fault_keeps_atomic_receipt_and_no_write_resend(
    offline_process_runtime, process_database, monkeypatch, tmp_path, committed
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
        worker = acknowledged(journey)
        before = database_state(engine)
        headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        response = admit(journey, headers)
        assert response.status_code == 202, response.text
        pending = VerificationView.model_validate(response.json())
        assert journey.executor.entered.wait(15)
        admitted = database_state(engine)
        original, faults = SessionTransaction.commit, []

        def terminal_commit(transaction, *args, **kwargs):
            # Flush uses internal child transactions too; only the root commits SQL.
            # SQLAlchemy's identity map holds weak references after persistence returns;
            # inspect actual SQL state inside the root transaction, not a cached object.
            scan = (
                transaction.session.get(Scan, pending.content.scan_id, populate_existing=True)
                if transaction.parent is None and not faults
                else None
            )
            if scan is not None and scan.status is ScanStatus.COMPLETED and not faults:
                faults.append(committed)
                assert database_state(engine) == admitted, "uncommitted terminal state leaked"
                if committed:
                    original(transaction, *args, **kwargs)
                    visible = database_state(engine)
                    assert len(visible["remediation_verification_receipts"]) == 1
                raise RuntimeError("synthetic terminal commit response lost")
            return original(transaction, *args, **kwargs)

        with patch.object(SessionTransaction, "commit", terminal_commit):
            journey.executor.release.set()
            journey.executor.shutdown(wait=True)
        assert faults == [committed], "real managed terminal transaction was not exercised"
        complete = wait_for_receipt(journey, pending.content.verification_id)
        assert complete.content == pending.content
        assert complete.receipt.scan_status is (
            ScanStatus.COMPLETED if committed else ScanStatus.FAILED
        )
        assert complete.receipt.outcome.value == ("VERIFIED" if committed else "INCONCLUSIVE")
        assert_receipt_storage(engine, complete)
        final = database_state(engine)
        old_audits = {row.event_id for row in admitted["audit_events"]}
        new_audits = [
            row.event_type.value for row in final["audit_events"] if row.event_id not in old_audits
        ]
        assert sorted(new_audits) == sorted(
            ["SCAN_COMPLETED", "REMEDIATION_VERIFICATION_COMPLETED", "FINDING_RESOLVED"]
            if committed
            else ["SCAN_FAILED", "REMEDIATION_VERIFICATION_COMPLETED"]
        )
        assert len(final["remediation_verification_receipts"]) == 1
        if not committed:
            for name in (
                "resource_snapshots",
                "control_assessments",
                "finding_occurrences",
                "findings",
            ):
                assert final[name] == before[name], name
        assert admit(journey, headers).json() == complete.model_dump(mode="json")
        assert database_state(engine) == final and journey.view().events == worker.events
        assert journey.executor.submissions == [pending.content.scan_id]
        unchanged_history(before, final)


@pytest.mark.parametrize("age", ["equal", "older"])
def test_signed_equal_or_older_collection_cannot_verify(
    offline_process_runtime, process_database, monkeypatch, tmp_path, age
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
        worker = acknowledged(journey)
        acknowledged_at = next(
            entry.content.created_at
            for entry in worker.events
            if entry.content.kind.value == "ACKNOWLEDGED"
        )
        before = database_state(engine)
        with (
            patch("app.services.remediation_service.datetime") as authority_clock,
            patch("app.services.inventory_service.datetime") as inventory_clock,
        ):
            authority_clock.now.return_value = acknowledged_at
            inventory_clock.now.return_value = acknowledged_at - timedelta(seconds=age == "older")
            response = admit(journey)
            assert response.status_code == 202, response.text
            pending = VerificationView.model_validate(response.json())
            assert pending.content.acknowledged_at == pending.content.created_at == acknowledged_at
            assert journey.executor.entered.wait(15)
            journey.executor.release.set()
            complete = wait_for_receipt(journey, pending.content.verification_id)
        assert complete.receipt.outcome.value == "INCONCLUSIVE"
        assert complete.receipt.reason.value == (
            "OBSERVATION_NOT_LATER" if age == "equal" else "SCAN_INCOMPLETE"
        )
        assert complete.receipt.scan_status is (
            ScanStatus.COMPLETED if age == "equal" else ScanStatus.FAILED
        )
        assert_receipt_storage(engine, complete)
        unchanged_history(before, database_state(engine))
        assert journey.view().events == worker.events


@pytest.mark.parametrize(
    "forgery", ["source", "rehashed-source", "time", "control", "target", "version"]
)
def test_incoming_forged_assessment_proof_never_seals_verified(
    offline_process_runtime, process_database, monkeypatch, tmp_path, forgery
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
        worker = acknowledged(journey)
        before = database_state(engine)
        response = admit(journey)
        assert response.status_code == 202, response.text
        pending = VerificationView.model_validate(response.json())
        assert journey.executor.entered.wait(15)
        injected = []

        def forge(session, *_):
            for row in session.new:
                if (
                    isinstance(row, EvidenceArtifact)
                    and row.scan_id == pending.content.scan_id
                    and row.schema_name == "control.ec2-004.evidence"
                ):
                    injected.append(forgery)
                    assert len(injected) == 1
                    # Model malicious incoming INSERT values, not an UPDATE to accepted
                    # history. Database FK/history guards and the real proof reader remain.
                    if forgery == "source":
                        row.source_api = "ec2:GetEbsDefaultKmsKeyId"
                    elif forgery == "rehashed-source":
                        row.payload = deepcopy(row.payload)
                        row.payload["source_proof"]["sources"][0]["source_outcome_id"] = str(
                            uuid4()
                        )
                        row.payload_sha256 = canonical_json_sha256(row.payload)
                    elif forgery == "time":
                        row.collected_at -= timedelta(seconds=1)
                    elif forgery == "control":
                        row.schema_name = "control.ec2-001.evidence"
                    elif forgery == "target":
                        row.resource_snapshot_id = worker.content.proposal.baseline.snapshot_id
                    else:
                        row.control_version_id = uuid4()

        event.listen(Session, "before_flush", forge)
        try:
            journey.executor.release.set()
            journey.executor.shutdown(wait=True)
        finally:
            event.remove(Session, "before_flush", forge)
        assert injected == [forgery]
        complete = wait_for_receipt(journey, pending.content.verification_id)
        assert (
            complete.receipt.outcome.value == "INCONCLUSIVE" and complete.receipt.evidence is None
        )
        assert complete.receipt.scan_status is (
            ScanStatus.FAILED if forgery in {"target", "version"} else ScanStatus.COMPLETED
        )
        assert_receipt_storage(engine, complete)
        final = database_state(engine)
        unchanged_history(before, final)
        assert journey.view().events == worker.events
        assert len(journey.executor.submissions) == 1


@pytest.mark.parametrize(
    "binding", ["catalog_sha256", "baseline_scan_id", "region", "acknowledgment_sha256"]
)
def test_rehashed_corrupt_intent_stays_running_and_read_replay_restart_cannot_repair(
    offline_process_runtime, process_database, monkeypatch, tmp_path, binding
):
    engine, child_url = process_database
    reader = regional_reader(enabled=True)
    with full_verification_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path, reader=reader
    ) as journey:
        worker = acknowledged(journey)
        before = database_state(engine)
        changed, retained = [], []

        def forge(session, *_):
            for row in session.new:
                if isinstance(row, RemediationVerification):
                    document = deepcopy(row.content)
                    document[binding] = (
                        str(uuid4())
                        if binding == "baseline_scan_id"
                        else "us-west-2"
                        if binding == "region"
                        else "0" * 64
                    )
                    row.content, row.content_sha256 = document, canonical_json_sha256(document)
                    changed.append(binding)
                    retained.append(
                        VerificationView(
                            content=document,
                            verification_sha256=row.content_sha256,
                            request_audit_event_id=row.audit_event_id,
                            receipt=None,
                            receipt_sha256=None,
                            receipt_audit_event_id=None,
                        )
                    )

        headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        event.listen(Session, "before_flush", forge)
        try:
            response = admit(journey, headers)
        finally:
            event.remove(Session, "before_flush", forge)
        assert changed == [binding]
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["code"] == "remediation_provenance_conflict"
        journey.executor.shutdown(wait=True)
        value = retained[0]
        conservative = database_state(engine)
        assert conservative["remediation_verification_receipts"] == ()
        with Session(engine) as session:
            assert session.get(Scan, value.content.scan_id).status is ScanStatus.RUNNING
        detail = "/api/v1/remediation-verifications/" + str(value.content.verification_id)
        for response in (
            journey.client.get(detail, headers=journey.reader),
            journey.client.get("/api/v1/remediation-verifications", headers=journey.reader),
            admit(journey, headers),
            admit(journey),
        ):
            assert response.status_code == 409
            assert response.json()["detail"]["code"] == "remediation_provenance_conflict"
        assert database_state(engine) == conservative and not journey.executor.entered.is_set()
        assert reader.client_requests == [] and journey.view().events == worker.events
        unchanged_history(before, conservative)
        source, read_headers = journey.source, journey.reader
    recovered = ManagedReader(engine, source, reader)
    with TestClient(
        create_app(executor_factory=lambda: recovered, resume_pending_scans=True)
    ) as client:
        recovered.shutdown(wait=True)
        assert recovered.submissions == [value.content.scan_id]
        assert not recovered.entered.is_set() and reader.client_requests == []
        assert client.get(detail, headers=read_headers).status_code == 409
        assert database_state(engine) == conservative, "startup fabricated a terminal failure"


def test_verification_is_separate_from_other_control_failure_and_mixed_historical_findings(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    readers = deque()
    for enabled in (False, True, False):
        reader = regional_reader(enabled=enabled)
        # Complete real inventory containing other EC2 FAILs in every attempt.
        ebs = ec2_client(default=enabled)
        reader._clients[("ec2", REGION)]._paginators.update(ebs._paginators)
        reader._clients[("ec2", REGION)]._responses.update(ebs._responses)
        readers.append(reader)
    with full_verification_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path, reader=readers.popleft
    ) as journey:
        worker = acknowledged(journey)
        before = database_state(engine)
        results = []
        for outcome, finding_status in (
            ("NOT_VERIFIED", FindingStatus.OPEN),
            ("VERIFIED", FindingStatus.RESOLVED),
            ("NOT_VERIFIED", FindingStatus.OPEN),
        ):
            response = admit(journey)
            assert response.status_code == 202, response.text
            pending = VerificationView.model_validate(response.json())
            assert journey.executor.entered.wait(15)
            journey.executor.release.set()
            complete = wait_for_receipt(journey, pending.content.verification_id)
            assert complete.receipt.outcome.value == outcome
            assert_receipt_storage(engine, complete)
            with Session(engine) as session:
                assert session.get(Finding, journey.source.finding_id).status is finding_status
                assessments = session.scalars(
                    select(ControlAssessment).where(
                        ControlAssessment.scan_id == complete.content.scan_id
                    )
                ).all()
                assert any(
                    assessment.resource_id != worker.content.proposal.resource_id
                    and assessment.assessment_result.value == "FAIL"
                    for assessment in assessments
                ), "other-control FAIL was absent from the complete scan"
            results.append(complete)
        for complete in results:
            response = journey.client.get(
                "/api/v1/remediation-verifications/" + str(complete.content.verification_id),
                headers=journey.reader,
            )
            assert response.status_code == 200 and response.json() == complete.model_dump(
                mode="json"
            )
        assert len(journey.executor.submissions) == 3 and journey.view().events == worker.events
        unchanged_history(before, database_state(engine))
