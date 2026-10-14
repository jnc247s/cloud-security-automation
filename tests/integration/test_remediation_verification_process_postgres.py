"""Signed installed write worker -> separate reader-only installed API/scanner -> READ receipt."""

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.models import Finding, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.verification_contracts import VerificationView
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
)
from tests.verification_process_runtime import run_reader, sdk_responses
from tests.worker_http import database_state, signed_headers
from tests.worker_process_http import script_for

pytestmark = pytest.mark.integration


def reader_scenario(journey, *, mode="observe", enabled=True, identity_account="123456789012"):
    operator = signed_headers(journey.issuer, "verification-operator", "ADMIN", key=uuid4())
    return {
        "mode": mode,
        "execution_id": str(journey.execution_id),
        "verification_id": None,
        "operator": operator["Authorization"],
        "reader": journey.reader["Authorization"],
        "jwks": {"keys": [journey.issuer.jwk]},
        "body": {"reason": "Verify retained policy through the separate installed reader process."},
        "idempotency_key": operator["Idempotency-Key"],
        "responses": sdk_responses(
            regional_reader(enabled=enabled), identity_account=identity_account
        ),
    }


@pytest.mark.parametrize("enabled", [True, False], ids=["pass", "fail"])
def test_separate_installed_reader_authentication_sdk_and_receipt(
    offline_process_runtime, process_database, monkeypatch, tmp_path, enabled
):
    engine, child_url = process_database
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=regional_reader(enabled=enabled),
    ) as journey:
        writer = journey.run(script_for("acknowledged", None))
        assert writer["exit_code"] == 0 and writer["enable_invocations"] == 1
        worker = journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        report = run_reader(
            offline_process_runtime, child_url, reader_scenario(journey, enabled=enabled)
        )
        complete = VerificationView.model_validate(report["complete"])
        assert complete.receipt.outcome.value == ("VERIFIED" if enabled else "NOT_VERIFIED")
        assert complete.receipt.scan_status is ScanStatus.COMPLETED
        assert complete.receipt.evidence.technical_result.value == ("PASS" if enabled else "FAIL")
        assert report["calls"][0] == "sts:GetCallerIdentity"
        assert "ec2:GetEbsEncryptionByDefault" in report["calls"]
        assert "ec2:GetEbsDefaultKmsKeyId" in report["calls"]
        assert all(
            call.split(":")[1].startswith(("Get", "List", "Describe")) for call in report["calls"]
        )
        assert report["submissions"] == [str(complete.content.scan_id)]
        assert report["writer_constructions"] == 0 and journey.executor.submissions == []
        assert_receipt_storage(engine, complete)
        unchanged_history(before, database_state(engine))
        assert journey.view().events == worker.events
        with Session(engine) as session:
            assert session.get(Finding, journey.source.finding_id).status is (
                FindingStatus.RESOLVED if enabled else FindingStatus.OPEN
            )


def test_installed_reader_wrong_account_denies_facts_before_collection(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=regional_reader(),
    ) as journey:
        writer = journey.run(script_for("acknowledged", None))
        assert writer["exit_code"] == 0 and writer["enable_invocations"] == 1
        journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        report = run_reader(
            offline_process_runtime,
            child_url,
            reader_scenario(journey, identity_account="999999999999"),
        )
        complete = VerificationView.model_validate(report["complete"])
        assert report["calls"] == ["sts:GetCallerIdentity"]
        assert complete.receipt.scan_status is ScanStatus.FAILED
        assert complete.receipt.outcome.value == "INCONCLUSIVE"
        assert complete.receipt.inventory_sha256 is None and complete.receipt.evidence is None
        assert_receipt_storage(engine, complete)
        after = database_state(engine)
        unchanged_history(before, after)
        for name in (
            "findings",
            "resources",
            "resource_snapshots",
            "control_assessments",
            "evidence_artifacts",
        ):
            assert after[name] == before[name]


def test_installed_api_verification_is_default_off_without_worker_configuration(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=regional_reader(),
    ) as journey:
        writer = journey.run(script_for("acknowledged", None))
        assert writer["exit_code"] == 0 and writer["enable_invocations"] == 1
        journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        report = run_reader(
            offline_process_runtime, child_url, reader_scenario(journey, mode="default-off")
        )
        assert report["api_checks"]["default_off"] is True
        assert report["pending"] is report["complete"] is None
        assert report["calls"] == report["submissions"] == []
        assert "REMEDIATION_VERIFICATION_ENABLED" not in report["env_names"]
        assert database_state(engine) == before


@pytest.mark.parametrize("mode", ["crash", "crash-collection"])
def test_fresh_installed_reader_resumes_same_durable_id_after_process_interruption(
    offline_process_runtime, process_database, monkeypatch, tmp_path, mode
):
    engine, child_url = process_database
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=regional_reader(),
    ) as journey:
        writer = journey.run(script_for("acknowledged", None))
        assert writer["exit_code"] == 0 and writer["enable_invocations"] == 1
        worker = journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        scenario = reader_scenario(journey, mode=mode)
        first = run_reader(offline_process_runtime, child_url, scenario)
        pending = VerificationView.model_validate(first["pending"])
        assert first["exit_code"] == 90 and first["stage"] == (
            "crash-before-provider" if mode == "crash" else "crash-during-collection"
        )
        if mode == "crash-collection":
            assert len(first["calls"]) == 2 and first["calls"][0] == "sts:GetCallerIdentity"
            assert not first["calls"][1].startswith("sts:")
            assert first["metadata_requests"] == 1 and first["credential_methods"] == [
                "container-role",
                "container-role",
            ]
        else:
            assert first["calls"] == [] and first["metadata_requests"] == 0
        assert pending.receipt is None and pending.content.attempt == 1
        admitted = database_state(engine)
        assert len(admitted["scans"]) == len(before["scans"]) + 1
        assert len(admitted["audit_events"]) == len(before["audit_events"]) + 2
        assert admitted["remediation_verification_receipts"] == ()
        with Session(engine) as session:
            assert session.get(Scan, pending.content.scan_id).status is ScanStatus.RUNNING
        scenario.update(mode="resume", verification_id=str(pending.content.verification_id))
        second = run_reader(offline_process_runtime, child_url, scenario)
        complete = VerificationView.model_validate(second["complete"])
        assert complete.content == pending.content and complete.receipt.outcome.value == "VERIFIED"
        assert first["submissions"] == second["submissions"] == [str(pending.content.scan_id)]
        assert second["source_hashes"] == first["source_hashes"]
        assert_receipt_storage(engine, complete)
        unchanged_history(before, database_state(engine))
        assert journey.view().events == worker.events
        assert journey.executor.submissions == [] and writer["enable_invocations"] == 1
