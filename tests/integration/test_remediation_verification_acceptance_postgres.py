"""Full signed/installed-write/managed-reader journey on self-owned PostgreSQL only."""

from collections import deque
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import ControlAssessment, Finding, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.verification_contracts import VerificationView
from tests.fakes import client_error
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
from tests.worker_http import ACCOUNT, REGION, database_state, signed_headers
from tests.worker_process_http import script_for

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("enabled", [True, False], ids=["pass", "fail"])
@pytest.mark.parametrize(
    "key",
    [None, f"arn:aws:kms:{REGION}:{ACCOUNT}:key/reviewed-key"],
    ids=["absent-kms", "present-kms"],
)
def test_signed_installed_write_then_managed_verification(
    offline_process_runtime, process_database, monkeypatch, tmp_path, enabled, key
):
    engine, child_url = process_database
    reader = regional_reader(enabled=enabled, key=key)
    with full_verification_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path, key=key, reader=reader
    ) as journey:
        report = journey.run(script_for("acknowledged", key))
        assert report["exit_code"] == 0 and report["stdout"] == "ACKNOWLEDGED_UNVERIFIED\n"
        assert report["enable_invocations"] == report["intent_checks"] == 1
        worker = journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        route = journey.detail + "/verifications"
        key_id = uuid4()
        operator = signed_headers(journey.issuer, "verification-operator", "ADMIN", key=key_id)
        body = {
            "reason": "Verify the exact retained policy after installed offline acknowledgment."
        }
        assert journey.client.post(route, json=body).status_code == 401
        assert journey.client.post(route, json=body, headers=journey.reader).status_code == 403
        assert database_state(engine) == before and journey.executor.submissions == []
        created = journey.client.post(route, json=body, headers=operator)
        assert created.status_code == 202, created.text
        assert created.headers["cache-control"] == "no-store"
        pending = VerificationView.model_validate(created.json())
        assert pending.receipt is None and pending.content.attempt == 1
        assert journey.executor.entered.wait(15), "real managed provider was not constructed"
        assert journey.executor.submissions == [pending.content.scan_id]
        assert journey.executor.boundaries == [
            ("submit", pending.content.scan_id, pending.content.verification_id),
            ("provider", pending.content.scan_id, pending.content.verification_id),
        ]
        assert pending.content.requested_by.model_dump(mode="json") == {
            "issuer": journey.issuer.issuer,
            "subject": "verification-operator",
            "roles": ["ADMIN"],
            "capability": "EXECUTE",
        }
        assert pending.content.baseline_scan_id == worker.content.proposal.baseline.scan_id
        assert pending.content.profile_version == "6.3.0"
        assert pending.content.catalog_version == "0.5.0"
        assert journey.client.post(route, json=body, headers=operator).json() == created.json()
        conflict = journey.client.post(route, json={"reason": "Changed intent."}, headers=operator)
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["code"] == "remediation_idempotency_conflict"
        assert (
            journey.client.post(
                route,
                json=body,
                headers=signed_headers(
                    journey.issuer, "verification-operator", "VIEWER", key=key_id
                ),
            ).status_code
            == 403
        )
        journey.executor.release.set()
        complete = wait_for_receipt(journey, pending.content.verification_id)
        assert (
            complete.content == pending.content
            and complete.verification_sha256 == pending.verification_sha256
        )
        assert complete.receipt.outcome.value == ("VERIFIED" if enabled else "NOT_VERIFIED")
        assert complete.receipt.evidence.technical_result.value == ("PASS" if enabled else "FAIL")
        assert complete.receipt.scan_status is ScanStatus.COMPLETED
        assert complete.receipt.evidence.observed_at > pending.content.acknowledged_at
        assert_receipt_storage(engine, complete)
        assert journey.client.post(
            route, json=body, headers=operator
        ).json() == complete.model_dump(mode="json")
        page = journey.client.get(
            "/api/v1/remediation-verifications",
            headers=journey.reader,
            params={"execution_id": str(journey.execution_id), "limit": 1},
        )
        assert page.status_code == 200
        assert page.json()["total"] == 1 and page.json()["items"] == [
            complete.model_dump(mode="json")
        ]
        after = database_state(engine)
        unchanged_history(before, after)
        assert len(after["scans"]) == len(before["scans"]) + 1
        assert (
            len(after["remediation_verifications"])
            == len(after["remediation_verification_receipts"])
            == 1
        )
        assert journey.view().phase is ExecutionPhase.ACKNOWLEDGED
        assert journey.view().events == worker.events
        with Session(engine) as session:
            finding = session.get(Finding, journey.source.finding_id)
            assert finding.status is (FindingStatus.RESOLVED if enabled else FindingStatus.OPEN)
            assert session.get(Scan, pending.content.scan_id).status is ScanStatus.COMPLETED
        calls = [
            call.operation_name for client in reader._clients.values() for call in client.calls
        ]
        assert "get_ebs_encryption_by_default" in calls and "get_ebs_default_kms_key_id" in calls
        assert all(call.startswith(("get_", "list_", "describe_")) for call in calls)
        assert len(journey.executor.submissions) == 1


@pytest.mark.parametrize(
    "case,baseline_key,observed_key,status,reason,technical",
    [
        (
            "changed-key",
            "reviewed-key",
            "different-key",
            ScanStatus.COMPLETED,
            "KMS_CONTEXT_CHANGED",
            "PASS",
        ),
        ("missing-key", "reviewed-key", None, ScanStatus.COMPLETED, "KMS_CONTEXT_CHANGED", "PASS"),
        ("unexpected-key", None, "new-key", ScanStatus.COMPLETED, "KMS_CONTEXT_CHANGED", "PASS"),
        ("kms-denied", None, None, ScanStatus.PARTIAL, "SCAN_INCOMPLETE", None),
        ("encryption-denied", None, None, ScanStatus.PARTIAL, "SCAN_INCOMPLETE", None),
        ("nondecisive", None, None, ScanStatus.PARTIAL, "SCAN_INCOMPLETE", None),
        ("wrong-account", None, None, ScanStatus.FAILED, "SCAN_INCOMPLETE", None),
        ("wrong-region", None, None, ScanStatus.FAILED, "SCAN_INCOMPLETE", None),
        ("provider-failed", None, None, ScanStatus.FAILED, "SCAN_INCOMPLETE", None),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_installed_write_then_inconclusive_managed_scan(
    offline_process_runtime,
    process_database,
    monkeypatch,
    tmp_path,
    case,
    baseline_key,
    observed_key,
    status,
    reason,
    technical,
):
    engine, child_url = process_database
    reader = regional_reader(enabled=True, key=observed_key)
    if case == "kms-denied":
        reader._clients[("ec2", REGION)]._responses["get_ebs_default_kms_key_id"] = deque(
            [client_error("AccessDenied", "GetEbsDefaultKmsKeyId")]
        )
    if case in {"encryption-denied", "nondecisive"}:
        reader._clients[("ec2", REGION)]._responses["get_ebs_encryption_by_default"] = deque(
            [
                client_error("AccessDenied", "GetEbsEncryptionByDefault")
                if case == "encryption-denied"
                else {"EbsEncryptionByDefault": "true"}
            ]
        )
    if case == "wrong-account":
        reader.account_id = "999999999999"
    if case == "wrong-region":
        reader.region_name = "us-west-2"
    if case == "provider-failed":
        reader = client_error("AccessDenied", "GetCallerIdentity")
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        key=baseline_key,
        reader=reader,
    ) as journey:
        report = journey.run(script_for("acknowledged", baseline_key))
        assert report["exit_code"] == 0 and report["enable_invocations"] == 1
        worker = journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        body = {"reason": "Check incomplete or changed state without inferring write success."}
        created = journey.client.post(journey.detail + "/verifications", json=body, headers=headers)
        assert created.status_code == 202, created.text
        pending = VerificationView.model_validate(created.json())
        assert journey.executor.entered.wait(15)
        assert pending.receipt is None
        journey.executor.release.set()
        complete = wait_for_receipt(journey, pending.content.verification_id)
        assert complete.receipt.outcome.value == "INCONCLUSIVE"
        assert complete.receipt.scan_status is status and complete.receipt.reason.value == reason
        if technical is None:
            assert complete.receipt.evidence is None
        else:
            assert complete.receipt.evidence.technical_result.value == technical
        assert_receipt_storage(engine, complete)
        assert journey.client.post(
            journey.detail + "/verifications", json=body, headers=headers
        ).json() == complete.model_dump(mode="json")
        assert len(journey.executor.submissions) == 1
        unchanged_history(before, database_state(engine))
        assert journey.view().events == worker.events
        with Session(engine) as session:
            assert session.get(Scan, pending.content.scan_id).status is status
            assert session.get(Finding, journey.source.finding_id).status is (
                FindingStatus.RESOLVED if status is ScanStatus.COMPLETED else FindingStatus.OPEN
            )
            if case == "kms-denied":
                assessment = session.scalar(
                    select(ControlAssessment).where(
                        ControlAssessment.scan_id == pending.content.scan_id,
                        ControlAssessment.control_id == worker.content.proposal.control_id,
                        ControlAssessment.resource_id == worker.content.proposal.resource_id,
                    )
                )
                assert assessment.assessment_result.value == "PASS"
        if case in {"wrong-account", "wrong-region"}:
            assert reader.client_requests == [], "identity denial collected unrelated facts"


def test_signed_active_bound_disabled_replay_and_three_explicit_attempts(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    readers = []

    def fresh_reader():
        readers.append(regional_reader(enabled=False))
        return readers[-1]

    with full_verification_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path, reader=fresh_reader
    ) as journey:
        report = journey.run(script_for("acknowledged", None))
        assert report["exit_code"] == 0 and report["enable_invocations"] == 1
        worker = journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        route = journey.detail + "/verifications"
        body = {"reason": "Explicit bounded attempt under unchanged retained policy."}
        values, headers_by_attempt = [], []
        for ordinal in range(1, 4):
            headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
            headers_by_attempt.append(headers)
            accepted = journey.client.post(route, json=body, headers=headers)
            assert accepted.status_code == 202, accepted.text
            pending = VerificationView.model_validate(accepted.json())
            assert pending.content.attempt == ordinal and pending.receipt is None
            assert journey.executor.entered.wait(15)
            active_before = database_state(engine)
            active = journey.client.post(
                route,
                json=body,
                headers=signed_headers(journey.issuer, "another-executor", "ADMIN"),
            )
            assert active.status_code == 409
            assert active.json()["detail"]["code"] == "remediation_verification_active"
            assert database_state(engine) == active_before
            assert len(journey.executor.submissions) == ordinal and len(readers) == ordinal - 1
            if ordinal == 1:
                monkeypatch.setenv("REMEDIATION_VERIFICATION_ENABLED", "false")
                get_settings.cache_clear()
                executor = journey.client.app.state.scan_executor
                journey.client.app.state.scan_executor = None
                try:
                    replay = journey.client.post(route, json=body, headers=headers)
                    assert replay.status_code == 200 and replay.json() == accepted.json()
                    disabled = journey.client.post(
                        route,
                        json=body,
                        headers=signed_headers(journey.issuer, "verification-operator", "ADMIN"),
                    )
                    assert disabled.status_code == 503
                    assert disabled.json()["detail"]["code"] == "remediation_verification_disabled"
                    assert database_state(engine) == active_before
                finally:
                    journey.client.app.state.scan_executor = executor
                    monkeypatch.setenv("REMEDIATION_VERIFICATION_ENABLED", "true")
                    get_settings.cache_clear()
            journey.executor.release.set()
            complete = wait_for_receipt(journey, pending.content.verification_id)
            assert complete.receipt.outcome.value == "NOT_VERIFIED"
            assert_receipt_storage(engine, complete)
            values.append(complete)
        exhausted_before = database_state(engine)
        exhausted = journey.client.post(
            route,
            json=body,
            headers=signed_headers(journey.issuer, "verification-operator", "ADMIN"),
        )
        assert exhausted.status_code == 409
        assert exhausted.json()["detail"]["code"] == "remediation_verification_limit"
        assert database_state(engine) == exhausted_before
        for value, headers in zip(values, headers_by_attempt, strict=True):
            replay = journey.client.post(route, json=body, headers=headers)
            assert replay.status_code == 200 and replay.json() == value.model_dump(mode="json")
        assert len(readers) == len(journey.executor.submissions) == 3
        assert len({value.content.scan_id for value in values}) == 3
        assert len({value.content.verification_id for value in values}) == 3
        assert journey.view().events == worker.events
        unchanged_history(before, database_state(engine))
