"""Closed faults cannot add public authority, rewrite old rows or replace global clocks."""

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from tests.dashboard_integrated_verification_faults import VerificationFault, fault_kind


@pytest.mark.parametrize("name", ["verification-equal", "verification-provenance"])
def test_two_explicit_faults(name):
    assert fault_kind(name) == name


@pytest.mark.parametrize(
    "name", [None, True, 1, {}, [], "", "equal", "verification-equal ", "verified"]
)
def test_no_arbitrary_fault(name):
    with pytest.raises(ValueError, match="Invalid integrated verification fault"):
        fault_kind(name)


@pytest.mark.parametrize("flag", [None, "true", "0"])
def test_explicit_isolation_required(monkeypatch, flag):
    monkeypatch.delenv("DASHBOARD_BROWSER_TEST", raising=False)
    if flag is not None:
        monkeypatch.setenv("DASHBOARD_BROWSER_TEST", flag)
    fault = VerificationFault(object(), object(), issuer="test", scenario="verification-equal")
    with pytest.raises(ValueError, match="explicit isolated mode"), fault.installed():
        pytest.fail("Fault installed outside explicit test mode")


def test_equal_clock_leaves_other_clocks_real_and_restores(monkeypatch):
    from app.services import inventory_service, remediation_service, scan_executor

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    fault = VerificationFault(object(), object(), issuer="test", scenario="verification-equal")
    at = datetime(2026, 10, 18, tzinfo=UTC)
    with fault.installed():
        assert inventory_service.datetime.now(UTC) > at
        fault.at = at
        assert inventory_service.datetime.now(UTC) == remediation_service.datetime.now(UTC) == at
        assert scan_executor.datetime is datetime
        assert datetime.now(UTC) > at
        with pytest.raises(ValueError, match="domain clock"):
            inventory_service.datetime.now()
        with pytest.raises(ValueError, match="explicit isolated mode"), fault.installed():
            pytest.fail("Nested installation allowed")
    assert inventory_service.datetime is remediation_service.datetime is datetime


@pytest.mark.parametrize("scenario", ["verification-equal", "verification-provenance"])
def test_missing_history_cannot_arm_clock_or_reader(scenario):
    fault = VerificationFault(object(), object(), issuer="test", scenario=scenario)
    with pytest.raises(ValueError, match="genuine queued admission"):
        fault._prove_ack(object())
    with pytest.raises(ValueError, match="reader binding"):
        fault.release(object())
    with pytest.raises(ValueError, match="Incomplete"):
        fault.assert_complete()
    assert fault.at is None and fault.insert_before is None


def test_incoming_fault_only_touches_one_new_artifact_on_owned_engine():
    from uuid import uuid4

    from app.models import EvidenceArtifact

    engine, scan = object(), uuid4()
    fault = VerificationFault(engine, object(), issuer="test", scenario="verification-provenance")
    fault.pending = SimpleNamespace(content=SimpleNamespace(scan_id=scan))
    fault._released = True
    row = EvidenceArtifact(
        scan_id=scan,
        schema_name="control.ec2-004.evidence",
        source_api="ec2:GetEbsEncryptionByDefault",
    )
    old = EvidenceArtifact(
        scan_id=uuid4(),
        schema_name="control.ec2-004.evidence",
        source_api="ec2:GetEbsEncryptionByDefault",
    )
    session = SimpleNamespace(bind=object(), new=[row, old])
    fault._observe_insert(session)
    assert fault.insert_before is None
    session.bind = engine
    session.new = [old]  # Accepted/dirty rows are deliberately not in session.new.
    fault._observe_insert(session)
    assert fault.insert_before is None
    session.new = [row, old]
    fault._observe_insert(session)
    assert row.source_api == "ec2:GetEbsDefaultKmsKeyId"
    assert old.source_api == "ec2:GetEbsEncryptionByDefault"
    assert {k for k in fault.insert_before if fault.insert_before[k] != fault.insert_after[k]} == {
        "source_api"
    }
    with pytest.raises(ValueError, match="Repeated or unbound"):
        fault._observe_insert(session)
