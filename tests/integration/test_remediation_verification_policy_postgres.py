"""Retained complete-scope generations survive genuine deployment-policy roll-forward."""

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.main import create_app
from app.models import Control, ControlAssessment, Finding, Scan
from app.models.enums import FindingStatus, ScanStatus
from app.models.profile import AssessmentPolicyArtifact, PersistedAssessmentProfile
from app.models.remediation_verification import RemediationVerification
from app.remediation.execution_contracts import ExecutionPhase
from app.remediation.verification_contracts import VerificationView
from tests.ec2_fixtures import ec2_profile
from tests.foundation_fixtures import extended_profile
from tests.integration.test_remediation_worker_process_postgres import (
    offline_process_runtime as offline_process_runtime,
)
from tests.integration.test_remediation_worker_process_postgres import (
    process_database as process_database,
)
from tests.s3_exposure_fixtures import exposure_profile
from tests.s3_sensitive_kms_fixtures import sensitive_kms_profile
from tests.verification_acceptance import (
    ManagedReader,
    assert_receipt_storage,
    full_verification_journey,
    regional_reader,
    unchanged_history,
    wait_for_receipt,
)
from tests.worker_http import database_state, signed_headers
from tests.worker_process_http import script_for

pytestmark = pytest.mark.integration

RESOURCE_TYPES = {
    "access_analyzer_finding",
    "aws_account",
    "cloudtrail_trail",
    "ebs_volume",
    "ec2_instance",
    "iam_access_key",
    "iam_aws_managed_policy",
    "iam_customer_managed_policy",
    "iam_group",
    "iam_inline_policy",
    "iam_managed_policy_version",
    "iam_mfa_device",
    "iam_role",
    "iam_user",
    "kms_key",
    "s3_bucket",
    "security_group",
    "subnet",
    "vpc",
    "vpc_flow_log",
}

# Independent expectations, not assertions derived from the production scope selector.
SCOPES = (
    (
        "current",
        ("access-analyzer", "cloudtrail", "cloudtrail-evidence", "ec2", "iam", "kms", "s3"),
        (
            "access_analyzer_evidence",
            "cloudtrail_evidence",
            "cloudtrail_trails",
            "ec2_ebs_evidence",
            "iam_account_evidence",
            "iam_users",
            "s3_buckets",
            "s3_evidence",
            "security_groups",
            "vpc_network_evidence",
        ),
    ),
    (
        "pre-5f",
        ("access-analyzer", "cloudtrail", "ec2", "iam", "kms", "s3"),
        (
            "access_analyzer_evidence",
            "cloudtrail_trails",
            "ec2_ebs_evidence",
            "iam_account_evidence",
            "iam_users",
            "s3_buckets",
            "s3_evidence",
            "security_groups",
            "vpc_network_evidence",
        ),
    ),
    (
        "pre-5e",
        ("access-analyzer", "cloudtrail", "ec2", "iam", "s3"),
        (
            "access_analyzer_evidence",
            "cloudtrail_trails",
            "ec2_ebs_evidence",
            "iam_account_evidence",
            "iam_users",
            "s3_buckets",
            "security_groups",
            "vpc_network_evidence",
        ),
    ),
    (
        "pre-5d",
        ("cloudtrail", "ec2", "iam", "s3"),
        (
            "cloudtrail_trails",
            "ec2_ebs_evidence",
            "iam_account_evidence",
            "iam_users",
            "s3_buckets",
            "security_groups",
            "vpc_network_evidence",
        ),
    ),
)


def artifact_profile():
    return ec2_profile(
        s3_exposure_approvals=exposure_profile().s3_exposure_approvals,
        sensitive_bucket_classifier=sensitive_kms_profile().sensitive_bucket_classifier,
    )


def rolled_forward_policy(tmp_path, monkeypatch):
    from app.assessment.sensitive_buckets import SensitiveBucketClassifier, SensitiveBucketTagRule

    latest = extended_profile(
        version="8.2.0",
        enabled_controls=("GOV-001",),
        required_tags=("NewOwner",),
        governed_resource_types=("ec2_instance",),
        s3_exposure_approvals=exposure_profile(policy_version="2.0.0").s3_exposure_approvals,
        sensitive_bucket_classifier=SensitiveBucketClassifier.create(
            version="2.0.0",
            sensitive_tag_rules=(SensitiveBucketTagRule(key="NewClass", value="Restricted"),),
        ),
    )
    path = tmp_path / "rolled-forward-policy.json"
    path.write_text(
        json.dumps(
            {
                "catalog_id": "aws-cloud-security-controls",
                "catalog_version": "0.13.0",
                "profile": latest.model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASSESSMENT_PROFILE_FILE", str(path))
    monkeypatch.setenv("ASSESSMENT_PROFILE_VERSION", latest.version)
    get_settings.cache_clear()
    selected = get_settings().assessment_policy
    assert selected.profile == latest and selected.catalog.version == "0.13.0"
    return latest


def policy_journey(
    offline_process_runtime,
    process_database,
    monkeypatch,
    tmp_path,
    generation,
    services,
    collectors,
    enabled,
    mode="manual",
):
    engine, child_url = process_database
    original_policy = artifact_profile()
    reader = regional_reader(enabled=enabled)
    with full_verification_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        reader=reader,
        policy=original_policy,
        requested_services=services,
    ) as journey:
        report = journey.run(script_for("acknowledged", None))
        assert report["exit_code"] == 0 and report["enable_invocations"] == 1
        worker = journey.check(ExecutionPhase.ACKNOWLEDGED)
        before = database_state(engine)
        headers = signed_headers(journey.issuer, "verification-operator", "ADMIN")
        body = {"reason": "Observe original policy and complete retained collector generation."}
        if mode != "manual":
            original_commit, faults = Session.commit, []

            def lost_commit_response(session):
                linked = any(isinstance(row, RemediationVerification) for row in session.new)
                original_commit(session)
                if linked:
                    faults.append(1)
                    raise RuntimeError("synthetic policy admission commit response lost")

            with patch.object(Session, "commit", lost_commit_response):
                with pytest.raises(
                    RuntimeError, match="synthetic policy admission commit response lost"
                ):
                    journey.client.post(
                        journey.detail + "/verifications", json=body, headers=headers
                    )
            assert faults == [1] and journey.executor.submissions == []
            replay = journey.client.post(
                journey.detail + "/verifications", json=body, headers=headers
            )
            assert replay.status_code == 200, replay.text
            pending = VerificationView.model_validate(replay.json())
            assert pending.receipt is None
            admitted = database_state(engine)
            assert len(admitted["scans"]) == len(before["scans"]) + 1
            assert len(admitted["audit_events"]) == len(before["audit_events"]) + 2
    latest = rolled_forward_policy(tmp_path, monkeypatch)
    assert latest.content_checksum != original_policy.content_checksum
    assert (
        latest.s3_exposure_approvals.content_checksum
        != original_policy.s3_exposure_approvals.content_checksum
    )
    assert (
        latest.sensitive_bucket_classifier.content_checksum
        != original_policy.sensitive_bucket_classifier.content_checksum
    )
    if mode == "disabled":
        monkeypatch.setenv("REMEDIATION_VERIFICATION_ENABLED", "false")
    elif mode == "wrong-account":
        monkeypatch.setenv("REMEDIATION_VERIFICATION_ACCOUNT_ID", "999999999999")
    elif mode == "wrong-region":
        monkeypatch.setenv("REMEDIATION_VERIFICATION_REGION", "us-west-2")
    get_settings.cache_clear()
    catalog_requests = []
    if mode == "unsupported-catalog":
        from app.services import scan_executor as execution

        original_resolver = execution.resolve_catalog

        def unsupported_retained_release(catalog_id, version):
            catalog_requests.append((catalog_id, version))
            if version == "0.5.0":
                raise ValueError("synthetic deployment no longer supports retained catalog")
            return original_resolver(catalog_id, version)

        monkeypatch.setattr(execution, "resolve_catalog", unsupported_retained_release)
    managed = ManagedReader(engine, journey.source, reader)
    application = create_app(executor_factory=lambda: managed, resume_pending_scans=True)
    with TestClient(application) as client:
        journey.client = client
        try:
            if mode == "manual":
                assert managed.submissions == [] and not reader.client_requests
                response = client.post(
                    journey.detail + "/verifications", json=body, headers=headers
                )
                assert response.status_code == 202, response.text
                pending = VerificationView.model_validate(response.json())
            if mode in {"disabled", "wrong-account", "wrong-region", "unsupported-catalog"}:
                complete = wait_for_receipt(journey, pending.content.verification_id)
                assert complete.content == pending.content
                assert complete.receipt.scan_status is ScanStatus.FAILED
                assert complete.receipt.outcome.value == "INCONCLUSIVE"
                assert (
                    complete.receipt.inventory_sha256 is None and complete.receipt.evidence is None
                )
                assert not managed.entered.is_set() and reader.client_requests == []
                assert managed.submissions == [pending.content.scan_id]
                assert_receipt_storage(engine, complete)
                assert client.post(
                    journey.detail + "/verifications", json=body, headers=headers
                ).json() == complete.model_dump(mode="json")
                after = database_state(engine)
                unchanged_history(before, after)
                for name in (
                    "resource_snapshots",
                    "control_assessments",
                    "evidence_artifacts",
                    "findings",
                    "resources",
                ):
                    assert after[name] == before[name]
                assert journey.view().events == worker.events
                if mode == "unsupported-catalog":
                    assert catalog_requests == [("aws-cloud-security-controls", "0.5.0")]
                return
            assert managed.entered.wait(15)
            assert pending.receipt is None and pending.content.attempt == 1
            assert pending.content.requested_services == services
            assert pending.content.requested_collectors == collectors
            expected_types = RESOURCE_TYPES - (
                {"kms_key", "access_analyzer_finding"}
                if generation == "pre-5d"
                else {"kms_key"}
                if generation == "pre-5e"
                else set()
            )
            assert set(pending.content.resource_types) == expected_types
            assert pending.content.profile_version == original_policy.version == "6.3.0"
            assert pending.content.profile_sha256 == original_policy.content_checksum
            assert pending.content.catalog_version == "0.5.0"
            assert pending.content.baseline_scan_id == worker.content.proposal.baseline.scan_id
            managed.release.set()
            complete = wait_for_receipt(journey, pending.content.verification_id)
            assert complete.receipt.outcome.value == ("VERIFIED" if enabled else "NOT_VERIFIED")
            assert complete.receipt.scan_status is ScanStatus.COMPLETED
            assert complete.receipt.evidence.technical_result.value == (
                "PASS" if enabled else "FAIL"
            )
            assert_receipt_storage(engine, complete)
            after = database_state(engine)
            unchanged_history(before, after)
            assert after["assessment_profiles"] == before["assessment_profiles"]
            assert after["assessment_policy_artifacts"] == before["assessment_policy_artifacts"]
            assert len(after["assessment_policy_artifacts"]) == 2
            assert managed.submissions == [pending.content.scan_id]
            assert journey.view().events == worker.events
            assert client.post(
                journey.detail + "/verifications", json=body, headers=headers
            ).json() == complete.model_dump(mode="json")
            with Session(engine) as session:
                scan = session.get(Scan, pending.content.scan_id)
                scope = scan.scope_manifest
                assert tuple(scan.requested_services) == tuple(scope.requested_services) == services
                assert tuple(scope.requested_collectors) == collectors
                assert scope.collector_outcomes == dict.fromkeys(collectors, "SUCCEEDED")
                assert set(scope.resource_types) == expected_types
                assert set(scope.enabled_controls) == set(original_policy.enabled_controls)
                profiles = session.scalars(select(PersistedAssessmentProfile)).all()
                assert len(profiles) == 1 and profiles[0].version == "6.3.0"
                assert {
                    item.version for item in session.scalars(select(AssessmentPolicyArtifact))
                } == {"1.0.0"}
                controls = session.scalars(
                    select(Control.control_key)
                    .join(ControlAssessment, Control.control_id == ControlAssessment.control_id)
                    .where(ControlAssessment.scan_id == pending.content.scan_id)
                ).all()
                assert "EC2-004" in controls and "GOV-001" not in controls
                assert session.get(Finding, journey.source.finding_id).status is (
                    FindingStatus.RESOLVED if enabled else FindingStatus.OPEN
                )
            called_services = {service for service, _ in reader.client_requests}
            assert ("accessanalyzer" in called_services) == (generation != "pre-5d")
        finally:
            managed.release.set()


@pytest.mark.parametrize("generation,services,collectors", SCOPES, ids=[case[0] for case in SCOPES])
@pytest.mark.parametrize("enabled", [True, False], ids=["pass", "fail"])
def test_signed_historical_scope_uses_exact_policy_after_deployment_change(
    offline_process_runtime,
    process_database,
    monkeypatch,
    tmp_path,
    generation,
    services,
    collectors,
    enabled,
):
    policy_journey(
        offline_process_runtime,
        process_database,
        monkeypatch,
        tmp_path,
        generation,
        services,
        collectors,
        enabled,
    )


@pytest.mark.parametrize("generation,services,collectors", SCOPES, ids=[case[0] for case in SCOPES])
def test_all_historical_scopes_resume_same_id_after_deployment_change(
    offline_process_runtime,
    process_database,
    monkeypatch,
    tmp_path,
    generation,
    services,
    collectors,
):
    policy_journey(
        offline_process_runtime,
        process_database,
        monkeypatch,
        tmp_path,
        generation,
        services,
        collectors,
        True,
        mode="restart",
    )


@pytest.mark.parametrize(
    "mode", ["disabled", "wrong-account", "wrong-region", "unsupported-catalog"]
)
def test_restart_denies_collection_without_scope_or_retained_catalog_support(
    offline_process_runtime,
    process_database,
    monkeypatch,
    tmp_path,
    mode,
):
    generation, services, collectors = SCOPES[0]
    policy_journey(
        offline_process_runtime,
        process_database,
        monkeypatch,
        tmp_path,
        generation,
        services,
        collectors,
        True,
        mode=mode,
    )
