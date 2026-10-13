"""Read-only EC2-004 postcondition proof; does not alter the FAIL-only baseline validator."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.identities import (
    control_assessment_id,
    resource_snapshot_id,
    stable_resource_id,
)
from app.assessment.models import AssessmentResult
from app.assessment.models import EvidenceArtifact as DomainEvidence
from app.assessment.source_outcomes import AccountEvidenceSubject, EvidenceSourceState
from app.database.evidence_graph import load_evidence_graph
from app.database.integrity import canonical_json_sha256
from app.models import (
    ControlAssessment,
    ControlVersion,
    EvidenceArtifact,
    PersistedAssessmentProfile,
    Resource,
    ResourceSnapshot,
    Scan,
    ScanScopeManifest,
)
from app.models.enums import ScanStatus
from app.remediation.contracts import AssessmentEvidenceBinding, ProposalContent, SourceBinding
from app.remediation.provenance import utc
from app.remediation.verification_contracts import (
    VerificationContent,
    VerificationEvidence,
    VerificationOutcome,
    VerificationReason,
)
from app.schemas.resource import ResourceScope


def _require(condition):
    if not condition:
        raise ValueError("verification evidence binding is inconsistent")


def postcondition_for(
    session: Session, scan: Scan, intent: VerificationContent, proposal: ProposalContent
) -> tuple[VerificationOutcome, VerificationReason, VerificationEvidence | None]:
    """Classify retained evidence only. Invalid/unavailable proof is never a success."""
    if scan.status is not ScanStatus.COMPLETED:
        return VerificationOutcome.INCONCLUSIVE, VerificationReason.SCAN_INCOMPLETE, None
    try:
        evidence, key, absence = _proof(session, scan, intent, proposal)
    except (ValueError, TypeError, KeyError, AttributeError):
        return VerificationOutcome.INCONCLUSIVE, VerificationReason.PROVENANCE_UNAVAILABLE, None
    if evidence.observed_at <= max(intent.acknowledged_at, proposal.baseline.observed_at):
        return VerificationOutcome.INCONCLUSIVE, VerificationReason.OBSERVATION_NOT_LATER, evidence
    if (key, absence) != (
        proposal.baseline.default_kms_key_id,
        proposal.baseline.default_kms_key_expected_absence,
    ):
        return VerificationOutcome.INCONCLUSIVE, VerificationReason.KMS_CONTEXT_CHANGED, evidence
    if evidence.technical_result is AssessmentResult.PASS:
        return VerificationOutcome.VERIFIED, VerificationReason.POSTCONDITION_PASS, evidence
    return VerificationOutcome.NOT_VERIFIED, VerificationReason.POSTCONDITION_FAIL, evidence


def _proof(session, scan, intent, proposal):
    baseline = proposal.baseline
    scope = session.scalar(
        select(ScanScopeManifest).where(ScanScopeManifest.scan_id == scan.scan_id)
    )
    _require(
        scan.scan_id == intent.scan_id
        and scan.aws_account_id == intent.account_id == proposal.account_id
        and scan.requested_regions == scan.successful_regions == [intent.region]
        and tuple(scan.requested_services) == intent.requested_services
        and scope is not None
        and tuple(scope.requested_collectors) == intent.requested_collectors
        and set(scope.resource_types) == set(intent.resource_types)
        and set(scope.collector_outcomes) == set(intent.requested_collectors)
        and all(value == "SUCCEEDED" for value in scope.collector_outcomes.values())
        and "EC2-004" in scope.enabled_controls
        and scan.inventory_sha256 is not None
        and scan.result_checksum is not None
    )
    resource = session.get(Resource, proposal.resource_id)
    identity = dict(
        account_id=proposal.account_id,
        service="ec2",
        resource_type="aws_account",
        scope=ResourceScope.REGIONAL,
        region=proposal.region,
        aws_resource_id=proposal.account_id,
    )
    snapshot_id = resource_snapshot_id(scan_id=scan.scan_id, **identity)
    snapshot = session.get(ResourceSnapshot, snapshot_id)
    _require(
        resource is not None
        and resource.resource_id
        == stable_resource_id(
            provider="aws",
            aws_account_id=proposal.account_id,
            **{key: value for key, value in identity.items() if key != "account_id"},
        )
        and resource.provider == "aws"
        and resource.service == "ec2"
        and resource.resource_type == "aws_account"
        and resource.aws_account_id == resource.aws_resource_id == proposal.account_id
        and resource.scope is ResourceScope.REGIONAL
        and resource.region == proposal.region
        and snapshot is not None
        and snapshot.resource_id == resource.resource_id
        and snapshot.scan_id == scan.scan_id
        and snapshot.scope is ResourceScope.REGIONAL
        and snapshot.region == proposal.region
        and utc(scan.started_at) <= utc(snapshot.observed_at) <= utc(scan.completed_at)
    )
    state = {
        "arn": snapshot.arn,
        "name": snapshot.name,
        "scope": snapshot.scope.value,
        "region": snapshot.region,
        "tags": snapshot.tags,
        "normalized_configuration": snapshot.normalized_configuration,
    }
    _require(canonical_json_sha256(state) == snapshot.state_sha256)
    assessment = session.get(
        ControlAssessment,
        control_assessment_id(
            scan_id=scan.scan_id, resource_snapshot_id=snapshot_id, control_id="EC2-004"
        ),
    )
    version = session.get(ControlVersion, baseline.control_version_id)
    _require(
        assessment is not None
        and not assessment.missing_evidence
        and assessment.assessment_result in {AssessmentResult.PASS, AssessmentResult.FAIL}
        and assessment.resource_id == resource.resource_id
        and assessment.resource_snapshot_id == snapshot_id
        and assessment.control_id == proposal.control_id
        and assessment.control_version_id == baseline.control_version_id
        and version is not None
        and version.definition_checksum == baseline.control_definition_sha256
    )
    profile = session.get(PersistedAssessmentProfile, assessment.assessment_profile_version_id)
    _require(
        profile is not None
        and (profile.profile_id, profile.version, profile.content_checksum)
        == (intent.profile_id, intent.profile_version, intent.profile_sha256)
    )
    graph = load_evidence_graph(session, scan.scan_id)
    _require(graph is not None and graph.collection_account_id == proposal.account_id)
    artifacts = {item.evidence_reference: item for item in graph.artifacts}

    def source(kind, api):
        matches = [
            item
            for item in graph.source_outcomes
            if item.evidence_kind == kind
            and item.source_api == api
            and item.collector == "ec2.ebs-defaults"
            and item.collector_version == "1.0.0"
            and isinstance(item.subject, AccountEvidenceSubject)
            and item.subject.aws_account_id == proposal.account_id
            and item.subject.scope is ResourceScope.REGIONAL
            and item.subject.region == proposal.region
        ]
        _require(len(matches) == 1)
        outcome = matches[0]
        artifact = artifacts[outcome.evidence_reference]
        payload = artifact.normalized_payload
        _require(
            payload.get("account_id") == proposal.account_id
            and payload.get("region") == proposal.region
            and payload.get("complete") is True
            and payload.get("failure_category") is None
            and utc(artifact.collected_at) == utc(snapshot.observed_at)
        )
        return (
            outcome,
            payload,
            SourceBinding(
                source_outcome_id=outcome.source_outcome_id,
                artifact_id=artifact.artifact_id,
                evidence_reference=artifact.evidence_reference,
                evidence_sha256=artifact.evidence_sha256,
            ),
        )

    encryption, payload, encryption_binding = source(
        "ec2.ebs-encryption-default", "ec2:GetEbsEncryptionByDefault"
    )
    enabled = payload.get("ebs_encryption_by_default")
    _require(
        encryption.state is EvidenceSourceState.PRESENT
        and type(enabled) is bool
        and (assessment.assessment_result is AssessmentResult.PASS) == enabled
    )
    kms, payload, kms_binding = source("ec2.ebs-default-kms-key", "ec2:GetEbsDefaultKmsKeyId")
    key, absence = payload.get("default_kms_key_id"), payload.get("expected_absence")
    _require(
        (kms.state is EvidenceSourceState.EXPECTED_ABSENCE and absence is True and key is None)
        or (
            kms.state is EvidenceSourceState.PRESENT
            and absence is False
            and isinstance(key, str)
            and bool(key.strip())
        )
    )
    expected_payload = {
        "evaluation_version": "1.0.0",
        "ebs_encryption_by_default": enabled,
        "source_proof": {
            "schema_version": "1.0.0",
            "scan_id": str(scan.scan_id),
            "sources": [
                {
                    "source_outcome_id": str(encryption_binding.source_outcome_id),
                    "artifact_id": str(encryption_binding.artifact_id),
                    "evidence_sha256": encryption_binding.evidence_sha256,
                }
            ],
            "relationship_observation_ids": [],
        },
    }
    expected = DomainEvidence.for_assessment(
        resource_snapshot_id=snapshot_id,
        scan_id=scan.scan_id,
        control_id="EC2-004",
        **identity,
        arn=snapshot.arn,
        collector="ec2.ebs-defaults",
        source="normalized-inventory",
        source_api="ec2:GetEbsEncryptionByDefault",
        collected_at=utc(snapshot.observed_at),
        schema_name="control.ec2-004.evidence",
        schema_version="1.0.0",
        evidence_key="primary",
        payload=expected_payload,
    )
    records = session.scalars(
        select(EvidenceArtifact).where(EvidenceArtifact.assessment_id == assessment.assessment_id)
    ).all()
    _require(len(records) == 1)
    record = records[0]
    _require(
        record.evidence_id == expected.evidence_id
        and record.payload_sha256
        == canonical_json_sha256(record.payload)
        == expected.payload_sha256
        and record.collector == expected.collector
        and record.source == expected.source
        and record.source_api == expected.source_api
        and record.schema_name == expected.schema_name
        and record.schema_version == expected.schema_version
        and record.evidence_key == expected.evidence_key
        and utc(record.collected_at) == utc(snapshot.observed_at)
    )
    return (
        VerificationEvidence(
            resource_id=resource.resource_id,
            snapshot_id=snapshot_id,
            state_sha256=snapshot.state_sha256,
            assessment_id=assessment.assessment_id,
            control_version_id=version.control_version_id,
            control_definition_sha256=version.definition_checksum,
            observed_at=utc(snapshot.observed_at),
            technical_result=assessment.assessment_result,
            assessment_evidence=(
                AssessmentEvidenceBinding(
                    evidence_id=record.evidence_id,
                    payload_sha256=record.payload_sha256,
                ),
            ),
            encryption_source=encryption_binding,
            kms_source=kms_binding,
        ),
        key,
        absence,
    )
