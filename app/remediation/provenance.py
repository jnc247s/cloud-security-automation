"""Read-only remediation prerequisites over accepted immutable assessment history."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.identities import resource_snapshot_id, stable_resource_id
from app.assessment.models import AssessmentResult
from app.assessment.models import EvidenceArtifact as DomainEvidenceArtifact
from app.assessment.source_outcomes import AccountEvidenceSubject, EvidenceSourceState
from app.database.catalogs import load_assessment_profile, verify_control_catalog
from app.database.evidence_graph import load_evidence_graph
from app.database.integrity import canonical_json_sha256
from app.models import (
    AuditEvent,
    Control,
    ControlAssessment,
    ControlVersion,
    EvidenceArtifact,
    Finding,
    FindingException,
    FindingOccurrence,
    PersistedAssessmentProfile,
    Resource,
    ResourceSnapshot,
    Scan,
)
from app.models.enums import ExceptionStatus, FindingStatus, ScanStatus
from app.remediation.contracts import (
    AssessmentEvidenceBinding,
    Baseline,
    BlockingReason,
    SourceBinding,
)
from app.rules.registry import resolve_catalog
from app.schemas.resource import ResourceScope


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _require(condition: bool) -> None:
    if not condition:
        raise ValueError("remediation baseline provenance is inconsistent")


def baseline_for(session: Session, finding: Finding, occurrence: FindingOccurrence) -> Baseline:
    """Validate source facts and retained FAIL; do not evaluate a rule or repair history."""
    _require(occurrence.finding_id == finding.finding_id)
    assessment = session.get(ControlAssessment, occurrence.assessment_id)
    scan = session.get(Scan, occurrence.scan_id)
    snapshot = session.get(ResourceSnapshot, occurrence.resource_snapshot_id)
    resource = session.get(Resource, occurrence.resource_id)
    control = session.get(Control, occurrence.control_id)
    version = session.get(ControlVersion, occurrence.control_version_id)
    _require(
        all(row is not None for row in (assessment, scan, snapshot, resource, control, version))
    )
    _require(
        scan.status is ScanStatus.COMPLETED
        and assessment.assessment_result is AssessmentResult.FAIL
        and control.control_key == "EC2-004"
        and not assessment.missing_evidence
        and occurrence.resource_id
        == finding.resource_id
        == assessment.resource_id
        == snapshot.resource_id
        and occurrence.control_id
        == finding.control_id
        == assessment.control_id
        == version.control_id
        and assessment.scan_id == scan.scan_id == snapshot.scan_id
        and resource.provider == "aws"
        and resource.service == "ec2"
        and resource.resource_type == "aws_account"
        and resource.scope is ResourceScope.REGIONAL
        and resource.scope == snapshot.scope
        and resource.region == snapshot.region == finding.region
        and resource.aws_account_id
        == resource.aws_resource_id
        == finding.aws_account_id
        == scan.aws_account_id
    )
    identity = dict(
        account_id=resource.aws_account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        scope=resource.scope,
        region=resource.region,
        aws_resource_id=resource.aws_resource_id,
    )
    _require(resource_snapshot_id(scan_id=scan.scan_id, **identity) == snapshot.snapshot_id)
    _require(
        stable_resource_id(
            provider="aws",
            aws_account_id=identity["account_id"],
            **{key: value for key, value in identity.items() if key != "account_id"},
        )
        == resource.resource_id
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
    profile = load_assessment_profile(
        session,
        profile_id=scan.assessment_profile_id,
        version=scan.assessment_profile_version,
        expected_checksum=scan.assessment_profile_checksum,
    )
    profile_row = session.get(PersistedAssessmentProfile, assessment.assessment_profile_version_id)
    _require(
        profile_row is not None
        and profile_row.profile_id == profile.profile_id
        and profile_row.version == profile.version
        and "EC2-004" in profile.enabled_controls
    )
    catalog, _ = resolve_catalog(scan.control_catalog_id, scan.control_catalog_version)
    verify_control_catalog(session, catalog)
    _require(
        version.catalog.catalog_key == catalog.catalog_id
        and version.catalog.version == catalog.version
    )
    graph = load_evidence_graph(session, scan.scan_id)
    _require(graph is not None)
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
            and item.subject.aws_account_id == resource.aws_account_id
            and item.subject.scope is ResourceScope.REGIONAL
            and item.subject.region == resource.region
        ]
        _require(len(matches) == 1)
        outcome = matches[0]
        artifact = artifacts[outcome.evidence_reference]
        payload = artifact.normalized_payload
        _require(
            payload.get("account_id") == resource.aws_account_id
            and payload.get("region") == resource.region
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

    encryption, encryption_payload, encryption_binding = source(
        "ec2.ebs-encryption-default", "ec2:GetEbsEncryptionByDefault"
    )
    _require(
        encryption.state is EvidenceSourceState.PRESENT
        and encryption_payload.get("ebs_encryption_by_default") is False
    )
    kms, kms_payload, kms_binding = source("ec2.ebs-default-kms-key", "ec2:GetEbsDefaultKmsKeyId")
    key = kms_payload.get("default_kms_key_id")
    absence = kms_payload.get("expected_absence")
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
        "ebs_encryption_by_default": False,
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
    evidence = session.scalars(
        select(EvidenceArtifact).where(EvidenceArtifact.assessment_id == assessment.assessment_id)
    ).all()
    _require(len(evidence) == 1)
    record = evidence[0]
    expected = DomainEvidenceArtifact.for_assessment(
        resource_snapshot_id=snapshot.snapshot_id,
        scan_id=scan.scan_id,
        control_id="EC2-004",
        account_id=resource.aws_account_id,
        service="ec2",
        resource_type="aws_account",
        aws_resource_id=resource.aws_resource_id,
        arn=snapshot.arn,
        scope=resource.scope,
        region=resource.region,
        collector="ec2.ebs-defaults",
        source="normalized-inventory",
        source_api="ec2:GetEbsEncryptionByDefault",
        collected_at=utc(snapshot.observed_at),
        schema_name="control.ec2-004.evidence",
        schema_version="1.0.0",
        evidence_key="primary",
        payload=expected_payload,
    )
    _require(
        record.evidence_id == expected.evidence_id
        and record.payload_sha256 == expected.payload_sha256
        and canonical_json_sha256(record.payload) == expected.payload_sha256
        and record.collector == expected.collector
        and record.source == expected.source
        and record.source_api == expected.source_api
        and record.schema_name == expected.schema_name
        and record.schema_version == expected.schema_version
        and record.evidence_key == expected.evidence_key
        and utc(record.collected_at) == utc(snapshot.observed_at)
    )
    return Baseline(
        occurrence_id=occurrence.occurrence_id,
        assessment_id=assessment.assessment_id,
        scan_id=scan.scan_id,
        snapshot_id=snapshot.snapshot_id,
        state_sha256=snapshot.state_sha256,
        observed_at=utc(snapshot.observed_at),
        profile_id=profile.profile_id,
        profile_version=profile.version,
        profile_sha256=profile.content_checksum,
        catalog_id=catalog.catalog_id,
        catalog_version=catalog.version,
        catalog_sha256=version.catalog.content_checksum,
        control_version_id=version.control_version_id,
        control_definition_sha256=version.definition_checksum,
        inventory_sha256=scan.inventory_sha256,
        assessment_evidence=(
            AssessmentEvidenceBinding(
                evidence_id=record.evidence_id,
                payload_sha256=record.payload_sha256,
            ),
        ),
        encryption_source=encryption_binding,
        kms_source=kms_binding,
        default_kms_key_id=key,
        default_kms_key_expected_absence=absence,
    )


def governance_state(session: Session, finding: Finding, at: datetime):
    exceptions = session.scalars(
        select(FindingException)
        .where(
            FindingException.finding_id == finding.finding_id,
            FindingException.resource_id == finding.resource_id,
            FindingException.control_id == finding.control_id,
        )
        .order_by(FindingException.exception_id)
        .execution_options(populate_existing=True)
    ).all()
    # Bind the append-only history, not a reversible current status or maximum
    # timestamp. Distinct disposition events may legally share the same time.
    finding_event_ids = session.scalars(
        select(AuditEvent.event_id)
        .where(
            AuditEvent.target_type == "finding",
            AuditEvent.target_id == finding.finding_id,
        )
        .order_by(AuditEvent.event_id)
    ).all()
    document = {
        "status": finding.status.value,
        "finding_event_ids": [str(event_id) for event_id in finding_event_ids],
        "exceptions": [
            {
                "exception_id": str(row.exception_id),
                "status": row.status.value,
                "expires_at": utc(row.expires_at).isoformat(),
                "revoked_at": utc(row.revoked_at).isoformat() if row.revoked_at else None,
            }
            for row in exceptions
        ],
    }
    blocking = []
    if finding.status not in {FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED}:
        blocking.append(BlockingReason.INELIGIBLE_FINDING)
    if any(row.status is ExceptionStatus.ACTIVE and utc(row.expires_at) > at for row in exceptions):
        blocking.append(BlockingReason.ACTIVE_EXCEPTION)
    return canonical_json_sha256(document), blocking


def has_newer_assessment(session: Session, finding: Finding, baseline: Baseline) -> bool:
    return (
        session.scalar(
            select(ControlAssessment.assessment_id)
            .join(
                ResourceSnapshot,
                ResourceSnapshot.snapshot_id == ControlAssessment.resource_snapshot_id,
            )
            .where(
                ControlAssessment.resource_id == finding.resource_id,
                ControlAssessment.control_id == finding.control_id,
                ControlAssessment.assessment_id != baseline.assessment_id,
                ResourceSnapshot.observed_at >= baseline.observed_at,
            )
            .limit(1)
        )
        is not None
    )
