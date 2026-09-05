"""Pure projections from persistence models to stable API representations."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.assessment import ControlAssessment, EvidenceArtifact
from app.models.audit import AuditEvent
from app.models.control import (
    Control,
    ControlFrameworkMapping,
    ControlVersion,
    Framework,
    FrameworkReference,
)
from app.models.exception import FindingException
from app.models.finding import Finding, FindingOccurrence
from app.models.resource import Resource, ResourceSnapshot
from app.schemas.api_views import (
    AssessmentDetailView,
    AssessmentView,
    AuditEventView,
    ControlVersionView,
    ControlView,
    EvidenceArtifactView,
    FindingDetailView,
    FindingExceptionView,
    FindingOccurrenceView,
    FindingView,
    FrameworkControlMappingView,
    FrameworkMappingView,
    FrameworkReferenceView,
    FrameworkView,
    ResourceSnapshotView,
    ResourceView,
)


def resource_snapshot_view(snapshot: ResourceSnapshot) -> ResourceSnapshotView:
    return ResourceSnapshotView(
        snapshot_id=snapshot.snapshot_id,
        resource_id=snapshot.resource_id,
        scan_id=snapshot.scan_id,
        scope=snapshot.scope,
        region=snapshot.region,
        arn=snapshot.arn,
        name=snapshot.name,
        tags=dict(snapshot.tags),
        normalized_configuration=dict(snapshot.normalized_configuration),
        state_sha256=snapshot.state_sha256,
        observed_at=snapshot.observed_at,
    )


def resource_view(resource: Resource) -> ResourceView:
    latest = max(resource.snapshots, key=lambda item: item.observed_at, default=None)
    return ResourceView(
        resource_id=resource.resource_id,
        provider=resource.provider,
        aws_account_id=resource.aws_account_id,
        aws_resource_id=resource.aws_resource_id,
        arn=resource.arn,
        service=resource.service,
        resource_type=resource.resource_type,
        scope=resource.scope,
        region=resource.region,
        latest_snapshot=resource_snapshot_view(latest) if latest is not None else None,
    )


def evidence_view(evidence: EvidenceArtifact) -> EvidenceArtifactView:
    return EvidenceArtifactView(
        evidence_id=evidence.evidence_id,
        assessment_id=evidence.assessment_id,
        scan_id=evidence.scan_id,
        resource_snapshot_id=evidence.resource_snapshot_id,
        control_version_id=evidence.control_version_id,
        control_id=evidence.control_id,
        collector=evidence.collector,
        source=evidence.source,
        source_api=evidence.source_api,
        collected_at=evidence.collected_at,
        schema_name=evidence.schema_name,
        schema_version=evidence.schema_version,
        evidence_key=evidence.evidence_key,
        payload=dict(evidence.payload),
        payload_sha256=evidence.payload_sha256,
    )


def framework_mapping_view(mapping: ControlFrameworkMapping) -> FrameworkMappingView:
    reference = mapping.framework_reference
    framework = reference.framework
    return FrameworkMappingView(
        mapping_id=mapping.mapping_id,
        control_version_id=mapping.control_version_id,
        framework_id=framework.framework_id,
        framework_key=framework.framework_key,
        framework_version=framework.version,
        framework_reference_id=reference.framework_reference_id,
        reference_key=reference.reference_key,
        reference_level=reference.level,
        reference_title=reference.title,
        mapping_rationale=mapping.mapping_rationale,
        mapping_source=mapping.mapping_source,
        mapping_source_version=mapping.mapping_source_version,
        verified_at=mapping.verified_at,
        mapping_checksum=mapping.mapping_checksum,
    )


def assessment_view(assessment: ControlAssessment) -> AssessmentView:
    return AssessmentView(
        assessment_id=assessment.assessment_id,
        scan_id=assessment.scan_id,
        resource_snapshot_id=assessment.resource_snapshot_id,
        resource_id=assessment.resource_id,
        control_version_id=assessment.control_version_id,
        control_id=assessment.control_id,
        assessment_profile_version_id=assessment.assessment_profile_version_id,
        assessment_result=assessment.assessment_result,
        reason=assessment.reason,
        missing_evidence=tuple(assessment.missing_evidence),
        evaluated_at=assessment.evaluated_at,
        evidence_count=len(assessment.evidence_artifacts),
    )


def assessment_detail_view(assessment: ControlAssessment) -> AssessmentDetailView:
    occurrence = assessment.finding_occurrence
    return AssessmentDetailView(
        **assessment_view(assessment).model_dump(),
        evidence=tuple(
            evidence_view(item)
            for item in sorted(
                assessment.evidence_artifacts,
                key=lambda item: (item.evidence_key, str(item.evidence_id)),
            )
        ),
        framework_mappings=tuple(
            framework_mapping_view(item)
            for item in sorted(
                assessment.control_version.framework_mappings,
                key=lambda item: str(item.mapping_id),
            )
        ),
        finding_id=occurrence.finding_id if occurrence is not None else None,
        finding_occurrence_id=occurrence.occurrence_id if occurrence is not None else None,
    )


def exception_view(exception: FindingException) -> FindingExceptionView:
    return FindingExceptionView(
        exception_id=exception.exception_id,
        finding_id=exception.finding_id,
        resource_id=exception.resource_id,
        control_id=exception.control_id,
        reason=exception.reason,
        approved_by=exception.approved_by,
        created_at=exception.created_at,
        expires_at=exception.expires_at,
        status=exception.status,
        revoked_at=exception.revoked_at,
    )


def occurrence_view(occurrence: FindingOccurrence) -> FindingOccurrenceView:
    return FindingOccurrenceView(
        occurrence_id=occurrence.occurrence_id,
        finding_id=occurrence.finding_id,
        assessment_id=occurrence.assessment_id,
        scan_id=occurrence.scan_id,
        resource_snapshot_id=occurrence.resource_snapshot_id,
        resource_id=occurrence.resource_id,
        control_version_id=occurrence.control_version_id,
        control_id=occurrence.control_id,
        assessment_result=occurrence.assessment_result,
        detected_at=occurrence.detected_at,
    )


def _exception_is_active(exception: FindingException) -> bool:
    expires_at = exception.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return exception.status.value == "ACTIVE" and expires_at > datetime.now(UTC)


def finding_view(finding: Finding) -> FindingView:
    return FindingView(
        finding_id=finding.finding_id,
        fingerprint=finding.fingerprint,
        aws_account_id=finding.aws_account_id,
        resource_id=finding.resource_id,
        control_id=finding.control_id,
        region=finding.region,
        status=finding.status,
        first_detected_at=finding.first_detected_at,
        last_detected_at=finding.last_detected_at,
        resolved_at=finding.resolved_at,
        occurrence_count=len(finding.occurrences),
        active_exception_ids=tuple(
            sorted(
                (item.exception_id for item in finding.exceptions if _exception_is_active(item)),
                key=str,
            )
        ),
    )


def finding_detail_view(finding: Finding) -> FindingDetailView:
    return FindingDetailView(
        **finding_view(finding).model_dump(),
        occurrences=tuple(
            occurrence_view(item)
            for item in sorted(finding.occurrences, key=lambda item: item.detected_at)
        ),
        exceptions=tuple(
            exception_view(item)
            for item in sorted(finding.exceptions, key=lambda item: item.created_at)
        ),
    )


def control_version_view(version: ControlVersion) -> ControlVersionView:
    return ControlVersionView(
        control_version_id=version.control_version_id,
        catalog_id=version.catalog_id,
        catalog_key=version.catalog.catalog_key,
        catalog_version=version.catalog.version,
        title=version.title,
        category=version.category,
        resource_type=version.resource_type,
        assessment_type=version.assessment_type,
        measure=version.measure,
        required_evidence=tuple(version.required_evidence),
        pass_logic=version.pass_logic,
        fail_logic=version.fail_logic,
        insufficient_evidence_behavior=version.insufficient_evidence_behavior,
        not_applicable_logic=version.not_applicable_logic,
        severity=version.severity,
        impact=version.impact,
        remediation_guidance=version.remediation_guidance,
        profile_parameters=tuple(version.profile_parameters),
        limitations=tuple(version.limitations),
        definition_checksum=version.definition_checksum,
        created_at=version.created_at,
        framework_mappings=tuple(
            framework_mapping_view(item)
            for item in sorted(version.framework_mappings, key=lambda item: str(item.mapping_id))
        ),
    )


def control_view(control: Control) -> ControlView:
    return ControlView(
        control_id=control.control_id,
        control_key=control.control_key,
        created_at=control.created_at,
        versions=tuple(
            control_version_view(item)
            for item in sorted(
                control.versions,
                key=lambda item: (item.catalog.created_at, str(item.control_version_id)),
                reverse=True,
            )
        ),
    )


def framework_control_mapping_view(
    mapping: ControlFrameworkMapping,
) -> FrameworkControlMappingView:
    version = mapping.control_version
    return FrameworkControlMappingView(
        mapping_id=mapping.mapping_id,
        control_id=version.control_id,
        control_key=version.control.control_key,
        control_version_id=version.control_version_id,
        mapping_rationale=mapping.mapping_rationale,
        mapping_source=mapping.mapping_source,
        mapping_source_version=mapping.mapping_source_version,
        verified_at=mapping.verified_at,
        mapping_checksum=mapping.mapping_checksum,
    )


def framework_reference_view(reference: FrameworkReference) -> FrameworkReferenceView:
    return FrameworkReferenceView(
        framework_reference_id=reference.framework_reference_id,
        framework_id=reference.framework_id,
        reference_key=reference.reference_key,
        level=reference.level,
        title=reference.title,
        description=reference.description,
        parent_reference_id=reference.parent_reference_id,
        control_mappings=tuple(
            framework_control_mapping_view(item)
            for item in sorted(reference.control_mappings, key=lambda item: str(item.mapping_id))
        ),
    )


def framework_view(framework: Framework) -> FrameworkView:
    return FrameworkView(
        framework_id=framework.framework_id,
        framework_key=framework.framework_key,
        name=framework.name,
        version=framework.version,
        source=framework.source,
        source_retrieved_at=framework.source_retrieved_at,
        source_checksum=framework.source_checksum,
        created_at=framework.created_at,
        references=tuple(
            framework_reference_view(item)
            for item in sorted(
                framework.references,
                key=lambda item: (item.level.value, item.reference_key),
            )
        ),
    )


def audit_event_view(event: AuditEvent) -> AuditEventView:
    return AuditEventView(
        event_id=event.event_id,
        event_type=event.event_type,
        actor_type=event.actor_type,
        actor_id=event.actor_id,
        target_type=event.target_type,
        target_id=event.target_id,
        timestamp=event.timestamp,
        metadata=dict(event.event_metadata),
    )
