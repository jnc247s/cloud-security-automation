"""Transactional persistence of already-collected and already-assessed scan results.

This module does not collect AWS data, evaluate controls, execute scans, or commit
transactions. Callers own the transaction and must roll it back on any error.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.assessment.controls import ControlCatalog as CatalogInput
from app.assessment.identities import (
    control_assessment_id,
    finding_fingerprint,
    inventory_sha256,
    resource_snapshot_id,
    stable_resource_id,
)
from app.assessment.models import AssessmentCandidate, AssessmentResult
from app.assessment.profiles import AssessmentProfile
from app.assessment.provenance import control_catalog_sha256
from app.database.catalogs import ensure_assessment_profile, ensure_control_catalog
from app.database.integrity import canonical_json_sha256
from app.database.validation import canonical_scope_document, validate_expected_assessments
from app.models import (
    AuditEvent,
    ControlAssessment,
    EvidenceArtifact,
    Finding,
    FindingOccurrence,
    Resource,
    ResourceSnapshot,
    Scan,
    ScanScopeManifest,
)
from app.models.enums import AuditEventType, FindingStatus, ScanStatus
from app.models.resource import GLOBAL_REGION_SENTINEL
from app.schemas.inventory import CollectionStatus, InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput
from app.schemas.resource import NormalizedResource, ResourceScope


class ScanPersistenceError(ValueError):
    """A result bundle cannot be recorded without violating historical integrity."""


def _utc(value: datetime) -> datetime:
    """Normalize database timestamps, including SQLite's naive UTC round trips."""

    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _require_aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ScanPersistenceError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _insert_if_absent(
    session: Session,
    model: type,
    values: dict[str, Any],
    conflict_columns: Sequence[str],
) -> bool:
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        statement = postgres_insert(model.__table__)
    elif dialect == "sqlite":
        statement = sqlite_insert(model.__table__)
    else:
        raise ScanPersistenceError("persistence supports PostgreSQL and SQLite tests only")
    result = session.execute(
        statement.values(**values).on_conflict_do_nothing(index_elements=conflict_columns)
    )
    return result.rowcount == 1


def _state_document(resource: NormalizedResource) -> dict[str, Any]:
    return {
        "arn": resource.arn,
        "name": resource.name,
        "scope": resource.scope.value,
        "region": resource.region,
        "tags": resource.tags,
        "normalized_configuration": resource.configuration,
    }


def _target_snapshot_id(scan_id: UUID, resource: NormalizedResource) -> UUID:
    return resource_snapshot_id(
        scan_id=scan_id,
        account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        scope=resource.scope,
        region=resource.region,
        aws_resource_id=resource.aws_resource_id,
    )


def _validate_bundle(
    snapshot: InventorySnapshot,
    scope: ScanScopeManifestInput,
    profile: AssessmentProfile,
    catalog: CatalogInput,
    assessments: Sequence[AssessmentCandidate],
) -> dict[UUID, NormalizedResource]:
    """Validate all provenance before any database writes are attempted."""

    InventorySnapshot.model_validate_json(snapshot.model_dump_json())
    ScanScopeManifestInput.model_validate_json(scope.model_dump_json())
    for candidate in assessments:
        # model_copy() is intentionally unchecked by Pydantic; validate at this trust boundary.
        AssessmentCandidate.model_validate_json(candidate.model_dump_json())
    if scope.aws_account_id != snapshot.account_id:
        raise ScanPersistenceError("scope account does not match the inventory")
    if snapshot.requested_region not in scope.requested_regions:
        raise ScanPersistenceError("inventory invocation region is outside the scope")
    if scope.collector_outcome_document() != {
        item.collector_name: item.status.value for item in snapshot.collector_outcomes
    }:
        raise ScanPersistenceError("scope collector outcomes do not match the inventory")
    if (
        scope.assessment_profile_id != profile.profile_id
        or scope.assessment_profile_version != profile.version
        or scope.assessment_profile_checksum != profile.calculate_content_checksum()
        or scope.control_catalog_id != catalog.catalog_id
        or scope.control_catalog_version != catalog.version
        or set(scope.enabled_controls) != set(profile.enabled_controls)
    ):
        raise ScanPersistenceError("scope does not match the exact profile and catalog")
    if set(item.control_id for item in assessments) != set(scope.enabled_controls):
        raise ScanPersistenceError("every enabled control requires an explicit assessment")
    try:
        validate_expected_assessments(snapshot, scope, catalog, assessments)
    except ValueError as error:
        raise ScanPersistenceError(str(error)) from error

    targets: dict[UUID, NormalizedResource] = {}
    for resource in snapshot.resources:
        if resource.account_id != snapshot.account_id:
            raise ScanPersistenceError("inventory contains a different AWS account")
        if resource.service not in scope.requested_services:
            raise ScanPersistenceError("resource service is outside the requested scope")
        if resource.resource_type not in scope.resource_types:
            raise ScanPersistenceError("resource type is outside the requested scope")
        if (
            resource.region is not None
            and resource.region not in scope.requested_regions
            and resource.service not in {"s3", "cloudtrail"}
        ):
            raise ScanPersistenceError("resource region is outside the requested scope")
        target_id = _target_snapshot_id(snapshot.scan_id, resource)
        if target_id in targets:
            raise ScanPersistenceError("inventory contains a duplicate resource identity")
        canonical_json_sha256(_state_document(resource))
        targets[target_id] = resource

    seen: set[tuple[str, UUID]] = set()
    expected_inventory_sha256 = inventory_sha256(snapshot)
    expected_catalog_sha256 = control_catalog_sha256(catalog)
    for candidate in assessments:
        if candidate.account_id != snapshot.account_id or candidate.scan_id != snapshot.scan_id:
            raise ScanPersistenceError("assessment belongs to another account or scan")
        if candidate.inventory_sha256 != expected_inventory_sha256:
            raise ScanPersistenceError("inventory facts changed after assessment")
        if candidate.control_catalog_sha256 != expected_catalog_sha256:
            raise ScanPersistenceError("control catalog differs from the evaluated catalog")
        if candidate.service not in scope.requested_services:
            raise ScanPersistenceError("assessment service is outside the requested scope")
        if (
            candidate.profile_id != profile.profile_id
            or candidate.profile_version != profile.version
            or candidate.profile_checksum != profile.calculate_content_checksum()
        ):
            raise ScanPersistenceError("assessment belongs to another profile version")
        contract = catalog.get(candidate.control_id)
        key = (candidate.control_id, candidate.resource_snapshot_id)
        if key in seen:
            raise ScanPersistenceError("duplicate assessment target and control")
        seen.add(key)
        target = NormalizedResource(
            account_id=candidate.account_id,
            service=candidate.service,
            resource_type=candidate.resource_type,
            aws_resource_id=candidate.aws_resource_id,
            arn=candidate.arn,
            name=candidate.name,
            scope=candidate.scope,
            region=candidate.region,
        )
        if _target_snapshot_id(snapshot.scan_id, target) != candidate.resource_snapshot_id:
            raise ScanPersistenceError("assessment resource snapshot identity is invalid")
        if candidate.resource_snapshot_id not in targets:
            if not (
                candidate.resource_type == "aws_account"
                and candidate.aws_resource_id == snapshot.account_id
                and candidate.scope is ResourceScope.GLOBAL
            ):
                raise ScanPersistenceError("assessment target is absent from the inventory")
            targets[candidate.resource_snapshot_id] = target
        else:
            original = targets[candidate.resource_snapshot_id]
            if candidate.arn != original.arn or candidate.name != original.name:
                raise ScanPersistenceError("assessment target metadata differs from inventory")
        for artifact in candidate.evidence_artifacts:
            if artifact.collected_at != snapshot.collected_at:
                raise ScanPersistenceError("evidence observation time differs from inventory")
        if candidate.result in {AssessmentResult.PASS, AssessmentResult.FAIL}:
            if candidate.resource_type != contract.technical.resource_type:
                raise ScanPersistenceError("decisive assessment has the wrong resource type")
            for artifact in candidate.evidence_artifacts:
                if artifact.collector not in scope.successful_collectors:
                    raise ScanPersistenceError("decisive evidence requires a successful collector")
    return targets


def persist_scan_result(
    session: Session,
    *,
    snapshot: InventorySnapshot,
    scope: ScanScopeManifestInput,
    profile: AssessmentProfile,
    catalog: CatalogInput,
    assessments: Sequence[AssessmentCandidate],
    started_at: datetime,
    completed_at: datetime,
    scanner_version: str,
    actor_type: str = "system",
    actor_id: str = "scanner",
) -> Scan:
    """Persist a complete historical graph in the caller's transaction.

    Repeating the identical scan ID and bundle is idempotent. Reusing that ID for
    different facts is rejected. Only an explicit PASS in a complete scope can
    resolve an existing finding; absence and incomplete evidence never do so.
    """

    started_at = _require_aware(started_at, "started_at")
    completed_at = _require_aware(completed_at, "completed_at")
    if not started_at <= snapshot.collected_at <= completed_at:
        raise ScanPersistenceError("scan timestamps must enclose the observation time")
    if not scanner_version.strip() or not actor_type.strip() or not actor_id.strip():
        raise ScanPersistenceError("scanner version and audit actor must not be blank")
    targets = _validate_bundle(snapshot, scope, profile, catalog, assessments)
    input_inventory_sha256 = inventory_sha256(snapshot)
    assessment_documents = []
    for candidate in sorted(assessments, key=lambda item: item.identity):
        document = candidate.model_dump(mode="json")
        document["evidence_artifacts"] = sorted(
            document["evidence_artifacts"], key=lambda item: item["evidence_id"]
        )
        for artifact_document in document["evidence_artifacts"]:
            artifact_document["collected_at"] = (
                datetime.fromisoformat(artifact_document["collected_at"])
                .astimezone(UTC)
                .isoformat()
            )
        assessment_documents.append(document)
    result_checksum = canonical_json_sha256(
        {
            "scan_id": str(snapshot.scan_id),
            "observed_at": snapshot.collected_at.astimezone(UTC).isoformat(),
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "scanner_version": scanner_version,
            "scope": canonical_scope_document(scope),
            "catalog_sha256": control_catalog_sha256(catalog),
            "resources": {str(key): _state_document(value) for key, value in targets.items()},
            "assessments": assessment_documents,
        }
    )
    existing = session.get(Scan, snapshot.scan_id)
    if existing is not None:
        if existing.result_checksum != result_checksum:
            raise ScanPersistenceError("scan ID already exists with different content")
        return existing

    profile_record = ensure_assessment_profile(session, profile)
    _, control_versions = ensure_control_catalog(session, catalog)
    status = ScanStatus.COMPLETED if scope.is_complete else ScanStatus.PARTIAL
    if all(item.status is CollectionStatus.FAILED for item in scope.collector_outcomes):
        status = ScanStatus.FAILED
    inserted = _insert_if_absent(
        session,
        Scan,
        {
            "scan_id": snapshot.scan_id,
            "aws_account_id": snapshot.account_id,
            "requested_regions": sorted(scope.requested_regions),
            "successful_regions": sorted(scope.successful_regions),
            "requested_services": sorted(scope.requested_services),
            "successful_collectors": list(scope.successful_collectors),
            "started_at": started_at,
            "completed_at": None,
            "status": ScanStatus.RUNNING,
            "scanner_version": scanner_version,
            "control_catalog_id": catalog.catalog_id,
            "control_catalog_version": catalog.version,
            "assessment_profile_id": profile.profile_id,
            "assessment_profile_version": profile.version,
            "assessment_profile_checksum": profile.calculate_content_checksum(),
            "inventory_sha256": input_inventory_sha256,
            "result_checksum": None,
        },
        ["scan_id"],
    )
    scan = session.get(Scan, snapshot.scan_id)
    assert scan is not None
    if not inserted:
        if scan.result_checksum != result_checksum:
            raise ScanPersistenceError("scan ID already exists with different content")
        return scan

    append_audit_event(
        session,
        AuditEventType.SCAN_STARTED,
        "scan",
        scan.scan_id,
        started_at,
        actor_type=actor_type,
        actor_id=actor_id,
    )
    scope_values = canonical_scope_document(scope)
    scope_values.pop("collector_outcomes", None)
    session.add(
        ScanScopeManifest(
            scan_id=scan.scan_id,
            **{
                key: list(value) if isinstance(value, tuple) else value
                for key, value in scope_values.items()
            },
            collector_outcomes=scope.collector_outcome_document(),
            recorded_at=completed_at,
        )
    )
    resource_ids: dict[UUID, UUID] = {}
    # A stable lock order prevents opposing multi-resource scans from deadlocking.
    for snapshot_id, target in sorted(targets.items(), key=lambda item: item[1].identity):
        resource_ids[snapshot_id] = _persist_resource_snapshot(
            session, scan, snapshot_id, target, snapshot.collected_at
        )
    session.flush()

    persisted: list[tuple[AssessmentCandidate, ControlAssessment]] = []
    for candidate in sorted(assessments, key=lambda item: item.identity):
        version = control_versions[candidate.control_id]
        assessment = ControlAssessment(
            assessment_id=control_assessment_id(
                scan_id=scan.scan_id,
                resource_snapshot_id=candidate.resource_snapshot_id,
                control_id=candidate.control_id,
            ),
            scan_id=scan.scan_id,
            resource_snapshot_id=candidate.resource_snapshot_id,
            resource_id=resource_ids[candidate.resource_snapshot_id],
            control_id=version.control_id,
            control_version_id=version.control_version_id,
            assessment_profile_version_id=profile_record.profile_version_id,
            assessment_result=candidate.result,
            reason=candidate.reason,
            missing_evidence=list(candidate.missing_evidence),
            evaluated_at=completed_at,
        )
        session.add(assessment)
        for artifact in candidate.evidence_artifacts:
            session.add(
                EvidenceArtifact(
                    evidence_id=artifact.evidence_id,
                    assessment_id=assessment.assessment_id,
                    scan_id=scan.scan_id,
                    resource_snapshot_id=candidate.resource_snapshot_id,
                    control_id=version.control_id,
                    control_version_id=version.control_version_id,
                    collector=artifact.collector,
                    source=artifact.source,
                    source_api=artifact.source_api,
                    collected_at=artifact.collected_at,
                    schema_name=artifact.schema_name,
                    schema_version=artifact.schema_version,
                    evidence_key=artifact.evidence_key,
                    payload=artifact.model_dump(mode="json")["payload"],
                    payload_sha256=artifact.payload_sha256,
                )
            )
        persisted.append((candidate, assessment))
    session.flush()
    for candidate, assessment in persisted:
        _reconcile_finding(
            session,
            candidate,
            assessment,
            snapshot.collected_at,
            actor_type=actor_type,
            actor_id=actor_id,
            complete_scope=scope.is_complete,
        )
    append_audit_event(
        session,
        AuditEventType.SCAN_FAILED
        if status is ScanStatus.FAILED
        else AuditEventType.SCAN_COMPLETED,
        "scan",
        scan.scan_id,
        completed_at,
        actor_type=actor_type,
        actor_id=actor_id,
        metadata={"status": status.value, "assessment_count": len(assessments)},
    )
    session.flush()
    scan.status = status
    scan.completed_at = completed_at
    scan.result_checksum = result_checksum
    session.flush()
    return scan


def _persist_resource_snapshot(
    session: Session,
    scan: Scan,
    snapshot_id: UUID,
    target: NormalizedResource,
    observed_at: datetime,
) -> UUID:
    resource_id = stable_resource_id(
        provider="aws",
        aws_account_id=target.account_id,
        service=target.service,
        resource_type=target.resource_type,
        scope=target.scope,
        region=target.region,
        aws_resource_id=target.aws_resource_id,
    )
    identity = {
        "provider": "aws",
        "aws_account_id": target.account_id,
        "aws_resource_id": target.aws_resource_id,
        "service": target.service,
        "resource_type": target.resource_type,
        "scope": target.scope,
        "region": target.region or GLOBAL_REGION_SENTINEL,
    }
    _insert_if_absent(
        session,
        Resource,
        {"resource_id": resource_id, "arn": target.arn, **identity},
        ["resource_id"],
    )
    resource = session.scalar(
        select(Resource).where(Resource.resource_id == resource_id).with_for_update()
    )
    if resource is None or any(getattr(resource, key) != value for key, value in identity.items()):
        raise ScanPersistenceError("stable resource identity conflict")
    state = _state_document(target)
    session.add(
        ResourceSnapshot(
            snapshot_id=snapshot_id,
            resource_id=resource_id,
            scan_id=scan.scan_id,
            arn=target.arn,
            scope=target.scope,
            region=target.region,
            name=target.name,
            tags=dict(target.tags),
            normalized_configuration=state["normalized_configuration"],
            state_sha256=canonical_json_sha256(state),
            observed_at=observed_at,
        )
    )
    return resource_id


def _reconcile_finding(
    session: Session,
    candidate: AssessmentCandidate,
    assessment: ControlAssessment,
    observed_at: datetime,
    *,
    actor_type: str,
    actor_id: str,
    complete_scope: bool,
) -> None:
    if candidate.result not in {AssessmentResult.PASS, AssessmentResult.FAIL}:
        return
    fingerprint = finding_fingerprint(
        aws_account_id=candidate.account_id,
        resource_id=assessment.resource_id,
        control_id=candidate.control_id,
        region=candidate.region,
    )
    finding = session.scalar(
        select(Finding).where(Finding.fingerprint == fingerprint).with_for_update()
    )
    created = finding is None
    if finding is None:
        if candidate.result is not AssessmentResult.FAIL:
            return
        finding = Finding(
            finding_id=uuid4(),
            fingerprint=fingerprint,
            aws_account_id=candidate.account_id,
            resource_id=assessment.resource_id,
            control_id=assessment.control_id,
            region=candidate.region,
            status=FindingStatus.OPEN,
            first_detected_at=observed_at,
            last_detected_at=observed_at,
        )
        session.add(finding)
        session.flush()
        append_audit_event(
            session,
            AuditEventType.FINDING_OPENED,
            "finding",
            finding.finding_id,
            observed_at,
            actor_type=actor_type,
            actor_id=actor_id,
            metadata={"assessment_id": str(assessment.assessment_id)},
        )
    if (
        finding.resource_id != assessment.resource_id
        or finding.control_id != assessment.control_id
        or finding.aws_account_id != candidate.account_id
    ):
        raise ScanPersistenceError("finding fingerprint identity conflict")
    if candidate.result is AssessmentResult.FAIL:
        session.add(
            FindingOccurrence(
                finding_id=finding.finding_id,
                assessment_id=assessment.assessment_id,
                scan_id=assessment.scan_id,
                resource_snapshot_id=assessment.resource_snapshot_id,
                resource_id=assessment.resource_id,
                control_version_id=assessment.control_version_id,
                control_id=assessment.control_id,
                assessment_result=AssessmentResult.FAIL,
                detected_at=observed_at,
            )
        )

    eligible_pass = Scan.status == ScanStatus.COMPLETED
    if complete_scope:
        eligible_pass = or_(eligible_pass, Scan.scan_id == assessment.scan_id)
    decisive = session.execute(
        select(ControlAssessment, ResourceSnapshot.observed_at)
        .join(
            ResourceSnapshot, ControlAssessment.resource_snapshot_id == ResourceSnapshot.snapshot_id
        )
        .join(Scan, ControlAssessment.scan_id == Scan.scan_id)
        .where(
            ControlAssessment.resource_id == assessment.resource_id,
            ControlAssessment.control_id == assessment.control_id,
            or_(
                ControlAssessment.assessment_result == AssessmentResult.FAIL,
                and_(
                    ControlAssessment.assessment_result == AssessmentResult.PASS,
                    eligible_pass,
                ),
            ),
        )
        .order_by(
            ResourceSnapshot.observed_at.desc(),
            case((ControlAssessment.assessment_result == AssessmentResult.FAIL, 1), else_=0).desc(),
            ControlAssessment.assessment_id.desc(),
        )
        .limit(1)
    ).one()
    first_fail, last_fail = session.execute(
        select(func.min(ResourceSnapshot.observed_at), func.max(ResourceSnapshot.observed_at))
        .join(
            ControlAssessment,
            ControlAssessment.resource_snapshot_id == ResourceSnapshot.snapshot_id,
        )
        .where(
            ControlAssessment.resource_id == assessment.resource_id,
            ControlAssessment.control_id == assessment.control_id,
            ControlAssessment.assessment_result == AssessmentResult.FAIL,
        )
    ).one()
    finding.first_detected_at = first_fail
    finding.last_detected_at = last_fail
    previous_status = finding.status
    latest_assessment, latest_observed = decisive
    event_type = None
    if latest_assessment.assessment_result is AssessmentResult.PASS:
        finding.status = FindingStatus.RESOLVED
        finding.resolved_at = latest_observed
        if previous_status is not FindingStatus.RESOLVED:
            event_type = AuditEventType.FINDING_RESOLVED
    elif previous_status is FindingStatus.RESOLVED:
        finding.status = FindingStatus.OPEN
        finding.resolved_at = None
        event_type = AuditEventType.FINDING_REOPENED
    elif candidate.result is AssessmentResult.FAIL and not created:
        event_type = AuditEventType.FINDING_UPDATED
    if event_type is not None:
        append_audit_event(
            session,
            event_type,
            "finding",
            finding.finding_id,
            observed_at,
            actor_type=actor_type,
            actor_id=actor_id,
            metadata={
                "assessment_id": str(assessment.assessment_id),
                "latest_assessment_id": str(latest_assessment.assessment_id),
                "previous_status": previous_status.value,
                "status": finding.status.value,
            },
        )


def append_audit_event(
    session: Session,
    event_type: AuditEventType,
    target_type: str,
    target_id: UUID,
    timestamp: datetime,
    *,
    actor_type: str,
    actor_id: str,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Append one event in the same transaction as the corresponding domain change."""

    event = AuditEvent(
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        target_type=target_type,
        target_id=target_id,
        timestamp=timestamp,
        event_metadata=metadata or {},
    )
    session.add(event)
    return event
