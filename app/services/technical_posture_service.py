"""Bounded, read-only reporting over exact retained scan and version identities."""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.engine import RowMapping
from sqlalchemy.orm import Session, joinedload, raiseload

from app.assessment.frameworks import FrameworkReferenceLevel
from app.assessment.models import AssessmentResult
from app.models.assessment import ControlAssessment
from app.models.control import (
    Control,
    ControlCatalog,
    ControlFrameworkMapping,
    ControlVersion,
    Framework,
    FrameworkReference,
)
from app.models.enums import ScanStatus
from app.models.profile import PersistedAssessmentProfile
from app.models.resource import Resource, ResourceSnapshot
from app.schemas.api_views import FrameworkMappingView
from app.schemas.scan import ScanDetail
from app.schemas.technical_posture import (
    AssessmentCounts,
    CatalogProvenance,
    ControlCoverage,
    ControlPosture,
    FrameworkPosture,
    FrameworkReferencePosture,
    TargetPosture,
    TechnicalPosture,
)
from app.services.errors import TechnicalPostureProvenanceError
from app.services.projections import framework_mapping_view
from app.services.scan_service import ScanService, _as_utc

_COUNT_FIELDS = {
    AssessmentResult.PASS: "pass_count",
    AssessmentResult.FAIL: "fail_count",
    AssessmentResult.INSUFFICIENT_EVIDENCE: "insufficient_evidence_count",
    AssessmentResult.NOT_APPLICABLE: "not_applicable_count",
}


def _sum_counts(counts: Iterable[AssessmentCounts]) -> AssessmentCounts:
    values = dict.fromkeys(_COUNT_FIELDS.values(), 0)
    for item in counts:
        for field in values:
            values[field] += getattr(item, field)
    return AssessmentCounts(**values)


def _coverage(controls: Iterable[ControlPosture], *, available: bool) -> ControlCoverage:
    rows = tuple(controls)
    enabled = sum(row.enabled for row in rows)
    assessed = sum(row.assessment_coverage == "ASSESSED" for row in rows)
    return ControlCoverage(
        registered_count=len(rows),
        enabled_count=enabled,
        disabled_count=len(rows) - enabled,
        assessed_count=assessed if available else None,
        unassessed_count=enabled - assessed if available else None,
    )


class TechnicalPostureService:
    """Do not evaluate rules, call AWS, select latest versions or mutate transactions."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_technical_posture(self, scan_id: UUID) -> TechnicalPosture:
        # Reporting must not flush even unrelated pending objects in a caller's session.
        with self.session.no_autoflush:
            return self._report(scan_id)

    def _report(self, scan_id: UUID) -> TechnicalPosture:
        scan = ScanService(self.session).get_scan(scan_id)
        profile = self.session.execute(
            select(
                PersistedAssessmentProfile.profile_version_id,
                PersistedAssessmentProfile.enabled_controls,
                PersistedAssessmentProfile.content_checksum,
            ).where(
                PersistedAssessmentProfile.profile_id == scan.assessment_profile_id,
                PersistedAssessmentProfile.version == scan.assessment_profile_version,
            )
        ).one_or_none()
        catalog = self.session.scalar(
            select(ControlCatalog).where(
                ControlCatalog.catalog_key == scan.control_catalog_id,
                ControlCatalog.version == scan.control_catalog_version,
            )
        )
        if (
            profile is None
            or catalog is None
            or profile.content_checksum != scan.assessment_profile_checksum
        ):
            raise TechnicalPostureProvenanceError
        enabled = profile.enabled_controls
        if (
            not isinstance(enabled, list)
            or any(not isinstance(key, str) or not key for key in enabled)
            or len(enabled) != len(set(enabled))
        ):
            raise TechnicalPostureProvenanceError
        enabled_keys = frozenset(enabled)
        if scan.scope is not None and (
            frozenset(scan.scope.enabled_controls) != enabled_keys
            or len(scan.scope.enabled_controls) != len(enabled_keys)
        ):
            raise TechnicalPostureProvenanceError

        definitions = (
            self.session.execute(
                select(
                    ControlVersion.control_version_id,
                    ControlVersion.control_id,
                    Control.control_key,
                    ControlVersion.title,
                    ControlVersion.category,
                    ControlVersion.resource_type,
                    ControlVersion.assessment_type,
                    ControlVersion.severity,
                    ControlVersion.definition_checksum,
                )
                .join(Control, Control.control_id == ControlVersion.control_id)
                .where(ControlVersion.catalog_id == catalog.catalog_id)
                .order_by(Control.control_key, ControlVersion.control_version_id)
            )
            .mappings()
            .all()
        )
        if not enabled_keys.issubset(row["control_key"] for row in definitions):
            raise TechnicalPostureProvenanceError
        version_ids = tuple(row["control_version_id"] for row in definitions)
        available = (
            scan.status is not ScanStatus.RUNNING
            and scan.scope is not None
            and scan.inventory_sha256 is not None
            and scan.result_checksum is not None
        )
        counts = (
            self._assessment_counts(scan, profile.profile_version_id, definitions)
            if available
            else {}
        )
        mappings = tuple(
            self.session.scalars(
                select(ControlFrameworkMapping)
                .where(ControlFrameworkMapping.control_version_id.in_(version_ids))
                .options(
                    joinedload(ControlFrameworkMapping.framework_reference).joinedload(
                        FrameworkReference.framework
                    ),
                    raiseload("*"),
                )
                .order_by(
                    ControlFrameworkMapping.control_version_id,
                    ControlFrameworkMapping.framework_reference_id,
                    ControlFrameworkMapping.mapping_id,
                )
            )
        )
        mapping_views: dict[UUID, list[FrameworkMappingView]] = defaultdict(list)
        for mapping in mappings:
            view = framework_mapping_view(mapping)
            mapping_views[mapping.control_version_id].append(
                view.model_copy(update={"verified_at": _as_utc(view.verified_at)})
            )
        control_rows = []
        for definition in definitions:
            is_enabled = definition["control_key"] in enabled_keys
            result_counts = counts.get(definition["control_version_id"], AssessmentCounts())
            coverage = (
                "DISABLED"
                if not is_enabled
                else "UNAVAILABLE"
                if not available
                else "ASSESSED"
                if result_counts.total
                else "UNASSESSED"
            )
            control_rows.append(
                ControlPosture(
                    **definition,
                    enabled=is_enabled,
                    assessment_coverage=coverage,
                    assessment_counts=result_counts if available else None,
                    framework_mappings=tuple(mapping_views[definition["control_version_id"]]),
                )
            )
        controls = tuple(control_rows)
        return TechnicalPosture(
            scan=scan,
            availability=(
                "IN_PROGRESS"
                if scan.status is ScanStatus.RUNNING
                else "AVAILABLE"
                if available
                else "UNAVAILABLE"
            ),
            catalog=CatalogProvenance(
                catalog_id=catalog.catalog_id,
                catalog_key=catalog.catalog_key,
                version=catalog.version,
                content_checksum=catalog.content_checksum,
            ),
            assessment_profile_version_id=profile.profile_version_id,
            enabled_controls=tuple(sorted(enabled_keys)),
            control_coverage=_coverage(controls, available=available),
            assessment_counts=_sum_counts(counts.values()) if available else None,
            targets=self._targets(scan_id) if available else None,
            controls=controls,
            frameworks=self._frameworks(controls, mappings, available=available),
        )

    def _assessment_counts(
        self, scan: ScanDetail, profile_id: UUID, definitions: Sequence[RowMapping]
    ) -> dict[UUID, AssessmentCounts]:
        enabled_ids = {
            row["control_version_id"]
            for row in definitions
            if row["control_key"] in scan.scope.enabled_controls
        }
        rows = self.session.execute(
            select(
                ControlAssessment.control_version_id,
                ControlAssessment.assessment_profile_version_id,
                ControlAssessment.assessment_result,
                func.count(ControlAssessment.assessment_id),
            )
            .where(ControlAssessment.scan_id == scan.scan_id)
            .group_by(
                ControlAssessment.control_version_id,
                ControlAssessment.assessment_profile_version_id,
                ControlAssessment.assessment_result,
            )
        )
        totals = defaultdict(lambda: dict.fromkeys(_COUNT_FIELDS.values(), 0))
        for version_id, assessment_profile_id, result, count in rows:
            # Never hide inconsistent rows behind an exact-version filtering join.
            if version_id not in enabled_ids or assessment_profile_id != profile_id:
                raise TechnicalPostureProvenanceError
            totals[version_id][_COUNT_FIELDS[result]] += count
        return {version_id: AssessmentCounts(**values) for version_id, values in totals.items()}

    def _targets(self, scan_id: UUID) -> tuple[TargetPosture, ...]:
        dimensions = (
            Resource.aws_account_id,
            Resource.service,
            Resource.resource_type,
            ResourceSnapshot.scope,
            ResourceSnapshot.region,
        )
        rows = self.session.execute(
            select(
                *dimensions,
                func.count(func.distinct(ResourceSnapshot.snapshot_id)),
                *(
                    func.sum(case((ControlAssessment.assessment_result == result, 1), else_=0))
                    for result in _COUNT_FIELDS
                ),
            )
            .select_from(ControlAssessment)
            .join(
                ResourceSnapshot,
                (ResourceSnapshot.snapshot_id == ControlAssessment.resource_snapshot_id)
                & (ResourceSnapshot.scan_id == ControlAssessment.scan_id),
            )
            .join(Resource, Resource.resource_id == ResourceSnapshot.resource_id)
            .where(ControlAssessment.scan_id == scan_id)
            .group_by(*dimensions)
            .order_by(*dimensions)
        )
        return tuple(
            TargetPosture(
                target_kind="ACCOUNT" if resource_type == "aws_account" else "RESOURCE",
                aws_account_id=account_id,
                service=service,
                resource_type=resource_type,
                scope=scope,
                region=region,
                assessed_snapshot_count=snapshots,
                assessment_counts=AssessmentCounts(
                    **dict(zip(_COUNT_FIELDS.values(), values, strict=True))
                ),
            )
            for account_id, service, resource_type, scope, region, snapshots, *values in rows
        )

    def _frameworks(
        self,
        controls: tuple[ControlPosture, ...],
        mappings: tuple[ControlFrameworkMapping, ...],
        *,
        available: bool,
    ) -> tuple[FrameworkPosture, ...]:
        frameworks: dict[UUID, Framework] = {}
        directly_mapped = defaultdict(set)
        for mapping in mappings:
            framework = mapping.framework_reference.framework
            frameworks[framework.framework_id] = framework
            directly_mapped[mapping.framework_reference_id].add(mapping.control_version_id)
        if not frameworks:
            return ()
        references = tuple(
            self.session.scalars(
                select(FrameworkReference)
                .where(FrameworkReference.framework_id.in_(frameworks))
                .options(raiseload("*"))
                .order_by(
                    FrameworkReference.reference_key, FrameworkReference.framework_reference_id
                )
            )
        )
        references_by_id = {row.framework_reference_id: row for row in references}
        expected_parent = {
            FrameworkReferenceLevel.CATEGORY: FrameworkReferenceLevel.FUNCTION,
            FrameworkReferenceLevel.SUBCATEGORY: FrameworkReferenceLevel.CATEGORY,
        }
        for reference in references:
            if reference.level is FrameworkReferenceLevel.FUNCTION:
                if reference.parent_reference_id is not None:
                    raise TechnicalPostureProvenanceError
            else:
                parent = references_by_id.get(reference.parent_reference_id)
                if (
                    parent is None
                    or parent.framework_id != reference.framework_id
                    or parent.level is not expected_parent[reference.level]
                ):
                    raise TechnicalPostureProvenanceError
        aggregated_ids = defaultdict(set)
        for reference_id, control_ids in directly_mapped.items():
            reference = references_by_id.get(reference_id)
            if reference is None:
                raise TechnicalPostureProvenanceError
            visited = set()
            while reference is not None:
                if reference.framework_reference_id in visited:
                    raise TechnicalPostureProvenanceError
                visited.add(reference.framework_reference_id)
                aggregated_ids[reference.framework_reference_id].update(control_ids)
                if reference.parent_reference_id is None:
                    break
                parent = references_by_id.get(reference.parent_reference_id)
                if parent is None or parent.framework_id != reference.framework_id:
                    raise TechnicalPostureProvenanceError
                reference = parent
        control_index = {control.control_version_id: control for control in controls}
        reports = []
        for framework in sorted(frameworks.values(), key=lambda f: (f.framework_key, f.version)):
            rows = []
            for reference in references:
                if reference.framework_id != framework.framework_id:
                    continue
                ids = tuple(sorted(aggregated_ids[reference.framework_reference_id]))
                mapped_controls = tuple(control_index[version_id] for version_id in ids)
                rows.append(
                    FrameworkReferencePosture(
                        framework_reference_id=reference.framework_reference_id,
                        reference_key=reference.reference_key,
                        level=reference.level,
                        title=reference.title,
                        parent_reference_id=reference.parent_reference_id,
                        mapped_control_version_ids=ids,
                        control_coverage=_coverage(mapped_controls, available=available),
                        assessment_counts=(
                            _sum_counts(control.assessment_counts for control in mapped_controls)
                            if available
                            else None
                        ),
                    )
                )
            reports.append(
                FrameworkPosture(
                    framework_id=framework.framework_id,
                    framework_key=framework.framework_key,
                    name=framework.name,
                    version=framework.version,
                    source=framework.source,
                    source_retrieved_at=_as_utc(framework.source_retrieved_at),
                    source_checksum=framework.source_checksum,
                    references=tuple(rows),
                )
            )
        return tuple(reports)
