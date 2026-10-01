"""Closed invocation-local S3-002 -> LOG-004 dependency, never historical lookup."""

from dataclasses import dataclass
from types import MappingProxyType
from uuid import UUID

from app.assessment.execution import ExecutionContract, account_target, validate_execution_targets
from app.assessment.models import AssessmentCandidate
from app.assessment.provenance import control_catalog_sha256


def assessment_order(catalog, enabled_controls):
    """Preserve lexical order except the one approved dependency; never auto-enable it."""
    for control in catalog.controls:
        execution = control.technical.execution_contract
        if execution is None:
            continue
        # Revalidate unchecked model_copy metadata at this boundary, including old schemas.
        execution = ExecutionContract.model_validate_json(execution.model_dump_json())
        if execution.assessment_dependencies:
            from app.assessment.s3_exposure_control import exposure_contract

            if (
                control.control_id != "LOG-004"
                or catalog.get("S3-002").technical != exposure_contract().technical
            ):
                raise ValueError("unsupported assessment dependency binding")
    ordered = sorted(enabled_controls)
    if "LOG-004" in ordered and "S3-002" in ordered:
        ordered.remove("S3-002")
        ordered.insert(ordered.index("LOG-004"), "S3-002")
    return tuple(ordered)


@dataclass(frozen=True, slots=True)
class ValidatedAssessmentContext:
    """Read-only validated prerequisites, scoped to one exact invocation."""

    scan_id: UUID
    inventory_sha256: str
    catalog_sha256: str
    profile_id: str
    profile_version: str
    profile_checksum: str
    prerequisites: MappingProxyType

    def matches(self, reader, profile):
        return (
            self.scan_id == reader.snapshot.scan_id
            and self.inventory_sha256 == reader.composition_inventory_sha256()
            and self.profile_id == profile.profile_id
            and self.profile_version == profile.version
            and self.profile_checksum == profile.calculate_content_checksum()
        )


def validated_context(reader, profile, catalog, candidates):
    """Independently validate prerequisites before publishing; caller order is immaterial."""
    snapshot = reader.snapshot
    inventory_digest = reader.composition_inventory_sha256()
    catalog_digest = control_catalog_sha256(catalog)
    profile_digest = profile.calculate_content_checksum()
    prerequisites = {}
    if "S3-002" in profile.enabled_controls:
        from app.assessment.s3_exposure_control import exposure_contract

        technical = catalog.get("S3-002").technical
        if technical != exposure_contract().technical:
            raise ValueError("composition requires canonical S3-002")
        selected = tuple(c for c in candidates if c.control_id == "S3-002")
        validate_execution_targets(snapshot, technical.execution_contract, selected)
        for raw in selected:
            candidate = AssessmentCandidate.model_validate_json(raw.model_dump_json())
            if (
                candidate.scan_id != snapshot.scan_id
                or candidate.inventory_sha256 != inventory_digest
                or candidate.control_catalog_sha256 != catalog_digest
                or candidate.profile_id != profile.profile_id
                or candidate.profile_version != profile.version
                or candidate.profile_checksum != profile_digest
            ):
                raise ValueError("prerequisite invocation binding differs")
            target = reader.resources.get(candidate.resource_snapshot_id)
            if target is not None:
                if (
                    candidate.identity[1:] != target.identity
                    or candidate.arn != target.arn
                    or candidate.name != target.name
                ):
                    raise ValueError("prerequisite destination metadata differs")
            else:
                fallback = account_target(snapshot, technical.execution_contract)
                if candidate.resource_snapshot_id != reader._target_id(fallback):
                    raise ValueError("prerequisite destination snapshot is absent")
                if candidate.arn != fallback.arn or candidate.name != fallback.name:
                    raise ValueError("prerequisite fallback metadata differs")
            if any(a.collected_at != snapshot.collected_at for a in candidate.evidence_artifacts):
                raise ValueError("prerequisite observation time differs")
            reader.validate_candidate(
                technical.execution_contract, candidate, profile=profile, exact_proof=True
            )
            key = (candidate.control_id, candidate.resource_snapshot_id)
            if key in prerequisites:
                raise ValueError("duplicate prerequisite target")
            prerequisites[key] = candidate
    return ValidatedAssessmentContext(
        snapshot.scan_id,
        inventory_digest,
        catalog_digest,
        profile.profile_id,
        profile.version,
        profile_digest,
        MappingProxyType(prerequisites),
    )
