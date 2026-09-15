"""Append-only Sprint 5 source-evidence and resource-relationship records."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.assessment.source_outcomes import (
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
)
from app.database.base import Base
from app.models.types import (
    JsonObject,
    enum_check_constraint,
    json_document_type,
    string_enum_type,
)
from app.schemas.resource import ResourceScope


class ScanSourceContract(Base):
    """One concrete evidence source promised by a versioned collector for a scan."""

    __tablename__ = "scan_source_contracts"
    __table_args__ = (
        enum_check_constraint("phase", EvidenceCollectionPhase, name="phase"),
        CheckConstraint("cardinality IN ('SINGLE', 'COLLECTION')", name="cardinality"),
        CheckConstraint(
            "owner_mode IN ('COLLECTION_ACCOUNT', 'AWS_MANAGED', 'EXTERNAL_ACCOUNT')",
            name="owner_mode",
        ),
        CheckConstraint("length(collection_account_id) = 12", name="collection_account_length"),
        CheckConstraint("length(trim(contract_key)) > 0", name="contract_key_not_blank"),
        CheckConstraint("length(trim(contract_version)) > 0", name="contract_version_not_blank"),
        CheckConstraint("length(trim(evidence_kind)) > 0", name="evidence_kind_not_blank"),
        CheckConstraint("length(trim(collector)) > 0", name="collector_not_blank"),
        CheckConstraint("length(trim(collector_version)) > 0", name="collector_version_not_blank"),
        CheckConstraint("length(trim(source_api)) > 0", name="source_api_not_blank"),
        CheckConstraint("length(trim(schema_version)) > 0", name="schema_version_not_blank"),
        CheckConstraint(
            "(phase = 'DISCOVERY' AND subject_kind = 'account' "
            "AND subject_resource_id IS NULL AND subject_resource_snapshot_id IS NULL) OR "
            "(phase = 'ENRICHMENT' AND subject_kind = 'resource' "
            "AND subject_resource_id IS NOT NULL "
            "AND subject_resource_snapshot_id IS NOT NULL)",
            name="phase_subject_consistent",
        ),
        CheckConstraint(
            "owner_mode = 'COLLECTION_ACCOUNT' OR identity_authoritative",
            name="exceptional_owner_requires_authority",
        ),
        ForeignKeyConstraint(
            ["subject_resource_snapshot_id", "scan_id", "subject_resource_id"],
            [
                "resource_snapshots.snapshot_id",
                "resource_snapshots.scan_id",
                "resource_snapshots.resource_id",
            ],
            name="fk_scan_source_contracts_subject_snapshot",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "source_outcome_id",
            "scan_id",
            name="uq_scan_source_contracts_outcome_scan",
        ),
        Index("ix_scan_source_contracts_scan", "scan_id"),
        Index("ix_scan_source_contracts_contract", "contract_key", "contract_version"),
    )

    source_outcome_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("scans.scan_id", ondelete="RESTRICT"),
        nullable=False,
    )
    collection_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    contract_key: Mapped[str] = mapped_column(String(128), nullable=False)
    contract_version: Mapped[str] = mapped_column(String(64), nullable=False)
    phase: Mapped[EvidenceCollectionPhase] = mapped_column(
        string_enum_type(EvidenceCollectionPhase, name="evidence_collection_phase", length=16),
        nullable=False,
    )
    subject_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    subject: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    subject_resource_id: Mapped[UUID | None] = mapped_column(Uuid)
    subject_resource_snapshot_id: Mapped[UUID | None] = mapped_column(Uuid)
    evidence_kind: Mapped[str] = mapped_column(String(128), nullable=False)
    collector: Mapped[str] = mapped_column(String(128), nullable=False)
    collector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_api: Mapped[str] = mapped_column(String(128), nullable=False)
    cardinality: Mapped[str] = mapped_column(String(16), nullable=False)
    owner_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    identity_authoritative: Mapped[bool] = mapped_column(Boolean, nullable=False)
    allows_supplemental_region: Mapped[bool] = mapped_column(Boolean, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)


class SourceEvidenceArtifact(Base):
    """One normalized and digest-bound artifact produced by an AWS evidence source."""

    __tablename__ = "source_evidence_artifacts"
    __table_args__ = (
        CheckConstraint("length(collection_account_id) = 12", name="collection_account_length"),
        CheckConstraint("length(trim(evidence_reference)) > 0", name="reference_not_blank"),
        CheckConstraint("length(evidence_sha256) = 64", name="evidence_sha256_length"),
        CheckConstraint("length(trim(evidence_schema)) > 0", name="evidence_schema_not_blank"),
        CheckConstraint(
            "length(trim(evidence_schema_version)) > 0",
            name="evidence_schema_version_not_blank",
        ),
        CheckConstraint("length(trim(schema_version)) > 0", name="schema_version_not_blank"),
        UniqueConstraint(
            "artifact_id",
            "scan_id",
            name="uq_source_evidence_artifacts_artifact_scan",
        ),
        UniqueConstraint(
            "scan_id",
            "evidence_reference",
            name="uq_source_evidence_artifacts_scan_reference",
        ),
        UniqueConstraint(
            "artifact_id",
            "scan_id",
            "evidence_reference",
            "evidence_sha256",
            name="uq_source_evidence_artifacts_outcome_reference",
        ),
        Index("ix_source_evidence_artifacts_scan", "scan_id"),
    )

    artifact_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("scans.scan_id", ondelete="RESTRICT"),
        nullable=False,
    )
    collection_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_schema: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    normalized_payload: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)


class SourceEvidenceOutcome(Base):
    """One immutable outcome for one declared source contract."""

    __tablename__ = "source_evidence_outcomes"
    __table_args__ = (
        enum_check_constraint("phase", EvidenceCollectionPhase, name="phase"),
        enum_check_constraint("state", EvidenceSourceState, name="state"),
        enum_check_constraint(
            "failure_category",
            EvidenceFailureCategory,
            name="failure_category",
        ),
        enum_check_constraint("subject_scope", ResourceScope, name="subject_scope"),
        CheckConstraint("length(collection_account_id) = 12", name="collection_account_length"),
        CheckConstraint("length(trim(evidence_kind)) > 0", name="evidence_kind_not_blank"),
        CheckConstraint("length(trim(collector)) > 0", name="collector_not_blank"),
        CheckConstraint("length(trim(collector_version)) > 0", name="collector_version_not_blank"),
        CheckConstraint("source = 'aws-api'", name="source_aws_api"),
        CheckConstraint("length(trim(source_api)) > 0", name="source_api_not_blank"),
        CheckConstraint("length(trim(evidence_reference)) > 0", name="reference_not_blank"),
        CheckConstraint("length(evidence_sha256) = 64", name="evidence_sha256_length"),
        CheckConstraint("length(trim(schema_version)) > 0", name="schema_version_not_blank"),
        CheckConstraint(
            "(phase = 'DISCOVERY' AND subject_kind = 'account' "
            "AND subject_resource_id IS NULL AND subject_resource_snapshot_id IS NULL) OR "
            "(phase = 'ENRICHMENT' AND subject_kind = 'resource' "
            "AND subject_resource_id IS NOT NULL "
            "AND subject_resource_snapshot_id IS NOT NULL)",
            name="phase_subject_consistent",
        ),
        CheckConstraint(
            "(subject_scope = 'regional' AND subject_region IS NOT NULL) OR "
            "(subject_scope = 'global' AND subject_region IS NULL)",
            name="subject_scope_region_consistent",
        ),
        CheckConstraint(
            "(state IN ('PRESENT', 'EXPECTED_ABSENCE') AND failure_category IS NULL) OR "
            "(state NOT IN ('PRESENT', 'EXPECTED_ABSENCE') AND failure_category IS NOT NULL)",
            name="state_failure_consistent",
        ),
        CheckConstraint(
            "state <> 'RESOURCE_DISAPPEARED' OR phase = 'ENRICHMENT'",
            name="disappearance_requires_enrichment",
        ),
        ForeignKeyConstraint(
            ["source_outcome_id", "scan_id"],
            ["scan_source_contracts.source_outcome_id", "scan_source_contracts.scan_id"],
            name="fk_source_evidence_outcomes_contract",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["artifact_id", "scan_id", "evidence_reference", "evidence_sha256"],
            [
                "source_evidence_artifacts.artifact_id",
                "source_evidence_artifacts.scan_id",
                "source_evidence_artifacts.evidence_reference",
                "source_evidence_artifacts.evidence_sha256",
            ],
            name="fk_source_evidence_outcomes_artifact",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["subject_resource_snapshot_id", "scan_id", "subject_resource_id"],
            [
                "resource_snapshots.snapshot_id",
                "resource_snapshots.scan_id",
                "resource_snapshots.resource_id",
            ],
            name="fk_source_evidence_outcomes_subject_snapshot",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        UniqueConstraint(
            "source_outcome_id",
            "scan_id",
            "evidence_reference",
            name="uq_source_evidence_outcomes_relationship_reference",
        ),
        Index("ix_source_evidence_outcomes_scan_state", "scan_id", "state"),
    )

    source_outcome_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    collection_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    phase: Mapped[EvidenceCollectionPhase] = mapped_column(
        string_enum_type(EvidenceCollectionPhase, name="evidence_collection_phase", length=16),
        nullable=False,
    )
    subject_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    subject: Mapped[JsonObject] = mapped_column(json_document_type(), nullable=False)
    subject_resource_id: Mapped[UUID | None] = mapped_column(Uuid)
    subject_resource_snapshot_id: Mapped[UUID | None] = mapped_column(Uuid)
    subject_scope: Mapped[ResourceScope] = mapped_column(
        string_enum_type(ResourceScope, name="source_subject_scope", length=16),
        nullable=False,
    )
    subject_region: Mapped[str | None] = mapped_column(String(64))
    evidence_kind: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[EvidenceSourceState] = mapped_column(
        string_enum_type(EvidenceSourceState, name="evidence_source_state", length=32),
        nullable=False,
    )
    failure_category: Mapped[EvidenceFailureCategory | None] = mapped_column(
        string_enum_type(
            EvidenceFailureCategory,
            name="evidence_failure_category",
            length=32,
        )
    )
    collector: Mapped[str] = mapped_column(String(128), nullable=False)
    collector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="aws-api")
    source_api: Mapped[str] = mapped_column(String(128), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    artifact_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    evidence_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)


class ResourceRelationshipObservation(Base):
    """One immutable observation of a directional resource relationship."""

    __tablename__ = "resource_relationship_observations"
    __table_args__ = (
        enum_check_constraint("relationship_type", RelationshipType, name="relationship_type"),
        enum_check_constraint("resolution", RelationshipResolution, name="resolution"),
        enum_check_constraint("source_scope", ResourceScope, name="source_scope"),
        CheckConstraint(
            "target_scope IS NULL OR target_scope IN ('regional', 'global')",
            name="target_scope",
        ),
        CheckConstraint("length(collection_account_id) = 12", name="collection_account_length"),
        CheckConstraint("source_provider = 'aws'", name="source_provider_aws"),
        CheckConstraint("target_provider = 'aws'", name="target_provider_aws"),
        CheckConstraint("provenance_source = 'aws-api'", name="provenance_source_aws_api"),
        CheckConstraint(
            "(source_scope = 'regional' AND source_region IS NOT NULL) OR "
            "(source_scope = 'global' AND source_region IS NULL)",
            name="source_scope_region_consistent",
        ),
        CheckConstraint(
            "target_scope IS NULL OR "
            "(target_scope = 'regional' AND target_region IS NOT NULL) OR "
            "(target_scope = 'global' AND target_region IS NULL)",
            name="target_scope_region_consistent",
        ),
        CheckConstraint(
            "(target_identity_state = 'stable' AND target_resource_id IS NOT NULL "
            "AND target_reference_id IS NULL) OR "
            "(target_identity_state = 'unresolved' AND target_resource_id IS NULL "
            "AND target_resource_snapshot_id IS NULL AND target_reference_id IS NOT NULL)",
            name="target_identity_consistent",
        ),
        CheckConstraint(
            "(resolution = 'RESOLVED' AND target_identity_state = 'stable' "
            "AND target_resource_snapshot_id IS NOT NULL) OR "
            "(resolution <> 'RESOLVED' AND target_resource_snapshot_id IS NULL)",
            name="resolution_snapshot_consistent",
        ),
        CheckConstraint(
            "resolution <> 'TARGET_IDENTITY_INCOMPLETE' OR target_identity_state = 'unresolved'",
            name="incomplete_resolution_consistent",
        ),
        CheckConstraint(
            "target_identity_state <> 'unresolved' OR resolution = 'TARGET_IDENTITY_INCOMPLETE'",
            name="unresolved_target_consistent",
        ),
        CheckConstraint(
            "target_resource_id IS NULL OR source_resource_id <> target_resource_id",
            name="endpoints_differ",
        ),
        CheckConstraint("length(trim(provenance_collector)) > 0", name="collector_not_blank"),
        CheckConstraint(
            "length(trim(provenance_collector_version)) > 0",
            name="collector_version_not_blank",
        ),
        CheckConstraint("length(trim(provenance_source_api)) > 0", name="source_api_not_blank"),
        CheckConstraint("length(trim(evidence_reference)) > 0", name="reference_not_blank"),
        CheckConstraint("length(trim(schema_version)) > 0", name="schema_version_not_blank"),
        ForeignKeyConstraint(
            ["source_resource_snapshot_id", "scan_id", "source_resource_id"],
            [
                "resource_snapshots.snapshot_id",
                "resource_snapshots.scan_id",
                "resource_snapshots.resource_id",
            ],
            name="fk_resource_relationships_source_snapshot",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["target_resource_snapshot_id", "scan_id", "target_resource_id"],
            [
                "resource_snapshots.snapshot_id",
                "resource_snapshots.scan_id",
                "resource_snapshots.resource_id",
            ],
            name="fk_resource_relationships_target_snapshot",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
        ),
        ForeignKeyConstraint(
            ["source_outcome_id", "scan_id", "evidence_reference"],
            [
                "source_evidence_outcomes.source_outcome_id",
                "source_evidence_outcomes.scan_id",
                "source_evidence_outcomes.evidence_reference",
            ],
            name="fk_resource_relationships_source_outcome",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "observation_id",
            "scan_id",
            name="uq_resource_relationships_observation_scan",
        ),
        UniqueConstraint(
            "scan_id",
            "relationship_id",
            name="uq_resource_relationships_scan_relationship",
        ),
        Index(
            "ix_resource_relationships_source",
            "source_resource_id",
            "relationship_type",
        ),
        Index(
            "ix_resource_relationships_target",
            "target_resource_id",
            "relationship_type",
        ),
        Index(
            "ix_resource_relationships_target_reference",
            "target_reference_id",
            "relationship_type",
        ),
        Index("ix_resource_relationships_scan", "scan_id"),
    )

    observation_id: Mapped[UUID] = mapped_column(Uuid, primary_key=True)
    relationship_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    scan_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    collection_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    relationship_type: Mapped[RelationshipType] = mapped_column(
        string_enum_type(RelationshipType, name="relationship_type", length=32),
        nullable=False,
    )
    resolution: Mapped[RelationshipResolution] = mapped_column(
        string_enum_type(RelationshipResolution, name="relationship_resolution", length=40),
        nullable=False,
    )
    source_provider: Mapped[str] = mapped_column(String(32), nullable=False)
    source_aws_account_id: Mapped[str] = mapped_column(String(32), nullable=False)
    source_service: Mapped[str] = mapped_column(String(64), nullable=False)
    source_resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    source_aws_resource_id: Mapped[str] = mapped_column(Text, nullable=False)
    source_scope: Mapped[ResourceScope] = mapped_column(
        string_enum_type(ResourceScope, name="relationship_source_scope", length=16),
        nullable=False,
    )
    source_region: Mapped[str | None] = mapped_column(String(64))
    source_resource_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    source_resource_snapshot_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    target_identity_state: Mapped[str] = mapped_column(String(16), nullable=False)
    target_provider: Mapped[str] = mapped_column(String(32), nullable=False)
    target_aws_account_id: Mapped[str | None] = mapped_column(String(32))
    target_service: Mapped[str] = mapped_column(String(64), nullable=False)
    target_resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    target_aws_resource_id: Mapped[str] = mapped_column(Text, nullable=False)
    target_scope: Mapped[str | None] = mapped_column(String(16))
    target_region: Mapped[str | None] = mapped_column(String(64))
    target_resource_id: Mapped[UUID | None] = mapped_column(Uuid)
    target_resource_snapshot_id: Mapped[UUID | None] = mapped_column(Uuid)
    target_reference_id: Mapped[UUID | None] = mapped_column(Uuid)
    source_outcome_id: Mapped[UUID] = mapped_column(Uuid, nullable=False)
    provenance_collector: Mapped[str] = mapped_column(String(128), nullable=False)
    provenance_collector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_source: Mapped[str] = mapped_column(String(16), nullable=False, default="aws-api")
    provenance_source_api: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
