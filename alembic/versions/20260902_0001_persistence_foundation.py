"""Create scan, resource, and finding persistence tables.

Revision ID: 20260902_0001
Revises:
Create Date: 2026-09-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "20260902_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    """Create the initial persistence schema."""

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_uuid", sa.Uuid(), nullable=False),
        sa.Column("account_id", sa.String(length=32), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "QUEUED",
                "RUNNING",
                "COMPLETED",
                "FAILED",
                name="scan_status",
                native_enum=False,
                create_constraint=False,
            ),
            server_default="QUEUED",
            nullable=False,
        ),
        sa.Column("resources_evaluated", sa.Integer(), server_default="0", nullable=False),
        sa.Column("controls_evaluated", sa.Integer(), server_default="0", nullable=False),
        sa.Column("findings_created", sa.Integer(), server_default="0", nullable=False),
        sa.Column("findings_resolved", sa.Integer(), server_default="0", nullable=False),
        sa.CheckConstraint(
            "controls_evaluated >= 0",
            name=op.f("ck_scans_controls_evaluated_nonnegative"),
        ),
        sa.CheckConstraint(
            "findings_created >= 0",
            name=op.f("ck_scans_findings_created_nonnegative"),
        ),
        sa.CheckConstraint(
            "findings_resolved >= 0",
            name=op.f("ck_scans_findings_resolved_nonnegative"),
        ),
        sa.CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at",
            name=op.f("ck_scans_completion_after_start"),
        ),
        sa.CheckConstraint(
            "(status = 'QUEUED' AND started_at IS NULL AND completed_at IS NULL) OR "
            "(status = 'RUNNING' AND started_at IS NOT NULL AND completed_at IS NULL) OR "
            "(status IN ('COMPLETED', 'FAILED') AND started_at IS NOT NULL "
            "AND completed_at IS NOT NULL)",
            name=op.f("ck_scans_lifecycle_timestamps_consistent"),
        ),
        sa.CheckConstraint(
            "resources_evaluated >= 0",
            name=op.f("ck_scans_resources_evaluated_nonnegative"),
        ),
        sa.CheckConstraint(
            "status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')",
            name=op.f("ck_scans_scan_status"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
        sa.UniqueConstraint("scan_uuid", name=op.f("uq_scans_scan_uuid")),
    )
    op.create_index(
        "ix_scans_account_region_started",
        "scans",
        ["account_id", "region", "started_at"],
        unique=False,
    )

    op.create_table(
        "resources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("identity_hash", sa.String(length=64), nullable=False),
        sa.Column("aws_resource_id", sa.Text(), nullable=False),
        sa.Column("arn", sa.Text(), nullable=True),
        sa.Column("service", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=128), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=True),
        sa.Column("account_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("tags", JSON_DOCUMENT, nullable=False),
        sa.Column("configuration", JSON_DOCUMENT, nullable=False),
        sa.Column("raw_configuration", JSON_DOCUMENT, nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "last_seen >= first_seen",
            name=op.f("ck_resources_seen_ordered"),
        ),
        sa.CheckConstraint(
            "(scope = 'regional' AND region IS NOT NULL) OR (scope = 'global' AND region IS NULL)",
            name=op.f("ck_resources_scope_region_consistent"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_resources")),
        sa.UniqueConstraint("identity_hash", name=op.f("uq_resources_identity_hash")),
    )
    op.create_index(
        "ix_resources_account_service_type",
        "resources",
        ["account_id", "service", "resource_type"],
        unique=False,
    )

    op.create_table(
        "scan_resources",
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("resource_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["resource_id"],
            ["resources.id"],
            name=op.f("fk_scan_resources_resource_id_resources"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_resources_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "scan_id",
            "resource_id",
            name=op.f("pk_scan_resources"),
        ),
    )
    op.create_index(
        "ix_scan_resources_resource_id",
        "scan_resources",
        ["resource_id"],
        unique=False,
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("finding_uuid", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.String(length=32), nullable=False),
        sa.Column("resource_id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column(
            "category",
            sa.Enum(
                "network",
                "storage",
                "identity",
                "logging",
                name="control_category",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.Enum(
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFO",
                name="finding_severity",
                native_enum=False,
                create_constraint=False,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("evidence", JSON_DOCUMENT, nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "OPEN",
                "ACKNOWLEDGED",
                "REMEDIATION_PROPOSED",
                "APPROVED",
                "RESOLVED",
                "FALSE_POSITIVE",
                name="finding_status",
                native_enum=False,
                create_constraint=False,
            ),
            server_default="OPEN",
            nullable=False,
        ),
        sa.Column("first_detected", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_detected", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "category IN ('network', 'storage', 'identity', 'logging')",
            name=op.f("ck_findings_control_category"),
        ),
        sa.CheckConstraint(
            "last_detected >= first_detected",
            name=op.f("ck_findings_detected_ordered"),
        ),
        sa.CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name=op.f("ck_findings_finding_severity"),
        ),
        sa.CheckConstraint(
            "status IN ('OPEN', 'ACKNOWLEDGED', 'REMEDIATION_PROPOSED', "
            "'APPROVED', 'RESOLVED', 'FALSE_POSITIVE')",
            name=op.f("ck_findings_finding_status"),
        ),
        sa.CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= last_detected",
            name=op.f("ck_findings_resolution_after_detection"),
        ),
        sa.ForeignKeyConstraint(
            ["resource_id"],
            ["resources.id"],
            name=op.f("fk_findings_resource_id_resources"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_findings_scan_id_scans"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "control_id",
            "resource_id",
            name="uq_findings_control_resource",
        ),
        sa.UniqueConstraint("finding_uuid", name=op.f("uq_findings_finding_uuid")),
    )
    op.create_index("ix_findings_resource_id", "findings", ["resource_id"], unique=False)
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index(
        "ix_findings_status_severity",
        "findings",
        ["status", "severity"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the initial persistence schema."""

    op.drop_index("ix_findings_status_severity", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_index("ix_findings_resource_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_scan_resources_resource_id", table_name="scan_resources")
    op.drop_table("scan_resources")
    op.drop_index("ix_resources_account_service_type", table_name="resources")
    op.drop_table("resources")
    op.drop_index("ix_scans_account_region_started", table_name="scans")
    op.drop_table("scans")
