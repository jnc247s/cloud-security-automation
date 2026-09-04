"""create canonical assessment history schema

Revision ID: 20260903_0001
Revises:
Create Date: 2026-09-03 23:35:49.998511
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

revision: str = "20260903_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_TABLES = (
    "assessment_profiles",
    "audit_events",
    "control_catalogs",
    "controls",
    "control_versions",
    "frameworks",
    "framework_references",
    "control_framework_mappings",
    "resources",
    "resource_snapshots",
    "scan_scope_manifests",
    "control_assessments",
    "evidence_artifacts",
    "finding_occurrences",
)

_SCAN_CHILD_TABLES = (
    "scan_scope_manifests",
    "resource_snapshots",
    "control_assessments",
    "evidence_artifacts",
    "finding_occurrences",
)

_INSERT_GUARD_TABLES = {
    "scan_starts_running": "scans",
    **{f"{table}_scan_running": table for table in _SCAN_CHILD_TABLES},
    "scope_provenance": "scan_scope_manifests",
    "assessment_provenance": "control_assessments",
    "snapshot_provenance": "resource_snapshots",
    "catalog_control_membership": "control_versions",
    "catalog_mapping_membership": "control_framework_mappings",
    "framework_reference_membership": "framework_references",
}


def _insert_guard(
    name: str,
    condition: str,
    message: str,
    *,
    locks: str = "",
    duplicate: str = "",
) -> None:
    """Install equivalent INSERT checks, with row locks on PostgreSQL.

    Existing catalog natural keys may reach ON CONFLICT DO NOTHING, whose
    conflict handling happens after BEFORE INSERT triggers. They do not change
    the historical graph, and the seeder separately verifies their content.
    """

    table = _INSERT_GUARD_TABLES[name]
    if op.get_bind().dialect.name == "postgresql":
        duplicate_return = f"IF {duplicate} THEN RETURN NEW; END IF;" if duplicate else ""
        op.execute(f"""
            CREATE FUNCTION guard_{name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                {duplicate_return}
                {locks}
                IF {condition} THEN
                    RAISE EXCEPTION '{message}' USING ERRCODE = '23000';
                END IF;
                RETURN NEW;
            END; $$
        """)
        op.execute(
            f"CREATE TRIGGER guard_{name} BEFORE INSERT ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION guard_{name}()"
        )
    elif op.get_bind().dialect.name == "sqlite":
        predicate = f"NOT ({duplicate}) AND ({condition})" if duplicate else condition
        op.execute(
            f"CREATE TRIGGER guard_{name} BEFORE INSERT ON {table} WHEN {predicate} "
            f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
        )


def _install_insert_guards() -> None:
    # Catalog/framework locks serialize first use against membership extension.
    # Always lock catalog before frameworks, in deterministic framework order.
    _insert_guard(
        "scan_starts_running",
        "NEW.status <> 'RUNNING'",
        "scan must start RUNNING",
        locks="""
            PERFORM catalog_id FROM control_catalogs
            WHERE catalog_key = NEW.control_catalog_id
              AND version = NEW.control_catalog_version FOR SHARE;
            PERFORM f.framework_id FROM frameworks f WHERE EXISTS (
                SELECT 1 FROM framework_references r
                JOIN control_framework_mappings m
                  ON m.framework_reference_id = r.framework_reference_id
                JOIN control_versions v ON v.control_version_id = m.control_version_id
                JOIN control_catalogs c ON c.catalog_id = v.catalog_id
                WHERE r.framework_id = f.framework_id
                  AND c.catalog_key = NEW.control_catalog_id
                  AND c.version = NEW.control_catalog_version
            ) ORDER BY f.framework_id FOR SHARE OF f;
        """,
    )
    for table in _SCAN_CHILD_TABLES:
        _insert_guard(
            f"{table}_scan_running",
            "NOT EXISTS (SELECT 1 FROM scans WHERE scan_id = NEW.scan_id AND status = 'RUNNING')",
            "scan children require a RUNNING scan",
            locks="PERFORM scan_id FROM scans WHERE scan_id = NEW.scan_id FOR SHARE;",
        )

    _insert_guard(
        "scope_provenance",
        """NOT EXISTS (
            SELECT 1 FROM scans s WHERE s.scan_id = NEW.scan_id
              AND s.aws_account_id = NEW.aws_account_id
              AND s.requested_regions = NEW.requested_regions
              AND s.successful_regions = NEW.successful_regions
              AND s.requested_services = NEW.requested_services
              AND s.assessment_profile_id = NEW.assessment_profile_id
              AND s.assessment_profile_version = NEW.assessment_profile_version
              AND s.assessment_profile_checksum = NEW.assessment_profile_checksum
              AND s.control_catalog_id = NEW.control_catalog_id
              AND s.control_catalog_version = NEW.control_catalog_version
        )""",
        "scope manifest provenance differs from scan",
        locks="PERFORM scan_id FROM scans WHERE scan_id = NEW.scan_id FOR SHARE;",
    )

    _insert_guard(
        "assessment_provenance",
        """NOT EXISTS (
            SELECT 1 FROM scans s
            JOIN assessment_profiles p ON p.profile_id = s.assessment_profile_id
                AND p.version = s.assessment_profile_version
                AND p.content_checksum = s.assessment_profile_checksum
            JOIN control_catalogs c ON c.catalog_key = s.control_catalog_id
                AND c.version = s.control_catalog_version
            JOIN control_versions v ON v.catalog_id = c.catalog_id
            WHERE s.scan_id = NEW.scan_id
              AND p.profile_version_id = NEW.assessment_profile_version_id
              AND v.control_version_id = NEW.control_version_id
              AND v.control_id = NEW.control_id
        )""",
        "assessment profile or catalog differs from scan",
        locks="PERFORM scan_id FROM scans WHERE scan_id = NEW.scan_id FOR SHARE;",
    )
    region_membership = (
        "EXISTS (SELECT 1 FROM jsonb_array_elements_text(s.requested_regions) region(value) "
        "WHERE region.value = NEW.region)"
        if op.get_bind().dialect.name == "postgresql"
        else "EXISTS (SELECT 1 FROM json_each(s.requested_regions) "
        "WHERE json_each.value = NEW.region)"
    )
    _insert_guard(
        "snapshot_provenance",
        f"""NOT EXISTS (
            SELECT 1 FROM resources r JOIN scans s ON s.scan_id = NEW.scan_id
            WHERE r.resource_id = NEW.resource_id
              AND r.aws_account_id = s.aws_account_id AND r.scope = NEW.scope
              AND ((r.scope = 'global' AND r.region = 'global' AND NEW.region IS NULL)
                OR (r.scope = 'regional' AND r.region = NEW.region
                    AND (r.service IN ('s3', 'cloudtrail') OR {region_membership})))
        )""",
        "snapshot account or scope differs from resource or scan",
        locks="PERFORM scan_id FROM scans WHERE scan_id = NEW.scan_id FOR SHARE;",
    )

    _insert_guard(
        "catalog_control_membership",
        """EXISTS (
            SELECT 1 FROM control_catalogs c JOIN scans s
              ON s.control_catalog_id = c.catalog_key AND s.control_catalog_version = c.version
            WHERE c.catalog_id = NEW.catalog_id
        )""",
        "referenced catalog membership is immutable",
        locks=(
            "PERFORM catalog_id FROM control_catalogs WHERE catalog_id = NEW.catalog_id FOR UPDATE;"
        ),
        duplicate="""EXISTS (SELECT 1 FROM control_versions
            WHERE catalog_id = NEW.catalog_id AND control_id = NEW.control_id)""",
    )
    _insert_guard(
        "catalog_mapping_membership",
        """EXISTS (
            SELECT 1 FROM control_versions v JOIN control_catalogs c ON c.catalog_id = v.catalog_id
            JOIN scans s ON s.control_catalog_id = c.catalog_key
                AND s.control_catalog_version = c.version
            WHERE v.control_version_id = NEW.control_version_id
        )""",
        "referenced catalog mappings are immutable",
        locks="""PERFORM c.catalog_id FROM control_catalogs c
            JOIN control_versions v ON v.catalog_id = c.catalog_id
            WHERE v.control_version_id = NEW.control_version_id FOR UPDATE OF c;""",
        duplicate="""EXISTS (SELECT 1 FROM control_framework_mappings
            WHERE control_version_id = NEW.control_version_id
              AND framework_reference_id = NEW.framework_reference_id)""",
    )
    _insert_guard(
        "framework_reference_membership",
        """EXISTS (
            SELECT 1 FROM framework_references r
            JOIN control_framework_mappings m
              ON m.framework_reference_id = r.framework_reference_id
            JOIN control_versions v ON v.control_version_id = m.control_version_id
            JOIN control_catalogs c ON c.catalog_id = v.catalog_id
            JOIN scans s ON s.control_catalog_id = c.catalog_key
                AND s.control_catalog_version = c.version
            WHERE r.framework_id = NEW.framework_id
        )""",
        "referenced framework membership is immutable",
        locks="""PERFORM framework_id FROM frameworks
            WHERE framework_id = NEW.framework_id FOR UPDATE;""",
        duplicate="""EXISTS (SELECT 1 FROM framework_references
            WHERE framework_id = NEW.framework_id AND reference_key = NEW.reference_key)""",
    )


def _install_history_guards() -> None:
    """Protect historical truth at the database boundary, including direct SQL."""

    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute("""
            CREATE FUNCTION reject_history_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
                RAISE EXCEPTION 'historical records are immutable' USING ERRCODE = '23000';
            END; $$
        """)
        for table in _IMMUTABLE_TABLES:
            op.execute(
                f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE OR TRUNCATE "
                f"ON {table} FOR EACH STATEMENT EXECUTE FUNCTION reject_history_mutation()"
            )
        op.execute("""
            CREATE FUNCTION reject_terminal_scan_mutation() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
                IF OLD.status <> 'RUNNING' THEN
                    RAISE EXCEPTION 'terminal scan records are immutable' USING ERRCODE = '23000';
                END IF;
                IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
                RETURN NEW;
            END; $$
        """)
        op.execute(
            "CREATE TRIGGER immutable_terminal_scans BEFORE UPDATE OR DELETE ON scans "
            "FOR EACH ROW EXECUTE FUNCTION reject_terminal_scan_mutation()"
        )
    elif dialect == "sqlite":
        for table in _IMMUTABLE_TABLES:
            for action in ("UPDATE", "DELETE"):
                op.execute(
                    f"CREATE TRIGGER immutable_{table}_{action.lower()} BEFORE {action} "
                    f"ON {table} BEGIN SELECT RAISE(ABORT, 'historical records are immutable'); END"
                )
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER immutable_terminal_scans_{action.lower()} BEFORE {action} "
                "ON scans WHEN OLD.status <> 'RUNNING' "
                "BEGIN SELECT RAISE(ABORT, 'terminal scan records are immutable'); END"
            )
    _install_insert_guards()


def _remove_history_guards() -> None:
    dialect = op.get_bind().dialect.name
    for name, table in _INSERT_GUARD_TABLES.items():
        if dialect == "postgresql":
            op.execute(f"DROP TRIGGER guard_{name} ON {table}")
            op.execute(f"DROP FUNCTION guard_{name}()")
        elif dialect == "sqlite":
            op.execute(f"DROP TRIGGER IF EXISTS guard_{name}")
    if dialect == "postgresql":
        for table in _IMMUTABLE_TABLES:
            op.execute(f"DROP TRIGGER immutable_{table} ON {table}")
        op.execute("DROP TRIGGER immutable_terminal_scans ON scans")
        op.execute("DROP FUNCTION reject_history_mutation()")
        op.execute("DROP FUNCTION reject_terminal_scan_mutation()")
    elif dialect == "sqlite":
        for table in (*_IMMUTABLE_TABLES, "terminal_scans"):
            for action in ("update", "delete"):
                op.execute(f"DROP TRIGGER IF EXISTS immutable_{table}_{action}")


def upgrade() -> None:
    """Apply this revision."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "assessment_profiles",
        sa.Column("profile_version_id", sa.Uuid(), nullable=False),
        sa.Column("profile_id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column(
            "enabled_controls",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "required_tags",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("stale_key_days", sa.Integer(), nullable=False),
        sa.Column(
            "approved_management_cidrs",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "public_ec2_exceptions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("restricted_data_requires_kms", sa.Boolean(), nullable=False),
        sa.Column("content_checksum", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(content_checksum) = 64", name=op.f("ck_assessment_profiles_checksum_length")
        ),
        sa.CheckConstraint(
            "length(trim(profile_id)) > 0", name=op.f("ck_assessment_profiles_profile_id_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(version)) > 0", name=op.f("ck_assessment_profiles_version_not_blank")
        ),
        sa.CheckConstraint(
            "stale_key_days >= 1", name=op.f("ck_assessment_profiles_stale_key_days_positive")
        ),
        sa.PrimaryKeyConstraint("profile_version_id", name=op.f("pk_assessment_profiles")),
        sa.UniqueConstraint("profile_id", "version", name="uq_assessment_profiles_profile_version"),
    )
    op.create_index(
        "ix_assessment_profiles_checksum", "assessment_profiles", ["content_checksum"], unique=False
    )
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column(
            "event_type",
            sa.Enum(
                "SCAN_STARTED",
                "SCAN_COMPLETED",
                "SCAN_FAILED",
                "FINDING_OPENED",
                "FINDING_UPDATED",
                "FINDING_REOPENED",
                "FINDING_ACKNOWLEDGED",
                "FINDING_RESOLVED",
                "FINDING_FALSE_POSITIVE",
                "FINDING_ACCEPTED_RISK",
                "EXCEPTION_CREATED",
                "EXCEPTION_EXPIRED",
                "EXCEPTION_REVOKED",
                name="audit_event_type",
                native_enum=False,
                create_constraint=True,
                length=64,
            ),
            nullable=False,
        ),
        sa.Column("actor_type", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=256), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(trim(actor_id)) > 0", name=op.f("ck_audit_events_actor_id_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(actor_type)) > 0", name=op.f("ck_audit_events_actor_type_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(target_type)) > 0", name=op.f("ck_audit_events_target_type_not_blank")
        ),
        sa.PrimaryKeyConstraint("event_id", name=op.f("pk_audit_events")),
    )
    op.create_index(
        "ix_audit_events_actor_time",
        "audit_events",
        ["actor_type", "actor_id", "timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_target_time",
        "audit_events",
        ["target_type", "target_id", "timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_audit_events_type_time", "audit_events", ["event_type", "timestamp"], unique=False
    )
    op.create_table(
        "control_catalogs",
        sa.Column("catalog_id", sa.Uuid(), nullable=False),
        sa.Column("catalog_key", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("content_checksum", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(content_checksum) = 64", name=op.f("ck_control_catalogs_checksum_length")
        ),
        sa.CheckConstraint(
            "length(trim(catalog_key)) > 0", name=op.f("ck_control_catalogs_catalog_key_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(version)) > 0", name=op.f("ck_control_catalogs_version_not_blank")
        ),
        sa.PrimaryKeyConstraint("catalog_id", name=op.f("pk_control_catalogs")),
        sa.UniqueConstraint("catalog_key", "version", name="uq_control_catalogs_key_version"),
    )
    op.create_table(
        "controls",
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("control_key", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(trim(control_key)) > 0", name=op.f("ck_controls_control_key_not_blank")
        ),
        sa.PrimaryKeyConstraint("control_id", name=op.f("pk_controls")),
        sa.UniqueConstraint("control_key", name=op.f("uq_controls_control_key")),
    )
    op.create_table(
        "frameworks",
        sa.Column("framework_id", sa.Uuid(), nullable=False),
        sa.Column("framework_key", sa.String(length=128), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("source_retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_checksum", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(source_checksum) = 64", name=op.f("ck_frameworks_checksum_length")
        ),
        sa.CheckConstraint(
            "length(trim(framework_key)) > 0", name=op.f("ck_frameworks_framework_key_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(version)) > 0", name=op.f("ck_frameworks_version_not_blank")
        ),
        sa.PrimaryKeyConstraint("framework_id", name=op.f("pk_frameworks")),
        sa.UniqueConstraint("framework_key", "version", name="uq_frameworks_key_version"),
    )
    op.create_table(
        "resources",
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("aws_account_id", sa.String(length=32), nullable=False),
        sa.Column("aws_resource_id", sa.Text(), nullable=False),
        sa.Column("arn", sa.Text(), nullable=True),
        sa.Column("service", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=128), nullable=False),
        sa.Column(
            "scope",
            sa.Enum(
                "global",
                "regional",
                name="resource_scope",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "(scope = 'regional' AND region <> 'global') OR "
            "(scope = 'global' AND region = 'global')",
            name=op.f("ck_resources_scope_region_consistent"),
        ),
        sa.CheckConstraint(
            "length(trim(aws_account_id)) > 0", name=op.f("ck_resources_account_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(aws_resource_id)) > 0", name=op.f("ck_resources_aws_resource_id_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(provider)) > 0", name=op.f("ck_resources_provider_not_blank")
        ),
        sa.CheckConstraint("length(trim(region)) > 0", name=op.f("ck_resources_region_not_blank")),
        sa.CheckConstraint(
            "length(trim(resource_type)) > 0", name=op.f("ck_resources_resource_type_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(service)) > 0", name=op.f("ck_resources_service_not_blank")
        ),
        sa.PrimaryKeyConstraint("resource_id", name=op.f("pk_resources")),
        sa.UniqueConstraint(
            "provider",
            "aws_account_id",
            "service",
            "resource_type",
            "scope",
            "region",
            "aws_resource_id",
            name="uq_resources_stable_identity",
        ),
    )
    op.create_index(
        "ix_resources_account_service_type",
        "resources",
        ["aws_account_id", "service", "resource_type", "scope", "region"],
        unique=False,
    )
    op.create_table(
        "control_versions",
        sa.Column("control_version_id", sa.Uuid(), nullable=False),
        sa.Column("catalog_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column(
            "category",
            sa.Enum(
                "network",
                "storage",
                "identity",
                "logging",
                name="control_category",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("resource_type", sa.String(length=128), nullable=False),
        sa.Column(
            "assessment_type",
            sa.Enum(
                "automated",
                name="assessment_type",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("measure", sa.Text(), nullable=False),
        sa.Column(
            "required_evidence",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("pass_logic", sa.Text(), nullable=False),
        sa.Column("fail_logic", sa.Text(), nullable=False),
        sa.Column("insufficient_evidence_behavior", sa.Text(), nullable=False),
        sa.Column("not_applicable_logic", sa.Text(), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFO",
                name="control_severity",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("remediation_guidance", sa.Text(), nullable=False),
        sa.Column(
            "profile_parameters",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "limitations",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("definition_checksum", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(definition_checksum) = 64", name=op.f("ck_control_versions_checksum_length")
        ),
        sa.CheckConstraint(
            "length(trim(resource_type)) > 0",
            name=op.f("ck_control_versions_resource_type_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(title)) > 0", name=op.f("ck_control_versions_title_not_blank")
        ),
        sa.ForeignKeyConstraint(
            ["catalog_id"],
            ["control_catalogs.catalog_id"],
            name=op.f("fk_control_versions_catalog_id_control_catalogs"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["control_id"],
            ["controls.control_id"],
            name=op.f("fk_control_versions_control_id_controls"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("control_version_id", name=op.f("pk_control_versions")),
        sa.UniqueConstraint("catalog_id", "control_id", name="uq_control_versions_catalog_control"),
        sa.UniqueConstraint(
            "control_version_id", "control_id", name="uq_control_versions_version_control"
        ),
    )
    op.create_index("ix_control_versions_control", "control_versions", ["control_id"], unique=False)
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("aws_account_id", sa.String(length=32), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "OPEN",
                "ACKNOWLEDGED",
                "RESOLVED",
                "FALSE_POSITIVE",
                "ACCEPTED_RISK",
                name="finding_status",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            server_default="OPEN",
            nullable=False,
        ),
        sa.Column("first_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(status = 'RESOLVED' AND resolved_at IS NOT NULL) OR "
            "(status <> 'RESOLVED' AND resolved_at IS NULL)",
            name=op.f("ck_findings_resolution_status_consistent"),
        ),
        sa.CheckConstraint(
            "last_detected_at >= first_detected_at", name=op.f("ck_findings_detected_ordered")
        ),
        sa.CheckConstraint("length(fingerprint) = 64", name=op.f("ck_findings_fingerprint_length")),
        sa.CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= last_detected_at",
            name=op.f("ck_findings_resolution_after_detection"),
        ),
        sa.ForeignKeyConstraint(
            ["control_id"],
            ["controls.control_id"],
            name=op.f("fk_findings_control_id_controls"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["resource_id"],
            ["resources.resource_id"],
            name=op.f("fk_findings_resource_id_resources"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("finding_id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "finding_id", "resource_id", "control_id", name="uq_findings_scope_identity"
        ),
        sa.UniqueConstraint("fingerprint", name="uq_findings_fingerprint"),
    )
    op.create_index(
        "ix_findings_account_status", "findings", ["aws_account_id", "status"], unique=False
    )
    op.create_index(
        "ix_findings_control_status", "findings", ["control_id", "status"], unique=False
    )
    op.create_index(
        "ix_findings_resource_status", "findings", ["resource_id", "status"], unique=False
    )
    op.create_table(
        "framework_references",
        sa.Column("framework_reference_id", sa.Uuid(), nullable=False),
        sa.Column("framework_id", sa.Uuid(), nullable=False),
        sa.Column("reference_key", sa.String(length=64), nullable=False),
        sa.Column(
            "level",
            sa.Enum(
                "function",
                "category",
                "subcategory",
                name="framework_reference_level",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("parent_reference_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "(level = 'function' AND parent_reference_id IS NULL) OR "
            "(level IN ('category', 'subcategory') AND parent_reference_id IS NOT NULL)",
            name=op.f("ck_framework_references_level_parent_consistent"),
        ),
        sa.CheckConstraint(
            "length(trim(reference_key)) > 0",
            name=op.f("ck_framework_references_reference_key_not_blank"),
        ),
        sa.CheckConstraint(
            "parent_reference_id IS NULL OR parent_reference_id <> framework_reference_id",
            name=op.f("ck_framework_references_parent_not_self"),
        ),
        sa.ForeignKeyConstraint(
            ["framework_id", "parent_reference_id"],
            ["framework_references.framework_id", "framework_references.framework_reference_id"],
            name="fk_framework_references_parent_same_framework",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["framework_id"],
            ["frameworks.framework_id"],
            name=op.f("fk_framework_references_framework_id_frameworks"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("framework_reference_id", name=op.f("pk_framework_references")),
        sa.UniqueConstraint(
            "framework_id", "framework_reference_id", name="uq_framework_references_framework_id"
        ),
        sa.UniqueConstraint(
            "framework_id", "reference_key", name="uq_framework_references_framework_key"
        ),
    )
    op.create_index(
        "ix_framework_references_framework_level",
        "framework_references",
        ["framework_id", "level"],
        unique=False,
    )
    op.create_table(
        "scans",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("aws_account_id", sa.String(length=32), nullable=False),
        sa.Column(
            "requested_regions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "successful_regions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "requested_services",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "successful_collectors",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "RUNNING",
                "COMPLETED",
                "PARTIAL",
                "FAILED",
                name="scan_status",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("scanner_version", sa.String(length=64), nullable=False),
        sa.Column("control_catalog_id", sa.String(length=128), nullable=False),
        sa.Column("control_catalog_version", sa.String(length=64), nullable=False),
        sa.Column("assessment_profile_id", sa.String(length=128), nullable=False),
        sa.Column("assessment_profile_version", sa.String(length=64), nullable=False),
        sa.Column("assessment_profile_checksum", sa.String(length=64), nullable=False),
        sa.Column("inventory_sha256", sa.String(length=64), nullable=False),
        sa.Column("result_checksum", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "(status = 'RUNNING' AND completed_at IS NULL) OR "
            "(status IN ('COMPLETED', 'PARTIAL', 'FAILED') AND completed_at IS NOT NULL)",
            name=op.f("ck_scans_lifecycle_timestamps_consistent"),
        ),
        sa.CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at",
            name=op.f("ck_scans_completion_after_start"),
        ),
        sa.CheckConstraint(
            "length(assessment_profile_checksum) = 64",
            name=op.f("ck_scans_assessment_profile_checksum_length"),
        ),
        sa.CheckConstraint(
            "length(inventory_sha256) = 64",
            name=op.f("ck_scans_inventory_sha256_length"),
        ),
        sa.CheckConstraint(
            "(status = 'RUNNING' AND result_checksum IS NULL) OR "
            "(status IN ('COMPLETED', 'PARTIAL', 'FAILED') AND result_checksum IS NOT NULL)",
            name=op.f("ck_scans_lifecycle_checksum_consistent"),
        ),
        sa.CheckConstraint(
            "result_checksum IS NULL OR length(result_checksum) = 64",
            name=op.f("ck_scans_result_checksum_length"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_profile_id", "assessment_profile_version"],
            ["assessment_profiles.profile_id", "assessment_profiles.version"],
            name="fk_scans_profile_version",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["control_catalog_id", "control_catalog_version"],
            ["control_catalogs.catalog_key", "control_catalogs.version"],
            name="fk_scans_catalog_version",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("scan_id", name=op.f("pk_scans")),
    )
    op.create_index(
        "ix_scans_account_started", "scans", ["aws_account_id", "started_at"], unique=False
    )
    op.create_index("ix_scans_status_started", "scans", ["status", "started_at"], unique=False)
    op.create_table(
        "control_framework_mappings",
        sa.Column("mapping_id", sa.Uuid(), nullable=False),
        sa.Column("control_version_id", sa.Uuid(), nullable=False),
        sa.Column("framework_reference_id", sa.Uuid(), nullable=False),
        sa.Column("mapping_rationale", sa.Text(), nullable=False),
        sa.Column("mapping_source", sa.Text(), nullable=False),
        sa.Column("mapping_source_version", sa.String(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mapping_checksum", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "length(mapping_checksum) = 64",
            name=op.f("ck_control_framework_mappings_checksum_length"),
        ),
        sa.CheckConstraint(
            "length(trim(mapping_rationale)) > 0",
            name=op.f("ck_control_framework_mappings_rationale_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(mapping_source)) > 0",
            name=op.f("ck_control_framework_mappings_source_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(mapping_source_version)) > 0",
            name=op.f("ck_control_framework_mappings_source_version_not_blank"),
        ),
        sa.ForeignKeyConstraint(
            ["control_version_id"],
            ["control_versions.control_version_id"],
            name=op.f("fk_control_framework_mappings_control_version_id_control_versions"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["framework_reference_id"],
            ["framework_references.framework_reference_id"],
            name=op.f("fk_control_framework_mappings_framework_reference_id_framework_references"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("mapping_id", name=op.f("pk_control_framework_mappings")),
        sa.UniqueConstraint(
            "control_version_id",
            "framework_reference_id",
            name="uq_control_framework_mappings_control_reference",
        ),
    )
    op.create_index(
        "ix_control_framework_mappings_reference",
        "control_framework_mappings",
        ["framework_reference_id"],
        unique=False,
    )
    op.create_table(
        "finding_exceptions",
        sa.Column("exception_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(length=256), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "ACTIVE",
                "EXPIRED",
                "REVOKED",
                name="exception_status",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            server_default="ACTIVE",
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(status = 'REVOKED' AND revoked_at IS NOT NULL) OR "
            "(status <> 'REVOKED' AND revoked_at IS NULL)",
            name=op.f("ck_finding_exceptions_revocation_status_consistent"),
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name=op.f("ck_finding_exceptions_expires_after_creation")
        ),
        sa.CheckConstraint(
            "length(trim(approved_by)) > 0",
            name=op.f("ck_finding_exceptions_approved_by_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(reason)) > 0", name=op.f("ck_finding_exceptions_reason_not_blank")
        ),
        sa.CheckConstraint(
            "revoked_at IS NULL OR revoked_at >= created_at",
            name=op.f("ck_finding_exceptions_revocation_after_creation"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "resource_id", "control_id"],
            ["findings.finding_id", "findings.resource_id", "findings.control_id"],
            name="fk_finding_exceptions_finding_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("exception_id", name=op.f("pk_finding_exceptions")),
    )
    op.create_index(
        "ix_finding_exceptions_scope_status",
        "finding_exceptions",
        ["resource_id", "control_id", "status"],
        unique=False,
    )
    op.create_index(
        "ix_finding_exceptions_status_expires",
        "finding_exceptions",
        ["status", "expires_at"],
        unique=False,
    )
    op.create_table(
        "resource_snapshots",
        sa.Column("snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column(
            "scope",
            sa.Enum(
                "global",
                "regional",
                name="resource_snapshot_scope",
                native_enum=False,
                create_constraint=True,
                length=16,
            ),
            nullable=False,
        ),
        sa.Column("region", sa.String(length=64), nullable=True),
        sa.Column("arn", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column(
            "tags",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "normalized_configuration",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("state_sha256", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(scope = 'regional' AND region IS NOT NULL) OR (scope = 'global' AND region IS NULL)",
            name=op.f("ck_resource_snapshots_scope_region_consistent"),
        ),
        sa.CheckConstraint(
            "length(state_sha256) = 64", name=op.f("ck_resource_snapshots_state_checksum_length")
        ),
        sa.CheckConstraint(
            "region IS NULL OR length(trim(region)) > 0",
            name=op.f("ck_resource_snapshots_region_not_blank"),
        ),
        sa.ForeignKeyConstraint(
            ["resource_id"],
            ["resources.resource_id"],
            name=op.f("fk_resource_snapshots_resource_id_resources"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.scan_id"],
            name=op.f("fk_resource_snapshots_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("snapshot_id", name=op.f("pk_resource_snapshots")),
        sa.UniqueConstraint("scan_id", "resource_id", name="uq_resource_snapshots_scan_resource"),
        sa.UniqueConstraint(
            "snapshot_id",
            "scan_id",
            "resource_id",
            name="uq_resource_snapshots_snapshot_scan_resource",
        ),
        sa.UniqueConstraint("snapshot_id", "scan_id", name="uq_resource_snapshots_snapshot_scan"),
    )
    op.create_index(
        "ix_resource_snapshots_resource_observed",
        "resource_snapshots",
        ["resource_id", "observed_at"],
        unique=False,
    )
    op.create_index("ix_resource_snapshots_scan", "resource_snapshots", ["scan_id"], unique=False)
    op.create_table(
        "scan_scope_manifests",
        sa.Column("manifest_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("aws_account_id", sa.String(length=32), nullable=False),
        sa.Column(
            "requested_regions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "successful_regions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "requested_services",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "requested_collectors",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "collector_outcomes",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "resource_types",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "enabled_controls",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("assessment_profile_id", sa.String(length=128), nullable=False),
        sa.Column("assessment_profile_version", sa.String(length=64), nullable=False),
        sa.Column("assessment_profile_checksum", sa.String(length=64), nullable=False),
        sa.Column("control_catalog_id", sa.String(length=128), nullable=False),
        sa.Column("control_catalog_version", sa.String(length=64), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "length(assessment_profile_checksum) = 64",
            name=op.f("ck_scan_scope_manifests_assessment_profile_checksum_length"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.scan_id"],
            name=op.f("fk_scan_scope_manifests_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("manifest_id", name=op.f("pk_scan_scope_manifests")),
        sa.UniqueConstraint("scan_id", name=op.f("uq_scan_scope_manifests_scan_id")),
    )
    op.create_index(
        "ix_scan_scope_manifests_account", "scan_scope_manifests", ["aws_account_id"], unique=False
    )
    op.create_table(
        "control_assessments",
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("resource_snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("control_version_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_profile_version_id", sa.Uuid(), nullable=False),
        sa.Column(
            "assessment_result",
            sa.Enum(
                "PASS",
                "FAIL",
                "INSUFFICIENT_EVIDENCE",
                "NOT_APPLICABLE",
                name="assessment_result",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "missing_evidence",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(trim(reason)) > 0", name=op.f("ck_control_assessments_reason_not_blank")
        ),
        sa.ForeignKeyConstraint(
            ["assessment_profile_version_id"],
            ["assessment_profiles.profile_version_id"],
            name=op.f("fk_control_assessments_assessment_profile_version_id_assessment_profiles"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["control_version_id", "control_id"],
            ["control_versions.control_version_id", "control_versions.control_id"],
            name="fk_control_assessments_version_control",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["resource_snapshot_id", "scan_id", "resource_id"],
            [
                "resource_snapshots.snapshot_id",
                "resource_snapshots.scan_id",
                "resource_snapshots.resource_id",
            ],
            name="fk_control_assessments_snapshot_scan",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.scan_id"],
            name=op.f("fk_control_assessments_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("assessment_id", name=op.f("pk_control_assessments")),
        sa.UniqueConstraint(
            "assessment_id",
            "scan_id",
            "resource_snapshot_id",
            "control_version_id",
            "control_id",
            name="uq_control_assessments_evidence_identity",
        ),
        sa.UniqueConstraint(
            "assessment_id",
            "scan_id",
            "resource_snapshot_id",
            "resource_id",
            "control_version_id",
            "control_id",
            "assessment_result",
            name="uq_control_assessments_occurrence_identity",
        ),
        sa.UniqueConstraint(
            "scan_id",
            "resource_snapshot_id",
            "control_version_id",
            name="uq_control_assessments_scan_snapshot_control",
        ),
    )
    op.create_index(
        "ix_control_assessments_control_result",
        "control_assessments",
        ["control_id", "assessment_result"],
        unique=False,
    )
    op.create_index(
        "ix_control_assessments_scan_result",
        "control_assessments",
        ["scan_id", "assessment_result"],
        unique=False,
    )
    op.create_index(
        "ix_control_assessments_snapshot",
        "control_assessments",
        ["resource_snapshot_id"],
        unique=False,
    )
    op.create_table(
        "evidence_artifacts",
        sa.Column("evidence_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("resource_snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("control_version_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("collector", sa.String(length=128), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("source_api", sa.Text(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_name", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.Column("evidence_key", sa.String(length=128), nullable=False),
        sa.Column(
            "payload",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(payload_sha256) = 64", name=op.f("ck_evidence_artifacts_payload_sha256_length")
        ),
        sa.CheckConstraint(
            "length(trim(collector)) > 0", name=op.f("ck_evidence_artifacts_collector_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(evidence_key)) > 0",
            name=op.f("ck_evidence_artifacts_evidence_key_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(schema_name)) > 0",
            name=op.f("ck_evidence_artifacts_schema_name_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(schema_version)) > 0",
            name=op.f("ck_evidence_artifacts_schema_version_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(source)) > 0", name=op.f("ck_evidence_artifacts_source_not_blank")
        ),
        sa.CheckConstraint(
            "length(trim(source_api)) > 0", name=op.f("ck_evidence_artifacts_source_api_not_blank")
        ),
        sa.ForeignKeyConstraint(
            [
                "assessment_id",
                "scan_id",
                "resource_snapshot_id",
                "control_version_id",
                "control_id",
            ],
            [
                "control_assessments.assessment_id",
                "control_assessments.scan_id",
                "control_assessments.resource_snapshot_id",
                "control_assessments.control_version_id",
                "control_assessments.control_id",
            ],
            name="fk_evidence_artifacts_assessment_provenance",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("evidence_id", name=op.f("pk_evidence_artifacts")),
        sa.UniqueConstraint(
            "assessment_id", "evidence_key", name="uq_evidence_artifacts_assessment_key"
        ),
    )
    op.create_index(
        "ix_evidence_artifacts_payload_sha256",
        "evidence_artifacts",
        ["payload_sha256"],
        unique=False,
    )
    op.create_index("ix_evidence_artifacts_scan", "evidence_artifacts", ["scan_id"], unique=False)
    op.create_index(
        "ix_evidence_artifacts_snapshot",
        "evidence_artifacts",
        ["resource_snapshot_id"],
        unique=False,
    )
    op.create_table(
        "finding_occurrences",
        sa.Column("occurrence_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("resource_snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("resource_id", sa.Uuid(), nullable=False),
        sa.Column("control_version_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column(
            "assessment_result",
            sa.Enum(
                "PASS",
                "FAIL",
                "INSUFFICIENT_EVIDENCE",
                "NOT_APPLICABLE",
                name="finding_occurrence_assessment_result",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            server_default="FAIL",
            nullable=False,
        ),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "assessment_result = 'FAIL'", name=op.f("ck_finding_occurrences_assessment_must_fail")
        ),
        sa.ForeignKeyConstraint(
            [
                "assessment_id",
                "scan_id",
                "resource_snapshot_id",
                "resource_id",
                "control_version_id",
                "control_id",
                "assessment_result",
            ],
            [
                "control_assessments.assessment_id",
                "control_assessments.scan_id",
                "control_assessments.resource_snapshot_id",
                "control_assessments.resource_id",
                "control_assessments.control_version_id",
                "control_assessments.control_id",
                "control_assessments.assessment_result",
            ],
            name="fk_finding_occurrences_failed_assessment",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "resource_id", "control_id"],
            ["findings.finding_id", "findings.resource_id", "findings.control_id"],
            name="fk_finding_occurrences_finding_scope",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("occurrence_id", name=op.f("pk_finding_occurrences")),
        sa.UniqueConstraint("assessment_id", name="uq_finding_occurrences_assessment"),
    )
    op.create_index(
        "ix_finding_occurrences_finding_detected",
        "finding_occurrences",
        ["finding_id", "detected_at"],
        unique=False,
    )
    op.create_index("ix_finding_occurrences_scan", "finding_occurrences", ["scan_id"], unique=False)
    _install_history_guards()
    # ### end Alembic commands ###


def downgrade() -> None:
    """Revert this revision."""
    _remove_history_guards()
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index("ix_finding_occurrences_scan", table_name="finding_occurrences")
    op.drop_index("ix_finding_occurrences_finding_detected", table_name="finding_occurrences")
    op.drop_table("finding_occurrences")
    op.drop_index("ix_evidence_artifacts_snapshot", table_name="evidence_artifacts")
    op.drop_index("ix_evidence_artifacts_scan", table_name="evidence_artifacts")
    op.drop_index("ix_evidence_artifacts_payload_sha256", table_name="evidence_artifacts")
    op.drop_table("evidence_artifacts")
    op.drop_index("ix_control_assessments_snapshot", table_name="control_assessments")
    op.drop_index("ix_control_assessments_scan_result", table_name="control_assessments")
    op.drop_index("ix_control_assessments_control_result", table_name="control_assessments")
    op.drop_table("control_assessments")
    op.drop_index("ix_scan_scope_manifests_account", table_name="scan_scope_manifests")
    op.drop_table("scan_scope_manifests")
    op.drop_index("ix_resource_snapshots_scan", table_name="resource_snapshots")
    op.drop_index("ix_resource_snapshots_resource_observed", table_name="resource_snapshots")
    op.drop_table("resource_snapshots")
    op.drop_index("ix_finding_exceptions_status_expires", table_name="finding_exceptions")
    op.drop_index("ix_finding_exceptions_scope_status", table_name="finding_exceptions")
    op.drop_table("finding_exceptions")
    op.drop_index(
        "ix_control_framework_mappings_reference", table_name="control_framework_mappings"
    )
    op.drop_table("control_framework_mappings")
    op.drop_index("ix_scans_status_started", table_name="scans")
    op.drop_index("ix_scans_account_started", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_framework_references_framework_level", table_name="framework_references")
    op.drop_table("framework_references")
    op.drop_index("ix_findings_resource_status", table_name="findings")
    op.drop_index("ix_findings_control_status", table_name="findings")
    op.drop_index("ix_findings_account_status", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_control_versions_control", table_name="control_versions")
    op.drop_table("control_versions")
    op.drop_index("ix_resources_account_service_type", table_name="resources")
    op.drop_table("resources")
    op.drop_table("frameworks")
    op.drop_table("controls")
    op.drop_table("control_catalogs")
    op.drop_index("ix_audit_events_type_time", table_name="audit_events")
    op.drop_index("ix_audit_events_target_time", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_time", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_assessment_profiles_checksum", table_name="assessment_profiles")
    op.drop_table("assessment_profiles")
    # ### end Alembic commands ###
