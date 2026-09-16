"""add the Sprint 5 evidence graph persistence foundation

Revision ID: 20260915_0003
Revises: 20260904_0002
Create Date: 2026-09-15 12:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260915_0003"
down_revision: str | None = "20260904_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GRAPH_TABLES = (
    "scan_source_contracts",
    "source_evidence_artifacts",
    "source_evidence_outcomes",
    "resource_relationship_observations",
)


def _json_document_type() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _drop_trigger(name: str, table: str) -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(f"DROP TRIGGER IF EXISTS {name} ON {table}")
        op.execute(f"DROP FUNCTION IF EXISTS {name}()")
    elif dialect == "sqlite":
        op.execute(f"DROP TRIGGER IF EXISTS {name}")


def _install_running_guard(table: str) -> None:
    name = f"guard_{table}_scan_running"
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(f"""
            CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                PERFORM scan_id FROM scans WHERE scan_id = NEW.scan_id FOR SHARE;
                IF NOT EXISTS (
                    SELECT 1 FROM scans
                    WHERE scan_id = NEW.scan_id AND status = 'RUNNING'
                ) THEN
                    RAISE EXCEPTION 'scan children require a RUNNING scan'
                        USING ERRCODE = '23000';
                END IF;
                RETURN NEW;
            END; $$
        """)
        op.execute(
            f"CREATE TRIGGER {name} BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION {name}()"
        )
    elif dialect == "sqlite":
        op.execute(
            f"CREATE TRIGGER {name} BEFORE INSERT ON {table} WHEN NOT EXISTS ("
            "SELECT 1 FROM scans WHERE scan_id = NEW.scan_id AND status = 'RUNNING') "
            "BEGIN SELECT RAISE(ABORT, 'scan children require a RUNNING scan'); END"
        )


def _install_immutable_guard(table: str) -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        name = f"immutable_{table}"
        op.execute(f"""
            CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                RAISE EXCEPTION 'historical records are immutable' USING ERRCODE = '23000';
            END; $$
        """)
        op.execute(
            f"CREATE TRIGGER {name} BEFORE UPDATE OR DELETE OR TRUNCATE ON {table} "
            f"FOR EACH STATEMENT EXECUTE FUNCTION {name}()"
        )
    elif dialect == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER immutable_{table}_{action.lower()} BEFORE {action} ON {table} "
                "BEGIN SELECT RAISE(ABORT, 'historical records are immutable'); END"
            )


def _drop_graph_guards() -> None:
    dialect = op.get_bind().dialect.name
    for table in _GRAPH_TABLES:
        _drop_trigger(f"guard_{table}_scan_running", table)
        if dialect == "postgresql":
            _drop_trigger(f"immutable_{table}", table)
        elif dialect == "sqlite":
            for action in ("update", "delete"):
                op.execute(f"DROP TRIGGER IF EXISTS immutable_{table}_{action}")
    for name, table in (
        ("guard_scan_source_contracts_provenance", "scan_source_contracts"),
        ("guard_source_evidence_artifacts_provenance", "source_evidence_artifacts"),
        ("guard_source_evidence_outcomes_provenance", "source_evidence_outcomes"),
        ("guard_resource_relationships_provenance", "resource_relationship_observations"),
        ("guard_evidence_graph_terminalization", "scans"),
    ):
        _drop_trigger(name, table)


def _install_provenance_guard(
    *,
    name: str,
    table: str,
    invalid_condition: str,
    message: str,
) -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute(f"""
            CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                IF {invalid_condition} THEN
                    RAISE EXCEPTION '{message}' USING ERRCODE = '23000';
                END IF;
                RETURN NEW;
            END; $$
        """)
        op.execute(
            f"CREATE TRIGGER {name} BEFORE INSERT ON {table} FOR EACH ROW EXECUTE FUNCTION {name}()"
        )
    elif dialect == "sqlite":
        op.execute(
            f"CREATE TRIGGER {name} BEFORE INSERT ON {table} WHEN {invalid_condition} "
            f"BEGIN SELECT RAISE(ABORT, '{message}'); END"
        )


def _install_graph_guards() -> None:
    for table in _GRAPH_TABLES:
        _install_running_guard(table)
        _install_immutable_guard(table)

    _install_provenance_guard(
        name="guard_scan_source_contracts_provenance",
        table="scan_source_contracts",
        invalid_condition="""NOT EXISTS (
            SELECT 1 FROM scans s WHERE s.scan_id = NEW.scan_id
              AND s.aws_account_id = NEW.collection_account_id
        )""",
        message="source contract collection account differs from scan",
    )
    _install_provenance_guard(
        name="guard_source_evidence_artifacts_provenance",
        table="source_evidence_artifacts",
        invalid_condition="""NOT EXISTS (
            SELECT 1 FROM scans s WHERE s.scan_id = NEW.scan_id
              AND s.aws_account_id = NEW.collection_account_id
        )""",
        message="source artifact collection account differs from scan",
    )
    _install_provenance_guard(
        name="guard_source_evidence_outcomes_provenance",
        table="source_evidence_outcomes",
        invalid_condition="""NOT EXISTS (
            SELECT 1 FROM scan_source_contracts c
            JOIN source_evidence_artifacts a
              ON a.artifact_id = NEW.artifact_id
             AND a.scan_id = NEW.scan_id
             AND a.evidence_reference = NEW.evidence_reference
             AND a.evidence_sha256 = NEW.evidence_sha256
            WHERE c.source_outcome_id = NEW.source_outcome_id
              AND c.scan_id = NEW.scan_id
              AND c.collection_account_id = NEW.collection_account_id
              AND a.collection_account_id = NEW.collection_account_id
              AND c.phase = NEW.phase
              AND c.evidence_kind = NEW.evidence_kind
              AND c.collector = NEW.collector
              AND c.collector_version = NEW.collector_version
              AND c.source_api = NEW.source_api
        )""",
        message="source outcome provenance differs from contract or artifact",
    )
    _install_provenance_guard(
        name="guard_resource_relationships_provenance",
        table="resource_relationship_observations",
        invalid_condition="""NOT EXISTS (
            SELECT 1 FROM source_evidence_outcomes o
            WHERE o.source_outcome_id = NEW.source_outcome_id
              AND o.scan_id = NEW.scan_id
              AND o.collection_account_id = NEW.collection_account_id
              AND o.state = 'PRESENT'
              AND o.collector = NEW.provenance_collector
              AND o.collector_version = NEW.provenance_collector_version
              AND o.source = NEW.provenance_source
              AND o.source_api = NEW.provenance_source_api
              AND o.evidence_reference = NEW.evidence_reference
              AND o.collected_at = NEW.collected_at
        )""",
        message="relationship provenance requires its PRESENT source outcome",
    )

    dialect = op.get_bind().dialect.name
    graph_rows_exist = """(
        EXISTS (SELECT 1 FROM scan_source_contracts c WHERE c.scan_id = NEW.scan_id)
        OR EXISTS (SELECT 1 FROM source_evidence_artifacts a WHERE a.scan_id = NEW.scan_id)
        OR EXISTS (SELECT 1 FROM source_evidence_outcomes o WHERE o.scan_id = NEW.scan_id)
        OR EXISTS (
            SELECT 1 FROM resource_relationship_observations r WHERE r.scan_id = NEW.scan_id
        )
    )"""
    missing_graph = f"""(
      ({graph_rows_exist} AND NOT EXISTS (
        SELECT 1 FROM scan_scope_manifests m WHERE m.scan_id = NEW.scan_id
      )) OR EXISTS (
        SELECT 1 FROM scan_scope_manifests m
        WHERE m.scan_id = NEW.scan_id
          AND (
            (m.source_manifest_schema_version IS NULL) <>
              (m.source_manifest_checksum IS NULL)
            OR (m.source_manifest_checksum IS NOT NULL
                AND length(m.source_manifest_checksum) <> 64)
            OR (m.source_manifest_schema_version IS NULL AND (
                EXISTS (SELECT 1 FROM scan_source_contracts c WHERE c.scan_id = NEW.scan_id)
                OR EXISTS (
                    SELECT 1 FROM source_evidence_artifacts a WHERE a.scan_id = NEW.scan_id
                )
                OR EXISTS (
                    SELECT 1 FROM source_evidence_outcomes o WHERE o.scan_id = NEW.scan_id
                )
                OR EXISTS (
                    SELECT 1 FROM resource_relationship_observations r
                    WHERE r.scan_id = NEW.scan_id
                )
            ))
            OR (m.source_manifest_schema_version IS NOT NULL AND (
                NOT EXISTS (
                    SELECT 1 FROM scan_source_contracts c WHERE c.scan_id = NEW.scan_id
                )
                OR EXISTS (
                    SELECT 1 FROM scan_source_contracts c
                    WHERE c.scan_id = NEW.scan_id AND NOT EXISTS (
                        SELECT 1 FROM source_evidence_outcomes o
                        WHERE o.scan_id = c.scan_id
                          AND o.source_outcome_id = c.source_outcome_id
                    )
                )
                OR EXISTS (
                    SELECT 1 FROM source_evidence_artifacts a
                    WHERE a.scan_id = NEW.scan_id AND NOT EXISTS (
                        SELECT 1 FROM source_evidence_outcomes o
                        WHERE o.scan_id = a.scan_id AND o.artifact_id = a.artifact_id
                    )
                )
            ))
          )
    ))"""
    if dialect == "postgresql":
        op.execute(f"""
            CREATE FUNCTION guard_evidence_graph_terminalization() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
                IF OLD.status = 'RUNNING' AND NEW.status <> 'RUNNING' AND {missing_graph} THEN
                    RAISE EXCEPTION 'terminal scan evidence graph is incomplete'
                        USING ERRCODE = '23000';
                END IF;
                RETURN NEW;
            END; $$
        """)
        op.execute(
            "CREATE TRIGGER guard_evidence_graph_terminalization "
            "BEFORE UPDATE OF status ON scans FOR EACH ROW "
            "EXECUTE FUNCTION guard_evidence_graph_terminalization()"
        )
    elif dialect == "sqlite":
        op.execute(
            "CREATE TRIGGER guard_evidence_graph_terminalization BEFORE UPDATE OF status ON scans "
            f"WHEN OLD.status = 'RUNNING' AND NEW.status <> 'RUNNING' AND {missing_graph} "
            "BEGIN SELECT RAISE(ABORT, 'terminal scan evidence graph is incomplete'); END"
        )


def _drop_snapshot_provenance_guard() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute("DROP TRIGGER guard_snapshot_provenance ON resource_snapshots")
        op.execute("DROP FUNCTION guard_snapshot_provenance()")
    elif dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS guard_snapshot_provenance")


def _install_snapshot_provenance_guard(*, graph_aware: bool) -> None:
    dialect = op.get_bind().dialect.name
    region_membership = (
        "EXISTS (SELECT 1 FROM jsonb_array_elements_text(s.requested_regions) region(value) "
        "WHERE region.value = NEW.region)"
        if dialect == "postgresql"
        else "EXISTS (SELECT 1 FROM json_each(s.requested_regions) "
        "WHERE json_each.value = NEW.region)"
    )
    if graph_aware:
        owner_admission = """(
            r.aws_account_id = s.aws_account_id OR (
                r.aws_account_id = 'aws'
                AND r.service = 'iam'
                AND r.resource_type IN (
                    'iam_aws_managed_policy', 'iam_managed_policy_version'
                )
                AND EXISTS (
                    SELECT 1 FROM scan_source_contracts contract
                    JOIN source_evidence_outcomes outcome
                      ON outcome.source_outcome_id = contract.source_outcome_id
                     AND outcome.scan_id = contract.scan_id
                    WHERE contract.scan_id = NEW.scan_id
                      AND contract.owner_mode = 'AWS_MANAGED'
                      AND contract.identity_authoritative
                      AND contract.subject_resource_snapshot_id = NEW.snapshot_id
                      AND contract.subject_resource_id = NEW.resource_id
                      AND outcome.state = 'PRESENT'
                )
            ) OR (
                r.aws_account_id <> 'aws'
                AND length(r.aws_account_id) = 12
                AND EXISTS (
                    SELECT 1 FROM scan_source_contracts contract
                    JOIN source_evidence_outcomes outcome
                      ON outcome.source_outcome_id = contract.source_outcome_id
                     AND outcome.scan_id = contract.scan_id
                    WHERE contract.scan_id = NEW.scan_id
                      AND contract.owner_mode = 'EXTERNAL_ACCOUNT'
                      AND contract.identity_authoritative
                      AND contract.subject_resource_snapshot_id = NEW.snapshot_id
                      AND contract.subject_resource_id = NEW.resource_id
                      AND outcome.state = 'PRESENT'
                )
                AND EXISTS (
                    SELECT 1 FROM resource_relationship_observations rel
                    WHERE rel.scan_id = NEW.scan_id
                      AND rel.resolution = 'RESOLVED'
                      AND (
                        (rel.source_resource_snapshot_id = NEW.snapshot_id
                         AND rel.source_resource_id = NEW.resource_id)
                        OR (rel.target_resource_snapshot_id = NEW.snapshot_id
                            AND rel.target_resource_id = NEW.resource_id)
                      )
                )
            )
        )"""
        region_admission = f"""(
            r.scope = 'global' AND r.region = 'global' AND NEW.region IS NULL
        ) OR (
            r.scope = 'regional' AND r.region = NEW.region AND (
                {region_membership}
                OR r.service IN ('s3', 'cloudtrail')
                OR EXISTS (
                    SELECT 1 FROM scan_source_contracts contract
                    JOIN source_evidence_outcomes outcome
                      ON outcome.source_outcome_id = contract.source_outcome_id
                     AND outcome.scan_id = contract.scan_id
                    WHERE contract.scan_id = NEW.scan_id
                      AND contract.allows_supplemental_region
                      AND outcome.state = 'PRESENT'
                      AND contract.subject_resource_snapshot_id = NEW.snapshot_id
                      AND contract.subject_resource_id = NEW.resource_id
                )
            )
        )"""
        condition = f"""NOT EXISTS (
            SELECT 1 FROM resources r JOIN scans s ON s.scan_id = NEW.scan_id
            WHERE r.resource_id = NEW.resource_id
              AND {owner_admission}
              AND r.scope = NEW.scope
              AND ({region_admission})
        )"""
    else:
        condition = f"""NOT EXISTS (
            SELECT 1 FROM resources r JOIN scans s ON s.scan_id = NEW.scan_id
            WHERE r.resource_id = NEW.resource_id
              AND r.aws_account_id = s.aws_account_id AND r.scope = NEW.scope
              AND ((r.scope = 'global' AND r.region = 'global' AND NEW.region IS NULL)
                OR (r.scope = 'regional' AND r.region = NEW.region
                    AND (r.service IN ('s3', 'cloudtrail') OR {region_membership})))
        )"""
    if dialect == "postgresql":
        op.execute(f"""
            CREATE FUNCTION guard_snapshot_provenance() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
                PERFORM scan_id FROM scans WHERE scan_id = NEW.scan_id FOR SHARE;
                IF {condition} THEN
                    RAISE EXCEPTION 'snapshot owner or scope differs from admitted scan evidence'
                        USING ERRCODE = '23000';
                END IF;
                RETURN NEW;
            END; $$
        """)
        op.execute(
            "CREATE TRIGGER guard_snapshot_provenance BEFORE INSERT ON resource_snapshots "
            "FOR EACH ROW EXECUTE FUNCTION guard_snapshot_provenance()"
        )
    elif dialect == "sqlite":
        op.execute(
            "CREATE TRIGGER guard_snapshot_provenance BEFORE INSERT ON resource_snapshots "
            f"WHEN {condition} BEGIN SELECT RAISE(ABORT, "
            "'snapshot owner or scope differs from admitted scan evidence'); END"
        )


def _drop_manifest_columns() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "sqlite":
        # SQLite rebuilds a table for DROP COLUMN. Its table-local triggers must
        # be restored explicitly after the swap.
        for name in (
            "guard_scan_scope_manifests_scan_running",
            "guard_scope_provenance",
            "immutable_scan_scope_manifests_update",
            "immutable_scan_scope_manifests_delete",
        ):
            op.execute(f"DROP TRIGGER IF EXISTS {name}")
        with op.batch_alter_table("scan_scope_manifests") as batch_op:
            batch_op.drop_column("source_manifest_checksum")
            batch_op.drop_column("source_manifest_schema_version")
        op.execute("""
            CREATE TRIGGER guard_scan_scope_manifests_scan_running
            BEFORE INSERT ON scan_scope_manifests
            WHEN NOT EXISTS (
                SELECT 1 FROM scans WHERE scan_id = NEW.scan_id AND status = 'RUNNING'
            ) BEGIN SELECT RAISE(ABORT, 'scan children require a RUNNING scan'); END
        """)
        op.execute("""
            CREATE TRIGGER guard_scope_provenance BEFORE INSERT ON scan_scope_manifests
            WHEN NOT EXISTS (
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
            ) BEGIN SELECT RAISE(ABORT, 'scope manifest provenance differs from scan'); END
        """)
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER immutable_scan_scope_manifests_{action.lower()} "
                f"BEFORE {action} ON scan_scope_manifests "
                "BEGIN SELECT RAISE(ABORT, 'historical records are immutable'); END"
            )
        return
    op.drop_column("scan_scope_manifests", "source_manifest_checksum")
    op.drop_column("scan_scope_manifests", "source_manifest_schema_version")


def upgrade() -> None:
    """Create the append-only generic evidence graph."""

    op.add_column(
        "scan_scope_manifests",
        sa.Column("source_manifest_schema_version", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "scan_scope_manifests",
        sa.Column("source_manifest_checksum", sa.String(length=64), nullable=True),
    )

    op.create_table(
        "scan_source_contracts",
        sa.Column("source_outcome_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("collection_account_id", sa.String(length=32), nullable=False),
        sa.Column("contract_key", sa.String(length=128), nullable=False),
        sa.Column("contract_version", sa.String(length=64), nullable=False),
        sa.Column("phase", sa.String(length=16), nullable=False),
        sa.Column("subject_kind", sa.String(length=16), nullable=False),
        sa.Column("subject", _json_document_type(), nullable=False),
        sa.Column("subject_resource_id", sa.Uuid(), nullable=True),
        sa.Column("subject_resource_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("evidence_kind", sa.String(length=128), nullable=False),
        sa.Column("collector", sa.String(length=128), nullable=False),
        sa.Column("collector_version", sa.String(length=64), nullable=False),
        sa.Column("source_api", sa.String(length=128), nullable=False),
        sa.Column("cardinality", sa.String(length=16), nullable=False),
        sa.Column("owner_mode", sa.String(length=32), nullable=False),
        sa.Column("identity_authoritative", sa.Boolean(), nullable=False),
        sa.Column("allows_supplemental_region", sa.Boolean(), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "phase IN ('DISCOVERY', 'ENRICHMENT')",
            name=op.f("ck_scan_source_contracts_phase"),
        ),
        sa.CheckConstraint(
            "cardinality IN ('SINGLE', 'COLLECTION')",
            name=op.f("ck_scan_source_contracts_cardinality"),
        ),
        sa.CheckConstraint(
            "owner_mode IN ('COLLECTION_ACCOUNT', 'AWS_MANAGED', 'EXTERNAL_ACCOUNT')",
            name=op.f("ck_scan_source_contracts_owner_mode"),
        ),
        sa.CheckConstraint(
            "length(collection_account_id) = 12",
            name=op.f("ck_scan_source_contracts_collection_account_length"),
        ),
        sa.CheckConstraint(
            "length(trim(contract_key)) > 0",
            name=op.f("ck_scan_source_contracts_contract_key_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(contract_version)) > 0",
            name=op.f("ck_scan_source_contracts_contract_version_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(evidence_kind)) > 0",
            name=op.f("ck_scan_source_contracts_evidence_kind_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(collector)) > 0",
            name=op.f("ck_scan_source_contracts_collector_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(collector_version)) > 0",
            name=op.f("ck_scan_source_contracts_collector_version_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(source_api)) > 0",
            name=op.f("ck_scan_source_contracts_source_api_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(schema_version)) > 0",
            name=op.f("ck_scan_source_contracts_schema_version_not_blank"),
        ),
        sa.CheckConstraint(
            "(phase = 'DISCOVERY' AND subject_kind = 'account' "
            "AND subject_resource_id IS NULL AND subject_resource_snapshot_id IS NULL) OR "
            "(phase = 'ENRICHMENT' AND subject_kind = 'resource' "
            "AND subject_resource_id IS NOT NULL "
            "AND subject_resource_snapshot_id IS NOT NULL)",
            name=op.f("ck_scan_source_contracts_phase_subject_consistent"),
        ),
        sa.CheckConstraint(
            "owner_mode = 'COLLECTION_ACCOUNT' OR identity_authoritative",
            name=op.f("ck_scan_source_contracts_exceptional_owner_requires_authority"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.scan_id"],
            name=op.f("fk_scan_source_contracts_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
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
        sa.PrimaryKeyConstraint("source_outcome_id", name=op.f("pk_scan_source_contracts")),
        sa.UniqueConstraint(
            "source_outcome_id", "scan_id", name="uq_scan_source_contracts_outcome_scan"
        ),
    )
    op.create_index(
        "ix_scan_source_contracts_scan", "scan_source_contracts", ["scan_id"], unique=False
    )
    op.create_index(
        "ix_scan_source_contracts_contract",
        "scan_source_contracts",
        ["contract_key", "contract_version"],
        unique=False,
    )

    op.create_table(
        "source_evidence_artifacts",
        sa.Column("artifact_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("collection_account_id", sa.String(length=32), nullable=False),
        sa.Column("evidence_reference", sa.String(length=512), nullable=False),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=False),
        sa.Column("evidence_schema", sa.String(length=128), nullable=False),
        sa.Column("evidence_schema_version", sa.String(length=64), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("normalized_payload", _json_document_type(), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(collection_account_id) = 12",
            name=op.f("ck_source_evidence_artifacts_collection_account_length"),
        ),
        sa.CheckConstraint(
            "length(trim(evidence_reference)) > 0",
            name=op.f("ck_source_evidence_artifacts_reference_not_blank"),
        ),
        sa.CheckConstraint(
            "length(evidence_sha256) = 64",
            name=op.f("ck_source_evidence_artifacts_evidence_sha256_length"),
        ),
        sa.CheckConstraint(
            "length(trim(evidence_schema)) > 0",
            name=op.f("ck_source_evidence_artifacts_evidence_schema_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(evidence_schema_version)) > 0",
            name=op.f("ck_source_evidence_artifacts_evidence_schema_version_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(schema_version)) > 0",
            name=op.f("ck_source_evidence_artifacts_schema_version_not_blank"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.scan_id"],
            name=op.f("fk_source_evidence_artifacts_scan_id_scans"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("artifact_id", name=op.f("pk_source_evidence_artifacts")),
        sa.UniqueConstraint(
            "artifact_id", "scan_id", name="uq_source_evidence_artifacts_artifact_scan"
        ),
        sa.UniqueConstraint(
            "scan_id",
            "evidence_reference",
            name="uq_source_evidence_artifacts_scan_reference",
        ),
        sa.UniqueConstraint(
            "artifact_id",
            "scan_id",
            "evidence_reference",
            "evidence_sha256",
            name="uq_source_evidence_artifacts_outcome_reference",
        ),
    )
    op.create_index(
        "ix_source_evidence_artifacts_scan",
        "source_evidence_artifacts",
        ["scan_id"],
        unique=False,
    )

    op.create_table(
        "source_evidence_outcomes",
        sa.Column("source_outcome_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("collection_account_id", sa.String(length=32), nullable=False),
        sa.Column("phase", sa.String(length=16), nullable=False),
        sa.Column("subject_kind", sa.String(length=16), nullable=False),
        sa.Column("subject", _json_document_type(), nullable=False),
        sa.Column("subject_resource_id", sa.Uuid(), nullable=True),
        sa.Column("subject_resource_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("subject_scope", sa.String(length=16), nullable=False),
        sa.Column("subject_region", sa.String(length=64), nullable=True),
        sa.Column("evidence_kind", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("failure_category", sa.String(length=32), nullable=True),
        sa.Column("collector", sa.String(length=128), nullable=False),
        sa.Column("collector_version", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("source_api", sa.String(length=128), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("artifact_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_reference", sa.String(length=512), nullable=False),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "phase IN ('DISCOVERY', 'ENRICHMENT')",
            name=op.f("ck_source_evidence_outcomes_phase"),
        ),
        sa.CheckConstraint(
            "state IN ('PRESENT', 'EXPECTED_ABSENCE', 'UNAVAILABLE', 'MALFORMED', "
            "'CONFLICT', 'RESOURCE_DISAPPEARED')",
            name=op.f("ck_source_evidence_outcomes_state"),
        ),
        sa.CheckConstraint(
            "failure_category IN ('ACCESS_DENIED', 'AUTHENTICATION_FAILED', 'THROTTLED', "
            "'TIMEOUT', 'SERVICE_ERROR', 'UNSUPPORTED_OPERATION', 'MALFORMED_RESPONSE', "
            "'CONFLICTING_EVIDENCE', 'RESOURCE_NOT_FOUND')",
            name=op.f("ck_source_evidence_outcomes_failure_category"),
        ),
        sa.CheckConstraint(
            "subject_scope IN ('regional', 'global')",
            name=op.f("ck_source_evidence_outcomes_subject_scope"),
        ),
        sa.CheckConstraint(
            "length(collection_account_id) = 12",
            name=op.f("ck_source_evidence_outcomes_collection_account_length"),
        ),
        sa.CheckConstraint(
            "length(trim(evidence_kind)) > 0",
            name=op.f("ck_source_evidence_outcomes_evidence_kind_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(collector)) > 0",
            name=op.f("ck_source_evidence_outcomes_collector_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(collector_version)) > 0",
            name=op.f("ck_source_evidence_outcomes_collector_version_not_blank"),
        ),
        sa.CheckConstraint(
            "source = 'aws-api'",
            name=op.f("ck_source_evidence_outcomes_source_aws_api"),
        ),
        sa.CheckConstraint(
            "length(trim(source_api)) > 0",
            name=op.f("ck_source_evidence_outcomes_source_api_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(evidence_reference)) > 0",
            name=op.f("ck_source_evidence_outcomes_reference_not_blank"),
        ),
        sa.CheckConstraint(
            "length(evidence_sha256) = 64",
            name=op.f("ck_source_evidence_outcomes_evidence_sha256_length"),
        ),
        sa.CheckConstraint(
            "length(trim(schema_version)) > 0",
            name=op.f("ck_source_evidence_outcomes_schema_version_not_blank"),
        ),
        sa.CheckConstraint(
            "(phase = 'DISCOVERY' AND subject_kind = 'account' "
            "AND subject_resource_id IS NULL AND subject_resource_snapshot_id IS NULL) OR "
            "(phase = 'ENRICHMENT' AND subject_kind = 'resource' "
            "AND subject_resource_id IS NOT NULL "
            "AND subject_resource_snapshot_id IS NOT NULL)",
            name=op.f("ck_source_evidence_outcomes_phase_subject_consistent"),
        ),
        sa.CheckConstraint(
            "(subject_scope = 'regional' AND subject_region IS NOT NULL) OR "
            "(subject_scope = 'global' AND subject_region IS NULL)",
            name=op.f("ck_source_evidence_outcomes_subject_scope_region_consistent"),
        ),
        sa.CheckConstraint(
            "(state IN ('PRESENT', 'EXPECTED_ABSENCE') AND failure_category IS NULL) OR "
            "(state NOT IN ('PRESENT', 'EXPECTED_ABSENCE') AND failure_category IS NOT NULL)",
            name=op.f("ck_source_evidence_outcomes_state_failure_consistent"),
        ),
        sa.CheckConstraint(
            "state <> 'RESOURCE_DISAPPEARED' OR phase = 'ENRICHMENT'",
            name=op.f("ck_source_evidence_outcomes_disappearance_requires_enrichment"),
        ),
        sa.ForeignKeyConstraint(
            ["source_outcome_id", "scan_id"],
            ["scan_source_contracts.source_outcome_id", "scan_source_contracts.scan_id"],
            name="fk_source_evidence_outcomes_contract",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
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
        sa.ForeignKeyConstraint(
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
        sa.PrimaryKeyConstraint("source_outcome_id", name=op.f("pk_source_evidence_outcomes")),
        sa.UniqueConstraint(
            "source_outcome_id",
            "scan_id",
            "evidence_reference",
            name="uq_source_evidence_outcomes_relationship_reference",
        ),
    )
    op.create_index(
        "ix_source_evidence_outcomes_scan_state",
        "source_evidence_outcomes",
        ["scan_id", "state"],
        unique=False,
    )

    op.create_table(
        "resource_relationship_observations",
        sa.Column("observation_id", sa.Uuid(), nullable=False),
        sa.Column("relationship_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("collection_account_id", sa.String(length=32), nullable=False),
        sa.Column("relationship_type", sa.String(length=32), nullable=False),
        sa.Column("resolution", sa.String(length=40), nullable=False),
        sa.Column("source_provider", sa.String(length=32), nullable=False),
        sa.Column("source_aws_account_id", sa.String(length=32), nullable=False),
        sa.Column("source_service", sa.String(length=64), nullable=False),
        sa.Column("source_resource_type", sa.String(length=128), nullable=False),
        sa.Column("source_aws_resource_id", sa.Text(), nullable=False),
        sa.Column("source_scope", sa.String(length=16), nullable=False),
        sa.Column("source_region", sa.String(length=64), nullable=True),
        sa.Column("source_resource_id", sa.Uuid(), nullable=False),
        sa.Column("source_resource_snapshot_id", sa.Uuid(), nullable=False),
        sa.Column("target_identity_state", sa.String(length=16), nullable=False),
        sa.Column("target_provider", sa.String(length=32), nullable=False),
        sa.Column("target_aws_account_id", sa.String(length=32), nullable=True),
        sa.Column("target_service", sa.String(length=64), nullable=False),
        sa.Column("target_resource_type", sa.String(length=128), nullable=False),
        sa.Column("target_aws_resource_id", sa.Text(), nullable=False),
        sa.Column("target_scope", sa.String(length=16), nullable=True),
        sa.Column("target_region", sa.String(length=64), nullable=True),
        sa.Column("target_resource_id", sa.Uuid(), nullable=True),
        sa.Column("target_resource_snapshot_id", sa.Uuid(), nullable=True),
        sa.Column("target_reference_id", sa.Uuid(), nullable=True),
        sa.Column("source_outcome_id", sa.Uuid(), nullable=False),
        sa.Column("provenance_collector", sa.String(length=128), nullable=False),
        sa.Column("provenance_collector_version", sa.String(length=64), nullable=False),
        sa.Column("provenance_source", sa.String(length=16), nullable=False),
        sa.Column("provenance_source_api", sa.String(length=128), nullable=False),
        sa.Column("evidence_reference", sa.String(length=512), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "relationship_type IN ('uses_volume', 'attached_to_security_group', 'in_subnet', "
            "'in_vpc', 'contains_subnet', 'has_flow_log', 'member_of_group', 'has_access_key', "
            "'has_mfa_device', 'attached_managed_policy', 'attached_inline_policy', "
            "'permissions_boundary', 'selects_default_version', 'references_resource', "
            "'encrypted_with', 'delivers_to_bucket')",
            name=op.f("ck_resource_relationship_observations_relationship_type"),
        ),
        sa.CheckConstraint(
            "resolution IN ('RESOLVED', 'TARGET_NOT_COLLECTED', 'TARGET_OUTSIDE_SCAN_SCOPE', "
            "'TARGET_ACCESS_DENIED', 'TARGET_EVIDENCE_INCOMPLETE', "
            "'TARGET_IDENTITY_INCOMPLETE')",
            name=op.f("ck_resource_relationship_observations_resolution"),
        ),
        sa.CheckConstraint(
            "source_scope IN ('regional', 'global')",
            name=op.f("ck_resource_relationship_observations_source_scope"),
        ),
        sa.CheckConstraint(
            "target_scope IS NULL OR target_scope IN ('regional', 'global')",
            name=op.f("ck_resource_relationship_observations_target_scope"),
        ),
        sa.CheckConstraint(
            "length(collection_account_id) = 12",
            name=op.f("ck_resource_relationship_observations_collection_account_length"),
        ),
        sa.CheckConstraint(
            "source_provider = 'aws'",
            name=op.f("ck_resource_relationship_observations_source_provider_aws"),
        ),
        sa.CheckConstraint(
            "target_provider = 'aws'",
            name=op.f("ck_resource_relationship_observations_target_provider_aws"),
        ),
        sa.CheckConstraint(
            "provenance_source = 'aws-api'",
            name=op.f("ck_resource_relationship_observations_provenance_source_aws_api"),
        ),
        sa.CheckConstraint(
            "(source_scope = 'regional' AND source_region IS NOT NULL) OR "
            "(source_scope = 'global' AND source_region IS NULL)",
            name=op.f("ck_resource_relationship_observations_source_scope_region_consistent"),
        ),
        sa.CheckConstraint(
            "target_scope IS NULL OR "
            "(target_scope = 'regional' AND target_region IS NOT NULL) OR "
            "(target_scope = 'global' AND target_region IS NULL)",
            name=op.f("ck_resource_relationship_observations_target_scope_region_consistent"),
        ),
        sa.CheckConstraint(
            "(target_identity_state = 'stable' AND target_resource_id IS NOT NULL "
            "AND target_reference_id IS NULL) OR "
            "(target_identity_state = 'unresolved' AND target_resource_id IS NULL "
            "AND target_resource_snapshot_id IS NULL AND target_reference_id IS NOT NULL)",
            name=op.f("ck_resource_relationship_observations_target_identity_consistent"),
        ),
        sa.CheckConstraint(
            "(resolution = 'RESOLVED' AND target_identity_state = 'stable' "
            "AND target_resource_snapshot_id IS NOT NULL) OR "
            "(resolution <> 'RESOLVED' AND target_resource_snapshot_id IS NULL)",
            name=op.f("ck_resource_relationship_observations_resolution_snapshot_consistent"),
        ),
        sa.CheckConstraint(
            "resolution <> 'TARGET_IDENTITY_INCOMPLETE' OR target_identity_state = 'unresolved'",
            name=op.f("ck_resource_relationship_observations_incomplete_resolution_consistent"),
        ),
        sa.CheckConstraint(
            "target_identity_state <> 'unresolved' OR resolution = 'TARGET_IDENTITY_INCOMPLETE'",
            name=op.f("ck_resource_relationship_observations_unresolved_target_consistent"),
        ),
        sa.CheckConstraint(
            "target_resource_id IS NULL OR source_resource_id <> target_resource_id",
            name=op.f("ck_resource_relationship_observations_endpoints_differ"),
        ),
        sa.CheckConstraint(
            "length(trim(provenance_collector)) > 0",
            name=op.f("ck_resource_relationship_observations_collector_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(provenance_collector_version)) > 0",
            name=op.f("ck_resource_relationship_observations_collector_version_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(provenance_source_api)) > 0",
            name=op.f("ck_resource_relationship_observations_source_api_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(evidence_reference)) > 0",
            name=op.f("ck_resource_relationship_observations_reference_not_blank"),
        ),
        sa.CheckConstraint(
            "length(trim(schema_version)) > 0",
            name=op.f("ck_resource_relationship_observations_schema_version_not_blank"),
        ),
        sa.ForeignKeyConstraint(
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
        sa.ForeignKeyConstraint(
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
        sa.ForeignKeyConstraint(
            ["source_outcome_id", "scan_id", "evidence_reference"],
            [
                "source_evidence_outcomes.source_outcome_id",
                "source_evidence_outcomes.scan_id",
                "source_evidence_outcomes.evidence_reference",
            ],
            name="fk_resource_relationships_source_outcome",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "observation_id", name=op.f("pk_resource_relationship_observations")
        ),
        sa.UniqueConstraint(
            "observation_id", "scan_id", name="uq_resource_relationships_observation_scan"
        ),
        sa.UniqueConstraint(
            "scan_id", "relationship_id", name="uq_resource_relationships_scan_relationship"
        ),
    )
    op.create_index(
        "ix_resource_relationships_source",
        "resource_relationship_observations",
        ["source_resource_id", "relationship_type"],
        unique=False,
    )
    op.create_index(
        "ix_resource_relationships_target",
        "resource_relationship_observations",
        ["target_resource_id", "relationship_type"],
        unique=False,
    )
    op.create_index(
        "ix_resource_relationships_target_reference",
        "resource_relationship_observations",
        ["target_reference_id", "relationship_type"],
        unique=False,
    )
    op.create_index(
        "ix_resource_relationships_scan",
        "resource_relationship_observations",
        ["scan_id"],
        unique=False,
    )

    _drop_snapshot_provenance_guard()
    _install_graph_guards()
    _install_snapshot_provenance_guard(graph_aware=True)


def downgrade() -> None:
    """Remove only an empty, preflight-approved evidence graph foundation."""

    _drop_snapshot_provenance_guard()
    _drop_graph_guards()
    _install_snapshot_provenance_guard(graph_aware=False)

    op.drop_index("ix_resource_relationships_scan", table_name="resource_relationship_observations")
    op.drop_index(
        "ix_resource_relationships_target_reference",
        table_name="resource_relationship_observations",
    )
    op.drop_index(
        "ix_resource_relationships_target",
        table_name="resource_relationship_observations",
    )
    op.drop_index(
        "ix_resource_relationships_source",
        table_name="resource_relationship_observations",
    )
    op.drop_table("resource_relationship_observations")
    op.drop_index("ix_source_evidence_outcomes_scan_state", table_name="source_evidence_outcomes")
    op.drop_table("source_evidence_outcomes")
    op.drop_index("ix_source_evidence_artifacts_scan", table_name="source_evidence_artifacts")
    op.drop_table("source_evidence_artifacts")
    op.drop_index("ix_scan_source_contracts_contract", table_name="scan_source_contracts")
    op.drop_index("ix_scan_source_contracts_scan", table_name="scan_source_contracts")
    op.drop_table("scan_source_contracts")
    _drop_manifest_columns()
