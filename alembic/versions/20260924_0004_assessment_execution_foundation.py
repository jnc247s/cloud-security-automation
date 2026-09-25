"""Add immutable extended assessment policy and execution-contract storage."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260924_0004"
down_revision = "20260915_0003"
branch_labels = None
depends_on = None


def _json():
    return sa.JSON(none_as_null=True).with_variant(
        postgresql.JSONB(none_as_null=True), "postgresql"
    )


def upgrade() -> None:
    bind = op.get_bind()
    if (
        bind.dialect.name == "sqlite"
        and not op.get_context().as_sql
        and not bind.connection.driver_connection.in_transaction
    ):
        # sqlite3 legacy mode otherwise commits ADD COLUMN before Alembic records the revision.
        # The caller's rollback must undo every part of this additive transition.
        op.execute("BEGIN IMMEDIATE")
    op.add_column("assessment_profiles", sa.Column("policy_extensions", _json(), nullable=True))
    op.add_column(
        "assessment_profiles",
        sa.Column(
            "schema_version",
            sa.String(32),
            sa.CheckConstraint(
                "(schema_version IS NULL AND policy_extensions IS NULL) OR "
                "(schema_version IS NOT NULL AND schema_version = '2.0.0' "
                "AND policy_extensions IS NOT NULL)",
                name=op.f("ck_assessment_profiles_profile_schema_pair"),
            ),
            nullable=True,
        ),
    )
    op.add_column("control_versions", sa.Column("execution_contract", _json(), nullable=True))
    op.create_table(
        "assessment_policy_artifacts",
        sa.Column("policy_artifact_id", sa.Uuid(), primary_key=True),
        sa.Column("artifact_kind", sa.String(32), nullable=False),
        sa.Column("artifact_id", sa.String(128), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("content_checksum", sa.String(64), nullable=False),
        sa.Column("content", _json(), nullable=False),
        sa.UniqueConstraint(
            "artifact_kind", "artifact_id", "version", name="uq_policy_artifact_version"
        ),
        sa.CheckConstraint(
            "artifact_kind IN ('s3-exposure', 'sensitive-bucket')", name="policy_kind"
        ),
        sa.CheckConstraint("length(content_checksum) = 64", name="policy_checksum"),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""
            CREATE FUNCTION reject_policy_artifact_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'assessment policy history is immutable' USING ERRCODE = '23000';
            END;
            $$ LANGUAGE plpgsql
        """)
        op.execute("""
            CREATE TRIGGER immutable_assessment_policy_artifacts
            BEFORE UPDATE OR DELETE OR TRUNCATE ON assessment_policy_artifacts
            FOR EACH STATEMENT EXECUTE FUNCTION reject_policy_artifact_mutation()
        """)
    else:
        for action in ("UPDATE", "DELETE"):
            op.execute(f"""
                CREATE TRIGGER immutable_assessment_policy_artifacts_{action.lower()}
                BEFORE {action} ON assessment_policy_artifacts BEGIN
                SELECT RAISE(ABORT, 'assessment policy history is immutable'); END
            """)


def downgrade() -> None:
    # Alembic env.py preflights the entire downgrade path before the first DDL.
    op.drop_table("assessment_policy_artifacts")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION reject_policy_artifact_mutation()")
        op.drop_constraint(
            op.f("ck_assessment_profiles_profile_schema_pair"), "assessment_profiles", type_="check"
        )
    op.drop_column("control_versions", "execution_contract")
    op.drop_column("assessment_profiles", "schema_version")
    op.drop_column("assessment_profiles", "policy_extensions")
