"""Populated 6A storage, recovery, history, and additive API projection checks."""

import pytest
from alembic import command
from alembic.util import CommandError
from sqlalchemy import event, inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.assessment.controls import build_default_control_catalog
from app.assessment.extended_profiles import canonical_profile_document
from app.assessment.sensitive_buckets import SensitiveBucketClassifier
from app.database.catalogs import (
    VersionContentConflictError,
    ensure_assessment_profile,
    ensure_control_catalog,
    load_assessment_profile,
    verify_control_catalog,
)
from app.database.persistence import persist_scan_result
from app.models import ControlAssessment, Finding, ResourceSnapshot
from app.models.profile import AssessmentPolicyArtifact
from app.services.control_service import ControlService
from tests.foundation_fixtures import extended_profile, regional_bundle
from tests.unit.database.factories import scan_bundle
from tests.unit.database.test_migrations import _migration_config


def exercise_extended_profile(engine):
    classifier = SensitiveBucketClassifier.create(
        version="1.0.0", sensitive_name_patterns=("private-*",)
    )
    profile = extended_profile(
        sensitive_bucket_classifier=classifier, max_unused_access_key_days=30
    )
    with Session(engine) as session, session.begin():
        ensure_assessment_profile(session, profile)
    with Session(engine) as session:
        loaded = load_assessment_profile(
            session,
            profile_id=profile.profile_id,
            version=profile.version,
            expected_checksum=profile.content_checksum,
        )
        assert canonical_profile_document(loaded) == canonical_profile_document(profile)
        assert loaded.content_checksum == profile.content_checksum
        artifact = session.scalar(select(AssessmentPolicyArtifact))
        assert artifact.content == classifier.model_dump(mode="json")
    changed = SensitiveBucketClassifier.create(
        version="1.0.0", sensitive_name_patterns=("changed-*",)
    )
    conflicting = extended_profile(version="3.0.0", sensitive_bucket_classifier=changed)
    with Session(engine) as session, pytest.raises(VersionContentConflictError), session.begin():
        ensure_assessment_profile(session, conflicting)
    with engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(update(AssessmentPolicyArtifact).values(content_checksum="a" * 64))


def test_extended_profile_and_artifact_are_immutable(migrated_engine):
    exercise_extended_profile(migrated_engine)


def exercise_regional_history(engine):
    bundle = regional_bundle()
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        assessment = session.scalar(select(ControlAssessment))
        snapshot = session.scalar(select(ResourceSnapshot))
        assert assessment.resource_snapshot_id == snapshot.snapshot_id
        assert snapshot.region == "us-east-1"
        assert snapshot.resource.resource_type == "aws_account"
        assert assessment.scan_id == bundle["snapshot"].scan_id
        assert session.scalar(select(Finding)).resource_id == snapshot.resource_id
        page = ControlService(session).list_controls(resource_type="aws_account")
        assert {c.control_key for c in page.items} == {"NET-001", "LOG-001"}
        extended = next(c for c in page.items if c.control_key == "NET-001").versions[0]
        assert (
            extended.execution_contract
            == bundle["catalog"].get("NET-001").technical.execution_contract
        )
        # No legacy resource_type match may override an explicit new target declaration.
        assert {
            c.control_key
            for c in ControlService(session).list_controls(resource_type="security_group").items
        } == {"NET-002"}


def test_regional_setting_history_and_generic_control_api(migrated_engine):
    exercise_regional_history(migrated_engine)


def exercise_blocked_downgrade(engine, config_factory, *, kind):
    if kind == "profile":
        with Session(engine) as session, session.begin():
            ensure_assessment_profile(session, extended_profile())
    else:
        exercise_regional_history(engine)
    with engine.connect() as connection:
        before = {
            name: connection.execute(text(f'SELECT * FROM "{name}"')).mappings().all()
            for name in inspect(connection).get_table_names()
        }
        columns = {
            name: [c["name"] for c in inspect(connection).get_columns(name)] for name in before
        }
    with pytest.raises(CommandError, match="blocked before revision 20260924_0004"):
        with engine.begin() as connection:
            command.downgrade(config_factory(connection), "20260915_0003")
    with engine.connect() as connection:
        assert {
            name: connection.execute(text(f'SELECT * FROM "{name}"')).mappings().all()
            for name in before
        } == before
        assert {
            name: [c["name"] for c in inspect(connection).get_columns(name)] for name in before
        } == columns


@pytest.mark.parametrize("kind", ["profile", "execution"])
def test_incompatible_downgrade_preserves_all_rows_and_schema(migrated_engine, kind):
    exercise_blocked_downgrade(migrated_engine, _migration_config, kind=kind)


def exercise_compatible_downgrade(engine, config_factory):
    bundle = scan_bundle()
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with engine.begin() as connection:
        before = connection.execute(text("SELECT * FROM scans")).mappings().all()
        command.downgrade(config_factory(connection), "20260915_0003")
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260915_0003"
        assert connection.execute(text("SELECT * FROM scans")).mappings().all() == before
        command.upgrade(config_factory(connection), "head")
        assert connection.execute(text("SELECT * FROM scans")).mappings().all() == before
        command.check(config_factory(connection))


def test_compatible_populated_downgrade_and_upgrade(migrated_engine):
    exercise_compatible_downgrade(migrated_engine, _migration_config)


def test_catalog_recovery_verification_is_read_only(migrated_engine):
    catalog = build_default_control_catalog()
    with Session(migrated_engine) as session, session.begin():
        ensure_control_catalog(session, catalog)
    statements = []

    def record(_conn, _cursor, statement, *_args):
        statements.append(statement.strip().split()[0].upper())

    event.listen(migrated_engine, "before_cursor_execute", record)
    try:
        with Session(migrated_engine) as session:
            verify_control_catalog(session, catalog)
        assert set(statements) == {"SELECT"}
    finally:
        event.remove(migrated_engine, "before_cursor_execute", record)


@pytest.mark.parametrize("field", ["source_outcome_id", "artifact_id", "evidence_sha256"])
def test_forged_source_proof_is_rejected_before_persistence(migrated_engine, field):
    from app.assessment.execution import account_target
    from app.assessment.models import AssessmentResult
    from app.database.persistence import ScanPersistenceError
    from app.rules.engine import RuleContractError, RuleEngine
    from app.rules.registry import RuleRegistry
    from tests.foundation_fixtures import SyntheticRegionalRule, regional_contract

    bundle = regional_bundle()
    original = bundle["assessments"][0]
    proof = original.evidence_artifacts[0].model_dump(mode="json")["payload"]["source_proof"]
    proof["sources"][0][field] = (
        "0" * 64 if field == "evidence_sha256" else "00000000-0000-0000-0000-000000000000"
    )
    generated = SyntheticRegionalRule().assessment_for_resource(
        bundle["snapshot"],
        bundle["profile"],
        account_target(bundle["snapshot"], regional_contract()),
        result=AssessmentResult.FAIL,
        evidence={"source_proof": proof},
        reason="Fixture forgery",
        collector="foundation.test",
        source_api="ec2:GetSetting",
    )
    forged = original.model_copy(update={"evidence_artifacts": generated.evidence_artifacts})
    bundle["assessments"] = (forged,)

    class ForgedRule(SyntheticRegionalRule):
        def assess(self, snapshot, profile):
            return (forged,)

    with pytest.raises(RuleContractError):
        RuleEngine(RuleRegistry((ForgedRule(),)), catalog=bundle["catalog"]).assess(
            bundle["snapshot"], bundle["profile"]
        )
    with Session(migrated_engine) as session, pytest.raises(ScanPersistenceError), session.begin():
        persist_scan_result(session, **bundle)
    with migrated_engine.connect() as connection:
        assert connection.scalar(text("SELECT COUNT(*) FROM scans")) == 0


def test_new_boundary_rejects_offline_downgrade(migrated_engine):
    from pathlib import Path

    from alembic.config import Config

    config = Config(str(Path(__file__).resolve().parents[3] / "alembic.ini"))
    config.attributes["database_url"] = "sqlite://"
    with pytest.raises(CommandError, match="Offline downgrade across 20260924_0004"):
        command.downgrade(config, "20260924_0004:20260915_0003", sql=True)


def exercise_transition_rollback(engine, config_factory):
    def fail_after_first_ddl(_conn, _cursor, statement, *_args):
        if "ALTER TABLE control_versions DROP COLUMN execution_contract" in statement:
            raise RuntimeError("injected transition failure")

    event.listen(engine, "before_cursor_execute", fail_after_first_ddl)
    try:
        with (
            pytest.raises(RuntimeError, match="injected transition failure"),
            engine.begin() as connection,
        ):
            command.downgrade(config_factory(connection), "20260915_0003")
    finally:
        event.remove(engine, "before_cursor_execute", fail_after_first_ddl)
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20260924_0004"
        assert "assessment_policy_artifacts" in inspect(connection).get_table_names()
        assert "execution_contract" in {
            c["name"] for c in inspect(connection).get_columns("control_versions")
        }
        command.check(config_factory(connection))


def test_failed_sqlite_transition_rolls_back_ddl(migrated_engine):
    exercise_transition_rollback(migrated_engine, _migration_config)
