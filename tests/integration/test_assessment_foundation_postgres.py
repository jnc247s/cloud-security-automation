"""6A acceptance against explicitly configured disposable PostgreSQL schemas."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from alembic import command
from sqlalchemy import event, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.assessment.sensitive_buckets import SensitiveBucketClassifier
from app.database.catalogs import VersionContentConflictError, ensure_assessment_profile
from app.models.profile import AssessmentPolicyArtifact, PersistedAssessmentProfile
from tests.foundation_fixtures import extended_profile
from tests.integration.test_persistence_postgres import migration_config
from tests.integration.test_persistence_postgres import postgres_engine as _postgres_engine
from tests.unit.database.test_assessment_foundation import (
    exercise_blocked_downgrade,
    exercise_compatible_downgrade,
    exercise_empty_targets,
    exercise_extended_profile,
    exercise_regional_history,
    exercise_transition_rollback,
    exercise_upgrade_rollback,
)

pytestmark = pytest.mark.integration
postgres_engine = _postgres_engine


def test_postgres_extended_profile_and_artifact_integrity(postgres_engine):
    exercise_extended_profile(postgres_engine)


def test_postgres_regional_history_and_control_filter(postgres_engine):
    exercise_regional_history(postgres_engine)


@pytest.mark.parametrize("kind", ["profile", "execution"])
def test_postgres_incompatible_downgrade_is_lossless(postgres_engine, kind):
    exercise_blocked_downgrade(postgres_engine, migration_config, kind=kind)


def test_postgres_legacy_downgrade_and_upgrade(postgres_engine):
    exercise_compatible_downgrade(postgres_engine, migration_config)


def test_postgres_concurrent_policy_artifact_version_conflict(postgres_engine):
    barrier = Barrier(2)

    def persist(number):
        profile = extended_profile(
            version=f"{number}.0.0",
            sensitive_bucket_classifier=SensitiveBucketClassifier.create(
                version="1.0.0", sensitive_name_patterns=(f"fixture-{number}-*",)
            ),
        )
        barrier.wait(timeout=10)
        try:
            with Session(postgres_engine) as session, session.begin():
                ensure_assessment_profile(session, profile)
            return "persisted"
        except VersionContentConflictError:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(persist, (2, 3)))
    assert sorted(results) == ["conflict", "persisted"]
    with Session(postgres_engine) as session:
        assert len(session.scalars(select(AssessmentPolicyArtifact)).all()) == 1
        assert len(session.scalars(select(PersistedAssessmentProfile)).all()) == 1


def test_postgres_failed_transition_rolls_back_ddl(postgres_engine):
    exercise_transition_rollback(postgres_engine, migration_config)


def test_postgres_failed_populated_upgrade_is_atomic(postgres_engine):
    exercise_upgrade_rollback(postgres_engine, migration_config)


@pytest.mark.parametrize("complete", [True, False])
def test_postgres_empty_targets_require_coverage(postgres_engine, complete):
    exercise_empty_targets(postgres_engine, complete=complete)


def test_postgres_downgrade_excludes_concurrent_profile_writer(postgres_engine):
    results = []

    def attempt_write():
        try:
            with Session(postgres_engine) as session, session.begin():
                session.execute(text("SET LOCAL lock_timeout = '150ms'"))
                ensure_assessment_profile(session, extended_profile())
        except OperationalError as error:
            return error.orig.sqlstate
        return "unexpected write"

    with ThreadPoolExecutor(max_workers=1) as executor:

        def after_lock(_conn, _cursor, statement, *_args):
            if statement.startswith("LOCK TABLE") and "assessment_policy_artifacts" in statement:
                results.append(executor.submit(attempt_write).result(timeout=10))

        event.listen(postgres_engine, "after_cursor_execute", after_lock)
        try:
            with postgres_engine.begin() as connection:
                command.downgrade(migration_config(connection), "20260915_0003")
            assert results == ["55P03"]  # PostgreSQL lock_not_available, not a timing guess.
        finally:
            event.remove(postgres_engine, "after_cursor_execute", after_lock)
