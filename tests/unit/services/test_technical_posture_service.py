"""Exact retained reporting truth tables, release history and bounded read work."""

from collections import Counter
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import boto3
import pytest
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.frameworks import FrameworkReferenceLevel as L
from app.assessment.models import AssessmentResult as R
from app.assessment.profiles import AssessmentProfile
from app.config import Settings
from app.database.catalogs import ensure_assessment_profile, ensure_control_catalog
from app.database.persistence import fail_pending_scan, persist_scan_result
from app.models.control import Control, ControlFrameworkMapping, Framework, FrameworkReference
from app.models.enums import ExceptionStatus, ScanStatus
from app.models.exception import FindingException
from app.models.finding import Finding
from app.models.scan import Scan
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.inventory import CollectionStatus, CollectorOutcome, InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput
from app.schemas.scan import ScanCreateRequest
from app.schemas.technical_posture import AssessmentCounts, ControlPosture
from app.services.errors import EntityNotFoundError, TechnicalPostureProvenanceError
from app.services.technical_posture_service import TechnicalPostureService, _coverage
from tests.cloudtrail_destination_fixtures import destination_bundle, mixed_destination_provider
from tests.integration.test_persistence_postgres import _count_sql_statements
from tests.network_control_fixtures import network_bundle, network_snapshot
from tests.sprint6_fixtures import CATALOG_CHECKSUMS, sprint6_bundle
from tests.unit.database.conftest import db_session as db_session
from tests.unit.database.conftest import migrated_engine as migrated_engine
from tests.unit.database.factories import scan_bundle
from tests.unit.services.test_network_external_admission import (
    EXTERNAL_ACCOUNT_ID,
    _security_group,
    _vpc,
)
from tests.unit.services.test_scan_service import RecordingExecutor


def persist(session, bundle):
    persist_scan_result(session, **bundle)
    session.commit()
    return bundle["snapshot"].scan_id


def as_counts(results):
    values = Counter(results)
    return AssessmentCounts(
        pass_count=values[R.PASS],
        fail_count=values[R.FAIL],
        insufficient_evidence_count=values[R.INSUFFICIENT_EVIDENCE],
        not_applicable_count=values[R.NOT_APPLICABLE],
    )


def exercise_result_state(session, result):
    options = {
        R.PASS: {"public_ssh": False},
        R.FAIL: {"public_ssh": True},
        R.INSUFFICIENT_EVIDENCE: {"malformed": True},
        R.NOT_APPLICABLE: {"public_ssh": None},
    }
    bundle = scan_bundle(**options[result])
    report = TechnicalPostureService(session).get_technical_posture(persist(session, bundle))
    assert report.availability == "AVAILABLE"
    assert report.assessment_counts == as_counts((result,))
    assert report.control_coverage.registered_count == 5
    assert report.control_coverage.enabled_count == report.control_coverage.assessed_count == 1
    assert report.control_coverage.disabled_count == 4
    assert report.control_coverage.unassessed_count == 0
    enabled = next(row for row in report.controls if row.enabled)
    assert enabled.control_key == "NET-001"
    assert enabled.assessment_coverage == "ASSESSED"
    assert enabled.assessment_counts == report.assessment_counts
    assert all(row.assessment_coverage == "DISABLED" for row in report.controls if not row.enabled)
    assert all(row.assessment_counts.total == 0 for row in report.controls if not row.enabled)
    assert sum(row.assessment_counts.total for row in report.targets) == 1
    assert sum(row.assessed_snapshot_count for row in report.targets) == 1


@pytest.mark.parametrize("result", R)
def test_each_four_state_result_and_disabled_definitions(db_session, result):
    exercise_result_state(db_session, result)


def exercise_collection_state(session, status):
    bundle = scan_bundle(collection_status=status)
    report = TechnicalPostureService(session).get_technical_posture(persist(session, bundle))
    assert report.availability == "AVAILABLE"
    assert report.scan.status.value == status.value.replace("SUCCEEDED", "COMPLETED")
    assert report.scan.scope.collector_outcomes == {"security_groups": status.value}
    assert report.assessment_counts == as_counts(a.result for a in bundle["assessments"])
    if status is not CollectionStatus.SUCCEEDED:
        assert report.scan.successful_regions == ()
        assert report.assessment_counts.insufficient_evidence_count == 1


@pytest.mark.parametrize("status", CollectionStatus)
def test_retained_failed_and_partial_results_remain_facts(db_session, status):
    exercise_collection_state(db_session, status)


def exercise_unfinished(session):
    from app.services.scan_service import ScanService

    settings = Settings(_env_file=None, app_env="test", auth_mode="development")
    pending = ScanService(session, settings).start_scan(
        ScanCreateRequest(), RecordingExecutor(), actor_id="report-test"
    )
    service = TechnicalPostureService(session)
    report = service.get_technical_posture(pending.scan_id)
    assert report.availability == "IN_PROGRESS"
    assert report.assessment_counts is None and report.targets is None
    assert report.control_coverage.assessed_count is None
    assert report.control_coverage.unassessed_count is None
    assert all(row.assessment_counts is None for row in report.controls)
    assert all(row.assessment_coverage == "UNAVAILABLE" for row in report.controls)
    fail_pending_scan(
        session,
        scan_id=pending.scan_id,
        completed_at=datetime.now(UTC) + timedelta(seconds=1),
        failure_code="TEST_COLLECTION_FAILURE",
        failure_message="The test collection could not finish.",
    )
    session.commit()
    failed = service.get_technical_posture(pending.scan_id)
    assert failed.availability == "UNAVAILABLE"
    assert failed.assessment_counts is None and failed.targets is None
    assert failed.scan.scope is None and failed.scan.inventory_sha256 is None
    assert failed.scan.failure.code == "TEST_COLLECTION_FAILURE"
    assert failed.scan.result_checksum is not None  # A failure digest is not a result bundle.
    assert all(ref.assessment_counts is None for f in failed.frameworks for ref in f.references)


def test_running_and_failure_without_bundle_are_not_zero_failure_summaries(db_session):
    exercise_unfinished(db_session)


def exercise_history(engine):
    bundles = []
    for index, version in enumerate(CATALOG_CHECKSUMS):
        bundle = sprint6_bundle(
            catalog_version=version,
            observed=datetime(2026, 10, 2, tzinfo=UTC) + timedelta(days=index),
        )
        with Session(engine) as session:
            persist(session, bundle)
        bundles.append(bundle)
    with Session(engine) as session:
        for bundle in bundles:
            report = TechnicalPostureService(session).get_technical_posture(
                bundle["snapshot"].scan_id
            )
            assert report.catalog.version == bundle["catalog"].version
            assert report.catalog.content_checksum == CATALOG_CHECKSUMS[bundle["catalog"].version]
            assert report.scan.assessment_profile_checksum == bundle["profile"].content_checksum
            assert report.assessment_counts == as_counts(a.result for a in bundle["assessments"])
            assert report.control_coverage.assessed_count == len(bundle["catalog"].controls)
            for row in report.controls:
                expected = [a for a in bundle["assessments"] if a.control_id == row.control_key]
                assert row.assessment_counts == as_counts(a.result for a in expected)
                assert all(
                    m.control_version_id == row.control_version_id for m in row.framework_mappings
                )
                assert all(
                    m.framework_version
                    == next(
                        f.version for f in report.frameworks if f.framework_id == m.framework_id
                    )
                    for m in row.framework_mappings
                )
            if bundle["catalog"].version == "0.13.0":
                assert report.assessment_counts.total == 39
                assert report.control_coverage.registered_count == 26
                assert report.assessment_counts == AssessmentCounts(
                    pass_count=21, fail_count=17, not_applicable_count=1
                )
                assert any(
                    t.target_kind == "ACCOUNT" and t.scope.value == "global" for t in report.targets
                )
                assert any(
                    t.target_kind == "ACCOUNT" and t.scope.value == "regional"
                    for t in report.targets
                )
                assert any(t.target_kind == "RESOURCE" for t in report.targets)
                assert sum(t.assessment_counts.total for t in report.targets) == 39
                # Per-control target assessments and unique snapshots are different dimensions.
                assert sum(t.assessed_snapshot_count for t in report.targets) < 39
            # Repeated display keys across local subsets retain separate UUID/version identities.
            ids = [ref.framework_reference_id for f in report.frameworks for ref in f.references]
            assert len(ids) == len(set(ids))


def test_every_supported_release_is_exact_after_newer_versions_are_registered(migrated_engine):
    exercise_history(migrated_engine)


def test_framework_parent_rows_deduplicate_mapping_fanout(db_session):
    report = TechnicalPostureService(db_session).get_technical_posture(
        persist(db_session, sprint6_bundle())
    )
    index = {row.control_version_id: row for row in report.controls}
    for framework in report.frameworks:
        for reference in framework.references:
            ids = reference.mapped_control_version_ids
            assert len(ids) == len(set(ids))
            expected = as_counts(
                [R.PASS] * sum(index[i].assessment_counts.pass_count for i in ids)
                + [R.FAIL] * sum(index[i].assessment_counts.fail_count for i in ids)
                + [R.NOT_APPLICABLE]
                * sum(index[i].assessment_counts.not_applicable_count for i in ids)
            )
            assert reference.assessment_counts == expected
            assert reference.control_coverage.registered_count == len(ids)
            assert framework.interpretation == "MAPPED_TECHNICAL_SUBSET"
    assert report.interpretation == "TECHNICAL_CONTEXT_ONLY"
    body = report.model_dump_json()
    assert '"normalized_configuration"' not in body and '"payload"' not in body
    assert '"tags"' not in body and '"reason"' not in body and '"finding_id"' not in body
    assert '"compliance_score"' not in body and '"technical_result"' not in body


def test_projection_keeps_unmapped_rows_unassessed_and_deduplicates_two_leaf_mappings(db_session):
    # Isolated synthetic hierarchy: no additions to bundled framework/catalog artifacts or mappings.
    control = next(
        c
        for c in TechnicalPostureService(db_session)
        .get_technical_posture(persist(db_session, scan_bundle()))
        .controls
        if c.enabled
    )
    framework = Framework(
        framework_id=uuid4(),
        framework_key="test-only-reporting-hierarchy",
        name="Synthetic projection fixture, not official NIST data",
        version="test.1",
        source="https://fixtures.example.test/reporting",
        source_retrieved_at=datetime(2026, 10, 2, tzinfo=UTC),
        source_checksum="0" * 64,
    )
    function = FrameworkReference(
        framework_reference_id=uuid4(),
        framework=framework,
        reference_key="TEST",
        level=L.FUNCTION,
        title="Synthetic function",
        description="Test",
    )
    category = FrameworkReference(
        framework_reference_id=uuid4(),
        framework=framework,
        reference_key="TEST.CAT",
        level=L.CATEGORY,
        title="Synthetic category",
        description="Test",
        parent_reference_id=function.framework_reference_id,
    )
    db_session.add_all([framework, function, category])
    db_session.flush()
    leaves = tuple(
        FrameworkReference(
            framework_reference_id=uuid4(),
            framework=framework,
            reference_key=f"TEST.CAT-{i}",
            level=L.SUBCATEGORY,
            title="Synthetic leaf",
            description="Test",
            parent_reference_id=category.framework_reference_id,
        )
        for i in range(3)
    )
    db_session.add_all(leaves)
    db_session.flush()
    # These mapping objects are not persisted or appended to the real retained definitions.
    mappings = tuple(
        ControlFrameworkMapping(
            control_version_id=control.control_version_id,
            framework_reference=leaf,
            framework_reference_id=leaf.framework_reference_id,
        )
        for leaf in leaves[:2]
    )
    service = TechnicalPostureService(db_session)
    with db_session.no_autoflush:
        report = service._frameworks((control,), mappings, available=True)[0]
    refs = {ref.reference_key: ref for ref in report.references}
    assert refs["TEST"].assessment_counts == control.assessment_counts
    assert refs["TEST.CAT"].assessment_counts == control.assessment_counts
    assert refs["TEST.CAT"].mapped_control_version_ids == (control.control_version_id,)
    assert refs["TEST.CAT-2"].mapped_control_version_ids == ()
    assert refs["TEST.CAT-2"].assessment_counts == AssessmentCounts()
    assert refs["TEST.CAT-2"].control_coverage.assessed_count == 0
    assert report.interpretation == "MAPPED_TECHNICAL_SUBSET"


def exercise_empty_enablement(session):
    bundle = scan_bundle()
    profile = AssessmentProfile.model_validate(
        {
            **bundle["profile"].model_dump(exclude={"content_checksum"}),
            "profile_id": "report-empty-enablement",
            "enabled_controls": (),
        }
    )
    bundle.update(
        profile=profile,
        scope=bundle["scope"].model_copy(
            update={
                "enabled_controls": (),
                "assessment_profile_id": profile.profile_id,
                "assessment_profile_checksum": profile.content_checksum,
            }
        ),
        assessments=RuleEngine(build_default_registry()).assess(bundle["snapshot"], profile),
    )
    # Preserve the accepted nonempty completed-scope contract. Empty profiles can be
    # retained on pending rows, but the normal persistence path cannot finish this bundle.
    with pytest.raises(ValidationError, match="at least 1 item"):
        persist_scan_result(session, **bundle)
    ensure_assessment_profile(session, profile)
    ensure_control_catalog(session, bundle["catalog"])
    scan_id = uuid4()
    session.add(
        Scan(
            scan_id=scan_id,
            aws_account_id=None,
            requested_regions=["us-east-1"],
            successful_regions=[],
            requested_services=["ec2"],
            successful_collectors=[],
            started_at=datetime.now(UTC),
            status=ScanStatus.RUNNING,
            scanner_version="report-empty-pending-fixture",
            control_catalog_id=bundle["catalog"].catalog_id,
            control_catalog_version=bundle["catalog"].version,
            assessment_profile_id=profile.profile_id,
            assessment_profile_version=profile.version,
            assessment_profile_checksum=profile.content_checksum,
        )
    )
    session.commit()
    report = TechnicalPostureService(session).get_technical_posture(scan_id)
    assert report.availability == "IN_PROGRESS"
    assert report.enabled_controls == ()
    assert report.assessment_counts is None and report.targets is None
    assert report.control_coverage.enabled_count == 0
    assert report.control_coverage.assessed_count is None
    assert report.control_coverage.disabled_count == report.control_coverage.registered_count == 5
    assert all(c.assessment_coverage == "DISABLED" for c in report.controls)
    assert all(
        ref.control_coverage.assessed_count is None and ref.control_coverage.enabled_count == 0
        for framework in report.frameworks
        for ref in framework.references
    )


def test_empty_enablement_is_no_assessment_not_an_overall_pass(db_session):
    exercise_empty_enablement(db_session)


def exercise_external_owner(session):
    snapshot = network_snapshot(
        groups=[_security_group("sg-shared", owner_id=EXTERNAL_ACCOUNT_ID, vpc_id="vpc-shared")],
        vpcs=[_vpc("vpc-shared", owner_id=EXTERNAL_ACCOUNT_ID)],
    )
    report = TechnicalPostureService(session).get_technical_posture(
        persist(session, network_bundle(snapshot=snapshot))
    )
    external = [t for t in report.targets if t.aws_account_id == EXTERNAL_ACCOUNT_ID]
    assert external and report.scan.aws_account_id != EXTERNAL_ACCOUNT_ID
    assert all(t.region == snapshot.requested_region for t in external)
    assert sum(t.assessment_counts.total for t in report.targets) == report.assessment_counts.total


def test_assessed_target_owner_is_not_replaced_with_collection_account(db_session):
    exercise_external_owner(db_session)


def exercise_supplemental_region(session):
    bundle = destination_bundle(provider=mixed_destination_provider())
    report = TechnicalPostureService(session).get_technical_posture(persist(session, bundle))
    assert report.scan.requested_regions == ("us-east-1",)
    assert any(t.region == "eu-west-1" and t.target_kind == "RESOURCE" for t in report.targets)
    assert "eu-west-1" not in report.scan.successful_regions
    assert sum(t.assessment_counts.total for t in report.targets) == len(bundle["assessments"])


def test_supplemental_target_region_is_not_full_scan_region_coverage(db_session):
    exercise_supplemental_region(db_session)


def scaled_bundle(size):
    bundle = scan_bundle()
    original = bundle["snapshot"]
    resource = original.resources[0]
    snapshot = InventorySnapshot.model_validate(
        {
            **original.model_dump(),
            "resources": tuple(
                resource.model_copy(update={"aws_resource_id": f"sg-report-{i}"})
                for i in range(size)
            ),
        }
    )
    bundle.update(
        snapshot=snapshot,
        assessments=RuleEngine(build_default_registry()).assess(snapshot, bundle["profile"]),
    )
    return bundle


def exercise_scaling(engine, size):
    with Session(engine) as session:
        scan_id = persist(session, scaled_bundle(size))
    with Session(engine) as session, _count_sql_statements(engine) as statements:
        report = TechnicalPostureService(session).get_technical_posture(scan_id)
        assert report.assessment_counts.fail_count == size
        assert report.targets[0].assessed_snapshot_count == size
    assert len(statements) == 10
    assert all(statement.lstrip().upper().startswith("SELECT") for statement in statements)
    assert not any(
        word in statement.lower()
        for statement in statements
        for word in (
            "normalized_configuration",
            "source_evidence_artifacts",
            "evidence_artifacts",
            "findings",
        )
    )
    return statements


@pytest.mark.parametrize("size", [16, 32])
def test_report_has_ten_read_queries_not_one_detail_call_per_assessment(migrated_engine, size):
    exercise_scaling(migrated_engine, size)


def test_reporting_never_calls_aws_rule_engine_or_transaction_writers(db_session, monkeypatch):
    scan_id = persist(db_session, scan_bundle())
    pending = Control(control_key="UNRELATED-TEST")
    db_session.add(pending)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("reporting must only read retained facts")

    monkeypatch.setattr(boto3, "client", forbidden)
    monkeypatch.setattr(boto3.session.Session, "client", forbidden)
    monkeypatch.setattr(RuleEngine, "assess", forbidden)
    for name in ("flush", "commit", "rollback"):
        monkeypatch.setattr(db_session, name, forbidden)
    assert (
        TechnicalPostureService(db_session).get_technical_posture(scan_id).availability
        == "AVAILABLE"
    )
    assert pending in db_session.new and pending.control_id is None


@pytest.mark.parametrize("handling", ["current", "expired", "revoked"])
def test_operational_exceptions_never_rewrite_historical_technical_counts(db_session, handling):
    scan_id = persist(db_session, scan_bundle())
    service = TechnicalPostureService(db_session)
    original = service.get_technical_posture(scan_id)
    finding = db_session.scalars(select(Finding)).one()
    now = datetime.now(UTC)
    exception = FindingException(
        finding_id=finding.finding_id,
        resource_id=finding.resource_id,
        control_id=finding.control_id,
        reason="Synthetic handling metadata must not appear in technical reporting.",
        approved_by="test-only-approver",
        created_at=now - timedelta(days=3),
        expires_at=now + timedelta(days=1) if handling == "current" else now - timedelta(days=1),
        status=ExceptionStatus.REVOKED if handling == "revoked" else ExceptionStatus.ACTIVE,
        revoked_at=now if handling == "revoked" else None,
    )
    db_session.add(exception)
    db_session.commit()
    assert service.get_technical_posture(scan_id) == original
    assert original.assessment_counts.fail_count == 1


def test_partial_collection_does_not_discard_independently_valid_pass(db_session):
    bundle = scan_bundle(public_ssh=False)
    original = bundle["snapshot"]
    outcomes = (
        *original.collector_outcomes,
        CollectorOutcome(collector_name="iam_users", status=CollectionStatus.FAILED),
    )
    snapshot = InventorySnapshot.model_validate(
        {**original.model_dump(), "collector_outcomes": outcomes}
    )
    scope = ScanScopeManifestInput.model_validate(
        {
            **bundle["scope"].model_dump(),
            "requested_services": ("ec2", "iam"),
            "requested_collectors": ("security_groups", "iam_users"),
            "collector_outcomes": outcomes,
            "successful_regions": (),
        }
    )
    bundle.update(
        snapshot=snapshot,
        scope=scope,
        assessments=RuleEngine(build_default_registry()).assess(snapshot, bundle["profile"]),
    )
    report = TechnicalPostureService(db_session).get_technical_posture(persist(db_session, bundle))
    assert report.scan.status.value == "PARTIAL"
    assert report.scan.scope.collector_outcomes["iam_users"] == "FAILED"
    assert report.availability == "AVAILABLE" and report.assessment_counts.pass_count == 1


def test_missing_scan_is_consistent_not_found(db_session):
    with pytest.raises(EntityNotFoundError, match="scan"):
        TechnicalPostureService(db_session).get_technical_posture(uuid4())


def test_disabled_unassessed_and_empty_enablement_are_not_technical_results(db_session):
    report = TechnicalPostureService(db_session).get_technical_posture(
        persist(db_session, scan_bundle())
    )
    control = next(row for row in report.controls if row.enabled)
    unassessed = ControlPosture(
        **{
            **control.model_dump(),
            "assessment_coverage": "UNASSESSED",
            "assessment_counts": AssessmentCounts(),
        }
    )
    coverage = _coverage((unassessed,), available=True)
    assert coverage.enabled_count == coverage.unassessed_count == 1
    assert coverage.assessed_count == 0
    empty = _coverage((), available=True)
    assert empty.registered_count == empty.enabled_count == empty.assessed_count == 0
    assert unassessed.assessment_coverage not in {result.value for result in R}


@pytest.mark.parametrize("wrong_version,wrong_profile", [(True, False), (False, True)])
def test_cross_catalog_or_cross_profile_rows_fail_closed(
    db_session, monkeypatch, wrong_version, wrong_profile
):
    report = TechnicalPostureService(db_session).get_technical_posture(
        persist(db_session, scan_bundle())
    )
    version = next(row.control_version_id for row in report.controls if row.enabled)
    monkeypatch.setattr(
        db_session,
        "execute",
        lambda _query: [
            (
                uuid4() if wrong_version else version,
                uuid4() if wrong_profile else report.assessment_profile_version_id,
                R.FAIL,
                1,
            )
        ],
    )
    with pytest.raises(TechnicalPostureProvenanceError):
        TechnicalPostureService(db_session)._assessment_counts(
            report.scan,
            report.assessment_profile_version_id,
            [{"control_version_id": version, "control_key": "NET-001"}],
        )
