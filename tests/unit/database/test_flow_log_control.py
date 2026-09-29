"""NET-006 history, exact policy, atomic forgery rejection and finding lifecycle."""

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.assessment.models import AssessmentResult as R
from app.assessment.models import EvidenceArtifact as ArtifactInput
from app.database.catalogs import load_assessment_profile, verify_control_catalog
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import ControlAssessment, EvidenceArtifact, Finding, ResourceSnapshot, Scan
from app.models.enums import FindingStatus
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from tests.ec2_fixtures import OBSERVED
from tests.fakes import client_error
from tests.flow_log_fixtures import flow_bundle, flow_profile
from tests.network_control_fixtures import network_bundle
from tests.unit.collectors.test_network import _flow_log
from tests.unit.database.test_network_controls import exercise_network_recovery


def exercise_flow_history(engine):
    bundles = [
        network_bundle(),
        flow_bundle(),
        flow_bundle(
            profile=flow_profile(version="6.4.3", vpc_flow_log_required_environments=("staging",))
        ),
    ]
    for bundle in bundles:
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for bundle in bundles:
            verify_control_catalog(session, bundle["catalog"])
            profile = load_assessment_profile(
                session,
                profile_id=bundle["profile"].profile_id,
                version=bundle["profile"].version,
                expected_checksum=bundle["profile"].content_checksum,
            )
            catalog, registry = resolve_catalog(
                bundle["catalog"].catalog_id, bundle["catalog"].version
            )
            assert (
                RuleEngine(registry, catalog=catalog).assess(bundle["snapshot"], profile)
                == bundle["assessments"]
            )
        for bundle, expected in zip(bundles[1:], (R.FAIL, R.NOT_APPLICABLE), strict=True):
            row = session.scalars(
                select(ControlAssessment).where(
                    ControlAssessment.scan_id == bundle["snapshot"].scan_id
                )
            ).one()
            assert row.assessment_result is expected
            assert session.get(ResourceSnapshot, row.resource_snapshot_id).scan_id == row.scan_id


def exercise_flow_rejection(engine, kind):
    bundle = flow_bundle(flow_logs=[_flow_log()])
    (original,) = bundle["assessments"]
    if kind in {"na", "fail", "insufficient"}:
        result = {"na": R.NOT_APPLICABLE, "fail": R.FAIL, "insufficient": R.INSUFFICIENT_EVIDENCE}[
            kind
        ]
        forged = original.model_copy(
            update={
                "result": result,
                "evidence_artifacts": original.evidence_artifacts if kind == "fail" else (),
                "missing_evidence": ("vpc_flow_logs.required_evidence",)
                if kind == "insufficient"
                else (),
            }
        )
    else:
        document = original.evidence_artifacts[0].model_dump(
            exclude={"evidence_id", "payload_sha256"}
        )
        proof = document["payload"]["source_proof"]
        if kind == "edge":
            proof["relationship_observation_ids"] = []
        elif kind == "source":
            proof["sources"][0]["artifact_id"] = str(uuid4())
        elif kind == "facts":
            proof["vpc_flow_logs"]["flow_logs"] = []
        else:
            document["payload"]["evaluation_version"] = "9.0.0"
        forged = original.model_copy(
            update={"evidence_artifacts": (ArtifactInput.for_assessment(**document),)}
        )
    bundle["assessments"] = (forged,)
    with (
        Session(engine) as session,
        pytest.raises(ScanPersistenceError, match="assessment source evidence is invalid"),
        session.begin(),
    ):
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        for model in (Scan, ResourceSnapshot, ControlAssessment, EvidenceArtifact, Finding):
            assert session.scalar(select(func.count()).select_from(model)) == 0


def exercise_flow_lifecycle(engine):
    bundles = (
        flow_bundle(),
        flow_bundle(
            flow_logs=[_flow_log()],
            subnet_error=client_error("AccessDenied", "offline"),
            observed=OBSERVED + timedelta(days=1),
        ),
        flow_bundle(flow_logs=[_flow_log()], observed=OBSERVED + timedelta(days=2)),
    )
    finding_id = None
    for index, bundle in enumerate(bundles):
        assert bundle["assessments"][0].result is (R.FAIL if index == 0 else R.PASS)
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            finding = session.scalars(select(Finding)).one()
            finding_id = finding_id or finding.finding_id
            assert finding.finding_id == finding_id
            assert finding.status is (FindingStatus.RESOLVED if index == 2 else FindingStatus.OPEN)


def test_flow_history(migrated_engine):
    exercise_flow_history(migrated_engine)


@pytest.mark.parametrize(
    "kind", ["na", "fail", "insufficient", "edge", "source", "facts", "version"]
)
def test_flow_rejection(migrated_engine, kind):
    exercise_flow_rejection(migrated_engine, kind)


def test_flow_lifecycle(migrated_engine):
    exercise_flow_lifecycle(migrated_engine)


def test_flow_recovery(migrated_engine, tmp_path):
    exercise_network_recovery(migrated_engine, tmp_path, flow_logs=True)
