"""Adversarial coverage validation at the durable persistence boundary."""

from copy import deepcopy

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.assessment.controls import ControlCatalog, build_default_control_catalog
from app.assessment.models import AssessmentResult
from app.database.persistence import ScanPersistenceError, persist_scan_result
from app.models import Scan
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.schemas.inventory import CollectionStatus, CollectorOutcome
from tests.unit.database.factories import scan_bundle


def _assess(bundle: dict) -> None:
    bundle["assessments"] = RuleEngine(build_default_registry()).assess(
        bundle["snapshot"], bundle["profile"]
    )


def _scan_count(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(Scan)) or 0


def test_complete_scan_cannot_omit_one_required_resource_assessment(
    db_session: Session,
) -> None:
    bundle = scan_bundle()
    original = bundle["snapshot"].resources[0]
    second = original.model_copy(
        update={"aws_resource_id": "sg-history-2", "name": "second-history-test"}
    )
    bundle["snapshot"] = bundle["snapshot"].model_copy(update={"resources": (original, second)})
    _assess(bundle)
    assert len(bundle["assessments"]) == 2
    bundle["assessments"] = bundle["assessments"][:1]

    with pytest.raises(ScanPersistenceError, match="target matrix differs"):
        persist_scan_result(db_session, **bundle)
    assert _scan_count(db_session) == 0


def test_single_region_inventory_cannot_claim_multi_region_completion(
    db_session: Session,
) -> None:
    bundle = scan_bundle()
    bundle["scope"] = bundle["scope"].model_copy(
        update={
            "requested_regions": ("us-east-1", "us-west-2"),
            "successful_regions": ("us-east-1", "us-west-2"),
        }
    )

    with pytest.raises(ScanPersistenceError, match="exactly the inventory invocation region"):
        persist_scan_result(db_session, **bundle)
    assert _scan_count(db_session) == 0


def test_unrelated_collector_gap_cannot_excuse_missing_resource_results(
    db_session: Session,
) -> None:
    bundle = scan_bundle(public_ssh=None)
    candidate = bundle["assessments"][0].model_copy(
        update={
            "result": AssessmentResult.INSUFFICIENT_EVIDENCE,
            "missing_evidence": ("collector_outcomes.iam_users.SUCCEEDED",),
            "reason": "An unrelated collector failed.",
        }
    )
    bundle["assessments"] = (candidate,)

    with pytest.raises(ScanPersistenceError, match="must name its missing collector"):
        persist_scan_result(db_session, **bundle)
    assert _scan_count(db_session) == 0


def test_catalog_content_cannot_be_relabelled_under_an_assessed_version(
    db_session: Session,
) -> None:
    bundle = scan_bundle()
    values = deepcopy(build_default_control_catalog().model_dump(mode="python"))
    values["controls"][0]["technical"]["title"] = "Relabelled after evaluation"
    bundle["catalog"] = ControlCatalog.model_validate(values)

    with pytest.raises(ScanPersistenceError, match="catalog differs"):
        persist_scan_result(db_session, **bundle)
    assert _scan_count(db_session) == 0


def test_semantic_scope_and_inventory_reordering_is_idempotent(
    db_session: Session,
) -> None:
    bundle = scan_bundle()
    security_groups = bundle["snapshot"].collector_outcomes[0]
    iam_users = CollectorOutcome(collector_name="iam_users", status=CollectionStatus.SUCCEEDED)
    bundle["snapshot"] = bundle["snapshot"].model_copy(
        update={"collector_outcomes": (security_groups, iam_users)}
    )
    bundle["scope"] = bundle["scope"].model_copy(
        update={
            "requested_services": ("ec2", "iam"),
            "requested_collectors": ("security_groups", "iam_users"),
            "collector_outcomes": (security_groups, iam_users),
            "resource_types": ("security_group", "iam_user"),
        }
    )
    _assess(bundle)
    first = persist_scan_result(db_session, **bundle)
    db_session.commit()

    retry = dict(bundle)
    retry["snapshot"] = bundle["snapshot"].model_copy(
        update={"collector_outcomes": (iam_users, security_groups)}
    )
    retry["scope"] = bundle["scope"].model_copy(
        update={
            "requested_services": ("iam", "ec2"),
            "requested_collectors": ("iam_users", "security_groups"),
            "collector_outcomes": (iam_users, security_groups),
            "resource_types": ("iam_user", "security_group"),
        }
    )
    _assess(retry)
    second = persist_scan_result(db_session, **retry)
    db_session.commit()

    assert second.scan_id == first.scan_id
    assert _scan_count(db_session) == 1
