"""Persisted EC2-004 remediation fixtures; all collection uses existing offline clients."""

from datetime import timedelta
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.persistence import persist_scan_result
from app.models import Control, Finding, FindingOccurrence
from app.remediation.contracts import ACTION_ID, ACTION_VERSION, ProposalRequest
from app.security.authentication import Principal
from app.services.remediation_service import RemediationService
from tests.ec2_fixtures import OBSERVED, ec2_bundle

NOW = OBSERVED + timedelta(minutes=1)
PROPOSER = Principal("analyst", frozenset({"ANALYST"}), "https://identity.example.test")
APPROVER = Principal("reviewer", frozenset({"APPROVER"}), "https://identity.example.test")
ADMIN = Principal("operator", frozenset({"ADMIN"}), "https://identity.example.test")
VIEWER = Principal("reader", frozenset({"VIEWER"}), "https://identity.example.test")


def seed(engine, **overrides):
    bundle = ec2_bundle(**overrides)
    with Session(engine) as session, session.begin():
        persist_scan_result(session, **bundle)
    with Session(engine) as session:
        finding = session.scalar(
            select(Finding)
            .join(Control)
            .where(
                Control.control_key == "EC2-004",
                Finding.region == bundle["snapshot"].requested_region,
            )
        )
        occurrence = session.scalar(
            select(FindingOccurrence).where(
                FindingOccurrence.finding_id == finding.finding_id,
                FindingOccurrence.scan_id == bundle["snapshot"].scan_id,
            )
        )
        request = ProposalRequest(
            finding_id=finding.finding_id,
            occurrence_id=occurrence.occurrence_id,
            action_id=ACTION_ID,
            action_version=ACTION_VERSION,
            reason="Reviewed future-volume and key-access compatibility.",
        )
    return request, bundle


def propose(engine, request=None, *, principal=PROPOSER, key=None, at=NOW):
    if request is None:
        request, _ = seed(engine)
    with Session(engine) as session:
        return RemediationService(session, clock=lambda: at).propose(
            request, principal, key or uuid4()
        )
