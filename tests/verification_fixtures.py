"""Full-scope offline verification fixtures; real collectors/rules/worker history."""

from collections import deque
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.config import get_settings
from app.database.persistence import persist_scan_result
from app.models import Control, Finding, FindingOccurrence
from app.remediation.contracts import ACTION_ID, ACTION_VERSION, ProposalRequest
from app.remediation.execution_contracts import AdmissionScope
from app.remediation.verification_contracts import VerificationRequest, VerificationScope
from app.remediation.worker_config import WorkerScope
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from app.services.inventory_service import InventoryService
from app.services.remediation_verification_service import RemediationVerificationService
from app.services.remediation_worker_service import RemediationWorkerService
from app.services.scan_executor import InProcessScanExecutor, _scope_for
from tests.ec2_fixtures import ACCOUNT, OBSERVED, ec2_profile
from tests.execution_fixtures import admit, approved
from tests.remediation_fixtures import ADMIN, VIEWER
from tests.unit.services.test_remediation_worker import Clock
from tests.unit.services.test_scan_service import RecordingExecutor, _empty_provider

REGION = "us-west-2"
SCOPE = VerificationScope(enabled=True, account_id=ACCOUNT, region=REGION)
WRITER_SCOPE = WorkerScope(
    enabled=True,
    account_id=ACCOUNT,
    region=REGION,
    role_arn=f"arn:aws:iam::{ACCOUNT}:role/remediation-writer",
)


def provider(*, enabled=False, key=None, kms_error=None):
    result = _empty_provider()
    ec2 = result._clients[("ec2", REGION)]
    ec2._responses["get_ebs_encryption_by_default"] = deque([{"EbsEncryptionByDefault": enabled}])
    ec2._responses["get_ebs_default_kms_key_id"] = deque(
        [kms_error if kms_error is not None else {"KmsKeyId": key} if key is not None else {}]
    )
    return result


class VerificationHarness:
    def __init__(self, engine, *, key=None, acknowledge=True):
        self.engine, self.clock, self.sessions = engine, Clock(), []
        policy = ec2_profile()
        catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.5.0")
        with patch("app.services.inventory_service.datetime") as clock:
            clock.now.return_value = OBSERVED
            snapshot = InventoryService(provider(key=key)).collect(scan_id=uuid4())
        bundle = dict(
            snapshot=snapshot,
            scope=_scope_for(snapshot, policy, catalog),
            profile=policy,
            catalog=catalog,
            assessments=RuleEngine(registry, catalog=catalog).assess(snapshot, policy),
            started_at=OBSERVED - timedelta(seconds=1),
            completed_at=OBSERVED + timedelta(seconds=1),
            scanner_version=__version__,
        )
        with Session(engine) as session, session.begin():
            persist_scan_result(session, **bundle)
        with Session(engine) as session:
            finding = session.scalar(
                select(Finding).join(Control).where(Control.control_key == "EC2-004")
            )
            occurrence = session.scalar(
                select(FindingOccurrence).where(FindingOccurrence.finding_id == finding.finding_id)
            )
            request = ProposalRequest(
                finding_id=finding.finding_id,
                occurrence_id=occurrence.occurrence_id,
                action_id=ACTION_ID,
                action_version=ACTION_VERSION,
                reason="Reviewed compatibility.",
            )
        self.proposal, self.execution_request, _ = approved(engine, request=request)
        execution = admit(
            engine,
            self.proposal,
            self.execution_request,
            scope=AdmissionScope(enabled=True, account_id=ACCOUNT, region=REGION),
        ).value
        self.execution_id = execution.content.execution_id
        if acknowledge:
            from app.remediation.worker_contracts import RegionalObservation

            claim = self.worker("claim", self.execution_id)
            assert self.worker("begin_read", claim)
            assert self.worker(
                "write_intent",
                claim,
                RegionalObservation(
                    encryption_by_default=False,
                    default_kms_key_id=key,
                    default_kms_key_expected_absence=key is None,
                ),
                self.clock(),
            )
            self.worker("acknowledge", claim, "offline-write-receipt")
        self.clock.advance(1)

    def worker(self, method, *args):
        with Session(self.engine) as session:
            return getattr(
                RemediationWorkerService(session, scope=WRITER_SCOPE, clock=self.clock), method
            )(*args)

    def session_factory(self):
        session = Session(self.engine, expire_on_commit=False)
        self.sessions.append(session)
        return session

    def request(
        self,
        *,
        executor=None,
        key=None,
        principal=ADMIN,
        reason="Verify approved setting.",
        scope=SCOPE,
    ):
        with Session(self.engine) as session:
            return RemediationVerificationService(
                session, scope=scope, clock=self.clock
            ).request_verification(
                self.execution_id,
                VerificationRequest(reason=reason),
                principal,
                key or uuid4(),
                executor or RecordingExecutor(),
            )

    def view(self, verification_id):
        with Session(self.engine) as session:
            return RemediationVerificationService(session).get_verification(verification_id, VIEWER)

    def run(self, scan_id, *, read_provider=None, observe_at=None, allowed=True):
        read_provider = read_provider or provider(enabled=True)

        def factory(region):
            assert region == REGION
            assert not any(session.in_transaction() for session in self.sessions)
            return read_provider

        executor = InProcessScanExecutor(
            session_factory=self.session_factory,
            provider_factory=factory,
            settings=get_settings().model_copy(
                update={
                    "remediation_verification_enabled": allowed,
                    "remediation_verification_account_id": ACCOUNT,
                    "remediation_verification_region": REGION,
                }
            ),
        )
        try:
            with patch("app.services.inventory_service.datetime") as clock:
                clock.now.return_value = observe_at or self.clock() + timedelta(seconds=1)
                executor._run(scan_id)
        finally:
            executor.shutdown()
        return read_provider
