"""Two closed incoming-verification faults; never modify accepted history or cloud authority.

Import is stdlib-only. The owned server installs this after explicit isolated configuration.
Signed bodies, actors and keys pass through unchanged; only domain observation time or a sole
NEW proof INSERT is faulted. Authentication, collectors, rules and receipt readers remain real.
"""

import os
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from threading import RLock
from types import SimpleNamespace
from uuid import UUID


def fault_kind(name):
    if type(name) is not str or name not in {"verification-equal", "verification-provenance"}:
        raise ValueError("Invalid integrated verification fault")
    return name


class VerificationFault:
    def __init__(self, engine, source, *, issuer, scenario):
        self.scenario = fault_kind(scenario)
        self.engine, self.source, self.issuer = engine, source, issuer
        self.initial, self.current, self.pending = None, None, None
        self.at, self.insert_before, self.insert_after = None, None, None
        self._lock, self._active, self._released = RLock(), False, False

    def _prove_ack(self, identifier):
        from sqlalchemy.orm import Session

        from app.models import FindingOccurrence
        from app.remediation.execution_contracts import AdmissionScope, ExecutionPhase
        from app.security.authentication import Principal
        from app.services.remediation_execution_service import RemediationExecutionService
        from tests.worker_http import ACCOUNT, REGION, assert_history

        if self.initial is None or self.at is not None:
            raise ValueError("Verification fault requires one genuine queued admission")
        with Session(self.engine) as session:
            current = RemediationExecutionService(
                session, scope=AdmissionScope(enabled=True, account_id=ACCOUNT, region=REGION)
            ).get_execution(
                identifier, Principal("fault-reader", frozenset({"VIEWER"}), self.issuer)
            )
            source = session.get(FindingOccurrence, self.source.occurrence_id)
            proposal, baseline = current.content.proposal, current.content.proposal.baseline
            if (
                source is None
                or current.phase is not ExecutionPhase.ACKNOWLEDGED
                or current.reservation_held
                or current.blocking_reasons
                or proposal.finding_id != source.finding_id
                or source.finding_id != self.source.finding_id
                or proposal.resource_id != source.resource_id
                or proposal.control_id != source.control_id
                or (proposal.account_id, proposal.region) != (ACCOUNT, REGION)
                or baseline.occurrence_id != source.occurrence_id
                or baseline.scan_id != source.scan_id
                or baseline.assessment_id != source.assessment_id
                or baseline.snapshot_id != source.resource_snapshot_id
                or baseline.control_version_id != source.control_version_id
            ):
                raise ValueError("Verification fault source binding rejected")
        assert_history(self.engine, self.initial, current, SimpleNamespace(issuer=self.issuer))
        acknowledgments = [e for e in current.events if e.content.kind.value == "ACKNOWLEDGED"]
        if len(acknowledgments) != 1:
            raise ValueError("Verification fault requires normal acknowledgment")
        self.current = current
        self.at = acknowledgments[0].content.created_at

    def _observe_insert(self, session, *_):
        from app.models import EvidenceArtifact

        if session.bind is not self.engine or self.pending is None:
            return
        for row in session.new:
            if (
                isinstance(row, EvidenceArtifact)
                and row.scan_id == self.pending.content.scan_id
                and row.schema_name == "control.ec2-004.evidence"
            ):
                with self._lock:
                    if self.insert_before is not None or not self._released:
                        raise ValueError("Repeated or unbound incoming proof fault")
                    if row.source_api != "ec2:GetEbsEncryptionByDefault":
                        raise ValueError("Unexpected incoming proof source")
                    self.insert_before = deepcopy(
                        {column.key: getattr(row, column.key) for column in row.__table__.columns}
                    )
                    row.source_api = "ec2:GetEbsDefaultKmsKeyId"
                    self.insert_after = deepcopy(
                        {column.key: getattr(row, column.key) for column in row.__table__.columns}
                    )

    def release(self, view):
        if (
            not self._active
            or self._released
            or self.pending is None
            or self.pending != view
            or view.receipt is not None
            or view.content.execution_id != self.current.content.execution_id
            or view.content.acknowledged_at != self.at
        ):
            raise ValueError("Verification fault reader binding rejected")
        self._released = True

    @contextmanager
    def installed(self):
        if os.environ.get("DASHBOARD_BROWSER_TEST") != "1" or self._active:
            raise ValueError("Verification fault requires explicit isolated mode")
        from unittest.mock import patch

        import httpx2 as httpx
        from sqlalchemy import event
        from sqlalchemy.orm import Session

        from app.remediation.execution_contracts import ExecutionPhase, ExecutionView
        from app.remediation.verification_contracts import VerificationView
        from app.services import inventory_service, remediation_service

        if any(
            module.datetime is not datetime for module in (inventory_service, remediation_service)
        ):
            raise ValueError("Verification fault cannot replace another domain clock")
        owner, original = self, httpx.AsyncClient.post

        class OwnedDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                if tz is not UTC:
                    raise ValueError("Verification fault domain clock rejected")
                return owner.at if owner.at is not None else datetime.now(tz)

        async def forward(client, url, *args, **kwargs):
            admission = (
                type(url) is str
                and url.startswith("/api/v1/remediations/")
                and url.endswith("/executions")
            )
            verification = (
                type(url) is str
                and url.startswith("/api/v1/remediation-executions/")
                and url.endswith("/verifications")
            )
            if not admission and not verification:
                return await original(client, url, *args, **kwargs)
            if not isinstance(client._transport, httpx.ASGITransport):
                raise ValueError("Verification fault requires fixed in-process bearer API")
            identifier = url.split("/")[-2]
            if str(UUID(identifier)) != identifier or UUID(identifier).version != 4:
                raise ValueError("Verification fault target rejected")
            if verification:
                owner._prove_ack(UUID(identifier))
            response = await original(client, url, *args, **kwargs)
            if response.status_code != 202:
                raise ValueError("Verification fault requires genuine accepted admission")
            if admission:
                initial = ExecutionView.model_validate(response.json())
                if owner.initial is not None or initial.phase is not ExecutionPhase.QUEUED:
                    raise ValueError("Verification fault queued admission rejected")
                owner.initial = initial
            else:
                owner.pending = VerificationView.model_validate(response.json())
                if owner.pending.receipt is not None:
                    raise ValueError("Verification fault cannot seed a receipt")
            return response

        self._active = True
        try:
            with ExitStack() as stack:
                if self.scenario == "verification-equal":
                    stack.enter_context(
                        patch.object(remediation_service, "datetime", OwnedDateTime)
                    )
                    stack.enter_context(patch.object(inventory_service, "datetime", OwnedDateTime))
                else:
                    event.listen(Session, "before_flush", self._observe_insert)
                    stack.callback(event.remove, Session, "before_flush", self._observe_insert)
                stack.enter_context(patch.object(httpx.AsyncClient, "post", forward))
                yield self
        finally:
            self._active = False

    def assert_complete(self):
        from sqlalchemy.orm import Session

        from app.models import EvidenceArtifact
        from app.remediation.provenance import utc
        from tests.verification_acceptance import assert_receipt_storage

        if self._active or not self._released or self.pending is None or self.at is None:
            raise ValueError("Incomplete verification fault proof")
        from app.security.authentication import Principal
        from app.services.remediation_verification_service import RemediationVerificationService

        with Session(self.engine) as session:
            view = RemediationVerificationService(session).get_verification(
                self.pending.content.verification_id,
                Principal("fault-final-reader", frozenset({"VIEWER"}), self.issuer),
            )
            assert view.receipt.outcome.value == "INCONCLUSIVE"
            assert view.receipt.scan_status.value == "COMPLETED"
            if self.scenario == "verification-equal":
                assert self.insert_before is self.insert_after is None
                assert view.receipt.reason.value == "OBSERVATION_NOT_LATER"
                assert view.content.created_at == view.content.acknowledged_at == self.at
                assert view.receipt.evidence.observed_at == self.at
                assert view.receipt.evidence.technical_result.value == "PASS"
            else:
                assert view.receipt.reason.value == "PROVENANCE_UNAVAILABLE"
                assert view.receipt.evidence is None
                assert self.insert_before is not None and self.insert_after is not None
                assert {
                    k for k in self.insert_before if self.insert_before[k] != self.insert_after[k]
                } == {"source_api"}
                row = session.get(EvidenceArtifact, self.insert_before["evidence_id"])
                for key, value in self.insert_after.items():
                    actual = getattr(row, key)
                    assert (utc(actual) if isinstance(actual, datetime) else actual) == value
        assert_receipt_storage(self.engine, view)
        print("INTEGRATED_VERIFICATION_FAULT_PROVED=" + self.scenario, flush=True)
