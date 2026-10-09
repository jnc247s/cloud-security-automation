"""One-job orchestration: every provider/AWS call is outside a completed SQL transaction."""

import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy.orm import Session

from app.remediation.execution_phases import ExecutionPhase
from app.remediation.worker_aws import (
    EbsDefaultWriter,
    RemediationAWS,
    WorkerAwsCode,
    WorkerAwsError,
)
from app.remediation.worker_config import WorkerScope
from app.remediation.worker_contracts import WorkerBlockingReason
from app.services.remediation_worker_service import RemediationWorkerService


class WorkerResult(StrEnum):
    DISABLED = "WORKER_DISABLED"
    NO_ACTION = "NO_ACTION"
    NO_WRITE = "NO_WRITE"
    ACKNOWLEDGED = "ACKNOWLEDGED_UNVERIFIED"
    QUARANTINED = "QUARANTINED_UNVERIFIED"


class RemediationWorker:
    """No human principal, generic dispatch, scanner settings or post-intent write retry."""

    def __init__(
        self,
        sessions: Callable[[], Session],
        *,
        scope: WorkerScope,
        aws_factory: Callable[[WorkerScope], RemediationAWS] = EbsDefaultWriter.from_ecs,
        clock: Callable[[], datetime] | None = None,
        monotonic=time.monotonic,
        pause=time.sleep,
    ):
        self.sessions = sessions
        self.scope = WorkerScope.model_validate(scope.model_dump())
        self.aws_factory = aws_factory
        self.clock = clock or (lambda: datetime.now(UTC))
        self.monotonic = monotonic
        self.pause = pause

    def _db(self, method, *args, **kwargs):
        # The context closes before returning; factory/SDK/close never see an open transaction.
        with self.sessions() as session:
            service = RemediationWorkerService(session, scope=self.scope, clock=self.clock)
            return getattr(service, method)(*args, **kwargs)

    def _readback(self, execution_id, aws=None):
        owns_client = aws is None
        budget = self._db("begin_readback", execution_id)
        if budget is None:
            return
        started = self.monotonic()
        window = min(30.0, max(0.0, (budget[1] - self.clock()).total_seconds()))
        if window == 0:
            self._db("record_observation", execution_id, polls=budget[0])
            return
        try:
            if aws is None:
                try:
                    aws = self.aws_factory(self.scope)
                except WorkerAwsError:
                    self._db("record_observation", execution_id, polls=budget[0])
                    return
            while budget is not None:
                if self.monotonic() - started >= window or self.clock() >= budget[1]:
                    self._db("record_observation", execution_id, polls=budget[0])
                    return
                transient = False
                try:
                    aws.verify_identity()
                    observation = aws.observe()
                    observed_at = self.clock()
                    if observed_at >= budget[1] or self.monotonic() - started >= window:
                        self._db("record_observation", execution_id, polls=budget[0])
                        return
                    self._db(
                        "record_observation",
                        execution_id,
                        observation=observation,
                        observed_at=observed_at,
                        polls=budget[0],
                    )
                    if observation.encryption_by_default is True:
                        return  # Desired state is an observation only, never causation or PASS.
                except WorkerAwsError as error:
                    self._db("record_observation", execution_id, polls=budget[0])
                    transient = error.code is WorkerAwsCode.READ_TRANSIENT
                    if not transient:
                        return
                self.pause(0.25)
                budget = self._db("begin_readback", execution_id)
        finally:
            if owns_client and aws is not None:
                aws.close()

    def run(self, execution_id: UUID) -> WorkerResult:
        if not self.scope.enabled:
            return WorkerResult.DISABLED
        phase, _ = self._db("inspect", execution_id)
        if phase is ExecutionPhase.WRITE_INTENT:
            self._db("quarantine", execution_id)
            self._readback(execution_id)
            return WorkerResult.QUARANTINED
        if phase is ExecutionPhase.QUARANTINED:
            self._readback(execution_id)
            return WorkerResult.QUARANTINED
        if phase is ExecutionPhase.ACKNOWLEDGED:
            self._readback(execution_id)
            return WorkerResult.ACKNOWLEDGED
        claim = self._db("claim", execution_id)
        if claim is None:
            phase, _ = self._db("inspect", execution_id)
            return (
                WorkerResult.NO_WRITE
                if phase is ExecutionPhase.NO_WRITE
                else WorkerResult.NO_ACTION
            )
        aws = None
        try:
            for _ in range(3):
                if not self._db("begin_read", claim):
                    phase, _ = self._db("inspect", execution_id)
                    return (
                        WorkerResult.NO_WRITE
                        if phase is ExecutionPhase.NO_WRITE
                        else WorkerResult.NO_ACTION
                    )
                try:
                    if aws is None:
                        aws = self.aws_factory(self.scope)
                    aws.verify_identity()
                    observation = aws.observe()
                    observed_at = self.clock()
                    break
                except WorkerAwsError as error:
                    if error.code is WorkerAwsCode.READ_TRANSIENT:
                        self.pause(0.25)
                        continue
                    reason = (
                        WorkerBlockingReason.WRITER_SCOPE_MISMATCH
                        if error.code
                        in {WorkerAwsCode.SCOPE_MISMATCH, WorkerAwsCode.INVALID_SOURCE}
                        else WorkerBlockingReason.READ_UNAVAILABLE
                    )
                    self._db("no_write", claim, reason)
                    return WorkerResult.NO_WRITE
            else:
                self._db("no_write", claim, WorkerBlockingReason.READ_BUDGET_EXHAUSTED)
                return WorkerResult.NO_WRITE
            if not self._db("write_intent", claim, observation, observed_at):
                phase, _ = self._db("inspect", execution_id)
                return (
                    WorkerResult.NO_WRITE
                    if phase is ExecutionPhase.NO_WRITE
                    else WorkerResult.NO_ACTION
                )
            # Commit is the cutoff. No SQL query/authority reevaluation between the final
            # deadline check and this one invocation. Pausing after that check remains an AWS
            # no-CAS external race, not something a SQL lease can promise to cancel.
            if self.clock() >= claim.content.expires_at:
                self._db("quarantine", execution_id, WorkerBlockingReason.LATE_DISPATCH)
                return WorkerResult.QUARANTINED
            try:
                receipt = aws.enable()
            except Exception:
                # Even an unexpected adapter/parser exception can follow a changed AWS state.
                self._db("quarantine", execution_id, WorkerBlockingReason.WRITE_UNCERTAIN)
                self._readback(execution_id, aws)
                return WorkerResult.QUARANTINED
            self._db("acknowledge", claim, receipt.request_id)
            phase, _ = self._db("inspect", execution_id)
            if phase is ExecutionPhase.WRITE_INTENT:
                self._db("quarantine", execution_id, WorkerBlockingReason.RECOVERY_UNCERTAIN)
                phase = ExecutionPhase.QUARANTINED
            self._readback(execution_id, aws)
            return (
                WorkerResult.QUARANTINED
                if phase is ExecutionPhase.QUARANTINED
                else WorkerResult.ACKNOWLEDGED
            )
        finally:
            if aws is not None:
                aws.close()
