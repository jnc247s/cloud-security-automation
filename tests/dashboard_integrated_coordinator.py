"""Owning test-parent dispatcher. Import only after isolated test-environment bootstrap.

No application route imports this module. It creates no human authority and never accepts an
arbitrary command, URL or environment. The existing runtime alone owns installed child dispatch.
"""

import os
from dataclasses import dataclass
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy.orm import Session

from app.assessment.models import AssessmentResult
from app.models import FindingOccurrence, Scan
from app.models.enums import ScanStatus
from app.remediation.contracts import ProposalRequest
from app.remediation.execution_contracts import AdmissionScope, ExecutionPhase
from app.security.authentication import Principal
from app.services.remediation_execution_service import RemediationExecutionService
from app.services.remediation_verification_service import RemediationVerificationService
from tests.dashboard_integrated_protocol import (
    ControlFence,
    ControlKind,
    classify_control_failure,
    parse_control,
)
from tests.dashboard_integrated_scenarios import build_worker_script, reader_scenario
from tests.worker_http import ACCOUNT, REGION, assert_history
from tests.worker_process_runtime import OfflineProcessRuntime


class CoordinatorError(RuntimeError):
    """Never echo database URLs, raw child output or provider diagnostics."""


@dataclass(frozen=True)
class IntegratedSource:
    finding_id: UUID
    occurrence_id: UUID
    scan_id: UUID
    assessment_id: UUID
    snapshot_id: UUID
    resource_id: UUID
    control_id: UUID
    control_version_id: UUID


class IntegratedCoordinator:
    """One test fixture's installed positive path, with independent committed-state reads."""

    def __init__(
        self,
        runtime,
        engine,
        child_url,
        source,
        *,
        instance,
        issuer,
        release_reader,
        scenario="verified",
        restart_authority=None,
    ):
        self.runtime, self.engine, self.child_url = runtime, engine, child_url
        self.instance, self.issuer = instance, issuer
        self.release_reader = release_reader
        self.restart_authority = restart_authority
        self.restart_dispatched, self.identity_restarted = False, False
        self.restarted_proposal, self.authority_before = None, None
        self.fence = ControlFence()
        self.acknowledged_execution = None
        self.quarantined_execution = None
        self.expired_execution = None
        self.expiry_before, self.before_worker, self.initial_execution = None, None, None
        self.revocation_before, self.revocation_ack_before, self.revoked_execution = (
            None,
            None,
            None,
        )
        self.worker_dispatched = False
        self.worker_history = None
        self.worker_report = None  # Private parent proof; never forwarded as a browser response.
        self.proposal_only_before = None
        self.stale_dispatched = False
        self.stale_scan_id, self.stale_view, self.stale_after = None, None, None
        self.governance_dispatched = False
        self.governance_before, self.governance_after, self.governance_view = None, None, None
        self.governance_at, self.governance_exception, self.governance_steps = None, None, ()
        self.last_stage = "SOURCE"
        try:
            self.scenario = reader_scenario(scenario)
            if str(UUID(instance)) != instance or UUID(instance).version != 4:
                raise ValueError
            self._owned()
            source = ProposalRequest.model_validate(source.model_dump(mode="json"))
            with Session(engine) as session:
                occurrence = session.get(FindingOccurrence, source.occurrence_id)
                if (
                    occurrence is None
                    or occurrence.finding_id != source.finding_id
                    or occurrence.assessment_result is not AssessmentResult.FAIL
                    or session.get(Scan, occurrence.scan_id).status is not ScanStatus.COMPLETED
                ):
                    raise ValueError
                self.source = IntegratedSource(
                    occurrence.finding_id,
                    occurrence.occurrence_id,
                    occurrence.scan_id,
                    occurrence.assessment_id,
                    occurrence.resource_snapshot_id,
                    occurrence.resource_id,
                    occurrence.control_id,
                    occurrence.control_version_id,
                )
            if self.scenario.worker == "none":
                from tests.worker_http import database_state

                self.proposal_only_before = database_state(engine)
                if (
                    self.proposal_only_before["remediation_proposals"]
                    or self.proposal_only_before["remediation_requests"]
                ):
                    raise ValueError
            if self.scenario.worker == "expired":
                from tests.worker_http import database_state

                self.expiry_before = database_state(engine)
                if (
                    self.expiry_before["remediation_proposals"]
                    or self.expiry_before["remediation_executions"]
                ):
                    raise ValueError
            if self.scenario.name == "cross-issuer":
                from tests.worker_http import database_state

                self.authority_before = database_state(engine)
                if (
                    self.authority_before["remediation_proposals"]
                    or self.authority_before["remediation_executions"]
                ):
                    raise ValueError
            if self.scenario.name in {"revoked-before-intent", "revoked-after-ack"}:
                from tests.worker_http import database_state

                self.revocation_before = database_state(engine)
                if (
                    self.revocation_before["remediation_proposals"]
                    or self.revocation_before["remediation_executions"]
                ):
                    raise ValueError
        except Exception:
            raise CoordinatorError("Integrated test source rejected") from None

    def _owned(self):
        if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
            raise ValueError
        if type(self.runtime) is not OfflineProcessRuntime:
            raise ValueError
        options = self.child_url.query.get("options")
        if not isinstance(options, str) or not options.startswith("-csearch_path="):
            raise ValueError
        schema = options.removeprefix("-csearch_path=")
        if schema not in self.runtime.schemas:
            raise ValueError
        if self.child_url != self.runtime.database_url(child=True, schema=schema):
            raise ValueError
        if self.engine.url != self.runtime.database_url(schema=schema):
            raise ValueError

    def _principal(self):
        return Principal("integrated-parent-reader", frozenset({"VIEWER"}), self.issuer)

    def _execution(self, identifier):
        with Session(self.engine) as session:
            return RemediationExecutionService(
                session, scope=AdmissionScope(enabled=True, account_id=ACCOUNT, region=REGION)
            ).get_execution(identifier, self._principal())

    def _bind(self, view):
        self._bind_proposal(view.content.proposal)

    def _history(self, initial, current):
        if self.scenario.name in {"revoked-before-intent", "revoked-after-ack"}:
            from tests.dashboard_integrated_revocation import read_revocation

            revoked = read_revocation(
                self,
                current,
                required=(
                    self.scenario.name == "revoked-before-intent"
                    or self.revocation_ack_before is not None
                ),
            )
            return assert_history(
                self.engine,
                initial,
                current,
                SimpleNamespace(issuer=self.issuer),
                revocation=revoked,
            )
        if self.scenario.name == "cross-issuer":
            from tests.dashboard_integrated_bootstrap import ISSUER, SECOND_ISSUER

            if (
                not self.identity_restarted
                or initial.content.proposal.proposal_id != self.restarted_proposal
                or self.issuer != ISSUER
            ):
                raise ValueError("Unproven integrated authority generation")
            identities = (
                (ISSUER, "proposer"),
                (SECOND_ISSUER, "proposer"),
                (SECOND_ISSUER, "requester"),
            )
            return assert_history(
                self.engine,
                initial,
                current,
                SimpleNamespace(issuer=self.issuer),
                human_identities=identities,
            )
        return assert_history(self.engine, initial, current, SimpleNamespace(issuer=self.issuer))

    def _bind_proposal(self, proposal):
        baseline, source = proposal.baseline, self.source
        if (
            proposal.finding_id != source.finding_id
            or proposal.resource_id != source.resource_id
            or proposal.control_id != source.control_id
            or proposal.account_id != ACCOUNT
            or proposal.region != REGION
            or baseline.occurrence_id != source.occurrence_id
            or baseline.scan_id != source.scan_id
            or baseline.assessment_id != source.assessment_id
            or baseline.snapshot_id != source.snapshot_id
            or baseline.control_version_id != source.control_version_id
        ):
            raise ValueError

    def _run_worker(self, message):
        if self.scenario.worker == "none":
            raise ValueError("No installed worker for proposal-only scenario")
        if self.worker_dispatched:
            raise ValueError("Installed worker already dispatched; no replacement is authorized")
        self.last_stage = "OWNERSHIP"
        self._owned()
        self.last_stage = "EXECUTION_READ"
        initial = self._execution(message.target_id)
        self.last_stage = "SOURCE_BINDING"
        self._bind(initial)
        self.last_stage = "ADMISSION_BINDING"
        if (
            self.acknowledged_execution is not None
            or initial.content.idempotency_key != message.request_id
            or initial.phase is not ExecutionPhase.QUEUED
            or not initial.reservation_held
            or [reason.value for reason in initial.blocking_reasons]
            != (
                ["EXECUTION_EXPIRED"]
                if self.scenario.worker == "expired"
                else ["APPROVAL_REVOKED"]
                if self.scenario.worker == "revoked"
                else []
            )
        ):
            raise ValueError
        # Existing proof validates the three exact signed actor/audit pairs independently.
        self.last_stage = "HUMAN_AUDIT"
        self._history(initial, initial)
        if self.scenario.worker in {"expired", "revoked"}:
            from tests.worker_http import database_state

            if (
                self.scenario.worker == "expired"
                and initial.validity_checked_at < initial.content.expires_at
            ):
                raise ValueError
            if (
                self.scenario.worker == "revoked"
                and initial.validity_checked_at >= initial.content.expires_at
            ):
                raise ValueError
            self.initial_execution, self.before_worker = initial, database_state(self.engine)
        proposal = initial.content.proposal
        scenario = {
            "argv": [str(initial.content.execution_id)],
            "responses": build_worker_script(
                self.scenario.name, proposal.baseline.default_kms_key_id
            ),
            "metadata": "valid",
            "target": {
                "execution_id": str(initial.content.execution_id),
                "proposal_id": str(proposal.proposal_id),
                "resource_id": str(proposal.resource_id),
                "finding_id": str(proposal.finding_id),
            },
        }
        # No SQL session/transaction remains open across this separate installed process.
        self.last_stage = "INSTALLED_DISPATCH"
        self.worker_dispatched = True  # Sticky even if dispatch/reply/proof later fails.
        report = self.runtime.run_worker(scenario, self.child_url)
        self.worker_report = report
        self.last_stage = "INSTALLED_REPORT"
        if self.scenario.worker in {"expired", "revoked"}:
            if (
                report["exit_code"] != 0
                or report["stdout"] != "NO_WRITE\n"
                or report["calls"] != []
                or report["wire_actions"] != []
                or report["lock_probes"] != []
                or report["enable_invocations"] != 0
                or report["intent_checks"] != 0
            ):
                raise ValueError
            current = self._execution(message.target_id)
            self._bind(current)
            self._history(initial, current)
            if (
                current.phase is not ExecutionPhase.NO_WRITE
                or current.reservation_held
                or [entry.content.kind.value for entry in current.events]
                != ["REQUESTED", "NO_WRITE"]
                or [reason.value for reason in current.events[-1].content.blocking_reasons]
                != [
                    "EXECUTION_EXPIRED" if self.scenario.worker == "expired" else "APPROVAL_REVOKED"
                ]
            ):
                raise ValueError
            self.worker_history = current
            if self.scenario.worker == "expired":
                self.expired_execution = current.content.execution_id
            else:
                self.revoked_execution = current.content.execution_id
            return "WORKER_NO_WRITE"
        if (
            report["exit_code"] != 0
            or report["stdout"]
            != (
                "ACKNOWLEDGED_UNVERIFIED\n"
                if self.scenario.worker == "acknowledged"
                else "QUARANTINED_UNVERIFIED\n"
            )
            or report["enable_invocations"] != 1
            or report["intent_checks"] != 1
        ):
            raise ValueError
        self.last_stage = "ACK_HISTORY"
        current = self._execution(message.target_id)
        self._bind(current)
        self._history(initial, current)
        self.worker_history = current
        if self.scenario.worker == "acknowledged":
            if current.phase is not ExecutionPhase.ACKNOWLEDGED or current.reservation_held:
                raise ValueError
            self.acknowledged_execution = current.content.execution_id
            if self.scenario.name == "revoked-after-ack":
                from tests.worker_http import database_state

                self.revocation_ack_before = database_state(self.engine)
            return "WORKER_ACKNOWLEDGED"
        if current.phase is not ExecutionPhase.QUARANTINED or not current.reservation_held:
            raise ValueError
        self.quarantined_execution = current.content.execution_id
        return "WORKER_QUARANTINED"

    def _release_reader(self, message):
        if self.scenario.worker in {"none", "expired", "revoked"}:
            raise ValueError("No managed reader for non-verifiable scenario")
        self.last_stage = "READER_OWNERSHIP"
        self._owned()
        self.last_stage = "VERIFICATION_READ"
        with Session(self.engine) as session:
            verification = RemediationVerificationService(session).get_verification(
                message.target_id, self._principal()
            )
        self.last_stage = "VERIFICATION_BINDING"
        if (
            self.acknowledged_execution is None
            or verification.content.execution_id != self.acknowledged_execution
            or verification.content.idempotency_key != message.request_id
            or verification.content.baseline_scan_id != self.source.scan_id
            or verification.receipt is not None
        ):
            raise ValueError
        if self.scenario.name == "revoked-after-ack":
            self.last_stage = "REVOKED_ACK_HISTORY"
            current = self._execution(self.acknowledged_execution)
            self._bind(current)
            self._history(self.worker_history, current)
        # This only opens the managed reader's fixture gate; it never submits or seals a scan.
        self.last_stage = "READER_GATE"
        self.release_reader(verification.content.scan_id)

    def handle(self, raw):
        message = parse_control(raw, expected_instance=self.instance)
        if message.kind is ControlKind.STOP:
            return self.fence.close(message)
        previous, claimed = self.fence.claim(message)
        if not claimed:
            return previous
        try:
            if message.kind is ControlKind.RUN_WORKER:
                state = self._run_worker(message)
            elif message.kind is ControlKind.RELEASE_READER:
                self._release_reader(message)
                state = "READER_RELEASED"
            elif message.kind is ControlKind.RESTART_AUTHORITY:
                from tests.dashboard_integrated_authority_restart import restart_bound_authority

                state = restart_bound_authority(self, message)
            elif message.kind is ControlKind.COLLECT_STALE:
                from tests.dashboard_integrated_staleness import collect_bound_stale_observation

                state = collect_bound_stale_observation(self, message)
            elif message.kind is ControlKind.CHANGE_GOVERNANCE:
                from tests.dashboard_integrated_governance import change_bound_governance

                state = change_bound_governance(self, message)
            else:
                raise ValueError("Unsupported integrated control")
        except Exception as error:
            # A later read/proof failure cannot prove that a dispatched write did not occur.
            self.fence.finish(message, "UNCONFIRMED")
            classification = classify_control_failure(error)
            raise CoordinatorError(
                "Integrated test control is unconfirmed at "
                + self.last_stage
                + "/"
                + classification
                + "; inspect owned history"
            ) from None
        return self.fence.finish(message, state)
