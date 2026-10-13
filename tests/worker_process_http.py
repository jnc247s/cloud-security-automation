"""Signed parent HTTP and independent history for fresh installed offline worker processes."""

import re
from contextlib import contextmanager
from datetime import timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Finding
from app.models.enums import FindingStatus
from app.models.remediation_execution import RemediationWorkerClaim
from app.remediation.execution_contracts import ExecutionPhase, ExecutionView
from app.remediation.provenance import utc
from tests.dashboard_fixtures import dashboard_client
from tests.remediation_fixtures import seed
from tests.worker_fault_http import SignedFaultJourney
from tests.worker_http import (
    ACCOUNT,
    REGION,
    ROLE,
    assert_history,
    database_state,
    history_projection,
    protected_state,
    signed_headers,
)
from tests.worker_process_harness import ENABLE, ENCRYPTION, IDENTITY, KEY


class ProcessJourney:
    # Reuse only the accepted pure persistence/audit guards, not the in-process worker runner.
    _authority_delta = SignedFaultJourney._authority_delta
    _other_audits = SignedFaultJourney._other_audits
    evidence_fixture = SignedFaultJourney.evidence_fixture

    def __init__(
        self, runtime, engine, child_url, client, issuer, executor, source, original, monkeypatch
    ):
        self.runtime, self.engine, self.child_url = runtime, engine, child_url
        self.client, self.issuer, self.executor = client, issuer, executor
        self.source, self.original = source, original
        self.monkeypatch = monkeypatch
        self.protected = protected_state(original)
        self.other_audits = {row.event_id: row for row in original["audit_events"]}
        self.reader = signed_headers(issuer, "reader", "VIEWER")
        self.requester = signed_headers(issuer, "requester", "ADMIN")
        proposal = client.post(
            "/api/v1/remediations",
            json=source.model_dump(mode="json"),
            headers=signed_headers(issuer, "proposer", "ANALYST"),
        )
        assert proposal.status_code == 201, proposal.text
        content = proposal.json()
        route = "/api/v1/remediations/" + content["content"]["proposal_id"]
        decision = {
            "proposal_sha256": content["proposal_sha256"],
            "decision": "APPROVE",
            "reason": "Reviewed exact installed-process test intent and key context.",
        }
        assert (
            client.post(
                route + "/decisions",
                json=decision,
                headers=signed_headers(issuer, "proposer", "ADMIN"),
            ).status_code
            == 403
        )
        approval = client.post(
            route + "/decisions",
            json=decision,
            headers=signed_headers(issuer, "approver", "APPROVER"),
        )
        assert approval.status_code == 201, approval.text
        self.admission = route + "/executions"
        self.body = {
            "proposal_sha256": content["proposal_sha256"],
            "approval_decision_id": approval.json()["decision_id"],
            "reason": "Run only the independently approved synthetic process action.",
        }
        assert (
            client.post(self.admission, json=self.body, headers=self.requester).status_code == 503
        )
        monkeypatch.setenv("REMEDIATION_ADMISSION_ENABLED", "true")
        monkeypatch.setenv("REMEDIATION_ACCOUNT_ID", ACCOUNT)
        monkeypatch.setenv("REMEDIATION_REGION", REGION)
        get_settings.cache_clear()
        for subject in ("proposer", "approver"):
            assert (
                client.post(
                    self.admission,
                    json=self.body,
                    headers=signed_headers(issuer, subject, "ADMIN"),
                ).status_code
                == 403
            )
        assert client.post(self.admission, json=self.body).status_code == 401
        assert client.post(self.admission, json=self.body, headers=self.reader).status_code == 403
        accepted = client.post(self.admission, json=self.body, headers=self.requester)
        assert accepted.status_code == 202, accepted.text
        assert accepted.headers["cache-control"] == "no-store"
        self._authority_delta(original, database_state(engine), content, approval.json(), True)
        self.initial = ExecutionView.model_validate(accepted.json())
        self.execution_id = self.initial.content.execution_id
        self.authority_baseline = database_state(engine)
        assert self.initial.phase is ExecutionPhase.QUEUED and self.initial.reservation_held
        assert (
            len(self.initial.events) == 1
            and self.initial.events[0].content.schema_version == "1.0.0"
        )
        self.detail = "/api/v1/remediation-executions/" + str(self.initial.content.execution_id)
        assert executor.submissions == []

    def additional_grant(self, source, *, expected_status=202):
        """Each extra authority is signed and checked before extending expectations."""
        before = database_state(self.engine)
        proposal = self.client.post(
            "/api/v1/remediations",
            json=source.model_dump(mode="json"),
            headers=signed_headers(self.issuer, "proposer", "ANALYST"),
        )
        assert proposal.status_code == 201, proposal.text
        proposal = proposal.json()
        route = "/api/v1/remediations/" + proposal["content"]["proposal_id"]
        approval = self.client.post(
            route + "/decisions",
            json={
                "proposal_sha256": proposal["proposal_sha256"],
                "decision": "APPROVE",
                "reason": "Independent review of this additional offline target.",
            },
            headers=signed_headers(self.issuer, "approver", "APPROVER"),
        )
        assert approval.status_code == 201, approval.text
        self.monkeypatch.setenv("REMEDIATION_ACCOUNT_ID", proposal["content"]["account_id"])
        self.monkeypatch.setenv("REMEDIATION_REGION", proposal["content"]["region"])
        get_settings.cache_clear()
        before_admission = database_state(self.engine)
        response = self.client.post(
            route + "/executions",
            json={
                "proposal_sha256": proposal["proposal_sha256"],
                "approval_decision_id": approval.json()["decision_id"],
                "reason": "Run only this separately approved offline target.",
            },
            headers=signed_headers(self.issuer, "requester", "ADMIN"),
        )
        assert response.status_code == expected_status, response.text
        after = database_state(self.engine)
        if expected_status != 202:
            assert after == before_admission, "failed admission changed persistence"
        self._authority_delta(before, after, proposal, approval.json(), expected_status == 202)
        self.authority_baseline = after
        if expected_status == 202:
            view = ExecutionView.model_validate(response.json())
            assert view.phase is ExecutionPhase.QUEUED and view.reservation_held
            assert_history(self.engine, view, view, self.issuer)
        assert self.executor.submissions == []
        return response

    def claim_state(self):
        with Session(self.engine) as session:
            row = session.get(RemediationWorkerClaim, self.execution_id)
            return (
                None
                if row is None
                else {
                    column.name: getattr(row, column.name)
                    for column in RemediationWorkerClaim.__table__.columns
                }
            )

    def _coordination(self, after, current, *, held, expected_readback=None):
        """Allow only own journal/claim/target changes; immutable authority stays exact."""
        mutable = {
            "audit_events",
            "remediation_execution_events",
            "remediation_worker_claims",
            "remediation_target_reservations",
        }
        for name, rows in self.authority_baseline.items():
            if name.startswith("remediation_") and name not in mutable:
                assert after[name] == rows, "immutable authority or guard changed"
        old_events = {
            row.event_id: row for row in self.authority_baseline["remediation_execution_events"]
        }
        events = {row.event_id: row for row in after["remediation_execution_events"]}
        assert all(events.get(key) == row for key, row in old_events.items())
        own_ids = {entry.content.event_id for entry in current.events}
        other_ids = {
            key for key, row in old_events.items() if row.execution_id != self.execution_id
        }
        assert set(events) == own_ids | other_ids, "unexpected execution journal rows"
        before_targets = self.authority_baseline["remediation_target_reservations"]
        targets = {row.reservation_id: row for row in after["remediation_target_reservations"]}
        assert set(targets) == {row.reservation_id for row in before_targets}
        for old in before_targets:
            expected = dict(old._mapping)
            if old.account_id == ACCOUNT and old.region == REGION:
                expected["execution_id"] = self.execution_id if held else None
            assert dict(targets[old.reservation_id]._mapping) == expected, (
                "unexpected target changes"
            )
        claims = after["remediation_worker_claims"]
        claim_events = [
            entry.content for entry in current.events if entry.content.kind.value == "CLAIMED"
        ]
        assert len(claims) == int(bool(claim_events)), "unexpected private worker claims"
        if not claim_events:
            return
        claim = claims[0]
        assert claim.execution_id == self.execution_id and claim.expected_role_arn == ROLE
        assert claim.generation == len(claim_events), "unexpected owner generation"
        assert re.fullmatch(r"[0-9a-f]{64}", claim.token_sha256)
        assert 0 <= claim.read_attempts <= 3
        assert utc(claim.lease_until) == min(
            current.content.expires_at, claim_events[-1].created_at + timedelta(seconds=30)
        )
        intents = [
            entry.content for entry in current.events if entry.content.kind.value == "WRITE_INTENT"
        ]
        assert len(intents) <= 1
        assert claim.write_intent_event_id == (intents[0].event_id if intents else None)
        polls = max((getattr(entry.content, "polls", 0) for entry in current.events), default=0)
        assert claim.readback_attempts == (
            polls if expected_readback is None else expected_readback
        )
        assert (claim.readback_started_at is None) == (claim.readback_attempts == 0)

    def view(self):
        response = self.client.get(self.detail, headers=self.reader)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        return ExecutionView.model_validate(response.json())

    def run(
        self,
        responses,
        *,
        metadata="valid",
        environment=None,
        argv=None,
        expected_engines=1,
        dotenv=False,
        guard_disarmed=False,
        application="worker",
    ):
        proposal = self.initial.content.proposal
        report = self.runtime.run_worker(
            {
                "argv": [str(self.initial.content.execution_id)] if argv is None else argv,
                "responses": responses,
                "metadata": metadata,
                "target": {
                    "execution_id": str(self.initial.content.execution_id),
                    "proposal_id": str(proposal.proposal_id),
                    "resource_id": str(proposal.resource_id),
                    "finding_id": str(proposal.finding_id),
                },
            },
            self.child_url,
            environment=environment,
            dotenv=dotenv,
            guard_disarmed=guard_disarmed,
            application=application,
        )
        assert report["stderr"] == "" and report["errors"] == []
        assert report["calls"] == report["lock_probes"]
        assert type(report["enable_invocations"]) is int
        assert report["enable_invocations"] in {0, 1}
        assert report["wire_actions"].count(ENABLE) == report["enable_invocations"]
        assert report["intent_checks"] == report["enable_invocations"]
        assert report["uid"] > 0
        assert set(report["versions"]) == {"python", "boto3", "botocore"}
        assert report["engine_creations"] == expected_engines
        assert report["host_file_reads"] == 0
        if application == "worker":
            assert report["application_settings_reads"] == 0
        else:
            assert report["application_settings_reads"] >= 1
        return report

    def check(self, phase, *, held=False, expected_readback=None):
        current = self.view()
        assert current.phase is phase and current.reservation_held is held
        assert_history(self.engine, self.initial, current, self.issuer)
        after = database_state(self.engine)
        assert protected_state(after) == self.protected
        assert self._other_audits() == self.other_audits, "unexpected unrelated audit changes"
        self._coordination(after, current, held=held, expected_readback=expected_readback)
        old = {row.event_id: row for row in self.original["audit_events"]}
        new = {row.event_id: row for row in after["audit_events"]}
        assert all(new[key] == value for key, value in old.items())
        own_audits = [
            row
            for row in after["audit_events"]
            if (
                row.target_type == "remediation"
                and row.target_id == current.content.proposal.proposal_id
            )
            or (row.target_type == "remediation_execution" and row.target_id == self.execution_id)
        ]
        assert len(own_audits) == 2 + len(current.events)
        with Session(self.engine) as session:
            assert session.get(Finding, self.source.finding_id).status is FindingStatus.OPEN
        expected = history_projection(self.client.get(self.detail, headers=self.reader))
        assert history_projection(self.client.get(self.detail, headers=self.reader)) == expected
        assert self.client.get(self.detail).status_code == 401
        listed = self.client.get(
            "/api/v1/remediation-executions",
            headers=self.reader,
            params={"proposal_id": str(self.initial.content.proposal.proposal_id)},
        )
        assert listed.status_code == 200 and listed.headers["cache-control"] == "no-store"
        assert listed.json()["total"] == 1 and len(listed.json()["items"]) == 1
        assert (
            ExecutionView.model_validate(listed.json()["items"][0]).model_dump(
                mode="json", exclude={"validity_checked_at"}
            )
            == expected
        )
        assert (
            history_projection(
                self.client.post(self.admission, json=self.body, headers=self.requester)
            )
            == expected
        )
        lost = signed_headers(
            self.issuer, "requester", "VIEWER", key=UUID(self.requester["Idempotency-Key"])
        )
        assert self.client.post(self.admission, json=self.body, headers=lost).status_code == 403
        assert (
            self.client.post(
                self.admission, json={**self.body, "reason": "changed"}, headers=self.requester
            ).status_code
            == 409
        )
        assert self.executor.submissions == [] and database_state(self.engine) == after
        return current


@contextmanager
def signed_process_journey(runtime, engine, child_url, monkeypatch, tmp_path, *, baseline_key=None):
    from unittest.mock import Mock

    from app.remediation.worker_aws import EbsDefaultWriter
    from app.remediation.worker_driver import RemediationWorker

    source, _ = seed(
        engine, kms_error={"KmsKeyId": baseline_key} if baseline_key is not None else {}
    )
    original = database_state(engine)
    # These are parent-only prohibitions, not replaced child worker/factory implementations.
    no_worker = Mock(side_effect=AssertionError("API parent cannot start a remediation worker"))
    no_writer = Mock(side_effect=AssertionError("API parent cannot construct a writer"))
    monkeypatch.setattr(RemediationWorker, "__init__", no_worker)
    monkeypatch.setattr(EbsDefaultWriter, "from_ecs", no_writer)
    with dashboard_client(engine, monkeypatch, tmp_path) as (client, issuer, _browser, executor):
        journey = ProcessJourney(
            runtime, engine, child_url, client, issuer, executor, source, original, monkeypatch
        )
        yield journey
        no_worker.assert_not_called()
        no_writer.assert_not_called()


def script_for(outcome, key):
    observed_key = (
        "unreviewed-key"
        if outcome in {"changed-key", "unexpected-key"}
        else None
        if outcome == "missing-key"
        else key
    )
    values = [[IDENTITY, "valid"], [ENCRYPTION, outcome == "already-enabled"], [KEY, observed_key]]
    if outcome == "acknowledged":
        values += [[ENABLE, True], [IDENTITY, "valid"], [ENCRYPTION, True], [KEY, key]]
    return values
