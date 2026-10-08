"""Signed production-mode bearer HTTP acceptance; only issuer I/O and AWS are offline."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, Finding
from app.models.enums import FindingStatus
from app.models.remediation import RemediationDecision, RemediationProposal
from tests.dashboard_fixtures import AUDIENCE, dashboard_client, sign_in
from tests.remediation_fixtures import seed


def exercise_remediation_http(engine, monkeypatch, tmp_path):
    request, _ = seed(engine)
    with dashboard_client(engine, monkeypatch, tmp_path) as (client, issuer, _boundary, executor):

        def headers(subject, role, **overrides):
            claims = {
                "iss": issuer.issuer,
                "aud": AUDIENCE,
                "sub": subject,
                "exp": datetime.now(UTC) + timedelta(minutes=5),
                "cognito:groups": [role],
                **overrides,
            }
            token = jwt.encode(
                claims, issuer.key, algorithm="RS256", headers={"kid": "dashboard-test"}
            )
            return {"Authorization": "Bearer " + token, "Idempotency-Key": str(uuid4())}

        analyst = headers("proposer", "ANALYST")
        approver = headers("approver", "APPROVER")
        administrator = headers("executor", "ADMIN")
        viewer = headers("reader", "VIEWER")
        body = request.model_dump(mode="json")
        route = "/api/v1/remediations"
        schema = client.get("/openapi.json").json()
        for path, method in (
            (route, "get"),
            (route, "post"),
            (route + "/{proposal_id}", "get"),
            (route + "/{proposal_id}/decisions", "post"),
            (route + "/{proposal_id}/revocations", "post"),
        ):
            operation = schema["paths"][path][method]
            assert operation["security"] == [{"HTTPBearer": []}]
            if method == "post":
                key_parameter = next(
                    item for item in operation["parameters"] if item["name"] == "Idempotency-Key"
                )
                assert key_parameter["required"] is True
                assert key_parameter["in"] == "header"
                assert key_parameter["schema"]["format"] == "uuid"
        proposal_schema = schema["components"]["schemas"]["ProposalRequest"]
        assert proposal_schema["additionalProperties"] is False
        assert proposal_schema["properties"]["action_id"]["const"] == body["action_id"]
        assert proposal_schema["properties"]["action_version"]["const"] == "1.0.0"
        assert client.post(route, json=body).status_code == 401
        assert client.post(route, json=body, headers=viewer).status_code == 403
        for bad_claim in (
            {"iss": "https://untrusted-issuer.test"},
            {"aud": "wrong-audience"},
            {"exp": datetime.now(UTC) - timedelta(seconds=1)},
        ):
            assert (
                client.post(
                    route, json=body, headers=headers("proposer", "ANALYST", **bad_claim)
                ).status_code
                == 401
            )
        assert (
            client.post(
                route, json=body, headers={"Authorization": analyst["Authorization"]}
            ).status_code
            == 422
        )
        for bad_body in (
            {**body, "action_id": "arbitrary.aws.call"},
            {**body, "action_version": "2.0.0"},
            {**body, "desired_state": False},
            {**body, "account_id": "999999999999"},
            {**body, "reason": " "},
            {**body, "reason": "x" * 2001},
        ):
            assert client.post(route, json=bad_body, headers=analyst).status_code == 422
        created = client.post(route, json=body, headers=analyst)
        assert created.status_code == 201, created.text
        assert created.headers["cache-control"] == "no-store"
        proposal = created.json()
        proposal_id = proposal["content"]["proposal_id"]
        replay = client.post(route, json=body, headers=analyst)
        assert replay.status_code == 200 and replay.json()["content"]["proposal_id"] == proposal_id
        changed = client.post(route, json={**body, "reason": "Different intent."}, headers=analyst)
        assert changed.status_code == 409
        assert changed.json()["detail"]["code"] == "remediation_idempotency_conflict"
        detail_route = f"{route}/{proposal_id}"
        assert client.get(detail_route).status_code == 401
        assert client.get(detail_route, headers=viewer).json()["approval_status"] == "PROPOSED"
        page = client.get(
            route, headers=viewer, params={"finding_id": str(request.finding_id), "limit": 1}
        ).json()
        assert page["total"] == 1 and len(page["items"]) == 1
        assert client.get(route, headers=viewer, params={"limit": 101}).status_code == 422
        assert client.get(f"{route}/{uuid4()}", headers=viewer).status_code == 404
        decision = {
            "proposal_sha256": proposal["proposal_sha256"],
            "decision": "APPROVE",
            "reason": "Reviewed exact policy, risk and KMS context.",
        }
        decisions_route = detail_route + "/decisions"
        assert client.post(decisions_route, json=decision, headers=analyst).status_code == 403
        self_decision = client.post(
            decisions_route, json=decision, headers=headers("proposer", "ADMIN")
        )
        assert self_decision.status_code == 403
        assert self_decision.json()["detail"]["code"] == "remediation_separation_required"
        forged = client.post(
            decisions_route, json={**decision, "proposal_sha256": "0" * 64}, headers=approver
        )
        assert forged.status_code == 409
        approved = client.post(decisions_route, json=decision, headers=approver)
        assert approved.status_code == 201, approved.text
        approval_id = approved.json()["decision_id"]
        assert client.post(decisions_route, json=decision, headers=approver).status_code == 200
        revocation = {
            "proposal_sha256": proposal["proposal_sha256"],
            "approval_decision_id": approval_id,
            "reason": "Change window cancelled.",
        }
        assert (
            client.post(detail_route + "/revocations", json=revocation, headers=analyst).status_code
            == 403
        )
        revoked = client.post(detail_route + "/revocations", json=revocation, headers=administrator)
        assert revoked.status_code == 201, revoked.text
        assert (
            client.post(
                detail_route + "/revocations", json=revocation, headers=administrator
            ).status_code
            == 200
        )
        assert client.get(detail_route, headers=viewer).json()["approval_status"] == "REVOKED"
        for suffix in ("execute", "withdraw"):
            assert (
                client.post(detail_route + "/" + suffix, headers=administrator, json={}).status_code
                == 404
            )
        # Additive 8B1 admission exists, but defaults off; this is not an AWS execution route.
        disabled = client.post(detail_route + "/executions", json=revocation, headers=administrator)
        assert disabled.status_code == 503
        assert disabled.json()["detail"]["code"] == "remediation_execution_disabled"
        # The accepted dashboard proxy remains GET-only; cookies do not grant bearer API authority.
        sign_in(client, issuer)
        assert client.get(detail_route).status_code == 401
        assert client.post(route, json=body).status_code == 401
        assert executor.submissions == []
    with Session(engine) as session:
        assert session.get(Finding, request.finding_id).status is FindingStatus.OPEN
        assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 1
        assert session.scalar(select(func.count()).select_from(RemediationDecision)) == 2
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.target_id == UUID(proposal_id))
        ).all()
        assert len(events) == 3
        assert {event.event_metadata["actor"]["subject"] for event in events} == {
            "proposer",
            "approver",
            "executor",
        }
