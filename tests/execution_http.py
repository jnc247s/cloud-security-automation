"""Real signed production-mode bearer admission; AWS calls are forbidden."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Finding
from app.models.enums import FindingStatus
from app.models.remediation_execution import RemediationExecution, RemediationExecutionEvent
from tests.dashboard_fixtures import AUDIENCE, dashboard_client, sign_in
from tests.remediation_fixtures import seed


def exercise_execution_http(engine, monkeypatch, tmp_path):
    source, _ = seed(engine)
    with dashboard_client(engine, monkeypatch, tmp_path) as (client, issuer, _boundary, executor):

        def headers(subject, role, **overrides):
            token = jwt.encode(
                {
                    "iss": issuer.issuer,
                    "aud": AUDIENCE,
                    "sub": subject,
                    "exp": datetime.now(UTC) + timedelta(minutes=5),
                    "cognito:groups": [role],
                    **overrides,
                },
                issuer.key,
                algorithm="RS256",
                headers={"kid": "dashboard-test"},
            )
            return {"Authorization": "Bearer " + token, "Idempotency-Key": str(uuid4())}

        proposer = headers("proposer", "ANALYST")
        approver = headers("approver", "APPROVER")
        requester = headers("third-human", "ADMIN")
        viewer = headers("reader", "VIEWER")
        proposal_response = client.post(
            "/api/v1/remediations", json=source.model_dump(mode="json"), headers=proposer
        )
        assert proposal_response.status_code == 201
        proposal = proposal_response.json()
        route = "/api/v1/remediations/" + proposal["content"]["proposal_id"]
        decision = client.post(
            route + "/decisions",
            json={
                "proposal_sha256": proposal["proposal_sha256"],
                "decision": "APPROVE",
                "reason": "Reviewed workload and default key compatibility.",
            },
            headers=approver,
        )
        assert decision.status_code == 201
        body = {
            "proposal_sha256": proposal["proposal_sha256"],
            "approval_decision_id": decision.json()["decision_id"],
            "reason": "Execute reviewed intent.",
        }
        admission = route + "/executions"
        assert client.post(admission, json=body).status_code == 401
        assert client.post(admission, json=body, headers=viewer).status_code == 403
        assert client.post(admission, json=body, headers=requester).status_code == 503
        monkeypatch.setenv("REMEDIATION_ADMISSION_ENABLED", "true")
        monkeypatch.setenv("REMEDIATION_ACCOUNT_ID", "123456789012")
        monkeypatch.setenv("REMEDIATION_REGION", "us-east-1")
        get_settings.cache_clear()
        for human in ("proposer", "approver"):
            response = client.post(admission, json=body, headers=headers(human, "ADMIN"))
            assert response.status_code == 403
            assert response.json()["detail"]["code"] == "remediation_separation_required"
        for bad_claim in (
            {"iss": "https://untrusted.example.test"},
            {"aud": "wrong"},
            {"exp": datetime.now(UTC) - timedelta(seconds=1)},
        ):
            assert (
                client.post(
                    admission, json=body, headers=headers("third-human", "ADMIN", **bad_claim)
                ).status_code
                == 401
            )
        assert (
            client.post(
                admission, json=body, headers={"Authorization": requester["Authorization"]}
            ).status_code
            == 422
        )
        for extra in (
            "region",
            "account_id",
            "role_arn",
            "credentials",
            "endpoint_url",
            "action_id",
            "desired_state",
        ):
            assert (
                client.post(
                    admission, json={**body, extra: "forbidden"}, headers=requester
                ).status_code
                == 422
            )
        for invalid in ({**body, "reason": " "}, {**body, "reason": "x" * 2001}):
            assert client.post(admission, json=invalid, headers=requester).status_code == 422
        assert (
            client.post(
                admission, json={**body, "proposal_sha256": "0" * 64}, headers=requester
            ).status_code
            == 409
        )
        accepted = client.post(admission, json=body, headers=requester)
        assert accepted.status_code == 202
        assert accepted.headers["cache-control"] == "no-store"
        execution = accepted.json()
        assert execution["phase"] == "QUEUED"
        assert execution["reservation_held"] is True
        assert execution["content"]["requested_by"]["subject"] == "third-human"
        assert client.post(admission, json=body, headers=requester).status_code == 200
        assert (
            client.post(
                admission, json={**body, "reason": "Changed"}, headers=requester
            ).status_code
            == 409
        )
        assert (
            client.post(
                admission, json=body, headers=headers("other-operator", "ADMIN")
            ).status_code
            == 409
        )
        lost_role = headers("third-human", "VIEWER")
        lost_role["Idempotency-Key"] = requester["Idempotency-Key"]
        assert client.post(admission, json=body, headers=lost_role).status_code == 403
        history = "/api/v1/remediation-executions"
        detail = history + "/" + execution["content"]["execution_id"]
        assert client.get(detail).status_code == 401
        viewed = client.get(detail, headers=viewer)
        assert viewed.status_code == 200
        assert viewed.headers["cache-control"] == "no-store"
        page = client.get(
            history, params={"proposal_id": proposal["content"]["proposal_id"]}, headers=viewer
        )
        assert page.status_code == 200 and page.json()["total"] == 1
        assert client.get(history, params={"limit": 101}, headers=viewer).status_code == 422
        assert (
            client.get(history, params={"proposal_id": str(uuid4())}, headers=viewer).json()[
                "total"
            ]
            == 0
        )
        assert client.get(history + "/" + str(uuid4()), headers=viewer).status_code == 404
        schema = client.get("/openapi.json").json()
        for path, method in (
            ("/api/v1/remediations/{proposal_id}/executions", "post"),
            (history, "get"),
            (history + "/{execution_id}", "get"),
        ):
            assert schema["paths"][path][method]["security"] == [{"HTTPBearer": []}]
        assert schema["components"]["schemas"]["ExecutionRequest"]["additionalProperties"] is False
        assert set(schema["components"]["schemas"]["ExecutionPhase"]["enum"]) == {
            "QUEUED",
            "EXPIRED",
            "BLOCKED",
            "CLAIMED",
            "WRITE_INTENT",
            "NO_WRITE",
            "ACKNOWLEDGED",
            "QUARANTINED",
        }
        # Only the approved additive worker vocabulary changes. Old human event bytes and
        # closed input contracts remain version 1; no worker launch/credential API is added.
        legacy = schema["components"]["schemas"]["ExecutionEventContent"]
        assert set(legacy["properties"]["phase"]["enum"]) == {"QUEUED", "EXPIRED", "BLOCKED"}
        assert legacy["properties"]["schema_version"]["const"] == "1.0.0"
        worker = schema["components"]["schemas"]["WorkerEventContent"]
        assert worker["additionalProperties"] is False
        assert worker["properties"]["schema_version"]["const"] == "2.0.0"
        assert set(schema["components"]["schemas"]["WorkerEventKind"]["enum"]) == {
            "CLAIMED",
            "WRITE_INTENT",
            "NO_WRITE",
            "ACKNOWLEDGED",
            "QUARANTINED",
            "OBSERVED",
            "OBSERVATION_FAILED",
        }
        assert set(schema["components"]["schemas"]["ExecutionRequest"]["properties"]) == {
            "proposal_sha256",
            "approval_decision_id",
            "reason",
        }
        assert client.post(route + "/execute", json=body, headers=requester).status_code == 404
        sign_in(client, issuer)
        assert client.post(admission, json=body).status_code == 401
        assert executor.submissions == []
    with Session(engine) as session:
        assert session.get(Finding, source.finding_id).status is FindingStatus.OPEN
        assert session.scalar(select(func.count()).select_from(RemediationExecution)) == 1
        assert session.scalar(select(func.count()).select_from(RemediationExecutionEvent)) == 1
