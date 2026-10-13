"""Signed production-mode admission/READ; real offline scan and immutable database receipts."""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.models.enums import AuditEventType
from tests.dashboard_fixtures import dashboard_client
from tests.verification_fixtures import REGION, VerificationHarness
from tests.worker_http import signed_headers


def exercise_verification_http(engine, monkeypatch, tmp_path):
    harness = VerificationHarness(engine)
    for name, value in {
        "REMEDIATION_VERIFICATION_ENABLED": "true",
        "REMEDIATION_VERIFICATION_ACCOUNT_ID": "123456789012",
        "REMEDIATION_VERIFICATION_REGION": REGION,
    }.items():
        monkeypatch.setenv(name, value)
    with dashboard_client(engine, monkeypatch, tmp_path) as (client, issuer, _, executor):
        route = f"/api/v1/remediation-executions/{harness.execution_id}/verifications"
        read_route = "/api/v1/remediation-verifications"
        reader = signed_headers(issuer, "reader", "VIEWER")
        key = uuid4()
        operator = signed_headers(issuer, "verification-operator", "ADMIN", key=key)
        body = {"reason": "Check the acknowledged setting under the original policy."}
        assert client.post(route, json=body).status_code == 401
        assert client.post(route, json=body, headers=reader).status_code == 403
        for override in (
            {"iss": "https://wrong.test"},
            {"aud": "wrong"},
            {"exp": datetime.now(UTC) - timedelta(seconds=1)},
        ):
            assert (
                client.post(
                    route,
                    json=body,
                    headers=signed_headers(issuer, "verification-operator", "ADMIN", **override),
                ).status_code
                == 401
            )
        for extra in (
            {"scan_id": str(uuid4())},
            {"profile_version": "latest"},
            {"region": REGION},
            {"desired_state": True},
            {"reason": " "},
        ):
            assert client.post(route, json={**body, **extra}, headers=operator).status_code == 422
        assert (
            client.post(
                route, json=body, headers={"Authorization": operator["Authorization"]}
            ).status_code
            == 422
        )
        assert client.get(read_route).status_code == 401
        assert executor.submissions == []
        created = client.post(route, json=body, headers=operator)
        assert created.status_code == 202, created.text
        assert created.headers["cache-control"] == "no-store"
        value = created.json()
        scan_id = UUID(value["content"]["scan_id"])
        verification_id = value["content"]["verification_id"]
        assert value["content"]["requested_by"] == {
            "issuer": issuer.issuer,
            "subject": "verification-operator",
            "roles": ["ADMIN"],
            "capability": "EXECUTE",
        }
        assert value["content"]["profile_version"] == "6.3.0" and value["receipt"] is None
        assert executor.submissions == [scan_id]
        replay = client.post(route, json=body, headers=operator)
        assert replay.status_code == 200 and replay.json() == value
        assert len(executor.submissions) == 1
        # Authorized retries are reads of accepted history, not new submissions.
        client.app.state.scan_executor = None
        unavailable_replay = client.post(route, json=body, headers=operator)
        assert unavailable_replay.status_code == 200, unavailable_replay.text
        assert unavailable_replay.json() == value
        unavailable_new = client.post(
            route, json=body, headers=signed_headers(issuer, "verification-operator", "ADMIN")
        )
        assert unavailable_new.status_code == 503
        assert len(executor.submissions) == 1
        client.app.state.scan_executor = executor
        changed = client.post(route, json={"reason": "Changed."}, headers=operator)
        assert (
            changed.status_code == 409
            and changed.json()["detail"]["code"] == "remediation_idempotency_conflict"
        )
        assert (
            client.post(
                route,
                json=body,
                headers=signed_headers(issuer, "verification-operator", "VIEWER", key=key),
            ).status_code
            == 403
        )
        harness.run(scan_id, observe_at=datetime.now(UTC))
        detail = client.get(read_route + "/" + verification_id, headers=reader)
        assert detail.status_code == 200, detail.text
        assert detail.headers["cache-control"] == "no-store"
        complete = detail.json()
        assert complete["receipt"]["outcome"] == "VERIFIED"
        assert complete["receipt"]["evidence"]["technical_result"] == "PASS"
        assert client.post(route, json=body, headers=operator).json() == complete
        assert len(executor.submissions) == 1
        page = client.get(
            read_route,
            headers=reader,
            params={"execution_id": str(harness.execution_id), "limit": 1},
        ).json()
        assert page["total"] == 1 and page["items"] == [complete]
        assert client.get(read_route, headers=reader, params={"limit": 101}).status_code == 422
        assert client.get(read_route + "/" + str(uuid4()), headers=reader).status_code == 404
        schema = client.get("/openapi.json").json()
        for path, method in (
            ("/api/v1/remediation-executions/{execution_id}/verifications", "post"),
            (read_route, "get"),
            (read_route + "/{verification_id}", "get"),
        ):
            assert schema["paths"][path][method]["security"] == [{"HTTPBearer": []}]
        request_schema = schema["components"]["schemas"]["VerificationRequest"]
        assert request_schema["additionalProperties"] is False
        assert set(request_schema["properties"]) == {"reason"}
    with Session(engine) as session:
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.event_type == AuditEventType.REMEDIATION_VERIFICATION_REQUESTED
            )
        )
        assert audit.event_metadata["actor"]["subject"] == "verification-operator"
