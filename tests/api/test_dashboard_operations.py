"""Real signed OIDC -> coordination -> bearer API -> immutable READ confirmation."""

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event
from types import SimpleNamespace
from uuid import UUID, uuid4

import httpx2 as httpx
import jwt
import pytest
from sqlalchemy import text

from app.dashboard import operation_routes
from app.dashboard.routes import SESSION_COOKIE
from app.security.authentication import Principal
from tests.dashboard_fixtures import ORIGIN, dashboard_client, sign_in
from tests.ec2_fixtures import ACCOUNT
from tests.remediation_fixtures import seed
from tests.unit.services.test_scan_service import RecordingExecutor
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.verification_fixtures import REGION, VerificationHarness

ROOT = "/dashboard/api/remediation-operations"


def operation_document(operation="PROPOSE", *, target=None, body=None):
    if body is None:
        body = {"reason": "Reviewed the exact target and KMS/workload risk."}
        if operation == "PROPOSE":
            body.update(finding_id=str(uuid4()), occurrence_id=str(uuid4()))
        elif operation != "REQUEST_VERIFICATION":
            body["proposal_sha256"] = "a" * 64
            if operation == "DECIDE":
                body["decision"] = "APPROVE"
            else:
                body["approval_decision_id"] = str(uuid4())
    result = {"schema_version": "1.0.0", "operation": operation, "input": body}
    if operation != "PROPOSE":
        result["target_id"] = target or str(uuid4())
    return result


def mutation_headers(status):
    return {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": status["csrf_token"]}


def prepare(client, status, document):
    response = client.post(ROOT, json=document, headers=mutation_headers(status))
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def submit(client, status, value):
    return client.post(
        f"{ROOT}/{value['operation_id']}/submit", json={}, headers=mutation_headers(status)
    )


@pytest.mark.parametrize("enabled", [False, True])
def test_opt_in_routes_and_verified_bootstrap_without_widening_generic_proxy(
    migrated_engine, monkeypatch, tmp_path, enabled
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=enabled) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        assert "features" not in client.get("/dashboard/session").json()
        issuer.role = "ADMIN"
        status = sign_in(client, issuer)
        assert status["issuer"] == issuer.issuer
        assert status["features"] == {"remediation": enabled}
        assert client.get(ROOT).status_code == (200 if enabled else 404)
        assert client.post(ROOT, json={}, headers=mutation_headers(status)).status_code == (
            422 if enabled else 404
        )
        for path in [
            "scans",
            "remediations",
            "remediation-executions",
            "remediation-verifications",
        ]:
            assert client.post(f"/dashboard/api/{path}", json={}).status_code == 405
        assert executor.submissions == []


@pytest.mark.parametrize("logout", [False, True])
def test_held_committed_response_never_duplicates_or_restores_a_logged_out_session(
    migrated_engine, monkeypatch, tmp_path, logout
):
    request, _ = seed(migrated_engine)
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = "ANALYST"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(request.finding_id),
                    "occurrence_id": str(request.occurrence_id),
                    "reason": request.reason,
                }
            ),
        )
        entered, release = Event(), Event()
        original = httpx.AsyncClient.post
        committed, forwards = [], []

        async def held_post(self, url, **kwargs):
            assert url == "/api/v1/remediations"
            forwards.append((kwargs["headers"]["Idempotency-Key"], kwargs["content"]))
            response = await original(self, url, **kwargs)
            assert response.status_code == 201
            committed.append(response.json()["content"]["proposal_id"])
            entered.set()
            assert await asyncio.to_thread(release.wait, 5), "Owned response gate not released"
            return response

        with monkeypatch.context() as held:
            held.setattr(httpx.AsyncClient, "post", held_post)
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(submit, client, status, value)
                try:
                    assert entered.wait(5), "Real proposal commit did not reach response gate"
                    with migrated_engine.connect() as db:
                        assert db.scalar(text("SELECT count(*) FROM remediation_proposals")) == 1
                    current = client.get(f"{ROOT}/{value['operation_id']}").json()
                    assert current["state"] == "IN_FLIGHT" and current["attempts"] == 1
                    if logout:
                        assert (
                            client.post(
                                "/dashboard/auth/logout", headers=mutation_headers(status)
                            ).status_code
                            == 204
                        )
                    else:
                        duplicate = submit(client, status, value)
                        assert duplicate.status_code == 200 and duplicate.json() == current
                        assert len(forwards) == 1
                finally:
                    release.set()
                first = pending.result(timeout=10)
        assert len(forwards) == 1 and forwards[0][0] == value["operation_id"]
        if logout:
            assert first.status_code == 401
            assert "result_id" not in first.text and committed[0] not in first.text
            assert client.get("/dashboard/session").json()["authenticated"] is False
            sign_in(client, issuer)
            assert client.get(ROOT).json()["items"] == []
            assert client.get(f"{ROOT}/{value['operation_id']}").status_code == 404
        else:
            assert first.status_code == 200 and first.json()["state"] == "CONFIRMED"
            assert first.json()["attempts"] == 1
            assert submit(client, status, value).json() == first.json()
        history = client.get(f"/dashboard/api/remediations/{committed[0]}")
        assert history.status_code == 200
        assert history.json()["content"]["proposer"] == {
            "issuer": issuer.issuer,
            "subject": issuer.subject,
            "roles": ["ANALYST"],
            "capability": "PROPOSE",
        }
        assert executor.submissions == []


def test_real_timeout_after_commit_requires_explicit_identical_retry(
    migrated_engine, monkeypatch, tmp_path
):
    request, _ = seed(migrated_engine)
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = "ANALYST"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(request.finding_id),
                    "occurrence_id": str(request.occurrence_id),
                    "reason": request.reason,
                }
            ),
        )
        original, forwards, deadlines = httpx.AsyncClient.post, [], []

        def controlled_deadline(seconds):
            assert seconds == 15  # Production timeout contract is not lengthened.
            deadline = asyncio.timeout(None)
            deadlines.append(deadline)
            return deadline

        async def delayed_post(self, url, **kwargs):
            forwards.append((kwargs["headers"]["Idempotency-Key"], kwargs["content"]))
            response = await original(self, url, **kwargs)
            assert response.status_code == (201 if len(forwards) == 1 else 200)
            if len(forwards) == 1:
                deadlines[-1].reschedule(asyncio.get_running_loop().time() + 0.01)
                await asyncio.sleep(1)
                pytest.fail("The real timeout did not cancel the held response")
            return response

        with monkeypatch.context() as timeout:
            timeout.setattr(
                operation_routes, "asyncio", SimpleNamespace(timeout=controlled_deadline)
            )
            timeout.setattr(httpx.AsyncClient, "post", delayed_post)
            first = submit(client, status, value)
            assert first.status_code == 200 and first.json()["state"] == "UNCONFIRMED"
            assert first.json()["result"] is None and len(forwards) == 1
            assert client.get(ROOT).json()["items"] == [first.json()]
            second = submit(client, status, value)
        assert second.status_code == 200 and second.json()["state"] == "CONFIRMED"
        assert second.json()["attempts"] == 2 and len(forwards) == 2
        assert forwards[0] == forwards[1] and forwards[0][0] == value["operation_id"]
        assert second.json()["expires_at"] == value["expires_at"]
        with migrated_engine.connect() as db:
            assert db.scalar(text("SELECT count(*) FROM remediation_proposals")) == 1
        assert executor.submissions == []


def test_fresh_capability_loss_denies_uncertain_retry_without_erasing_history(
    migrated_engine, monkeypatch, tmp_path
):
    request, _ = seed(migrated_engine)
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = "ANALYST"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(request.finding_id),
                    "occurrence_id": str(request.occurrence_id),
                    "reason": request.reason,
                }
            ),
        )
        original, forwards, committed = httpx.AsyncClient.post, [], []

        async def lost_post(self, url, **kwargs):
            response = await original(self, url, **kwargs)
            assert response.status_code == 201
            forwards.append(url)
            committed.append(response.json()["content"]["proposal_id"])
            raise httpx.ReadError("Controlled loss after commit")

        with monkeypatch.context() as loss:
            loss.setattr(httpx.AsyncClient, "post", lost_post)
            assert submit(client, status, value).json()["state"] == "UNCONFIRMED"
            session = boundary.store.get(client.cookies.get(SESSION_COOKIE), touch=False)
            original_token = session.access_token
            claims = jwt.decode(
                original_token,
                issuer.key.public_key(),
                algorithms=["RS256"],
                audience=issuer.audience,
                issuer=issuer.issuer,
            )
            claims["cognito:groups"] = ["VIEWER"]
            session.access_token = jwt.encode(
                claims, issuer.key, algorithm="RS256", headers={"kid": "dashboard-test"}
            )
            assert session.principal.role_names == frozenset({"ANALYST"})  # Hint is no authority.
            denied = submit(client, status, value)
            assert denied.status_code == 403 and len(forwards) == 1
            recovered = client.get(f"{ROOT}/{value['operation_id']}").json()
            assert recovered["state"] == "UNCONFIRMED" and recovered["attempts"] == 1
            assert recovered["result"] is None
            assert client.get(f"/dashboard/api/remediations/{committed[0]}").status_code == 200
            session.access_token = original_token
        assert submit(client, status, value).json()["state"] == "CONFIRMED"
        with migrated_engine.connect() as db:
            assert db.scalar(text("SELECT count(*) FROM remediation_proposals")) == 1
        assert executor.submissions == []


def test_api_capacity_refuses_new_preparation_without_eviction_or_dispatch(
    migrated_engine, monkeypatch, tmp_path
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = "ANALYST"
        status = sign_in(client, issuer)
        prepared = [prepare(client, status, operation_document()) for _ in range(16)]
        denied = client.post(ROOT, json=operation_document(), headers=mutation_headers(status))
        assert denied.status_code == 503 and denied.headers["cache-control"] == "no-store"
        retained = client.get(ROOT).json()["items"]
        assert len(retained) == 16
        assert {item["operation_id"] for item in retained} == {
            item["operation_id"] for item in prepared
        }
        assert all(item["state"] == "PREPARED" and item["attempts"] == 0 for item in retained)
        for item in prepared:
            assert client.get(f"{ROOT}/{item['operation_id']}").json() == item
        with migrated_engine.connect() as db:
            assert db.scalar(text("SELECT count(*) FROM remediation_proposals")) == 0
        assert executor.submissions == []


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
@pytest.mark.parametrize(
    "operation", ["PROPOSE", "DECIDE", "REVOKE", "REQUEST_EXECUTION", "REQUEST_VERIFICATION"]
)
def test_preparation_requires_fresh_capability_and_creates_no_domain_history(
    migrated_engine, monkeypatch, tmp_path, role, operation
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = role
        status = sign_in(client, issuer)
        allowed = (
            role == "ADMIN"
            or role == "APPROVER"
            and operation in {"PROPOSE", "DECIDE", "REVOKE"}
            or role == "ANALYST"
            and operation == "PROPOSE"
        )
        with migrated_engine.connect() as db:
            before = "\n".join(db.connection.driver_connection.iterdump())
        response = client.post(
            ROOT, json=operation_document(operation), headers=mutation_headers(status)
        )
        assert response.status_code == (201 if allowed else 403)
        if allowed:
            value = response.json()
            assert (
                value["state"] == "PREPARED" and value["attempts"] == 0 and value["result"] is None
            )
            assert value["actor"] == {"issuer": issuer.issuer, "subject": issuer.subject}
            assert client.get(f"{ROOT}/{value['operation_id']}").json() == value
            assert client.get(ROOT).json()["items"] == [value]
            assert "access_token" not in json.dumps(value)
        with migrated_engine.connect() as db:
            assert "\n".join(db.connection.driver_connection.iterdump()) == before
        assert executor.submissions == []


@pytest.mark.parametrize(
    "change",
    [
        "origin",
        "fetch-site",
        "csrf",
        "context",
        "duplicate-origin",
        "duplicate-csrf",
        "duplicate-context",
        "duplicate-cookie",
        "authorization",
        "key",
        "query",
        "duplicate-json",
        "extra",
        "content-type",
        "oversize",
    ],
)
def test_closed_boundary_rejects_untrusted_input_without_preparing_or_forwarding(
    migrated_engine, monkeypatch, tmp_path, change
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = "ADMIN"
        status = sign_in(client, issuer)
        headers = {**mutation_headers(status), "Content-Type": "application/json"}
        raw, path = json.dumps(operation_document()).encode(), ROOT
        if change in {"origin", "fetch-site", "csrf", "context"}:
            field = {
                "origin": "Origin",
                "fetch-site": "Sec-Fetch-Site",
                "csrf": "X-CSRF-Token",
                "context": "X-Dashboard-Context",
            }[change]
            headers[field] = "not-the-current-trusted-value"
        elif change.startswith("duplicate-") and change != "duplicate-json":
            field = {
                "duplicate-origin": "Origin",
                "duplicate-csrf": "X-CSRF-Token",
                "duplicate-context": "X-Dashboard-Context",
                "duplicate-cookie": "Cookie",
            }[change]
            if field == "Cookie":
                headers[field] = f"cloudsec_session={client.cookies.get(SESSION_COOKIE)}"
            else:
                headers.setdefault(field, client.headers.get(field))
            headers = [*headers.items(), (field, headers[field])]
        elif change == "authorization":
            headers["Authorization"] = "Bearer browser-selected-identity"
        elif change == "key":
            headers["Idempotency-Key"] = str(uuid4())
        elif change == "query":
            path += "?url=https://untrusted.example.test"
        elif change == "duplicate-json":
            raw = b'{"operation":"PROPOSE","operation":"DECIDE"}'
        elif change == "extra":
            raw = json.dumps(
                {**operation_document(), "url": "https://untrusted.example.test"}
            ).encode()
        elif change == "content-type":
            headers["Content-Type"] = "text/plain"
        else:
            raw = b" " * (12 * 1024 + 1)
        response = client.post(path, content=raw, headers=headers)
        assert response.status_code in {401, 403, 413, 415, 422}
        assert "untrusted.example.test" not in response.text
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert (
            boundary.store.operations(
                client.cookies.get(SESSION_COOKIE),
                boundary.store.get(client.cookies.get(SESSION_COOKIE), touch=False).principal,
            )
            == ()
        )
        assert executor.submissions == []


def test_cached_admin_hint_cannot_grant_a_viewer_write_authority(
    migrated_engine, monkeypatch, tmp_path
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        _,
    ):
        status = sign_in(client, issuer)
        session = boundary.store.get(client.cookies.get(SESSION_COOKIE), touch=False)
        session.principal = Principal(issuer.subject, frozenset({"ADMIN"}), issuer.issuer)
        assert (
            client.post(
                ROOT, json=operation_document(), headers=mutation_headers(status)
            ).status_code
            == 403
        )
        refreshed = client.get("/dashboard/session").json()
        assert refreshed["roles"] == ["VIEWER"]


def test_lost_committed_response_is_unconfirmed_then_explicit_same_key_retry_confirms(
    migrated_engine, monkeypatch, tmp_path
):
    request, _ = seed(migrated_engine)
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = "ANALYST"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(request.finding_id),
                    "occurrence_id": str(request.occurrence_id),
                    "reason": request.reason,
                }
            ),
        )
        original = httpx.AsyncClient.post
        forwarded = []

        async def lose_response(self, url, **kwargs):
            response = await original(self, url, **kwargs)
            forwarded.append((kwargs["headers"]["Idempotency-Key"], kwargs["content"]))
            assert response.status_code == 201
            raise httpx.ReadError("controlled loss after commit")

        with monkeypatch.context() as loss:
            loss.setattr(httpx.AsyncClient, "post", lose_response)
            first = submit(client, status, value)
        assert first.status_code == 200 and first.json()["state"] == "UNCONFIRMED"
        recovered = client.get(ROOT).json()["items"]
        assert len(recovered) == 1 and recovered[0]["operation_id"] == value["operation_id"]
        second = submit(client, status, value)
        assert second.status_code == 200 and second.json()["state"] == "CONFIRMED"
        assert second.json()["attempts"] == 2
        result_id = second.json()["result"]["result_id"]
        history = client.get(f"/dashboard/api/remediations/{result_id}").json()
        assert history["content"]["proposer"]["subject"] == issuer.subject
        assert history["content"]["reason"] == request.reason
        assert forwarded[0][0] == value["operation_id"]
        assert json.loads(forwarded[0][1])["reason"] == request.reason
        assert submit(client, status, value).json() == second.json()
        with migrated_engine.connect() as db:
            assert db.scalar(text("SELECT count(*) FROM remediation_proposals")) == 1
        assert executor.submissions == []


def test_foreign_operation_expired_preparation_and_replacement_body_fail_closed(
    migrated_engine, monkeypatch, tmp_path
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        _,
    ):
        issuer.role = "ADMIN"
        status = sign_in(client, issuer)
        value = prepare(client, status, operation_document())
        path = f"{ROOT}/{value['operation_id']}/submit"
        assert (
            client.post(
                path, json={"reason": "replace"}, headers=mutation_headers(status)
            ).status_code
            == 422
        )
        assert client.get(f"{ROOT}/not-a-uuid").status_code == 404
        assert client.get(f"{ROOT}/{uuid4()}").status_code == 404
        identifier = client.cookies.get(SESSION_COOKIE)
        prepared = boundary.store.operation(
            identifier,
            boundary.store.get(identifier).principal,
            UUID(value["operation_id"]),
        )
        boundary.store._operations[prepared.operation_id] = replace(prepared, expires_at=0)
        assert submit(client, status, value).status_code == 409
        assert client.get(f"{ROOT}/{value['operation_id']}").json()["state"] == "EXPIRED"
        assert (
            client.post("/dashboard/auth/logout", headers=mutation_headers(status)).status_code
            == 204
        )
        sign_in(client, issuer)
        assert client.get(ROOT).json()["items"] == []
        assert client.get(f"{ROOT}/{value['operation_id']}").status_code == 404


def switch_identity(client, issuer, status, *, role, subject):
    assert (
        client.post("/dashboard/auth/logout", headers=mutation_headers(status)).status_code == 204
    )
    issuer.role, issuer.subject = role, subject
    return sign_in(client, issuer)


@pytest.mark.parametrize("decision", ["APPROVE", "REJECT"])
def test_signed_three_human_decision_admission_and_revocation_preserve_distinct_authority(
    migrated_engine, monkeypatch, tmp_path, decision
):
    request, _ = seed(migrated_engine, region=REGION)
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        # Explicit local fixture scope, independent of scanner configuration and UI opt-in.
        boundary.settings.remediation_admission_enabled = True
        boundary.settings.remediation_account_id = ACCOUNT
        boundary.settings.remediation_region = REGION
        issuer.role, issuer.subject = "ANALYST", "signed-proposer"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(request.finding_id),
                    "occurrence_id": str(request.occurrence_id),
                    "reason": request.reason,
                }
            ),
        )
        submitted = submit(client, status, value).json()
        assert submitted["state"] == "CONFIRMED"
        proposal_id = submitted["result"]["result_id"]
        proposal = client.get(f"/dashboard/api/remediations/{proposal_id}").json()
        digest = proposal["proposal_sha256"]
        status = switch_identity(client, issuer, status, role="APPROVER", subject="signed-approver")
        value = prepare(
            client,
            status,
            operation_document(
                "DECIDE",
                target=proposal_id,
                body={
                    "proposal_sha256": digest,
                    "decision": decision,
                    "reason": "Independent exact review.",
                },
            ),
        )
        submitted = submit(client, status, value).json()
        assert submitted["state"] == "CONFIRMED"
        approval_id = submitted["result"]["result_id"]
        proposal = client.get(f"/dashboard/api/remediations/{proposal_id}").json()
        assert proposal["approval_status"] == ("APPROVED" if decision == "APPROVE" else "REJECTED")
        assert proposal["decisions"][0]["actor"]["subject"] == "signed-approver"
        if decision == "REJECT":
            assert executor.submissions == []
            return
        status = switch_identity(client, issuer, status, role="ADMIN", subject="signed-requester")
        value = prepare(
            client,
            status,
            operation_document(
                "REQUEST_EXECUTION",
                target=proposal_id,
                body={
                    "proposal_sha256": digest,
                    "approval_decision_id": approval_id,
                    "reason": "Request bounded admission; do not launch a worker.",
                },
            ),
        )
        submitted = submit(client, status, value).json()
        assert submitted["state"] == "CONFIRMED"
        execution_id = submitted["result"]["result_id"]
        execution = client.get(f"/dashboard/api/remediation-executions/{execution_id}").json()
        assert execution["phase"] == "QUEUED" and execution["reservation_held"] is True
        assert execution["content"]["requested_by"]["subject"] == "signed-requester"
        assert execution["content"]["proposal"]["proposer"]["subject"] == "signed-proposer"
        assert execution["content"]["approval"]["actor"]["subject"] == "signed-approver"
        status = switch_identity(client, issuer, status, role="APPROVER", subject="signed-revoker")
        value = prepare(
            client,
            status,
            operation_document(
                "REVOKE",
                target=proposal_id,
                body={
                    "proposal_sha256": digest,
                    "approval_decision_id": approval_id,
                    "reason": "Revoke without claiming earlier effects were canceled.",
                },
            ),
        )
        assert submit(client, status, value).json()["state"] == "CONFIRMED"
        proposal = client.get(f"/dashboard/api/remediations/{proposal_id}").json()
        assert proposal["approval_status"] == "REVOKED"
        assert executor.submissions == []  # Admission is not a worker or scanner launcher.


def test_self_approval_is_denied_by_real_service_without_admin_bypass(
    migrated_engine, monkeypatch, tmp_path
):
    request, _ = seed(migrated_engine)
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        _,
        executor,
    ):
        issuer.role = "ADMIN"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(request.finding_id),
                    "occurrence_id": str(request.occurrence_id),
                    "reason": request.reason,
                }
            ),
        )
        proposal_id = submit(client, status, value).json()["result"]["result_id"]
        history_path = f"/dashboard/api/remediations/{proposal_id}"
        proposal = client.get(history_path).json()
        value = prepare(
            client,
            status,
            operation_document(
                "DECIDE",
                target=proposal_id,
                body={
                    "proposal_sha256": proposal["proposal_sha256"],
                    "decision": "APPROVE",
                    "reason": "Same human must not approve even as ADMIN.",
                },
            ),
        )
        assert submit(client, status, value).json()["state"] == "UNCONFIRMED"
        after = client.get(history_path).json()
        assert after["approval_status"] == "PROPOSED" and after["decisions"] == []
        assert executor.submissions == []


@pytest.mark.parametrize("submission_fails", [False, True])
def test_verification_accepted_request_and_durable_submission_failure_are_not_verdicts(
    migrated_engine, monkeypatch, tmp_path, submission_fails
):
    harness = VerificationHarness(migrated_engine)
    with dashboard_client(
        migrated_engine,
        monkeypatch,
        tmp_path,
        remediation_enabled=True,
        executor_factory=lambda: RecordingExecutor(
            RuntimeError("controlled submission failure") if submission_fails else None
        ),
    ) as (client, issuer, boundary, executor):
        boundary.settings.remediation_verification_enabled = True
        boundary.settings.remediation_verification_account_id = ACCOUNT
        boundary.settings.remediation_verification_region = REGION
        issuer.role, issuer.subject = "ADMIN", "signed-observer"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document("REQUEST_VERIFICATION", target=str(harness.execution_id)),
        )
        result = submit(client, status, value)
        assert result.status_code == 200 and result.json()["state"] == "CONFIRMED"
        reference = result.json()["result"]
        history = client.get(
            f"/dashboard/api/remediation-verifications/{reference['result_id']}"
        ).json()
        assert history["content"]["scan_id"] == reference["scan_id"]
        assert history["content"]["idempotency_key"] == value["operation_id"]
        assert history["content"]["requested_by"]["subject"] == "signed-observer"
        assert history["receipt"] is None or history["receipt"]["outcome"] != "VERIFIED"
        assert len(executor.submissions) == 1
        assert submit(client, status, value).json() == result.json()
        assert len(executor.submissions) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "response-id",
        "response-actor",
        "response-digest",
        "response-invalid",
        "history-actor",
        "history-digest",
        "history-unauthorized",
    ],
)
def test_malformed_or_cross_bound_response_never_confirms_an_untrusted_reference(
    migrated_engine, monkeypatch, tmp_path, fault
):
    request, _ = seed(migrated_engine)
    with dashboard_client(migrated_engine, monkeypatch, tmp_path, remediation_enabled=True) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = "ANALYST"
        status = sign_in(client, issuer)
        value = prepare(
            client,
            status,
            operation_document(
                body={
                    "finding_id": str(request.finding_id),
                    "occurrence_id": str(request.occurrence_id),
                    "reason": request.reason,
                }
            ),
        )
        original_post, original_get = httpx.AsyncClient.post, httpx.AsyncClient.get
        posts = []

        def corrupt(response):
            if fault == "history-unauthorized":
                return httpx.Response(401, json={"detail": "controlled unauthorized history"})
            if fault == "response-invalid":
                return httpx.Response(201, json={"private": "must-not-reflect-this-response"})
            body = response.json()
            if fault == "response-id":
                body["content"]["proposal_id"] = str(uuid4())
            elif fault.endswith("actor"):
                body["content"]["proposer"]["subject"] = "another-actor"
            else:
                body["proposal_sha256"] = "b" * 64
            return httpx.Response(response.status_code, json=body)

        async def post(self, url, **kwargs):
            response = await original_post(self, url, **kwargs)
            posts.append(url)
            return corrupt(response) if fault.startswith("response-") else response

        async def get(self, url, **kwargs):
            response = await original_get(self, url, **kwargs)
            return corrupt(response) if fault.startswith("history-") else response

        with monkeypatch.context() as transport_fault:
            transport_fault.setattr(httpx.AsyncClient, "post", post)
            transport_fault.setattr(httpx.AsyncClient, "get", get)
            response = submit(client, status, value)
        assert len(posts) == 1
        assert "must-not-reflect-this-response" not in response.text
        if fault == "history-unauthorized":
            assert response.status_code == 401
            assert client.get("/dashboard/session").json()["authenticated"] is False
        else:
            assert response.status_code == 200 and response.json()["state"] == "UNCONFIRMED"
            assert response.json()["result"] is None
            assert client.get(f"{ROOT}/{value['operation_id']}").json()["state"] == "UNCONFIRMED"
        with migrated_engine.connect() as db:
            assert db.scalar(text("SELECT count(*) FROM remediation_proposals")) == 1
        assert executor.submissions == []
