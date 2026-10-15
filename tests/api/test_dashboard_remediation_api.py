"""New history GETs cross the real signed API/READ boundary, without mutation."""

from uuid import uuid4

import httpx2 as httpx
import pytest
from sqlalchemy import text

from app.dashboard.routes import SESSION_COOKIE
from tests.dashboard_fixtures import ORIGIN, dashboard_client, sign_in
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.verification_fixtures import VerificationHarness

KINDS = ("remediations", "remediation-executions", "remediation-verifications")


def test_disabled_dashboard_installs_no_history_routes(monkeypatch):
    from app import main
    from app.config import Settings
    from tests.unit.services.test_scan_service import RecordingExecutor

    settings = Settings(
        _env_file=None,
        app_env="test",
        auth_mode="development",
        database_url="sqlite://",
        dashboard_enabled=False,
    )
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    application = main.create_app(executor_factory=RecordingExecutor)
    assert application.dependency_overrides == {}
    assert not any(
        getattr(route, "path", "").startswith("/dashboard") for route in application.routes
    )


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
def test_signed_history_matches_api_and_never_writes(migrated_engine, monkeypatch, tmp_path, role):
    harness = VerificationHarness(migrated_engine)
    verification = harness.request().value
    harness.run(verification.content.scan_id)
    proposal_id = harness.proposal.content.proposal_id
    execution_id = harness.execution_id
    verification_id = verification.content.verification_id
    paths = (
        f"remediations?finding_id={harness.proposal.content.finding_id}&limit=25&offset=0",
        f"remediations/{proposal_id}",
        f"remediation-executions?proposal_id={proposal_id}&limit=25&offset=0",
        f"remediation-executions/{execution_id}",
        f"remediation-verifications?execution_id={execution_id}&limit=25&offset=0",
        f"remediation-verifications/{verification_id}",
    )
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = role
        sign_in(client, issuer)
        token = boundary.store.get(client.cookies.get(SESSION_COOKIE), touch=False).access_token
        with migrated_engine.connect() as db:
            before = "\n".join(db.connection.driver_connection.iterdump())
        for path in paths:
            response = client.get(f"/dashboard/api/{path}")
            direct = client.get(f"/api/v1/{path}", headers={"Authorization": f"Bearer {token}"})
            assert response.status_code == direct.status_code == 200
            # Validity is checked independently at each read, not an atomic mixed report.
            actual, expected = response.json(), direct.json()
            if "items" in actual:
                for a, b in zip(actual["items"], expected["items"], strict=True):
                    if "validity_checked_at" in a:
                        assert a.pop("validity_checked_at")
                        assert b.pop("validity_checked_at")
            elif "validity_checked_at" in actual:
                assert actual.pop("validity_checked_at")
                assert expected.pop("validity_checked_at")
            assert actual == expected
            assert response.headers["cache-control"] == "no-store"
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
            assert "x-dashboard-read-at" not in response.headers
        for kind in KINDS:
            page = client.get(f"/dashboard/api/{kind}").json()
            assert page["limit"] == 25 and page["offset"] == 0 and page["total"] == 1
            for method in (client.post, client.put, client.patch, client.delete):
                assert method(f"/dashboard/api/{kind}").status_code == 405
        assert (
            client.post(
                f"/dashboard/api/remediations/{proposal_id}/executions", json={}
            ).status_code
            == 404
        )
        assert (
            client.post(
                f"/dashboard/api/remediation-executions/{execution_id}/verifications", json={}
            ).status_code
            == 404
        )
        assert executor.submissions == []
        with migrated_engine.connect() as db:
            after = "\n".join(db.connection.driver_connection.iterdump())
            assert db.scalar(text("PRAGMA foreign_keys")) == 1
        assert after == before
        client.cookies.clear()
        for path in paths:
            assert client.get(f"/dashboard/api/{path}").status_code == 401
            assert client.get(f"/api/v1/{path}").status_code == 401


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "offset=-1",
        "limit=1&limit=2",
        "url=https://attacker.test",
        "account_id=bad",
        "finding_id=bad",
        "proposal_id=bad",
        "execution_id=bad",
    ],
)
def test_typed_bounded_list_rejects_injection(migrated_engine, monkeypatch, tmp_path, kind, query):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, executor):
        sign_in(client, issuer)
        response = client.get(f"/dashboard/api/{kind}?{query}")
        assert response.status_code == 422
        assert response.headers["cache-control"] == "no-store"
        assert executor.submissions == []


@pytest.mark.parametrize("kind", KINDS)
def test_history_detail_missing_unknown_queries_methods_and_sessions(
    migrated_engine, monkeypatch, tmp_path, kind
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, boundary, _):
        sign_in(client, issuer)
        path = f"/dashboard/api/{kind}/{uuid4()}"
        assert client.get(path).status_code == 404
        assert client.get(path + "?limit=1").status_code == 422
        assert client.get(f"/dashboard/api/{kind}/not-a-uuid").status_code == 422
        for method in (client.post, client.put, client.patch, client.delete):
            assert method(path).status_code == 405
        assert client.get(path, headers={"Origin": "https://attacker.test"}).status_code == 403
        assert client.get(path, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert client.get(path, headers={"X-Dashboard-Context": "Z" * 43}).status_code == 401
        cookie = client.cookies.get(SESSION_COOKIE)
        boundary.store.revoke(cookie)
        assert client.get(path).status_code == 401


@pytest.mark.parametrize("kind", KINDS)
def test_inflight_logout_never_returns_old_history(migrated_engine, monkeypatch, tmp_path, kind):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, boundary, _):
        status = sign_in(client, issuer)
        cookie = client.cookies.get(SESSION_COOKIE)
        original = httpx.AsyncClient.get

        async def revoked_read(self, *args, **kwargs):
            result = await original(self, *args, **kwargs)
            boundary.store.revoke(cookie)
            return result

        monkeypatch.setattr(httpx.AsyncClient, "get", revoked_read)
        response = client.get(f"/dashboard/api/{kind}")
        assert response.status_code == 401 and "items" not in response.json()
        assert response.headers["cache-control"] == "no-store"
        assert (
            client.post(
                "/dashboard/auth/logout",
                headers={"Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]},
            ).status_code
            == 401
        )


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("detail", [False, True])
@pytest.mark.parametrize("attack", ["expired", "forged-token", "missing-context"])
def test_six_reads_never_trust_an_old_session_identity(
    migrated_engine, monkeypatch, tmp_path, kind, detail, attack
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        sign_in(client, issuer)
        cookie = client.cookies.get(SESSION_COOKIE)
        session = boundary.store.get(cookie, touch=False)
        if attack == "expired":
            boundary.store.clock = lambda: session.expires + 1
        elif attack == "forged-token":
            session.access_token = "not-a-signed-bearer"
        else:
            client.headers.pop("X-Dashboard-Context")
        path = f"/dashboard/api/{kind}" + (f"/{uuid4()}" if detail else "")
        response = client.get(path)
        assert response.status_code == 401
        assert "items" not in response.json()
        assert response.headers["cache-control"] == "no-store"
        assert executor.submissions == []
