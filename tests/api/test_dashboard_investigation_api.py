"""New allowlisted reads retain the real signed bearer/READ and session boundary."""

from datetime import UTC, datetime
from uuid import uuid4

import httpx2 as httpx
import pytest
from sqlalchemy.orm import Session

from app.dashboard.routes import SESSION_COOKIE
from tests.dashboard_fixtures import ORIGIN, dashboard_client, sign_in
from tests.unit.database.factories import graph_scan_bundle, scan_bundle
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.unit.services.test_technical_posture_service import persist


def exercise_reads(engine, monkeypatch, tmp_path, role):
    with Session(engine) as db:
        old = persist(db, scan_bundle(tags={"observed": "old"}))
        persist(db, scan_bundle(public_ssh=False, tags={"observed": "new"}))
        graph = persist(db, graph_scan_bundle())
    with dashboard_client(engine, monkeypatch, tmp_path) as (client, issuer, boundary, executor):
        issuer.role = role
        sign_in(client, issuer)
        rows = client.get("/dashboard/api/assessments", params={"scan_id": old}).json()
        assessment = rows["items"][0]
        identifier = assessment["assessment_id"]
        detail = client.get(f"/dashboard/api/assessments/{identifier}").json()
        resource = detail["resource_id"]
        control = detail["control_id"]
        paths = (
            f"assessments?scan_id={old}&result=FAIL&limit=1",
            f"assessments/{identifier}",
            f"resources/{resource}",
            f"resources/{resource}/history?scan_id={old}",
            f"controls/{control}",
            f"findings?resource_id={resource}&control_id={control}",
            f"findings/{detail['finding_id']}",
            f"exceptions?finding_id={detail['finding_id']}",
            f"source-outcomes?scan_id={graph}",
            f"relationships?scan_id={graph}",
        )
        token = boundary.store.get(client.cookies.get(SESSION_COOKIE), touch=False).access_token
        for path in paths:
            response = client.get(f"/dashboard/api/{path}")
            upstream_path = path + "&limit=25" if "?" in path and "limit=" not in path else path
            direct = client.get(
                f"/api/v1/{upstream_path}", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == direct.status_code == 200
            assert response.json() == direct.json()
            assert response.headers["cache-control"] == "no-store"
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
            if path.startswith(("findings", "exceptions")):
                reference = datetime.fromisoformat(response.headers["x-dashboard-read-at"])
                assert reference.tzinfo == UTC
                assert abs((datetime.now(UTC) - reference).total_seconds()) < 30
            else:
                assert "x-dashboard-read-at" not in response.headers
        historical = client.get(f"/dashboard/api/resources/{resource}/history?scan_id={old}").json()
        assert historical["items"][0]["tags"] == {"observed": "old"}
        assert historical["items"][0]["snapshot_id"] == detail["resource_snapshot_id"]
        assert (
            client.get(f"/dashboard/api/resources/{resource}/history?scan_id={uuid4()}").json()[
                "total"
            ]
            == 0
        )
        for kind, key in (
            ("source-outcomes", "source_outcome_id"),
            ("relationships", "observation_id"),
        ):
            row = client.get(f"/dashboard/api/{kind}?scan_id={graph}").json()["items"][0]
            response = client.get(f"/dashboard/api/{kind}/{row[key]}")
            assert response.status_code == 200
            assert response.json()["scan_id"] == str(graph)
            assert (
                response.json()
                == client.get(
                    f"/api/v1/{kind}/{row[key]}", headers={"Authorization": f"Bearer {token}"}
                ).json()
            )
        assert client.get(f"/api/v1/assessments/{identifier}").status_code == 401
        assert executor.submissions == []
        client.headers.pop("X-Dashboard-Context")
        assert client.get(f"/dashboard/api/assessments/{identifier}").status_code == 401


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
def test_real_bearer_reads_and_exact_history(migrated_engine, monkeypatch, tmp_path, role):
    exercise_reads(migrated_engine, monkeypatch, tmp_path, role)


@pytest.mark.parametrize(
    "kind", ["assessments", "source-outcomes", "relationships", "findings", "exceptions"]
)
@pytest.mark.parametrize(
    "query",
    [
        "limit=101",
        "offset=-1",
        "limit=1&limit=2",
        "url=https://attacker.test",
        "status=not-a-state",
    ],
)
def test_bounded_typed_injection_rejection(migrated_engine, monkeypatch, tmp_path, kind, query):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, _):
        sign_in(client, issuer)
        response = client.get(
            f"/dashboard/api/{kind}?scan_id={uuid4()}&{query}"
            if kind in {"assessments", "source-outcomes", "relationships"}
            else f"/dashboard/api/{kind}?{query}"
        )
        assert response.status_code == 422
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "kind", ["assessments", "resources", "controls", "findings", "source-outcomes", "relationships"]
)
def test_detail_no_query_no_mutations_and_missing_not_success(
    migrated_engine, monkeypatch, tmp_path, kind
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, _):
        sign_in(client, issuer)
        path = f"/dashboard/api/{kind}/{uuid4()}"
        assert client.get(path + "?url=ignored").status_code == 422
        assert client.get(path).status_code == 404
        assert client.post(path, json={}).status_code == 405
        assert client.put(path, json={}).status_code == 405
        assert client.delete(path).status_code == 405
        assert "x-dashboard-read-at" not in client.get(path).headers
        client.cookies.clear()
        assert client.get(path).status_code == 401


@pytest.mark.parametrize("kind", ["assessments", "source-outcomes", "relationships", "history"])
def test_exact_scan_is_required_and_typed(migrated_engine, monkeypatch, tmp_path, kind):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, _):
        sign_in(client, issuer)
        path = (
            f"/dashboard/api/resources/{uuid4()}/history"
            if kind == "history"
            else f"/dashboard/api/{kind}"
        )
        for suffix in ("", "?scan_id=not-a-uuid", f"?scan_id={uuid4()}&scan_id={uuid4()}"):
            assert client.get(path + suffix).status_code == 422


@pytest.mark.parametrize(
    "kind", ["assessments", "source-outcomes", "relationships", "findings", "exceptions"]
)
def test_new_reads_reject_cross_origin_wrong_context_and_inflight_logout(
    migrated_engine, monkeypatch, tmp_path, kind
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        status = sign_in(client, issuer)
        path = f"/dashboard/api/{kind}"
        if kind in {"assessments", "source-outcomes", "relationships"}:
            path += f"?scan_id={uuid4()}"
        for headers in (
            {"Origin": "https://attacker.test"},
            {"Sec-Fetch-Site": "cross-site"},
        ):
            assert client.get(path, headers=headers).status_code == 403
        assert client.get(path, headers={"X-Dashboard-Context": "Z" * 43}).status_code == 401
        assert client.get(path).status_code == 200
        cookie = client.cookies.get(SESSION_COOKIE)
        original = httpx.AsyncClient.get

        async def revoked_read(self, *args, **kwargs):
            upstream = await original(self, *args, **kwargs)
            boundary.store.revoke(cookie)
            return upstream

        monkeypatch.setattr(httpx.AsyncClient, "get", revoked_read)
        response = client.get(path)
        assert response.status_code == 401
        assert "items" not in response.json()
        assert "x-dashboard-read-at" not in response.headers
        assert response.headers["cache-control"] == "no-store"
        assert (
            client.post(
                "/dashboard/auth/logout",
                headers={"Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]},
            ).status_code
            == 401
        )
        assert executor.submissions == []
