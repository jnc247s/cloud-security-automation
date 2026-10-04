"""Real bearer/READ enforcement behind the browser session; no authentication overrides."""

import time
from dataclasses import replace
from uuid import uuid4

import httpx2 as httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.orm import Session

from app.dashboard.routes import LOGIN_COOKIE, SESSION_COOKIE
from tests.dashboard_fixtures import ORIGIN, begin_login, dashboard_client, sign_in
from tests.unit.database.factories import scan_bundle
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.unit.services.test_technical_posture_service import persist


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
def test_exact_scan_reads_cross_real_bearer_boundary(migrated_engine, monkeypatch, tmp_path, role):
    with Session(migrated_engine) as db:
        scan_id = persist(db, scan_bundle())
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (
        client,
        issuer,
        boundary,
        executor,
    ):
        issuer.role = role
        status = sign_in(client, issuer)
        assert status["roles"] == [role]
        cookie = client.cookies.get(SESSION_COOKIE)
        assert cookie and "." not in cookie
        assert "access_token" not in str(status) and "id_token" not in str(status)
        for path in (
            "/dashboard/",
            "/dashboard/session",
            "/dashboard/api/scans",
            f"/dashboard/api/scans/{scan_id}",
            f"/dashboard/api/scans/{scan_id}/technical-posture",
        ):
            response = client.get(path)
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert (
            client.get(f"/dashboard/api/scans/{scan_id}/technical-posture").json()[
                "assessment_counts"
            ]["fail_count"]
            == 1
        )
        assert client.get("/api/v1/scans").status_code == 401
        assert client.post("/dashboard/api/scans", json={}).status_code == 405
        assert client.get("/dashboard/api/resources").status_code == 404
        assert executor.submissions == []
        assert boundary.store.get(cookie) is not None


@pytest.mark.parametrize(
    "location,changes",
    [
        ("access", {"aud": "wrong"}),
        ("access", {"iss": "https://wrong.example.test"}),
        ("access", {"exp": 1}),
        ("access", {"cognito:groups": ["UNRECOGNIZED"]}),
        ("access", {"cognito:groups": []}),
        ("access", {"sub": "different"}),
        ("identity", {"nonce": "wrong"}),
        ("identity", {"aud": "wrong"}),
        ("identity", {"iss": "https://wrong.example.test"}),
        ("identity", {"exp": 1}),
        ("identity", {"sub": "different"}),
        ("identity", {"iat": time.time() + 86400}),
    ],
)
def test_rejects_untrusted_tokens(migrated_engine, monkeypatch, tmp_path, location, changes):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, _):
        getattr(issuer, f"{'id' if location == 'identity' else 'access'}_overrides").update(changes)
        response = client.get(
            "/dashboard/auth/callback", params=begin_login(client, issuer), follow_redirects=False
        )
        assert response.headers["location"] == "/dashboard/?login=failed"
        assert client.get("/dashboard/session").json()["authenticated"] is False
        assert client.get("/dashboard/api/scans").status_code == 401


@pytest.mark.parametrize(
    "changes",
    [
        {"state": "wrong"},
        {"code": "wrong"},
        {"error": "access_denied"},
        {"iss": "wrong"},
        {"code": "x" * 2049},
        {"next": "https://attacker.example.test"},
    ],
)
def test_callback_one_time_bounded_and_not_an_open_redirect(
    migrated_engine, monkeypatch, tmp_path, changes
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, _):
        params = begin_login(client, issuer)
        response = client.get(
            "/dashboard/auth/callback", params={**params, **changes}, follow_redirects=False
        )
        assert response.headers["location"] == "/dashboard/?login=failed"
        replay = client.get("/dashboard/auth/callback", params=params, follow_redirects=False)
        assert replay.headers["location"] == "/dashboard/?login=failed"


def test_csrf_origin_cookies_logout_and_replay(migrated_engine, monkeypatch, tmp_path):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, boundary, _):
        response = client.get("/dashboard/session")
        csrf = response.json()["csrf_token"]
        for expected in ("HttpOnly", "Secure", "SameSite=lax", "Path=/dashboard"):
            assert expected in response.headers["set-cookie"]
        assert "Domain=" not in response.headers["set-cookie"]
        for headers in (
            {},
            {"Origin": ORIGIN},
            {"Origin": "https://attacker.example.test", "X-CSRF-Token": csrf},
        ):
            assert client.post("/dashboard/auth/login", headers=headers).status_code == 403
        params = begin_login(client, issuer)
        response = client.get("/dashboard/auth/callback", params=params, follow_redirects=False)
        assert "SameSite=strict" in response.headers["set-cookie"]
        cookie = client.cookies.get(SESSION_COOKIE)
        status = client.get("/dashboard/session").json()
        client.headers["X-Dashboard-Context"] = status["session_context"]
        assert (
            client.get(
                "/dashboard/api/scans", headers={"Origin": "https://attacker.example.test"}
            ).status_code
            == 403
        )
        assert (
            client.get("/dashboard/api/scans", headers={"Sec-Fetch-Site": "cross-site"}).status_code
            == 403
        )
        assert (
            client.post(
                "/dashboard/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": "wrong"}
            ).status_code
            == 403
        )
        response = client.post(
            "/dashboard/auth/logout",
            headers={"Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]},
        )
        assert response.status_code == 204
        assert boundary.store.get(cookie) is None
        client.cookies.set(SESSION_COOKIE, cookie)
        assert client.get("/dashboard/api/scans").status_code == 401
        client.cookies.clear()
        assert (
            client.get("/dashboard/auth/callback", params=params, follow_redirects=False)
            .headers["location"]
            .endswith("failed")
        )
        assert issuer.exchanges == 1


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "offset=-1",
        "url=https://attacker.example.test",
        "role=ADMIN",
        "limit=25&limit=100",
    ],
)
def test_read_adapter_rejects_unbounded_or_injected_queries(
    migrated_engine, monkeypatch, tmp_path, query
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, _):
        sign_in(client, issuer)
        assert client.get(f"/dashboard/api/scans?{query}").status_code == 422


def test_missing_scan_idle_absolute_and_token_expiry(migrated_engine, monkeypatch, tmp_path):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, boundary, _):
        sign_in(client, issuer)
        assert client.get(f"/dashboard/api/scans/{uuid4()}").status_code == 404
        assert client.get("/dashboard/api/scans/not-a-uuid").status_code == 422
        cookie = client.cookies.get(SESSION_COOKIE)
        session = boundary.store.get(cookie, touch=False)
        boundary.store.clock = lambda: session.expires + 1
        assert client.get("/dashboard/api/scans").status_code == 401
        assert client.get("/dashboard/session").json()["authenticated"] is False
        assert not client.cookies.get(SESSION_COOKIE)
        assert client.cookies.get(LOGIN_COOKIE)


@pytest.mark.parametrize("attack", ["signature", "pkce", "browser"])
def test_callback_rejects_forgery_and_browser_or_pkce_substitution(
    migrated_engine, monkeypatch, tmp_path, attack
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, boundary, _):
        params = begin_login(client, issuer)
        if attack == "signature":
            issuer.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif attack == "pkce":
            browser = client.cookies.get(LOGIN_COOKIE)
            boundary.store._logins[browser] = replace(
                boundary.store._logins[browser], verifier="substituted-verifier"
            )
        else:
            client.cookies.clear()
        response = client.get("/dashboard/auth/callback", params=params, follow_redirects=False)
        assert response.headers["location"] == "/dashboard/?login=failed"
        assert response.headers["cache-control"] == "no-store"
        assert client.get("/dashboard/api/scans").status_code == 401
        assert not client.cookies.get(SESSION_COOKIE)


def test_login_rotates_session_and_in_flight_read_cannot_outlive_logout(
    migrated_engine, monkeypatch, tmp_path
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, boundary, _):
        sign_in(client, issuer)
        old_cookie = client.cookies.get(SESSION_COOKIE)
        client.cookies.clear()
        params = begin_login(client, issuer)
        client.cookies.set(
            SESSION_COOKIE, old_cookie, domain="dashboard.example.test", path="/dashboard"
        )
        response = client.get("/dashboard/auth/callback", params=params, follow_redirects=False)
        assert response.headers["location"] == "/dashboard/"
        current = client.cookies.get(SESSION_COOKIE)
        assert current != old_cookie and boundary.store.get(old_cookie) is None
        client.headers["X-Dashboard-Context"] = client.get("/dashboard/session").json()[
            "session_context"
        ]

        original = httpx.AsyncClient.get

        async def revoked_read(self, *args, **kwargs):
            upstream = await original(self, *args, **kwargs)
            boundary.store.revoke(current)
            return upstream

        monkeypatch.setattr(httpx.AsyncClient, "get", revoked_read)
        response = client.get("/dashboard/api/scans")
        assert response.status_code == 401
        assert "items" not in response.json()
        assert response.headers["cache-control"] == "no-store"


def test_discovery_failure_is_sanitized_and_has_no_development_fallback(
    migrated_engine, monkeypatch, tmp_path
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, _):
        original = issuer.metadata
        monkeypatch.setattr(
            issuer, "metadata", lambda: {**original(), "issuer": "untrusted-secret"}
        )
        status = client.get("/dashboard/session").json()
        response = client.post(
            "/dashboard/auth/login",
            headers={"Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]},
        )
        assert response.status_code == 503
        assert "untrusted-secret" not in response.text
        assert response.headers["cache-control"] == "no-store"
        assert client.get("/dashboard/api/scans").status_code == 401


@pytest.mark.parametrize("route", ["login", "logout"])
def test_non_ascii_csrf_is_rejected_with_dashboard_security_headers(
    migrated_engine, monkeypatch, tmp_path, route
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, _, _):
        if route == "logout":
            sign_in(client, issuer)
        else:
            client.get("/dashboard/session")
        response = client.post(
            f"/dashboard/auth/{route}",
            headers=[(b"Origin", ORIGIN.encode()), (b"X-CSRF-Token", b"\xff" * 43)],
        )
        assert response.status_code == 403
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


@pytest.mark.parametrize("unexpected_failure", [False, True])
def test_callback_rejection_and_unexpected_failure_redact_query_and_secure_response(
    migrated_engine, monkeypatch, tmp_path, unexpected_failure
):
    with dashboard_client(
        migrated_engine, monkeypatch, tmp_path, raise_server_exceptions=False
    ) as (client, issuer, boundary, _):
        params = begin_login(client, issuer)
        observed = []
        original_app = client._transport.app

        async def observe(scope, receive, send):
            async def response_start(message):
                if message["type"] == "http.response.start":
                    observed.append(scope["query_string"])
                await send(message)

            await original_app(scope, receive, response_start)

        monkeypatch.setattr(client._transport, "app", observe)
        if unexpected_failure:

            def programming_failure(*_args):
                raise RuntimeError("Controlled programming failure")

            monkeypatch.setattr(boundary.store, "consume", programming_failure)
        else:
            params["state"] = "\u00ff" * 43
        params["code"] = "SYNTHETIC_REVIEW_CODE"
        response = client.get("/dashboard/auth/callback", params=params, follow_redirects=False)
        assert response.status_code == (500 if unexpected_failure else 303)
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert observed == [b""]
        assert "SYNTHETIC_REVIEW_CODE" not in response.text
        if unexpected_failure:
            assert response.text == "Internal Server Error"
        else:
            assert response.headers["location"] == "/dashboard/?login=failed"
            assert client.get("/dashboard/session").json()["authenticated"] is False
        assert issuer.exchanges == 0


def test_read_requires_expected_session_context_before_bearer_forwarding(
    migrated_engine, monkeypatch, tmp_path
):
    with dashboard_client(migrated_engine, monkeypatch, tmp_path) as (client, issuer, boundary, _):
        old_context = sign_in(client, issuer)["session_context"]
        client.cookies.clear()
        issuer.subject = "second-reader"
        current = sign_in(client, issuer)
        assert current["subject"] == "second-reader"
        assert current["session_context"] != old_context
        assert current["session_context"] != current["csrf_token"]
        forwarded = []
        original = httpx.AsyncClient.get

        async def record(self, *args, **kwargs):
            forwarded.append(args)
            return await original(self, *args, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "get", record)
        for supplied in ("", "wrong", old_context):
            response = client.get("/dashboard/api/scans", headers={"X-Dashboard-Context": supplied})
            assert response.status_code == 401
            assert "items" not in response.json()
            assert response.headers["cache-control"] == "no-store"
        response = client.get(
            "/dashboard/api/scans", headers=[(b"X-Dashboard-Context", b"\xff" * 43)]
        )
        assert response.status_code == 401 and forwarded == []
        assert boundary.store.get(client.cookies.get(SESSION_COOKIE), touch=False)
        assert client.get("/dashboard/api/scans").status_code == 200
        assert len(forwarded) == 1
        # A context is correlation, never a replacement for the session or bearer token.
        client.cookies.clear()
        assert client.get("/dashboard/api/scans").status_code == 401
        assert len(forwarded) == 1
