"""Controlled issuer I/O with real signed tokens, real API authorization and real database reads."""

import base64
import hashlib
import json
import secrets
import time
from contextlib import contextmanager
from urllib.parse import parse_qs, urlparse

import boto3
import httpx2 as httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.database import session as database_session
from app.main import create_app
from app.security.authentication import _oidc_backend
from tests.unit.services.test_scan_service import RecordingExecutor

ISSUER = "https://identity.example.test"
ORIGIN = "https://dashboard.example.test"
AUDIENCE = "https://api.example.test"
CLIENT_ID = "dashboard-test-client"


class ControlledIssuer:
    def __init__(self, *, issuer=ISSUER, client_id=CLIENT_ID, audience=AUDIENCE):
        self.issuer, self.client_id, self.audience = issuer, client_id, audience
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwk.update(kid="dashboard-test", use="sig", alg="RS256")
        self.codes = {}
        self.grants = {}
        self.role = "VIEWER"
        self.subject = "test-reader"
        self.access_overrides = {}
        self.id_overrides = {}
        self.exchanges = 0

    def authorize(self, authorization_url):
        query = parse_qs(urlparse(authorization_url).query)
        assert query["response_type"] == ["code"]
        assert query["code_challenge_method"] == ["S256"]
        assert query["resource"] == [self.audience]
        code = secrets.token_urlsafe(32)
        self.codes[code] = query
        return query, code

    def token_response(self, form):
        query = self.codes.pop(form.get("code", [""])[0], None)
        self.exchanges += 1
        verifier = form.get("code_verifier", [""])[0]
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        if not query or query["code_challenge"] != [challenge]:
            return 400, {"error": "invalid_grant"}
        now = time.time()
        role, subject = self.grants.pop(form.get("code", [""])[0], (self.role, self.subject))
        common = {"iss": self.issuer, "sub": subject, "iat": int(now), "exp": int(now + 300)}
        access = jwt.encode(
            {
                **common,
                "aud": self.audience,
                "cognito:groups": [role],
                "token_use": "access",
                **self.access_overrides,
            },
            self.key,
            algorithm="RS256",
            headers={"kid": "dashboard-test"},
        )
        identity = jwt.encode(
            {**common, "aud": self.client_id, "nonce": query["nonce"][0], **self.id_overrides},
            self.key,
            algorithm="RS256",
            headers={"kid": "dashboard-test"},
        )
        return 200, {
            "access_token": access,
            "id_token": identity,
            "token_type": "Bearer",
            "expires_in": 300,
        }

    def metadata(self):
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def handle(self, request):
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=self.metadata())
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [self.jwk]})
        if request.url.path == "/token":
            form = parse_qs(request.content.decode())
            assert form["grant_type"] == ["authorization_code"]
            assert form["redirect_uri"] == [f"{ORIGIN}/dashboard/auth/callback"]
            status, body = self.token_response(form)
            return httpx.Response(status, json=body)
        raise AssertionError("Unexpected issuer URL")


@contextmanager
def dashboard_client(engine, monkeypatch, tmp_path, *, raise_server_exceptions=True):
    static = tmp_path / "static"
    static.mkdir()
    (static / "assets").mkdir()
    (static / "index.html").write_text(
        "<!doctype html><title>Dashboard test assets</title>", encoding="utf-8"
    )
    issuer = ControlledIssuer()
    for name, value in {
        "APP_ENV": "production",
        "AUTH_MODE": "oidc",
        "OIDC_ISSUER": ISSUER,
        "OIDC_AUDIENCE": AUDIENCE,
        "OIDC_JWKS_URL": f"{ISSUER}/jwks",
        "OIDC_ROLES_CLAIM": "cognito:groups",
        "OIDC_ALGORITHMS": "RS256",
        "OIDC_ALLOW_INSECURE_HTTP": "false",
        "DATABASE_URL": "sqlite://",
        "DASHBOARD_ENABLED": "true",
        "DASHBOARD_ORIGIN": ORIGIN,
        "DASHBOARD_CLIENT_ID": CLIENT_ID,
        "DASHBOARD_CLIENT_SECRET": secrets.token_urlsafe(32),
        "DASHBOARD_STATIC_DIR": str(static),
        "DASHBOARD_SCOPES": "openid",
        "ASSESSMENT_PROFILE_VERSION": "1.0.0",
        "REMEDIATION_ADMISSION_ENABLED": "false",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ASSESSMENT_PROFILE_FILE", raising=False)
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda _self: {"keys": [issuer.jwk]})
    monkeypatch.setattr(
        database_session,
        "SessionLocal",
        sessionmaker(bind=engine, autoflush=False, expire_on_commit=False),
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Dashboard must not call AWS")

    monkeypatch.setattr(boto3, "client", forbidden)
    monkeypatch.setattr(boto3.session.Session, "client", forbidden)
    get_settings.cache_clear()
    _oidc_backend.cache_clear()
    executor = RecordingExecutor()
    try:
        application = create_app(executor_factory=lambda: executor)
        assert application.dependency_overrides == {}
        application.state.dashboard.oidc.transport = httpx.MockTransport(issuer.handle)
        with TestClient(
            application, base_url=ORIGIN, raise_server_exceptions=raise_server_exceptions
        ) as client:
            yield client, issuer, application.state.dashboard, executor
    finally:
        get_settings.cache_clear()
        _oidc_backend.cache_clear()


def begin_login(client, issuer):
    status = client.get("/dashboard/session").json()
    response = client.post(
        "/dashboard/auth/login", headers={"Origin": ORIGIN, "X-CSRF-Token": status["csrf_token"]}
    )
    assert response.status_code == 200
    query, code = issuer.authorize(response.json()["authorization_url"])
    return {"state": query["state"][0], "code": code}


def sign_in(client, issuer):
    response = client.get(
        "/dashboard/auth/callback", params=begin_login(client, issuer), follow_redirects=False
    )
    assert response.status_code == 303 and response.headers["location"] == "/dashboard/"
    status = client.get("/dashboard/session").json()
    client.headers["X-Dashboard-Context"] = status["session_context"]
    return status
