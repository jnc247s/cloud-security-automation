"""Real route/database/production JWT verification; only AWS and JWKS I/O are offline."""

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import boto3
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.database import session as database_session
from app.database.catalogs import ensure_assessment_profile, ensure_control_catalog
from app.database.persistence import fail_pending_scan
from app.main import create_app
from app.models.enums import ScanStatus
from app.models.scan import Scan
from app.schemas.inventory import CollectionStatus
from app.schemas.scan import ScanCreateRequest
from app.security.authentication import _oidc_backend
from app.services.scan_service import ScanService
from tests.unit.database.factories import scan_bundle
from tests.unit.services.test_scan_service import RecordingExecutor
from tests.unit.services.test_scan_service import migrated_engine as migrated_engine
from tests.unit.services.test_technical_posture_service import persist

ISSUER = "https://identity.example.test"
AUDIENCE = "cloud-security-control-plane"


@contextmanager
def production_client(engine, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="posture-test", use="sig", alg="RS256")
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda _self: {"keys": [jwk]})
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database_session, "SessionLocal", factory)
    for setting, value in {
        "APP_ENV": "production",
        "AUTH_MODE": "oidc",
        "OIDC_ISSUER": ISSUER,
        "OIDC_AUDIENCE": AUDIENCE,
        "OIDC_JWKS_URL": f"{ISSUER}/jwks",
        "OIDC_ALGORITHMS": "RS256",
        "OIDC_ROLES_CLAIM": "roles",
        "OIDC_ALLOW_INSECURE_HTTP": "false",
        "DATABASE_URL": "sqlite://",
        "ASSESSMENT_PROFILE_VERSION": "1.0.0",
    }.items():
        monkeypatch.setenv(setting, value)
    # Empty is a supplied (invalid) policy path; absence selects the accepted default.
    monkeypatch.delenv("ASSESSMENT_PROFILE_FILE", raising=False)
    get_settings.cache_clear()
    _oidc_backend.cache_clear()
    executor = RecordingExecutor()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("reporting HTTP requests must not call AWS")

    monkeypatch.setattr(boto3, "client", forbidden)
    monkeypatch.setattr(boto3.session.Session, "client", forbidden)
    try:
        application = create_app(executor_factory=lambda: executor)
        assert application.dependency_overrides == {}
        with TestClient(application) as client:
            yield client, key, executor
    finally:
        get_settings.cache_clear()
        _oidc_backend.cache_clear()


def token(key, role="VIEWER", **overrides):
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "report-test-reader",
        "roles": [role],
        "exp": datetime.now(UTC) + timedelta(minutes=5),
        **overrides,
    }
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "posture-test"})


def headers(key, role="VIEWER", **overrides):
    return {"Authorization": f"Bearer {token(key, role, **overrides)}"}


def exercise_read_role(engine, monkeypatch, role):
    with Session(engine) as session:
        scan_id = persist(session, scan_bundle())
    with production_client(engine, monkeypatch) as (client, key, executor):
        authorization = headers(key, role)
        route = f"/api/v1/scans/{scan_id}/technical-posture"
        response = client.get(route, headers=authorization)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        body = response.json()
        assert body["scan"] == client.get(f"/api/v1/scans/{scan_id}", headers=authorization).json()
        assert body["availability"] == "AVAILABLE"
        assert body["assessment_counts"]["fail_count"] == 1
        assert body["control_coverage"]["enabled_count"] == 1
        assert body["control_coverage"]["disabled_count"] == 4
        assert "payload" not in response.text and "normalized_configuration" not in response.text
        assert (
            client.get(
                f"/api/v1/scans/{uuid4()}/technical-posture", headers=authorization
            ).status_code
            == 404
        )
        assert (
            client.get(
                "/api/v1/scans/not-a-uuid/technical-posture", headers=authorization
            ).status_code
            == 422
        )
        if role != "ADMIN":
            denied = client.post("/api/v1/scans", headers=authorization, json={})
            assert denied.status_code == 403
            assert denied.json()["detail"]["code"] == "insufficient_capability"
        assert executor.submissions == []
        schema = client.get("/openapi.json").json()
        operation = schema["paths"]["/api/v1/scans/{scan_id}/technical-posture"]["get"]
        assert operation["security"] == [{"HTTPBearer": []}]
        assert set(operation["responses"]) >= {"200", "409", "422"}


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST", "APPROVER", "ADMIN"])
def test_every_read_role_uses_real_production_jwt_and_keeps_execute_separate(
    migrated_engine, monkeypatch, role
):
    exercise_read_role(migrated_engine, monkeypatch, role)


def exercise_lifecycle_http(engine, monkeypatch, state):
    with Session(engine) as session:
        if state in {"RUNNING", "FAILED_NO_BUNDLE"}:
            pending = ScanService(
                session, Settings(_env_file=None, app_env="test", auth_mode="development")
            ).start_scan(ScanCreateRequest(), RecordingExecutor(), actor_id="test-only-setup")
            scan_id = pending.scan_id
            if state == "FAILED_NO_BUNDLE":
                fail_pending_scan(
                    session,
                    scan_id=scan_id,
                    completed_at=datetime.now(UTC) + timedelta(seconds=1),
                    failure_code="TEST_HTTP_COLLECTION_FAILURE",
                    failure_message="The test collection could not finish.",
                )
                session.commit()
        else:
            status = CollectionStatus.PARTIAL if state == "PARTIAL" else CollectionStatus.FAILED
            scan_id = persist(session, scan_bundle(collection_status=status))
    with production_client(engine, monkeypatch) as (client, key, executor):
        response = client.get(f"/api/v1/scans/{scan_id}/technical-posture", headers=headers(key))
        assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
        body = response.json()
        if state in {"RUNNING", "FAILED_NO_BUNDLE"}:
            assert body["availability"] == ("IN_PROGRESS" if state == "RUNNING" else "UNAVAILABLE")
            assert body["assessment_counts"] is None and body["targets"] is None
            assert body["control_coverage"]["assessed_count"] is None
        else:
            assert body["availability"] == "AVAILABLE"
            assert body["scan"]["status"] == status.value
            assert body["scan"]["scope"]["collector_outcomes"]["security_groups"] == status.value
            assert body["assessment_counts"]["insufficient_evidence_count"] == 1
            assert body["assessment_counts"]["pass_count"] == 0
        assert executor.submissions == []


@pytest.mark.parametrize("state", ["RUNNING", "FAILED_NO_BUNDLE", "PARTIAL", "FAILED_RETAINED"])
def test_http_collection_lifecycle_keeps_unavailable_distinct(migrated_engine, monkeypatch, state):
    exercise_lifecycle_http(migrated_engine, monkeypatch, state)


@pytest.mark.parametrize(
    "variant",
    [
        "missing",
        "malformed",
        "expired",
        "wrong-issuer",
        "wrong-audience",
        "wrong-signature",
        "unknown-role",
    ],
)
def test_missing_invalid_or_untrusted_tokens_fail_closed(migrated_engine, monkeypatch, variant):
    with Session(migrated_engine) as session:
        scan_id = persist(session, scan_bundle())
    with production_client(migrated_engine, monkeypatch) as (client, key, executor):
        overrides = {
            "expired": {"exp": datetime.now(UTC) - timedelta(minutes=1)},
            "wrong-issuer": {"iss": "https://untrusted.example.test"},
            "wrong-audience": {"aud": "different-api"},
            "unknown-role": {"roles": ["UNRECOGNIZED"]},
        }.get(variant, {})
        if variant == "wrong-signature":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        authorization = headers(key, **overrides)
        if variant == "missing":
            authorization = {}
        elif variant == "malformed":
            authorization = {"Authorization": "Bearer malformed-test-token"}
        response = client.get(f"/api/v1/scans/{scan_id}/technical-posture", headers=authorization)
        assert response.status_code == 401
        assert response.json() == {
            "detail": {
                "code": "authentication_required",
                "message": "A valid bearer token is required.",
            }
        }
        assert response.headers["WWW-Authenticate"] == "Bearer"
        assert executor.submissions == []


def exercise_provenance_error(engine, monkeypatch):
    # A privileged inconsistent insert is a negative fixture, not a mutation of protected history.
    bundle = scan_bundle()
    with Session(engine) as session:
        ensure_assessment_profile(session, bundle["profile"])
        ensure_control_catalog(session, bundle["catalog"])
        scan = Scan(
            scan_id=uuid4(),
            aws_account_id=None,
            requested_regions=["us-east-1"],
            successful_regions=[],
            requested_services=["ec2"],
            successful_collectors=[],
            started_at=datetime.now(UTC),
            completed_at=None,
            status=ScanStatus.RUNNING,
            scanner_version="report-negative-fixture",
            control_catalog_id=bundle["catalog"].catalog_id,
            control_catalog_version=bundle["catalog"].version,
            assessment_profile_id=bundle["profile"].profile_id,
            assessment_profile_version=bundle["profile"].version,
            assessment_profile_checksum="f" * 64,
            inventory_sha256=None,
            result_checksum=None,
        )
        scan_id = scan.scan_id
        session.add(scan)
        session.commit()
    with production_client(engine, monkeypatch) as (client, key, executor):
        response = client.get(f"/api/v1/scans/{scan_id}/technical-posture", headers=headers(key))
        assert response.status_code == 409
        assert response.headers["Cache-Control"] == "no-store"
        assert response.json() == {
            "detail": {
                "code": "technical_posture_provenance_conflict",
                "message": "The retained scan reporting provenance is inconsistent.",
            }
        }
        assert "f" * 64 not in response.text
        assert executor.submissions == []


def test_provenance_conflict_is_sanitized_and_not_a_safe_summary(migrated_engine, monkeypatch):
    exercise_provenance_error(migrated_engine, monkeypatch)
