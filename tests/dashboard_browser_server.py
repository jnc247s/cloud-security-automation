"""Loopback-only disposable browser acceptance fixture, never included in the runtime image.

The validation harness owns TEST_DATABASE_URL. Keys and client credentials exist only in memory.
No authentication dependency override, live AWS call, password system or production IdP.
"""

# Environment must be pinned before importing the application's startup/configuration modules.
# ruff: noqa: E402

import base64
import os
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs
from uuid import UUID

if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
    raise RuntimeError("Start this fixture only through disposable dashboard validation")

from sqlalchemy.engine import make_url

test_database = os.environ["TEST_DATABASE_URL"]
test_url = make_url(test_database)
if (
    test_url.get_backend_name() != "postgresql"
    or test_url.host != "127.0.0.1"
    or test_url.database != "cloudsec_test"
):
    raise RuntimeError("Browser acceptance requires the harness's disposable PostgreSQL URL")

ORIGIN = "http://127.0.0.1:9011"
ISSUER = "http://127.0.0.1:9012"
secret = secrets.token_urlsafe(32)
os.environ.update(
    {
        "APP_ENV": "test",
        "AUTH_MODE": "oidc",
        "DATABASE_URL": test_database,
        "OIDC_ISSUER": ISSUER,
        "OIDC_AUDIENCE": "http://localhost/cloudsec-api",
        "OIDC_JWKS_URL": f"{ISSUER}/jwks",
        "OIDC_ROLES_CLAIM": "cognito:groups",
        "OIDC_ALGORITHMS": "RS256",
        "OIDC_ALLOW_INSECURE_HTTP": "true",
        "DASHBOARD_ENABLED": "true",
        "DASHBOARD_ORIGIN": ORIGIN,
        "DASHBOARD_CLIENT_ID": "dashboard-test-client",
        "DASHBOARD_CLIENT_SECRET": secret,
        "DASHBOARD_SCOPES": "openid",
        "DASHBOARD_STATIC_DIR": str(Path(__file__).resolve().parents[1] / "frontend/dist"),
    }
)
os.environ.pop("ASSESSMENT_PROFILE_FILE", None)

import boto3
import uvicorn
from alembic import command
from alembic.config import Config
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.persistence import fail_pending_scan
from app.database.session import engine
from app.main import create_app
from app.models.enums import ExceptionStatus, FindingStatus
from app.models.exception import FindingException
from app.models.finding import Finding
from app.schemas.inventory import CollectionStatus
from app.schemas.scan import ScanCreateRequest
from app.services.scan_service import ScanService
from tests.dashboard_fixtures import ControlledIssuer
from tests.sprint6_fixtures import sprint6_bundle
from tests.unit.database.factories import scan_bundle
from tests.unit.services.test_scan_service import RecordingExecutor
from tests.unit.services.test_technical_posture_service import persist


def forbidden(*_args, **_kwargs):
    raise AssertionError("Browser acceptance must never call AWS")


boto3.client = forbidden
boto3.session.Session.client = forbidden
config = Config("alembic.ini")
config.attributes["database_url"] = test_database
command.upgrade(config, "head")
with Session(engine) as db:
    for identifier, status in (
        ("11111111-1111-1111-1111-111111111111", CollectionStatus.SUCCEEDED),
        ("22222222-2222-2222-2222-222222222222", CollectionStatus.PARTIAL),
    ):
        persist(
            db,
            scan_bundle(
                scan_id=UUID(identifier),
                collection_status=status,
                tags={
                    "observed": "historical-old",
                    "hostile": "<img src=x onerror=alert(1)>",
                    "large": "x" * 16000,
                },
            ),
        )
    persist(
        db,
        scan_bundle(
            scan_id=UUID("33333333-3333-3333-3333-333333333333"),
            observed_at=datetime(2026, 10, 4, 12, tzinfo=UTC),
            public_ssh=False,
            tags={"observed": "newer-pass"},
        ),
    )
    # Real unchanged collectors/rules with offline responses; deterministic test scan IDs only.
    for identifier, options in (
        ("44444444-4444-4444-4444-444444444444", {}),
        ("55555555-5555-5555-5555-555555555555", {"empty_family": "s3_bucket"}),
        ("88888888-8888-8888-8888-888888888888", {"catalog_version": "0.3.0"}),
    ):
        with patch("tests.governance_fixtures.uuid4", return_value=UUID(identifier)):
            persist(db, sprint6_bundle(**options))
    for identifier, options in (
        ("66666666-6666-6666-6666-666666666666", {"malformed": True}),
        ("77777777-7777-7777-7777-777777777777", {"public_ssh": None}),
    ):
        persist(db, scan_bundle(scan_id=UUID(identifier), **options))
    finding = db.scalars(select(Finding).where(Finding.status == FindingStatus.RESOLVED)).one()
    finding.status = FindingStatus.ACCEPTED_RISK
    finding.resolved_at = None
    now = datetime.now(UTC)
    db.add(
        FindingException(
            finding_id=finding.finding_id,
            resource_id=finding.resource_id,
            control_id=finding.control_id,
            reason="Controlled expired exception; historical FAIL remains FAIL",
            approved_by="test-approver",
            status=ExceptionStatus.ACTIVE,
            created_at=now - timedelta(days=3),
            expires_at=now - timedelta(days=1),
        )
    )
    executor = RecordingExecutor()
    for _ in range(27):
        ScanService(db).start_scan(ScanCreateRequest(), executor, actor_id="test-reader")
    failed = ScanService(db).start_scan(ScanCreateRequest(), executor, actor_id="test-reader")
    fail_pending_scan(
        db,
        scan_id=failed.scan_id,
        completed_at=datetime.now(UTC),
        failure_code="scan_execution_failed",
        failure_message="Controlled acceptance failure; no live AWS call.",
    )
    db.commit()

issuer = ControlledIssuer(issuer=ISSUER, audience="http://localhost/cloudsec-api")
provider = FastAPI()
application = create_app(executor_factory=RecordingExecutor)
assert application.dependency_overrides == {}


@provider.get("/.well-known/openid-configuration")
def discovery():
    return issuer.metadata()


@provider.get("/jwks")
def jwks():
    return {"keys": [issuer.jwk]}


@provider.get("/authorize")
def authorize(request: Request):
    # Fixed local test page. No untrusted query value is reflected into HTML.
    issuer.authorize(str(request.url))
    response = HTMLResponse("""<!doctype html><html lang="en"><title>Controlled test issuer</title>
      <h1>Controlled local issuer — test only</h1><form method="get" action="/approve">
      <label for="role">Test role</label><select id="role" name="role">
      <option>VIEWER</option><option>ANALYST</option><option>APPROVER</option><option>ADMIN</option>
      </select><label for="subject">Test subject</label><select id="subject" name="subject">
      <option>test-reader</option><option>test-reader-A</option><option>test-reader-B</option>
      </select><button>Approve test login</button></form></html>""")
    # Keep test authorization state out of URLs/forms too; opaque test correlation only.
    transaction = secrets.token_urlsafe(32)
    pending_queries[transaction] = dict(request.query_params)
    response.set_cookie("test_transaction", transaction, httponly=True, samesite="lax")
    return response


pending_queries = {}


@provider.get("/approve")
def approve(request: Request, role: str = "VIEWER", subject: str = "test-reader"):
    query = pending_queries.pop(request.cookies.get("test_transaction", ""), None)
    if (
        not query
        or role not in {"VIEWER", "ANALYST", "APPROVER", "ADMIN"}
        or subject not in {"test-reader", "test-reader-A", "test-reader-B"}
    ):
        return JSONResponse({"error": "test authorization rejected"}, status_code=400)
    code = secrets.token_urlsafe(32)
    issuer.codes[code] = {key: [value] for key, value in query.items()}
    issuer.grants[code] = (role, subject)
    return RedirectResponse(
        f"{ORIGIN}/dashboard/auth/callback?code={code}&state={query['state']}", status_code=303
    )


@provider.post("/token")
async def token(request: Request):
    expected = "Basic " + base64.b64encode(f"dashboard-test-client:{secret}".encode()).decode()
    if request.headers.get("authorization") != expected:
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    status, body = issuer.token_response(parse_qs((await request.body()).decode()))
    return JSONResponse(body, status_code=status)


@provider.post("/expire-dashboard-sessions")
def expire():
    # Test-only control, isolated to this fixture's loopback server, absent from the application.
    application.state.dashboard.store.clear()
    return {"expired": True}


def main():
    identity_server = uvicorn.Server(
        uvicorn.Config(provider, host="127.0.0.1", port=9012, access_log=False, log_level="warning")
    )
    thread = threading.Thread(target=identity_server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not identity_server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("Controlled issuer did not start")
        time.sleep(0.05)
    try:
        uvicorn.run(application, host="127.0.0.1", port=9011, log_level="warning", access_log=False)
    finally:
        identity_server.should_exit = True
        thread.join(timeout=10)
        application.state.dashboard.store.clear()
        engine.dispose()


if __name__ == "__main__":
    main()
