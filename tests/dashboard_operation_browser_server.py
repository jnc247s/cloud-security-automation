"""Separate opt-in signed browser fixture. Never packaged in the application image.

Each child owns a fresh PostgreSQL schema; legacy fixture data and default-off routes stay
unchanged. Only offline seed services and a recording scan executor are used in 8D2. This is
not installed-worker/managed-reader acceptance, which remains a separate 8D3 requirement.
"""

import base64
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs

from tests.dashboard_operation_runtime import owned_schema

ORIGIN = "http://127.0.0.1:9021"
ISSUER = "http://127.0.0.1:9022"
AUDIENCE = "http://localhost/cloudsec-api"
CLIENT = "dashboard-test-client"


def configure(database: str, secret: str) -> None:
    for name in tuple(os.environ):
        if name.startswith(
            (
                "APP_",
                "AUTH_",
                "AWS_",
                "BOTO",
                "OIDC_",
                "DASHBOARD_",
                "REMEDIATION_",
                "ASSESSMENT_",
                "DEV_IDENTITY_",
            )
        ):
            os.environ.pop(name)
    os.environ.update(
        {
            "APP_ENV": "test",
            "AUTH_MODE": "oidc",
            "DATABASE_URL": database,
            "OIDC_ISSUER": ISSUER,
            "OIDC_AUDIENCE": AUDIENCE,
            "OIDC_JWKS_URL": ISSUER + "/jwks",
            "OIDC_ROLES_CLAIM": "cognito:groups",
            "OIDC_ALGORITHMS": "RS256",
            "OIDC_ALLOW_INSECURE_HTTP": "true",
            "DASHBOARD_ENABLED": "true",
            "DASHBOARD_REMEDIATION_ENABLED": "true",
            "DASHBOARD_ORIGIN": ORIGIN,
            "DASHBOARD_CLIENT_ID": CLIENT,
            "DASHBOARD_CLIENT_SECRET": secret,
            "DASHBOARD_SCOPES": "openid",
            "DASHBOARD_STATIC_DIR": str(Path(__file__).resolve().parents[1] / "frontend/dist"),
            "REMEDIATION_ADMISSION_ENABLED": "true",
            "REMEDIATION_ACCOUNT_ID": "123456789012",
            "REMEDIATION_REGION": "us-west-2",
            "REMEDIATION_VERIFICATION_ENABLED": "true",
            "REMEDIATION_VERIFICATION_ACCOUNT_ID": "123456789012",
            "REMEDIATION_VERIFICATION_REGION": "us-west-2",
            "ASSESSMENT_PROFILE_VERSION": "1.0.0",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent/cloudsec-browser-credentials",
            "AWS_CONFIG_FILE": "/nonexistent/cloudsec-browser-config",
            "LOG_LEVEL": "WARNING",
        }
    )


def serve(instance: str) -> None:
    # All application imports follow explicit isolated environment configuration.
    import boto3
    import uvicorn
    from alembic import command
    from alembic.config import Config
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

    from app.database.session import engine
    from app.main import create_app
    from tests.dashboard_fixtures import ControlledIssuer
    from tests.unit.services.test_scan_service import RecordingExecutor
    from tests.verification_fixtures import VerificationHarness

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Operation browser fixture must never call AWS")

    boto3.client = forbidden
    boto3.session.Session.client = forbidden
    config = Config("alembic.ini")
    config.attributes["database_url"] = os.environ["DATABASE_URL"]
    command.upgrade(config, "head")
    print("OPERATION_FIXTURE_STAGE=MIGRATED", flush=True)
    harness = VerificationHarness(engine)
    print("OPERATION_FIXTURE_STAGE=SEEDED", flush=True)
    baseline = harness.proposal.content
    issuer = ControlledIssuer(issuer=ISSUER, audience=AUDIENCE)
    provider = FastAPI()
    recording_executor = RecordingExecutor()
    application = create_app(executor_factory=lambda: recording_executor)
    if application.dependency_overrides:
        raise RuntimeError("Operation browser acceptance must use genuine API authentication")
    pending = {}
    secret = os.environ["DASHBOARD_CLIENT_SECRET"]

    @application.get("/__test/fixture")
    def fixture():
        return {
            "instance_id": instance,
            "scan_id": str(baseline.baseline.scan_id),
            "assessment_id": str(baseline.baseline.assessment_id),
            "seed_proposal_id": str(baseline.proposal_id),
            "seed_execution_id": str(harness.execution_id),
            "scan_submissions": len(recording_executor.submissions),
        }

    @provider.get("/.well-known/openid-configuration")
    def discovery():
        return issuer.metadata()

    @provider.get("/jwks")
    def jwks():
        return {"keys": [issuer.jwk]}

    @provider.get("/authorize")
    def authorize(request: Request):
        query = dict(request.query_params)
        if (
            query.get("redirect_uri") != ORIGIN + "/dashboard/auth/callback"
            or query.get("client_id") != CLIENT
            or any(len(request.query_params.getlist(key)) != 1 for key in request.query_params)
        ):
            return JSONResponse({"error": "controlled authorization rejected"}, status_code=400)
        issuer.authorize(str(request.url))
        transaction = secrets.token_urlsafe(32)
        pending[transaction] = query
        response = HTMLResponse("""<!doctype html><html lang="en">
          <title>Controlled operation issuer</title>
          <h1>Controlled operation issuer — test only</h1><form method="get" action="/approve">
          <label for="identity">Test identity</label><select id="identity" name="identity">
          <option value="proposer">proposer</option><option value="approver">approver</option>
          <option value="requester">requester</option></select>
          <button>Approve test login</button></form></html>""")
        response.set_cookie(
            "test_operation_transaction", transaction, httponly=True, samesite="lax"
        )
        return response

    @provider.get("/approve")
    def approve(request: Request, identity: str = "proposer"):
        query = pending.pop(request.cookies.get("test_operation_transaction", ""), None)
        roles = {"proposer": "ANALYST", "approver": "APPROVER", "requester": "ADMIN"}
        if not query or identity not in roles:
            return JSONResponse({"error": "controlled authorization rejected"}, status_code=400)
        code = secrets.token_urlsafe(32)
        issuer.codes[code] = {key: [value] for key, value in query.items()}
        issuer.grants[code] = (roles[identity], identity)
        return RedirectResponse(
            f"{ORIGIN}/dashboard/auth/callback?code={code}&state={query['state']}", status_code=303
        )

    @provider.post("/token")
    async def token(request: Request):
        expected = "Basic " + base64.b64encode(f"{CLIENT}:{secret}".encode()).decode()
        form = parse_qs((await request.body()).decode())
        if request.headers.get("authorization") != expected or form.get("redirect_uri") != [
            ORIGIN + "/dashboard/auth/callback"
        ]:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        status, body = issuer.token_response(form)
        return JSONResponse(body, status_code=status)

    servers = [
        uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, access_log=False, log_level="warning")
        )
        for app, port in [(provider, 9022), (application, 9021)]
    ]
    threads = [threading.Thread(target=server.run, daemon=True) for server in servers]
    try:
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 15
        while not all(server.started for server in servers):
            if time.monotonic() > deadline or any(not thread.is_alive() for thread in threads):
                raise RuntimeError("Controlled operation fixture did not start")
            time.sleep(0.05)
        print("OPERATION_FIXTURE_READY", flush=True)
        # One bounded stop message/EOF from this owning test child, never a shell command.
        if sys.stdin.readline(16).strip() not in {"stop", ""}:
            raise RuntimeError("Invalid operation fixture control")
    finally:
        for server in servers:
            server.should_exit = True
        for thread in threads:
            thread.join(timeout=10)
        application.state.dashboard.store.clear()
        engine.dispose()
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError("Controlled operation fixture cleanup did not finish")


def main() -> int:
    if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
        print("Operation fixture requires disposable browser validation", file=sys.stderr)
        return 1
    if (Path(__file__).resolve().parents[1] / ".env").exists():
        print("Operation fixture refuses an operator env-file", file=sys.stderr)
        return 1
    try:
        instance = os.environ["DASHBOARD_OPS_FIXTURE_ID"]
        with owned_schema(os.environ["TEST_DATABASE_URL"], instance) as isolated:
            print("OPERATION_FIXTURE_STAGE=DATABASE_READY", flush=True)
            configure(isolated.render_as_string(hide_password=False), secrets.token_urlsafe(32))
            serve(instance)
        return 0
    except Exception:
        # Never print connection strings, provider errors, HTTP payloads or signing material.
        print("Controlled operation fixture failed; no success claimed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
