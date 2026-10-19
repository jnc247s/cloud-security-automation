"""Test-only pre-import configuration. No application imports or operator target fallback."""

import os
import re
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://127.0.0.1:9031"
ISSUER = "http://127.0.0.1:9032"
SECOND_ISSUER = ISSUER + "/issuer-b"
AUDIENCE = "http://localhost/cloudsec-api"
CLIENT = "dashboard-test-client"
MARKER = "cloudsec.dashboard.integrated:"


def require_instance(value):
    try:
        if type(value) is not str or str(UUID(value)) != value or UUID(value).version != 4:
            raise ValueError
        return value
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Invalid integrated fixture owner") from None


def require_test_environment(instance):
    require_instance(instance)
    if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
        raise ValueError("Integrated fixture requires explicit browser-test mode")
    for directory in (ROOT, ROOT / "frontend"):
        if any(
            (directory / name).exists()
            for name in (
                ".env",
                ".env.local",
                ".env.test",
                ".env.test.local",
                ".env.production",
                ".env.production.local",
            )
        ):
            raise ValueError("Integrated fixture refuses operator env-files")


def identity_issuer(phase, scenario):
    if type(phase) is str and phase == "initial":
        return ISSUER
    if type(phase) is str and phase == "secondary" and scenario == "cross-issuer":
        return SECOND_ISSUER
    raise ValueError("Invalid integrated authority generation")


def configure(database="sqlite://", *, secret=None, identity_phase="initial", scenario="verified"):
    """Called before any app/config import, in both owning parent and server-only child."""
    selected_issuer = identity_issuer(identity_phase, scenario)
    if secret is None and identity_phase != "initial":
        raise ValueError("Invalid integrated authority generation")
    for name in tuple(os.environ):
        if name.upper().startswith(
            (
                "APP_",
                "AUTH_",
                "AWS_",
                "BOTO",
                "DATABASE_",
                "TEST_DATABASE_",
                "OIDC_",
                "DASHBOARD_",
                "REMEDIATION_",
                "ASSESSMENT_",
                "DEV_IDENTITY_",
            )
        ):
            os.environ.pop(name)
    os.environ.update(
        APP_ENV="test",
        AUTH_MODE="development",
        DATABASE_URL=database,
        DASHBOARD_BROWSER_TEST="1",
        DASHBOARD_ENABLED="false",
        DASHBOARD_REMEDIATION_ENABLED="false",
        REMEDIATION_ADMISSION_ENABLED="false",
        REMEDIATION_VERIFICATION_ENABLED="false",
        AWS_EC2_METADATA_DISABLED="true",
        AWS_SHARED_CREDENTIALS_FILE="/nonexistent/cloudsec-integrated-credentials",
        AWS_CONFIG_FILE="/nonexistent/cloudsec-integrated-config",
        LOG_LEVEL="WARNING",
    )
    if secret is not None:
        os.environ.update(
            AUTH_MODE="oidc",
            OIDC_ISSUER=selected_issuer,
            OIDC_AUDIENCE=AUDIENCE,
            OIDC_JWKS_URL=selected_issuer + "/jwks",
            OIDC_ROLES_CLAIM="cognito:groups",
            OIDC_ALGORITHMS="RS256",
            OIDC_ALLOW_INSECURE_HTTP="true",
            DASHBOARD_ENABLED="true",
            DASHBOARD_REMEDIATION_ENABLED="true",
            DASHBOARD_ORIGIN=ORIGIN,
            DASHBOARD_CLIENT_ID=CLIENT,
            DASHBOARD_CLIENT_SECRET=secret,
            DASHBOARD_SCOPES="openid",
            DASHBOARD_STATIC_DIR=str(ROOT / "frontend/dist"),
            REMEDIATION_ADMISSION_ENABLED="true",
            REMEDIATION_ACCOUNT_ID="123456789012",
            REMEDIATION_REGION="us-east-1",
            REMEDIATION_VERIFICATION_ENABLED="true",
            REMEDIATION_VERIFICATION_ACCOUNT_ID="123456789012",
            REMEDIATION_VERIFICATION_REGION="us-east-1",
        )


def server_database(raw, instance, *, container=False):
    """Only read a guardian-created marked schema; never create/adopt a supplied namespace."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    require_test_environment(instance)
    engine = None
    try:
        url = make_url(raw)
        schema = url.query.get("options", "").removeprefix("-csearch_path=")
        if (
            url.drivername != "postgresql+psycopg"
            or url.host != ("pg" if container else "127.0.0.1")
            or type(container) is not bool
            or url.username != "cloudsec_test"
            or not url.password
            or url.database != "cloudsec_test"
            or url.port is None
            or not 1 <= url.port <= 65535
            or (container and url.port != 5432)
            or re.fullmatch(r"sprint8_worker_[0-9a-f]{32}", schema, re.ASCII) is None
            or dict(url.query) != {"options": "-csearch_path=" + schema}
        ):
            raise ValueError
        engine = create_engine(url, connect_args={"connect_timeout": 5})
        with engine.connect() as connection:
            if (
                connection.execute(text("SELECT current_database()")).scalar_one()
                != "cloudsec_test"
            ):
                raise ValueError
            actual = connection.execute(
                text(
                    "SELECT pg_catalog.obj_description(oid, 'pg_namespace') "
                    "FROM pg_catalog.pg_namespace WHERE nspname=:schema"
                ),
                {"schema": schema},
            ).scalar_one_or_none()
            if actual != MARKER + instance:
                raise ValueError
        return url
    except Exception:
        raise ValueError("Integrated server database ownership rejected") from None
    finally:
        if engine is not None:
            engine.dispose()
