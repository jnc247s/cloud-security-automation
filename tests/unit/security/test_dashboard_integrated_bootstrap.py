"""Pre-import/env and ownership guard evidence; no Docker or application import required."""

from uuid import uuid4

import pytest

from tests import dashboard_integrated_bootstrap as bootstrap


@pytest.mark.parametrize(
    "phase,scenario,expected",
    [
        ("initial", "verified", "http://127.0.0.1:9032"),
        ("initial", "cross-issuer", "http://127.0.0.1:9032"),
        ("secondary", "cross-issuer", "http://127.0.0.1:9032/issuer-b"),
    ],
)
def test_only_fixed_test_authority_generations_select_a_trusted_issuer(phase, scenario, expected):
    assert bootstrap.identity_issuer(phase, scenario) == expected


@pytest.mark.parametrize(
    "phase,scenario",
    [
        (None, "cross-issuer"),
        (True, "cross-issuer"),
        ("", "cross-issuer"),
        ("http://arbitrary.test", "cross-issuer"),
        ("secondary", "verified"),
        ("secondary", "cross-issuer "),
        ("third", "cross-issuer"),
    ],
)
def test_untrusted_phase_or_non_cross_scenario_cannot_change_trust_configuration(phase, scenario):
    with pytest.raises(ValueError, match="Invalid integrated authority generation"):
        bootstrap.identity_issuer(phase, scenario)


@pytest.mark.parametrize(
    "module",
    [
        "dashboard_integrated_authority_expiry",
        "dashboard_integrated_execution_expiry",
        "dashboard_integrated_session_expiry",
        "dashboard_integrated_authority_restart",
        "dashboard_integrated_staleness",
        "dashboard_integrated_governance",
        "dashboard_integrated_revocation",
        "dashboard_integrated_reference",
    ],
)
def test_authority_clock_import_cannot_load_application_configuration(module):
    import os
    import subprocess
    import sys

    env = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith(
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
        )
    }
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import sys; import tests.{module}; "
            "assert not any(n == 'app' or n.startswith('app.') for n in sys.modules)",
        ],
        cwd=bootstrap.ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        creationflags=0x08000000 if os.name == "nt" else 0,
    )
    assert result.returncode == 0 and result.stdout == "" and result.stderr == ""


@pytest.mark.parametrize(
    "value", [None, "", 1, {}, "a" * 36, "ABCDEF01-1234-4123-8123-123456789abc"]
)
def test_owner_must_be_canonical_uuid4(value):
    with pytest.raises(ValueError, match="Invalid integrated fixture owner"):
        bootstrap.require_instance(value)


def test_configure_discards_inherited_write_and_identity_settings(monkeypatch):
    # Restore the whole process environment after the bootstrap's deliberate sanitization.
    monkeypatch.setattr(bootstrap.os, "environ", dict(bootstrap.os.environ))
    for name in ("AWS_ACCESS_KEY_ID", "REMEDIATION_WORKER_ENABLED", "DATABASE_URL", "OIDC_ISSUER"):
        bootstrap.os.environ[name] = "untrusted-inherited-value"
    bootstrap.configure()
    assert bootstrap.os.environ["DATABASE_URL"] == "sqlite://"
    assert "AWS_ACCESS_KEY_ID" not in bootstrap.os.environ
    assert "REMEDIATION_WORKER_ENABLED" not in bootstrap.os.environ
    assert "OIDC_ISSUER" not in bootstrap.os.environ
    assert bootstrap.os.environ["DASHBOARD_ENABLED"] == "false"
    assert bootstrap.os.environ["REMEDIATION_VERIFICATION_ENABLED"] == "false"


@pytest.mark.parametrize("container", [False, True])
@pytest.mark.parametrize(
    "case", ["driver", "host", "user", "password", "database", "port", "schema", "query"]
)
def test_server_rejects_unowned_url_before_connection(monkeypatch, case, container):
    import sqlalchemy
    from sqlalchemy.engine import URL

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    url = URL.create(
        "postgresql+psycopg",
        username="cloudsec_test",
        password="synthetic",
        host="pg" if container else "127.0.0.1",
        port=5432,
        database="cloudsec_test",
        query={"options": "-csearch_path=sprint8_worker_" + uuid4().hex},
    )
    wrong = {
        "driver": lambda: url.set(drivername="sqlite"),
        "host": lambda: url.set(host="localhost"),
        "user": lambda: url.set(username="operator"),
        "password": lambda: url.set(password=""),
        "database": lambda: url.set(database="operator"),
        "port": lambda: url.set(port=0),
        "schema": lambda: url.set(query={"options": "-csearch_path=public"}),
        "query": lambda: url.update_query_dict({"sslmode": "disable"}),
    }[case]()
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("Must not connect to unowned target")

    monkeypatch.setattr(sqlalchemy, "create_engine", forbidden)
    with pytest.raises(ValueError, match="Integrated server database ownership rejected"):
        bootstrap.server_database(
            wrong.render_as_string(hide_password=False), str(uuid4()), container=container
        )
    assert calls == []
