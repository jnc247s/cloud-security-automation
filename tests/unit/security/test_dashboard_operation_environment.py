"""A caller's browser opt-in must not widen the existing validation environment."""

from types import SimpleNamespace

from scripts import validate


def test_validation_explicitly_disables_browser_mutations_without_changing_host(monkeypatch):
    monkeypatch.setenv("DASHBOARD_ENABLED", "true")
    monkeypatch.setenv("DASHBOARD_REMEDIATION_ENABLED", "true")
    calls = []

    def run(*args, env=None, **kwargs):
        calls.append((args, dict(env) if env is not None else None))
        output = "127.0.0.1:15432" if args[:2] == ("docker", "port") else ""
        return SimpleNamespace(stdout=output, returncode=0)

    monkeypatch.setattr(validate, "run", run)
    validate.validate(["tests/unit/test_config.py"])
    test_environments = [env for args, env in calls if "pytest" in args and env is not None]
    assert len(test_environments) == 2
    assert all(env["DASHBOARD_ENABLED"] == "false" for env in test_environments)
    assert all(env["DASHBOARD_REMEDIATION_ENABLED"] == "false" for env in test_environments)
    assert all("TEST_DATABASE_URL" in env for env in test_environments)
    assert validate.os.environ["DASHBOARD_REMEDIATION_ENABLED"] == "true"
