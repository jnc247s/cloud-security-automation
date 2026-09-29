"""The local validation runner must isolate databases and clean up on failed gates."""

import subprocess

import pytest

from scripts import validate as runner


@pytest.mark.parametrize("fail_tests", [False, True])
def test_validation_isolated_cleanup_and_failure_propagation(monkeypatch, fail_tests):
    calls = []
    monkeypatch.setenv("TEST_DATABASE_URL", "do-not-use-existing-database")

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        if "pytest" in args and fail_tests:
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, "127.0.0.1:55432\n", "")

    monkeypatch.setattr(runner, "run", run)
    if fail_tests:
        with pytest.raises(subprocess.CalledProcessError):
            runner.validate(["tests/unit"])
    else:
        runner.validate(["tests/unit"])
    created = next(args for args, _ in calls if args[:2] == ("docker", "run"))
    name = created[created.index("--name") + 1]
    assert calls[-1][0] == ("docker", "rm", "--force", name)
    assert "--tmpfs" in created and "127.0.0.1::5432" in created
    for args, kwargs in calls:
        if "pytest" in args:
            url = kwargs["env"]["TEST_DATABASE_URL"]
            assert url.startswith("postgresql+psycopg://cloudsec_test:")
            assert "@127.0.0.1:55432/cloudsec_test" in url
            assert url not in args
    assert runner.os.environ["TEST_DATABASE_URL"] == "do-not-use-existing-database"
    assert any("build" in args for args, _ in calls) is not fail_tests
