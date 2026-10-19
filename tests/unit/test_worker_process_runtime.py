"""Ownership/cleanup/error guards run without Docker, databases or cloud access."""

import os
import subprocess
from copy import deepcopy
from unittest.mock import Mock

import pytest

from tests.worker_process_runtime import (
    KIND_LABEL,
    OWNER_LABEL,
    OfflineProcessRuntime,
    cleanup_preserving_primary,
    isolated_child_environment,
    loopback_port,
    require_local_docker_endpoint,
    require_owned_labels,
    validate_container_security,
    validate_process_report,
)

OWNER = "cloudsec-worker-process-" + "a" * 32


def process_proof():
    from tests.worker_process_harness import SOURCE_PATHS

    sources = {path: "a" * 64 for path in SOURCE_PATHS}
    return {
        "schema_version": 1,
        "exit_code": 0,
        "stdout": "WORKER_DISABLED\n",
        "stderr": "",
        "errors": [],
        "calls": [],
        "wire_actions": [],
        "lock_probes": [],
        "enable_invocations": 0,
        "intent_checks": 0,
        "source_hashes": sources,
        "locations": {
            "app": "/app/app",
            "boto3": "/usr/local/lib/python3.12/site-packages/boto3/__init__.py",
            "botocore": "/usr/local/lib/python3.12/site-packages/botocore/__init__.py",
        },
        "versions": {"python": "3.12.15", "boto3": "1.43.112", "botocore": "1.43.112"},
        "uid": 999,
        "engine_creations": 0,
        "application_settings_reads": 0,
        "host_file_reads": 0,
        "security": {"no_new_privileges": 1, "effective_capabilities": "0000000000000000"},
        "api_checks": {},
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", "1"),
        ("exit_code", False),
        ("exit_code", 1),
        ("stdout", "synthetic-sensitive-report"),
        ("stdout", None),
        ("stderr", "synthetic-sensitive-report"),
        ("errors", ["GUARD_FAILED"]),
        ("uid", None),
        ("uid", True),
        ("uid", 0),
        ("uid", -1),
        ("source_hashes", {}),
        ("calls", ["unexpected"]),
        ("calls", ["metadata"]),
        ("calls", ["metadata"] * 129),
        ("lock_probes", ["metadata"]),
        ("wire_actions", ["EnableEbsEncryptionByDefault"]),
        ("wire_actions", "GetCallerIdentity"),
        ("enable_invocations", True),
        ("enable_invocations", 1),
        ("intent_checks", True),
        ("intent_checks", 1),
        ("engine_creations", True),
        ("engine_creations", 2),
        ("application_settings_reads", True),
        ("application_settings_reads", 1),
        ("host_file_reads", True),
        ("host_file_reads", 1),
        ("security", {}),
        ("security", {"no_new_privileges": True, "effective_capabilities": "0000000000000000"}),
        ("security", {"no_new_privileges": 1, "effective_capabilities": "0000000000000001"}),
        ("versions", {}),
        (
            "versions",
            {"python": "synthetic-sensitive-report", "boto3": "1.0.0", "botocore": "1.0.0"},
        ),
        ("locations", {}),
        (
            "locations",
            {"app": "/harness/app", "boto3": "/harness/boto3", "botocore": "/harness/botocore"},
        ),
    ],
)
def test_parent_rejects_incomplete_ambiguous_or_false_process_proof(field, value):
    report = process_proof()
    sources = deepcopy(report["source_hashes"])
    report[field] = value
    with pytest.raises(RuntimeError, match="invalid offline process proof") as caught:
        validate_process_report(report, sources, 0, [])
    assert "synthetic-sensitive-report" not in str(caught.value)


def test_parent_requires_closed_report_and_source_field_sets():
    for change in ("missing", "extra", "wrong-source"):
        report = process_proof()
        sources = deepcopy(report["source_hashes"])
        if change == "missing":
            del report["uid"]
        elif change == "extra":
            report["unexpected"] = "synthetic-sensitive-report"
        else:
            report["source_hashes"][next(iter(sources))] = "b" * 64
        with pytest.raises(RuntimeError, match="invalid offline process proof"):
            validate_process_report(report, sources, 0, [])


def test_parent_requires_expected_wire_sequence_and_all_enable_proofs():
    from tests.worker_process_harness import ENABLE

    report = process_proof()
    report.update(
        stdout="ACKNOWLEDGED_UNVERIFIED\n",
        calls=["sdk:" + ENABLE, "wire:" + ENABLE],
        lock_probes=["sdk:" + ENABLE, "wire:" + ENABLE],
        wire_actions=[ENABLE],
        enable_invocations=1,
        intent_checks=1,
    )
    validate_process_report(report, report["source_hashes"], 0, [ENABLE])
    with pytest.raises(RuntimeError, match="invalid offline process proof"):
        validate_process_report(report, report["source_hashes"], 0, [])
    report["calls"] = report["lock_probes"] = ["wire:" + ENABLE]
    with pytest.raises(RuntimeError, match="invalid offline process proof"):
        validate_process_report(report, report["source_hashes"], 0, [ENABLE])


def test_parent_accepts_bounded_deliberate_death_without_claiming_success():
    report = process_proof()
    report.update(exit_code=47, stdout="")
    validate_process_report(report, report["source_hashes"], 47, [])


def test_packaged_api_proof_cannot_be_accepted_as_worker_or_missing_readiness():
    report = process_proof()
    report.update(
        stdout="API_STARTUP_VERIFIED\n",
        engine_creations=1,
        application_settings_reads=2,
        api_checks={
            "health": "healthy",
            "ready": "ready",
            "database": "ready",
            "openapi": True,
            "bearer_security": True,
            "tests_absent": True,
        },
    )
    validate_process_report(report, report["source_hashes"], 0, [], application="api")
    with pytest.raises(RuntimeError, match="invalid offline process proof"):
        validate_process_report(report, report["source_hashes"], 0, [])
    for field, value in (
        ("database", "unavailable"),
        ("tests_absent", False),
        ("bearer_security", 1),
        ("openapi", False),
    ):
        malformed = deepcopy(report)
        malformed["api_checks"][field] = value
        with pytest.raises(RuntimeError, match="invalid offline process proof"):
            validate_process_report(malformed, report["source_hashes"], 0, [], application="api")


def test_worker_and_api_log_bootstrap_keep_distinct_accepted_contracts():
    import logging

    from tests.worker_process_harness import harness_log_level

    assert harness_log_level("worker") == logging.DEBUG
    assert harness_log_level("api") == logging.CRITICAL


def test_worker_only_log_injection_cannot_change_packaged_api_logging(monkeypatch):
    from tests.worker_process_harness import post_entrypoint_diagnostics

    logger = Mock()
    get_logger = Mock(return_value=logger)
    # Restore before pytest's own call/teardown logging hooks use the real root logger.
    with monkeypatch.context() as scoped_patch:
        scoped_patch.setattr("tests.worker_process_harness.logging.getLogger", get_logger)
        post_entrypoint_diagnostics("api")
        get_logger.assert_not_called()
        logger.error.assert_not_called()
        post_entrypoint_diagnostics("worker")
    assert get_logger.call_count == logger.error.call_count == 3
    assert all(call.kwargs == {"exc_info": True} for call in logger.error.call_args_list)


def container_proof():
    mounts = {
        "/harness/worker.py": "/owned/worker.py",
        "/harness/scenario.json": "/owned/scenario.json",
    }
    value = {
        "image": "sha256:" + "a" * 64,
        "user": "app",
        "cmd": ["python", "/harness/worker.py", "/harness/scenario.json"],
        "entrypoint": None,
        "read_only": True,
        "privileged": False,
        "caps": ["ALL"],
        "caps_add": None,
        "security": ["no-new-privileges"],
        "network": OWNER,
        "ports": {},
        "tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"},
        "mounts": [
            {
                "Type": "bind",
                "Source": source,
                "Destination": target,
                "RW": False,
                "Propagation": "rprivate",
            }
            for target, source in mounts.items()
        ],
    }
    return value, mounts


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", "unrelated-image"),
        ("user", "root"),
        ("cmd", ["uvicorn", "app.main:app"]),
        ("entrypoint", ["unplanned"]),
        ("read_only", False),
        ("read_only", 1),
        ("privileged", True),
        ("caps", []),
        ("caps_add", ["SYS_ADMIN"]),
        ("security", []),
        ("network", "host"),
        ("ports", {"5432/tcp": [{"HostPort": "5432"}]}),
        ("tmpfs", {"/home/app/.aws": "rw"}),
        ("mounts", []),
    ],
)
def test_independent_container_metadata_rejects_unsafe_or_wrong_runtime(field, value):
    report, mounts = container_proof()
    image = report["image"]
    report[field] = value
    with pytest.raises(RuntimeError, match="security metadata mismatch"):
        validate_container_security(report, image, OWNER, mounts)


def test_independent_container_metadata_requires_closed_fields():
    for change in ("missing", "extra"):
        report, mounts = container_proof()
        image = report["image"]
        if change == "missing":
            del report["read_only"]
        else:
            report["unexpected"] = "synthetic-sensitive-value"
        with pytest.raises(RuntimeError, match="security metadata mismatch"):
            validate_container_security(report, image, OWNER, mounts)


@pytest.mark.parametrize("network", ["host", "bridge", "unrelated", None])
def test_container_validator_cannot_accept_a_broader_expected_network(network):
    report, mounts = container_proof()
    report["network"] = network
    with pytest.raises(RuntimeError, match="security metadata mismatch"):
        validate_container_security(report, report["image"], network, mounts)


@pytest.mark.parametrize("extra_target", ["/app/app", "/home/app/.aws"])
def test_container_validator_cannot_accept_broader_expected_mounts(extra_target):
    report, mounts = container_proof()
    mounts[extra_target] = "/user/credential-store"
    with pytest.raises(RuntimeError, match="security metadata mismatch"):
        validate_container_security(report, report["image"], OWNER, mounts)


def test_independent_mount_inspection_accepts_only_exact_narrow_read_only_sources():
    report, mounts = container_proof()
    validate_container_security(report, report["image"], OWNER, mounts)
    for field, value in (
        ("Source", "/user/credential-store"),
        ("Destination", "/app/app"),
        ("Type", "volume"),
        ("RW", True),
        ("RW", 0),
        ("Propagation", "rshared"),
    ):
        changed = deepcopy(report)
        changed["mounts"][0][field] = value
        with pytest.raises(RuntimeError, match="mount metadata mismatch"):
            validate_container_security(changed, report["image"], OWNER, mounts)
    report["mounts"][1] = deepcopy(report["mounts"][0])
    with pytest.raises(RuntimeError, match="mount metadata mismatch"):
        validate_container_security(report, report["image"], OWNER, mounts)


@pytest.mark.parametrize("secondary_cleanup_failure", [False, True])
def test_security_inspection_failure_prevents_process_start_and_preserves_primary(
    monkeypatch, tmp_path, secondary_cleanup_failure
):
    from types import SimpleNamespace

    runtime = OfflineProcessRuntime()
    runtime.image = "sha256:" + "a" * 64
    runtime.port = 12345
    runtime.schemas = {"sprint8_worker_" + "b" * 32}
    runtime.temporary = SimpleNamespace(name=str(tmp_path))
    monkeypatch.setattr(runtime, "_assert_database_owned", lambda: None)
    monkeypatch.setattr(runtime, "_reserve", Mock())
    create = Mock(return_value=subprocess.CompletedProcess(["docker"], 0, "", ""))
    monkeypatch.setattr(runtime, "_docker", create)
    primary = RuntimeError("independent security guard")
    monkeypatch.setattr(runtime, "_worker_security", Mock(side_effect=primary))
    cleanup = Mock(side_effect=RuntimeError("secondary") if secondary_cleanup_failure else None)
    monkeypatch.setattr(runtime, "_remove_worker", cleanup)
    scenario = {"argv": [], "responses": [], "metadata": "valid", "target": {}}
    child_url = runtime.database_url(child=True, schema=next(iter(runtime.schemas)))
    if secondary_cleanup_failure:
        with (
            pytest.warns(UserWarning, match="primary retained"),
            pytest.raises(RuntimeError) as caught,
        ):
            runtime.run_worker(scenario, child_url)
    else:
        with pytest.raises(RuntimeError) as caught:
            runtime.run_worker(scenario, child_url)
    assert caught.value is primary
    assert len(create.call_args_list) == 1 and create.call_args.args[0] == "create"
    cleanup.assert_called_once()


@pytest.mark.parametrize(
    "endpoint",
    [
        "unix:///var/run/docker.sock",
        "unix:///run/user/1000/docker.sock",
        "npipe:////./pipe/docker_engine",
        "npipe:////./pipe/dockerDesktopLinuxEngine",
    ],
)
def test_local_engine_endpoints_are_explicit(endpoint):
    require_local_docker_endpoint(endpoint)


@pytest.mark.parametrize(
    "endpoint",
    [
        None,
        "",
        "tcp://127.0.0.1:2375",
        "tcp://production:2376",
        "ssh://sensitive-user@production",
        "unix://remote/var/run/docker.sock",
        "unix:///var/run/docker.sock?override=secret",
        "npipe:////remote/pipe/docker_engine",
        "unix://[invalid-sensitive-endpoint",
        "unix:///var/run/docker.sock\n",
    ],
)
def test_remote_or_ambiguous_engine_endpoint_fails_without_echoing_input(endpoint):
    with pytest.raises(RuntimeError, match="local Docker endpoint") as caught:
        require_local_docker_endpoint(endpoint)
    assert "sensitive-user" not in str(caught.value)
    assert "production" not in str(caught.value)


def test_child_input_cannot_override_engine_selection(monkeypatch):
    call = Mock(side_effect=AssertionError("No command"))
    monkeypatch.setattr("tests.worker_process_runtime.subprocess.run", call)
    with pytest.raises(RuntimeError, match="cannot select"):
        OfflineProcessRuntime()._docker("info", env={"DOCKER_HOST": "tcp://production:2376"})
    call.assert_not_called()


def test_verified_endpoint_is_pinned_across_inherited_environment_changes(monkeypatch):
    runtime = OfflineProcessRuntime()
    runtime.endpoint = "unix:///var/run/docker.sock"
    monkeypatch.setenv("DOCKER_HOST", "tcp://production:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "production")
    call = Mock(return_value=subprocess.CompletedProcess(["docker"], 0, "", ""))
    monkeypatch.setattr("tests.worker_process_runtime.subprocess.run", call)
    runtime._docker("info")
    assert call.call_args.args[0] == ["docker", "--host", runtime.endpoint, "info"]
    assert not any(name.upper().startswith("DOCKER_") for name in call.call_args.kwargs["env"])


def test_remote_configured_host_stops_before_any_docker_command(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://production:2376")
    runtime = OfflineProcessRuntime()
    call = Mock(side_effect=AssertionError("No command"))
    monkeypatch.setattr(runtime, "_docker", call)
    with pytest.raises(RuntimeError, match="local Docker endpoint"):
        runtime.start()
    call.assert_not_called()
    assert runtime.temporary is None and runtime.possible_resources == []


@pytest.mark.parametrize("context", ["", "--context=production", "first\nsecond"])
def test_unsafe_context_name_stops_before_inspection_or_provisioning(monkeypatch, context):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    runtime = OfflineProcessRuntime()
    call = Mock(return_value=subprocess.CompletedProcess(["docker"], 0, context, ""))
    monkeypatch.setattr(runtime, "_docker", call)
    with pytest.raises(RuntimeError, match="context identity unavailable"):
        runtime.start()
    call.assert_called_once_with("context", "show")
    assert runtime.temporary is None and runtime.possible_resources == []


def test_remote_context_endpoint_never_contacts_the_engine_or_provisions(monkeypatch):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    runtime = OfflineProcessRuntime()
    call = Mock(
        side_effect=[
            subprocess.CompletedProcess(["docker"], 0, "default\n", ""),
            subprocess.CompletedProcess(["docker"], 0, '"ssh://production"', ""),
        ]
    )
    monkeypatch.setattr(runtime, "_docker", call)
    with pytest.raises(RuntimeError, match="local Docker endpoint"):
        runtime.start()
    assert call.call_count == 2
    assert runtime.temporary is None and runtime.possible_resources == []


@pytest.mark.parametrize(
    "value",
    [
        "0.0.0.0:5432",
        "[::1]:5432",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:1\n127.0.0.1:2",
        "secret-url",
    ],
)
def test_port_requires_one_strict_loopback_endpoint(value):
    with pytest.raises(RuntimeError, match="exactly one loopback"):
        loopback_port(value)


def test_port_accepts_valid_owned_endpoint():
    assert loopback_port("127.0.0.1:32123\n") == 32123


@pytest.mark.parametrize(
    "kind,name",
    [("network", OWNER), ("database", OWNER + "-db"), ("worker", OWNER + "-worker-" + "b" * 32)],
)
def test_owned_targets_require_both_exact_name_and_kind(kind, name):
    require_owned_labels(OWNER, name, kind, {OWNER_LABEL: OWNER, KIND_LABEL: kind})
    for labels in (
        {},
        {OWNER_LABEL: OWNER},
        {OWNER_LABEL: "other", KIND_LABEL: kind},
        {OWNER_LABEL: OWNER, KIND_LABEL: "other"},
    ):
        with pytest.raises(RuntimeError, match="mismatch"):
            require_owned_labels(OWNER, name, kind, labels)


@pytest.mark.parametrize(
    "name", ["main", "/", OWNER + "-db-extra", OWNER + "-worker-", OWNER + "-worker-user-data"]
)
def test_labels_cannot_authorize_broad_or_unrelated_names(name):
    with pytest.raises(RuntimeError, match="mismatch"):
        require_owned_labels(OWNER, name, "database", {OWNER_LABEL: OWNER, KIND_LABEL: "database"})


def test_invalid_owner_rejected_before_resource_use():
    with pytest.raises(RuntimeError, match="invalid offline resource owner"):
        require_owned_labels("user-container", "user-container", "network", {})


def test_child_environment_omits_application_cloud_database_and_identity_values(monkeypatch):
    for name in (
        "AWS_ACCESS_KEY_ID",
        "aws_profile",
        "BOTO_CONFIG",
        "APP_ENV",
        "AUTH_MODE",
        "DATABASE_URL",
        "TEST_DATABASE_URL",
        "OIDC_ISSUER",
        "DASHBOARD_CLIENT_SECRET",
        "REMEDIATION_WORKER_ENABLED",
        "POSTGRES_PASSWORD",
    ):
        monkeypatch.setenv(name, "synthetic-sensitive-value")
    monkeypatch.setenv("DOCKER_TEST_CONTEXT", "kept")
    child = isolated_child_environment({"POSTGRES_PASSWORD": "new-owned-password"})
    assert child["POSTGRES_PASSWORD"] == "new-owned-password"
    assert child["DOCKER_TEST_CONTEXT"] == "kept"
    assert "synthetic-sensitive-value" not in child.values()
    assert os.environ["POSTGRES_PASSWORD"] == "synthetic-sensitive-value"


@pytest.mark.parametrize(
    "primary_failed,cleanup_failed", [(False, False), (True, False), (False, True), (True, True)]
)
def test_cleanup_outcomes_do_not_replace_primary(primary_failed, cleanup_failed):
    primary = RuntimeError("primary") if primary_failed else None
    cleanup = Mock(side_effect=RuntimeError("cleanup") if cleanup_failed else None)
    if cleanup_failed and primary is None:
        with pytest.raises(RuntimeError, match="cleanup"):
            cleanup_preserving_primary(cleanup, primary)
    elif cleanup_failed:
        with pytest.warns(UserWarning, match="primary retained"):
            cleanup_preserving_primary(cleanup, primary)
    else:
        cleanup_preserving_primary(cleanup, primary)
    cleanup.assert_called_once_with()


def test_even_failed_cleanup_diagnostic_cannot_replace_original_error(monkeypatch):
    monkeypatch.setattr(
        "tests.worker_process_runtime.warnings.warn", Mock(side_effect=RuntimeError("diagnostic"))
    )
    primary = RuntimeError("primary")
    cleanup_preserving_primary(Mock(side_effect=RuntimeError("cleanup")), primary)


def test_context_preserves_exact_body_failure_when_cleanup_also_fails(monkeypatch):
    runtime = OfflineProcessRuntime()
    monkeypatch.setattr(runtime, "start", lambda: runtime)
    monkeypatch.setattr(runtime, "cleanup", Mock(side_effect=RuntimeError("secondary")))
    original = RuntimeError("original")
    with pytest.warns(UserWarning, match="primary retained"):
        with pytest.raises(RuntimeError) as caught, runtime:
            raise original
    assert caught.value is original


def test_start_failure_is_not_replaced_by_cleanup_failure(monkeypatch):
    runtime = OfflineProcessRuntime()
    original = RuntimeError("original start")
    monkeypatch.setattr(runtime, "start", Mock(side_effect=original))
    monkeypatch.setattr(runtime, "cleanup", Mock(side_effect=RuntimeError("secondary")))
    with pytest.warns(UserWarning, match="primary retained"):
        with pytest.raises(RuntimeError) as caught:
            runtime.__enter__()
    assert caught.value is original


def test_existing_resource_is_not_adopted_or_registered_for_cleanup(monkeypatch):
    runtime = OfflineProcessRuntime()
    monkeypatch.setattr(runtime, "_exists", lambda *args: True)
    with pytest.raises(RuntimeError, match="already exists"):
        runtime._reserve(runtime.database_name, "database")
    assert runtime.possible_resources == []


def test_cleanup_never_removes_an_unowned_resource(monkeypatch):
    runtime = OfflineProcessRuntime()
    runtime.possible_resources.append((runtime.database_name, "database"))
    monkeypatch.setattr(runtime, "_exists", lambda *args: True)
    monkeypatch.setattr(runtime, "_labels", lambda *args: {OWNER_LABEL: "unrelated"})
    remove = Mock(side_effect=AssertionError("No removal"))
    monkeypatch.setattr(runtime, "_docker", remove)
    with pytest.raises(RuntimeError, match="cleanup failed"):
        runtime.cleanup()
    remove.assert_not_called()


def test_docker_errors_never_echo_raw_command_environment_or_stderr(monkeypatch):
    monkeypatch.setattr(
        "tests.worker_process_runtime.subprocess.run",
        Mock(
            return_value=subprocess.CompletedProcess(
                ["docker"], 1, "synthetic-secret-body", "synthetic-secret-password"
            )
        ),
    )
    with pytest.raises(RuntimeError) as caught:
        OfflineProcessRuntime()._docker(
            "info", env={"POSTGRES_PASSWORD": "synthetic-secret-password"}
        )
    assert "synthetic-secret" not in str(caught.value)


def test_docker_output_uses_explicit_utf8_not_windows_code_page(monkeypatch):
    call = Mock(return_value=subprocess.CompletedProcess(["docker"], 0, "", ""))
    monkeypatch.setattr("tests.worker_process_runtime.subprocess.run", call)
    OfflineProcessRuntime()._docker("info")
    assert call.call_args.kwargs["encoding"] == "utf-8"


def test_only_owned_database_joins_bridge_for_loopback_and_private_alias(monkeypatch, tmp_path):
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    runtime = OfflineProcessRuntime()
    calls = []

    def command(*args, **kwargs):
        calls.append((args, kwargs))
        output = ""
        if args[:2] == ("context", "show"):
            output = "default"
        elif args[:2] == ("context", "inspect"):
            output = '"unix:///var/run/docker.sock"'
        elif args[0] == "info":
            output = "linux"
        elif args[:2] == ("image", "inspect"):
            output = "sha256:" + "a" * 64
        elif args[0] == "port":
            output = "127.0.0.1:31234"
        return subprocess.CompletedProcess(["docker"], 0, output, "")

    monkeypatch.setattr(runtime, "_docker", command)
    monkeypatch.setattr(runtime, "_reserve", lambda *args: None)
    monkeypatch.setattr(runtime, "_assert_database_owned", lambda: None)
    temporary = Mock(name=str(tmp_path))
    temporary.name = str(tmp_path)
    monkeypatch.setattr(
        "tests.worker_process_runtime.tempfile.TemporaryDirectory", lambda **kwargs: temporary
    )
    runtime.start()
    database_run = next(args for args, _kwargs in calls if args[0] == "run")
    assert database_run[database_run.index("--network") + 1] == "bridge"
    assert database_run[database_run.index("--publish") + 1] == "127.0.0.1::5432"
    private = ("network", "connect", "--alias", "pg", runtime.owner, runtime.database_name)
    assert private in [args for args, _kwargs in calls]
    assert [args for args, _kwargs in calls].index(private) < next(
        i for i, (args, _kwargs) in enumerate(calls) if args[0] == "port"
    )


def test_urls_require_live_owned_handle_before_being_derived(monkeypatch):
    runtime = OfflineProcessRuntime()
    lookup = Mock(side_effect=RuntimeError("not owned"))
    monkeypatch.setattr(runtime, "_assert_database_owned", lookup)
    with pytest.raises(RuntimeError, match="not owned"):
        runtime.database_url(child=True)
    lookup.assert_called_once_with()


@pytest.mark.parametrize(
    "attached,retained,stderr,expected",
    [
        ('{"proof":1}\n', '{"proof":1}\n', "", True),
        ("", '{"proof":1}\n', "", True),
        ("", "", "", False),
        ('{"proof":1}', "", "", False),
        ("{broken", '{"proof":1}\n', "", False),
        ('{"proof":2}', '{"proof":1}', "", False),
        ("", "{broken", "", False),
        ("", "[]", "", False),
        ("", '{"proof":1}', "synthetic-sensitive-stderr", False),
    ],
)
def test_terminal_report_requires_retained_same_child_output_and_no_conflicting_stream(
    attached, retained, stderr, expected
):
    from types import SimpleNamespace

    from tests.worker_process_runtime import decode_terminal_report

    primary = SimpleNamespace(stdout=attached, stderr="")
    saved = SimpleNamespace(stdout=retained, stderr=stderr)
    if expected:
        assert decode_terminal_report(primary, saved) == {"proof": 1}
    else:
        with pytest.raises(RuntimeError) as caught:
            decode_terminal_report(primary, saved)
        assert "synthetic-sensitive" not in str(caught.value)
