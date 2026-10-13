"""Fresh installed-image process journeys; only self-owned PostgreSQL and synthetic AWS I/O."""

import os
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.engine import make_url

from app.remediation.execution_contracts import ADMISSION_CAPACITY, ExecutionPhase
from app.remediation.provenance import utc
from tests.worker_fault_http import source_for_account
from tests.worker_http import CASES, database_state
from tests.worker_process_harness import ENABLE, ENCRYPTION, IDENTITY, KEY
from tests.worker_process_http import script_for, signed_process_journey
from tests.worker_process_runtime import OfflineProcessRuntime

pytestmark = pytest.mark.integration

FORBIDDEN_SOURCES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "BOTO_CONFIG",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_EC2",
    "AWS_ENDPOINT_URL_STS",
    "AWS_ENDPOINT_URL_OTHER",
    "AWS_CA_BUNDLE",
    "AWS_DATA_PATH",
)
INVALID_RELATIVE_URIS = (
    None,
    "",
    "http://localhost/credentials",
    "//host/credentials",
    "/../credentials",
    "/v2/credentials/abc?token=synthetic-sensitive-value",
    "/v2/credentials/abc#fragment",
    "/v2/credentials/abc/extra",
    "/v2/credentials/%2fescape",
    "/v2/credentials/ abc",
)


def assert_no_write(journey, report, reason):
    assert report["exit_code"] == 0 and report["stdout"] == "NO_WRITE\n"
    assert report["enable_invocations"] == report["intent_checks"] == 0
    assert ENABLE not in report["wire_actions"]
    current = journey.check(ExecutionPhase.NO_WRITE)
    assert [entry.content.kind.value for entry in current.events] == [
        "REQUESTED",
        "CLAIMED",
        "NO_WRITE",
    ]
    assert [value.value for value in current.events[-1].content.blocking_reasons] == [reason]
    return current


def wait_for_owned_deadline(deadline):
    """Exercise the real accepted lease/window; never rewrite persisted time or budgets."""
    seconds = max(0.0, (utc(deadline) - datetime.now(UTC)).total_seconds()) + 0.1
    assert seconds <= 31, "unexpected test lease/window duration"
    time.sleep(seconds)


def false_read():
    return [[IDENTITY, "valid"], [ENCRYPTION, False], [KEY, None]]


def true_read():
    return [[IDENTITY, "valid"], [ENCRYPTION, True], [KEY, None]]


def unchanged_postintent_owner(before, after):
    for field in (
        "execution_id",
        "token_sha256",
        "expected_role_arn",
        "generation",
        "read_attempts",
        "lease_until",
        "write_intent_event_id",
    ):
        assert before[field] == after[field], "post-intent ownership or intent changed"


@pytest.mark.parametrize(
    "table",
    [
        "remediation_proposals",
        "remediation_decisions",
        "remediation_requests",
        "remediation_executions",
        "remediation_admission_guard",
        "remediation_execution_events",
        "remediation_target_reservations",
        "remediation_worker_claims",
    ],
)
def test_parent_coordination_guard_rejects_missing_or_stray_snapshot_rows(
    offline_process_runtime, process_database, monkeypatch, tmp_path, table
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        current = journey.check(ExecutionPhase.QUEUED, held=True)
        before = database_state(engine)
        malformed = dict(before)
        malformed[table] = (SimpleNamespace(),) if table == "remediation_worker_claims" else ()
        with pytest.raises(AssertionError):
            journey._coordination(malformed, current, held=True)
        assert database_state(engine) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("execution_id", uuid4()),
        ("expected_role_arn", "unplanned-role"),
        ("generation", 2),
        ("token_sha256", "invalid-digest"),
        ("read_attempts", 4),
        ("lease_until", datetime(2099, 1, 1, tzinfo=UTC)),
        ("write_intent_event_id", uuid4()),
        ("readback_attempts", 1),
        ("readback_started_at", datetime(2099, 1, 1, tzinfo=UTC)),
    ],
)
def test_parent_coordination_guard_rejects_corrupt_private_claim_snapshot(
    offline_process_runtime, process_database, monkeypatch, tmp_path, field, value
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run(script_for("already-enabled", None))
        assert report["enable_invocations"] == 0
        current = journey.check(ExecutionPhase.NO_WRITE)
        before = database_state(engine)
        malformed = dict(before)
        claim = SimpleNamespace(**dict(before["remediation_worker_claims"][0]._mapping))
        setattr(claim, field, value)
        malformed["remediation_worker_claims"] = (claim,)
        with pytest.raises(AssertionError):
            journey._coordination(malformed, current, held=False)
        assert database_state(engine) == before


@pytest.mark.parametrize("guard", ["unused", "wrong-sequence", "unarmed"])
def test_parent_cannot_accept_broken_transport_guard_as_worker_success(
    offline_process_runtime, process_database, monkeypatch, tmp_path, guard
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        responses = (
            script_for("already-enabled", None) + [[IDENTITY, "valid"]]
            if guard == "unused"
            else [[ENCRYPTION, False]]
            if guard == "wrong-sequence"
            else []
        )
        with pytest.raises(RuntimeError, match="invalid offline process proof"):
            journey.run(responses, guard_disarmed=guard == "unarmed")
        phase = (
            ExecutionPhase.NO_WRITE
            if guard == "unused"
            else ExecutionPhase.CLAIMED
            if guard == "wrong-sequence"
            else ExecutionPhase.QUEUED
        )
        current = journey.check(phase, held=guard != "unused")
        assert all(entry.content.kind.value != "WRITE_INTENT" for entry in current.events)


def test_installed_packaging_api_startup_cannot_dispatch_queued_remediation(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        before = database_state(engine)
        report = journey.run([], application="api")
        assert report["exit_code"] == 0 and report["stdout"] == "API_STARTUP_VERIFIED\n"
        assert report["enable_invocations"] == report["intent_checks"] == 0
        assert report["calls"] == report["wire_actions"] == []
        assert database_state(engine) == before
        current = journey.check(ExecutionPhase.QUEUED, held=True)
        assert len(current.events) == 1 and journey.claim_state() is None


@pytest.fixture(scope="session")
def offline_process_runtime():
    configured = os.environ.get("TEST_DATABASE_URL")
    if not configured:
        pytest.skip("set disposable TEST_DATABASE_URL to run PostgreSQL/process integration")
    if make_url(configured).get_backend_name() != "postgresql":
        pytest.fail("TEST_DATABASE_URL must name PostgreSQL integration")
    # The configured URL enables integration; it is NEVER used as this process stack's target.
    with OfflineProcessRuntime() as runtime:
        yield runtime


@pytest.fixture
def process_database(offline_process_runtime):
    with offline_process_runtime.schema() as value:
        yield value


@pytest.mark.parametrize("outcome,baseline_key", CASES)
def test_signed_installed_process_history(
    offline_process_runtime, process_database, monkeypatch, tmp_path, outcome, baseline_key
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime,
        engine,
        child_url,
        monkeypatch,
        tmp_path,
        baseline_key=baseline_key,
    ) as journey:
        report = journey.run(script_for(outcome, baseline_key))
        success = outcome == "acknowledged"
        assert report["exit_code"] == 0
        assert report["stdout"] == ("ACKNOWLEDGED_UNVERIFIED\n" if success else "NO_WRITE\n")
        assert report["enable_invocations"] == int(success)
        current = journey.check(ExecutionPhase.ACKNOWLEDGED if success else ExecutionPhase.NO_WRITE)
        assert [entry.content.kind.value for entry in current.events] == (
            ["REQUESTED", "CLAIMED", "WRITE_INTENT", "ACKNOWLEDGED", "OBSERVED"]
            if success
            else ["REQUESTED", "CLAIMED", "NO_WRITE"]
        )
        if success:
            assert current.events[-1].content.observation.encryption_by_default is True
            assert current.events[-1].content.polls == 1
        else:
            assert [reason.value for reason in current.events[-1].content.blocking_reasons] == [
                "PRECONDITION_CHANGED"
            ]


@pytest.mark.parametrize("name", FORBIDDEN_SOURCES)
@pytest.mark.parametrize("value", ["", "synthetic-sensitive-source"])
def test_installed_process_forbidden_sources_fail_before_provider_construction(
    offline_process_runtime, process_database, monkeypatch, tmp_path, name, value
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run([], environment={name: value})
        assert report["calls"] == report["lock_probes"] == report["wire_actions"] == []
        assert_no_write(journey, report, "WRITER_SCOPE_MISMATCH")


@pytest.mark.parametrize("uri", INVALID_RELATIVE_URIS)
def test_installed_process_invalid_relative_uri_never_looks_up_credentials(
    offline_process_runtime, process_database, monkeypatch, tmp_path, uri
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run([], environment={"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": uri})
        assert report["calls"] == report["lock_probes"] == report["wire_actions"] == []
        assert_no_write(journey, report, "WRITER_SCOPE_MISMATCH")


@pytest.mark.parametrize("metadata", ["malformed", "unavailable"])
def test_installed_process_metadata_failure_is_bounded_without_fallback_or_write(
    offline_process_runtime, process_database, monkeypatch, tmp_path, metadata
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run([], metadata=metadata)
        assert report["calls"] == ["factory", "metadata", "metadata", "metadata"]
        assert report["wire_actions"] == []
        assert_no_write(journey, report, "READ_UNAVAILABLE")


@pytest.mark.parametrize("identity", ["wrong-account", "wrong-role", "missing-field"])
def test_installed_process_rejects_wrong_or_incomplete_identity(
    offline_process_runtime, process_database, monkeypatch, tmp_path, identity
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run([[IDENTITY, identity]])
        assert report["wire_actions"] == [IDENTITY]
        assert_no_write(journey, report, "WRITER_SCOPE_MISMATCH")


@pytest.mark.parametrize(
    "responses,reason",
    [
        ([[IDENTITY, "valid"], [ENCRYPTION, "missing-field"]], "READ_UNAVAILABLE"),
        ([[IDENTITY, "valid"], [ENCRYPTION, False], [KEY, ""]], "READ_UNAVAILABLE"),
        ([[IDENTITY, "valid"], [ENCRYPTION, "denied"]], "READ_UNAVAILABLE"),
        ([[IDENTITY, "valid"], [ENCRYPTION, "503"]] * 3, "READ_BUDGET_EXHAUSTED"),
    ],
)
def test_installed_process_incomplete_or_failed_reads_never_enable(
    offline_process_runtime, process_database, monkeypatch, tmp_path, responses, reason
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run(responses)
        assert report["wire_actions"] == [entry[0] for entry in responses]
        assert_no_write(journey, report, reason)


@pytest.mark.parametrize(
    "environment,output",
    [
        ({"REMEDIATION_WORKER_ACCOUNT_ID": None}, "WORKER_UNAVAILABLE\n"),
        ({"REMEDIATION_WORKER_REGION": None}, "WORKER_UNAVAILABLE\n"),
        ({"REMEDIATION_WORKER_ROLE_ARN": None}, "WORKER_UNAVAILABLE\n"),
        ({"REMEDIATION_WORKER_DATABASE_URL": None}, "WORKER_UNAVAILABLE\n"),
        ({"REMEDIATION_WORKER_DATABASE_URL": "sqlite://"}, "WORKER_CONFIGURATION_REJECTED\n"),
        (
            {"REMEDIATION_WORKER_DATABASE_URL": "synthetic-sensitive-invalid-url"},
            "WORKER_UNAVAILABLE\n",
        ),
        ({"REMEDIATION_WORKER_ENABLED": "synthetic-sensitive-value"}, "WORKER_UNAVAILABLE\n"),
        ({"REMEDIATION_WORKER_ACCOUNT_ID": "synthetic-sensitive-value"}, "WORKER_UNAVAILABLE\n"),
        (
            {"REMEDIATION_WORKER_REGION": "https://synthetic-sensitive-endpoint"},
            "WORKER_UNAVAILABLE\n",
        ),
        ({"REMEDIATION_WORKER_ROLE_ARN": "synthetic-sensitive-value"}, "WORKER_UNAVAILABLE\n"),
        ({"REMEDIATION_WORKER_REGION": "us-west-2"}, "WORKER_UNAVAILABLE\n"),
        (
            {
                "REMEDIATION_WORKER_ACCOUNT_ID": "999999999999",
                "REMEDIATION_WORKER_ROLE_ARN": "arn:aws:iam::999999999999:role/remediation-worker",
            },
            "WORKER_UNAVAILABLE\n",
        ),
    ],
)
def test_installed_process_configuration_cutoffs_leave_admitted_grant_untouched(
    offline_process_runtime, process_database, monkeypatch, tmp_path, environment, output
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        scope_conflict = (
            environment.get("REMEDIATION_WORKER_REGION") == "us-west-2"
            or environment.get("REMEDIATION_WORKER_ACCOUNT_ID") == "999999999999"
        )
        report = journey.run([], environment=environment, expected_engines=int(scope_conflict))
        assert report["exit_code"] == 1 and report["stdout"] == output
        assert report["calls"] == [] and report["enable_invocations"] == 0
        current = journey.check(ExecutionPhase.QUEUED, held=True)
        assert len(current.events) == 1


@pytest.mark.parametrize("argv", [[], ["synthetic-sensitive-argument"], ["invalid", "extra"]])
def test_installed_process_argument_errors_do_not_echo_input_or_claim_a_job(
    offline_process_runtime, process_database, monkeypatch, tmp_path, argv
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run([], argv=argv, expected_engines=0)
        assert report["exit_code"] == 2 and report["stdout"] == "WORKER_INVALID_ARGUMENT\n"
        assert report["calls"] == [] and report["enable_invocations"] == 0
        assert len(journey.check(ExecutionPhase.QUEUED, held=True).events) == 1


@pytest.mark.parametrize("argv", [["--help"], ["-h"]])
def test_installed_process_help_precedes_sensitive_invalid_configuration(
    offline_process_runtime, process_database, monkeypatch, tmp_path, argv
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run(
            [],
            argv=argv,
            environment={"REMEDIATION_WORKER_ENABLED": "synthetic-sensitive-value"},
            expected_engines=0,
        )
        assert report["exit_code"] == 0
        assert report["stdout"] == (
            "Process one explicitly admitted remediation job: "
            "python -m app.remediation.worker UUID\n"
        )
        assert report["calls"] == [] and report["enable_invocations"] == 0
        assert len(journey.check(ExecutionPhase.QUEUED, held=True).events) == 1


def test_installed_process_default_off_never_uses_scanner_or_application_fallback(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        report = journey.run(
            [],
            expected_engines=0,
            environment={
                "REMEDIATION_WORKER_ENABLED": None,
                "REMEDIATION_WORKER_ACCOUNT_ID": None,
                "REMEDIATION_WORKER_REGION": None,
                "REMEDIATION_WORKER_ROLE_ARN": None,
                "REMEDIATION_WORKER_DATABASE_URL": None,
                "DATABASE_URL": "sqlite:///synthetic-sensitive-scanner.db",
                "APP_ENV": "production",
                "AUTH_MODE": "oidc",
                "REMEDIATION_ADMISSION_ENABLED": "true",
                "AWS_REGION": "us-west-2",
                "AWS_DEFAULT_REGION": "us-west-2",
                "AWS_PROFILE": "synthetic-scanner-read-only",
            },
        )
        assert report["exit_code"] == 0 and report["stdout"] == "WORKER_DISABLED\n"
        assert report["calls"] == [] and report["enable_invocations"] == 0
        assert len(journey.check(ExecutionPhase.QUEUED, held=True).events) == 1


@pytest.mark.parametrize("mode", ["default-off", "missing-database", "enabled"])
def test_installed_process_ignores_narrow_synthetic_dotenv_file(
    offline_process_runtime, process_database, monkeypatch, tmp_path, mode
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        environment = (
            {"REMEDIATION_WORKER_ENABLED": None}
            if mode == "default-off"
            else {"REMEDIATION_WORKER_DATABASE_URL": None}
            if mode == "missing-database"
            else {}
        )
        enabled = mode == "enabled"
        report = journey.run(
            script_for("acknowledged", None) if enabled else [],
            environment=environment,
            dotenv=True,
            expected_engines=int(enabled),
        )
        assert report["host_file_reads"] == report["application_settings_reads"] == 0
        if enabled:
            assert report["enable_invocations"] == 1
            assert report["stdout"] == "ACKNOWLEDGED_UNVERIFIED\n"
            journey.check(ExecutionPhase.ACKNOWLEDGED)
        else:
            assert report["exit_code"] == int(mode == "missing-database")
            assert report["stdout"] == (
                "WORKER_DISABLED\n" if mode == "default-off" else "WORKER_UNAVAILABLE\n"
            )
            assert report["calls"] == [] and report["enable_invocations"] == 0
            assert len(journey.check(ExecutionPhase.QUEUED, held=True).events) == 1


@pytest.mark.parametrize("receipt", ["timeout", "503", "missing-field", "invalid-xml"])
def test_fresh_process_uncertain_write_remains_quarantined_without_resend(
    offline_process_runtime, process_database, monkeypatch, tmp_path, receipt
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        first = journey.run(false_read() + [[ENABLE, receipt], [IDENTITY, "denied"]])
        assert first["exit_code"] == 0 and first["stdout"] == "QUARANTINED_UNVERIFIED\n"
        assert first["enable_invocations"] == first["intent_checks"] == 1
        initial = journey.check(ExecutionPhase.QUARANTINED, held=True)
        assert [entry.content.kind.value for entry in initial.events] == [
            "REQUESTED",
            "CLAIMED",
            "WRITE_INTENT",
            "QUARANTINED",
            "OBSERVATION_FAILED",
        ]
        assert [reason.value for reason in initial.events[3].content.blocking_reasons] == [
            "WRITE_UNCERTAIN"
        ]
        owner = journey.claim_state()
        assert owner["generation"] == owner["read_attempts"] == owner["readback_attempts"] == 1
        recovered = journey.run(true_read())
        assert recovered["enable_invocations"] == recovered["intent_checks"] == 0
        assert recovered["stdout"] == "QUARANTINED_UNVERIFIED\n"
        current = journey.check(ExecutionPhase.QUARANTINED, held=True)
        assert current.events[-1].content.polls == 2
        assert current.events[-1].content.observation.encryption_by_default is True
        after = journey.claim_state()
        unchanged_postintent_owner(owner, after)
        assert utc(after["readback_started_at"]) == utc(owner["readback_started_at"])
        assert after["readback_attempts"] == 2
        assert first["wire_actions"].count(ENABLE) + recovered["wire_actions"].count(ENABLE) == 1


def test_owned_process_death_after_intent_recovers_without_reclaim_or_repeat_enable(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        dead = journey.run(false_read() + [[ENABLE, "death"]])
        assert dead["exit_code"] == 47 and dead["stdout"] == ""
        assert dead["enable_invocations"] == dead["intent_checks"] == 1
        current = journey.check(ExecutionPhase.WRITE_INTENT, held=True)
        assert [entry.content.kind.value for entry in current.events] == [
            "REQUESTED",
            "CLAIMED",
            "WRITE_INTENT",
        ]
        owner = journey.claim_state()
        assert owner["readback_attempts"] == 0 and owner["readback_started_at"] is None
        reports = [dead]
        started = None
        for poll in (1, 2, 3):
            report = journey.run([[IDENTITY, "denied"]] if poll == 1 else true_read())
            reports.append(report)
            assert report["stdout"] == "QUARANTINED_UNVERIFIED\n"
            assert report["enable_invocations"] == 0
            current = journey.check(ExecutionPhase.QUARANTINED, held=True)
            assert current.events[-1].content.polls == poll
            claim = journey.claim_state()
            unchanged_postintent_owner(owner, claim)
            if started is None:
                started = utc(claim["readback_started_at"])
            assert utc(claim["readback_started_at"]) == started
            assert claim["readback_attempts"] == poll
        before = database_state(engine)
        exhausted = journey.run([])
        assert exhausted["stdout"] == "QUARANTINED_UNVERIFIED\n"
        assert exhausted["calls"] == [] and exhausted["enable_invocations"] == 0
        assert database_state(engine) == before
        current = journey.check(ExecutionPhase.QUARANTINED, held=True)
        assert current.content == journey.initial.content
        assert current.events[-1].content.observation.encryption_by_default is True
        assert sum(report["wire_actions"].count(ENABLE) for report in reports) == 1


def test_fresh_process_readback_deaths_consume_global_budget_without_new_window(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        first = journey.run(false_read() + [[ENABLE, "death"]])
        assert first["exit_code"] == 47
        journey.check(ExecutionPhase.WRITE_INTENT, held=True)
        owner = journey.claim_state()
        started = None
        for poll in (1, 2, 3):
            dead = journey.run([[IDENTITY, "death"]])
            assert dead["exit_code"] == 47 and dead["enable_invocations"] == 0
            current = journey.check(ExecutionPhase.QUARANTINED, held=True, expected_readback=poll)
            assert current.events[-1].content.kind.value == "QUARANTINED"
            claim = journey.claim_state()
            unchanged_postintent_owner(owner, claim)
            if started is None:
                started = utc(claim["readback_started_at"])
            assert utc(claim["readback_started_at"]) == started
            assert claim["readback_attempts"] == poll
        before = database_state(engine)
        exhausted = journey.run([])
        assert exhausted["calls"] == [] and exhausted["enable_invocations"] == 0
        assert database_state(engine) == before
        journey.check(ExecutionPhase.QUARANTINED, held=True, expected_readback=3)


def test_fresh_process_cannot_renew_expired_readback_window_or_release_quarantine(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        first = journey.run(false_read() + [[ENABLE, "timeout"], [IDENTITY, "denied"]])
        assert first["enable_invocations"] == 1
        journey.check(ExecutionPhase.QUARANTINED, held=True)
        owner = journey.claim_state()
        wait_for_owned_deadline(utc(owner["readback_started_at"]) + timedelta(seconds=30))
        before = database_state(engine)
        expired = journey.run([])
        assert expired["stdout"] == "QUARANTINED_UNVERIFIED\n"
        assert expired["calls"] == [] and expired["enable_invocations"] == 0
        assert database_state(engine) == before
        assert journey.claim_state() == owner
        journey.check(ExecutionPhase.QUARANTINED, held=True)


def test_fresh_process_preintent_reclaim_keeps_global_three_read_budget(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        previous = None
        for attempt in (1, 2, 3):
            if previous is not None:
                wait_for_owned_deadline(previous["lease_until"])
            dead = journey.run([[IDENTITY, "valid"], [ENCRYPTION, "death"]])
            assert dead["exit_code"] == 47 and dead["enable_invocations"] == 0
            journey.check(ExecutionPhase.CLAIMED, held=True)
            claim = journey.claim_state()
            assert claim["generation"] == claim["read_attempts"] == attempt
            assert claim["write_intent_event_id"] is None and claim["readback_attempts"] == 0
            if previous is not None:
                assert claim["token_sha256"] != previous["token_sha256"], "old owner was reused"
            before = database_state(engine)
            active_lease = journey.run([])
            assert active_lease["stdout"] == "NO_ACTION\n" and active_lease["calls"] == []
            assert database_state(engine) == before
            previous = claim
        wait_for_owned_deadline(previous["lease_until"])
        exhausted = journey.run([])
        assert exhausted["calls"] == [] and exhausted["enable_invocations"] == 0
        current = journey.check(ExecutionPhase.NO_WRITE)
        assert [reason.value for reason in current.events[-1].content.blocking_reasons] == [
            "READ_BUDGET_EXHAUSTED"
        ]
        assert journey.claim_state() == previous


def test_fresh_process_quarantine_retains_target_and_global_admission_capacity(
    offline_process_runtime, process_database, monkeypatch, tmp_path
):
    engine, child_url = process_database
    with signed_process_journey(
        offline_process_runtime, engine, child_url, monkeypatch, tmp_path
    ) as journey:
        first = journey.run(false_read() + [[ENABLE, "death"]])
        assert first["exit_code"] == 47 and first["enable_invocations"] == 1
        recovered = journey.run(true_read())
        assert recovered["enable_invocations"] == 0
        journey.check(ExecutionPhase.QUARANTINED, held=True)
        conflict = journey.additional_grant(journey.source, expected_status=409)
        assert conflict.json()["detail"]["code"] == "remediation_execution_target_reserved"
        assert ADMISSION_CAPACITY == 32
        for number in range(ADMISSION_CAPACITY - 1):
            account = f"{100000000000 + number:012d}"
            before_fixture = database_state(engine)
            source = source_for_account(engine, account)
            journey.evidence_fixture(before_fixture, account=account)
            journey.additional_grant(source)
        before_fixture = database_state(engine)
        source = source_for_account(engine, "999999999999")
        journey.evidence_fixture(before_fixture, account="999999999999")
        denied = journey.additional_grant(source, expected_status=503)
        assert denied.json()["detail"]["code"] == "remediation_execution_capacity"
        assert (
            sum(
                row.execution_id is not None
                for row in database_state(engine)["remediation_target_reservations"]
            )
            == ADMISSION_CAPACITY
        )
        journey.check(ExecutionPhase.QUARANTINED, held=True)
