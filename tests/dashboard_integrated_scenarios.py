"""Closed test-parent fact scenarios, never browser-selected policy or execution authority."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ReaderScenario:
    name: str
    outcome: str
    reason: str
    scan_status: str
    technical: str | None
    assessment: str
    finding: str
    response_loss: bool = False
    attempts: int = 1
    worker: str = "acknowledged"


def reader_scenario(name="verified"):
    choices = {
        "subject-replacement": ReaderScenario(
            "subject-replacement",
            "NO_EXECUTION",
            "SUBJECT_CHANGED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            response_loss=True,
            attempts=0,
            worker="none",
        ),
        "issuer-rejection": ReaderScenario(
            "issuer-rejection",
            "NO_EXECUTION",
            "ISSUER_REJECTED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            response_loss=True,
            attempts=0,
            worker="none",
        ),
        "cross-issuer": ReaderScenario(
            "cross-issuer",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
            response_loss=True,
        ),
        "verified": ReaderScenario(
            "verified", "VERIFIED", "POSTCONDITION_PASS", "COMPLETED", "PASS", "PASS", "RESOLVED"
        ),
        "verification-equal": ReaderScenario(
            "verification-equal",
            "INCONCLUSIVE",
            "OBSERVATION_NOT_LATER",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "verification-provenance": ReaderScenario(
            "verification-provenance",
            "INCONCLUSIVE",
            "PROVENANCE_UNAVAILABLE",
            "COMPLETED",
            None,
            "PASS",
            "RESOLVED",
        ),
        "feature-hints": ReaderScenario(
            "feature-hints",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "history-versions": ReaderScenario(
            "history-versions",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "reply-reference": ReaderScenario(
            "reply-reference",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "history-reference": ReaderScenario(
            "history-reference",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "revoked-after-ack": ReaderScenario(
            "revoked-after-ack",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "revoked-before-intent": ReaderScenario(
            "revoked-before-intent",
            "NO_VERIFICATION",
            "APPROVAL_REVOKED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            attempts=0,
            worker="revoked",
        ),
        "recovery-guards": ReaderScenario(
            "recovery-guards",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "capacity-session": ReaderScenario(
            "capacity-session",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "in-flight": ReaderScenario(
            "in-flight", "VERIFIED", "POSTCONDITION_PASS", "COMPLETED", "PASS", "PASS", "RESOLVED"
        ),
        "capacity-global": ReaderScenario(
            "capacity-global",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "uncertain-submit": ReaderScenario(
            "uncertain-submit",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
            True,
        ),
        "capability-loss": ReaderScenario(
            "capability-loss",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
            True,
        ),
        "expiry-session": ReaderScenario(
            "expiry-session",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
            True,
        ),
        "expiry-global": ReaderScenario(
            "expiry-global",
            "VERIFIED",
            "POSTCONDITION_PASS",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
            True,
        ),
        "proposal-expiry": ReaderScenario(
            "proposal-expiry",
            "NO_EXECUTION",
            "EXPIRED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            response_loss=True,
            attempts=0,
            worker="none",
        ),
        "idle-expiry": ReaderScenario(
            "idle-expiry",
            "NO_EXECUTION",
            "SESSION_IDLE_EXPIRED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            response_loss=True,
            attempts=0,
            worker="none",
        ),
        "token-expiry": ReaderScenario(
            "token-expiry",
            "NO_EXECUTION",
            "ACCESS_TOKEN_EXPIRED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            response_loss=True,
            attempts=0,
            worker="none",
        ),
        "execution-expiry": ReaderScenario(
            "execution-expiry",
            "NO_VERIFICATION",
            "EXECUTION_EXPIRED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            attempts=0,
            worker="expired",
        ),
        "not-verified": ReaderScenario(
            "not-verified",
            "NOT_VERIFIED",
            "POSTCONDITION_FAIL",
            "COMPLETED",
            "FAIL",
            "FAIL",
            "OPEN",
        ),
        "kms-changed": ReaderScenario(
            "kms-changed",
            "INCONCLUSIVE",
            "KMS_CONTEXT_CHANGED",
            "COMPLETED",
            "PASS",
            "PASS",
            "RESOLVED",
        ),
        "attempt-limit": ReaderScenario(
            "attempt-limit",
            "NOT_VERIFIED",
            "POSTCONDITION_FAIL",
            "COMPLETED",
            "FAIL",
            "FAIL",
            "OPEN",
            attempts=3,
        ),
        "partial": ReaderScenario(
            "partial", "INCONCLUSIVE", "SCAN_INCOMPLETE", "PARTIAL", None, "PASS", "OPEN"
        ),
        "quarantine": ReaderScenario(
            "quarantine",
            "NO_VERIFICATION",
            "QUARANTINED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            attempts=0,
            worker="quarantine",
        ),
        "late-ack": ReaderScenario(
            "late-ack",
            "NO_VERIFICATION",
            "QUARANTINED",
            "NO_SCAN",
            None,
            "FAIL",
            "OPEN",
            attempts=0,
            worker="late-ack",
        ),
    }
    from tests.dashboard_integrated_staleness import stale_case

    for stale_name in (
        "stale-newer-fail",
        "stale-newer-pass",
        "stale-newer-insufficient",
        "stale-equal-fail",
        "stale-equal-pass",
        "stale-equal-insufficient",
    ):
        case = stale_case(stale_name)
        choices[stale_name] = ReaderScenario(
            stale_name,
            "NO_EXECUTION",
            "STALE_TARGET",
            case.scan_status,
            None,
            case.assessment,
            case.finding,
            attempts=0,
            worker="none",
        )
    from tests.dashboard_integrated_governance import authority_case

    for authority_name in (
        "admission-stale",
        "governance-change",
        "governance-round-trip",
        "governance-exception",
    ):
        case = authority_case(authority_name)
        choices[authority_name] = ReaderScenario(
            authority_name,
            "NO_EXECUTION",
            case.blocker,
            "COMPLETED" if authority_name == "admission-stale" else "NO_SCAN",
            None,
            "FAIL",
            case.finding,
            attempts=0,
            worker="none",
        )
    if type(name) is not str or name not in choices:
        raise ValueError("Invalid integrated reader scenario")
    return choices[name]


def build_reader(name):
    # Deferred until explicit isolated application configuration, with only closed synthetic I/O.
    from collections import deque

    from tests.fakes import client_error
    from tests.verification_acceptance import regional_reader
    from tests.worker_http import REGION

    scenario = reader_scenario(name)
    if scenario.attempts == 0:
        raise ValueError("No managed reader for non-verifiable scenario")
    reader = regional_reader(
        enabled=scenario.name not in {"not-verified", "attempt-limit"},
        key="new-key" if scenario.name == "kms-changed" else None,
    )
    if scenario.name == "partial":
        reader._clients[("ec2", REGION)]._responses["get_ebs_default_kms_key_id"] = deque(
            [client_error("AccessDenied", "GetEbsDefaultKmsKeyId")]
        )
    return reader


def build_source(engine, name):
    scenario = reader_scenario(name)
    if scenario.worker == "expired":
        from tests.dashboard_integrated_execution_expiry import historical_execution_source

        return historical_execution_source(engine)
    from tests.verification_acceptance import full_scope_source

    return full_scope_source(engine)


def build_worker_script(name, key):
    from tests.worker_process_harness import ENABLE, IDENTITY
    from tests.worker_process_http import script_for

    scenario = reader_scenario(name)
    if scenario.worker == "none":
        raise ValueError("No installed worker for proposal-only scenario")
    if scenario.worker in {"expired", "revoked"}:
        return []  # No credential lookup, SDK read or write is permitted for these grants.
    values = script_for("acknowledged", key)
    if scenario.worker == "quarantine":
        return values[:3] + [[ENABLE, "timeout"], [IDENTITY, "denied"]]
    if scenario.worker == "late-ack":
        values[3] = [ENABLE, "late-ack"]
    return values
