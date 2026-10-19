"""Closed test-parent IPC; never an application route, execution grant or command broker.

Only an owning test parent may consume these messages. Before any effect, it must independently
bind the target to its live owned database/source and validate durable signed authority. Parsing
alone grants nothing. Keep this module stdlib-only so importing it cannot load app configuration.
"""

import json
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from uuid import UUID

MAX_CONTROL_BYTES = 2048


def classify_control_failure(error):
    """Closed diagnostic categories only; never echo arbitrary exception text or child output."""
    if type(error) is RuntimeError and len(error.args) == 1 and type(error.args[0]) is str:
        known = {
            "offline Docker operation unavailable": "RUNTIME_DOCKER_UNAVAILABLE",
            "offline Docker operation failed": "RUNTIME_DOCKER_FAILED",
            "owned process terminal state mismatch": "RUNTIME_TERMINAL",
            "unexpected container process stderr": "RUNTIME_STDERR",
            "missing or malformed offline process report": "RUNTIME_REPORT",
            "owned process report transports disagree": "RUNTIME_REPORT_CONFLICT",
            "owned process container identity unavailable": "RUNTIME_IDENTITY",
            "owned worker network is not internal": "RUNTIME_SECURITY",
            "owned worker security inspection failed": "RUNTIME_SECURITY",
            "owned image default startup metadata mismatch": "RUNTIME_IMAGE",
        }
        if error.args[0] in known:
            return known[error.args[0]]
        proofs = {
            "FIELDS",
            "SCHEMA_VERSION",
            "EXIT_STATUS",
            "EXECUTION_PROVENANCE",
            "TRANSPORT_FIELDS",
            "TRANSPORT_COUNTS",
            "EFFECT_COUNTERS",
            "ENGINE_COUNT",
            "HOST_FILE_GUARD",
            "CONFIG_READS",
            "WORKER_CONFIG",
            "API_CONFIG",
            "SECURITY",
            "INTENT_COUNTS",
            "PACKAGED_API_STARTUP_FAILED",
            "PACKAGED_API_HTTP_BOUNDARY",
            "PACKAGED_API_DID_NOT_SHUT_DOWN",
            "API_STARTED_REMEDIATION_WORKER",
            "API_CONSTRUCTED_WRITE_IDENTITY",
            "UNPLANNED_ENGINE_TARGET",
            "UNPLANNED_DATABASE_ENGINE",
            "HOST_CREDENTIAL_OR_DOTENV_READ",
            "TEST_HELPERS_PACKAGED_IN_PRODUCTION",
            "UNEXPECTED_HARNESS_FAILURE",
            "HARNESS_GUARD",
            "POST_ENTRYPOINT_DIAGNOSTIC",
            "CHILD_RUNTIME_WARNING",
            "CHILD_THREAD_EXCEPTION",
            "CHILD_DEPENDENCY_DEBUG",
            "UNEXPECTED_CHILD_STDERR",
        }
        for proof in proofs:
            if error.args[0] == "invalid offline process proof [" + proof + "]":
                return "RUNTIME_PROOF_" + proof
        if error.args[0] == "invalid offline process proof":
            return "RUNTIME_PROOF"
    return {
        AssertionError: "ASSERTION",
        FileNotFoundError: "MISSING_TEST_FILE",
        KeyError: "MISSING_FIELD",
        AttributeError: "ATTRIBUTE",
        TypeError: "TYPE",
        ValueError: "VALUE",
        RuntimeError: "RUNTIME",
    }.get(type(error), "ERROR")


class ControlProtocolError(ValueError):
    """Sanitized failure; never echo message bodies, connection strings or credentials."""


class ControlKind(StrEnum):
    RUN_WORKER = "RUN_WORKER"
    RELEASE_READER = "RELEASE_READER"
    RESTART_AUTHORITY = "RESTART_AUTHORITY"
    COLLECT_STALE = "COLLECT_STALE"
    CHANGE_GOVERNANCE = "CHANGE_GOVERNANCE"
    STOP = "STOP"


@dataclass(frozen=True)
class ControlMessage:
    instance_id: UUID
    # Work/release correlation must also match the durable upstream operation key.
    request_id: UUID
    kind: ControlKind
    target_id: UUID | None


@dataclass(frozen=True)
class ControlReply:
    message: ControlMessage
    state: str
    effects_canceled: bool = False


class ControlFence:
    """Bounded private coordination, not domain authority. Never lock across external work."""

    def __init__(self):
        self._lock = RLock()
        self._records: dict[UUID, ControlReply] = {}
        self._targets: set[tuple[ControlKind, UUID | None]] = set()
        self.closed = False

    def claim(self, message: ControlMessage) -> tuple[ControlReply, bool]:
        with self._lock:
            if self.closed:
                return ControlReply(message, "CLOSED"), False
            previous = self._records.get(message.request_id)
            if previous is not None:
                if previous.message != message:
                    raise ControlProtocolError("Integrated test control conflict")
                return previous, False
            target = (message.kind, message.target_id)
            if target in self._targets or len(self._records) >= 32:
                raise ControlProtocolError("Integrated test control unavailable")
            reply = ControlReply(message, "IN_FLIGHT")
            self._records[message.request_id] = reply
            self._targets.add(target)
            return reply, True

    def finish(self, message: ControlMessage, state: str) -> ControlReply:
        success = {
            ControlKind.RUN_WORKER: {
                "WORKER_ACKNOWLEDGED",
                "WORKER_QUARANTINED",
                "WORKER_NO_WRITE",
            },
            ControlKind.RELEASE_READER: {"READER_RELEASED"},
            ControlKind.RESTART_AUTHORITY: {"AUTHORITY_RESTARTED"},
            ControlKind.COLLECT_STALE: {"STALE_OBSERVATION_PERSISTED"},
            ControlKind.CHANGE_GOVERNANCE: {"GOVERNANCE_CHANGED"},
        }
        if message.kind not in success or state not in success[message.kind] | {
            "REJECTED",
            "UNCONFIRMED",
        }:
            raise ControlProtocolError("Invalid integrated test control settlement")
        with self._lock:
            previous = self._records.get(message.request_id)
            if previous is None or previous.message != message or previous.state != "IN_FLIGHT":
                raise ControlProtocolError("Integrated test control settlement conflict")
            reply = ControlReply(message, "CLOSED" if self.closed else state)
            self._records[message.request_id] = reply
            return reply

    def close(self, message: ControlMessage) -> ControlReply:
        if message.kind is not ControlKind.STOP or message.target_id is not None:
            raise ControlProtocolError("Invalid integrated test control close")
        with self._lock:
            self.closed = True
            return ControlReply(message, "CLOSED")


def _uuid4(value: object) -> UUID:
    if type(value) is not str:
        raise ValueError
    parsed = UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError
    return parsed


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _constant(_value: str):
    raise ValueError


def parse_control(raw: bytes, *, expected_instance: str) -> ControlMessage:
    """Validate one bounded UTF-8 JSON command from the private owning-parent channel."""
    try:
        owner = _uuid4(expected_instance)
        if type(raw) is not bytes or not raw or len(raw) > MAX_CONTROL_BYTES:
            raise ValueError
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
        if type(value) is not dict or value.get("schema_version") != "1.0.0":
            raise ValueError
        if type(value.get("command")) is not str:
            raise ValueError
        kind = ControlKind(value["command"])
        target_field = {
            ControlKind.RUN_WORKER: "execution_id",
            ControlKind.RELEASE_READER: "verification_id",
            ControlKind.RESTART_AUTHORITY: "proposal_id",
            ControlKind.COLLECT_STALE: "proposal_id",
            ControlKind.CHANGE_GOVERNANCE: "proposal_id",
            ControlKind.STOP: None,
        }[kind]
        fields = {"schema_version", "instance_id", "request_id", "command"}
        if target_field is not None:
            fields.add(target_field)
        if set(value) != fields or _uuid4(value["instance_id"]) != owner:
            raise ValueError
        return ControlMessage(
            instance_id=owner,
            request_id=_uuid4(value["request_id"]),
            kind=kind,
            target_id=_uuid4(value[target_field]) if target_field else None,
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ControlProtocolError("Invalid integrated test control message") from None
