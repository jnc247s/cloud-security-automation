"""Read-only container reply mount. Parent writes only bounded owner/key-bound metadata.

No database URL, credential, shell argument or worker report belongs in this directory. A
permit is not a result: reader completion is separately acknowledged over the private pipe.
"""

import json
import os
import tempfile
import time
from pathlib import Path

from tests.dashboard_integrated_guardian import reply_wire, wire
from tests.dashboard_integrated_protocol import (
    MAX_CONTROL_BYTES,
    ControlKind,
    ControlProtocolError,
    ControlReply,
    parse_control,
)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value


def parse_reply(raw, expected):
    try:
        if type(raw) is not bytes or not raw or len(raw) > MAX_CONTROL_BYTES:
            raise ValueError
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        if type(value) is not dict or value.pop("effects_canceled", None) is not False:
            raise ValueError
        state = value.pop("state", None)
        states = {
            ControlKind.RUN_WORKER: {
                "WORKER_ACKNOWLEDGED",
                "WORKER_QUARANTINED",
                "WORKER_NO_WRITE",
            },
            ControlKind.RELEASE_READER: {"READER_RELEASED"},
            ControlKind.RESTART_AUTHORITY: {"AUTHORITY_RESTARTED"},
            ControlKind.COLLECT_STALE: {"STALE_OBSERVATION_PERSISTED"},
            ControlKind.CHANGE_GOVERNANCE: {"GOVERNANCE_CHANGED"},
            ControlKind.STOP: {"CLOSED"},
        }
        message = parse_control(
            json.dumps(value).encode(), expected_instance=str(expected.instance_id)
        )
        if message != expected or type(state) is not str or state not in states[expected.kind]:
            raise ValueError
        return ControlReply(message, state)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ControlProtocolError("Invalid integrated parent reply") from None


def payload(reply):
    return reply_wire(reply).removeprefix("INTEGRATED_REPLY=").encode()


def _path(directory, message, permit, proof=False):
    if (
        type(permit) is not bool
        or type(proof) is not bool
        or (permit and proof)
        or directory.is_symlink()
        or not directory.is_dir()
    ):
        raise ControlProtocolError("Invalid integrated reply directory")
    if proof and message.kind is not ControlKind.STOP:
        raise ControlProtocolError("Only stopped coordination may carry independent storage proof")
    prefix = "proof-" if proof else "permit-" if permit else "reply-"
    target = directory / (prefix + str(message.request_id) + ".json")
    if target.is_symlink() or target.parent.resolve() != directory.resolve():
        raise ControlProtocolError("Invalid integrated reply path")
    return target


def publish(directory: Path, reply, *, permit=False, proof=False):
    target = _path(directory, reply.message, permit, proof)
    if proof and reply.state != "CLOSED":
        raise ControlProtocolError("Invalid integrated storage proof settlement")
    data = (
        wire(
            str(reply.message.instance_id),
            reply.message.kind.value,
            reply.message.request_id,
            reply.message.target_id,
        )
        if permit
        else payload(reply)
    )
    if len(data) > MAX_CONTROL_BYTES:
        raise ControlProtocolError("Oversized integrated reply")
    temporary = None
    try:
        # Publish complete bytes atomically and exclusively, never a half-written result.
        with tempfile.NamedTemporaryFile(dir=directory, prefix="pending-", delete=False) as output:
            temporary = Path(output.name)
            output.write(data)
        try:
            os.link(temporary, target)
        except FileExistsError:
            with target.open("rb") as existing:
                if existing.read(MAX_CONTROL_BYTES + 1) != data:
                    raise ControlProtocolError("Integrated reply conflict") from None
    finally:
        if temporary is not None:
            temporary.unlink()


def receive(directory: Path, message, *, permit=False, timeout=60):
    target, deadline = _path(directory, message, permit), time.monotonic() + timeout
    while time.monotonic() < deadline:
        if target.is_symlink():
            raise ControlProtocolError("Invalid integrated reply path")
        if target.is_file():
            with target.open("rb") as source:
                raw = source.read(MAX_CONTROL_BYTES + 1)
            if permit:
                if (
                    message.kind not in {ControlKind.RELEASE_READER, ControlKind.RESTART_AUTHORITY}
                    or parse_control(raw, expected_instance=str(message.instance_id)) != message
                ):
                    raise ControlProtocolError("Invalid integrated reader permit")
                return
            return parse_reply(raw, message)
        time.sleep(0.02)
    raise ControlProtocolError("Integrated reply deadline; effects remain unconfirmed")


def proof_present(directory: Path, message):
    target = _path(directory, message, False, True)
    if not target.exists():
        return False
    with target.open("rb") as source:
        parse_reply(source.read(MAX_CONTROL_BYTES + 1), message)
    return True
