"""Linux browser adapter: no Docker access, only fixed parent commands and read-only replies."""

import json
import os
import sys
from pathlib import Path

from tests.dashboard_integrated_bootstrap import require_test_environment
from tests.dashboard_integrated_guardian import OwnedServer, reply_wire
from tests.dashboard_integrated_mailbox import proof_present, receive
from tests.dashboard_integrated_protocol import (
    MAX_CONTROL_BYTES,
    ControlKind,
    ControlReply,
    parse_control,
)
from tests.dashboard_integrated_scenarios import reader_scenario


def main():
    instance, server, primary = None, None, None
    try:
        instance = os.environ["DASHBOARD_INTEGRATED_INSTANCE"]
        require_test_environment(instance)
        scenario = reader_scenario(os.environ.get("DASHBOARD_INTEGRATED_SCENARIO", "verified"))
        if os.environ.get("DASHBOARD_INTEGRATED_EXTERNAL") != "1" or os.name != "posix":
            raise ValueError("Container proxy requires explicit isolated mode")
        directory = Path("/integrated-replies")
        if not os.statvfs(directory).f_flag & os.ST_RDONLY or os.getuid() == 0:
            raise ValueError("Container reply mount must be read-only and nonroot")
        env = dict(os.environ)
        for name in tuple(env):
            if name.upper().startswith(("DOCKER_", "DASHBOARD_INTEGRATED_EXTERNAL")):
                env.pop(name)
        if scenario.name == "cross-issuer":
            from tests.dashboard_integrated_authority_restart import RestartableAuthorityServer

            server = RestartableAuthorityServer(env)
        else:
            server = OwnedServer(env)
        server.wait(b"INTEGRATED_SERVER_READY", 30)
        print("INTEGRATED_FIXTURE_READY", flush=True)
        restarted_message = None
        while raw := sys.stdin.buffer.readline(MAX_CONTROL_BYTES + 1):
            message = parse_control(raw, expected_instance=instance)
            print(
                "INTEGRATED_PARENT_CONTROL=" + json.dumps(json.loads(raw), separators=(",", ":")),
                flush=True,
            )
            if message.kind is ControlKind.RELEASE_READER:
                receive(directory, message, permit=True, timeout=10)
                server.send(raw)
                server.wait(b"INTEGRATED_READER_RELEASED=" + str(message.request_id).encode(), 6)
                print(
                    reply_wire(ControlReply(message, "READER_RELEASED")).replace(
                        "INTEGRATED_REPLY=", "INTEGRATED_PARENT_REPLY=", 1
                    ),
                    flush=True,
                )
            elif message.kind is ControlKind.RESTART_AUTHORITY:
                if scenario.name != "cross-issuer":
                    raise ValueError("Authority restart is unavailable for this fixture")
                if restarted_message is None:
                    receive(directory, message, permit=True, timeout=10)
                    server.restart(message)
                    restarted_message = message
                    print(
                        reply_wire(ControlReply(message, "AUTHORITY_RESTARTED")).replace(
                            "INTEGRATED_REPLY=", "INTEGRATED_PARENT_REPLY=", 1
                        ),
                        flush=True,
                    )
                elif restarted_message != message:
                    raise ValueError("Authority restart replay conflict")
            reply = receive(directory, message)
            if message.kind is ControlKind.STOP:
                # Closing coordination is never itself evidence of completed persistence.
                if proof_present(directory, message):
                    print("INTEGRATED_PERSISTENCE_PROOF=" + scenario.outcome, flush=True)
                break
            print(reply_wire(reply), flush=True)
        else:
            raise ValueError("Container fixture lost its owning control channel")
    except BaseException as error:
        primary = error
    finally:
        if server is not None:
            try:
                server.close(instance)
            except Exception as error:
                if primary is None:
                    primary = error
        if primary is None:
            print("INTEGRATED_FIXTURE_CLEANED", flush=True)
    if primary is not None:
        print("Integrated container proxy failed; no success claimed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
