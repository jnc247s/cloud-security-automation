"""Owning native test parent. Never imported by the API, browser bundle or worker image.

Only this process owns Docker. Its child is an unprivileged API/managed reader, controlled over
private pipes. Work messages name durable IDs, never arbitrary commands, URLs or credentials.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
from uuid import uuid4

from tests.dashboard_integrated_bootstrap import (
    ISSUER,
    MARKER,
    ROOT,
    configure,
    require_test_environment,
)
from tests.dashboard_integrated_protocol import MAX_CONTROL_BYTES, ControlKind, parse_control
from tests.dashboard_integrated_scenarios import reader_scenario


def wire(instance, command, key, target=None):
    value = {
        "schema_version": "1.0.0",
        "instance_id": instance,
        "request_id": str(key),
        "command": command,
    }
    if command != "STOP":
        value[
            {
                "RUN_WORKER": "execution_id",
                "RELEASE_READER": "verification_id",
                "RESTART_AUTHORITY": "proposal_id",
                "COLLECT_STALE": "proposal_id",
                "CHANGE_GOVERNANCE": "proposal_id",
            }[command]
        ] = str(target)
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def reply_wire(reply):
    value = json.loads(
        wire(
            str(reply.message.instance_id),
            reply.message.kind.value,
            reply.message.request_id,
            reply.message.target_id,
        )
    )
    value.update(state=reply.state, effects_canceled=reply.effects_canceled)
    return "INTEGRATED_REPLY=" + json.dumps(value, separators=(",", ":"))


class OwnedServer:
    """Track only the exact returned child, with bounded metadata and redacted diagnostics."""

    def __init__(self, env):
        self.child = subprocess.Popen(
            [sys.executable, "-m", "tests.dashboard_integrated_server"],
            cwd=ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        self.events, self.invalid = queue.Queue(maxsize=8), threading.Event()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        while raw := self.child.stdout.readline(MAX_CONTROL_BYTES + 1):
            if len(raw) > MAX_CONTROL_BYTES:
                self.invalid.set()
                return
            line = raw.rstrip(b"\r\n")
            # Never forward an arbitrary child's diagnostic line to logs/browser.
            if line == b"INTEGRATED_SERVER_READY" or line.startswith(
                b"INTEGRATED_READER_RELEASED="
            ):
                try:
                    self.events.put_nowait(line)
                except queue.Full:
                    self.invalid.set()
                    return

    def wait(self, expected, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.invalid.is_set() or self.child.poll() is not None:
                raise RuntimeError("Owned integrated server stopped")
            try:
                if self.events.get(timeout=0.05) != expected:
                    raise ValueError("Owned integrated server message mismatch")
                return
            except queue.Empty:
                pass
        raise RuntimeError("Owned integrated server response deadline")

    def send(self, raw):
        if (
            type(raw) is not bytes
            or not 0 < len(raw) <= MAX_CONTROL_BYTES
            or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1
        ):
            raise ValueError("Owned integrated server frame rejected")
        if self.child.poll() is not None:
            raise RuntimeError("Owned integrated server is unavailable")
        self.child.stdin.write(raw)
        self.child.stdin.flush()

    def close(self, instance):
        try:
            if self.child.poll() is None:
                self.send(wire(instance, "STOP", uuid4()))
                self.child.stdin.close()
            if self.child.wait(timeout=15) != 0:
                raise RuntimeError("Owned integrated server failed")
            self.thread.join(timeout=2)
            if self.thread.is_alive() or self.invalid.is_set():
                raise RuntimeError("Owned integrated server pipe cleanup failed")
        finally:
            if self.child.poll() is None:
                self.child.terminate()  # Exact child only, never an existing port listener.
                try:
                    self.child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    self.child.wait(timeout=5)
            self.child.stdout.close()


def run(instance, scenario="verified"):
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.models.remediation_verification import RemediationVerification
    from tests.dashboard_integrated_coordinator import IntegratedCoordinator
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.dashboard_integrated_scenarios import build_source
    from tests.worker_http import database_state
    from tests.worker_process_runtime import (
        OfflineProcessRuntime,
        cleanup_preserving_primary,
        isolated_child_environment,
    )

    expected = reader_scenario(scenario)
    with OfflineProcessRuntime() as runtime, runtime.schema() as (engine, child_url):
        print("INTEGRATED_FIXTURE_STAGE=DATABASE_READY", flush=True)
        source = build_source(engine, expected.name)
        print("INTEGRATED_FIXTURE_STAGE=SOURCE_READY", flush=True)
        schema = child_url.query["options"].removeprefix("-csearch_path=")
        # Derived from the live handle's registered schema; no browser URL can select this DDL.
        assert schema in runtime.schemas
        with engine.begin() as connection:
            connection.exec_driver_sql(f"COMMENT ON SCHEMA {schema} IS '{MARKER}{instance}'")
        env = isolated_child_environment(
            {
                "DASHBOARD_BROWSER_TEST": "1",
                "DASHBOARD_INTEGRATED_INSTANCE": instance,
                "DASHBOARD_INTEGRATED_SOURCE": source.model_dump_json(),
                "DASHBOARD_INTEGRATED_SCENARIO": expected.name,
                "DATABASE_URL": engine.url.render_as_string(hide_password=False),
                "PYTHONUNBUFFERED": "1",
            }
        )
        for name in tuple(env):
            if name.upper().startswith("DOCKER_"):
                env.pop(name)
        if expected.name == "cross-issuer":
            from tests.dashboard_integrated_authority_restart import RestartableAuthorityServer

            server = RestartableAuthorityServer(env)
        else:
            server = OwnedServer(env)
        primary, before_reader, parent = None, None, None
        try:
            server.wait(b"INTEGRATED_SERVER_READY", 30)

            def release(scan_id):
                with Session(engine) as session:
                    request = session.execute(
                        select(RemediationVerification).where(
                            RemediationVerification.scan_id == scan_id
                        )
                    ).scalar_one()
                    raw = wire(
                        instance, "RELEASE_READER", request.idempotency_key, request.verification_id
                    )
                    key = request.idempotency_key
                server.send(raw)  # Session/transaction finished before IPC and provider I/O.
                server.wait(b"INTEGRATED_READER_RELEASED=" + str(key).encode(), 6)

            parent = IntegratedCoordinator(
                runtime,
                engine,
                child_url,
                source,
                instance=instance,
                issuer=ISSUER,
                release_reader=release,
                scenario=expected.name,
                restart_authority=server.restart if expected.name == "cross-issuer" else None,
            )
            print("INTEGRATED_FIXTURE_READY", flush=True)
            while raw := sys.stdin.buffer.readline(MAX_CONTROL_BYTES + 1):
                message = parse_control(raw, expected_instance=instance)
                reply = parent.handle(raw)
                if message.kind is ControlKind.RUN_WORKER and before_reader is None:
                    before_reader = database_state(engine)
                if message.kind is ControlKind.STOP:
                    break
                print(reply_wire(reply), flush=True)
            if before_reader is not None or expected.worker == "none":
                # Independent persistence proof; not a substitute for native UI assertions.
                assert_integrated_receipt(parent, before_reader, scenario=expected.name)
                print("INTEGRATED_PERSISTENCE_PROOF=" + expected.outcome, flush=True)
        except BaseException as error:
            primary = error
            if parent is not None:
                print("INTEGRATED_FIXTURE_STAGE=" + parent.last_stage, flush=True)
            raise
        finally:
            cleanup_preserving_primary(lambda: server.close(instance), primary)


def main():
    try:
        instance = os.environ["DASHBOARD_INTEGRATED_INSTANCE"]
        require_test_environment(instance)
        scenario = reader_scenario(os.environ.get("DASHBOARD_INTEGRATED_SCENARIO", "verified"))
        configure()
        run(instance, scenario.name)
        print("INTEGRATED_FIXTURE_CLEANED", flush=True)
        return 0
    except Exception:
        print("Integrated guardian failed; inspect owned test receipts", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
