"""Parent-only Linux-browser adapter, using the accepted browser network namespace pattern.

Worker isolation remains owned by OfflineProcessRuntime. Browser/API receive no Docker socket,
Docker endpoint, host credential mount, write role or generic command interface. The only bind
mount contains read-only, bounded control replies. Never log environment values or raw IPC.
"""

import json
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from uuid import uuid4

from tests.dashboard_integrated_bootstrap import ISSUER, MARKER, ROOT
from tests.dashboard_integrated_guardian import wire
from tests.dashboard_integrated_mailbox import parse_reply, publish
from tests.dashboard_integrated_protocol import (
    MAX_CONTROL_BYTES,
    ControlKind,
    ControlReply,
    parse_control,
)
from tests.dashboard_integrated_scenarios import reader_scenario

BROWSER_LABEL = "cloudsec.integrated-browser"


def close_for_teardown(directory, reply, prove):
    if reply.message.kind is not ControlKind.STOP or reply.state != "CLOSED":
        raise ValueError("Invalid integrated teardown")
    try:
        prove()
    except Exception:
        # Let the browser report its original assertion. The parent still fails acceptance.
        proven = False
    else:
        publish(directory, reply, proof=True)
        proven = True
    publish(directory, reply)
    return proven


def require_browser_identity(runtime, name, metadata, image):
    try:
        if (
            re.fullmatch(re.escape(runtime.owner) + r"-browser-[0-9a-f]{32}", name, re.ASCII)
            is None
            or metadata["Name"] != "/" + name
            or metadata["Config"]["Labels"].get(BROWSER_LABEL) != name
            or metadata["Image"] != image
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise RuntimeError("Integrated browser ownership/security mismatch") from None


def require_browser_owned(runtime, name, metadata, directory, image):
    """A narrow exact handle, never cleanup by label, prefix, port, image or wildcard alone."""
    try:
        require_browser_identity(runtime, name, metadata, image)
        runtime._assert_database_owned()
        database_id = runtime._docker(
            "container", "inspect", "--format", "{{.Id}}", runtime.database_name
        ).stdout.strip()
        if re.fullmatch(r"[0-9a-f]{64}", database_id, re.ASCII) is None:
            raise ValueError
        if (
            re.fullmatch(re.escape(runtime.owner) + r"-browser-[0-9a-f]{32}", name, re.ASCII)
            is None
            or metadata["Name"] != "/" + name
            or metadata["Config"]["Labels"].get(BROWSER_LABEL) != name
            or metadata["Image"] != image
            or metadata["Config"]["User"] != "pwuser"
            or metadata["HostConfig"]["NetworkMode"]
            not in {"container:" + runtime.database_name, "container:" + database_id}
            or metadata["HostConfig"]["Privileged"] is not False
            or metadata["HostConfig"]["CapDrop"] != ["ALL"]
            or metadata["HostConfig"]["CapAdd"] not in (None, [])
            or metadata["HostConfig"]["SecurityOpt"] != ["no-new-privileges"]
            or metadata["HostConfig"]["PortBindings"] not in (None, {})
            or len(metadata["Mounts"]) != 1
        ):
            raise ValueError
        mount = metadata["Mounts"][0]
        expected = str(directory.resolve()).replace("\\", "/")
        if (
            mount["Type"] != "bind"
            or mount["Destination"] != "/integrated-replies"
            or mount["Source"].replace("\\", "/") != expected
            or mount["RW"] is not False
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError, IndexError):
        raise RuntimeError("Integrated browser ownership/security mismatch") from None


def assert_browser_source(runtime, image, expected):
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image, re.ASCII) is None:
        raise ValueError("Invalid integrated browser image")
    from tests.worker_process_runtime import isolated_child_environment

    script = """
import hashlib,json,os,pathlib,subprocess,sys
expected=json.load(sys.stdin)
assert os.getuid()!=0
for name,digest in expected.items():
    p=pathlib.Path(name)
    assert not p.is_absolute() and '..' not in p.parts and not p.is_symlink()
    assert hashlib.sha256(p.read_bytes()).hexdigest()==digest
assert subprocess.check_output(['node','--version'],text=True).strip()=='v24.19.0'
assert subprocess.check_output(['pnpm','--version'],text=True).strip()=='11.19.0'
package=pathlib.Path('frontend/node_modules/@playwright/test/package.json')
assert json.loads(package.read_text())['version']=='1.63.0'
print('INTEGRATED_BROWSER_SOURCE_VERIFIED')
"""
    result = subprocess.run(
        [
            "docker",
            "--host",
            runtime.endpoint,
            "run",
            "--rm",
            "-i",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            image,
            "/opt/diagnostic-python/bin/python",
            "-c",
            script,
        ],
        cwd=ROOT,
        env=isolated_child_environment(),
        input=json.dumps(expected),
        text=True,
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0 or result.stdout.strip() != "INTEGRATED_BROWSER_SOURCE_VERIFIED":
        raise RuntimeError("Integrated browser source/tool proof failed")


def run_project(
    runtime, engine, child_url, source, *, image, project, expected, scenario="verified"
):
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.models.remediation_verification import RemediationVerification
    from tests.dashboard_integrated_coordinator import IntegratedCoordinator
    from tests.dashboard_integrated_proof import assert_integrated_receipt
    from tests.worker_http import database_state
    from tests.worker_process_runtime import cleanup_preserving_primary, isolated_child_environment

    if project not in {"chromium", "firefox"}:
        raise ValueError("Unknown pinned browser project")
    selected = reader_scenario(scenario)
    runtime._assert_database_owned()
    assert_browser_source(runtime, image, expected)
    instance, name = str(uuid4()), runtime.owner + "-browser-" + uuid4().hex
    schema = child_url.query["options"].removeprefix("-csearch_path=")
    if schema not in runtime.schemas or child_url != runtime.database_url(
        child=True, schema=schema
    ):
        raise ValueError("Unowned integrated browser source")
    with engine.begin() as connection:
        connection.exec_driver_sql(f"COMMENT ON SCHEMA {schema} IS '{MARKER}{instance}'")
    with tempfile.TemporaryDirectory(
        prefix="sprint8-browser-replies-", dir=ROOT / ".tmp"
    ) as temporary:
        directory = Path(temporary)
        commands, gates, invalid = queue.Queue(maxsize=8), queue.Queue(maxsize=8), threading.Event()
        before_reader, process, reader, primary, reserved = None, None, None, None, False

        def release(scan_id):
            with Session(engine) as session:
                request = session.execute(
                    select(RemediationVerification).where(
                        RemediationVerification.scan_id == scan_id
                    )
                ).scalar_one()
                message = parse_control(
                    wire(
                        instance, "RELEASE_READER", request.idempotency_key, request.verification_id
                    ),
                    expected_instance=instance,
                )
            publish(directory, ControlReply(message, "IN_FLIGHT"), permit=True)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if invalid.is_set() or process.poll() is not None:
                    raise RuntimeError("Integrated browser gate transport stopped")
                try:
                    parse_reply(gates.get(timeout=0.05), message)
                    return
                except queue.Empty:
                    pass
            raise RuntimeError("Integrated browser gate acknowledgment deadline")

        def restart_authority(message):
            if selected.name != "cross-issuer":
                raise ValueError("Authority restart is unavailable for this fixture")
            publish(directory, ControlReply(message, "IN_FLIGHT"), permit=True)
            # Exact old child shutdown and new child startup use their unchanged 15s/30s bounds.
            deadline = time.monotonic() + 50
            while time.monotonic() < deadline:
                if invalid.is_set() or process.poll() is not None:
                    raise RuntimeError("Integrated authority gate transport stopped")
                try:
                    parse_reply(gates.get(timeout=0.05), message)
                    return
                except queue.Empty:
                    pass
            raise RuntimeError("Integrated authority gate acknowledgment deadline")

        parent = IntegratedCoordinator(
            runtime,
            engine,
            child_url,
            source,
            instance=instance,
            issuer=ISSUER,
            release_reader=release,
            scenario=selected.name,
            restart_authority=restart_authority if selected.name == "cross-issuer" else None,
        )
        # Sharing only the owned PG namespace matches the accepted local browser adapter.
        # Installed workers remain separately launched on the runtime's internal-only network.
        database = runtime.database_url(child=True, schema=schema).set(host="127.0.0.1")
        public = database.set(query={})
        env = isolated_child_environment(
            {
                "APP_ENV": "test",
                "AUTH_MODE": "development",
                "DATABASE_URL": database.render_as_string(hide_password=False),
                "TEST_DATABASE_URL": public.render_as_string(hide_password=False),
                "DASHBOARD_ENABLED": "false",
                "DASHBOARD_REMEDIATION_ENABLED": "false",
                "REMEDIATION_ADMISSION_ENABLED": "false",
                "REMEDIATION_VERIFICATION_ENABLED": "false",
                "DASHBOARD_BROWSER_TEST": "1",
                "DASHBOARD_INTEGRATED_EXTERNAL": "1",
                "DASHBOARD_INTEGRATED_INSTANCE": instance,
                "DASHBOARD_INTEGRATED_SOURCE": source.model_dump_json(),
                "DASHBOARD_INTEGRATED_SCENARIO": selected.name,
                "PYTHON_EXECUTABLE": "/opt/diagnostic-python/bin/python",
                "PYTHONUNBUFFERED": "1",
                "PYTHONPATH": "/app",
                "PYTHONIOENCODING": "utf-8",
                "AWS_EC2_METADATA_DISABLED": "true",
                "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent/no-credentials",
                "AWS_CONFIG_FILE": "/nonexistent/no-config",
            }
        )
        passed_names = (
            "APP_ENV",
            "AUTH_MODE",
            "DATABASE_URL",
            "TEST_DATABASE_URL",
            "DASHBOARD_ENABLED",
            "DASHBOARD_REMEDIATION_ENABLED",
            "REMEDIATION_ADMISSION_ENABLED",
            "REMEDIATION_VERIFICATION_ENABLED",
            "DASHBOARD_BROWSER_TEST",
            "DASHBOARD_INTEGRATED_EXTERNAL",
            "DASHBOARD_INTEGRATED_INSTANCE",
            "DASHBOARD_INTEGRATED_SOURCE",
            "DASHBOARD_INTEGRATED_SCENARIO",
            "PYTHON_EXECUTABLE",
            "PYTHONUNBUFFERED",
            "PYTHONPATH",
            "PYTHONIOENCODING",
            "AWS_EC2_METADATA_DISABLED",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONFIG_FILE",
        )
        command = [
            "docker",
            "--host",
            runtime.endpoint,
            "run",
            "--name",
            name,
            "--label",
            BROWSER_LABEL + "=" + name,
            "--network",
            "container:" + runtime.database_name,
            "--init",
            "--shm-size",
            "1g",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--mount",
            "type=bind,source=" + str(directory.resolve()) + ",target=/integrated-replies,readonly",
        ]
        for key in passed_names:
            command.extend(["--env", key])
        command.extend(
            [
                image,
                "pnpm",
                "--dir",
                "frontend",
                "test:browser",
                "e2e/remediation-integrated.spec.ts",
                "--project",
                project,
                "--max-failures=1",
                "--grep",
                "scenario-" + selected.name,
            ]
        )

        def drain():
            for raw in iter(process.stdout.readline, b""):
                # Consume frames before logging; never echo private IPC or worker reports.
                prefix = next(
                    (
                        p
                        for p in (b"INTEGRATED_PARENT_CONTROL=", b"INTEGRATED_PARENT_REPLY=")
                        if raw.startswith(p)
                    ),
                    None,
                )
                if prefix is not None:
                    if len(raw) > MAX_CONTROL_BYTES:
                        invalid.set()
                        continue
                    try:
                        (commands if prefix == b"INTEGRATED_PARENT_CONTROL=" else gates).put_nowait(
                            raw[len(prefix) :]
                        )
                    except queue.Full:
                        invalid.set()
                else:
                    sys.stdout.write(raw.decode("utf-8", errors="replace"))
                    sys.stdout.flush()

        try:
            if runtime._docker("container", "inspect", name, check=False).returncode == 0:
                raise RuntimeError("Refusing existing integrated browser")
            reserved = (
                True  # Creation can succeed even if the subsequent transport response is lost.
            )
            process = subprocess.Popen(
                command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            reader = threading.Thread(target=drain, daemon=True)
            reader.start()
            deadline = time.monotonic() + 90
            metadata = None
            while time.monotonic() < deadline:
                inspected = runtime._docker("container", "inspect", name, check=False)
                if inspected.returncode == 0:
                    metadata = json.loads(inspected.stdout)[0]
                    break
                if process.poll() is not None:
                    raise RuntimeError("Integrated browser did not start")
                time.sleep(0.05)
            require_browser_owned(runtime, name, metadata, directory, image)
            stopped = proven = False
            while time.monotonic() < deadline:
                if invalid.is_set():
                    raise RuntimeError("Integrated browser control frame rejected")
                try:
                    raw = commands.get(timeout=0.05)
                except queue.Empty:
                    if process.poll() is not None:
                        break
                    continue
                message = parse_control(raw, expected_instance=instance)
                reply = parent.handle(raw)
                if message.kind is ControlKind.RUN_WORKER and before_reader is None:
                    before_reader = database_state(engine)
                if message.kind is ControlKind.STOP:
                    proven = close_for_teardown(
                        directory,
                        reply,
                        lambda saved=before_reader: assert_integrated_receipt(
                            parent, saved, scenario=selected.name
                        ),
                    )
                    stopped = True
                else:
                    publish(directory, reply)
            if process.wait(timeout=15) != 0 or not stopped or not proven or invalid.is_set():
                raise RuntimeError("Integrated browser acceptance failed at " + parent.last_stage)
            reader.join(timeout=2)
            if reader.is_alive():
                raise RuntimeError("Integrated browser output did not close")
            print(
                "INTEGRATED_CONTAINER_PROOF="
                + project
                + ":"
                + selected.name
                + ":"
                + selected.outcome,
                flush=True,
            )
        except BaseException as error:
            primary = error
            raise
        finally:

            def cleanup():
                if reserved:
                    inspected = runtime._docker("container", "inspect", name, check=False)
                    if inspected.returncode == 0:
                        require_browser_identity(
                            runtime, name, json.loads(inspected.stdout)[0], image
                        )
                        runtime._docker("container", "rm", "--force", name)
                if process is not None:
                    process.wait(timeout=15)
                if reader is not None:
                    reader.join(timeout=2)
                    if reader.is_alive():
                        raise RuntimeError("Integrated browser output cleanup failed")

            cleanup_preserving_primary(cleanup, primary)
