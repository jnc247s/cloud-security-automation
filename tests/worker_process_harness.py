"""Mounted test-only transport observer. Not packaged, imported or enabled by production."""

from __future__ import annotations

import builtins
import hashlib
import importlib.util
import io
import json
import logging
import os
import platform
import runpy
import sys
import threading
import time
from collections import deque
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from urllib.parse import parse_qs
from urllib.request import ProxyHandler, build_opener
from xml.sax.saxutils import escape

import boto3
import botocore
import psycopg
import sqlalchemy
from botocore.awsrequest import AWSResponse
from botocore.client import BaseClient
from botocore.exceptions import ReadTimeoutError
from botocore.loaders import Loader
from sqlalchemy import event
from sqlalchemy.engine import Engine, make_url

import app
import app.config
from app.remediation.worker_aws import _WorkloadSession

ACCOUNT = "123456789012"
REGION = "us-east-1"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/security/remediation-worker"
IDENTITY = "GetCallerIdentity"
ENCRYPTION = "GetEbsEncryptionByDefault"
KEY = "GetEbsDefaultKmsKeyId"
ENABLE = "EnableEbsEncryptionByDefault"
METADATA_URL = "http://169.254.170.2/v2/credentials/offline-process"
SOURCE_PATHS = (
    "app/remediation/worker.py",
    "app/remediation/worker_config.py",
    "app/remediation/worker_driver.py",
    "app/remediation/worker_aws.py",
    "app/remediation/worker_contracts.py",
    "app/remediation/execution_contracts.py",
    "app/services/remediation_worker_service.py",
    "app/services/remediation_execution_service.py",
    "app/models/remediation_execution.py",
    "app/main.py",
    "app/api/routes/health.py",
    "app/services/scan_executor.py",
    "app/services/inventory_service.py",
    "app/database/session.py",
)


class Payload(io.BytesIO):
    def stream(self, **_kwargs):
        yield self.read()


def harness_log_level(application):
    return logging.DEBUG if application == "worker" else logging.CRITICAL


def post_entrypoint_diagnostics(application):
    """The dedicated worker's log-suppression contract is not the API logging contract."""
    if application != "worker":
        return
    for logger_name in ("botocore.credentials", "botocore.endpoint", "sqlalchemy.engine"):
        logging.getLogger(logger_name).error(
            "synthetic-sensitive-post-entrypoint-marker", exc_info=True
        )


def main():
    output, error_output = io.StringIO(), io.StringIO()
    original_stdout = sys.stdout
    proof = {
        "schema_version": 1,
        "exit_code": 73,
        "stdout": "",
        "stderr": "",
        "errors": [],
        "calls": [],
        "wire_actions": [],
        "lock_probes": [],
        "enable_invocations": 0,
        "intent_checks": 0,
        "source_hashes": {},
        "locations": {},
        "versions": {},
        "uid": os.getuid(),
        "engine_creations": 0,
        "application_settings_reads": 0,
        "host_file_reads": 0,
        "security": {},
        "api_checks": {},
    }

    def fail(code):
        proof["errors"].append(code)
        raise AssertionError("offline process harness guard failed")

    def emit():
        proof["stdout"] = output.getvalue()
        proof["stderr"] = error_output.getvalue()
        original_stdout.write(json.dumps(proof, sort_keys=True) + "\n")
        original_stdout.flush()

    try:
        scenario = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if (
            set(scenario)
            != {
                "argv",
                "responses",
                "metadata",
                "target",
                "source_hashes",
                "transport_guard",
                "application",
            }
            or scenario["transport_guard"] not in {"armed", "disarmed"}
            or scenario["application"] not in {"worker", "api"}
        ):
            fail("INVALID_SCENARIO")
        if set(scenario["source_hashes"]) != set(SOURCE_PATHS):
            fail("INCOMPLETE_SOURCE_MANIFEST")
        queue = deque(scenario["responses"])
        package = Path(app.__file__).resolve().parent
        if str(package).startswith("/harness"):
            fail("SHADOWED_APPLICATION")
        for relative, expected in scenario["source_hashes"].items():
            if not relative.startswith("app/") or ".." in Path(relative).parts:
                fail("INVALID_SOURCE_PATH")
            value = hashlib.sha256((package / relative[4:]).read_bytes()).hexdigest()
            proof["source_hashes"][relative] = value
            if value != expected:
                fail("INSTALLED_SOURCE_MISMATCH")
        proof["locations"] = {
            "app": str(package),
            "boto3": str(Path(boto3.__file__).resolve()),
            "botocore": str(Path(botocore.__file__).resolve()),
        }
        if any(value.startswith("/harness") for value in proof["locations"].values()):
            fail("SHADOWED_RUNTIME")
        proof["versions"] = {
            "python": platform.python_version(),
            "boto3": boto3.__version__,
            "botocore": botocore.__version__,
        }
        if proof["uid"] == 0:
            fail("ROOT_WORKER")
        status = dict(
            line.split(":", 1)
            for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines()
            if ":" in line
        )
        proof["security"] = {
            "no_new_privileges": int(status["NoNewPrivs"].strip()),
            "effective_capabilities": status["CapEff"].strip(),
        }
        if proof["security"] != {
            "no_new_privileges": 1,
            "effective_capabilities": "0000000000000000",
        }:
            fail("UNSAFE_PROCESS_PRIVILEGES")
        real_open, real_io_open = builtins.open, io.open

        def guarded_open(original, filename, *args, **kwargs):
            if isinstance(filename, (str, bytes, os.PathLike)):
                candidate = Path(os.fsdecode(filename))
                if ".aws" in candidate.parts or candidate.name == ".env":
                    proof["host_file_reads"] += 1
                    fail("HOST_CREDENTIAL_OR_DOTENV_READ")
            return original(filename, *args, **kwargs)

        builtins.open = lambda filename, *args, **kwargs: guarded_open(
            real_open, filename, *args, **kwargs
        )
        io.open = lambda filename, *args, **kwargs: guarded_open(
            real_io_open, filename, *args, **kwargs
        )

        def forbidden_settings(*_args, **_kwargs):
            proof["application_settings_reads"] += 1
            fail("APPLICATION_OR_SCANNER_SETTINGS")

        real_settings = app.config.get_settings

        def api_settings():
            proof["application_settings_reads"] += 1
            return real_settings()

        app.config.get_settings = (
            forbidden_settings if scenario["application"] == "worker" else api_settings
        )
        real_engine = sqlalchemy.create_engine

        def create_engine(url, *args, **kwargs):
            proof["engine_creations"] += 1
            expected = os.environ.get("REMEDIATION_WORKER_DATABASE_URL")
            if expected is None or make_url(url) != make_url(expected):
                fail("UNPLANNED_ENGINE_TARGET")
            configured = make_url(url)
            if (
                proof["engine_creations"] != 1
                or configured.get_backend_name() != "postgresql"
                or configured.host != "pg"
                or configured.port != 5432
                or configured.database != "cloudsec_test"
            ):
                fail("UNPLANNED_DATABASE_ENGINE")
            return real_engine(url, *args, **kwargs)

        sqlalchemy.create_engine = create_engine
        if "app.remediation.worker" in sys.modules:
            fail("PRELOADED_WORKER_ENTRYPOINT")
        transactions = set()

        def begin(connection):
            transactions.add(id(connection))

        def end(connection):
            transactions.discard(id(connection))

        for name, callback in (("begin", begin), ("commit", end), ("rollback", end)):
            event.listen(Engine, name, callback)

        def boundary(label, *, intent=False):
            if transactions:
                fail("WORKER_TRANSACTION_SPANS_IO")
            target = scenario["target"]
            url = make_url(os.environ["REMEDIATION_WORKER_DATABASE_URL"])
            if (
                url.get_backend_name() != "postgresql"
                or url.host != "pg"
                or url.port != 5432
                or url.database != "cloudsec_test"
            ):
                fail("NON_OWNED_PROBE_TARGET")
            # This independent native connection is outside the worker Engine event tracker.
            dsn = url.set(drivername="postgresql").render_as_string(hide_password=False)
            with psycopg.connect(dsn, connect_timeout=3) as probe:
                with probe.cursor() as cursor:
                    cursor.execute("SET LOCAL lock_timeout = '2s'")
                    cursor.execute("SET LOCAL statement_timeout = '3s'")
                    for sql, params in (
                        (
                            "SELECT guard_id FROM remediation_admission_guard "
                            "WHERE guard_id=1 FOR UPDATE NOWAIT",
                            (),
                        ),
                        (
                            "SELECT resource_id FROM resources "
                            "WHERE resource_id=%s::uuid FOR UPDATE NOWAIT",
                            (target["resource_id"],),
                        ),
                        (
                            "SELECT finding_id FROM findings "
                            "WHERE finding_id=%s::uuid FOR UPDATE NOWAIT",
                            (target["finding_id"],),
                        ),
                        (
                            "SELECT proposal_id FROM remediation_proposals "
                            "WHERE proposal_id=%s::uuid FOR UPDATE NOWAIT",
                            (target["proposal_id"],),
                        ),
                        (
                            "SELECT reservation_id FROM remediation_target_reservations "
                            "WHERE account_id=%s AND region=%s AND action_id=%s FOR UPDATE NOWAIT",
                            (ACCOUNT, REGION, "aws.ec2.enable-ebs-encryption-by-default"),
                        ),
                        (
                            "SELECT execution_id FROM remediation_worker_claims "
                            "WHERE execution_id=%s::uuid FOR UPDATE NOWAIT",
                            (target["execution_id"],),
                        ),
                    ):
                        cursor.execute(sql, params)
                        if cursor.fetchone() is None:
                            fail("MISSING_PROBE_COORDINATE")
                    if intent:
                        cursor.execute(
                            "SELECT e.content, e.event_sha256, a.actor_type, a.metadata "
                            "FROM remediation_execution_events e JOIN audit_events a "
                            "ON a.event_id=e.audit_event_id WHERE e.execution_id=%s::uuid "
                            "ORDER BY e.sequence DESC LIMIT 1",
                            (target["execution_id"],),
                        )
                        row = cursor.fetchone()
                        if (
                            row is None
                            or row[0]["kind"] != "WRITE_INTENT"
                            or row[0]["phase"] != "WRITE_INTENT"
                            or row[0]["actor"]
                            != {"service_id": "remediation-worker", "expected_role_arn": ROLE}
                            or row[2] != "service"
                            or row[3]["event_sha256"] != row[1]
                        ):
                            fail("UNCOMMITTED_OR_UNPAIRED_INTENT")
                        proof["intent_checks"] += 1
            if transactions:
                fail("PROBE_LEFT_WORKER_TRANSACTION")
            proof["lock_probes"].append(label)
            proof["calls"].append(label)
            # Real worker logging must suppress even exception-bearing dependency diagnostics.
            for logger_name in ("botocore.credentials", "botocore.endpoint", "sqlalchemy.engine"):
                logger = logging.getLogger(logger_name)
                logger.debug("synthetic-sensitive-debug-marker")
                logger.warning("synthetic-sensitive-warning-marker", exc_info=True)
                logger.error("synthetic-sensitive-error-marker", exc_info=True)

        real_init = _WorkloadSession.__init__
        real_create = _WorkloadSession.create_client
        real_close = BaseClient.close

        def session_init(session, *args, **kwargs):
            boundary("factory")
            return real_init(session, *args, **kwargs)

        def capture(model, params, **_kwargs):
            if params != {}:
                fail("CALLER_SELECTED_AWS_PARAMETERS")
            boundary("sdk:" + model.name)
            if model.name == ENABLE:
                proof["enable_invocations"] += 1
                if proof["enable_invocations"] > 1:
                    fail("REPEATED_ENABLE_INVOCATION")

        def create_client(session, name, **kwargs):
            if name not in {"sts", "ec2"}:
                fail("UNPLANNED_SDK_CLIENT")
            boundary("client:" + name)
            if (
                session.get_component("data_loader").search_paths != [Loader.BUILTIN_DATA_PATH]
                or session.get_config_variable("sts_regional_endpoints") != "regional"
                or session.get_config_variable("csm_enabled") is not False
            ):
                fail("UNTRUSTED_MODELS_OR_TELEMETRY")
            sdk = real_create(session, name, **kwargs)
            if (
                sdk.meta.region_name != REGION
                or sdk.meta.endpoint_url != f"https://{name}.{REGION}.amazonaws.com"
                or sdk.meta.config.retries != {"mode": "standard", "total_max_attempts": 1}
                or sdk.meta.config.connect_timeout != 2
                or sdk.meta.config.read_timeout != 5
                or sdk.meta.config.proxies != {}
            ):
                fail("UNBOUNDED_OR_REDIRECTED_CLIENT")
            sdk.meta.events.register("before-parameter-build.*.*", capture)
            return sdk

        def close(sdk):
            boundary("close:" + sdk.meta.service_model.service_name)
            return real_close(sdk)

        def forbidden(*_args, **_kwargs):
            fail("HOST_AWS_CONFIGURATION")

        def send(_transport, request, **_kwargs):
            if request.url == METADATA_URL:
                if request.method != "GET":
                    fail("UNPLANNED_METADATA_METHOD")
                boundary("metadata")
                if scenario["metadata"] == "unavailable":
                    return AWSResponse(
                        request.url, 500, {}, Payload(b"synthetic-sensitive-metadata")
                    )
                if scenario["metadata"] == "malformed":
                    return AWSResponse(request.url, 200, {}, Payload(b"synthetic-sensitive-json"))
                body = json.dumps(
                    {
                        "AccessKeyId": "offline-test-access-key",
                        "SecretAccessKey": "offline-test-secret-key",
                        "Token": "offline-test-session-token",
                        "Expiration": "2099-01-01T00:00:00Z",
                    }
                ).encode()
                return AWSResponse(request.url, 200, {}, Payload(body))
            if request.method != "POST" or request.url.rstrip("/") not in {
                f"https://sts.{REGION}.amazonaws.com",
                f"https://ec2.{REGION}.amazonaws.com",
            }:
                fail("UNEXPECTED_NETWORK_DESTINATION")
            body = request.body.decode() if isinstance(request.body, bytes) else request.body
            fields = parse_qs(body, strict_parsing=True)
            if set(fields) != {"Action", "Version"} or any(len(v) != 1 for v in fields.values()):
                fail("UNPLANNED_WIRE_PARAMETERS")
            action = fields["Action"][0]
            expected_service = "sts" if action == IDENTITY else "ec2"
            if request.url.rstrip("/") != f"https://{expected_service}.{REGION}.amazonaws.com":
                fail("WRONG_OPERATION_ENDPOINT")
            boundary("wire:" + action, intent=action == ENABLE)
            proof["wire_actions"].append(action)
            if not queue:
                fail("UNEXPECTED_TRANSPORT_ATTEMPT")
            expected, response = queue.popleft()
            if action != expected:
                fail("TRANSPORT_SEQUENCE_MISMATCH")
            if response == "death":
                proof["exit_code"] = 47
                emit()
                os._exit(47)
            if response == "timeout":
                raise ReadTimeoutError(endpoint_url=request.url)
            code = 200
            if response in {"503", "denied"}:
                code = 503 if response == "503" else 400
                error = "ServiceUnavailable" if code == 503 else "AccessDenied"
                xml = (
                    f"<Response><Errors><Error><Code>{error}</Code>"
                    "<Message>synthetic-sensitive-provider</Message></Error></Errors>"
                    "<RequestID>offline-error</RequestID></Response>"
                )
            elif response == "invalid-xml":
                xml = "<invalid-sensitive-receipt"
            elif action == IDENTITY:
                account = "999999999999" if response == "wrong-account" else ACCOUNT
                role = "wrong-role" if response == "wrong-role" else "remediation-worker"
                xml = f"<GetCallerIdentityResponse xmlns='https://sts.amazonaws.com/doc/2011-06-15/'><GetCallerIdentityResult><UserId>ROLEID:offline-process</UserId><Account>{account}</Account><Arn>arn:aws:sts::{account}:assumed-role/{role}/offline-process</Arn></GetCallerIdentityResult><ResponseMetadata><RequestId>offline-identity</RequestId></ResponseMetadata></GetCallerIdentityResponse>"
                if response == "missing-field":
                    xml = xml.replace("<UserId>ROLEID:offline-process</UserId>", "")
            else:
                field = (
                    (f"<kmsKeyId>{escape(response)}</kmsKeyId>" if response is not None else "")
                    if action == KEY
                    else ""
                    if response == "missing-field"
                    else f"<ebsEncryptionByDefault>{str(response).lower()}</ebsEncryptionByDefault>"
                )
                xml = f"<{action}Response xmlns='http://ec2.amazonaws.com/doc/2016-11-15/'><requestId>offline-process-write</requestId>{field}</{action}Response>"
            return AWSResponse(
                request.url, code, {"content-type": "text/xml"}, Payload(xml.encode())
            )

        _WorkloadSession.__init__ = session_init
        _WorkloadSession.create_client = create_client
        BaseClient.close = close
        botocore.httpsession.URLLib3Session.send = send
        botocore.configloader.load_config = forbidden
        botocore.configloader.raw_config_parse = forbidden
        if scenario["transport_guard"] == "disarmed":
            # Negative guard proof must never restore the real network transport.
            botocore.httpsession.URLLib3Session.send = forbidden
        if botocore.httpsession.URLLib3Session.send is not send:
            fail("UNARMED_TRANSPORT")

        def api_startup():
            import uvicorn

            from app.remediation.worker_aws import EbsDefaultWriter
            from app.remediation.worker_driver import RemediationWorker

            def no_worker(*_args, **_kwargs):
                fail("API_STARTED_REMEDIATION_WORKER")

            def no_writer(*_args, **_kwargs):
                fail("API_CONSTRUCTED_WRITE_IDENTITY")

            # These prohibitions run before importing the real packaged API module.
            RemediationWorker.__init__ = no_worker
            EbsDefaultWriter.from_ecs = classmethod(no_writer)
            absent = all(not Path(path).exists() for path in ("/app/tests", "/app/scripts"))
            if not absent or importlib.util.find_spec("tests") is not None:
                fail("TEST_HELPERS_PACKAGED_IN_PRODUCTION")
            server = uvicorn.Server(
                uvicorn.Config(
                    "app.main:app",
                    host="127.0.0.1",
                    port=8000,
                    log_level="critical",
                    access_log=False,
                    lifespan="on",
                )
            )
            thread = threading.Thread(target=server.run, daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 15
                while not server.started:
                    if not thread.is_alive() or time.monotonic() >= deadline:
                        fail("PACKAGED_API_STARTUP_FAILED")
                    time.sleep(0.05)
                values = {}
                http = build_opener(ProxyHandler({}))
                for endpoint in ("health", "ready", "openapi.json"):
                    with http.open("http://127.0.0.1:8000/" + endpoint, timeout=3) as response:
                        if response.status != 200:
                            fail("PACKAGED_API_HTTP_BOUNDARY")
                        values[endpoint] = json.load(response)
                document = values["openapi.json"]
                bearer = all(
                    {"HTTPBearer": []} in operation.get("security", [])
                    for path, operations in document["paths"].items()
                    if path.startswith("/api/v1")
                    for operation in operations.values()
                )
                proof["api_checks"] = {
                    "health": values["health"]["status"],
                    "ready": values["ready"]["status"],
                    "database": values["ready"]["checks"]["database"],
                    "openapi": document["info"]["title"] == "Cloud Security Control Plane"
                    and "/api/v1/scans" in document["paths"],
                    "bearer_security": bearer,
                    "tests_absent": absent,
                }
                print("API_STARTUP_VERIFIED")
                proof["exit_code"] = 0
            finally:
                server.should_exit = True
                thread.join(timeout=5)
                if thread.is_alive():
                    fail("PACKAGED_API_DID_NOT_SHUT_DOWN")

        sys.argv = ["app.remediation.worker", *scenario["argv"]]
        with redirect_stdout(output), redirect_stderr(error_output):
            logging.basicConfig(
                level=harness_log_level(scenario["application"]), stream=error_output, force=True
            )
            try:
                if scenario["application"] == "api":
                    api_startup()
                else:
                    runpy.run_module("app.remediation.worker", run_name="__main__", alter_sys=True)
            except SystemExit as exited:
                if type(exited.code) is not int:
                    fail("INVALID_ENTRYPOINT_EXIT")
                proof["exit_code"] = exited.code
            post_entrypoint_diagnostics(scenario["application"])
            if queue:
                fail("UNUSED_EXPECTED_TRANSPORT")
            if transactions:
                fail("UNCLOSED_WORKER_TRANSACTION")
    except BaseException:
        if not proof["errors"]:
            proof["errors"].append("UNEXPECTED_HARNESS_FAILURE")
        proof["exit_code"] = 73
    emit()
    return proof["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
