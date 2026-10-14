"""Mounted reader-only installed API/SDK observer; never shipped in the production image."""

from __future__ import annotations

import base64
import builtins
import hashlib
import importlib.util
import io
import json
import logging
import os
import platform
import secrets
import socket
import sys
import threading
import time
import traceback
from collections import deque
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

import boto3
import botocore
import jwt
import psycopg
import uvicorn
from botocore.awsrequest import AWSResponse
from botocore.client import BaseClient
from botocore.httpsession import URLLib3Session
from botocore.stub import Stubber
from sqlalchemy.engine import make_url

import app

ACCOUNT = "123456789012"
REGION = "us-east-1"
READER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/security/offline-scanner-reader"
READ_OPERATIONS = {
    "get_caller_identity",
    "describe_instances",
    "describe_volumes",
    "describe_security_groups",
    "describe_vpcs",
    "describe_subnets",
    "describe_flow_logs",
    "get_ebs_encryption_by_default",
    "get_ebs_default_kms_key_id",
    "list_analyzers",
    "list_users",
    "list_groups",
    "list_roles",
    "list_policies",
    "get_account_summary",
    "list_buckets",
    "get_public_access_block",
    "list_trails",
}


class Payload(io.BytesIO):
    def stream(self, **_kwargs):
        yield self.read()


def decode(value):
    if isinstance(value, dict):
        if set(value) == {"$bytes"}:
            return base64.b64decode(value["$bytes"], validate=True)
        if set(value) == {"$datetime"}:
            return datetime.fromisoformat(value["$datetime"])
        return {key: decode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [decode(item) for item in value]
    return value


def main():
    original_stdout, output, errors = sys.stdout, io.StringIO(), io.StringIO()
    proof = {
        "schema_version": 1,
        "exit_code": 73,
        "errors": [],
        "stage": "input",
        "calls": [],
        "boundaries": [],
        "submissions": [],
        "metadata_requests": 0,
        "credential_methods": [],
        "credential_fingerprints": [],
        "writer_constructions": 0,
        "host_file_reads": 0,
        "source_hashes": {},
        "locations": {},
        "versions": {},
        "uid": os.getuid(),
        "security": {},
        "api_checks": {},
        "pending": None,
        "complete": None,
        "env_names": sorted(os.environ),
        "error_location": None,
        "reader_role_arn": None,
    }
    managed_sessions, gate = set(), threading.Event()

    def fail(code):
        proof["errors"].append(code)
        raise AssertionError("closed installed reader guard failed")

    def emit(code):
        proof["exit_code"] = code
        proof["stdout_bytes"] = len(output.getvalue().encode())
        proof["stderr_bytes"] = len(errors.getvalue().encode())
        original_stdout.write(json.dumps(proof, sort_keys=True) + "\n")
        original_stdout.flush()

    try:
        scenario = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if set(scenario) != {
            "mode",
            "execution_id",
            "verification_id",
            "operator",
            "reader",
            "jwks",
            "body",
            "idempotency_key",
            "source_hashes",
            "responses",
        } or scenario["mode"] not in {
            "observe",
            "resume",
            "crash",
            "crash-collection",
            "default-off",
        }:
            fail("INVALID_SCENARIO")
        UUID(scenario["execution_id"])
        UUID(scenario["idempotency_key"])
        package = Path(app.__file__).resolve().parent
        if str(package).startswith("/harness"):
            fail("SHADOWED_APPLICATION")
        for relative, expected in scenario["source_hashes"].items():
            if not relative.startswith("app/") or ".." in Path(relative).parts:
                fail("INVALID_SOURCE_PATH")
            actual = hashlib.sha256((package / relative[4:]).read_bytes()).hexdigest()
            proof["source_hashes"][relative] = actual
            if actual != expected:
                fail("INSTALLED_SOURCE_MISMATCH")
        proof["locations"] = {
            "app": str(package),
            "boto3": str(Path(boto3.__file__).resolve()),
            "botocore": str(Path(botocore.__file__).resolve()),
        }
        proof["versions"] = {
            "python": platform.python_version(),
            "boto3": boto3.__version__,
            "botocore": botocore.__version__,
        }
        status = dict(
            line.split(":", 1)
            for line in Path("/proc/self/status").read_text().splitlines()
            if ":" in line
        )
        proof["security"] = {
            "no_new_privileges": int(status["NoNewPrivs"].strip()),
            "effective_capabilities": status["CapEff"].strip(),
        }
        if proof["uid"] <= 0 or proof["security"] != {
            "no_new_privileges": 1,
            "effective_capabilities": "0000000000000000",
        }:
            fail("UNSAFE_PRIVILEGES")
        if any(name.startswith("REMEDIATION_WORKER_") for name in os.environ) or any(
            name in os.environ
            for name in (
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_PROFILE",
                "AWS_DEFAULT_PROFILE",
                "AWS_ROLE_ARN",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            )
        ):
            fail("SHARED_OR_STATIC_CREDENTIAL_SOURCE")
        if any(
            Path(path).exists() for path in ("/app/tests", "/app/scripts")
        ) or importlib.util.find_spec("tests"):
            fail("TEST_HELPERS_PACKAGED")
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
        real_connect = socket.socket.connect

        def closed_connect(sock, address):
            if not isinstance(address, tuple) or address[:2] != ("127.0.0.1", 8158):
                fail("UNPLANNED_SOCKET_TRANSPORT")
            return real_connect(sock, address)

        socket.socket.connect = closed_connect
        metadata_path = os.environ["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"]
        if not metadata_path.startswith("/v2/credentials/offline-reader-"):
            fail("WRITER_METADATA_REUSED")
        credential = {
            "AccessKeyId": "ASIA" + secrets.token_hex(8).upper(),
            "SecretAccessKey": secrets.token_urlsafe(30),
            "Token": secrets.token_urlsafe(24),
            "Expiration": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "RoleArn": READER_ROLE,
        }
        expected_url = "http://169.254.170.2" + metadata_path

        def metadata_send(_transport, request):
            if request.url != expected_url or request.method != "GET":
                fail("UNPLANNED_HTTP_TRANSPORT")
            boundary("metadata", proof["submissions"][-1])
            proof["metadata_requests"] += 1
            proof["reader_role_arn"] = credential["RoleArn"]
            return AWSResponse(request.url, 200, {}, Payload(json.dumps(credential).encode()))

        URLLib3Session.send = metadata_send
        queues = {}
        for service, methods in scenario["responses"].items():
            if service not in {
                "sts",
                "ec2",
                "s3",
                "s3control",
                "iam",
                "cloudtrail",
                "accessanalyzer",
            }:
                fail("UNPLANNED_SERVICE")
            for method, responses in methods.items():
                if method not in READ_OPERATIONS:
                    fail("WRITE_OPERATION_CONFIGURED")
                queues[(service, method)] = deque(decode(responses))
        real_make_call = BaseClient._make_api_call
        url = make_url(os.environ["DATABASE_URL"])
        if url.host != "pg" or url.port != 5432 or url.database != "cloudsec_test":
            fail("UNOWNED_DATABASE")
        dsn = url.set(drivername="postgresql").render_as_string(hide_password=False)

        def boundary(label, scan_id):
            if managed_sessions:
                fail("MANAGED_TRANSACTION_SPANS_IO")
            with (
                psycopg.connect(dsn, connect_timeout=3) as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute("SET LOCAL lock_timeout = '3s'")
                cursor.execute("SET LOCAL statement_timeout = '5s'")
                cursor.execute(
                    "SELECT guard_id FROM remediation_verification_guard "
                    "WHERE guard_id=1 FOR UPDATE"
                )
                if cursor.fetchone() != (1,):
                    fail("MISSING_VERIFICATION_GUARD")
                cursor.execute(
                    "SELECT status FROM scans WHERE scan_id=%s::uuid FOR UPDATE", (scan_id,)
                )
                if cursor.fetchone() != ("RUNNING",):
                    fail("INTENT_NOT_DURABLE_RUNNING")
                cursor.execute(
                    "SELECT v.verification_id, a.event_type, a.metadata "
                    "FROM remediation_verifications v "
                    "JOIN audit_events a ON a.event_id=v.audit_event_id WHERE v.scan_id=%s::uuid",
                    (scan_id,),
                )
                request = cursor.fetchone()
                if (
                    request is None
                    or request[1] != "REMEDIATION_VERIFICATION_REQUESTED"
                    or request[2]["actor"]["subject"] != "verification-operator"
                ):
                    fail("MISSING_ATTRIBUTED_INTENT")
                cursor.execute(
                    "SELECT count(*) FROM audit_events WHERE target_id=%s::uuid "
                    "AND event_type='SCAN_STARTED'",
                    (scan_id,),
                )
                if cursor.fetchone() != (1,):
                    fail("MISSING_START_AUDIT")
                cursor.execute(
                    "SELECT f.resource_id, f.finding_id FROM remediation_executions e "
                    "JOIN remediation_proposals p ON p.proposal_id=e.proposal_id "
                    "JOIN findings f ON f.finding_id=p.finding_id WHERE e.execution_id=%s::uuid",
                    (scenario["execution_id"],),
                )
                target = cursor.fetchone()
                if target is None:
                    fail("MISSING_ORIGINAL_TARGET")
                cursor.execute(
                    "SELECT resource_id FROM resources WHERE resource_id=%s FOR UPDATE",
                    (target[0],),
                )
                if cursor.fetchone() is None:
                    fail("MISSING_ORIGINAL_RESOURCE")
                cursor.execute(
                    "SELECT finding_id FROM findings WHERE finding_id=%s FOR UPDATE", (target[1],)
                )
                if cursor.fetchone() is None:
                    fail("MISSING_ORIGINAL_FINDING")
            proof["boundaries"].append(label)

        def read_call(client, operation, params):
            service = client.meta.service_model.service_name
            method = next(
                (
                    key
                    for key, name in client.meta.method_to_api_mapping.items()
                    if name == operation
                ),
                None,
            )
            if method not in READ_OPERATIONS or not queues.get((service, method)):
                fail("UNPLANNED_OR_WRITE_SDK_CALL")
            proof["stage"] = "sdk:" + service + ":" + operation
            boundary("sdk:" + service + ":" + operation, proof["submissions"][-1])
            credentials = client._request_signer._credentials
            if credentials is None or credentials.method != "container-role":
                fail("WRONG_CREDENTIAL_CHAIN")
            frozen = credentials.get_frozen_credentials()
            if (
                frozen.access_key != credential["AccessKeyId"]
                or frozen.secret_key != credential["SecretAccessKey"]
                or frozen.token != credential["Token"]
            ):
                fail("CREDENTIAL_SHARING")
            proof["credential_methods"].append(credentials.method)
            proof["credential_fingerprints"].append(
                hashlib.sha256(frozen.access_key.encode()).hexdigest()
            )
            response = queues[(service, method)].popleft()
            proof["calls"].append(service + ":" + operation)
            with Stubber(client) as stub:
                if set(response) == {"$error"}:
                    error = response["$error"]
                    stub.add_client_error(
                        method,
                        service_error_code=error["Code"],
                        service_message="synthetic reader denial",
                    )
                else:
                    stub.add_response(method, response)
                result = real_make_call(client, operation, params)
                stub.assert_no_pending_responses()
                if scenario["mode"] == "crash-collection" and service != "sts":
                    gate.set()
                    if not threading.Event().wait(30):
                        fail("CRASH_BOUNDARY_NOT_TERMINATED")
                return result

        BaseClient._make_api_call = read_call
        jwt.PyJWKClient.fetch_data = lambda _self: scenario["jwks"]
        proof["stage"] = "application-import"
        from app.remediation.worker_aws import EbsDefaultWriter
        from app.remediation.worker_driver import RemediationWorker

        def no_writer(*_args, **_kwargs):
            proof["writer_constructions"] += 1
            fail("WRITER_CONSTRUCTION")

        RemediationWorker.__init__ = no_writer
        EbsDefaultWriter.from_ecs = classmethod(no_writer)
        from app.config import get_settings
        from app.database.session import SessionLocal
        from app.main import create_app
        from app.services.scan_executor import InProcessScanExecutor

        @contextmanager
        def tracked_session():
            with SessionLocal() as session:
                managed_sessions.add(id(session))
                try:
                    yield session
                finally:
                    managed_sessions.remove(id(session))

        class ObservedExecutor(InProcessScanExecutor):
            def submit(self, scan_id):
                boundary("submit", str(scan_id))
                proof["submissions"].append(str(scan_id))
                super().submit(scan_id)

            def _build_provider(self, region):
                boundary("provider", proof["submissions"][-1])
                if scenario["mode"] == "crash":
                    gate.set()
                    if not threading.Event().wait(30):
                        fail("CRASH_BOUNDARY_NOT_TERMINATED")
                return super()._build_provider(region)

        executor = ObservedExecutor(session_factory=tracked_session, settings=get_settings())
        application = create_app(executor_factory=lambda: executor, resume_pending_scans=True)
        if application.dependency_overrides:
            fail("AUTHENTICATION_BYPASSED")
        server = uvicorn.Server(
            uvicorn.Config(
                application,
                host="127.0.0.1",
                port=8158,
                log_level="error",
                access_log=False,
                lifespan="on",
            )
        )
        thread = threading.Thread(target=server.run, daemon=True)
        http = build_opener(ProxyHandler({}))

        def request(path, *, body=None, token=None, key=None):
            headers = {}
            if token:
                headers["Authorization"] = token
            if key:
                headers["Idempotency-Key"] = key
            data = None if body is None else json.dumps(body).encode()
            if data is not None:
                headers["Content-Type"] = "application/json"
            try:
                response = http.open(
                    Request("http://127.0.0.1:8158" + path, data=data, headers=headers), timeout=10
                )
            except HTTPError as error:
                response = error
            with response:
                return response.code, json.load(response), response.headers.get("cache-control")

        proof["stage"] = "api-startup"
        with redirect_stdout(output), redirect_stderr(errors):
            logging.basicConfig(level=logging.ERROR, stream=errors, force=True)
            thread.start()
            try:
                deadline = time.monotonic() + 15
                while not server.started:
                    if not thread.is_alive() or time.monotonic() >= deadline:
                        fail("API_STARTUP_FAILED")
                    time.sleep(0.05)
                for endpoint in ("/health", "/ready", "/openapi.json"):
                    code, value, _ = request(endpoint)
                    if code != 200:
                        fail("STARTUP_HTTP_FAILED")
                    proof["api_checks"][endpoint] = (
                        value["info"]["title"] if endpoint == "/openapi.json" else value["status"]
                    )
                    if endpoint == "/openapi.json":
                        for path, method in (
                            ("/api/v1/remediation-executions/{execution_id}/verifications", "post"),
                            ("/api/v1/remediation-verifications", "get"),
                            ("/api/v1/remediation-verifications/{verification_id}", "get"),
                        ):
                            if value["paths"][path][method]["security"] != [{"HTTPBearer": []}]:
                                fail("BEARER_SCHEMA_CHANGED")
                        contract = value["components"]["schemas"]["VerificationRequest"]
                        if contract["additionalProperties"] is not False or set(
                            contract["properties"]
                        ) != {"reason"}:
                            fail("REQUEST_SCHEMA_NOT_CLOSED")
                        proof["api_checks"]["bearer_schema"] = True
                route = (
                    "/api/v1/remediation-executions/" + scenario["execution_id"] + "/verifications"
                )
                if scenario["mode"] != "resume":
                    if (
                        request(route, body=scenario["body"], key=scenario["idempotency_key"])[0]
                        != 401
                    ):
                        fail("MISSING_AUTH_ALLOWED")
                    if (
                        request(
                            route,
                            body=scenario["body"],
                            token=scenario["reader"],
                            key=scenario["idempotency_key"],
                        )[0]
                        != 403
                    ):
                        fail("READ_PRINCIPAL_ALLOWED_WRITE_AUTHORITY")
                    scheme, token = scenario["operator"].split(" ", 1)
                    header, claims, signature = token.split(".")
                    altered = ("A" if signature[0] != "A" else "B") + signature[1:]
                    forged = scheme + " " + ".".join((header, claims, altered))
                    if (
                        request(
                            route,
                            body=scenario["body"],
                            token=forged,
                            key=scenario["idempotency_key"],
                        )[0]
                        != 401
                    ):
                        fail("INVALID_SIGNATURE_ACCEPTED")
                    code, value, cache = request(
                        route,
                        body=scenario["body"],
                        token=scenario["operator"],
                        key=scenario["idempotency_key"],
                    )
                    if scenario["mode"] == "default-off":
                        if (
                            code != 503
                            or value["detail"]["code"] != "remediation_verification_disabled"
                            or proof["calls"]
                            or proof["submissions"]
                        ):
                            fail("DEFAULT_OFF_NOT_ENFORCED")
                        proof["api_checks"]["default_off"] = True
                        proof["stage"] = "complete"
                        continue_scan = False
                    else:
                        if code != 202 or cache != "no-store":
                            proof["api_checks"]["admission_status"] = code
                            detail = value.get("detail", {})
                            error_code = detail.get("code") if isinstance(detail, dict) else None
                            proof["api_checks"]["admission_error"] = (
                                error_code
                                if error_code
                                in {
                                    "remediation_provenance_conflict",
                                    "remediation_database_unavailable",
                                    "remediation_state_conflict",
                                    "verification_submission_failed",
                                }
                                else "OTHER"
                            )
                            fail("SIGNED_ADMISSION_FAILED")
                        proof["pending"] = value
                        continue_scan = True
                else:
                    continue_scan = True
                if scenario["mode"] in {"crash", "crash-collection"}:
                    if not gate.wait(15) or proof["pending"]["receipt"] is not None:
                        fail("CRASH_NOT_AT_RUNNING_BOUNDARY")
                    proof["stage"] = (
                        "crash-before-provider"
                        if scenario["mode"] == "crash"
                        else "crash-during-collection"
                    )
                    emit(90)
                    os._exit(90)
                if continue_scan:
                    identifier = (
                        scenario["verification_id"]
                        if scenario["mode"] == "resume"
                        else proof["pending"]["content"]["verification_id"]
                    )
                    deadline = time.monotonic() + 30
                    while True:
                        code, value, cache = request(
                            "/api/v1/remediation-verifications/" + identifier,
                            token=scenario["reader"],
                        )
                        if code != 200 or cache != "no-store":
                            fail("SIGNED_READ_FAILED")
                        if value["receipt"] is not None:
                            break
                        if time.monotonic() >= deadline:
                            fail("RECEIPT_NOT_SEALED")
                        time.sleep(0.05)
                    proof["complete"] = value
                    replay_code, replay, _ = request(
                        route,
                        body=scenario["body"],
                        token=scenario["operator"],
                        key=scenario["idempotency_key"],
                    )
                    if replay_code != 200 or replay != value or len(proof["submissions"]) != 1:
                        fail("REPLAY_RESUBMITTED_OR_CHANGED_INTENT")
                    list_code, page, _ = request(
                        "/api/v1/remediation-verifications?execution_id="
                        + scenario["execution_id"],
                        token=scenario["reader"],
                    )
                    if list_code != 200 or page["total"] != 1 or page["items"] != [value]:
                        fail("READ_LIST_FAILED")
                    proof["stage"] = "complete"
            finally:
                server.should_exit = True
                thread.join(timeout=10)
                if thread.is_alive():
                    fail("SERVER_NOT_SHUT_DOWN")
        if managed_sessions:
            fail("UNCLOSED_MANAGED_SESSIONS")
        emit(0)
        return 0
    except BaseException as error:
        frames = traceback.extract_tb(error.__traceback__)
        if frames:
            proof["error_location"] = {
                "file": Path(frames[-1].filename).name,
                "line": frames[-1].lineno,
                "type": type(error).__name__,
            }
        if not proof["errors"]:
            proof["errors"].append("UNEXPECTED_HARNESS_FAILURE")
        emit(73)
        return 73


if __name__ == "__main__":
    raise SystemExit(main())
