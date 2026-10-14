"""Sibling installed-reader launcher using only the existing owned offline process stack."""

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from botocore.exceptions import ClientError
from sqlalchemy.engine import URL

from app.remediation.verification_contracts import VerificationView
from tests.dashboard_fixtures import AUDIENCE, ISSUER
from tests.verification_process_harness import ACCOUNT, READ_OPERATIONS, READER_ROLE, REGION
from tests.worker_process_runtime import (
    KIND_LABEL,
    OWNER_LABEL,
    ROOT,
    cleanup_preserving_primary,
    require_owned_labels,
    validate_container_security,
)


def encode(value):
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode()}
    if isinstance(value, datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, ClientError):
        return {"$error": {"Code": value.response["Error"]["Code"]}}
    if isinstance(value, Mapping):
        return {key: encode(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [encode(item) for item in value]
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise ValueError("unsupported synthetic reader response")


def sdk_responses(reader, *, identity_account=ACCOUNT):
    values = {}
    for (service, region), client in reader._clients.items():
        if region != REGION:
            raise ValueError("unexpected synthetic reader Region")
        methods = {method: list(responses) for method, responses in client._responses.items()}
        for method, paginators in client._paginators.items():
            pages = []
            for paginator in paginators:
                if paginator.error is not None:
                    pages.append(paginator.error)
                else:
                    pages.extend(paginator.pages)
            methods[method] = pages
        if set(methods) - READ_OPERATIONS:
            raise ValueError("non-reader SDK response configured")
        values[service] = encode(methods)
    values["sts"] = {
        "get_caller_identity": [
            {
                "Account": identity_account,
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/offline-scanner-reader/installed-test",
                "UserId": "AROAREADER:installed-test",
            }
        ],
    }
    return values


def source_hashes():
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / "app").rglob("*"))
        if path.is_file() and path.suffix in {".py", ".json"}
    }


def reader_security(value, image, network, mounts):
    """Validate reader-specific names, then reuse every unchanged generic security guard."""
    if (
        not isinstance(value, dict)
        or set(mounts) != {"/harness/reader.py", "/harness/scenario.json"}
        or value.get("cmd")
        != [
            "python",
            "/harness/reader.py",
            "/harness/scenario.json",
        ]
    ):
        raise RuntimeError("invalid installed reader command/mount contract")
    entries = value.get("mounts")
    if (
        not isinstance(entries, list)
        or len(entries) != 2
        or any(not isinstance(item, dict) for item in entries)
        or {item.get("Destination") for item in entries} != set(mounts)
    ):
        raise RuntimeError("invalid original reader mount names")
    normalized = dict(value, cmd=["python", "/harness/worker.py", "/harness/scenario.json"])
    normalized["mounts"] = [
        dict(
            item,
            Destination="/harness/worker.py"
            if item.get("Destination") == "/harness/reader.py"
            else item.get("Destination"),
        )
        for item in value.get("mounts", [])
    ]
    expected = {
        "/harness/worker.py": mounts["/harness/reader.py"],
        "/harness/scenario.json": mounts["/harness/scenario.json"],
    }
    validate_container_security(normalized, image, network, expected)


def validate_reader_report(report, hashes, code, mode):
    if mode not in {"observe", "resume", "crash", "crash-collection", "default-off"}:
        raise RuntimeError("invalid installed reader mode")
    fields = {
        "schema_version",
        "exit_code",
        "errors",
        "stage",
        "calls",
        "boundaries",
        "submissions",
        "metadata_requests",
        "credential_methods",
        "credential_fingerprints",
        "writer_constructions",
        "host_file_reads",
        "source_hashes",
        "locations",
        "versions",
        "uid",
        "security",
        "api_checks",
        "pending",
        "complete",
        "env_names",
        "error_location",
        "stdout_bytes",
        "stderr_bytes",
        "reader_role_arn",
    }
    if not isinstance(report, dict) or set(report) != fields:
        raise RuntimeError("invalid installed reader proof shape")
    expected_code = 90 if mode in {"crash", "crash-collection"} else 0
    if report["errors"] or report["error_location"] is not None:
        # Only closed labels/locations, never child output, input, tokens or credentials.
        stage = report.get("stage")
        safe_stage = (
            stage
            if isinstance(stage, str)
            and stage
            in {"input", "application-import", "api-startup", "complete", "crash-before-provider"}
            else "SDK_OR_HARNESS"
        )
        location = report.get("error_location")
        safe_location = ""
        if isinstance(location, dict) and type(location.get("line")) is int:
            safe_location = " line " + str(location["line"])
        known_errors = {
            "SIGNED_ADMISSION_FAILED",
            "SIGNED_READ_FAILED",
            "MISSING_START_AUDIT",
            "MISSING_ORIGINAL_TARGET",
            "MISSING_ORIGINAL_FINDING",
            "MISSING_ORIGINAL_RESOURCE",
            "MANAGED_TRANSACTION_SPANS_IO",
            "UNPLANNED_OR_WRITE_SDK_CALL",
            "WRONG_CREDENTIAL_CHAIN",
            "UNEXPECTED_HARNESS_FAILURE",
            "REPLAY_RESUBMITTED_OR_CHANGED_INTENT",
            "RECEIPT_NOT_SEALED",
        }
        classification = (
            next(
                (
                    value
                    for value in report["errors"]
                    if isinstance(value, str) and value in known_errors
                ),
                "OTHER_GUARD",
            )
            if isinstance(report["errors"], list)
            else "OTHER_GUARD"
        )
        checks = report.get("api_checks", {})
        status = checks.get("admission_status") if isinstance(checks, dict) else None
        context = " status " + str(status) if type(status) is int else ""
        error_code = checks.get("admission_error") if isinstance(checks, dict) else None
        if error_code in {
            "remediation_provenance_conflict",
            "remediation_database_unavailable",
            "remediation_state_conflict",
            "verification_submission_failed",
        }:
            context += " " + error_code
        raise RuntimeError(
            "installed reader guard failed: "
            + safe_stage
            + safe_location
            + " "
            + classification
            + context
        )
    if code != expected_code or type(report["exit_code"]) is not int or report["exit_code"] != code:
        raise RuntimeError("installed reader exit proof mismatch")
    if (
        type(report["schema_version"]) is not int
        or report["schema_version"] != 1
        or report["source_hashes"] != hashes
        or type(report["uid"]) is not int
        or report["uid"] <= 0
    ):
        raise RuntimeError("installed reader source/identity proof mismatch")
    required_sources = {
        "app/main.py",
        "app/config.py",
        "app/database/persistence.py",
        "app/services/remediation_verification_service.py",
        "app/remediation/verification_evidence.py",
        "app/services/scan_executor.py",
        "app/security/authentication.py",
        "app/aws/sessions.py",
    }
    if not required_sources <= set(hashes) or any(
        not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
        for value in hashes.values()
    ):
        raise RuntimeError("incomplete installed source identity")
    for name in ("writer_constructions", "host_file_reads", "stdout_bytes"):
        if type(report[name]) is not int or report[name] != 0:
            raise RuntimeError("installed reader isolation proof mismatch")
    if (
        report["security"] != {"no_new_privileges": 1, "effective_capabilities": "0000000000000000"}
        or type(report["security"].get("no_new_privileges")) is not int
    ):
        raise RuntimeError("installed reader privilege proof mismatch")
    if report["api_checks"] != {
        "/health": "healthy",
        "/ready": "ready",
        "/openapi.json": "Cloud Security Control Plane",
        "bearer_schema": True,
        **({"default_off": True} if mode == "default-off" else {}),
    }:
        raise RuntimeError("installed reader startup proof mismatch")
    if type(report["api_checks"]["bearer_schema"]) is not bool or (
        mode == "default-off" and type(report["api_checks"]["default_off"]) is not bool
    ):
        raise RuntimeError("installed reader schema evidence has invalid type")
    names = report["env_names"]
    forbidden = {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_ENDPOINT_URL",
    }
    if (
        not isinstance(names, list)
        or len(names) > 128
        or any(
            not isinstance(name, str) or re.fullmatch(r"[A-Z][A-Z0-9_]*", name) is None
            for name in names
        )
        or len(set(names)) != len(names)
        or any(name.startswith("REMEDIATION_WORKER_") for name in names)
        or forbidden & set(names)
    ):
        raise RuntimeError("writer configuration shared with installed reader")
    for field in (
        "calls",
        "boundaries",
        "submissions",
        "credential_methods",
        "credential_fingerprints",
    ):
        values = report[field]
        if (
            not isinstance(values, list)
            or len(values) > 128
            or any(not isinstance(value, str) for value in values)
        ):
            raise RuntimeError("unbounded or malformed installed reader evidence")
    for count in ("metadata_requests", "stderr_bytes"):
        if type(report[count]) is not int or not 0 <= report[count] <= 16384:
            raise RuntimeError("invalid installed reader counter")
    if mode != "default-off":
        try:
            if len(report["submissions"]) != 1:
                raise ValueError
            UUID(report["submissions"][0])
        except ValueError:
            raise RuntimeError("invalid installed scan submission identity") from None
    if not isinstance(report["locations"], dict) or set(report["locations"]) != {
        "app",
        "boto3",
        "botocore",
    }:
        raise RuntimeError("invalid installed reader locations")
    for name, location in report["locations"].items():
        pattern = (
            r"(?:/app/app|/usr/local/lib/python[0-9]+\.[0-9]+/site-packages/app)"
            if name == "app"
            else r"/usr/local/lib/python[0-9]+\.[0-9]+/site-packages/" + name + r"/__init__\.py"
        )
        if not isinstance(location, str) or re.fullmatch(pattern, location) is None:
            raise RuntimeError("shadowed installed runtime location")
    if (
        not isinstance(report["versions"], dict)
        or set(report["versions"]) != {"python", "boto3", "botocore"}
        or any(
            not isinstance(version, str)
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*", version) is None
            for version in report["versions"].values()
        )
    ):
        raise RuntimeError("invalid installed dependency versions")
    if mode in {"default-off", "crash"}:
        if (
            report["calls"]
            or report["metadata_requests"]
            or report["credential_methods"]
            or report["credential_fingerprints"]
            or report["reader_role_arn"] is not None
        ):
            raise RuntimeError("unexpected provider before installed reader boundary")
        if mode == "default-off":
            if (
                report["pending"] is not None
                or report["complete"] is not None
                or report["submissions"]
                or report["boundaries"]
                or "REMEDIATION_VERIFICATION_ENABLED" in names
            ):
                raise RuntimeError("default-off proof contains admitted work")
        else:
            pending = VerificationView.model_validate(report["pending"])
            if (
                pending.receipt is not None
                or report["complete"] is not None
                or report["submissions"] != [str(pending.content.scan_id)]
                or report["boundaries"] != ["submit", "provider"]
                or report["stage"] != "crash-before-provider"
            ):
                raise RuntimeError("process interruption was not at the durable pending boundary")
    else:
        if (
            report["metadata_requests"] != 1
            or not report["calls"]
            or set(report["credential_methods"]) != {"container-role"}
        ):
            raise RuntimeError("installed reader SDK/credential chain was not exercised")
        if report["reader_role_arn"] != READER_ROLE or any(
            re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
            for fingerprint in report["credential_fingerprints"]
        ):
            raise RuntimeError("wrong or malformed reader credential identity")
        if (
            len(report["credential_fingerprints"]) != len(report["calls"])
            or len(set(report["credential_fingerprints"])) != 1
            or len(report["calls"]) != len(report["credential_methods"])
        ):
            raise RuntimeError("installed reader credential identity mismatch")
        if report["boundaries"] != [
            "submit",
            "provider",
            "metadata",
            *["sdk:" + call for call in report["calls"]],
        ]:
            raise RuntimeError("installed reader committed IO boundary proof mismatch")
        allowed_operations = {
            "".join(part.title() if part != "ebs" else "Ebs" for part in method.split("_"))
            for method in READ_OPERATIONS
        }
        if any(
            call.count(":") != 1
            or call.split(":")[0]
            not in {"sts", "ec2", "s3", "s3control", "iam", "cloudtrail", "accessanalyzer"}
            or call.split(":")[1] not in allowed_operations
            for call in report["calls"]
        ):
            raise RuntimeError("write or unknown SDK operation in installed reader proof")
        if mode == "crash-collection":
            pending = VerificationView.model_validate(report["pending"])
            if (
                pending.receipt is not None
                or report["complete"] is not None
                or report["submissions"] != [str(pending.content.scan_id)]
                or report["stage"] != "crash-during-collection"
                or len(report["calls"]) != 2
                or report["calls"][0] != "sts:GetCallerIdentity"
                or report["calls"][1].startswith("sts:")
            ):
                raise RuntimeError("interruption was not during real read-only fact collection")
            return report
        complete = VerificationView.model_validate(report["complete"])
        if (
            complete.receipt is None
            or report["submissions"] != [str(complete.content.scan_id)]
            or report["stage"] != "complete"
        ):
            raise RuntimeError("missing installed terminal receipt")
        receipt = complete.receipt
        if (
            receipt.scan_id != complete.content.scan_id
            or receipt.verification_id != complete.content.verification_id
            or receipt.verification_sha256 != complete.verification_sha256
        ):
            raise RuntimeError("inconsistent installed receipt identity")
    return report


def run_reader(runtime, child_url, scenario):
    runtime._assert_database_owned()
    if (
        not isinstance(child_url, URL)
        or (
            child_url.drivername,
            child_url.host,
            child_url.port,
            child_url.database,
            child_url.username,
            child_url.password,
            set(child_url.query),
        )
        != (
            "postgresql+psycopg",
            "pg",
            5432,
            "cloudsec_test",
            "cloudsec_test",
            runtime.password,
            {"options"},
        )
        or child_url.query["options"] not in {"-csearch_path=" + name for name in runtime.schemas}
    ):
        raise RuntimeError("reader URL is not from a live owned schema")
    if set(scenario) != {
        "mode",
        "execution_id",
        "verification_id",
        "operator",
        "reader",
        "jwks",
        "body",
        "idempotency_key",
        "responses",
    } or scenario["mode"] not in {"observe", "resume", "crash", "crash-collection", "default-off"}:
        raise RuntimeError("invalid closed installed reader scenario")
    document = dict(scenario, source_hashes=source_hashes())
    path = Path(runtime.temporary.name) / ("reader-scenario-" + uuid4().hex + ".json")
    path.write_text(json.dumps(document), encoding="utf-8")
    harness = Path(__file__).with_name("verification_process_harness.py").resolve()
    mounts = {"/harness/reader.py": str(harness), "/harness/scenario.json": str(path.resolve())}
    environment = {
        "APP_ENV": "production",
        "AUTH_MODE": "oidc",
        "OIDC_ISSUER": ISSUER,
        "OIDC_AUDIENCE": AUDIENCE,
        "OIDC_JWKS_URL": ISSUER + "/jwks",
        "OIDC_ROLES_CLAIM": "cognito:groups",
        "OIDC_ALGORITHMS": "RS256",
        "OIDC_ALLOW_INSECURE_HTTP": "false",
        "DATABASE_URL": child_url.render_as_string(hide_password=False),
        "LOG_LEVEL": "ERROR",
        "DASHBOARD_ENABLED": "false",
        "AWS_REGION": REGION,
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_CONFIG_FILE": "/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE": "/dev/null",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/offline-reader-" + uuid4().hex,
    }
    if scenario["mode"] != "default-off":
        environment.update(
            REMEDIATION_VERIFICATION_ENABLED="true",
            REMEDIATION_VERIFICATION_ACCOUNT_ID=ACCOUNT,
            REMEDIATION_VERIFICATION_REGION=REGION,
        )
    name = runtime.owner + "-worker-" + uuid4().hex
    runtime._reserve(name, "worker")
    args = [
        "create",
        "--name",
        name,
        "--label",
        OWNER_LABEL + "=" + runtime.owner,
        "--label",
        KIND_LABEL + "=worker",
        "--network",
        runtime.owner,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
    ]
    for destination, source in mounts.items():
        args.extend(["--mount", f"type=bind,source={source},target={destination},readonly"])
    for key in sorted(environment):
        args.extend(["--env", key])
    args.extend([runtime.image, "python", "/harness/reader.py", "/harness/scenario.json"])
    primary = None
    try:
        runtime._docker(*args, env=environment)
        require_owned_labels(runtime.owner, name, "worker", runtime._labels(name, "worker"))
        require_owned_labels(
            runtime.owner, runtime.owner, "network", runtime._labels(runtime.owner, "network")
        )
        if (
            json.loads(
                runtime._docker(
                    "network", "inspect", "--format", "{{json .Internal}}", runtime.owner
                ).stdout
            )
            is not True
        ):
            raise RuntimeError("reader network is not internal")
        template = (
            '{"image":{{json .Image}},"user":{{json .Config.User}},"cmd":{{json .Config.Cmd}},'
            '"entrypoint":{{json .Config.Entrypoint}},'
            '"read_only":{{json .HostConfig.ReadonlyRootfs}},'
            '"privileged":{{json .HostConfig.Privileged}},"caps_add":{{json .HostConfig.CapAdd}},'
            '"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},'
            '"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
            '"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}}}'
        )
        reader_security(
            json.loads(runtime._docker("container", "inspect", "--format", template, name).stdout),
            runtime.image,
            runtime.owner,
            mounts,
        )
        result = runtime._docker("start", "--attach", name, timeout=90, check=False)
        state = json.loads(
            runtime._docker(
                "container",
                "inspect",
                "--format",
                '{"running":{{json .State.Running}},"code":{{json .State.ExitCode}},'
                '"status":{{json .State.Status}}}',
                name,
            ).stdout
        )
        if (
            state != {"running": False, "code": result.returncode, "status": "exited"}
            or result.stderr
        ):
            raise RuntimeError("installed reader terminal state mismatch")
        try:
            report = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError("missing installed reader proof") from None
        return validate_reader_report(
            report, document["source_hashes"], result.returncode, scenario["mode"]
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_preserving_primary(lambda: runtime._remove_worker(name), primary)
