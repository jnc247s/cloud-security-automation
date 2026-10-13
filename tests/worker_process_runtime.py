"""Private, owned offline process resources. Never attach to an operator database or task."""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import tempfile
import time
import warnings
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

ROOT = Path(__file__).resolve().parents[1]
OWNER_LABEL = "cloudsec.worker-process"
KIND_LABEL = "cloudsec.worker-process-kind"
_OWNER = re.compile(r"cloudsec-worker-process-[0-9a-f]{32}", re.ASCII)
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_SCHEMA = re.compile(r"sprint8_worker_[0-9a-f]{32}", re.ASCII)
_EXCLUDED_ENV = (
    "AWS_",
    "BOTO_",
    "APP_",
    "AUTH_",
    "DATABASE_",
    "TEST_DATABASE_",
    "OIDC_",
    "DASHBOARD_",
    "REMEDIATION_",
    "ASSESSMENT_PROFILE_",
    "DEV_IDENTITY_",
    "POSTGRES_",
)


def isolated_child_environment(extra=None):
    """Keep Docker/OS configuration, not application, identity or cloud configuration."""
    value = {
        name: content
        for name, content in os.environ.items()
        if not name.upper().startswith(_EXCLUDED_ENV) and name.upper() != "BOTO_CONFIG"
    }
    value.update(extra or {})
    return value


def loopback_port(value):
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})\s*", value, re.ASCII)
    if match is None or not 1 <= int(match[1]) <= 65535:
        raise RuntimeError("owned PostgreSQL must have exactly one loopback port")
    return int(match[1])


def require_local_docker_endpoint(value):
    """Do not provision test resources through an inherited remote Docker context."""
    if not isinstance(value, str) or re.search(r"[\x00-\x20\x7f]", value):
        raise RuntimeError("offline tests require a local Docker endpoint")
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise RuntimeError("offline tests require a local Docker endpoint") from None
    unix = (
        parsed.scheme == "unix"
        and not parsed.netloc
        and parsed.path.startswith("/")
        and parsed.path.endswith("/docker.sock")
        and not parsed.query
        and not parsed.fragment
    )
    pipe = value in {
        "npipe:////./pipe/docker_engine",
        "npipe:////./pipe/dockerDesktopLinuxEngine",
    }
    if not unix and not pipe:
        raise RuntimeError("offline tests require a local Docker endpoint")


def require_owned_labels(owner, name, kind, labels):
    """Validate exact narrow targets before any removal; label checks alone are insufficient."""
    if _OWNER.fullmatch(owner) is None:
        raise RuntimeError("invalid offline resource owner")
    allowed = (
        name == owner
        if kind == "network"
        else name == owner + "-db"
        if kind == "database"
        else re.fullmatch(re.escape(owner) + r"-worker-[0-9a-f]{32}", name, re.ASCII)
        if kind == "worker"
        else False
    )
    if not allowed or not isinstance(labels, dict) or labels.get(OWNER_LABEL) != owner:
        raise RuntimeError("offline resource ownership mismatch")
    if labels.get(KIND_LABEL) != kind:
        raise RuntimeError("offline resource kind mismatch")


def cleanup_preserving_primary(cleanup, primary=None):
    """Cleanup-only failure fails; a secondary cleanup/diagnostic failure cannot mask primary."""
    try:
        cleanup()
    except BaseException:
        if primary is None:
            raise
        try:
            warnings.warn(
                "Secondary owned process cleanup failure; primary retained.", stacklevel=2
            )
        except BaseException:
            pass


def validate_process_report(
    report, source_hashes, exit_code, expected_actions, *, application="worker"
):
    """Fail closed on bounded proof, including types, provenance and transport counts."""
    from tests.worker_process_harness import ENABLE, ENCRYPTION, IDENTITY, KEY, SOURCE_PATHS

    def reject(classification=None):
        suffix = "" if classification is None else " [" + classification + "]"
        raise RuntimeError("invalid offline process proof" + suffix)

    fields = {
        "schema_version",
        "exit_code",
        "stdout",
        "stderr",
        "errors",
        "calls",
        "wire_actions",
        "lock_probes",
        "enable_invocations",
        "intent_checks",
        "source_hashes",
        "locations",
        "versions",
        "uid",
        "engine_creations",
        "application_settings_reads",
        "host_file_reads",
        "security",
        "api_checks",
    }
    if not isinstance(report, dict) or set(report) != fields:
        reject()
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        reject()
    if type(report["exit_code"]) is not int or report["exit_code"] != exit_code:
        reject()
    outputs = {
        0: {
            "WORKER_DISABLED\n",
            "NO_ACTION\n",
            "NO_WRITE\n",
            "ACKNOWLEDGED_UNVERIFIED\n",
            "QUARANTINED_UNVERIFIED\n",
            "API_STARTUP_VERIFIED\n",
            "Process one explicitly admitted remediation job: "
            "python -m app.remediation.worker UUID\n",
        },
        1: {"WORKER_CONFIGURATION_REJECTED\n", "WORKER_UNAVAILABLE\n"},
        2: {"WORKER_INVALID_ARGUMENT\n"},
        47: {""},  # Deliberate owned-process death before the worker can report its outcome.
    }
    if report["errors"] != []:
        known = {
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
        }
        values = report["errors"]
        classification = (
            next(
                (value for value in values if isinstance(value, str) and value in known),
                "HARNESS_GUARD",
            )
            if isinstance(values, list)
            else "HARNESS_GUARD"
        )
        reject(classification)
    if report["stderr"] != "":
        marker = isinstance(report["stderr"], str) and (
            "synthetic-sensitive-post-entrypoint-marker" in report["stderr"]
        )
        classification = (
            "POST_ENTRYPOINT_DIAGNOSTIC"
            if marker
            else "CHILD_RUNTIME_WARNING"
            if isinstance(report["stderr"], str) and "Warning:" in report["stderr"]
            else "CHILD_THREAD_EXCEPTION"
            if isinstance(report["stderr"], str) and "Exception in thread" in report["stderr"]
            else "CHILD_DEPENDENCY_DEBUG"
            if isinstance(report["stderr"], str) and "DEBUG" in report["stderr"]
            else "UNEXPECTED_CHILD_STDERR"
        )
        reject(classification)
    if (
        exit_code not in outputs
        or not isinstance(report["stdout"], str)
        or report["stdout"] not in outputs[exit_code]
        or report["stderr"] != ""
        or report["errors"] != []
        or type(report["uid"]) is not int
        or not 1 <= report["uid"] < 2**31
        or set(source_hashes) != set(SOURCE_PATHS)
        or report["source_hashes"] != source_hashes
    ):
        reject()
    actions = {IDENTITY, ENCRYPTION, KEY, ENABLE}
    labels = {"factory", "metadata", "client:sts", "client:ec2", "close:sts", "close:ec2"}
    labels |= {prefix + action for prefix in ("sdk:", "wire:") for action in actions}
    for field, allowed in (("calls", labels), ("lock_probes", labels), ("wire_actions", actions)):
        value = report[field]
        if (
            not isinstance(value, list)
            or len(value) > 128
            or any(not isinstance(item, str) or item not in allowed for item in value)
        ):
            reject()
    if (
        report["calls"] != report["lock_probes"]
        or [value[5:] for value in report["calls"] if value.startswith("wire:")]
        != report["wire_actions"]
        or report["wire_actions"] != list(expected_actions)
    ):
        reject()
    for field in ("enable_invocations", "intent_checks"):
        if type(report[field]) is not int or report[field] not in {0, 1}:
            reject()
    if type(report["engine_creations"]) is not int or report["engine_creations"] not in {0, 1}:
        reject()
    if type(report["host_file_reads"]) is not int or report["host_file_reads"] != 0:
        reject()
    reads = report["application_settings_reads"]
    if type(reads) is not int or application not in {"worker", "api"}:
        reject()
    if application == "worker":
        if reads != 0 or report["api_checks"] != {} or report["stdout"] == "API_STARTUP_VERIFIED\n":
            reject()
    else:
        checks = report["api_checks"]
        if (
            not 1 <= reads <= 64
            or report["engine_creations"] != 1
            or report["stdout"] != "API_STARTUP_VERIFIED\n"
            or exit_code != 0
            or report["calls"] != []
            or report["enable_invocations"] != 0
            or not isinstance(checks, dict)
            or checks
            != {
                "health": "healthy",
                "ready": "ready",
                "database": "ready",
                "openapi": True,
                "bearer_security": True,
                "tests_absent": True,
            }
            or any(
                type(checks.get(key)) is not bool
                for key in ("openapi", "bearer_security", "tests_absent")
            )
        ):
            reject()
    if (
        not isinstance(report["security"], dict)
        or set(report["security"]) != {"no_new_privileges", "effective_capabilities"}
        or type(report["security"]["no_new_privileges"]) is not int
        or report["security"]["no_new_privileges"] != 1
        or report["security"]["effective_capabilities"] != "0000000000000000"
    ):
        reject()
    if not (
        report["enable_invocations"]
        == report["intent_checks"]
        == report["wire_actions"].count(ENABLE)
        == report["calls"].count("sdk:" + ENABLE)
    ):
        reject()
    versions, locations = report["versions"], report["locations"]
    if not isinstance(versions, dict) or set(versions) != {"python", "boto3", "botocore"}:
        reject()
    if any(
        not isinstance(value, str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+-]*", value, re.ASCII) is None
        for value in versions.values()
    ):
        reject()
    if not isinstance(locations, dict) or set(locations) != {"app", "boto3", "botocore"}:
        reject()
    for name, value in locations.items():
        if (
            not isinstance(value, str)
            or not value.startswith("/")
            or ".." in value.split("/")
            or re.search(r"[\x00-\x20\x7f]", value)
        ):
            reject()
        if name == "app":
            valid = value == "/app/app" or re.fullmatch(
                r"/usr/local/lib/python[0-9]+\.[0-9]+/site-packages/app", value, re.ASCII
            )
        else:
            valid = re.fullmatch(
                r"/usr/local/lib/python[0-9]+\.[0-9]+/site-packages/" + name + r"/__init__\.py",
                value,
                re.ASCII,
            )
        if not valid:
            reject()


def validate_container_security(value, image, network, mounts):
    """Independent Docker metadata, never worker self-report or broad container inspection."""
    fields = {
        "image",
        "user",
        "cmd",
        "entrypoint",
        "read_only",
        "privileged",
        "caps",
        "security",
        "network",
        "ports",
        "mounts",
        "tmpfs",
        "caps_add",
    }
    if (
        not isinstance(image, str)
        or _IMAGE.fullmatch(image) is None
        or not isinstance(network, str)
        or _OWNER.fullmatch(network) is None
        or not isinstance(mounts, dict)
        or set(mounts)
        not in (
            {"/harness/worker.py", "/harness/scenario.json"},
            {"/harness/worker.py", "/harness/scenario.json", "/app/.env"},
        )
        or not isinstance(value, dict)
        or set(value) != fields
        or value["image"] != image
        or value["user"] != "app"
        or value["cmd"] != ["python", "/harness/worker.py", "/harness/scenario.json"]
        or value["entrypoint"] is not None
        or value["read_only"] is not True
        or value["privileged"] is not False
        or value["caps"] != ["ALL"]
        or value["caps_add"] not in (None, [])
        or value["security"] != ["no-new-privileges"]
        or value["network"] != network
        or value["ports"] not in (None, {})
        or value["tmpfs"] != {"/tmp": "rw,noexec,nosuid,size=16m"}
        or not isinstance(value["mounts"], list)
        or len(value["mounts"]) != len(mounts)
    ):
        raise RuntimeError("owned worker security metadata mismatch")
    seen = set()
    for entry in value["mounts"]:
        if (
            not isinstance(entry, dict)
            or not isinstance(entry.get("Destination"), str)
            or entry["Destination"] not in mounts
            or entry["Destination"] in seen
            or entry.get("Type") != "bind"
            or entry.get("Source") != mounts[entry["Destination"]]
            or entry.get("RW") is not False
            or entry.get("Propagation") != "rprivate"
        ):
            raise RuntimeError("owned worker mount metadata mismatch")
        seen.add(entry["Destination"])
    if seen != set(mounts):
        raise RuntimeError("owned worker mount metadata incomplete")


class OfflineProcessRuntime:
    """One fresh image/network/tmpfs PG. Password/URLs are private and never put in argv."""

    def __init__(self):
        self.owner = "cloudsec-worker-process-" + uuid4().hex
        self.database_name = self.owner + "-db"
        self.password = secrets.token_hex(24)
        self.endpoint = None
        self.image = None
        self.port = None
        self.possible_resources = []
        self.schemas = set()
        self.temporary = None

    def _docker(self, *args, env=None, timeout=60, check=True):
        if env and any(name.upper().startswith("DOCKER_") for name in env):
            raise RuntimeError("child input cannot select a Docker endpoint")
        child_env = isolated_child_environment(env)
        prefix = ["docker"]
        if self.endpoint is not None:
            require_local_docker_endpoint(self.endpoint)
            for name in tuple(child_env):
                if name.upper().startswith("DOCKER_"):
                    child_env.pop(name)
            prefix.extend(["--host", self.endpoint])
        try:
            result = subprocess.run(
                [*prefix, *args],
                cwd=ROOT,
                env=child_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeError("offline Docker operation unavailable") from None
        if check and result.returncode:
            # A Docker error/child env may contain credentials. Do not echo it or the command.
            raise RuntimeError("offline Docker operation failed")
        return result

    def _exists(self, name, kind):
        if kind == "network":
            result = self._docker(
                "network", "ls", "--filter", "name=^" + name + "$", "--format", "{{.Name}}"
            )
        else:
            result = self._docker(
                "container",
                "ls",
                "--all",
                "--filter",
                "name=^/" + name + "$",
                "--format",
                "{{.Names}}",
            )
        names = result.stdout.splitlines()
        if any(item != name for item in names):
            raise RuntimeError("offline Docker identity listing conflict")
        return names == [name]

    def _labels(self, name, kind):
        field = "{{json .Labels}}" if kind == "network" else "{{json .Config.Labels}}"
        command = ("network", "inspect") if kind == "network" else ("container", "inspect")
        try:
            return json.loads(self._docker(*command, "--format", field, name).stdout)
        except (ValueError, TypeError):
            raise RuntimeError("offline Docker ownership inspection failed") from None

    def _reserve(self, name, kind):
        # Never adopt/reuse an existing resource, even with superficially matching labels.
        require_owned_labels(self.owner, name, kind, {OWNER_LABEL: self.owner, KIND_LABEL: kind})
        if self._exists(name, kind):
            raise RuntimeError("offline resource name already exists")
        # Track possible creation before the CLI returns: a transport timeout is not absence.
        self.possible_resources.append((name, kind))

    def _assert_database_owned(self):
        if self.port is None or not self._exists(self.database_name, "database"):
            raise RuntimeError("owned PostgreSQL is unavailable")
        require_owned_labels(
            self.owner,
            self.database_name,
            "database",
            self._labels(self.database_name, "database"),
        )

    def start(self):
        configured_host = os.environ.get("DOCKER_HOST")
        if configured_host is not None:
            require_local_docker_endpoint(configured_host)
        context = self._docker("context", "show").stdout.strip()
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", context, re.ASCII) is None:
            raise RuntimeError("Docker context identity unavailable")
        try:
            endpoint = json.loads(
                self._docker(
                    "context", "inspect", context, "--format", "{{json .Endpoints.docker.Host}}"
                ).stdout
            )
        except ValueError:
            raise RuntimeError("Docker context endpoint unavailable") from None
        require_local_docker_endpoint(endpoint)
        self.endpoint = endpoint
        if self._docker("info", "--format", "{{.OSType}}").stdout.strip() != "linux":
            raise RuntimeError("offline tests require the local Linux Docker engine")
        self.temporary = tempfile.TemporaryDirectory(prefix=self.owner + "-")
        self._docker(
            "build",
            "--label",
            OWNER_LABEL + "=" + self.owner,
            "--tag",
            self.owner + ":test",
            ".",
            timeout=600,
        )
        self.image = self._docker(
            "image", "inspect", "--format", "{{.Id}}", self.owner + ":test"
        ).stdout.strip()
        if _IMAGE.fullmatch(self.image) is None:
            raise RuntimeError("offline image identity is invalid")
        self._reserve(self.owner, "network")
        self._docker(
            "network",
            "create",
            "--internal",
            "--label",
            OWNER_LABEL + "=" + self.owner,
            "--label",
            KIND_LABEL + "=network",
            self.owner,
        )
        self._reserve(self.database_name, "database")
        self._docker(
            "run",
            "--detach",
            "--name",
            self.database_name,
            "--label",
            OWNER_LABEL + "=" + self.owner,
            "--label",
            KIND_LABEL + "=database",
            "--network",
            "bridge",
            "--publish",
            "127.0.0.1::5432",
            "--tmpfs",
            "/var/lib/postgresql/data",
            "--env",
            "POSTGRES_PASSWORD",
            "--env",
            "POSTGRES_USER=cloudsec_test",
            "--env",
            "POSTGRES_DB=cloudsec_test",
            "postgres:16-alpine",
            env={"POSTGRES_PASSWORD": self.password},
        )
        # Internal-only networks do not provide this host port on the tested Docker engine.
        # Only PG joins the normal bridge for loopback publishing; workers stay internal-only.
        self._docker("network", "connect", "--alias", "pg", self.owner, self.database_name)
        self.port = loopback_port(self._docker("port", self.database_name, "5432").stdout)
        deadline = time.monotonic() + 60
        while self._docker(
            "exec",
            self.database_name,
            "pg_isready",
            "-h",
            "127.0.0.1",
            "-U",
            "cloudsec_test",
            "-d",
            "cloudsec_test",
            check=False,
        ).returncode:
            if time.monotonic() >= deadline:
                raise RuntimeError("owned PostgreSQL readiness deadline expired")
            time.sleep(0.25)
        self._assert_database_owned()
        return self

    def database_url(self, *, child=False, schema=None):
        self._assert_database_owned()
        if schema is not None and _SCHEMA.fullmatch(schema) is None:
            raise RuntimeError("invalid owned test schema")
        return URL.create(
            "postgresql+psycopg",
            username="cloudsec_test",
            password=self.password,
            host="pg" if child else "127.0.0.1",
            port=5432 if child else self.port,
            database="cloudsec_test",
            query={} if schema is None else {"options": "-csearch_path=" + schema},
        )

    @contextmanager
    def schema(self):
        # The URL comes only from this live, labelled handle; TEST_DATABASE_URL is not a target.
        from alembic import command

        from tests.integration.test_persistence_postgres import migration_config

        name = "sprint8_worker_" + uuid4().hex
        admin = create_engine(self.database_url(), connect_args={"connect_timeout": 5})
        engine = None
        created = False
        primary = None
        try:
            with admin.begin() as connection:
                connection.execute(text(f'CREATE SCHEMA "{name}"'))
            created = True
            self.schemas.add(name)
            engine = create_engine(
                self.database_url(schema=name),
                connect_args={"connect_timeout": 5},
                pool_pre_ping=True,
            )
            with engine.begin() as connection:
                command.upgrade(migration_config(connection), "head")
            yield engine, self.database_url(child=True, schema=name)
        except BaseException as error:
            primary = error
            raise
        finally:

            def cleanup():
                try:
                    if engine is not None:
                        engine.dispose()
                    if created:
                        self._assert_database_owned()
                        if _SCHEMA.fullmatch(name) is None:
                            raise RuntimeError("invalid owned schema cleanup boundary")
                        with admin.begin() as connection:
                            connection.execute(text(f'DROP SCHEMA "{name}" CASCADE'))
                        self.schemas.discard(name)
                finally:
                    admin.dispose()

            cleanup_preserving_primary(cleanup, primary)

    def _worker_security(self, name, mounts):
        require_owned_labels(self.owner, name, "worker", self._labels(name, "worker"))
        template = (
            '{"image":{{json .Image}},"user":{{json .Config.User}},'
            '"cmd":{{json .Config.Cmd}},"entrypoint":{{json .Config.Entrypoint}},'
            '"read_only":{{json .HostConfig.ReadonlyRootfs}},'
            '"privileged":{{json .HostConfig.Privileged}},'
            '"caps_add":{{json .HostConfig.CapAdd}},'
            '"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},'
            '"network":{{json .HostConfig.NetworkMode}},'
            '"ports":{{json .HostConfig.PortBindings}},"mounts":{{json .Mounts}},'
            '"tmpfs":{{json .HostConfig.Tmpfs}}}'
        )
        require_owned_labels(self.owner, self.owner, "network", self._labels(self.owner, "network"))
        if (
            json.loads(
                self._docker(
                    "network", "inspect", "--format", "{{json .Internal}}", self.owner
                ).stdout
            )
            is not True
        ):
            raise RuntimeError("owned worker network is not internal")
        try:
            value = json.loads(
                self._docker("container", "inspect", "--format", template, name).stdout
            )
        except (ValueError, TypeError):
            raise RuntimeError("owned worker security inspection failed") from None
        validate_container_security(value, self.image, self.owner, mounts)

    def _remove_worker(self, name):
        if self._exists(name, "worker"):
            require_owned_labels(self.owner, name, "worker", self._labels(name, "worker"))
            self._docker("container", "rm", "--force", name)
            if self._exists(name, "worker"):
                raise RuntimeError("owned worker remains after cleanup")

    def run_worker(
        self,
        scenario,
        child_url,
        *,
        environment=None,
        dotenv=False,
        guard_disarmed=False,
        application="worker",
    ):
        """Fresh installed entrypoint; only explicitly selected test files are mounted."""
        import hashlib

        from app.remediation.worker_aws import _FORBIDDEN_SOURCE_VARIABLES
        from tests.worker_process_harness import SOURCE_PATHS

        self._assert_database_owned()
        if (
            not isinstance(child_url, URL)
            or child_url.drivername != "postgresql+psycopg"
            or child_url.host != "pg"
            or child_url.port != 5432
            or child_url.database != "cloudsec_test"
            or child_url.username != "cloudsec_test"
            or child_url.password != self.password
            or set(child_url.query) != {"options"}
            or child_url.query["options"] not in {"-csearch_path=" + v for v in self.schemas}
        ):
            raise RuntimeError("worker URL is not derived from a live owned schema")
        if self.image is None or _IMAGE.fullmatch(self.image) is None or self.temporary is None:
            raise RuntimeError("owned process image/runtime unavailable")
        worker_env = {
            "REMEDIATION_WORKER_ENABLED": "true",
            "REMEDIATION_WORKER_ACCOUNT_ID": "123456789012",
            "REMEDIATION_WORKER_REGION": "us-east-1",
            "REMEDIATION_WORKER_ROLE_ARN": (
                "arn:aws:iam::123456789012:role/security/remediation-worker"
            ),
            "REMEDIATION_WORKER_DATABASE_URL": child_url.render_as_string(hide_password=False),
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/offline-process",
        }
        if application not in {"worker", "api"}:
            raise RuntimeError("invalid test-only installed application selection")
        if application == "api":
            if environment or dotenv or guard_disarmed:
                raise RuntimeError("packaged API probe has closed owned configuration")
            image_metadata = json.loads(
                self._docker(
                    "image",
                    "inspect",
                    "--format",
                    '{"id":{{json .Id}},"user":{{json .Config.User}},"cmd":{{json .Config.Cmd}}}',
                    self.image,
                ).stdout
            )
            if image_metadata != {
                "id": self.image,
                "user": "app",
                "cmd": ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"],
            }:
                raise RuntimeError("owned image default startup metadata mismatch")
            worker_env.update(
                {
                    "APP_ENV": "test",
                    "AUTH_MODE": "development",
                    "DATABASE_URL": child_url.render_as_string(hide_password=False),
                    "LOG_LEVEL": "CRITICAL",
                    "DASHBOARD_ENABLED": "false",
                    "AWS_EC2_METADATA_DISABLED": "true",
                }
            )
        allowed = (
            set(worker_env)
            | set(_FORBIDDEN_SOURCE_VARIABLES)
            | {
                "AWS_ENDPOINT_URL",
                "AWS_ENDPOINT_URL_EC2",
                "AWS_ENDPOINT_URL_STS",
                "AWS_ENDPOINT_URL_OTHER",
                "AWS_REGION",
                "AWS_DEFAULT_REGION",
                "AWS_STS_REGIONAL_ENDPOINTS",
                "AWS_CSM_ENABLED",
                "AWS_CSM_HOST",
                "AWS_DEFAULTS_MODE",
                "AWS_RETRY_MODE",
                "AWS_MAX_ATTEMPTS",
                "DATABASE_URL",
                "APP_ENV",
                "AUTH_MODE",
                "REMEDIATION_ADMISSION_ENABLED",
            }
        )
        for name, value in (environment or {}).items():
            if name not in allowed or (value is not None and not isinstance(value, str)):
                raise RuntimeError("unplanned child environment field")
            if name == "REMEDIATION_WORKER_DATABASE_URL" and value not in {
                None,
                "sqlite://",
                "synthetic-sensitive-invalid-url",
            }:
                raise RuntimeError("caller cannot redirect a worker database")
            if value is None:
                worker_env.pop(name, None)
            else:
                worker_env[name] = value
        if set(scenario) != {"argv", "responses", "metadata", "target"}:
            raise RuntimeError("unplanned offline process scenario fields")
        document = dict(scenario)
        document["application"] = application
        if type(guard_disarmed) is not bool:
            raise RuntimeError("invalid test-only transport guard selection")
        document["transport_guard"] = "disarmed" if guard_disarmed else "armed"
        document["source_hashes"] = {
            relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in SOURCE_PATHS
        }
        scenario_path = Path(self.temporary.name) / ("worker-scenario-" + uuid4().hex + ".json")
        scenario_path.write_text(json.dumps(document), encoding="utf-8")
        harness_path = Path(__file__).with_name("worker_process_harness.py").resolve()
        if not harness_path.is_file():
            raise RuntimeError("test-only process harness missing")
        if type(dotenv) is not bool:
            raise RuntimeError("invalid test-only dotenv trap selection")
        mounts = {
            "/harness/worker.py": str(harness_path),
            "/harness/scenario.json": str(scenario_path.resolve()),
        }
        if dotenv:
            trap = Path(self.temporary.name) / ("worker-dotenv-" + uuid4().hex + ".env")
            trap.write_text(
                "REMEDIATION_WORKER_ENABLED=true\n"
                "REMEDIATION_WORKER_ACCOUNT_ID=123456789012\n"
                "REMEDIATION_WORKER_REGION=us-east-1\n"
                "REMEDIATION_WORKER_ROLE_ARN=arn:aws:iam::123456789012:role/remediation-worker\n"
                "REMEDIATION_WORKER_DATABASE_URL=sqlite:///synthetic-sensitive-dotenv.db\n"
                "DATABASE_URL=sqlite:///synthetic-sensitive-scanner.db\n"
                "AWS_PROFILE=synthetic-sensitive-profile\n",
                encoding="utf-8",
            )
            mounts["/app/.env"] = str(trap.resolve())
        name = self.owner + "-worker-" + uuid4().hex
        self._reserve(name, "worker")
        args = [
            "create",
            "--name",
            name,
            "--label",
            OWNER_LABEL + "=" + self.owner,
            "--label",
            KIND_LABEL + "=worker",
            "--network",
            self.owner,
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
        for field in sorted(worker_env):
            args.extend(["--env", field])
        args.extend([self.image, "python", "/harness/worker.py", "/harness/scenario.json"])
        primary = None
        try:
            self._docker(*args, env=worker_env)
            self._worker_security(name, mounts)
            result = self._docker("start", "--attach", name, timeout=90, check=False)
            state = json.loads(
                self._docker(
                    "container",
                    "inspect",
                    "--format",
                    '{"running":{{json .State.Running}},"exit_code":{{json .State.ExitCode}},'
                    '"status":{{json .State.Status}}}',
                    name,
                ).stdout
            )
            if (
                state.get("running") is not False
                or state.get("status") != "exited"
                or type(state.get("exit_code")) is not int
                or state["exit_code"] != result.returncode
            ):
                raise RuntimeError("owned process terminal state mismatch")
            if result.stderr:
                raise RuntimeError("unexpected container process stderr")
            try:
                report = json.loads(result.stdout)
            except ValueError:
                raise RuntimeError("missing or malformed offline process report") from None
            validate_process_report(
                report,
                document["source_hashes"],
                result.returncode,
                [entry[0] for entry in document["responses"]],
                application=application,
            )
            return report
        except BaseException as error:
            primary = error
            raise
        finally:
            cleanup_preserving_primary(lambda: self._remove_worker(name), primary)

    def cleanup(self):
        failed = False
        for name, kind in reversed(self.possible_resources):
            try:
                if not self._exists(name, kind):
                    continue
                require_owned_labels(self.owner, name, kind, self._labels(name, kind))
                if kind == "network":
                    self._docker("network", "rm", name)
                else:
                    self._docker("container", "rm", "--force", name)
                if self._exists(name, kind):
                    raise RuntimeError("owned offline resource remains")
            except BaseException:
                failed = True
        if self.temporary is not None:
            try:
                self.temporary.cleanup()
            except BaseException:
                failed = True
        if failed:
            raise RuntimeError("owned offline process cleanup failed")

    def __enter__(self):
        try:
            return self.start()
        except BaseException as error:
            cleanup_preserving_primary(self.cleanup, error)
            raise

    def __exit__(self, kind, value, traceback):
        cleanup_preserving_primary(self.cleanup, value)
        return False
