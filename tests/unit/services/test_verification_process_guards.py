"""Independent malformed-proof/container checks for the test-only installed reader launcher."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.database.integrity import canonical_json_sha256
from app.remediation.verification_contracts import (
    VerificationContent,
    VerificationReceipt,
    VerificationView,
)
from tests.verification_process_harness import READER_ROLE
from tests.verification_process_runtime import (
    reader_security,
    source_hashes,
    validate_reader_report,
)

IMAGE = "sha256:" + "a" * 64
NETWORK = "cloudsec-worker-process-" + "a" * 32


def view():
    now = datetime.now(UTC)
    content = VerificationContent(
        verification_id=uuid4(),
        execution_id=uuid4(),
        execution_sha256="a" * 64,
        acknowledgment_event_id=uuid4(),
        acknowledgment_sha256="b" * 64,
        acknowledged_at=now - timedelta(seconds=1),
        baseline_scan_id=uuid4(),
        scan_id=uuid4(),
        attempt=1,
        account_id="123456789012",
        region="us-east-1",
        requested_services=("ec2",),
        requested_collectors=("ec2_ebs_evidence",),
        resource_types=("aws_account",),
        profile_id="default",
        profile_version="6.3.0",
        profile_sha256="c" * 64,
        catalog_id="aws-cloud-security-controls",
        catalog_version="0.5.0",
        catalog_sha256="d" * 64,
        requested_by={
            "issuer": "https://identity.example.test",
            "subject": "verification-operator",
            "roles": ("ADMIN",),
            "capability": "EXECUTE",
        },
        idempotency_key=uuid4(),
        created_at=now,
        reason="Synthetic guard proof only.",
    )
    digest = canonical_json_sha256(content.model_dump(mode="json"))
    receipt = VerificationReceipt.model_validate_json(
        __import__("json").dumps(
            {
                "verification_id": str(content.verification_id),
                "verification_sha256": digest,
                "scan_id": str(content.scan_id),
                "scan_status": "FAILED",
                "result_sha256": "e" * 64,
                "inventory_sha256": None,
                "outcome": "INCONCLUSIVE",
                "reason": "SCAN_INCOMPLETE",
                "evidence": None,
                "created_at": now.isoformat(),
            }
        )
    )
    return VerificationView(
        content=content,
        verification_sha256=digest,
        request_audit_event_id=uuid4(),
        receipt=receipt,
        receipt_sha256=canonical_json_sha256(receipt.model_dump(mode="json")),
        receipt_audit_event_id=uuid4(),
    )


def report():
    complete = view()
    return {
        "schema_version": 1,
        "exit_code": 0,
        "errors": [],
        "stage": "complete",
        "calls": ["sts:GetCallerIdentity"],
        "boundaries": ["submit", "provider", "metadata", "sdk:sts:GetCallerIdentity"],
        "submissions": [str(complete.content.scan_id)],
        "metadata_requests": 1,
        "credential_methods": ["container-role"],
        "credential_fingerprints": ["f" * 64],
        "reader_role_arn": READER_ROLE,
        "writer_constructions": 0,
        "host_file_reads": 0,
        "source_hashes": source_hashes(),
        "locations": {
            "app": "/usr/local/lib/python3.12/site-packages/app",
            "boto3": "/usr/local/lib/python3.12/site-packages/boto3/__init__.py",
            "botocore": "/usr/local/lib/python3.12/site-packages/botocore/__init__.py",
        },
        "versions": {"python": "3.12.15", "boto3": "1.40.0", "botocore": "1.40.0"},
        "uid": 101,
        "security": {"no_new_privileges": 1, "effective_capabilities": "0000000000000000"},
        "api_checks": {
            "/health": "healthy",
            "/ready": "ready",
            "/openapi.json": "Cloud Security Control Plane",
            "bearer_schema": True,
        },
        "pending": None,
        "complete": complete.model_dump(mode="json"),
        "env_names": ["APP_ENV", "AUTH_MODE", "DATABASE_URL"],
        "error_location": None,
        "stdout_bytes": 0,
        "stderr_bytes": 120,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "schema-bool",
        "uid-bool",
        "source-missing",
        "source-changed",
        "worker-env",
        "static-key",
        "write-call",
        "bad-service",
        "no-metadata-boundary",
        "metadata-bool",
        "bad-role",
        "wrong-method",
        "bad-fingerprint",
        "writer-constructed",
        "host-file",
        "shadowed-source",
        "bad-version",
        "security-bool",
        "extra-submission",
        "wrong-submission",
        "unbounded-calls",
        "wrong-receipt",
        "auth-schema-bool",
        "duplicate-env",
    ],
)
def test_reader_report_rejects_each_malformed_boundary(mutation):
    original = report()
    hashes = dict(original["source_hashes"])
    validate_reader_report(original, hashes, 0, "observe")
    altered = deepcopy(original)
    if mutation == "schema-bool":
        altered["schema_version"] = True
    elif mutation == "uid-bool":
        altered["uid"] = True
    elif mutation == "source-missing":
        altered["source_hashes"].pop("app/main.py")
    elif mutation == "source-changed":
        altered["source_hashes"]["app/main.py"] = "0" * 64
    elif mutation == "worker-env":
        altered["env_names"].append("REMEDIATION_WORKER_ROLE_ARN")
    elif mutation == "static-key":
        altered["env_names"].append("AWS_ACCESS_KEY_ID")
    elif mutation == "write-call":
        altered["calls"] = ["ec2:EnableEbsEncryptionByDefault"]
    elif mutation == "bad-service":
        altered["calls"] = ["unknown:GetCallerIdentity"]
    elif mutation == "no-metadata-boundary":
        altered["boundaries"].remove("metadata")
    elif mutation == "metadata-bool":
        altered["metadata_requests"] = True
    elif mutation == "bad-role":
        altered["reader_role_arn"] = READER_ROLE.replace(
            "offline-scanner-reader", "remediation-worker"
        )
    elif mutation == "wrong-method":
        altered["credential_methods"] = ["env"]
    elif mutation == "bad-fingerprint":
        altered["credential_fingerprints"] = ["not-a-digest"]
    elif mutation == "writer-constructed":
        altered["writer_constructions"] = 1
    elif mutation == "host-file":
        altered["host_file_reads"] = 1
    elif mutation == "shadowed-source":
        altered["locations"]["app"] = "/harness/app"
    elif mutation == "bad-version":
        altered["versions"]["python"] = "unknown"
    elif mutation == "security-bool":
        altered["security"]["no_new_privileges"] = True
    elif mutation == "extra-submission":
        altered["submissions"].append(str(uuid4()))
    elif mutation == "wrong-submission":
        altered["submissions"] = [str(uuid4())]
    elif mutation == "unbounded-calls":
        altered["calls"] *= 129
    elif mutation == "wrong-receipt":
        altered["complete"]["receipt"]["scan_id"] = str(uuid4())
    elif mutation == "auth-schema-bool":
        altered["api_checks"]["bearer_schema"] = 1
    elif mutation == "duplicate-env":
        altered["env_names"].append("APP_ENV")
    with pytest.raises(RuntimeError):
        validate_reader_report(altered, hashes, 0, "observe")


def container():
    mounts = {
        "/harness/reader.py": "/workspace/reader.py",
        "/harness/scenario.json": "/workspace/scenario.json",
    }
    return mounts, {
        "image": IMAGE,
        "user": "app",
        "cmd": ["python", "/harness/reader.py", "/harness/scenario.json"],
        "entrypoint": None,
        "read_only": True,
        "privileged": False,
        "caps": ["ALL"],
        "caps_add": None,
        "security": ["no-new-privileges"],
        "network": NETWORK,
        "ports": {},
        "tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"},
        "mounts": [
            {
                "Type": "bind",
                "Destination": destination,
                "Source": source,
                "RW": False,
                "Propagation": "rprivate",
            }
            for destination, source in mounts.items()
        ],
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "writable",
        "root",
        "privileged",
        "caps",
        "network",
        "port",
        "writable-mount",
        "worker-alias",
        "source",
        "command",
    ],
)
def test_reader_container_adapter_preserves_every_security_guard(mutation):
    mounts, valid = container()
    reader_security(valid, IMAGE, NETWORK, mounts)
    value = deepcopy(valid)
    if mutation == "writable":
        value["read_only"] = False
    elif mutation == "root":
        value["user"] = "root"
    elif mutation == "privileged":
        value["privileged"] = True
    elif mutation == "caps":
        value["caps_add"] = ["SYS_ADMIN"]
    elif mutation == "network":
        value["network"] = "bridge"
    elif mutation == "port":
        value["ports"] = {"8158/tcp": [{"HostPort": "8158"}]}
    elif mutation == "writable-mount":
        value["mounts"][0]["RW"] = True
    elif mutation == "worker-alias":
        value["mounts"][0]["Destination"] = "/harness/worker.py"
    elif mutation == "source":
        value["mounts"][0]["Source"] = "/workspace/unplanned.py"
    elif mutation == "command":
        value["cmd"][1] = "/harness/worker.py"
    with pytest.raises(RuntimeError):
        reader_security(value, IMAGE, NETWORK, mounts)


@pytest.mark.parametrize(
    "mutation", ["stage", "terminal", "only-sts", "credentials", "extra-call", "boundary"]
)
def test_collection_interruption_report_requires_real_reader_sdk_boundary(mutation):
    valid = report()
    valid["exit_code"] = 90
    valid["stage"] = "crash-during-collection"
    valid["pending"] = deepcopy(valid["complete"])
    for field in ("receipt", "receipt_sha256", "receipt_audit_event_id"):
        valid["pending"][field] = None
    valid["complete"] = None
    valid["calls"] = ["sts:GetCallerIdentity", "s3:ListBuckets"]
    valid["boundaries"] = [
        "submit",
        "provider",
        "metadata",
        *["sdk:" + call for call in valid["calls"]],
    ]
    valid["credential_methods"] = ["container-role", "container-role"]
    valid["credential_fingerprints"] = ["f" * 64, "f" * 64]
    hashes = source_hashes()
    validate_reader_report(valid, hashes, 90, "crash-collection")
    value = deepcopy(valid)
    if mutation == "stage":
        value["stage"] = "crash-before-provider"
    elif mutation == "terminal":
        value["complete"] = report()["complete"]
    elif mutation == "only-sts":
        value["calls"] = ["sts:GetCallerIdentity"]
        value["boundaries"] = ["submit", "provider", "metadata", "sdk:sts:GetCallerIdentity"]
        value["credential_methods"] = ["container-role"]
        value["credential_fingerprints"] = ["f" * 64]
    elif mutation == "credentials":
        value["credential_methods"][1] = "env"
    elif mutation == "extra-call":
        value["calls"].append("s3:ListBuckets")
        value["boundaries"].append("sdk:s3:ListBuckets")
        value["credential_methods"].append("container-role")
        value["credential_fingerprints"].append("f" * 64)
    else:
        value["boundaries"].pop()
    with pytest.raises(RuntimeError):
        validate_reader_report(value, hashes, 90, "crash-collection")
