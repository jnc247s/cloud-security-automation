"""Container cleanup and security require the exact owning handle, not a broad selector."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from tests.dashboard_integrated_container import BROWSER_LABEL, require_browser_owned


def owned(tmp_path):
    runtime = SimpleNamespace(
        owner="cloudsec-worker-process-" + "a" * 32,
        database_name="cloudsec-worker-process-" + "a" * 32 + "-db",
        _assert_database_owned=lambda: None,
        _docker=lambda *_args: SimpleNamespace(stdout="d" * 64),
    )
    name, image = runtime.owner + "-browser-" + "b" * 32, "sha256:" + "c" * 64
    value = {
        "Name": "/" + name,
        "Image": image,
        "Config": {"User": "pwuser", "Labels": {BROWSER_LABEL: name}},
        "HostConfig": {
            "NetworkMode": "container:" + runtime.database_name,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges"],
            "PortBindings": None,
        },
        "Mounts": [
            {
                "Type": "bind",
                "Destination": "/integrated-replies",
                "Source": str(tmp_path.resolve()).replace("\\", "/"),
                "RW": False,
            }
        ],
    }
    return runtime, name, image, value


@pytest.mark.parametrize("namespace", ["name", "resolved-id"])
def test_exact_read_only_reply_mount_and_owned_namespace(tmp_path, namespace):
    runtime, name, image, value = owned(tmp_path)
    if namespace == "resolved-id":
        value["HostConfig"]["NetworkMode"] = "container:" + "d" * 64
    require_browser_owned(runtime, name, value, tmp_path, image)


@pytest.mark.parametrize(
    "case",
    [
        "name",
        "label",
        "image",
        "user",
        "network",
        "privileged",
        "caps",
        "caps-add",
        "security",
        "ports",
        "mount-count",
        "mount-type",
        "mount-target",
        "mount-source",
        "mount-write",
    ],
)
def test_other_handles_or_broader_privileges_cannot_be_adopted_or_removed(tmp_path, case):
    runtime, name, image, original = owned(tmp_path)
    value = deepcopy(original)
    if case in {"name", "image"}:
        value["Name" if case == "name" else "Image"] = "foreign"
    elif case == "label":
        value["Config"]["Labels"] = {}
    elif case == "user":
        value["Config"]["User"] = "root"
    elif case.startswith("mount-"):
        if case == "mount-count":
            value["Mounts"].append(dict(value["Mounts"][0]))
        else:
            field = {
                "mount-type": "Type",
                "mount-target": "Destination",
                "mount-source": "Source",
                "mount-write": "RW",
            }[case]
            value["Mounts"][0][field] = True if case == "mount-write" else "foreign"
    else:
        field, changed = {
            "network": ("NetworkMode", "host"),
            "privileged": ("Privileged", True),
            "caps": ("CapDrop", []),
            "caps-add": ("CapAdd", ["SYS_ADMIN"]),
            "security": ("SecurityOpt", []),
            "ports": ("PortBindings", {"9031/tcp": []}),
        }[case]
        value["HostConfig"][field] = changed
    with pytest.raises(RuntimeError, match="ownership/security mismatch"):
        require_browser_owned(runtime, name, value, tmp_path, image)
