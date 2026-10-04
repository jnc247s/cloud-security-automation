"""Run local acceptance gates with an isolated, automatically cleaned PostgreSQL runtime."""

from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
from pathlib import Path
from time import monotonic, sleep
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, env=None, capture=False, check=True):
    return subprocess.run(args, cwd=ROOT, env=env, check=check, text=True, capture_output=capture)


def validate(focused: list[str], *, dashboard: bool = False) -> None:
    """Never reuse DATABASE_URL or TEST_DATABASE_URL for the disposable test database."""
    run("docker", "info", "--format", "{{.ServerVersion}}", capture=True)
    name = f"cloudsec-validation-{uuid4().hex}"
    password = secrets.token_hex(24)
    env = dict(os.environ, POSTGRES_PASSWORD=password)
    created = False
    try:
        # Password is passed through the child environment, never printed or put in argv.
        run(
            "docker",
            "run",
            "--detach",
            "--name",
            name,
            "--label",
            f"cloudsec.validation={name}",
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
            env=env,
            capture=True,
        )
        created = True
        endpoint = run("docker", "port", name, "5432", capture=True).stdout.strip()
        if not endpoint.startswith("127.0.0.1:") or not endpoint.split(":")[-1].isdigit():
            raise RuntimeError("Disposable PostgreSQL port was not bound to loopback")
        port = endpoint.split(":")[-1]
        env.pop("POSTGRES_PASSWORD", None)
        env["TEST_DATABASE_URL"] = (
            f"postgresql+psycopg://cloudsec_test:{password}@127.0.0.1:{port}/cloudsec_test"
        )
        env["DASHBOARD_ENABLED"] = "false"
        deadline = monotonic() + 60
        while run(
            "docker",
            "exec",
            name,
            "pg_isready",
            "-h",
            "127.0.0.1",
            "-U",
            "cloudsec_test",
            "-d",
            "cloudsec_test",
            capture=True,
            check=False,
        ).returncode:
            if monotonic() >= deadline:
                raise RuntimeError("Disposable PostgreSQL did not become ready within 60 seconds")
            sleep(0.25)
        if focused:
            print("Running focused acceptance checks", flush=True)
            run(sys.executable, "-m", "pytest", *focused, "-q", env=env)
        if dashboard:
            pnpm = "pnpm.cmd" if os.name == "nt" else "pnpm"
            for gate in ("typecheck", "lint", "test", "build"):
                run(pnpm, "--dir", "frontend", gate, env=env)
            browser_env = dict(env, DASHBOARD_BROWSER_TEST="1", PYTHON_EXECUTABLE=sys.executable)
            run(pnpm, "--dir", "frontend", "test:browser", env=browser_env)
        run(sys.executable, "-m", "ruff", "check", ".")
        run(sys.executable, "-m", "ruff", "format", "--check", ".")
        print("Running complete regression with disposable PostgreSQL", flush=True)
        run(sys.executable, "-m", "pytest", env=env)
        run("git", "diff", "--check")
        run("docker", "compose", "config", "--quiet")
        run("docker", "build", "-t", "cloud-security-automation:validation", ".")
    finally:
        if created:
            # Only the exact uniquely named container created above; no volumes or user DBs.
            run("docker", "rm", "--force", name, capture=True)
            print(
                "Removed disposable validation database; user databases were untouched.", flush=True
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--focused", nargs="+", default=[], help="Focused pytest paths/node IDs")
    parser.add_argument(
        "--dashboard", action="store_true", help="Include real browser/issuer/PostgreSQL acceptance"
    )
    args = parser.parse_args()
    try:
        validate(args.focused, dashboard=args.dashboard)
    except (subprocess.CalledProcessError, OSError, RuntimeError):
        # Do not dump child environments or database credentials on failure.
        print(
            "Validation failed; see the preceding gate output. No success is claimed.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
