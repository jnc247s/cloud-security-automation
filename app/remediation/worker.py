"""Separate, default-off single-job process. Never part of API/scanner startup."""

import logging
import sys
from uuid import UUID

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.remediation.worker_config import WorkerSettings
from app.remediation.worker_driver import RemediationWorker


def main(argv=None) -> int:
    # This dedicated process prints fixed classifications only. SDK DEBUG/warning tracebacks
    # may include signed headers, credential responses or sensitive configuration; no logging
    # from dependencies is permitted here. This never changes API/scanner logging.
    logging.disable(logging.CRITICAL)
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["--help"], ["-h"]):
        print(
            "Process one explicitly admitted remediation job: python -m app.remediation.worker UUID"
        )
        return 0
    try:
        if len(args) != 1:
            raise ValueError("one execution UUID required")
        execution_id = UUID(args[0])
    except (ValueError, TypeError, AttributeError):
        print("WORKER_INVALID_ARGUMENT")
        return 2
    try:
        settings = WorkerSettings()
        if not settings.enabled:
            print("WORKER_DISABLED")
            return 0
        url = make_url(settings.database_url)
        if url.get_backend_name() != "postgresql":
            print("WORKER_CONFIGURATION_REJECTED")
            return 1
        engine = create_engine(url, pool_pre_ping=True, connect_args={"connect_timeout": 5})
        try:
            sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
            result = RemediationWorker(sessions, scope=settings.scope).run(execution_id)
        finally:
            engine.dispose()
        print(result.value)
        return 0
    except Exception:
        # Never print exception/URL/response/evidence, even for unexpected provider/SQL failures.
        print("WORKER_UNAVAILABLE")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
