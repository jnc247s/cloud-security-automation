"""Callback codes and identity-client debug payloads cannot escape the dashboard boundary."""

import asyncio
import logging

import pytest

from app.dashboard.logging import IdentityHTTPFilter
from app.dashboard.middleware import DashboardSecurityMiddleware


def test_identity_debug_logs_omit_headers_payloads_and_exception_details():
    for name in ("httpx2", "httpcore2.connection", "authlib.client"):
        record = logging.LogRecord(name, logging.DEBUG, __file__, 1, "secret %s", ("token",), None)
        record.exc_text = "private exception"
        record.stack_info = "private stack"
        assert IdentityHTTPFilter().filter(record)
        assert record.getMessage() == "Identity-provider/internal HTTP exchange (details omitted)"
        assert record.exc_text is None and record.stack_info is None and record.exc_info is None
    record = logging.LogRecord("app", logging.INFO, __file__, 1, "safe %s", ("health",), None)
    assert IdentityHTTPFilter().filter(record) and record.getMessage() == "safe health"


def test_callback_query_is_consumed_before_response_access_logging():
    scope = {"type": "http", "path": "/dashboard/auth/callback", "query_string": b"code=private"}
    observed = []

    async def application(scope, receive, send):
        assert scope["query_string"] == b"code=private"
        await send({"type": "http.response.start", "status": 303, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def send(message):
        observed.append((scope["query_string"], message))

    asyncio.run(DashboardSecurityMiddleware(application)(scope, None, send))
    assert all(query == b"" for query, _ in observed)
    headers = dict(observed[0][1]["headers"])
    assert headers[b"cache-control"] == b"no-store"
    assert headers[b"referrer-policy"] == b"no-referrer"
    assert b"frame-ancestors 'none'" in headers[b"content-security-policy"]


@pytest.mark.parametrize("started", [False, True])
def test_unexpected_dashboard_errors_remain_observable_and_do_not_duplicate_responses(started):
    scope = {"type": "http", "path": "/dashboard/auth/callback", "query_string": b"code=private"}
    observed = []

    async def application(scope, receive, send):
        if started:
            await send({"type": "http.response.start", "status": 200, "headers": []})
        raise RuntimeError("Controlled programming failure")

    async def send(message):
        observed.append((scope["query_string"], message))

    with pytest.raises(RuntimeError, match="Controlled programming failure"):
        asyncio.run(DashboardSecurityMiddleware(application)(scope, None, send))
    starts = [
        (query, message) for query, message in observed if message["type"] == "http.response.start"
    ]
    assert len(starts) == 1
    assert starts[0][0] == b""
    assert starts[0][1]["status"] == (200 if started else 500)
    assert dict(starts[0][1]["headers"])[b"cache-control"] == b"no-store"
    assert scope["query_string"] == b""
