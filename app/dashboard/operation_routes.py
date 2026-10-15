"""Explicit session-bound preparation/confirmation, never a generic mutation proxy."""

import asyncio
import json
from typing import TYPE_CHECKING
from uuid import UUID

import httpx2 as httpx
from fastapi import APIRouter, HTTPException, Request

from app.dashboard.operation_results import ResultAuthenticationRejected, confirm_result
from app.dashboard.operations import (
    MAX_PREPARATION_BYTES,
    InvalidPreparation,
    OperationExpired,
    OperationUnavailable,
    PreparedOperation,
    parse_preparation,
    validate_json_document,
)
from app.dashboard.store import CapacityError, matches_opaque
from app.remediation.contracts import ACTION_RISK
from app.security.authorization import Capability, capabilities_for

if TYPE_CHECKING:
    from app.dashboard.routes import Dashboard

_SECURITY_HEADERS = frozenset(
    {
        "host",
        "origin",
        "sec-fetch-site",
        "x-csrf-token",
        "x-dashboard-context",
        "cookie",
        "authorization",
        "idempotency-key",
        "content-type",
        "content-length",
        "transfer-encoding",
    }
)


def operation_view(value: PreparedOperation) -> dict:
    """Only non-secret coordination and trusted references; no raw upstream responses."""
    return {
        "schema_version": "1.0.0",
        "operation_id": str(value.operation_id),
        "operation": value.input.kind.value,
        "target_id": str(value.input.target_id) if value.input.target_id else None,
        "input": json.loads(value.input.body_json),
        "actor": {"issuer": value.actor[0], "subject": value.actor[1]},
        "risk_summary": ACTION_RISK,
        "prepared_at": value.prepared_at,
        "expires_at": value.expires_at,
        "state": value.state.value,
        "attempts": value.attempts,
        "result": {
            "result_id": str(value.result.result_id),
            "scan_id": str(value.result.scan_id) if value.result.scan_id else None,
        }
        if value.result
        else None,
    }


def _checks(request: Request, boundary: "Dashboard", *, mutation: bool) -> None:
    if not boundary.settings.dashboard_remediation_enabled:
        raise HTTPException(404, "Dashboard operation unavailable")
    if request.query_params:
        raise HTTPException(422, "Unsupported dashboard operation parameter")
    for name in _SECURITY_HEADERS:
        values = request.headers.getlist(name)
        if len(values) > 1 or any(
            len(value) > (8192 if name == "cookie" else 4096) for value in values
        ):
            raise HTTPException(403, "Dashboard operation headers rejected")
    if any(
        name in request.headers
        for name in ("authorization", "idempotency-key", "transfer-encoding")
    ):
        raise HTTPException(403, "Dashboard operation headers rejected")
    cookies = request.headers.get("cookie", "").split(";")
    if sum(cookie.strip().partition("=")[0] == "cloudsec_session" for cookie in cookies) > 1:
        raise HTTPException(403, "Dashboard operation headers rejected")
    boundary.origin(request, mutation=mutation)
    if mutation and request.headers.get("sec-fetch-site") != "same-origin":
        raise HTTPException(403, "Dashboard operation origin rejected")


async def _body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "").lower().replace(" ", "")
    if content_type not in {"application/json", "application/json;charset=utf-8"}:
        raise HTTPException(415, "Dashboard operation requires JSON")
    length = request.headers.get("content-length")
    if length is not None and (not length.isascii() or not length.isdigit() or len(length) > 5):
        raise HTTPException(422, "Invalid dashboard operation body")
    if length is not None and int(length) > MAX_PREPARATION_BYTES:
        raise HTTPException(413, "Dashboard operation body too large")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_PREPARATION_BYTES:
            raise HTTPException(413, "Dashboard operation body too large")
        raw.extend(chunk)
    if length is not None and len(raw) != int(length):
        raise HTTPException(422, "Invalid dashboard operation body")
    return bytes(raw)


async def _identity(request: Request, boundary: "Dashboard", *, mutation: bool):
    identifier, session, principal = await boundary.verified_session(request)
    if not matches_opaque(session.context, request.headers.get("x-dashboard-context", "")):
        raise HTTPException(401, "Dashboard session changed")
    if mutation and not matches_opaque(session.csrf, request.headers.get("x-csrf-token", "")):
        raise HTTPException(403, "Dashboard operation confirmation rejected")
    if Capability.READ not in capabilities_for(principal):
        raise HTTPException(403, "Dashboard operation capability required")
    return identifier, session, principal


def _operation(boundary, identifier, principal, operation_id: str) -> PreparedOperation:
    try:
        parsed = UUID(operation_id)
        if str(parsed) != operation_id:
            raise ValueError
        return boundary.store.operation(identifier, principal, parsed)
    except (ValueError, OperationUnavailable):
        raise HTTPException(404, "Dashboard operation unavailable") from None


def install_operations(router: APIRouter, boundary: "Dashboard") -> None:
    @router.post("/api/remediation-operations", status_code=201)
    async def prepare(request: Request):
        _checks(request, boundary, mutation=True)
        raw = await _body(request)
        identifier, _, principal = await _identity(request, boundary, mutation=True)
        try:
            operation = parse_preparation(raw)
            if operation.capability not in capabilities_for(principal):
                raise HTTPException(403, "Dashboard operation capability required")
            return operation_view(boundary.store.prepare(identifier, principal, operation))
        except InvalidPreparation:
            raise HTTPException(422, "Invalid remediation preparation") from None
        except CapacityError:
            raise HTTPException(
                503, "Dashboard operation capacity reached; review existing history"
            ) from None
        except OperationUnavailable:
            raise HTTPException(401, "Dashboard sign-in required") from None

    @router.get("/api/remediation-operations")
    async def operations(request: Request):
        _checks(request, boundary, mutation=False)
        identifier, _, principal = await _identity(request, boundary, mutation=False)
        try:
            return {
                "schema_version": "1.0.0",
                "items": [
                    operation_view(value)
                    for value in boundary.store.operations(identifier, principal)
                ],
            }
        except OperationUnavailable:
            raise HTTPException(401, "Dashboard sign-in required") from None

    @router.get("/api/remediation-operations/{operation_id}")
    async def operation(request: Request, operation_id: str):
        _checks(request, boundary, mutation=False)
        identifier, _, principal = await _identity(request, boundary, mutation=False)
        return operation_view(_operation(boundary, identifier, principal, operation_id))

    @router.post("/api/remediation-operations/{operation_id}/submit")
    async def submit(request: Request, operation_id: str):
        _checks(request, boundary, mutation=True)
        raw = await _body(request)
        try:
            validate_json_document(raw)
            if json.loads(raw) != {}:
                raise ValueError
        except (ValueError, UnicodeError, RecursionError):
            raise HTTPException(422, "Confirmation cannot replace prepared input") from None
        identifier, session, principal = await _identity(request, boundary, mutation=True)
        prepared = _operation(boundary, identifier, principal, operation_id)
        if prepared.input.capability not in capabilities_for(principal):
            raise HTTPException(403, "Dashboard operation capability required")
        try:
            claimed, dispatch = boundary.store.claim(identifier, principal, prepared.operation_id)
        except OperationExpired:
            raise HTTPException(
                409, "Preparation expired; prior effects are not canceled"
            ) from None
        except OperationUnavailable:
            raise HTTPException(401, "Dashboard sign-in required") from None
        if not dispatch:
            return operation_view(claimed)
        reference = None
        try:
            async with (
                asyncio.timeout(15),
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=request.app, raise_app_exceptions=False),
                    base_url="http://internal.invalid",
                    follow_redirects=False,
                    trust_env=False,
                    headers={"Authorization": f"Bearer {session.access_token}"},
                ) as client,
            ):
                upstream = await client.post(
                    claimed.input.path,
                    content=claimed.input.body_json.encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Idempotency-Key": str(claimed.operation_id),
                    },
                )
                if upstream.status_code == 401:
                    boundary.store.revoke(identifier)
                else:
                    reference = await confirm_result(client, claimed, upstream)
        except ResultAuthenticationRejected:
            boundary.store.revoke(identifier)
        except (httpx.HTTPError, TimeoutError):
            pass  # No automatic retry or claim that an unknown forwarded outcome had no effect.
        finally:
            try:
                settled = boundary.store.settle(
                    identifier, principal, claimed.operation_id, claimed.attempts, reference
                )
            except OperationUnavailable:
                raise HTTPException(
                    401, "Dashboard sign-in required; reconcile prior requests in history"
                ) from None
        return operation_view(settled)
