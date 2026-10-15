"""Fixed typed remediation history reads; never approval, admission or AWS dispatch."""

from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import APIRouter, Request

from app.dashboard.investigation_routes import Account, Limit, Offset, parameters

if TYPE_CHECKING:
    from app.dashboard.routes import Dashboard


def install_remediation_reads(router: APIRouter, boundary: "Dashboard") -> None:
    @router.get("/api/remediations")
    async def proposals(
        request: Request,
        finding_id: UUID | None = None,
        account_id: Account = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ):
        return await boundary.read(
            request,
            "/api/v1/remediations",
            parameters(
                request, finding_id=finding_id, account_id=account_id, limit=limit, offset=offset
            ),
        )

    @router.get("/api/remediations/{proposal_id}")
    async def proposal(request: Request, proposal_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/remediations/{proposal_id}")

    @router.get("/api/remediation-executions")
    async def executions(
        request: Request, proposal_id: UUID | None = None, limit: Limit = 25, offset: Offset = 0
    ):
        return await boundary.read(
            request,
            "/api/v1/remediation-executions",
            parameters(request, proposal_id=proposal_id, limit=limit, offset=offset),
        )

    @router.get("/api/remediation-executions/{execution_id}")
    async def execution(request: Request, execution_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/remediation-executions/{execution_id}")

    @router.get("/api/remediation-verifications")
    async def verifications(
        request: Request, execution_id: UUID | None = None, limit: Limit = 25, offset: Offset = 0
    ):
        return await boundary.read(
            request,
            "/api/v1/remediation-verifications",
            parameters(request, execution_id=execution_id, limit=limit, offset=offset),
        )

    @router.get("/api/remediation-verifications/{verification_id}")
    async def verification(request: Request, verification_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/remediation-verifications/{verification_id}")
