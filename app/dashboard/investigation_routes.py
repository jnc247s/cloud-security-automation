"""Explicit typed GET allowlist; no client-selected upstream URL, method or headers."""

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request

from app.assessment.models import AssessmentResult
from app.assessment.relationships import RelationshipResolution, RelationshipType
from app.assessment.source_outcomes import EvidenceCollectionPhase, EvidenceSourceState
from app.models.enums import ExceptionStatus, FindingStatus

if TYPE_CHECKING:
    from app.dashboard.routes import Dashboard

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]
Account = Annotated[str | None, Query(pattern=r"^[0-9]{12}$")]
Name = Annotated[str | None, Query(min_length=1, max_length=128)]


def parameters(request: Request, **values) -> dict:
    if set(request.query_params) - set(values):
        raise HTTPException(422, "Unsupported dashboard parameter")
    if any(len(request.query_params.getlist(key)) != 1 for key in request.query_params):
        raise HTTPException(422, "Duplicate dashboard parameter")
    return {key: value for key, value in values.items() if value is not None}


def install_investigation(router: APIRouter, boundary: "Dashboard") -> None:
    @router.get("/api/assessments")
    async def assessments(
        request: Request,
        scan_id: UUID,
        resource_id: UUID | None = None,
        control_id: UUID | None = None,
        result: AssessmentResult | None = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ):
        return await boundary.read(
            request,
            "/api/v1/assessments",
            parameters(
                request,
                scan_id=scan_id,
                resource_id=resource_id,
                control_id=control_id,
                result=result,
                limit=limit,
                offset=offset,
            ),
        )

    @router.get("/api/assessments/{assessment_id}")
    async def assessment(request: Request, assessment_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/assessments/{assessment_id}")

    @router.get("/api/resources/{resource_id}")
    async def resource(request: Request, resource_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/resources/{resource_id}")

    @router.get("/api/resources/{resource_id}/history")
    async def history(
        request: Request, resource_id: UUID, scan_id: UUID, limit: Limit = 25, offset: Offset = 0
    ):
        return await boundary.read(
            request,
            f"/api/v1/resources/{resource_id}/history",
            parameters(request, scan_id=scan_id, limit=limit, offset=offset),
        )

    @router.get("/api/controls/{control_id}")
    async def control(request: Request, control_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/controls/{control_id}")

    @router.get("/api/findings")
    async def findings(
        request: Request,
        account_id: Account = None,
        resource_id: UUID | None = None,
        control_id: UUID | None = None,
        status: FindingStatus | None = None,
        region: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ):
        return await boundary.read(
            request,
            "/api/v1/findings",
            parameters(
                request,
                account_id=account_id,
                resource_id=resource_id,
                control_id=control_id,
                status=status,
                region=region,
                limit=limit,
                offset=offset,
            ),
            operational=True,
        )

    @router.get("/api/findings/{finding_id}")
    async def finding(request: Request, finding_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/findings/{finding_id}", operational=True)

    @router.get("/api/exceptions")
    async def exceptions(
        request: Request,
        finding_id: UUID | None = None,
        resource_id: UUID | None = None,
        control_id: UUID | None = None,
        status: ExceptionStatus | None = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ):
        return await boundary.read(
            request,
            "/api/v1/exceptions",
            parameters(
                request,
                finding_id=finding_id,
                resource_id=resource_id,
                control_id=control_id,
                status=status,
                limit=limit,
                offset=offset,
            ),
            operational=True,
        )

    @router.get("/api/source-outcomes")
    async def outcomes(
        request: Request,
        scan_id: UUID,
        collection_account_id: Account = None,
        contract_key: Name = None,
        collector: Name = None,
        phase: EvidenceCollectionPhase | None = None,
        subject_resource_id: UUID | None = None,
        evidence_kind: Name = None,
        state: EvidenceSourceState | None = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ):
        return await boundary.read(
            request,
            "/api/v1/source-outcomes",
            parameters(
                request,
                scan_id=scan_id,
                collection_account_id=collection_account_id,
                contract_key=contract_key,
                collector=collector,
                phase=phase,
                subject_resource_id=subject_resource_id,
                evidence_kind=evidence_kind,
                state=state,
                limit=limit,
                offset=offset,
            ),
        )

    @router.get("/api/source-outcomes/{source_outcome_id}")
    async def outcome(request: Request, source_outcome_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/source-outcomes/{source_outcome_id}")

    @router.get("/api/relationships")
    async def relationships(
        request: Request,
        scan_id: UUID,
        collection_account_id: Account = None,
        relationship_id: UUID | None = None,
        source_resource_id: UUID | None = None,
        target_resource_id: UUID | None = None,
        target_reference_id: UUID | None = None,
        relationship_type: RelationshipType | None = None,
        resolution: RelationshipResolution | None = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ):
        return await boundary.read(
            request,
            "/api/v1/relationships",
            parameters(
                request,
                scan_id=scan_id,
                collection_account_id=collection_account_id,
                relationship_id=relationship_id,
                source_resource_id=source_resource_id,
                target_resource_id=target_resource_id,
                target_reference_id=target_reference_id,
                relationship_type=relationship_type,
                resolution=resolution,
                limit=limit,
                offset=offset,
            ),
        )

    @router.get("/api/relationships/{observation_id}")
    async def relationship(request: Request, observation_id: UUID):
        parameters(request)
        return await boundary.read(request, f"/api/v1/relationships/{observation_id}")
