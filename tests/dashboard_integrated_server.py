"""Server-only half of the owned native fixture; no Docker or write-identity access.

The guardian seeds retained evidence, not human authority. All grants arrive through genuine
browser OIDC/BFF/bearer requests. This child only opens an already submitted managed reader gate.
"""

import base64
import os
import secrets
import sys
import threading
import time
from contextlib import ExitStack
from urllib.parse import parse_qs

from tests.dashboard_integrated_authority_expiry import CommittedProposalExpiry, ProposalExpiryClock
from tests.dashboard_integrated_bootstrap import (
    AUDIENCE,
    CLIENT,
    ISSUER,
    ORIGIN,
    configure,
    identity_issuer,
    require_test_environment,
    server_database,
    server_static_assets,
)
from tests.dashboard_integrated_execution_expiry import (
    CommittedExecutionExpiry,
    ExecutionExpiryClock,
)
from tests.dashboard_integrated_expiry import CommittedPreparationExpiry, PreparationExpiryClock
from tests.dashboard_integrated_identity import (
    CommittedIdentitySubstitution,
    CommittedProposalCapabilityLoss,
)
from tests.dashboard_integrated_loss import (
    CommittedProposalInFlight,
    CommittedProposalReplyLoss,
    InFlightObserver,
)
from tests.dashboard_integrated_proof import assert_reader_sequence
from tests.dashboard_integrated_protocol import MAX_CONTROL_BYTES, ControlKind, parse_control
from tests.dashboard_integrated_reference import CommittedReferenceSubstitution
from tests.dashboard_integrated_scenarios import build_reader, reader_scenario
from tests.dashboard_integrated_session_expiry import (
    CommittedSessionExpiry,
    IdleExpiryClock,
    make_expiry_issuer,
)
from tests.dashboard_integrated_verification_faults import VerificationFault


def serve(instance, source, scenario, *, identity_phase="initial"):
    # Configuration and independently checked schema marker precede every application import.
    import boto3
    import uvicorn
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
    from sqlalchemy.orm import Session

    from app.database.session import engine
    from app.main import create_app
    from app.remediation.contracts import ProposalRequest
    from app.remediation.worker_aws import EbsDefaultWriter
    from app.remediation.worker_driver import RemediationWorker
    from app.security.authentication import Principal
    from app.services.remediation_verification_service import RemediationVerificationService
    from tests.dashboard_fixtures import ControlledIssuer
    from tests.verification_acceptance import ManagedReader

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Integrated API/reader cannot acquire a write identity or call AWS")

    boto3.client = forbidden
    boto3.session.Session.client = forbidden
    RemediationWorker.__init__ = forbidden
    EbsDefaultWriter.from_ecs = forbidden
    source = ProposalRequest.model_validate_json(source)
    scenario = reader_scenario(scenario)
    issuer_url = identity_issuer(identity_phase, scenario.name)
    managed = ManagedReader(engine, source, lambda: build_reader(scenario.name))
    managed.actor_subject = "requester"
    application = create_app(executor_factory=lambda: managed)
    if application.dependency_overrides:
        raise RuntimeError("Integrated browser acceptance requires genuine API authentication")
    issuer, provider, pending = (
        ControlledIssuer(issuer=issuer_url, audience=AUDIENCE),
        FastAPI(),
        {},
    )
    session_expiry = scenario.name in {"idle-expiry", "token-expiry"}
    if session_expiry:
        issuer = make_expiry_issuer(scenario.name, issuer=ISSUER, audience=AUDIENCE)
    idle_clock = IdleExpiryClock(ISSUER) if scenario.name == "idle-expiry" else None
    if idle_clock is not None:
        application.state.dashboard.store.clock = idle_clock
    expiry_clock = None
    if scenario.name in {"expiry-session", "expiry-global"}:
        # Test issuer chooses its initial lifetime; no token/session is extended later. The
        # accepted store's injectable clock can then cross preparation expiry before logout.
        issuer.access_overrides["exp"] = int(time.time()) + 3600
        expiry_clock = PreparationExpiryClock(
            ISSUER, 16 if scenario.name == "expiry-session" else 256
        )
        application.state.dashboard.store.clock = expiry_clock
    response_loss = (
        CommittedProposalReplyLoss(engine, issuer=issuer_url)
        if scenario.response_loss
        and not (scenario.name == "cross-issuer" and identity_phase == "secondary")
        else None
    )
    if session_expiry:
        response_loss = CommittedSessionExpiry(
            engine,
            issuer=issuer,
            store=application.state.dashboard.store,
            scenario=scenario.name,
            clock=idle_clock,
        )
    if scenario.name == "capability-loss":
        response_loss = CommittedProposalCapabilityLoss(
            engine, issuer=issuer, store=application.state.dashboard.store
        )
    if scenario.name in {"subject-replacement", "issuer-rejection"}:
        response_loss = CommittedIdentitySubstitution(
            engine, issuer=issuer, store=application.state.dashboard.store, scenario=scenario.name
        )
    if expiry_clock is not None:
        response_loss = CommittedPreparationExpiry(
            engine, issuer=ISSUER, store=application.state.dashboard.store, clock=expiry_clock
        )
    proposal_clock = ProposalExpiryClock(ISSUER) if scenario.name == "proposal-expiry" else None
    if proposal_clock is not None:
        response_loss = CommittedProposalExpiry(
            engine, issuer=ISSUER, store=application.state.dashboard.store, clock=proposal_clock
        )
    execution_clock = ExecutionExpiryClock(ISSUER) if scenario.name == "execution-expiry" else None
    execution_gate = (
        CommittedExecutionExpiry(
            engine, issuer=ISSUER, store=application.state.dashboard.store, clock=execution_clock
        )
        if execution_clock is not None
        else None
    )
    in_flight = (
        CommittedProposalInFlight(engine, issuer=ISSUER) if scenario.name == "in-flight" else None
    )
    reference_gate = (
        CommittedReferenceSubstitution(engine, issuer=issuer_url, scenario=scenario.name)
        if scenario.name in {"reply-reference", "history-reference"}
        else None
    )
    if in_flight is not None:
        application.add_middleware(InFlightObserver, gate=in_flight)
    verification_fault = (
        VerificationFault(engine, source, issuer=issuer_url, scenario=scenario.name)
        if scenario.name in {"verification-equal", "verification-provenance"}
        else None
    )
    secret = os.environ["DASHBOARD_CLIENT_SECRET"]

    @application.get("/__test/fixture")
    def fixture():
        from app.models import FindingOccurrence

        with Session(engine) as session:
            occurrence = session.get(FindingOccurrence, source.occurrence_id)
            return {
                "instance_id": instance,
                "finding_id": str(source.finding_id),
                "occurrence_id": str(source.occurrence_id),
                "scan_id": str(occurrence.scan_id),
                "assessment_id": str(occurrence.assessment_id),
                "scan_submissions": len(managed.submissions),
                "scenario": scenario.name,
                "proposal_response_losses": response_loss.losses if response_loss else 0,
                "proposal_reply_gate": in_flight.stage if in_flight is not None else "DISABLED",
            }

    @provider.get("/.well-known/openid-configuration")
    def discovery():
        return issuer.metadata()

    @provider.get("/jwks")
    def jwks():
        return {"keys": [issuer.jwk]}

    @provider.get("/authorize")
    def authorize(request: Request):
        query = dict(request.query_params)
        if (
            query.get("redirect_uri") != ORIGIN + "/dashboard/auth/callback"
            or query.get("client_id") != CLIENT
            or any(len(request.query_params.getlist(key)) != 1 for key in request.query_params)
        ):
            return JSONResponse({"error": "controlled authorization rejected"}, status_code=400)
        issuer.authorize(str(request.url))
        transaction = secrets.token_urlsafe(32)
        pending[transaction] = query
        prefix = "/issuer-b" if identity_phase == "secondary" else ""
        response = HTMLResponse(f"""<!doctype html><html lang="en">
          <title>Controlled integrated issuer</title><h1>Test-only integrated issuer</h1>
          <form method="get" action="{prefix}/approve"><label for="identity">Test identity</label>
          <select id="identity" name="identity"><option value="proposer">proposer</option>
          <option value="approver">approver</option><option value="requester">requester</option>
          <option value="viewer">viewer</option></select><button>Approve test login</button>
          </form></html>""")
        response.set_cookie(
            "test_integrated_transaction", transaction, httponly=True, samesite="lax"
        )
        return response

    @provider.get("/approve")
    def approve(request: Request, identity: str = "proposer"):
        query = pending.pop(request.cookies.get("test_integrated_transaction", ""), None)
        roles = {
            "proposer": "ANALYST",
            "approver": "APPROVER",
            "requester": "ADMIN",
            "viewer": "VIEWER",
        }
        if scenario.name == "cross-issuer" and identity_phase == "secondary":
            roles["proposer"] = "ADMIN"
        if not query or identity not in roles:
            return JSONResponse({"error": "controlled authorization rejected"}, status_code=400)
        code = secrets.token_urlsafe(32)
        issuer.codes[code] = {key: [value] for key, value in query.items()}
        subject = (
            "proposer"
            if scenario.name == "cross-issuer"
            and identity_phase == "secondary"
            and identity == "approver"
            else identity
        )
        issuer.grants[code] = (roles[identity], subject)
        return RedirectResponse(
            f"{ORIGIN}/dashboard/auth/callback?code={code}&state={query['state']}", status_code=303
        )

    @provider.post("/token")
    async def token(request: Request):
        expected = "Basic " + base64.b64encode(f"{CLIENT}:{secret}".encode()).decode()
        form = parse_qs((await request.body()).decode())
        if request.headers.get("authorization") != expected or form.get("redirect_uri") != [
            ORIGIN + "/dashboard/auth/callback"
        ]:
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        status, body = issuer.token_response(form)
        return JSONResponse(body, status_code=status)

    provider_root = provider
    if identity_phase == "secondary":
        provider_root = FastAPI()
        provider_root.mount("/issuer-b", provider)
    servers = [
        uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, access_log=False, log_level="warning")
        )
        for app, port in ((provider_root, 9032), (application, 9031))
    ]
    threads = [threading.Thread(target=server.run, daemon=True) for server in servers]
    transport_stack = ExitStack()
    try:
        if proposal_clock is not None:
            transport_stack.enter_context(proposal_clock.installed())
        if execution_clock is not None:
            transport_stack.enter_context(execution_clock.installed())
            transport_stack.enter_context(execution_gate.installed())
        if response_loss is not None:
            transport_stack.enter_context(response_loss.installed())
        if in_flight is not None:
            transport_stack.enter_context(in_flight.installed())
        if reference_gate is not None:
            transport_stack.enter_context(reference_gate.installed())
        if verification_fault is not None:
            transport_stack.enter_context(verification_fault.installed())
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 15
        while not all(server.started for server in servers):
            if time.monotonic() > deadline or any(not thread.is_alive() for thread in threads):
                raise RuntimeError("Integrated server readiness failed")
            time.sleep(0.05)
        print("INTEGRATED_SERVER_READY", flush=True)
        while True:
            raw = sys.stdin.buffer.readline(MAX_CONTROL_BYTES + 1)
            if not raw:
                break
            message = parse_control(raw, expected_instance=instance)
            if message.kind is ControlKind.STOP:
                break
            if message.kind is not ControlKind.RELEASE_READER:
                raise ValueError("Server cannot launch a write worker")
            with Session(engine) as session:
                principal = Principal("server-gate-reader", frozenset({"VIEWER"}), issuer_url)
                service = RemediationVerificationService(session)
                view = service.get_verification(message.target_id, principal)
                page = service.list_verifications(principal, execution_id=view.content.execution_id)
                values = sorted(page.items, key=lambda value: value.content.attempt)
            if (
                view.content.idempotency_key != message.request_id
                or view.receipt is not None
                or page.total != len(values)
                or values[-1].content.verification_id != message.target_id
                or not managed.entered.wait(5)
            ):
                raise ValueError("Managed gate does not match accepted verification")
            assert_reader_sequence(managed, values, max_attempts=scenario.attempts)
            if verification_fault is not None:
                verification_fault.release(view)
            # No open SQL session, direct scan invocation, receipt seeding or authority mutation.
            managed.release.set()
            print("INTEGRATED_READER_RELEASED=" + str(message.request_id), flush=True)
    finally:
        managed.release.set()
        for server in servers:
            server.should_exit = True
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=10)
        try:
            if isinstance(response_loss, (CommittedSessionExpiry, CommittedIdentitySubstitution)):
                response_loss.assert_complete()  # Before clear: cleanup cannot fabricate rejection.
        finally:
            application.state.dashboard.store.clear()
            transport_stack.close()
            if verification_fault is not None:
                verification_fault.assert_complete()
            engine.dispose()
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError("Integrated server cleanup failed")
        if in_flight is not None:
            in_flight.assert_complete()
        if isinstance(response_loss, CommittedProposalCapabilityLoss):
            response_loss.assert_complete()
        if isinstance(response_loss, CommittedPreparationExpiry):
            response_loss.assert_complete()
        if isinstance(response_loss, CommittedProposalExpiry):
            response_loss.assert_complete()
        if execution_gate is not None:
            execution_gate.assert_complete()
        if reference_gate is not None:
            reference_gate.assert_complete()
        if scenario.name == "cross-issuer" and identity_phase == "initial":
            if (
                response_loss is None
                or response_loss.losses != 1
                or len(response_loss.requests) != 1
            ):
                raise ValueError("Incomplete initial authority commit/loss proof")


def main():
    try:
        instance = os.environ["DASHBOARD_INTEGRATED_INSTANCE"]
        require_test_environment(instance)
        source = os.environ["DASHBOARD_INTEGRATED_SOURCE"]
        scenario = reader_scenario(os.environ.get("DASHBOARD_INTEGRATED_SCENARIO", "verified"))
        identity_phase = os.environ.get("DASHBOARD_INTEGRATED_IDENTITY_PHASE", "initial")
        static_mode = os.environ.get("DASHBOARD_INTEGRATED_STATIC_MODE", "browser")
        identity_issuer(identity_phase, scenario.name)
        database = server_database(os.environ["DATABASE_URL"], instance)
        with server_static_assets(instance, static_mode, scenario.name) as static:
            configure(
                database.render_as_string(hide_password=False),
                secret=secrets.token_urlsafe(32),
                identity_phase=identity_phase,
                scenario=scenario.name,
            )
            if static is not None:
                os.environ["DASHBOARD_STATIC_DIR"] = str(static)
            serve(instance, source, scenario.name, identity_phase=identity_phase)
        return 0
    except Exception:
        # No raw SQL, credentials, tokens, HTTP payloads or provider exception body.
        print("Integrated server failed; no success claimed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
