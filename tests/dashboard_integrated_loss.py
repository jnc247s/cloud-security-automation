"""Closed test-only transport gates AFTER genuine signed API commit, never a fake result.

Importing this module loads no application configuration. Installation belongs only to the
isolated native server/test context; the wrapper forwards authentication, body and key unchanged.
"""

import hashlib
import json
from contextlib import contextmanager
from threading import Lock
from uuid import UUID


class CommittedProposalReplyLoss:
    def __init__(self, engine, *, issuer):
        self.engine, self.issuer = engine, issuer
        self._lock, self._active = Lock(), False
        self._requests, self._losses = [], 0

    @property
    def losses(self):
        with self._lock:
            return self._losses

    @property
    def requests(self):
        with self._lock:
            return tuple(self._requests)  # Only UUID/body digest, never a bearer token.

    def _prove(self, response, key):
        from sqlalchemy import func, select
        from sqlalchemy.orm import Session

        from app.database.integrity import canonical_json_sha256
        from app.models import AuditEvent
        from app.models.enums import AuditEventType
        from app.models.remediation import RemediationProposal, RemediationRequest
        from app.remediation.contracts import ProposalView

        view = ProposalView.model_validate(response.json())
        actor = view.content.proposer
        assert (actor.issuer, actor.subject, actor.roles) == (self.issuer, "proposer", ("ANALYST",))
        # Independent committed connection, no session/transaction held while losing HTTP reply.
        with Session(self.engine) as session:
            assert session.scalar(select(func.count()).select_from(RemediationProposal)) == 1
            proposal = session.get(RemediationProposal, view.content.proposal_id)
            assert proposal.content == view.content.model_dump(mode="json")
            assert (
                proposal.proposal_sha256
                == view.proposal_sha256
                == canonical_json_sha256(proposal.content)
            )
            ledger = session.execute(
                select(RemediationRequest).where(
                    RemediationRequest.operation == "CREATE",
                    RemediationRequest.idempotency_key == key,
                )
            ).scalar_one()
            assert ledger.proposal_id == proposal.proposal_id
            assert (ledger.actor_issuer, ledger.actor_subject) == (self.issuer, "proposer")
            audit = session.execute(
                select(AuditEvent).where(
                    AuditEvent.target_type == "remediation",
                    AuditEvent.target_id == proposal.proposal_id,
                    AuditEvent.event_type == AuditEventType.REMEDIATION_PROPOSED,
                )
            ).scalar_one()
            assert audit.actor_type == "human"
            assert audit.actor_id == canonical_json_sha256([self.issuer, "proposer"])
        return proposal.proposal_id

    def _after_proof(self, _key):
        pass

    async def _committed(self, response, key, _encoded):
        import httpx2 as httpx

        self._prove(response, key)
        self._after_proof(key)
        with self._lock:
            lose = self._losses == 0
            if lose:
                self._losses = 1
        if lose:
            raise httpx.ReadTimeout("Synthetic committed proposal response loss")

    @contextmanager
    def installed(self):
        from unittest.mock import patch

        import httpx2 as httpx

        with self._lock:
            if self._active:
                raise ValueError("Integrated response-loss gate already installed")
            self._active = True
        original = httpx.AsyncClient.post

        async def forward(client, url, *args, **kwargs):
            if type(url) is not str or url != "/api/v1/remediations":
                return await original(client, url, *args, **kwargs)
            if not isinstance(client._transport, httpx.ASGITransport):
                raise ValueError("Response-loss gate requires the fixed in-process bearer API")
            raw, key = kwargs["content"], kwargs["headers"]["Idempotency-Key"]
            if type(raw) not in (str, bytes):
                raise ValueError("Invalid integrated proposal transport")
            encoded = raw.encode("utf-8") if type(raw) is str else raw
            if len(encoded) > 12288:
                raise ValueError("Invalid integrated proposal transport")
            parsed = UUID(key)
            if str(parsed) != key or parsed.version != 4:
                raise ValueError("Invalid integrated operation key")
            with self._lock:
                self._requests.append((parsed, hashlib.sha256(encoded).hexdigest()))
            response = await original(client, url, *args, **kwargs)
            if response.status_code == 201 and self.losses == 0:
                await self._committed(response, parsed, encoded)
            return response

        try:
            with patch.object(httpx.AsyncClient, "post", forward):
                yield self
        finally:
            with self._lock:
                self._active = False


class CommittedProposalInFlight(CommittedProposalReplyLoss):
    """Hold a proven commit until the genuine BFF rejects duplicate dispatch as IN_FLIGHT.

    No public release route, parent command or authority mutation. The unchanged 15s BFF
    timeout remains the failure bound if the native duplicate never arrives.
    """

    def __init__(self, engine, *, issuer):
        super().__init__(engine, issuer=issuer)
        self._held_key, self._held_input = None, None
        self._released, self._returned = False, False
        self._observed = False
        self._wait_loop, self._release_event = None, None

    @property
    def stage(self):
        with self._lock:
            return (
                "RETURNED"
                if self._returned
                else "RELEASED"
                if self._released
                else "UNBOUND"
                if self._observed
                else "HELD"
                if self._held_key
                else "WAITING"
            )

    @property
    def held(self):
        with self._lock:
            return self._held_key is not None

    @property
    def released(self):
        with self._lock:
            return self._released

    async def _committed(self, response, key, encoded):
        import asyncio

        self._prove(response, key)  # Independent committed connection closes before waiting.
        loop, released = asyncio.get_running_loop(), asyncio.Event()
        with self._lock:
            if self._held_key is not None:
                raise ValueError("Integrated in-flight gate already used")
            self._wait_loop, self._release_event = loop, released
            self._held_key, self._held_input = key, json.loads(encoded)
        try:
            await released.wait()
            with self._lock:
                if not self._released:
                    raise ValueError("Integrated in-flight release was not validated")
                self._returned = True
        finally:
            with self._lock:
                self._wait_loop, self._release_event = None, None

    def observe_duplicate(self, path, status, value):
        with self._lock:
            self._observed = True
            if (
                self._held_key is None
                or self._released
                or path != f"/dashboard/api/remediation-operations/{self._held_key}/submit"
                or type(status) is not int
                or status != 200
                or type(value) is not dict
                or set(value)
                != {
                    "schema_version",
                    "operation_id",
                    "operation",
                    "target_id",
                    "input",
                    "actor",
                    "risk_summary",
                    "prepared_at",
                    "expires_at",
                    "state",
                    "attempts",
                    "result",
                }
                or value["schema_version"] != "1.0.0"
                or value["operation_id"] != str(self._held_key)
                or value["operation"] != "PROPOSE"
                or value["target_id"] is not None
                or value["actor"] != {"issuer": self.issuer, "subject": "proposer"}
                or value["input"] != self._held_input
                or value["state"] != "IN_FLIGHT"
                or type(value["attempts"]) is not int
                or value["attempts"] != 1
                or value["result"] is not None
                or len(self._requests) != 1
            ):
                return False
            self._released = True
            if self._release_event is not None:
                # A TestClient caller may be on another thread. Schedule on the owning loop;
                # no polling timer, SQL transaction or unvalidated response can release it.
                self._wait_loop.call_soon_threadsafe(self._release_event.set)
            return True

    def assert_complete(self):
        if not self.released or not self._returned or len(self.requests) != 1 or self.losses:
            raise ValueError("Incomplete integrated in-flight proof")


class InFlightObserver:
    """Read-through test ASGI observer: real auth/handler/reply first, never fabricate a reply."""

    def __init__(self, app, *, gate):
        self.app, self.gate = app, gate

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope["method"] != "POST"
            or not self.gate.held
            or scope["path"]
            != f"/dashboard/api/remediation-operations/{self.gate._held_key}/submit"
        ):
            return await self.app(scope, receive, send)
        status, body = None, bytearray()

        async def observe(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            if message["type"] == "http.response.body":
                body.extend(message.get("body", b""))
                if len(body) > 12288:
                    raise ValueError("Integrated in-flight response too large")
            await send(message)  # Forward exact real response before any gate effect.
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                try:
                    value = json.loads(body)
                except (ValueError, UnicodeError):
                    return
                self.gate.observe_duplicate(scope["path"], status, value)

        await self.app(scope, receive, observe)
