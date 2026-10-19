"""Closed reply/confirmation-READ substitution AFTER genuine signed proposal commit."""

import hashlib
import json
import os
from contextlib import contextmanager
from uuid import UUID

from tests.dashboard_integrated_loss import CommittedProposalReplyLoss

SPOOFED_REFERENCE = UUID("5f02520a-fdc5-4ae1-a789-9d447104abb1")


def reference_stage(name):
    choices = {"reply-reference": "reply", "history-reference": "history"}
    if type(name) is not str or name not in choices:
        raise ValueError("Invalid integrated reference stage")
    return choices[name]


class CommittedReferenceSubstitution(CommittedProposalReplyLoss):
    def __init__(self, engine, *, issuer, scenario):
        super().__init__(engine, issuer=issuer)
        self.stage = reference_stage(scenario)
        self._substitutions, self._reads = 0, []
        self.proposal_id, self._key, self._pending = None, None, False

    @property
    def substitutions(self):
        with self._lock:
            return self._substitutions

    @property
    def reads(self):
        with self._lock:
            return tuple(self._reads)  # Fixed IDs/statuses, never tokens or response bodies.

    def _substitute(self, response):
        with self._lock:
            if (
                not self._active
                or not self._pending
                or self._substitutions
                or self.proposal_id is None
            ):
                raise ValueError("Integrated reference substitution is unbound")
            self._substitutions = 1  # Sticky; failure cannot authorize another injected result.
        import httpx2 as httpx

        from app.database.integrity import canonical_json_sha256
        from app.remediation.contracts import ProposalView

        body = response.json()
        if body["content"]["proposal_id"] != str(self.proposal_id):
            raise ValueError("Integrated reference substitution is unbound")
        body["content"]["proposal_id"] = str(SPOOFED_REFERENCE)
        body["proposal_sha256"] = canonical_json_sha256(body["content"])
        # This is an internally coherent but untrusted reference, not just malformed JSON.
        ProposalView.model_validate_json(json.dumps(body), strict=True)
        return httpx.Response(response.status_code, json=body)

    @contextmanager
    def installed(self):
        if os.environ.get("DASHBOARD_BROWSER_TEST") != "1":
            raise ValueError("Integrated reference transport unavailable")
        from unittest.mock import patch

        import httpx2 as httpx

        with self._lock:
            if self._active:
                raise ValueError("Integrated reference transport unavailable")
            self._active = True
        original_post, original_get = httpx.AsyncClient.post, httpx.AsyncClient.get

        async def post(client, url, *args, **kwargs):
            if type(url) is not str or url != "/api/v1/remediations":
                return await original_post(client, url, *args, **kwargs)
            if not isinstance(client._transport, httpx.ASGITransport):
                raise ValueError("Integrated reference transport unavailable")
            raw, key = kwargs["content"], kwargs["headers"]["Idempotency-Key"]
            if type(raw) not in (str, bytes) or type(key) is not str:
                raise ValueError("Invalid integrated reference input")
            encoded = raw.encode("utf-8") if type(raw) is str else raw
            try:
                parsed = UUID(key)
            except ValueError:
                raise ValueError("Invalid integrated reference input") from None
            if len(encoded) > 12288 or str(parsed) != key or parsed.version != 4:
                raise ValueError("Invalid integrated reference input")
            with self._lock:
                self._requests.append((parsed, hashlib.sha256(encoded).hexdigest()))
            response = await original_post(client, url, *args, **kwargs)
            if response.status_code not in {200, 201}:
                return response
            if self.proposal_id is None and response.status_code != 201:
                raise ValueError("Integrated reference requires a new genuine commit")
            identifier = self._prove(response, parsed)  # Actual commit/audit/ledger first.
            if identifier == SPOOFED_REFERENCE:
                raise ValueError("Integrated reference test target collision")
            with self._lock:
                if self._pending or (
                    self.proposal_id is not None
                    and (
                        self.proposal_id != identifier
                        or self._key != parsed
                        or self._requests[-1] != self._requests[0]
                    )
                ):
                    raise ValueError("Integrated reference replay changed frozen authority")
                self.proposal_id, self._key, self._pending = identifier, parsed, True
            return (
                self._substitute(response)
                if self.stage == "reply" and not self.substitutions
                else response
            )

        async def get(client, url, *args, **kwargs):
            with self._lock:
                pending, identifier = self._pending, self.proposal_id
            targets = {
                "/api/v1/remediations/" + str(identifier),
                "/api/v1/remediations/" + str(SPOOFED_REFERENCE),
            }
            if not pending or type(url) is not str or url not in targets:
                return await original_get(client, url, *args, **kwargs)
            if not isinstance(client._transport, httpx.ASGITransport):
                raise ValueError("Integrated reference transport unavailable")
            response = await original_get(client, url, *args, **kwargs)
            target = UUID(url.rsplit("/", 1)[1])
            if target == identifier and response.status_code == 200:
                self._prove(response, self._key)  # Genuine authorized READ before alteration.
            altered = (
                self._substitute(response)
                if self.stage == "history"
                and not self.substitutions
                and response.status_code == 200
                else response
            )
            with self._lock:
                self._reads.append((target, response.status_code))
                self._pending = False
            return altered

        try:
            with (
                patch.object(httpx.AsyncClient, "post", post),
                patch.object(httpx.AsyncClient, "get", get),
            ):
                yield self
        finally:
            with self._lock:
                self._active = False

    def assert_complete(self):
        expected = (
            ((SPOOFED_REFERENCE, 404), (self.proposal_id, 200))
            if self.stage == "reply"
            else ((self.proposal_id, 200), (self.proposal_id, 200))
        )
        if (
            self.substitutions != 1
            or self.losses != 0
            or self._pending
            or type(self.proposal_id) is not UUID
            or type(self._key) is not UUID
            or len(self.requests) != 2
            or self.requests[0] != self.requests[1]
            or self.reads != expected
        ):
            raise ValueError("Incomplete integrated reference proof")
