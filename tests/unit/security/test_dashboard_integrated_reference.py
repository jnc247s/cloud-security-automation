"""Closed reference-substitution faults cannot skip genuine commit proof or select routes."""

import pytest


@pytest.mark.parametrize(
    "name,stage", [("reply-reference", "reply"), ("history-reference", "history")]
)
def test_reference_fault_has_only_two_fixed_transport_stages(name, stage):
    from tests.dashboard_integrated_reference import reference_stage

    assert reference_stage(name) == stage


@pytest.mark.parametrize(
    "name", [None, True, 1, {}, [], "", "reply", "reply-reference ", "verified"]
)
def test_arbitrary_reference_fault_or_route_is_rejected(name):
    from tests.dashboard_integrated_reference import reference_stage

    with pytest.raises(ValueError, match="Invalid integrated reference stage"):
        reference_stage(name)


@pytest.mark.parametrize("flag", [None, "true"])
def test_reference_transport_requires_explicit_isolated_mode(monkeypatch, flag):
    from tests.dashboard_integrated_reference import CommittedReferenceSubstitution

    monkeypatch.delenv("DASHBOARD_BROWSER_TEST", raising=False)
    if flag is not None:
        monkeypatch.setenv("DASHBOARD_BROWSER_TEST", flag)
    gate = CommittedReferenceSubstitution(
        object(), issuer="test-issuer", scenario="reply-reference"
    )
    with pytest.raises(ValueError, match="Integrated reference transport unavailable"):
        with gate.installed():
            raise AssertionError("No implicit installation")


def test_reference_transport_cannot_nest_or_claim_unproven_completion(monkeypatch):
    from tests.dashboard_integrated_reference import CommittedReferenceSubstitution

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    gate = CommittedReferenceSubstitution(
        object(), issuer="test-issuer", scenario="history-reference"
    )
    with gate.installed():
        with pytest.raises(ValueError, match="Integrated reference transport unavailable"):
            with gate.installed():
                raise AssertionError("No nested installation")
        with pytest.raises(ValueError, match="Incomplete integrated reference proof"):
            gate.assert_complete()
    assert gate.requests == () and gate.substitutions == 0 and gate.losses == 0


@pytest.mark.parametrize(
    "body,key",
    [
        (None, "22345678-1234-4123-8123-123456789abc"),
        ({}, "22345678-1234-4123-8123-123456789abc"),
        (b"x" * 12289, "22345678-1234-4123-8123-123456789abc"),
        ("{}", None),
        ("{}", True),
        ("{}", "not-a-key"),
        ("{}", "22345678-1234-1123-8123-123456789abc"),
        ("{}", "22345678-1234-4123-8123-123456789ABC"),
    ],
)
def test_reference_transport_rejects_untrusted_body_or_key_before_forward(monkeypatch, body, key):
    import asyncio

    import httpx2 as httpx

    from tests.dashboard_integrated_reference import CommittedReferenceSubstitution

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    called = []

    async def app(*args):
        called.append(True)
        raise AssertionError("Invalid transport input reached API")

    gate = CommittedReferenceSubstitution(
        object(), issuer="test-issuer", scenario="reply-reference"
    )

    async def story():
        with gate.installed():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app), base_url="http://internal.invalid"
            ) as client:
                with pytest.raises(ValueError, match="Invalid integrated reference input"):
                    await client.post(
                        "/api/v1/remediations", content=body, headers={"Idempotency-Key": key}
                    )

    asyncio.run(story())
    assert called == [] and gate.requests == () and gate.substitutions == 0


def test_reference_transport_cannot_adopt_a_non_asgi_client(monkeypatch):
    import asyncio

    import httpx2 as httpx

    from tests.dashboard_integrated_reference import CommittedReferenceSubstitution

    monkeypatch.setenv("DASHBOARD_BROWSER_TEST", "1")
    called = []

    def send(_request):
        called.append(True)
        raise AssertionError("Non-ASGI transport reached dispatch")

    gate = CommittedReferenceSubstitution(
        object(), issuer="test-issuer", scenario="history-reference"
    )

    async def story():
        with gate.installed():
            async with httpx.AsyncClient(transport=httpx.MockTransport(send)) as client:
                with pytest.raises(ValueError, match="Integrated reference transport unavailable"):
                    await client.post(
                        "/api/v1/remediations",
                        content="{}",
                        headers={"Idempotency-Key": "22345678-1234-4123-8123-123456789abc"},
                    )

    asyncio.run(story())
    assert called == [] and gate.requests == ()
