"""Small offline boto3-style fakes shared by collector unit tests."""

from collections import deque
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError


@dataclass(frozen=True)
class RecordedCall:
    """One recorded fake client call."""

    operation_name: str
    parameters: dict[str, Any]


class FakePaginator:
    """Return predetermined pages or raise a predetermined error."""

    def __init__(
        self,
        pages: Iterable[Mapping[str, Any]] = (),
        *,
        error: BaseException | None = None,
    ) -> None:
        self.pages = [dict(page) for page in pages]
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def paginate(self, **kwargs: Any) -> Iterator[dict[str, Any]]:
        """Record paginator options and yield the configured pages."""

        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        yield from self.pages


class FakeAWSClient:
    """Minimal dynamic client supporting queued responses and paginators."""

    def __init__(
        self,
        *,
        paginators: Mapping[str, FakePaginator | Iterable[FakePaginator]] | None = None,
        responses: Mapping[str, Iterable[Mapping[str, Any] | BaseException]] | None = None,
    ) -> None:
        self._paginators: dict[str, deque[FakePaginator]] = {}
        for operation_name, configured in (paginators or {}).items():
            if isinstance(configured, FakePaginator):
                configured_paginators = [configured]
            else:
                configured_paginators = list(configured)
            self._paginators[operation_name] = deque(configured_paginators)

        self._responses = {
            operation_name: deque(outcomes)
            for operation_name, outcomes in (responses or {}).items()
        }
        self.calls: list[RecordedCall] = []
        self.paginator_requests: list[str] = []

    def get_paginator(self, operation_name: str) -> FakePaginator:
        """Return the next paginator configured for an operation."""

        self.paginator_requests.append(operation_name)
        try:
            return self._paginators[operation_name].popleft()
        except (KeyError, IndexError) as error:
            message = f"No fake paginator configured for {operation_name}"
            raise AssertionError(message) from error

    def __getattr__(self, operation_name: str) -> Any:
        """Build a callable for a configured low-level client operation."""

        if operation_name.startswith("_") or operation_name not in self._responses:
            raise AttributeError(operation_name)

        def invoke(**kwargs: Any) -> dict[str, Any]:
            self.calls.append(RecordedCall(operation_name, kwargs))
            try:
                outcome = self._responses[operation_name].popleft()
            except IndexError as error:
                message = f"No fake response remaining for {operation_name}"
                raise AssertionError(message) from error

            if isinstance(outcome, BaseException):
                raise outcome
            return dict(outcome)

        return invoke


class FakeClientProvider:
    """Resolve fake clients by the same service-and-region key as production."""

    def __init__(
        self,
        clients: Mapping[tuple[str, str], FakeAWSClient],
        *,
        region_name: str = "us-east-1",
        account_id: str = "123456789012",
        partition: str = "aws",
    ) -> None:
        self._clients = dict(clients)
        self.region_name = region_name
        self.account_id = account_id
        self.partition = partition
        self.client_requests: list[tuple[str, str]] = []

    def client(self, service_name: str, *, region_name: str | None = None) -> FakeAWSClient:
        """Return the configured fake client and record its resolved region."""

        resolved_region = region_name or self.region_name
        key = (service_name, resolved_region)
        self.client_requests.append(key)
        try:
            return self._clients[key]
        except KeyError as error:
            message = f"No fake client configured for {service_name} in {resolved_region}"
            raise AssertionError(message) from error


def client_error(code: str, operation_name: str, *, status_code: int = 400) -> ClientError:
    """Create a service-shaped botocore error without making an AWS call."""

    return ClientError(
        {
            "Error": {"Code": code, "Message": f"simulated {code}"},
            "ResponseMetadata": {"HTTPStatusCode": status_code},
        },
        operation_name,
    )
