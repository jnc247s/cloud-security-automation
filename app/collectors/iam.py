"""Account-global IAM identity and permissions evidence collection."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import unquote_to_bytes

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import EvidenceCardinality
from app.assessment.relationships import RelationshipEndpoint, RelationshipType
from app.assessment.source_outcomes import (
    AccountEvidenceSubject,
    EvidenceCollectionPhase,
    EvidenceFailureCategory,
    EvidenceSourceState,
    ResourceEvidenceSubject,
)
from app.collectors.base import (
    CollectionContext,
    CollectorEvidenceConflictError,
    CollectorEvidenceError,
    CollectorResult,
    RelationshipReference,
    ResourceCollector,
    SourceObservation,
    build_source_observation,
    collection_status_for,
    iter_paginated_items,
    require_boolean,
    require_datetime,
    require_integer,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    require_string,
    should_skip_exact_duplicate,
    source_failure,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope

_ACCESS_KEY_STATUSES = {"Active", "Inactive", "Expired"}
_COLLECTOR_VERSION = "2.0.0"
_CONTRACT_VERSION = "1.0.0"
_EVIDENCE_SCHEMA_VERSION = "1.0.0"
_EXPECTED_FAILURES = (BotoCoreError, ClientError, CollectorEvidenceError)


@dataclass(frozen=True, slots=True)
class _Discovery:
    """Validated resources and raw source objects retained from one discovery API."""

    resources: tuple[NormalizedResource, ...]
    raw_by_resource_id: Mapping[str, Mapping[str, Any]]
    error: BaseException | None
    discarded_item_count: int


@dataclass(frozen=True, slots=True)
class _PaginatedResult:
    """One independently attributable paginated IAM result."""

    items: tuple[Any, ...]
    error: BaseException | None
    discarded_item_count: int


@dataclass(frozen=True, slots=True)
class _PolicyReference:
    """One exact managed-policy relationship established by an identity API."""

    source: NormalizedResource
    policy_arn: str
    policy_name: str
    relationship_type: RelationshipType
    observation: SourceObservation


class IAMUserCollector(ResourceCollector):
    """Collect account-global IAM users and authentication metadata facts."""

    collector_name = "iam_users"
    produces_evidence_graph = True

    def collect(self) -> list[NormalizedResource]:
        """Preserve the accepted Sprint 1 direct user-inventory contract."""

        client = self.client_provider.client("iam")
        account_id = self.client_provider.account_id
        resources: list[NormalizedResource] = []
        seen_users: dict[str, dict[str, Any]] = {}

        for user in iter_paginated_items(client, "list_users", "Users"):
            user_name = _required_string_member(user, "UserName", "list_users", "Users[].UserName")
            user_id = _required_string_member(user, "UserId", "list_users", "Users[].UserId")
            arn = _required_string_member(user, "Arn", "list_users", "Users[].Arn")
            path = _required_string_member(user, "Path", "list_users", "Users[].Path")
            created_at = _required_datetime_member(
                user,
                "CreateDate",
                "list_users",
                "Users[].CreateDate",
            )
            password_last_used = _nullable_datetime_member(
                user,
                "PasswordLastUsed",
                "list_users",
                "Users[].PasswordLastUsed",
            )
            if should_skip_exact_duplicate(
                seen_users,
                user_id,
                user,
                operation_name="list_users",
                fact_path="Users[].UserId",
            ):
                continue

            tags = tags_to_dict(
                list(
                    iter_paginated_items(
                        client,
                        "list_user_tags",
                        "Tags",
                        UserName=user_name,
                    )
                ),
                operation_name="list_user_tags",
                fact_path="Tags",
            )
            mfa_devices = self._collect_mfa_devices(client, user_name)
            access_keys = self._collect_access_keys(client, user_name)

            resources.append(
                NormalizedResource(
                    account_id=account_id,
                    service="iam",
                    resource_type="iam_user",
                    aws_resource_id=user_id,
                    arn=arn,
                    name=user_name,
                    scope=ResourceScope.GLOBAL,
                    region=None,
                    tags=tags,
                    configuration={
                        "path": path,
                        "created_at": to_json_safe(created_at),
                        "password_last_used": to_json_safe(password_last_used),
                        "mfa_devices": to_json_safe(mfa_devices),
                        "access_keys": to_json_safe(access_keys),
                    },
                    raw_configuration={
                        "user": to_json_safe(user),
                        "mfa_devices": to_json_safe(mfa_devices),
                        "access_keys": to_json_safe(access_keys),
                    },
                )
            )

        return resources

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Collect the complete 5C IAM identity graph without changing ``collect``."""

        if context.collection_account_id != self.client_provider.account_id:
            raise ValueError("collection context account does not match the AWS client provider")
        return _IAMGraphBuilder(
            client=self.client_provider.client("iam"),
            context=context,
            account_id=self.client_provider.account_id,
            partition=self.client_provider.partition,
            operational_collector_name=self.collector_name,
        ).collect()

    @staticmethod
    def _collect_mfa_devices(client: Any, user_name: str) -> list[dict[str, Any]]:
        mfa_devices: list[dict[str, Any]] = []
        seen_devices: dict[str, dict[str, Any]] = {}

        for device in iter_paginated_items(
            client,
            "list_mfa_devices",
            "MFADevices",
            UserName=user_name,
        ):
            device_user_name = _required_string_member(
                device,
                "UserName",
                "list_mfa_devices",
                "MFADevices[].UserName",
            )
            if device_user_name != user_name:
                raise CollectorEvidenceError("list_mfa_devices", "MFADevices[].UserName")
            serial_number = _required_string_member(
                device,
                "SerialNumber",
                "list_mfa_devices",
                "MFADevices[].SerialNumber",
            )
            _required_datetime_member(
                device,
                "EnableDate",
                "list_mfa_devices",
                "MFADevices[].EnableDate",
            )
            if should_skip_exact_duplicate(
                seen_devices,
                serial_number,
                device,
                operation_name="list_mfa_devices",
                fact_path="MFADevices[].SerialNumber",
            ):
                continue
            mfa_devices.append(device)

        return mfa_devices

    @staticmethod
    def _collect_access_keys(client: Any, user_name: str) -> list[dict[str, Any]]:
        access_keys: list[dict[str, Any]] = []
        seen_access_keys: dict[str, dict[str, Any]] = {}

        for key_metadata in iter_paginated_items(
            client,
            "list_access_keys",
            "AccessKeyMetadata",
            UserName=user_name,
        ):
            access_key_id = _required_string_member(
                key_metadata,
                "AccessKeyId",
                "list_access_keys",
                "AccessKeyMetadata[].AccessKeyId",
            )
            _validate_optional_access_key_metadata(key_metadata, user_name)
            if should_skip_exact_duplicate(
                seen_access_keys,
                access_key_id,
                key_metadata,
                operation_name="list_access_keys",
                fact_path="AccessKeyMetadata[].AccessKeyId",
            ):
                continue

            raw_last_used_response = client.get_access_key_last_used(AccessKeyId=access_key_id)
            last_used_response = require_mapping(
                raw_last_used_response,
                operation_name="get_access_key_last_used",
                fact_path="response",
            )
            _validate_optional_response_user_name(last_used_response, user_name)
            last_used = _validated_last_used(last_used_response)
            access_keys.append(
                {
                    **key_metadata,
                    "LastUsed": last_used,
                }
            )

        return access_keys


class _IAMGraphBuilder:
    """Build one deterministic account-global IAM evidence graph."""

    def __init__(
        self,
        *,
        client: Any,
        context: CollectionContext,
        account_id: str,
        partition: str,
        operational_collector_name: str,
    ) -> None:
        self.client = client
        self.context = context
        self.account_id = account_id
        self.partition = partition
        self.operational_collector_name = operational_collector_name
        self.resources: dict[tuple[str, str, str, str, str, str], NormalizedResource] = {}
        self.observations: list[SourceObservation] = []
        self.relationships: list[RelationshipReference] = []
        self.policy_references: list[_PolicyReference] = []
        self.conflicted_user_child_identities: set[tuple[str, str, str, str, str, str]] = set()

    def collect(self) -> CollectorResult:
        """Collect independent discovery and enrichment sources in dependency order."""

        users = self._discover(
            operation_name="list_users",
            result_key="Users",
            identity_key="UserId",
            normalizer=self._normalize_user,
            collector="iam.users",
            evidence_kind="iam.users.discovery",
            source_api="iam:ListUsers",
        )
        groups = self._discover(
            operation_name="list_groups",
            result_key="Groups",
            identity_key="GroupId",
            normalizer=self._normalize_group,
            collector="iam.groups",
            evidence_kind="iam.groups.discovery",
            source_api="iam:ListGroups",
        )
        roles = self._discover(
            operation_name="list_roles",
            result_key="Roles",
            identity_key="RoleId",
            normalizer=self._normalize_role,
            collector="iam.roles",
            evidence_kind="iam.roles.discovery",
            source_api="iam:ListRoles",
        )
        policies = self._discover(
            operation_name="list_policies",
            result_key="Policies",
            identity_key="Arn",
            normalizer=self._normalize_local_policy,
            collector="iam.policies",
            evidence_kind="iam.customer-managed-policies.discovery",
            source_api="iam:ListPolicies",
            paginate_options={"Scope": "Local"},
        )

        self._record_discovery(users, "iam.users", "iam.users.discovery", "iam:ListUsers")
        self._record_discovery(groups, "iam.groups", "iam.groups.discovery", "iam:ListGroups")
        self._record_discovery(roles, "iam.roles", "iam.roles.discovery", "iam:ListRoles")
        self._record_discovery(
            policies,
            "iam.policies",
            "iam.customer-managed-policies.discovery",
            "iam:ListPolicies",
        )

        for resource in users.resources:
            self._put_resource(resource)
            self._record_resource_identity(
                resource,
                collector="iam.users",
                evidence_kind="iam.user",
                source_api="iam:ListUsers",
            )
        for resource in groups.resources:
            self._put_resource(resource)
            self._record_resource_identity(
                resource,
                collector="iam.groups",
                evidence_kind="iam.group",
                source_api="iam:ListGroups",
            )
        for resource in roles.resources:
            self._put_resource(resource)
            self._record_resource_identity(
                resource,
                collector="iam.roles",
                evidence_kind="iam.role",
                source_api="iam:ListRoles",
            )
        for resource in policies.resources:
            self._put_resource(resource)
            self._record_resource_identity(
                resource,
                collector="iam.policies",
                evidence_kind="iam.customer-managed-policy",
                source_api="iam:ListPolicies",
            )

        for resource in users.resources:
            self._enrich_user(resource)
        for resource in groups.resources:
            self._enrich_group(resource)
        for resource in roles.resources:
            self._enrich_role(resource)

        self._materialize_referenced_policies()
        for policy in tuple(
            resource
            for resource in self.resources.values()
            if resource.resource_type in {"iam_customer_managed_policy", "iam_aws_managed_policy"}
        ):
            self._enrich_managed_policy(policy)

        resources = tuple(sorted(self.resources.values(), key=lambda item: item.identity))
        outcomes = tuple(observation.outcome for observation in self.observations)
        return CollectorResult(
            resources=resources,
            status=collection_status_for(outcomes),
            source_contracts=tuple(observation.contract for observation in self.observations),
            artifacts=tuple(observation.artifact for observation in self.observations),
            source_outcomes=outcomes,
            relationships=tuple(self.relationships),
        )

    def _discover(
        self,
        *,
        operation_name: str,
        result_key: str,
        identity_key: str,
        normalizer: Callable[[Mapping[str, Any], str], NormalizedResource],
        collector: str,
        evidence_kind: str,
        source_api: str,
        paginate_options: Mapping[str, object] | None = None,
    ) -> _Discovery:
        del collector, evidence_kind, source_api
        source = self._paginated_mappings(
            operation_name,
            result_key,
            **dict(paginate_options or {}),
        )
        resources: dict[str, NormalizedResource] = {}
        raw_by_id: dict[str, Mapping[str, Any]] = {}
        errors = [source.error] if source.error is not None else []
        discarded = source.discarded_item_count
        blocked: set[str] = set()

        for index, item in enumerate(source.items):
            item_path = f"{result_key}[{index}]"
            identity: str | None = None
            try:
                item_mapping = require_mapping(
                    item,
                    operation_name=operation_name,
                    fact_path=item_path,
                )
                identity = _required_string_member(
                    item_mapping,
                    identity_key,
                    operation_name,
                    f"{item_path}.{identity_key}",
                )
                _reject_unsafe_identity(identity, operation_name, f"{item_path}.{identity_key}")
                if identity in blocked:
                    discarded += 1
                    continue
                previous = raw_by_id.get(identity)
                if previous is not None:
                    if previous == item_mapping:
                        continue
                    blocked.add(identity)
                    raw_by_id.pop(identity, None)
                    if resources.pop(identity, None) is not None:
                        discarded += 1
                    discarded += 1
                    errors.append(
                        CollectorEvidenceConflictError(
                            operation_name,
                            f"{item_path}.{identity_key}",
                        )
                    )
                    continue
                resource = normalizer(item_mapping, item_path)
                raw_by_id[identity] = item_mapping
                resources[identity] = resource
            except CollectorEvidenceError as error:
                errors.append(error)
                discarded += 1
                if identity is not None:
                    resources.pop(identity, None)
                    raw_by_id.pop(identity, None)

        return _Discovery(
            resources=tuple(sorted(resources.values(), key=lambda item: item.identity)),
            raw_by_resource_id=raw_by_id,
            error=_preferred_error(errors),
            discarded_item_count=discarded,
        )

    def _paginated_mappings(
        self,
        operation_name: str,
        result_key: str,
        **paginate_options: object,
    ) -> _PaginatedResult:
        items: list[Mapping[str, Any]] = []
        errors: list[BaseException] = []
        discarded = 0
        try:
            paginator = self.client.get_paginator(operation_name)
            for page_index, raw_page in enumerate(paginator.paginate(**paginate_options)):
                page = require_mapping(
                    raw_page,
                    operation_name=operation_name,
                    fact_path=f"pages[{page_index}]",
                )
                items_path = f"pages[{page_index}].{result_key}"
                raw_items = require_list(
                    require_member(
                        page,
                        result_key,
                        operation_name=operation_name,
                        fact_path=items_path,
                    ),
                    operation_name=operation_name,
                    fact_path=items_path,
                )
                for item_index, raw_item in enumerate(raw_items):
                    try:
                        items.append(
                            require_mapping(
                                raw_item,
                                operation_name=operation_name,
                                fact_path=f"{items_path}[{item_index}]",
                            )
                        )
                    except CollectorEvidenceError as error:
                        errors.append(error)
                        discarded += 1
        except _EXPECTED_FAILURES as error:
            errors.append(error)
        return _PaginatedResult(
            items=tuple(items),
            error=_preferred_error(errors),
            discarded_item_count=discarded,
        )

    def _paginated_strings(
        self,
        operation_name: str,
        result_key: str,
        **paginate_options: object,
    ) -> _PaginatedResult:
        values: list[str] = []
        errors: list[BaseException] = []
        discarded = 0
        seen: set[str] = set()
        try:
            paginator = self.client.get_paginator(operation_name)
            for page_index, raw_page in enumerate(paginator.paginate(**paginate_options)):
                page = require_mapping(
                    raw_page,
                    operation_name=operation_name,
                    fact_path=f"pages[{page_index}]",
                )
                values_path = f"pages[{page_index}].{result_key}"
                raw_values = require_list(
                    require_member(
                        page,
                        result_key,
                        operation_name=operation_name,
                        fact_path=values_path,
                    ),
                    operation_name=operation_name,
                    fact_path=values_path,
                )
                for value_index, raw_value in enumerate(raw_values):
                    try:
                        value = require_non_empty_string(
                            raw_value,
                            operation_name=operation_name,
                            fact_path=f"{values_path}[{value_index}]",
                        )
                        _reject_unsafe_identity(
                            value,
                            operation_name,
                            f"{values_path}[{value_index}]",
                        )
                        if value not in seen:
                            seen.add(value)
                            values.append(value)
                    except CollectorEvidenceError as error:
                        errors.append(error)
                        discarded += 1
        except _EXPECTED_FAILURES as error:
            errors.append(error)
        return _PaginatedResult(
            items=tuple(values),
            error=_preferred_error(errors),
            discarded_item_count=discarded,
        )

    def _record_discovery(
        self,
        source: _Discovery,
        collector: str,
        evidence_kind: str,
        source_api: str,
    ) -> SourceObservation:
        state, category = _state_for(source.error)
        observation = build_source_observation(
            context=self.context,
            contract_key=evidence_kind,
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=AccountEvidenceSubject(
                aws_account_id=self.account_id,
                scope=ResourceScope.GLOBAL,
                region=None,
            ),
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=_COLLECTOR_VERSION,
            source_api=source_api,
            cardinality=EvidenceCardinality.COLLECTION,
            evidence_reference=f"normalized://aws/iam/{evidence_kind}/discovery",
            evidence_schema=evidence_kind,
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": self.account_id,
                "scope": ResourceScope.GLOBAL.value,
                "resource_ids": sorted(resource.aws_resource_id for resource in source.resources),
                "resource_count": len(source.resources),
                "discarded_item_count": source.discarded_item_count,
                "complete": source.error is None,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )
        self.observations.append(observation)
        return observation

    def _record_resource_identity(
        self,
        resource: NormalizedResource,
        *,
        collector: str,
        evidence_kind: str,
        source_api: str,
        evidence_reference: str | None = None,
        configuration: Mapping[str, object] | None = None,
    ) -> SourceObservation:
        observation = build_source_observation(
            context=self.context,
            contract_key=evidence_kind,
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=_resource_subject(self.context, resource),
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=_COLLECTOR_VERSION,
            source_api=source_api,
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=evidence_reference
            or _evidence_reference(evidence_kind, resource.aws_resource_id),
            evidence_schema=evidence_kind,
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": resource.account_id,
                "resource_type": resource.resource_type,
                "resource_id": resource.aws_resource_id,
                "arn": resource.arn,
                "name": resource.name,
                "tags": [
                    {"key": key, "value": value} for key, value in sorted(resource.tags.items())
                ],
                "configuration": dict(
                    configuration
                    if configuration is not None
                    else _artifact_configuration(resource)
                ),
            },
            state=EvidenceSourceState.PRESENT,
            identity_authoritative=True,
        )
        self.observations.append(observation)
        return observation

    def _record_enrichment(
        self,
        resource: NormalizedResource,
        *,
        collector: str,
        evidence_kind: str,
        source_api: str,
        payload: Mapping[str, object],
        error: BaseException | None,
        expected_absence: bool = False,
        identity_authoritative: bool = False,
    ) -> SourceObservation:
        if error is not None:
            state, category = _state_for(error)
        elif expected_absence:
            state, category = EvidenceSourceState.EXPECTED_ABSENCE, None
        else:
            state, category = EvidenceSourceState.PRESENT, None
        normalized_payload = {
            "account_id": resource.account_id,
            "resource_type": resource.resource_type,
            "resource_id": resource.aws_resource_id,
            **dict(payload),
            "complete": error is None,
            "failure_category": category.value if category is not None else None,
        }
        observation = build_source_observation(
            context=self.context,
            contract_key=evidence_kind,
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=_resource_subject(self.context, resource),
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=_COLLECTOR_VERSION,
            source_api=source_api,
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=_evidence_reference(evidence_kind, resource.aws_resource_id),
            evidence_schema=evidence_kind,
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload=normalized_payload,
            state=state,
            failure_category=category,
            identity_authoritative=identity_authoritative,
        )
        self.observations.append(observation)
        return observation

    def _put_resource(self, resource: NormalizedResource) -> None:
        previous = self.resources.get(resource.identity)
        if previous is not None and previous != resource:
            raise CollectorEvidenceConflictError("iam_graph", "resources.identity")
        self.resources[resource.identity] = resource

    def _replace_resource(self, resource: NormalizedResource) -> NormalizedResource:
        self.resources[resource.identity] = resource
        return resource

    def _resource(self, resource: NormalizedResource) -> NormalizedResource:
        return self.resources[resource.identity]

    def _normalize_user(
        self,
        item: Mapping[str, Any],
        item_path: str,
    ) -> NormalizedResource:
        operation = "list_users"
        user_name = _required_string_member(item, "UserName", operation, f"{item_path}.UserName")
        user_id = _required_string_member(item, "UserId", operation, f"{item_path}.UserId")
        arn = _required_string_member(item, "Arn", operation, f"{item_path}.Arn")
        path = _required_string_member(item, "Path", operation, f"{item_path}.Path")
        _validate_identity_arn(
            arn,
            partition=self.partition,
            account_id=self.account_id,
            resource_prefix="user/",
            operation_name=operation,
            fact_path=f"{item_path}.Arn",
            expected_path=path,
            expected_name=user_name,
        )
        created_at = _required_datetime_member(
            item, "CreateDate", operation, f"{item_path}.CreateDate"
        )
        password_last_used = _nullable_datetime_member(
            item,
            "PasswordLastUsed",
            operation,
            f"{item_path}.PasswordLastUsed",
        )
        return NormalizedResource(
            account_id=self.account_id,
            service="iam",
            resource_type="iam_user",
            aws_resource_id=user_id,
            arn=arn,
            name=user_name,
            scope=ResourceScope.GLOBAL,
            region=None,
            configuration={
                "path": path,
                "created_at": to_json_safe(created_at),
                "password_last_used": to_json_safe(password_last_used),
                "mfa_devices": [],
                "access_keys": [],
            },
            raw_configuration={
                "Path": path,
                "UserName": user_name,
                "UserId": user_id,
                "Arn": arn,
                "CreateDate": to_json_safe(created_at),
                "PasswordLastUsed": to_json_safe(password_last_used),
            },
        )

    def _normalize_group(
        self,
        item: Mapping[str, Any],
        item_path: str,
    ) -> NormalizedResource:
        operation = "list_groups"
        group_name = _required_string_member(item, "GroupName", operation, f"{item_path}.GroupName")
        group_id = _required_string_member(item, "GroupId", operation, f"{item_path}.GroupId")
        arn = _required_string_member(item, "Arn", operation, f"{item_path}.Arn")
        path = _required_string_member(item, "Path", operation, f"{item_path}.Path")
        _validate_identity_arn(
            arn,
            partition=self.partition,
            account_id=self.account_id,
            resource_prefix="group/",
            operation_name=operation,
            fact_path=f"{item_path}.Arn",
            expected_path=path,
            expected_name=group_name,
        )
        created_at = _required_datetime_member(
            item, "CreateDate", operation, f"{item_path}.CreateDate"
        )
        return NormalizedResource(
            account_id=self.account_id,
            service="iam",
            resource_type="iam_group",
            aws_resource_id=group_id,
            arn=arn,
            name=group_name,
            scope=ResourceScope.GLOBAL,
            region=None,
            configuration={
                "path": path,
                "created_at": to_json_safe(created_at),
                "member_user_ids": [],
            },
            raw_configuration={
                "Path": path,
                "GroupName": group_name,
                "GroupId": group_id,
                "Arn": arn,
                "CreateDate": to_json_safe(created_at),
            },
        )

    def _normalize_role(
        self,
        item: Mapping[str, Any],
        item_path: str,
    ) -> NormalizedResource:
        operation = "list_roles"
        role_name = _required_string_member(item, "RoleName", operation, f"{item_path}.RoleName")
        role_id = _required_string_member(item, "RoleId", operation, f"{item_path}.RoleId")
        arn = _required_string_member(item, "Arn", operation, f"{item_path}.Arn")
        path = _required_string_member(item, "Path", operation, f"{item_path}.Path")
        _validate_identity_arn(
            arn,
            partition=self.partition,
            account_id=self.account_id,
            resource_prefix="role/",
            operation_name=operation,
            fact_path=f"{item_path}.Arn",
            expected_path=path,
            expected_name=role_name,
        )
        created_at = _required_datetime_member(
            item, "CreateDate", operation, f"{item_path}.CreateDate"
        )
        configuration: dict[str, object] = {
            "path": path,
            "created_at": to_json_safe(created_at),
            "description": _optional_string_member(
                item, "Description", operation, f"{item_path}.Description"
            ),
            "max_session_duration": _optional_integer_member(
                item,
                "MaxSessionDuration",
                operation,
                f"{item_path}.MaxSessionDuration",
            ),
            "trust_policy_document": None,
            "permissions_boundary_arn": None,
        }
        return NormalizedResource(
            account_id=self.account_id,
            service="iam",
            resource_type="iam_role",
            aws_resource_id=role_id,
            arn=arn,
            name=role_name,
            scope=ResourceScope.GLOBAL,
            region=None,
            configuration=configuration,
            raw_configuration={
                "Path": path,
                "RoleName": role_name,
                "RoleId": role_id,
                "Arn": arn,
                "CreateDate": to_json_safe(created_at),
                "Description": configuration["description"],
                "MaxSessionDuration": configuration["max_session_duration"],
            },
        )

    def _normalize_local_policy(
        self,
        item: Mapping[str, Any],
        item_path: str,
    ) -> NormalizedResource:
        operation = "list_policies"
        arn = _required_string_member(item, "Arn", operation, f"{item_path}.Arn")
        owner, policy_type = _parse_policy_arn(
            arn,
            partition=self.partition,
            expected_account_id=self.account_id,
            operation_name=operation,
            fact_path=f"{item_path}.Arn",
            allow_aws_managed=False,
        )
        policy_name = _required_string_member(
            item,
            "PolicyName",
            operation,
            f"{item_path}.PolicyName",
        )
        policy_id = _required_string_member(item, "PolicyId", operation, f"{item_path}.PolicyId")
        default_version_id = _required_string_member(
            item,
            "DefaultVersionId",
            operation,
            f"{item_path}.DefaultVersionId",
        )
        path = _required_string_member(item, "Path", operation, f"{item_path}.Path")
        _validate_identity_arn(
            arn,
            partition=self.partition,
            account_id=owner,
            resource_prefix="policy/",
            operation_name=operation,
            fact_path=f"{item_path}.Arn",
            expected_path=path,
            expected_name=policy_name,
        )
        return NormalizedResource(
            account_id=owner,
            service="iam",
            resource_type=policy_type,
            aws_resource_id=arn,
            arn=arn,
            name=policy_name,
            scope=ResourceScope.GLOBAL,
            region=None,
            tags={},
            configuration={
                "policy_id": policy_id,
                "path": path,
                "default_version_id": default_version_id,
                "is_attachable": _optional_boolean_member(
                    item,
                    "IsAttachable",
                    operation,
                    f"{item_path}.IsAttachable",
                ),
                "attachment_count": _optional_integer_member(
                    item,
                    "AttachmentCount",
                    operation,
                    f"{item_path}.AttachmentCount",
                ),
                "permissions_boundary_usage_count": _optional_integer_member(
                    item,
                    "PermissionsBoundaryUsageCount",
                    operation,
                    f"{item_path}.PermissionsBoundaryUsageCount",
                ),
                "metadata_complete": False,
            },
            raw_configuration=_safe_policy_metadata(item),
        )

    def _enrich_user(self, original: NormalizedResource) -> None:
        resource = self._resource(original)
        user_name = _require_resource_name(resource, "list_users")

        tag_source = self._paginated_mappings(
            "list_user_tags",
            "Tags",
            UserName=user_name,
        )
        tag_error = tag_source.error
        tags: dict[str, str] = {}
        try:
            tags = tags_to_dict(
                tag_source.items,
                operation_name="list_user_tags",
                fact_path="Tags",
            )
        except CollectorEvidenceError as error:
            tag_error = _preferred_error(
                [candidate for candidate in (tag_error, error) if candidate]
            )
        resource = self._update_resource(resource, tags=tags)
        self._record_enrichment(
            resource,
            collector="iam.users",
            evidence_kind="iam.user.tags",
            source_api="iam:ListUserTags",
            payload={
                "tags": [{"key": key, "value": value} for key, value in sorted(tags.items())],
                "discarded_item_count": tag_source.discarded_item_count,
            },
            error=tag_error,
        )

        mfa_source = self._paginated_mappings(
            "list_mfa_devices",
            "MFADevices",
            UserName=user_name,
        )
        mfa_resources, mfa_raw, mfa_error, mfa_discarded = self._normalize_mfa_devices(
            resource,
            mfa_source,
        )
        mfa_resources, mfa_raw, collision_error, collision_count = (
            self._exclude_cross_user_child_conflicts(
                parent=resource,
                children=mfa_resources,
                raw_by_id={
                    item.aws_resource_id: raw
                    for item, raw in zip(mfa_resources, mfa_raw, strict=True)
                },
                evidence_kind="iam.user.mfa-devices",
                source_api="iam:ListMFADevices",
                operation_name="list_mfa_devices",
                configuration_field="mfa_devices",
                identity_field="SerialNumber",
                payload_ids_field="device_ids",
                payload_count_field="device_count",
            )
        )
        mfa_error = _preferred_error(
            [candidate for candidate in (mfa_error, collision_error) if candidate]
        )
        mfa_discarded += collision_count
        mfa_observation = self._record_enrichment(
            resource,
            collector="iam.users",
            evidence_kind="iam.user.mfa-devices",
            source_api="iam:ListMFADevices",
            payload={
                "device_ids": sorted(item.aws_resource_id for item in mfa_resources),
                "device_count": len(mfa_resources),
                "discarded_item_count": mfa_discarded,
            },
            error=mfa_error,
        )
        for mfa_resource in mfa_resources:
            self._put_resource(mfa_resource)
            identity_observation = self._record_resource_identity(
                mfa_resource,
                collector="iam.users",
                evidence_kind="iam.mfa-device",
                source_api="iam:ListMFADevices",
            )
            if mfa_observation.outcome.state is EvidenceSourceState.PRESENT:
                self._add_relationship(
                    RelationshipType.HAS_MFA_DEVICE,
                    resource,
                    mfa_resource,
                    identity_observation,
                    "iam.mfa-device",
                )

        access_source = self._paginated_mappings(
            "list_access_keys",
            "AccessKeyMetadata",
            UserName=user_name,
        )
        key_resources, key_raw, key_error, key_discarded = self._normalize_access_keys(
            resource,
            access_source,
        )
        key_resources, key_raw, collision_error, collision_count = (
            self._exclude_cross_user_child_conflicts(
                parent=resource,
                children=key_resources,
                raw_by_id=key_raw,
                evidence_kind="iam.user.access-keys",
                source_api="iam:ListAccessKeys",
                operation_name="list_access_keys",
                configuration_field="access_keys",
                identity_field="AccessKeyId",
                payload_ids_field="key_resource_ids",
                payload_count_field="key_count",
            )
        )
        key_error = _preferred_error(
            [candidate for candidate in (key_error, collision_error) if candidate]
        )
        key_discarded += collision_count
        access_observation = self._record_enrichment(
            resource,
            collector="iam.users",
            evidence_kind="iam.user.access-keys",
            source_api="iam:ListAccessKeys",
            payload={
                "key_resource_ids": sorted(item.aws_resource_id for item in key_resources),
                "key_count": len(key_resources),
                "discarded_item_count": key_discarded,
            },
            error=key_error,
        )
        completed_keys: list[NormalizedResource] = []
        for key_resource in key_resources:
            key_resource = self._enrich_access_key(key_resource)
            completed_keys.append(key_resource)
            self._put_resource(key_resource)
            identity_observation = self._record_resource_identity(
                key_resource,
                collector="iam.users",
                evidence_kind="iam.access-key",
                source_api="iam:ListAccessKeys",
            )
            if access_observation.outcome.state is EvidenceSourceState.PRESENT:
                self._add_relationship(
                    RelationshipType.HAS_ACCESS_KEY,
                    resource,
                    key_resource,
                    identity_observation,
                    "iam.access-key",
                )

        resource = self._update_resource(
            resource,
            configuration_updates={
                "mfa_devices": to_json_safe(
                    [mfa_raw[item.aws_resource_id] for item in mfa_resources]
                ),
                "access_keys": to_json_safe(
                    [
                        {
                            **key_raw[item.aws_resource_id],
                            "LastUsed": _legacy_last_used(item),
                        }
                        for item in completed_keys
                    ]
                ),
            },
            raw_updates={
                "mfa_devices": to_json_safe(
                    [mfa_raw[item.aws_resource_id] for item in mfa_resources]
                ),
                "access_keys": to_json_safe(
                    [
                        {
                            **key_raw[item.aws_resource_id],
                            "LastUsed": _legacy_last_used(item),
                        }
                        for item in completed_keys
                    ]
                ),
            },
        )

        profile, profile_error = self._get_identity_profile(
            "get_user",
            "User",
            resource,
            UserName=user_name,
        )
        boundary_arn: str | None = None
        if profile is not None:
            try:
                boundary_arn = self._validate_profile(
                    profile,
                    resource,
                    operation_name="get_user",
                    name_key="UserName",
                    id_key="UserId",
                    allow_trust_policy=False,
                )[0]
                resource = self._update_resource(
                    resource,
                    configuration_updates={"permissions_boundary_arn": boundary_arn},
                    raw_updates={"get_user": _safe_identity_profile(profile)},
                )
            except CollectorEvidenceError as error:
                profile_error = error
                boundary_arn = None
        profile_observation = self._record_enrichment(
            resource,
            collector="iam.users",
            evidence_kind="iam.user.profile",
            source_api="iam:GetUser",
            payload={"permissions_boundary_arn": boundary_arn},
            error=profile_error,
        )
        if boundary_arn is not None and profile_error is None:
            self._remember_policy_reference(
                resource,
                policy_arn=boundary_arn,
                policy_name=_policy_name_from_arn(boundary_arn),
                relationship_type=RelationshipType.PERMISSIONS_BOUNDARY,
                observation=profile_observation,
            )

        self._collect_managed_policy_attachments(
            resource,
            operation_name="list_attached_user_policies",
            source_api="iam:ListAttachedUserPolicies",
            collector="iam.users",
            evidence_kind="iam.user.attached-managed-policies",
            options={"UserName": user_name},
        )
        self._collect_inline_policies(
            resource,
            list_operation="list_user_policies",
            get_operation="get_user_policy",
            source_api_list="iam:ListUserPolicies",
            source_api_get="iam:GetUserPolicy",
            collector="iam.users",
            evidence_prefix="iam.user.inline-policies",
            options={"UserName": user_name},
        )

    def _normalize_mfa_devices(
        self,
        user: NormalizedResource,
        source: _PaginatedResult,
    ) -> tuple[
        tuple[NormalizedResource, ...],
        tuple[Mapping[str, Any], ...],
        BaseException | None,
        int,
    ]:
        resources: dict[str, NormalizedResource] = {}
        raw_by_id: dict[str, Mapping[str, Any]] = {}
        errors = [source.error] if source.error is not None else []
        discarded = source.discarded_item_count
        blocked: set[str] = set()
        user_name = _require_resource_name(user, "list_mfa_devices")
        for index, item in enumerate(source.items):
            path = f"MFADevices[{index}]"
            serial: str | None = None
            try:
                device = require_mapping(
                    item,
                    operation_name="list_mfa_devices",
                    fact_path=path,
                )
                device_user = _required_string_member(
                    device,
                    "UserName",
                    "list_mfa_devices",
                    f"{path}.UserName",
                )
                if device_user != user_name:
                    raise CollectorEvidenceError("list_mfa_devices", f"{path}.UserName")
                serial = _required_string_member(
                    device,
                    "SerialNumber",
                    "list_mfa_devices",
                    f"{path}.SerialNumber",
                )
                _reject_unsafe_identity(serial, "list_mfa_devices", f"{path}.SerialNumber")
                if serial.startswith("arn:"):
                    _validate_identity_arn(
                        serial,
                        partition=self.partition,
                        account_id=self.account_id,
                        resource_prefix="mfa/",
                        operation_name="list_mfa_devices",
                        fact_path=f"{path}.SerialNumber",
                    )
                if serial in blocked:
                    discarded += 1
                    continue
                enabled_at = _required_datetime_member(
                    device,
                    "EnableDate",
                    "list_mfa_devices",
                    f"{path}.EnableDate",
                )
                previous = raw_by_id.get(serial)
                if previous is not None:
                    if previous == device:
                        continue
                    blocked.add(serial)
                    raw_by_id.pop(serial, None)
                    if resources.pop(serial, None) is not None:
                        discarded += 1
                    discarded += 1
                    errors.append(
                        CollectorEvidenceConflictError(
                            "list_mfa_devices",
                            f"{path}.SerialNumber",
                        )
                    )
                    continue
                resource = NormalizedResource(
                    account_id=self.account_id,
                    service="iam",
                    resource_type="iam_mfa_device",
                    aws_resource_id=serial,
                    arn=serial if serial.startswith("arn:") else None,
                    name=serial.rsplit("/", 1)[-1],
                    scope=ResourceScope.GLOBAL,
                    region=None,
                    configuration={
                        "user_id": user.aws_resource_id,
                        "user_name": user_name,
                        "enabled_at": to_json_safe(enabled_at),
                    },
                    raw_configuration={
                        "UserName": user_name,
                        "SerialNumber": serial,
                        "EnableDate": to_json_safe(enabled_at),
                    },
                )
                raw_by_id[serial] = device
                resources[serial] = resource
            except CollectorEvidenceError as error:
                errors.append(error)
                discarded += 1
                if serial is not None:
                    resources.pop(serial, None)
                    raw_by_id.pop(serial, None)
        ordered = tuple(sorted(resources.values(), key=lambda item: item.identity))
        return (
            ordered,
            tuple(raw_by_id[item.aws_resource_id] for item in ordered),
            _preferred_error(errors),
            discarded,
        )

    def _exclude_cross_user_child_conflicts(
        self,
        *,
        parent: NormalizedResource,
        children: tuple[NormalizedResource, ...],
        raw_by_id: Mapping[str, Mapping[str, Any]],
        evidence_kind: str,
        source_api: str,
        operation_name: str,
        configuration_field: str,
        identity_field: str,
        payload_ids_field: str,
        payload_count_field: str,
    ) -> tuple[
        tuple[NormalizedResource, ...],
        Mapping[str, Mapping[str, Any]],
        BaseException | None,
        int,
    ]:
        """Quarantine an impossible child identity observed under multiple IAM users."""

        retained: list[NormalizedResource] = []
        retained_raw: dict[str, Mapping[str, Any]] = {}
        conflicts: list[BaseException] = []
        for child in children:
            identity = child.identity
            existing = self.resources.get(identity)
            if identity in self.conflicted_user_child_identities:
                conflicts.append(
                    CollectorEvidenceConflictError(
                        operation_name,
                        identity_field,
                    )
                )
                continue
            if existing is None or existing == child:
                retained.append(child)
                retained_raw[child.aws_resource_id] = raw_by_id[child.aws_resource_id]
                continue

            conflict = CollectorEvidenceConflictError(
                operation_name,
                identity_field,
            )
            conflicts.append(conflict)
            self.conflicted_user_child_identities.add(identity)
            self.resources.pop(identity, None)
            prior_parent = self._iam_user_by_id(existing.configuration.get("user_id"))
            prior_observation = self._remove_user_child_evidence(
                child=existing,
                parent=prior_parent,
                evidence_kind=evidence_kind,
            )
            self._remove_child_from_embedded_configuration(
                parent=prior_parent,
                configuration_field=configuration_field,
                identity_field=identity_field,
                child_id=child.aws_resource_id,
            )
            prior_payload = prior_observation.artifact.model_dump(mode="json")["normalized_payload"]
            prior_ids = prior_payload.get(payload_ids_field, [])
            if not isinstance(prior_ids, list):  # pragma: no cover - collector invariant
                raise TypeError("IAM child evidence IDs must be a list")
            remaining_ids = sorted(item for item in prior_ids if item != child.aws_resource_id)
            prior_discarded = prior_payload.get("discarded_item_count", 0)
            if not isinstance(prior_discarded, int) or isinstance(prior_discarded, bool):
                raise TypeError("IAM child discarded count must be an integer")
            self._record_enrichment(
                prior_parent,
                collector="iam.users",
                evidence_kind=evidence_kind,
                source_api=source_api,
                payload={
                    payload_ids_field: remaining_ids,
                    payload_count_field: len(remaining_ids),
                    "discarded_item_count": prior_discarded + 1,
                },
                error=conflict,
            )
        return (
            tuple(retained),
            retained_raw,
            _preferred_error(conflicts),
            len(conflicts),
        )

    def _iam_user_by_id(self, user_id: object) -> NormalizedResource:
        if not isinstance(user_id, str):  # pragma: no cover - child model invariant
            raise TypeError("IAM child resource must identify its parent user")
        candidates = [
            resource
            for resource in self.resources.values()
            if resource.resource_type == "iam_user" and resource.aws_resource_id == user_id
        ]
        if len(candidates) != 1:  # pragma: no cover - discovery identity invariant
            raise ValueError("IAM child parent user must resolve exactly once")
        return candidates[0]

    def _remove_user_child_evidence(
        self,
        *,
        child: NormalizedResource,
        parent: NormalizedResource,
        evidence_kind: str,
    ) -> SourceObservation:
        prior: list[SourceObservation] = []
        retained: list[SourceObservation] = []
        for observation in self.observations:
            subject = observation.outcome.subject
            if isinstance(subject, ResourceEvidenceSubject) and (
                _subject_matches_resource(subject, child)
                or (
                    _subject_matches_resource(subject, parent)
                    and observation.outcome.evidence_kind == evidence_kind
                )
            ):
                if (
                    _subject_matches_resource(subject, parent)
                    and observation.outcome.evidence_kind == evidence_kind
                ):
                    prior.append(observation)
                continue
            retained.append(observation)
        if len(prior) != 1:
            raise ValueError("IAM child conflict requires one prior parent source")
        self.observations = retained
        self.relationships = [
            reference
            for reference in self.relationships
            if not _relationship_references_resource(reference, child)
        ]
        return prior[0]

    def _remove_child_from_embedded_configuration(
        self,
        *,
        parent: NormalizedResource,
        configuration_field: str,
        identity_field: str,
        child_id: str,
    ) -> None:
        existing = parent.configuration.get(configuration_field)
        if not isinstance(existing, list):  # pragma: no cover - user model invariant
            raise TypeError("IAM user child configuration must be a list")
        retained = [
            item
            for item in existing
            if not isinstance(item, Mapping) or item.get(identity_field) != child_id
        ]
        self._update_resource(
            parent,
            configuration_updates={configuration_field: retained},
            raw_updates={configuration_field: retained},
        )

    def _normalize_access_keys(
        self,
        user: NormalizedResource,
        source: _PaginatedResult,
    ) -> tuple[
        tuple[NormalizedResource, ...],
        Mapping[str, Mapping[str, Any]],
        BaseException | None,
        int,
    ]:
        resources: dict[str, NormalizedResource] = {}
        raw_by_id: dict[str, Mapping[str, Any]] = {}
        errors = [source.error] if source.error is not None else []
        discarded = source.discarded_item_count
        blocked: set[str] = set()
        user_name = _require_resource_name(user, "list_access_keys")
        for index, item in enumerate(source.items):
            path = f"AccessKeyMetadata[{index}]"
            key_id: str | None = None
            try:
                metadata = require_mapping(
                    item,
                    operation_name="list_access_keys",
                    fact_path=path,
                )
                key_id = _required_string_member(
                    metadata,
                    "AccessKeyId",
                    "list_access_keys",
                    f"{path}.AccessKeyId",
                )
                _reject_unsafe_identity(key_id, "list_access_keys", f"{path}.AccessKeyId")
                if key_id in blocked:
                    discarded += 1
                    continue
                metadata_user = _required_string_member(
                    metadata,
                    "UserName",
                    "list_access_keys",
                    f"{path}.UserName",
                )
                if metadata_user != user_name:
                    raise CollectorEvidenceError("list_access_keys", f"{path}.UserName")
                status = _required_string_member(
                    metadata,
                    "Status",
                    "list_access_keys",
                    f"{path}.Status",
                )
                if status not in _ACCESS_KEY_STATUSES:
                    raise CollectorEvidenceError("list_access_keys", f"{path}.Status")
                created_at = _required_datetime_member(
                    metadata,
                    "CreateDate",
                    "list_access_keys",
                    f"{path}.CreateDate",
                )
                previous = raw_by_id.get(key_id)
                if previous is not None:
                    if previous == metadata:
                        continue
                    blocked.add(key_id)
                    raw_by_id.pop(key_id, None)
                    if resources.pop(key_id, None) is not None:
                        discarded += 1
                    discarded += 1
                    errors.append(
                        CollectorEvidenceConflictError(
                            "list_access_keys",
                            f"{path}.AccessKeyId",
                        )
                    )
                    continue
                raw_by_id[key_id] = metadata
                resources[key_id] = NormalizedResource(
                    account_id=self.account_id,
                    service="iam",
                    resource_type="iam_access_key",
                    aws_resource_id=key_id,
                    arn=None,
                    name=None,
                    scope=ResourceScope.GLOBAL,
                    region=None,
                    configuration={
                        "user_id": user.aws_resource_id,
                        "user_name": user_name,
                        "status": status,
                        "created_at": to_json_safe(created_at),
                        "last_used_state": "unavailable",
                        "last_used_at": None,
                        "last_used_service": None,
                        "last_used_region": None,
                        "observed_at": to_json_safe(self.context.collected_at),
                    },
                    raw_configuration={
                        "UserName": user_name,
                        "Status": status,
                        "CreateDate": to_json_safe(created_at),
                    },
                )
            except CollectorEvidenceError as error:
                errors.append(error)
                discarded += 1
                if key_id is not None:
                    resources.pop(key_id, None)
                    raw_by_id.pop(key_id, None)
        return (
            tuple(sorted(resources.values(), key=lambda item: item.identity)),
            raw_by_id,
            _preferred_error(errors),
            discarded,
        )

    def _enrich_access_key(self, resource: NormalizedResource) -> NormalizedResource:
        response, error = self._call_response(
            "get_access_key_last_used",
            AccessKeyId=resource.aws_resource_id,
        )
        last_used_state = "unavailable"
        used_at: datetime | None = None
        service_name: str | None = None
        region: str | None = None
        expected_absence = False
        if response is not None:
            try:
                if "UserName" in response:
                    returned_user = require_non_empty_string(
                        response["UserName"],
                        operation_name="get_access_key_last_used",
                        fact_path="UserName",
                    )
                    if returned_user != resource.configuration["user_name"]:
                        raise CollectorEvidenceError("get_access_key_last_used", "UserName")
                if "AccessKeyLastUsed" not in response:
                    last_used_state = "no_recorded_use"
                    expected_absence = True
                else:
                    last_used = require_mapping(
                        response["AccessKeyLastUsed"],
                        operation_name="get_access_key_last_used",
                        fact_path="AccessKeyLastUsed",
                    )
                    service_name = _required_string_member(
                        last_used,
                        "ServiceName",
                        "get_access_key_last_used",
                        "AccessKeyLastUsed.ServiceName",
                    )
                    region = _required_string_member(
                        last_used,
                        "Region",
                        "get_access_key_last_used",
                        "AccessKeyLastUsed.Region",
                    )
                    if "LastUsedDate" not in last_used:
                        if service_name != "N/A" or region != "N/A":
                            raise CollectorEvidenceError(
                                "get_access_key_last_used",
                                "AccessKeyLastUsed.LastUsedDate",
                            )
                        last_used_state = "no_recorded_use"
                        expected_absence = True
                    else:
                        used_at = require_datetime(
                            last_used["LastUsedDate"],
                            operation_name="get_access_key_last_used",
                            fact_path="AccessKeyLastUsed.LastUsedDate",
                        )
                        last_used_state = "recorded_use"
            except CollectorEvidenceError as caught:
                error = caught
                last_used_state = "unavailable"
                used_at = None
                service_name = None
                region = None

        resource = self._update_resource(
            resource,
            configuration_updates={
                "last_used_state": last_used_state,
                "last_used_at": to_json_safe(used_at),
                "last_used_service": service_name,
                "last_used_region": region,
            },
            raw_updates={
                "LastUsed": (
                    None
                    if last_used_state == "no_recorded_use"
                    else {
                        "LastUsedDate": to_json_safe(used_at),
                        "ServiceName": service_name,
                        "Region": region,
                    }
                )
            },
        )
        self._record_enrichment(
            resource,
            collector="iam.users",
            evidence_kind="iam.access-key.last-used",
            source_api="iam:GetAccessKeyLastUsed",
            payload={
                "last_used_state": last_used_state,
                "last_used_at": to_json_safe(used_at),
                "last_used_service": service_name,
                "last_used_region": region,
                "observed_at": to_json_safe(self.context.collected_at),
            },
            error=error,
            expected_absence=expected_absence and error is None,
        )
        return resource

    def _enrich_group(self, original: NormalizedResource) -> None:
        resource = self._resource(original)
        group_name = _require_resource_name(resource, "list_groups")
        members, member_error, discarded = self._collect_group_members(resource)
        resource = self._update_resource(
            resource,
            configuration_updates={
                "member_user_ids": sorted(member.aws_resource_id for member in members)
            },
        )
        membership_observation = self._record_enrichment(
            resource,
            collector="iam.groups",
            evidence_kind="iam.group.members",
            source_api="iam:GetGroup",
            payload={
                "member_user_ids": sorted(member.aws_resource_id for member in members),
                "member_count": len(members),
                "discarded_item_count": discarded,
            },
            error=member_error,
        )
        if membership_observation.outcome.state is EvidenceSourceState.PRESENT:
            for user in members:
                self._add_relationship(
                    RelationshipType.MEMBER_OF_GROUP,
                    user,
                    resource,
                    membership_observation,
                    "iam.group",
                )

        self._collect_managed_policy_attachments(
            resource,
            operation_name="list_attached_group_policies",
            source_api="iam:ListAttachedGroupPolicies",
            collector="iam.groups",
            evidence_kind="iam.group.attached-managed-policies",
            options={"GroupName": group_name},
        )
        self._collect_inline_policies(
            resource,
            list_operation="list_group_policies",
            get_operation="get_group_policy",
            source_api_list="iam:ListGroupPolicies",
            source_api_get="iam:GetGroupPolicy",
            collector="iam.groups",
            evidence_prefix="iam.group.inline-policies",
            options={"GroupName": group_name},
        )

    def _collect_group_members(
        self,
        group: NormalizedResource,
    ) -> tuple[tuple[NormalizedResource, ...], BaseException | None, int]:
        group_name = _require_resource_name(group, "get_group")
        members: dict[str, NormalizedResource] = {}
        seen_raw: dict[str, Mapping[str, Any]] = {}
        errors: list[BaseException] = []
        discarded = 0
        blocked: set[str] = set()
        try:
            paginator = self.client.get_paginator("get_group")
            for page_index, raw_page in enumerate(paginator.paginate(GroupName=group_name)):
                page = require_mapping(
                    raw_page,
                    operation_name="get_group",
                    fact_path=f"pages[{page_index}]",
                )
                group_value = require_mapping(
                    require_member(
                        page,
                        "Group",
                        operation_name="get_group",
                        fact_path=f"pages[{page_index}].Group",
                    ),
                    operation_name="get_group",
                    fact_path=f"pages[{page_index}].Group",
                )
                self._validate_identity_summary(
                    group_value,
                    group,
                    operation_name="get_group",
                    name_key="GroupName",
                    id_key="GroupId",
                )
                users_path = f"pages[{page_index}].Users"
                raw_users = require_list(
                    require_member(
                        page,
                        "Users",
                        operation_name="get_group",
                        fact_path=users_path,
                    ),
                    operation_name="get_group",
                    fact_path=users_path,
                )
                for user_index, raw_user in enumerate(raw_users):
                    path = f"{users_path}[{user_index}]"
                    user_id: str | None = None
                    try:
                        user = require_mapping(
                            raw_user,
                            operation_name="get_group",
                            fact_path=path,
                        )
                        user_id = _required_string_member(
                            user,
                            "UserId",
                            "get_group",
                            f"{path}.UserId",
                        )
                        _reject_unsafe_identity(user_id, "get_group", f"{path}.UserId")
                        if user_id in blocked:
                            discarded += 1
                            continue
                        candidates = [
                            item
                            for item in self.resources.values()
                            if item.resource_type == "iam_user" and item.aws_resource_id == user_id
                        ]
                        if len(candidates) != 1:
                            raise CollectorEvidenceError("get_group", f"{path}.UserId")
                        collected_user = candidates[0]
                        self._validate_identity_summary(
                            user,
                            collected_user,
                            operation_name="get_group",
                            name_key="UserName",
                            id_key="UserId",
                        )
                        previous = seen_raw.get(user_id)
                        if previous is not None:
                            if previous == user:
                                continue
                            blocked.add(user_id)
                            seen_raw.pop(user_id, None)
                            if members.pop(user_id, None) is not None:
                                discarded += 1
                            discarded += 1
                            errors.append(
                                CollectorEvidenceConflictError(
                                    "get_group",
                                    f"{path}.UserId",
                                )
                            )
                            continue
                        seen_raw[user_id] = user
                        members[user_id] = collected_user
                    except CollectorEvidenceError as error:
                        errors.append(error)
                        discarded += 1
                        if user_id is not None:
                            members.pop(user_id, None)
                            seen_raw.pop(user_id, None)
        except _EXPECTED_FAILURES as error:
            errors.append(error)
        return (
            tuple(sorted(members.values(), key=lambda item: item.identity)),
            _preferred_error(errors),
            discarded,
        )

    def _enrich_role(self, original: NormalizedResource) -> None:
        resource = self._resource(original)
        role_name = _require_resource_name(resource, "list_roles")
        profile, profile_error = self._get_identity_profile(
            "get_role",
            "Role",
            resource,
            RoleName=role_name,
        )
        boundary_arn: str | None = None
        trust_policy: Mapping[str, object] | None = None
        if profile is not None:
            try:
                boundary_arn, trust_policy = self._validate_profile(
                    profile,
                    resource,
                    operation_name="get_role",
                    name_key="RoleName",
                    id_key="RoleId",
                    allow_trust_policy=True,
                )
                resource = self._update_resource(
                    resource,
                    configuration_updates={
                        "permissions_boundary_arn": boundary_arn,
                        "trust_policy_document": trust_policy,
                    },
                    raw_updates={"get_role": _safe_identity_profile(profile)},
                )
            except CollectorEvidenceError as error:
                profile_error = error
                boundary_arn = None
                trust_policy = None
        profile_observation = self._record_enrichment(
            resource,
            collector="iam.roles",
            evidence_kind="iam.role.profile",
            source_api="iam:GetRole",
            payload={
                "permissions_boundary_arn": boundary_arn,
                "trust_policy_document": trust_policy,
            },
            error=profile_error,
        )
        if boundary_arn is not None and profile_error is None:
            self._remember_policy_reference(
                resource,
                policy_arn=boundary_arn,
                policy_name=_policy_name_from_arn(boundary_arn),
                relationship_type=RelationshipType.PERMISSIONS_BOUNDARY,
                observation=profile_observation,
            )

        tag_source = self._paginated_mappings(
            "list_role_tags",
            "Tags",
            RoleName=role_name,
        )
        tag_error = tag_source.error
        tags: dict[str, str] = {}
        try:
            tags = tags_to_dict(
                tag_source.items,
                operation_name="list_role_tags",
                fact_path="Tags",
            )
        except CollectorEvidenceError as error:
            tag_error = _preferred_error(
                [candidate for candidate in (tag_error, error) if candidate]
            )
        resource = self._update_resource(resource, tags=tags)
        self._record_enrichment(
            resource,
            collector="iam.roles",
            evidence_kind="iam.role.tags",
            source_api="iam:ListRoleTags",
            payload={
                "tags": [{"key": key, "value": value} for key, value in sorted(tags.items())],
                "discarded_item_count": tag_source.discarded_item_count,
            },
            error=tag_error,
        )

        self._collect_managed_policy_attachments(
            resource,
            operation_name="list_attached_role_policies",
            source_api="iam:ListAttachedRolePolicies",
            collector="iam.roles",
            evidence_kind="iam.role.attached-managed-policies",
            options={"RoleName": role_name},
        )
        self._collect_inline_policies(
            resource,
            list_operation="list_role_policies",
            get_operation="get_role_policy",
            source_api_list="iam:ListRolePolicies",
            source_api_get="iam:GetRolePolicy",
            collector="iam.roles",
            evidence_prefix="iam.role.inline-policies",
            options={"RoleName": role_name},
        )

    def _get_identity_profile(
        self,
        operation_name: str,
        result_key: str,
        resource: NormalizedResource,
        **options: object,
    ) -> tuple[Mapping[str, Any] | None, BaseException | None]:
        response, error = self._call_response(operation_name, **options)
        if response is None:
            return None, error
        try:
            profile = require_mapping(
                require_member(
                    response,
                    result_key,
                    operation_name=operation_name,
                    fact_path=result_key,
                ),
                operation_name=operation_name,
                fact_path=result_key,
            )
        except CollectorEvidenceError as caught:
            return None, caught
        del resource
        return profile, error

    def _validate_profile(
        self,
        profile: Mapping[str, Any],
        resource: NormalizedResource,
        *,
        operation_name: str,
        name_key: str,
        id_key: str,
        allow_trust_policy: bool,
    ) -> tuple[str | None, Mapping[str, object] | None]:
        self._validate_identity_summary(
            profile,
            resource,
            operation_name=operation_name,
            name_key=name_key,
            id_key=id_key,
        )
        boundary_arn: str | None = None
        if "PermissionsBoundary" in profile:
            boundary = require_mapping(
                profile["PermissionsBoundary"],
                operation_name=operation_name,
                fact_path=f"{name_key}.PermissionsBoundary",
            )
            boundary_type = _required_string_member(
                boundary,
                "PermissionsBoundaryType",
                operation_name,
                "PermissionsBoundary.PermissionsBoundaryType",
            )
            if boundary_type != "PermissionsBoundaryPolicy":
                raise CollectorEvidenceError(
                    operation_name,
                    "PermissionsBoundary.PermissionsBoundaryType",
                )
            boundary_arn = _required_string_member(
                boundary,
                "PermissionsBoundaryArn",
                operation_name,
                "PermissionsBoundary.PermissionsBoundaryArn",
            )
            _parse_policy_arn(
                boundary_arn,
                partition=self.partition,
                expected_account_id=self.account_id,
                operation_name=operation_name,
                fact_path="PermissionsBoundary.PermissionsBoundaryArn",
                allow_aws_managed=True,
            )
        trust_policy: Mapping[str, object] | None = None
        if allow_trust_policy:
            trust_value = require_member(
                profile,
                "AssumeRolePolicyDocument",
                operation_name=operation_name,
                fact_path="Role.AssumeRolePolicyDocument",
            )
            trust_policy = _decode_policy_document(
                trust_value,
                operation_name=operation_name,
                fact_path="Role.AssumeRolePolicyDocument",
                identity_policy=False,
            )
        return boundary_arn, trust_policy

    def _validate_identity_summary(
        self,
        value: Mapping[str, Any],
        resource: NormalizedResource,
        *,
        operation_name: str,
        name_key: str,
        id_key: str,
    ) -> None:
        returned_name = _required_string_member(
            value,
            name_key,
            operation_name,
            f"{name_key}",
        )
        returned_id = _required_string_member(value, id_key, operation_name, f"{id_key}")
        returned_arn = _required_string_member(value, "Arn", operation_name, "Arn")
        if (
            returned_name != resource.name
            or returned_id != resource.aws_resource_id
            or returned_arn != resource.arn
        ):
            raise CollectorEvidenceError(operation_name, id_key)

    def _collect_managed_policy_attachments(
        self,
        resource: NormalizedResource,
        *,
        operation_name: str,
        source_api: str,
        collector: str,
        evidence_kind: str,
        options: Mapping[str, object],
    ) -> None:
        source = self._paginated_mappings(
            operation_name,
            "AttachedPolicies",
            **dict(options),
        )
        attachments: dict[str, str] = {}
        errors = [source.error] if source.error is not None else []
        discarded = source.discarded_item_count
        for index, item in enumerate(source.items):
            path = f"AttachedPolicies[{index}]"
            try:
                attachment = require_mapping(
                    item,
                    operation_name=operation_name,
                    fact_path=path,
                )
                name = _required_string_member(
                    attachment,
                    "PolicyName",
                    operation_name,
                    f"{path}.PolicyName",
                )
                arn = _required_string_member(
                    attachment,
                    "PolicyArn",
                    operation_name,
                    f"{path}.PolicyArn",
                )
                _parse_policy_arn(
                    arn,
                    partition=self.partition,
                    expected_account_id=self.account_id,
                    operation_name=operation_name,
                    fact_path=f"{path}.PolicyArn",
                    allow_aws_managed=True,
                )
                if name != _policy_name_from_arn(arn):
                    raise CollectorEvidenceError(operation_name, f"{path}.PolicyName")
                previous = attachments.get(arn)
                if previous is not None and previous != name:
                    attachments.pop(arn, None)
                    raise CollectorEvidenceConflictError(
                        operation_name,
                        f"{path}.PolicyArn",
                    )
                attachments[arn] = name
            except CollectorEvidenceError as error:
                errors.append(error)
                discarded += 1
        error = _preferred_error(errors)
        observation = self._record_enrichment(
            resource,
            collector=collector,
            evidence_kind=evidence_kind,
            source_api=source_api,
            payload={
                "policy_arns": sorted(attachments),
                "policy_count": len(attachments),
                "discarded_item_count": discarded,
            },
            error=error,
        )
        for arn, name in sorted(attachments.items()):
            self._remember_policy_reference(
                resource,
                policy_arn=arn,
                policy_name=name,
                relationship_type=RelationshipType.ATTACHED_MANAGED_POLICY,
                observation=observation,
            )

    def _collect_inline_policies(
        self,
        resource: NormalizedResource,
        *,
        list_operation: str,
        get_operation: str,
        source_api_list: str,
        source_api_get: str,
        collector: str,
        evidence_prefix: str,
        options: Mapping[str, object],
    ) -> None:
        source = self._paginated_strings(
            list_operation,
            "PolicyNames",
            **dict(options),
        )
        policy_names = tuple(str(item) for item in source.items)
        observation = self._record_enrichment(
            resource,
            collector=collector,
            evidence_kind=evidence_prefix,
            source_api=source_api_list,
            payload={
                "policy_names": sorted(policy_names),
                "policy_count": len(policy_names),
                "discarded_item_count": source.discarded_item_count,
            },
            error=source.error,
        )
        owner_keys = tuple(key for key in ("UserName", "GroupName", "RoleName") if key in options)
        if len(owner_keys) != 1:
            raise ValueError("inline-policy collection requires exactly one IAM owner name")
        owner_key = owner_keys[0]
        expected_owner_name = options[owner_key]
        if not isinstance(expected_owner_name, str):  # pragma: no cover - internal call contract
            raise TypeError("inline-policy owner name must be a string")
        for policy_name in sorted(policy_names):
            inline_id = _inline_policy_id(resource, policy_name)
            inline = NormalizedResource(
                account_id=self.account_id,
                service="iam",
                resource_type="iam_inline_policy",
                aws_resource_id=inline_id,
                arn=None,
                name=policy_name,
                scope=ResourceScope.GLOBAL,
                region=None,
                configuration={
                    "owner_resource_type": resource.resource_type,
                    "owner_resource_id": resource.aws_resource_id,
                    "owner_name": resource.name,
                    "policy_name": policy_name,
                    "document": None,
                    "document_sha256": None,
                    "document_complete": False,
                },
                raw_configuration={
                    "owner_resource_type": resource.resource_type,
                    "owner_resource_id": resource.aws_resource_id,
                    "PolicyName": policy_name,
                },
            )
            self._put_resource(inline)
            self._record_resource_identity(
                inline,
                collector=collector,
                evidence_kind="iam.inline-policy.reference",
                source_api=source_api_list,
            )
            if observation.outcome.state is EvidenceSourceState.PRESENT:
                self._add_relationship(
                    RelationshipType.ATTACHED_INLINE_POLICY,
                    resource,
                    inline,
                    observation,
                    "iam.inline-policy.reference",
                )

            get_options = {**dict(options), "PolicyName": policy_name}
            response, error = self._call_response(get_operation, **get_options)
            document: Mapping[str, object] | None = None
            if response is not None:
                try:
                    returned_owner = _required_string_member(
                        response,
                        owner_key,
                        get_operation,
                        owner_key,
                    )
                    if returned_owner != expected_owner_name:
                        raise CollectorEvidenceError(get_operation, owner_key)
                    returned_name = _required_string_member(
                        response,
                        "PolicyName",
                        get_operation,
                        "PolicyName",
                    )
                    if returned_name != policy_name:
                        raise CollectorEvidenceError(get_operation, "PolicyName")
                    document = _decode_policy_document(
                        require_member(
                            response,
                            "PolicyDocument",
                            operation_name=get_operation,
                            fact_path="PolicyDocument",
                        ),
                        operation_name=get_operation,
                        fact_path="PolicyDocument",
                    )
                    digest = _policy_document_digest(document)
                    inline = self._update_resource(
                        inline,
                        configuration_updates={
                            "document": document,
                            "document_sha256": digest,
                            "document_complete": True,
                        },
                        raw_updates={
                            "PolicyName": policy_name,
                            "PolicyDocument": document,
                        },
                    )
                except CollectorEvidenceError as caught:
                    error = caught
                    document = None
            self._record_enrichment(
                inline,
                collector=collector,
                evidence_kind="iam.inline-policy.document",
                source_api=source_api_get,
                payload={
                    "policy_name": policy_name,
                    "document": document,
                    "document_sha256": (
                        _policy_document_digest(document) if document is not None else None
                    ),
                },
                error=error,
            )

    def _remember_policy_reference(
        self,
        source: NormalizedResource,
        *,
        policy_arn: str,
        policy_name: str,
        relationship_type: RelationshipType,
        observation: SourceObservation,
    ) -> None:
        self.policy_references.append(
            _PolicyReference(
                source=source,
                policy_arn=policy_arn,
                policy_name=policy_name,
                relationship_type=relationship_type,
                observation=observation,
            )
        )

    def _materialize_referenced_policies(self) -> None:
        references_by_arn: dict[str, list[_PolicyReference]] = {}
        for reference in self.policy_references:
            references_by_arn.setdefault(reference.policy_arn, []).append(reference)

        for arn, references in sorted(references_by_arn.items()):
            owner, resource_type = _parse_policy_arn(
                arn,
                partition=self.partition,
                expected_account_id=self.account_id,
                operation_name="iam_policy_reference",
                fact_path="PolicyArn",
                allow_aws_managed=True,
            )
            names = {reference.policy_name for reference in references}
            if len(names) != 1:
                raise CollectorEvidenceConflictError(
                    "iam_policy_reference",
                    "PolicyName",
                )
            identity = (
                owner,
                "iam",
                resource_type,
                ResourceScope.GLOBAL.value,
                "global",
                arn,
            )
            policy = self.resources.get(identity)
            if policy is None:
                policy = NormalizedResource(
                    account_id=owner,
                    service="iam",
                    resource_type=resource_type,
                    aws_resource_id=arn,
                    arn=arn,
                    name=next(iter(names)),
                    scope=ResourceScope.GLOBAL,
                    region=None,
                    configuration={
                        "policy_id": None,
                        "path": None,
                        "default_version_id": None,
                        "is_attachable": None,
                        "attachment_count": None,
                        "permissions_boundary_usage_count": None,
                        "metadata_complete": False,
                    },
                    raw_configuration={"PolicyArn": arn},
                )
                self._put_resource(policy)
                first = sorted(
                    references,
                    key=lambda item: (
                        item.observation.outcome.source_api,
                        item.source.identity,
                        item.relationship_type.value,
                    ),
                )[0]
                self._record_resource_identity(
                    policy,
                    collector=first.observation.outcome.collector,
                    evidence_kind="iam.managed-policy.reference",
                    source_api=first.observation.outcome.source_api,
                    configuration={
                        "policy_arn": arn,
                        "reference_kind": first.relationship_type.value,
                    },
                )

            for reference in references:
                if reference.observation.outcome.state is EvidenceSourceState.PRESENT:
                    self._add_relationship(
                        reference.relationship_type,
                        reference.source,
                        policy,
                        reference.observation,
                        "iam.managed-policy.reference",
                    )

    def _enrich_managed_policy(self, original: NormalizedResource) -> None:
        policy = self._resource(original)
        response, metadata_error = self._call_response(
            "get_policy",
            PolicyArn=policy.aws_resource_id,
        )
        default_version_id: str | None = None
        if response is not None:
            try:
                metadata = require_mapping(
                    require_member(
                        response,
                        "Policy",
                        operation_name="get_policy",
                        fact_path="Policy",
                    ),
                    operation_name="get_policy",
                    fact_path="Policy",
                )
                policy = self._normalize_policy_metadata(metadata, policy)
                default_version_id = str(policy.configuration["default_version_id"])
            except CollectorEvidenceError as error:
                metadata_error = error
                default_version_id = None
        metadata_observation = self._record_enrichment(
            policy,
            collector="iam.policies",
            evidence_kind="iam.managed-policy.metadata",
            source_api="iam:GetPolicy",
            payload={
                "policy_arn": policy.aws_resource_id,
                "default_version_id": default_version_id,
                "metadata_complete": metadata_error is None,
            },
            error=metadata_error,
            identity_authoritative=True,
        )

        if policy.resource_type == "iam_customer_managed_policy":
            self._collect_policy_tags(policy)

        if default_version_id is None or metadata_error is not None:
            return
        version_id = _managed_policy_version_id(policy.aws_resource_id, default_version_id)
        version = NormalizedResource(
            account_id=policy.account_id,
            service="iam",
            resource_type="iam_managed_policy_version",
            aws_resource_id=version_id,
            arn=None,
            name=default_version_id,
            scope=ResourceScope.GLOBAL,
            region=None,
            configuration={
                "policy_arn": policy.aws_resource_id,
                "version_id": default_version_id,
                "is_default_version": True,
                "created_at": None,
                "document": None,
                "document_sha256": None,
                "document_complete": False,
            },
            raw_configuration={
                "PolicyArn": policy.aws_resource_id,
                "VersionId": default_version_id,
            },
        )
        self._put_resource(version)
        self._record_resource_identity(
            version,
            collector="iam.policies",
            evidence_kind="iam.managed-policy-version.reference",
            source_api="iam:GetPolicy",
        )
        self._add_relationship(
            RelationshipType.SELECTS_DEFAULT_VERSION,
            policy,
            version,
            metadata_observation,
            "iam.managed-policy-version.reference",
        )

        version_response, version_error = self._call_response(
            "get_policy_version",
            PolicyArn=policy.aws_resource_id,
            VersionId=default_version_id,
        )
        document: Mapping[str, object] | None = None
        created_at: datetime | None = None
        if version_response is not None:
            try:
                raw_version = require_mapping(
                    require_member(
                        version_response,
                        "PolicyVersion",
                        operation_name="get_policy_version",
                        fact_path="PolicyVersion",
                    ),
                    operation_name="get_policy_version",
                    fact_path="PolicyVersion",
                )
                returned_version = _required_string_member(
                    raw_version,
                    "VersionId",
                    "get_policy_version",
                    "PolicyVersion.VersionId",
                )
                if returned_version != default_version_id:
                    raise CollectorEvidenceError(
                        "get_policy_version",
                        "PolicyVersion.VersionId",
                    )
                is_default = require_member(
                    raw_version,
                    "IsDefaultVersion",
                    operation_name="get_policy_version",
                    fact_path="PolicyVersion.IsDefaultVersion",
                )
                if is_default is not True:
                    raise CollectorEvidenceError(
                        "get_policy_version",
                        "PolicyVersion.IsDefaultVersion",
                    )
                created_at = _required_datetime_member(
                    raw_version,
                    "CreateDate",
                    "get_policy_version",
                    "PolicyVersion.CreateDate",
                )
                document = _decode_policy_document(
                    require_member(
                        raw_version,
                        "Document",
                        operation_name="get_policy_version",
                        fact_path="PolicyVersion.Document",
                    ),
                    operation_name="get_policy_version",
                    fact_path="PolicyVersion.Document",
                )
                version = self._update_resource(
                    version,
                    configuration_updates={
                        "created_at": to_json_safe(created_at),
                        "document": document,
                        "document_sha256": _policy_document_digest(document),
                        "document_complete": True,
                    },
                    raw_updates={
                        "CreateDate": to_json_safe(created_at),
                        "Document": document,
                        "IsDefaultVersion": True,
                    },
                )
            except CollectorEvidenceError as error:
                version_error = error
                document = None
                created_at = None
        self._record_enrichment(
            version,
            collector="iam.policies",
            evidence_kind="iam.managed-policy-version.document",
            source_api="iam:GetPolicyVersion",
            payload={
                "policy_arn": policy.aws_resource_id,
                "version_id": default_version_id,
                "created_at": to_json_safe(created_at),
                "document": document,
                "document_sha256": (
                    _policy_document_digest(document) if document is not None else None
                ),
            },
            error=version_error,
            identity_authoritative=True,
        )

    def _normalize_policy_metadata(
        self,
        metadata: Mapping[str, Any],
        resource: NormalizedResource,
    ) -> NormalizedResource:
        operation = "get_policy"
        arn = _required_string_member(metadata, "Arn", operation, "Policy.Arn")
        owner, resource_type = _parse_policy_arn(
            arn,
            partition=self.partition,
            expected_account_id=self.account_id,
            operation_name=operation,
            fact_path="Policy.Arn",
            allow_aws_managed=True,
        )
        if (
            arn != resource.aws_resource_id
            or owner != resource.account_id
            or resource_type != resource.resource_type
        ):
            raise CollectorEvidenceError(operation, "Policy.Arn")
        policy_name = _required_string_member(
            metadata,
            "PolicyName",
            operation,
            "Policy.PolicyName",
        )
        if policy_name != resource.name or policy_name != _policy_name_from_arn(arn):
            raise CollectorEvidenceError(operation, "Policy.PolicyName")
        policy_id = _required_string_member(
            metadata,
            "PolicyId",
            operation,
            "Policy.PolicyId",
        )
        default_version_id = _required_string_member(
            metadata,
            "DefaultVersionId",
            operation,
            "Policy.DefaultVersionId",
        )
        path = _required_string_member(metadata, "Path", operation, "Policy.Path")
        _validate_identity_arn(
            arn,
            partition=self.partition,
            account_id=owner,
            resource_prefix="policy/",
            operation_name=operation,
            fact_path="Policy.Arn",
            expected_path=path,
            expected_name=policy_name,
        )
        return self._update_resource(
            resource,
            configuration_updates={
                "policy_id": policy_id,
                "path": path,
                "default_version_id": default_version_id,
                "is_attachable": _optional_boolean_member(
                    metadata,
                    "IsAttachable",
                    operation,
                    "Policy.IsAttachable",
                ),
                "attachment_count": _optional_integer_member(
                    metadata,
                    "AttachmentCount",
                    operation,
                    "Policy.AttachmentCount",
                ),
                "permissions_boundary_usage_count": _optional_integer_member(
                    metadata,
                    "PermissionsBoundaryUsageCount",
                    operation,
                    "Policy.PermissionsBoundaryUsageCount",
                ),
                "metadata_complete": True,
            },
            raw_updates={"get_policy": _safe_policy_metadata(metadata)},
        )

    def _collect_policy_tags(self, policy: NormalizedResource) -> None:
        source = self._paginated_mappings(
            "list_policy_tags",
            "Tags",
            PolicyArn=policy.aws_resource_id,
        )
        tag_error = source.error
        tags: dict[str, str] = {}
        try:
            tags = tags_to_dict(
                source.items,
                operation_name="list_policy_tags",
                fact_path="Tags",
            )
        except CollectorEvidenceError as error:
            tag_error = _preferred_error(
                [candidate for candidate in (tag_error, error) if candidate]
            )
        policy = self._update_resource(policy, tags=tags)
        self._record_enrichment(
            policy,
            collector="iam.policies",
            evidence_kind="iam.customer-managed-policy.tags",
            source_api="iam:ListPolicyTags",
            payload={
                "tags": [{"key": key, "value": value} for key, value in sorted(tags.items())],
                "discarded_item_count": source.discarded_item_count,
            },
            error=tag_error,
            identity_authoritative=True,
        )

    def _add_relationship(
        self,
        relationship_type: RelationshipType,
        source: NormalizedResource,
        target: NormalizedResource,
        observation: SourceObservation,
        target_evidence_kind: str,
    ) -> None:
        self.relationships.append(
            RelationshipReference(
                relationship_type=relationship_type,
                source=_observed_endpoint(self.context, source),
                target=RelationshipEndpoint.for_aws_resource(
                    aws_account_id=target.account_id,
                    service=target.service,
                    resource_type=target.resource_type,
                    aws_resource_id=target.aws_resource_id,
                    scope=target.scope,
                    region=target.region,
                    observed_in_scan_id=None,
                ),
                provenance=observation.provenance,
                target_collector_name=self.operational_collector_name,
                target_evidence_kind=target_evidence_kind,
            )
        )

    def _update_resource(
        self,
        resource: NormalizedResource,
        *,
        tags: Mapping[str, str] | None = None,
        configuration_updates: Mapping[str, object] | None = None,
        raw_updates: Mapping[str, object] | None = None,
    ) -> NormalizedResource:
        updated = resource.model_copy(
            update={
                "tags": dict(tags) if tags is not None else resource.tags,
                "configuration": {
                    **resource.configuration,
                    **dict(configuration_updates or {}),
                },
                "raw_configuration": {
                    **resource.raw_configuration,
                    **dict(raw_updates or {}),
                },
            }
        )
        self.resources[updated.identity] = updated
        return updated

    def _call_response(
        self,
        operation_name: str,
        **options: object,
    ) -> tuple[Mapping[str, Any] | None, BaseException | None]:
        try:
            raw_response = getattr(self.client, operation_name)(**options)
            return (
                require_mapping(
                    raw_response,
                    operation_name=operation_name,
                    fact_path="response",
                ),
                None,
            )
        except _EXPECTED_FAILURES as error:
            return None, error


def _resource_subject(
    context: CollectionContext,
    resource: NormalizedResource,
) -> ResourceEvidenceSubject:
    return ResourceEvidenceSubject.for_aws_resource(
        scan_id=context.scan_id,
        aws_account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        aws_resource_id=resource.aws_resource_id,
        scope=resource.scope,
        region=resource.region,
    )


def _observed_endpoint(
    context: CollectionContext,
    resource: NormalizedResource,
) -> RelationshipEndpoint:
    return RelationshipEndpoint.for_aws_resource(
        aws_account_id=resource.account_id,
        service=resource.service,
        resource_type=resource.resource_type,
        aws_resource_id=resource.aws_resource_id,
        scope=resource.scope,
        region=resource.region,
        observed_in_scan_id=context.scan_id,
    )


def _subject_matches_resource(
    subject: ResourceEvidenceSubject,
    resource: NormalizedResource,
) -> bool:
    return (
        subject.aws_account_id == resource.account_id
        and subject.service == resource.service
        and subject.resource_type == resource.resource_type
        and subject.aws_resource_id == resource.aws_resource_id
        and subject.scope is resource.scope
        and subject.region == resource.region
    )


def _endpoint_matches_resource(
    endpoint: RelationshipEndpoint,
    resource: NormalizedResource,
) -> bool:
    return (
        endpoint.aws_account_id == resource.account_id
        and endpoint.service == resource.service
        and endpoint.resource_type == resource.resource_type
        and endpoint.aws_resource_id == resource.aws_resource_id
        and endpoint.scope is resource.scope
        and endpoint.region == resource.region
    )


def _relationship_references_resource(
    reference: RelationshipReference,
    resource: NormalizedResource,
) -> bool:
    return _endpoint_matches_resource(reference.source, resource) or (
        isinstance(reference.target, RelationshipEndpoint)
        and _endpoint_matches_resource(reference.target, resource)
    )


def _artifact_configuration(resource: NormalizedResource) -> dict[str, object]:
    """Keep graph artifacts credential-free while legacy snapshots retain their shape."""

    configuration = dict(resource.configuration)
    if resource.resource_type == "iam_user":
        configuration.pop("access_keys", None)
        configuration.pop("mfa_devices", None)
    return configuration


def _evidence_reference(evidence_kind: str, identity: str) -> str:
    identity_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"normalized://aws/iam/{evidence_kind}/{identity_digest}"


def _reject_unsafe_identity(value: str, operation_name: str, fact_path: str) -> None:
    if any(separator in value for separator in ("\x1f", "\r", "\n")):
        raise CollectorEvidenceError(operation_name, fact_path)


def _require_resource_name(resource: NormalizedResource, operation_name: str) -> str:
    if resource.name is None:
        raise CollectorEvidenceError(operation_name, "resource.name")
    return resource.name


def _optional_string_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in value or value[key] is None:
        return None
    return require_string(
        value[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _optional_integer_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> int | None:
    if key not in value or value[key] is None:
        return None
    return require_integer(
        value[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _optional_boolean_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> bool | None:
    if key not in value or value[key] is None:
        return None
    return require_boolean(
        value[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _validate_identity_arn(
    arn: str,
    *,
    partition: str,
    account_id: str,
    resource_prefix: str,
    operation_name: str,
    fact_path: str,
    expected_path: str | None = None,
    expected_name: str | None = None,
) -> None:
    _reject_unsafe_identity(arn, operation_name, fact_path)
    parts = arn.split(":", 5)
    if (
        len(parts) != 6
        or parts[:3] != ["arn", partition, "iam"]
        or parts[3] != ""
        or parts[4] != account_id
        or not parts[5].startswith(resource_prefix)
        or len(parts[5]) == len(resource_prefix)
        or not parts[5].rsplit("/", 1)[-1]
    ):
        raise CollectorEvidenceError(operation_name, fact_path)
    if (expected_path is None) != (expected_name is None):
        raise ValueError("IAM ARN validation requires both expected path and name")
    if expected_path is not None and expected_name is not None:
        _reject_unsafe_identity(expected_path, operation_name, fact_path)
        _reject_unsafe_identity(expected_name, operation_name, fact_path)
        if (
            not expected_path.startswith("/")
            or not expected_path.endswith("/")
            or (len(expected_path) > 1 and not expected_path[1:-1])
            or parts[5] != f"{resource_prefix.removesuffix('/')}{expected_path}{expected_name}"
        ):
            raise CollectorEvidenceError(operation_name, fact_path)


def _parse_policy_arn(
    arn: str,
    *,
    partition: str,
    expected_account_id: str,
    operation_name: str,
    fact_path: str,
    allow_aws_managed: bool,
) -> tuple[str, str]:
    _reject_unsafe_identity(arn, operation_name, fact_path)
    parts = arn.split(":", 5)
    if (
        len(parts) != 6
        or parts[:3] != ["arn", partition, "iam"]
        or parts[3] != ""
        or not parts[5].startswith("policy/")
        or len(parts[5]) == len("policy/")
        or not parts[5].rsplit("/", 1)[-1]
    ):
        raise CollectorEvidenceError(operation_name, fact_path)
    owner = parts[4]
    if owner == "aws":
        if not allow_aws_managed:
            raise CollectorEvidenceError(operation_name, fact_path)
        return "aws", "iam_aws_managed_policy"
    if owner != expected_account_id:
        raise CollectorEvidenceError(operation_name, fact_path)
    return owner, "iam_customer_managed_policy"


def _policy_name_from_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1]


def _inline_policy_id(owner: NormalizedResource, policy_name: str) -> str:
    return json.dumps(
        {
            "owner_account_id": owner.account_id,
            "owner_resource_id": owner.aws_resource_id,
            "owner_resource_type": owner.resource_type,
            "policy_name": policy_name,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _managed_policy_version_id(policy_arn: str, version_id: str) -> str:
    return json.dumps(
        {"policy_arn": policy_arn, "version_id": version_id},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_policy_document(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
    identity_policy: bool = True,
) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        document: object = dict(value)
    elif isinstance(value, str):
        if not value:
            raise CollectorEvidenceError(operation_name, fact_path)
        for index, character in enumerate(value):
            if character == "%" and (
                index + 2 >= len(value)
                or any(
                    candidate not in "0123456789abcdefABCDEF"
                    for candidate in value[index + 1 : index + 3]
                )
            ):
                raise CollectorEvidenceError(operation_name, fact_path)

        def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate policy key")
                result[key] = item
            return result

        try:
            decoded = unquote_to_bytes(value).decode("utf-8")
            document = json.loads(decoded, object_pairs_hook=reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise CollectorEvidenceError(operation_name, fact_path) from error
    else:
        raise CollectorEvidenceError(operation_name, fact_path)
    document = _strict_json_value(
        document,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if not isinstance(document, Mapping):
        raise CollectorEvidenceError(operation_name, fact_path)
    normalized = dict(document)
    if "Statement" not in normalized:
        raise CollectorEvidenceError(operation_name, f"{fact_path}.Statement")
    statements = normalized["Statement"]
    if isinstance(statements, Mapping):
        statement_items = [dict(statements)]
    elif isinstance(statements, list) and statements:
        statement_items = []
        for index, statement in enumerate(statements):
            if not isinstance(statement, Mapping):
                raise CollectorEvidenceError(
                    operation_name,
                    f"{fact_path}.Statement[{index}]",
                )
            statement_items.append(dict(statement))
    else:
        raise CollectorEvidenceError(operation_name, f"{fact_path}.Statement")
    for index, statement in enumerate(statement_items):
        statement_path = f"{fact_path}.Statement[{index}]"
        effect = require_non_empty_string(
            require_member(
                statement,
                "Effect",
                operation_name=operation_name,
                fact_path=f"{statement_path}.Effect",
            ),
            operation_name=operation_name,
            fact_path=f"{statement_path}.Effect",
        )
        if effect not in {"Allow", "Deny"}:
            raise CollectorEvidenceError(operation_name, f"{statement_path}.Effect")
        action_fields = [name for name in ("Action", "NotAction") if name in statement]
        if len(action_fields) != 1:
            raise CollectorEvidenceError(operation_name, statement_path)
        resource_fields = [name for name in ("Resource", "NotResource") if name in statement]
        principal_fields = [name for name in ("Principal", "NotPrincipal") if name in statement]
        if identity_policy:
            if len(resource_fields) != 1 or principal_fields:
                raise CollectorEvidenceError(operation_name, statement_path)
        elif len(principal_fields) != 1 or resource_fields:
            raise CollectorEvidenceError(operation_name, statement_path)
        for element_name in ("Action", "NotAction", "Resource", "NotResource"):
            if element_name in statement:
                _validate_policy_string_or_list(
                    statement[element_name],
                    operation_name=operation_name,
                    fact_path=f"{statement_path}.{element_name}",
                )
        for element_name in ("Principal", "NotPrincipal"):
            if element_name in statement:
                _validate_policy_principal(
                    statement[element_name],
                    operation_name=operation_name,
                    fact_path=f"{statement_path}.{element_name}",
                )
        if "Condition" in statement:
            require_mapping(
                statement["Condition"],
                operation_name=operation_name,
                fact_path=f"{statement_path}.Condition",
            )
    normalized["Statement"] = statement_items
    return normalized


def _strict_json_value(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
    ancestors: set[int] | None = None,
    depth: int = 0,
) -> object:
    """Return an immutable-evidence-safe JSON value without coercing malformed objects."""

    if depth > 100:
        raise CollectorEvidenceError(operation_name, fact_path)
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CollectorEvidenceError(operation_name, fact_path)
        return value

    if ancestors is None:
        ancestors = set()
    identity = id(value)
    if identity in ancestors:
        raise CollectorEvidenceError(operation_name, fact_path)

    if isinstance(value, Mapping):
        ancestors.add(identity)
        try:
            normalized: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise CollectorEvidenceError(operation_name, fact_path)
                normalized[key] = _strict_json_value(
                    item,
                    operation_name=operation_name,
                    fact_path=f"{fact_path}.{key}",
                    ancestors=ancestors,
                    depth=depth + 1,
                )
            return normalized
        finally:
            ancestors.remove(identity)

    if isinstance(value, list):
        ancestors.add(identity)
        try:
            return [
                _strict_json_value(
                    item,
                    operation_name=operation_name,
                    fact_path=f"{fact_path}[{index}]",
                    ancestors=ancestors,
                    depth=depth + 1,
                )
                for index, item in enumerate(value)
            ]
        finally:
            ancestors.remove(identity)

    raise CollectorEvidenceError(operation_name, fact_path)


def _validate_policy_principal(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> None:
    if isinstance(value, str):
        require_non_empty_string(
            value,
            operation_name=operation_name,
            fact_path=fact_path,
        )
        return
    principal = require_mapping(
        value,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if not principal:
        raise CollectorEvidenceError(operation_name, fact_path)
    for principal_type, identities in principal.items():
        require_non_empty_string(
            principal_type,
            operation_name=operation_name,
            fact_path=fact_path,
        )
        _validate_policy_string_or_list(
            identities,
            operation_name=operation_name,
            fact_path=f"{fact_path}.{principal_type}",
        )


def _validate_policy_string_or_list(
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> None:
    if isinstance(value, str):
        require_non_empty_string(
            value,
            operation_name=operation_name,
            fact_path=fact_path,
        )
        return
    values = require_list(
        value,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if not values:
        raise CollectorEvidenceError(operation_name, fact_path)
    for index, item in enumerate(values):
        require_non_empty_string(
            item,
            operation_name=operation_name,
            fact_path=f"{fact_path}[{index}]",
        )


def _policy_document_digest(document: Mapping[str, object]) -> str:
    canonical = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_identity_profile(profile: Mapping[str, Any]) -> dict[str, object]:
    allowed = {
        "Path",
        "UserName",
        "UserId",
        "RoleName",
        "RoleId",
        "Arn",
        "CreateDate",
        "PasswordLastUsed",
        "Description",
        "MaxSessionDuration",
        "PermissionsBoundary",
        "AssumeRolePolicyDocument",
    }
    return {key: to_json_safe(value) for key, value in profile.items() if key in allowed}


def _safe_policy_metadata(metadata: Mapping[str, Any]) -> dict[str, object]:
    allowed = {
        "PolicyName",
        "PolicyId",
        "Arn",
        "Path",
        "DefaultVersionId",
        "AttachmentCount",
        "PermissionsBoundaryUsageCount",
        "IsAttachable",
        "Description",
        "CreateDate",
        "UpdateDate",
    }
    return {key: to_json_safe(value) for key, value in metadata.items() if key in allowed}


def _legacy_last_used(resource: NormalizedResource) -> dict[str, object] | None:
    if resource.configuration["last_used_state"] == "no_recorded_use":
        return None
    if resource.configuration["last_used_state"] != "recorded_use":
        return None
    return {
        "LastUsedDate": resource.configuration["last_used_at"],
        "ServiceName": resource.configuration["last_used_service"],
        "Region": resource.configuration["last_used_region"],
    }


def _state_for(
    error: BaseException | None,
) -> tuple[EvidenceSourceState, EvidenceFailureCategory | None]:
    if error is None:
        return EvidenceSourceState.PRESENT, None
    return source_failure(error)


def _preferred_error(errors: list[BaseException]) -> BaseException | None:
    for expected_type in (CollectorEvidenceConflictError, CollectorEvidenceError):
        for error in errors:
            if isinstance(error, expected_type):
                return error
    return errors[0] if errors else None


def _required_string_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> str:
    return require_non_empty_string(
        require_member(
            value,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _required_datetime_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> datetime:
    return require_datetime(
        require_member(
            value,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _nullable_datetime_member(
    value: Mapping[str, Any],
    key: str,
    operation_name: str,
    fact_path: str,
) -> datetime | None:
    if key not in value or value[key] is None:
        return None
    return require_datetime(
        value[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _validate_optional_access_key_metadata(
    key_metadata: Mapping[str, Any],
    expected_user_name: str,
) -> None:
    operation_name = "list_access_keys"
    fact_path = "AccessKeyMetadata[]"
    if "UserName" in key_metadata:
        user_name = require_non_empty_string(
            key_metadata["UserName"],
            operation_name=operation_name,
            fact_path=f"{fact_path}.UserName",
        )
        if user_name != expected_user_name:
            raise CollectorEvidenceError(operation_name, f"{fact_path}.UserName")
    if "Status" in key_metadata:
        status = require_non_empty_string(
            key_metadata["Status"],
            operation_name=operation_name,
            fact_path=f"{fact_path}.Status",
        )
        if status not in _ACCESS_KEY_STATUSES:
            raise CollectorEvidenceError(operation_name, f"{fact_path}.Status")
    if "CreateDate" in key_metadata:
        require_datetime(
            key_metadata["CreateDate"],
            operation_name=operation_name,
            fact_path=f"{fact_path}.CreateDate",
        )


def _validate_optional_response_user_name(
    response: Mapping[str, Any],
    expected_user_name: str,
) -> None:
    if "UserName" not in response:
        return
    user_name = require_non_empty_string(
        response["UserName"],
        operation_name="get_access_key_last_used",
        fact_path="UserName",
    )
    if user_name != expected_user_name:
        raise CollectorEvidenceError("get_access_key_last_used", "UserName")


def _validated_last_used(response: Mapping[str, Any]) -> dict[str, Any] | None:
    operation_name = "get_access_key_last_used"
    if "AccessKeyLastUsed" not in response:
        return None

    last_used = require_mapping(
        response["AccessKeyLastUsed"],
        operation_name=operation_name,
        fact_path="AccessKeyLastUsed",
    )
    _required_string_member(
        last_used,
        "ServiceName",
        operation_name,
        "AccessKeyLastUsed.ServiceName",
    )
    _required_string_member(
        last_used,
        "Region",
        operation_name,
        "AccessKeyLastUsed.Region",
    )
    if "LastUsedDate" in last_used:
        require_datetime(
            last_used["LastUsedDate"],
            operation_name=operation_name,
            fact_path="AccessKeyLastUsed.LastUsedDate",
        )
    return last_used
