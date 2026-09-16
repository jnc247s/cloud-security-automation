"""Sprint 5A EC2 instance and EBS evidence collection.

The collector is deliberately fact-only.  It records source completeness and normalized AWS
facts, while later rule code remains responsible for interpreting those facts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Any
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError

from app.assessment.evidence_graph import EvidenceCardinality
from app.assessment.relationships import (
    RelationshipEndpoint,
    RelationshipType,
    UnresolvedRelationshipTarget,
)
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
    require_boolean,
    require_list,
    require_mapping,
    require_member,
    require_non_empty_string,
    require_string,
    source_failure,
    tags_to_dict,
    to_json_safe,
)
from app.schemas.resource import NormalizedResource, ResourceScope

_COLLECTOR_VERSION = "1.0.0"
_CONTRACT_VERSION = "1.0.0"
_EVIDENCE_SCHEMA_VERSION = "1.0.0"
_EXPECTED_FAILURES = (BotoCoreError, ClientError, CollectorEvidenceError)


@dataclass(frozen=True, slots=True)
class _InstanceFacts:
    """One validated instance and the targets referenced by its AWS observation."""

    resource: NormalizedResource
    security_group_ids: tuple[str, ...]
    volume_ids: tuple[str, ...]
    subnet_id: str | None
    vpc_id: str | None


@dataclass(frozen=True, slots=True)
class _SourceCollection:
    """Safe facts retained from one independently observable AWS source."""

    resources: tuple[NormalizedResource, ...]
    instance_facts: tuple[_InstanceFacts, ...]
    error: BaseException | None
    discarded_item_count: int


class EC2EbsCollector(ResourceCollector):
    """Collect EC2 instances, EBS volumes, and Regional EBS-default facts."""

    collector_name = "ec2_ebs_evidence"
    produces_evidence_graph = True

    def collect(self) -> list[NormalizedResource]:
        """Preserve the established direct collector API for offline and CLI callers."""

        from datetime import UTC, datetime

        context = CollectionContext(
            scan_id=uuid4(),
            collection_account_id=self.client_provider.account_id,
            region=self.client_provider.region_name,
            collected_at=datetime.now(UTC),
        )
        return list(self.collect_with_context(context).resources)

    def collect_with_context(self, context: CollectionContext) -> CollectorResult:
        """Collect four independent sources and retain every safely normalized resource."""

        if context.collection_account_id != self.client_provider.account_id:
            raise ValueError("collection context account does not match the AWS client provider")
        if context.region != self.client_provider.region_name:
            raise ValueError("collection context Region does not match the AWS client provider")

        client = self.client_provider.client("ec2")
        resources: list[NormalizedResource] = []
        observations: list[SourceObservation] = []
        relationship_references: list[RelationshipReference] = []

        instances = self._collect_instances(client, context)
        resources.extend(instances.resources)
        instance_discovery = self._build_discovery_observation(
            context=context,
            source=instances,
            contract_key="ec2.instances.discovery",
            evidence_kind="ec2.instances.discovery",
            collector="ec2.instances",
            source_api="ec2:DescribeInstances",
            evidence_reference=(
                f"normalized://aws/ec2/{context.region}/describe-instances/discovery"
            ),
            evidence_schema="ec2.instances.discovery",
        )
        observations.append(instance_discovery)

        instance_facts_by_id = {
            item.resource.aws_resource_id: item for item in instances.instance_facts
        }
        for resource in instances.resources:
            observation = self._build_resource_observation(
                context=context,
                resource=resource,
                contract_key="ec2.instance",
                evidence_kind="ec2.instance",
                collector="ec2.instances",
                source_api="ec2:DescribeInstances",
                evidence_reference=(
                    f"normalized://aws/ec2/{context.region}/instances/{resource.aws_resource_id}"
                ),
                evidence_schema="ec2.instance",
            )
            observations.append(observation)
            relationship_references.extend(
                self._instance_relationships(
                    context=context,
                    facts=instance_facts_by_id[resource.aws_resource_id],
                    observation=observation,
                )
            )

        volumes = self._collect_volumes(client, context)
        resources.extend(volumes.resources)
        observations.append(
            self._build_discovery_observation(
                context=context,
                source=volumes,
                contract_key="ec2.volumes.discovery",
                evidence_kind="ec2.volumes.discovery",
                collector="ec2.volumes",
                source_api="ec2:DescribeVolumes",
                evidence_reference=(
                    f"normalized://aws/ec2/{context.region}/describe-volumes/discovery"
                ),
                evidence_schema="ec2.volumes.discovery",
            )
        )
        for resource in volumes.resources:
            observations.append(
                self._build_resource_observation(
                    context=context,
                    resource=resource,
                    contract_key="ec2.volume",
                    evidence_kind="ec2.volume",
                    collector="ec2.volumes",
                    source_api="ec2:DescribeVolumes",
                    evidence_reference=(
                        f"normalized://aws/ec2/{context.region}/volumes/{resource.aws_resource_id}"
                    ),
                    evidence_schema="ec2.volume",
                )
            )

        observations.append(self._collect_ebs_encryption_default(client, context))
        observations.append(self._collect_ebs_default_kms_key(client, context))

        resources.sort(key=lambda resource: resource.identity)
        outcomes = tuple(observation.outcome for observation in observations)
        return CollectorResult(
            resources=tuple(resources),
            status=collection_status_for(outcomes),
            source_contracts=tuple(observation.contract for observation in observations),
            artifacts=tuple(observation.artifact for observation in observations),
            source_outcomes=outcomes,
            relationships=tuple(relationship_references),
        )

    def _collect_instances(self, client: Any, context: CollectionContext) -> _SourceCollection:
        resources: dict[str, NormalizedResource] = {}
        facts: dict[str, _InstanceFacts] = {}
        seen_raw: dict[str, dict[str, Any]] = {}
        blocked_ids: set[str] = set()
        errors: list[BaseException] = []
        discarded_count = 0

        try:
            paginator = client.get_paginator("describe_instances")
            for page_index, raw_page in enumerate(paginator.paginate()):
                page = require_mapping(
                    raw_page,
                    operation_name="describe_instances",
                    fact_path=f"pages[{page_index}]",
                )
                reservations = require_list(
                    require_member(
                        page,
                        "Reservations",
                        operation_name="describe_instances",
                        fact_path=f"pages[{page_index}].Reservations",
                    ),
                    operation_name="describe_instances",
                    fact_path=f"pages[{page_index}].Reservations",
                )
                for reservation_index, raw_reservation in enumerate(reservations):
                    reservation_path = f"pages[{page_index}].Reservations[{reservation_index}]"
                    try:
                        reservation = require_mapping(
                            raw_reservation,
                            operation_name="describe_instances",
                            fact_path=reservation_path,
                        )
                        instances = require_list(
                            require_member(
                                reservation,
                                "Instances",
                                operation_name="describe_instances",
                                fact_path=f"{reservation_path}.Instances",
                            ),
                            operation_name="describe_instances",
                            fact_path=f"{reservation_path}.Instances",
                        )
                    except CollectorEvidenceError as error:
                        errors.append(error)
                        discarded_count += 1
                        continue

                    for instance_index, raw_instance in enumerate(instances):
                        item_path = f"{reservation_path}.Instances[{instance_index}]"
                        instance_id: str | None = None
                        try:
                            instance = require_mapping(
                                raw_instance,
                                operation_name="describe_instances",
                                fact_path=item_path,
                            )
                            instance_id = _required_id(
                                instance,
                                "InstanceId",
                                operation_name="describe_instances",
                                fact_path=f"{item_path}.InstanceId",
                            )
                            if instance_id in blocked_ids:
                                discarded_count += 1
                                continue
                            previous = seen_raw.get(instance_id)
                            if previous is not None:
                                if previous == instance:
                                    continue
                                if instance_id in resources:
                                    discarded_count += 1
                                raise CollectorEvidenceConflictError(
                                    "describe_instances",
                                    f"{item_path}.InstanceId",
                                )
                            seen_raw[instance_id] = instance
                            normalized = self._normalize_instance(
                                instance,
                                item_path=item_path,
                                context=context,
                            )
                            resources[instance_id] = normalized.resource
                            facts[instance_id] = normalized
                        except CollectorEvidenceError as error:
                            errors.append(error)
                            discarded_count += 1
                            if isinstance(error, CollectorEvidenceConflictError):
                                if instance_id is not None:
                                    blocked_ids.add(instance_id)
                                    resources.pop(instance_id, None)
                                    facts.pop(instance_id, None)
                            continue
        except _EXPECTED_FAILURES as error:
            errors.append(error)

        return _SourceCollection(
            resources=tuple(resources[key] for key in sorted(resources)),
            instance_facts=tuple(facts[key] for key in sorted(facts)),
            error=_preferred_error(errors),
            discarded_item_count=discarded_count,
        )

    def _normalize_instance(
        self,
        instance: Mapping[str, Any],
        *,
        item_path: str,
        context: CollectionContext,
    ) -> _InstanceFacts:
        operation = "describe_instances"
        instance_id = _required_id(
            instance,
            "InstanceId",
            operation_name=operation,
            fact_path=f"{item_path}.InstanceId",
        )
        state = require_mapping(
            require_member(
                instance,
                "State",
                operation_name=operation,
                fact_path=f"{item_path}.State",
            ),
            operation_name=operation,
            fact_path=f"{item_path}.State",
        )
        state_name = require_non_empty_string(
            require_member(
                state,
                "Name",
                operation_name=operation,
                fact_path=f"{item_path}.State.Name",
            ),
            operation_name=operation,
            fact_path=f"{item_path}.State.Name",
        )
        metadata_options = require_mapping(
            require_member(
                instance,
                "MetadataOptions",
                operation_name=operation,
                fact_path=f"{item_path}.MetadataOptions",
            ),
            operation_name=operation,
            fact_path=f"{item_path}.MetadataOptions",
        )
        normalized_metadata = {
            "state": _required_string_member(
                metadata_options,
                "State",
                operation_name=operation,
                fact_path=f"{item_path}.MetadataOptions.State",
            ),
            "http_endpoint": _required_string_member(
                metadata_options,
                "HttpEndpoint",
                operation_name=operation,
                fact_path=f"{item_path}.MetadataOptions.HttpEndpoint",
            ),
            "http_tokens": _required_string_member(
                metadata_options,
                "HttpTokens",
                operation_name=operation,
                fact_path=f"{item_path}.MetadataOptions.HttpTokens",
            ),
        }

        network_interfaces = require_list(
            require_member(
                instance,
                "NetworkInterfaces",
                operation_name=operation,
                fact_path=f"{item_path}.NetworkInterfaces",
            ),
            operation_name=operation,
            fact_path=f"{item_path}.NetworkInterfaces",
        )
        public_ipv4s: set[str] = set()
        private_ipv4s: set[str] = set()
        security_group_ids: set[str] = set()

        _add_optional_ipv4(
            public_ipv4s,
            instance,
            "PublicIpAddress",
            operation_name=operation,
            fact_path=f"{item_path}.PublicIpAddress",
        )
        _add_optional_ipv4(
            private_ipv4s,
            instance,
            "PrivateIpAddress",
            operation_name=operation,
            fact_path=f"{item_path}.PrivateIpAddress",
        )

        if "SecurityGroups" in instance:
            _add_group_ids(
                security_group_ids,
                instance["SecurityGroups"],
                operation_name=operation,
                fact_path=f"{item_path}.SecurityGroups",
            )

        for interface_index, raw_interface in enumerate(network_interfaces):
            interface_path = f"{item_path}.NetworkInterfaces[{interface_index}]"
            interface = require_mapping(
                raw_interface,
                operation_name=operation,
                fact_path=interface_path,
            )
            _add_group_ids(
                security_group_ids,
                require_member(
                    interface,
                    "Groups",
                    operation_name=operation,
                    fact_path=f"{interface_path}.Groups",
                ),
                operation_name=operation,
                fact_path=f"{interface_path}.Groups",
            )
            _add_optional_ipv4(
                private_ipv4s,
                interface,
                "PrivateIpAddress",
                operation_name=operation,
                fact_path=f"{interface_path}.PrivateIpAddress",
            )
            _add_association_public_ip(
                public_ipv4s,
                interface,
                operation_name=operation,
                fact_path=f"{interface_path}.Association",
            )

            private_addresses = require_list(
                require_member(
                    interface,
                    "PrivateIpAddresses",
                    operation_name=operation,
                    fact_path=f"{interface_path}.PrivateIpAddresses",
                ),
                operation_name=operation,
                fact_path=f"{interface_path}.PrivateIpAddresses",
            )
            for address_index, raw_address in enumerate(private_addresses):
                address_path = f"{interface_path}.PrivateIpAddresses[{address_index}]"
                address = require_mapping(
                    raw_address,
                    operation_name=operation,
                    fact_path=address_path,
                )
                _add_required_ipv4(
                    private_ipv4s,
                    address,
                    "PrivateIpAddress",
                    operation_name=operation,
                    fact_path=f"{address_path}.PrivateIpAddress",
                )
                _add_association_public_ip(
                    public_ipv4s,
                    address,
                    operation_name=operation,
                    fact_path=f"{address_path}.Association",
                )

        volume_ids: set[str] = set()
        block_devices = require_list(
            require_member(
                instance,
                "BlockDeviceMappings",
                operation_name=operation,
                fact_path=f"{item_path}.BlockDeviceMappings",
            ),
            operation_name=operation,
            fact_path=f"{item_path}.BlockDeviceMappings",
        )
        for mapping_index, raw_mapping in enumerate(block_devices):
            mapping_path = f"{item_path}.BlockDeviceMappings[{mapping_index}]"
            block_mapping = require_mapping(
                raw_mapping,
                operation_name=operation,
                fact_path=mapping_path,
            )
            if "Ebs" not in block_mapping:
                continue
            ebs = require_mapping(
                block_mapping["Ebs"],
                operation_name=operation,
                fact_path=f"{mapping_path}.Ebs",
            )
            volume_ids.add(
                _required_id(
                    ebs,
                    "VolumeId",
                    operation_name=operation,
                    fact_path=f"{mapping_path}.Ebs.VolumeId",
                )
            )

        tags = _normalize_optional_tags(
            instance,
            operation_name=operation,
            fact_path=f"{item_path}.Tags",
        )
        vpc_id = _optional_id(
            instance,
            "VpcId",
            operation_name=operation,
            fact_path=f"{item_path}.VpcId",
        )
        subnet_id = _optional_id(
            instance,
            "SubnetId",
            operation_name=operation,
            fact_path=f"{item_path}.SubnetId",
        )
        resource = NormalizedResource(
            account_id=context.collection_account_id,
            service="ec2",
            resource_type="ec2_instance",
            aws_resource_id=instance_id,
            arn=(
                f"arn:{self.client_provider.partition}:ec2:{context.region}:"
                f"{context.collection_account_id}:instance/{instance_id}"
            ),
            name=tags.get("Name"),
            scope=ResourceScope.REGIONAL,
            region=context.region,
            tags=tags,
            configuration={
                "state": state_name,
                "metadata_options": normalized_metadata,
                "public_ipv4_addresses": sorted(public_ipv4s),
                "private_ipv4_addresses": sorted(private_ipv4s),
                "vpc_id": vpc_id,
                "subnet_id": subnet_id,
                "security_group_ids": sorted(security_group_ids),
                "ebs_volume_ids": sorted(volume_ids),
            },
            raw_configuration=to_json_safe(instance),
        )
        return _InstanceFacts(
            resource=resource,
            security_group_ids=tuple(sorted(security_group_ids)),
            volume_ids=tuple(sorted(volume_ids)),
            subnet_id=subnet_id,
            vpc_id=vpc_id,
        )

    def _collect_volumes(self, client: Any, context: CollectionContext) -> _SourceCollection:
        resources: dict[str, NormalizedResource] = {}
        seen_raw: dict[str, dict[str, Any]] = {}
        blocked_ids: set[str] = set()
        errors: list[BaseException] = []
        discarded_count = 0

        try:
            paginator = client.get_paginator("describe_volumes")
            for page_index, raw_page in enumerate(paginator.paginate()):
                page = require_mapping(
                    raw_page,
                    operation_name="describe_volumes",
                    fact_path=f"pages[{page_index}]",
                )
                raw_volumes = require_list(
                    require_member(
                        page,
                        "Volumes",
                        operation_name="describe_volumes",
                        fact_path=f"pages[{page_index}].Volumes",
                    ),
                    operation_name="describe_volumes",
                    fact_path=f"pages[{page_index}].Volumes",
                )
                for volume_index, raw_volume in enumerate(raw_volumes):
                    item_path = f"pages[{page_index}].Volumes[{volume_index}]"
                    volume_id: str | None = None
                    try:
                        volume = require_mapping(
                            raw_volume,
                            operation_name="describe_volumes",
                            fact_path=item_path,
                        )
                        volume_id = _required_id(
                            volume,
                            "VolumeId",
                            operation_name="describe_volumes",
                            fact_path=f"{item_path}.VolumeId",
                        )
                        if volume_id in blocked_ids:
                            discarded_count += 1
                            continue
                        previous = seen_raw.get(volume_id)
                        if previous is not None:
                            if previous == volume:
                                continue
                            if volume_id in resources:
                                discarded_count += 1
                            raise CollectorEvidenceConflictError(
                                "describe_volumes",
                                f"{item_path}.VolumeId",
                            )
                        seen_raw[volume_id] = volume
                        resources[volume_id] = self._normalize_volume(
                            volume,
                            item_path=item_path,
                            context=context,
                        )
                    except CollectorEvidenceError as error:
                        errors.append(error)
                        discarded_count += 1
                        if isinstance(error, CollectorEvidenceConflictError):
                            if volume_id is not None:
                                blocked_ids.add(volume_id)
                                resources.pop(volume_id, None)
                        continue
        except _EXPECTED_FAILURES as error:
            errors.append(error)

        return _SourceCollection(
            resources=tuple(resources[key] for key in sorted(resources)),
            instance_facts=(),
            error=_preferred_error(errors),
            discarded_item_count=discarded_count,
        )

    def _normalize_volume(
        self,
        volume: Mapping[str, Any],
        *,
        item_path: str,
        context: CollectionContext,
    ) -> NormalizedResource:
        operation = "describe_volumes"
        volume_id = _required_id(
            volume,
            "VolumeId",
            operation_name=operation,
            fact_path=f"{item_path}.VolumeId",
        )
        state = _required_string_member(
            volume,
            "State",
            operation_name=operation,
            fact_path=f"{item_path}.State",
        )
        encrypted = require_boolean(
            require_member(
                volume,
                "Encrypted",
                operation_name=operation,
                fact_path=f"{item_path}.Encrypted",
            ),
            operation_name=operation,
            fact_path=f"{item_path}.Encrypted",
        )
        kms_key_id = _optional_non_empty_string(
            volume,
            "KmsKeyId",
            operation_name=operation,
            fact_path=f"{item_path}.KmsKeyId",
        )
        attachments = require_list(
            require_member(
                volume,
                "Attachments",
                operation_name=operation,
                fact_path=f"{item_path}.Attachments",
            ),
            operation_name=operation,
            fact_path=f"{item_path}.Attachments",
        )
        normalized_attachments: list[dict[str, object]] = []
        attachment_instance_ids: set[str] = set()
        for attachment_index, raw_attachment in enumerate(attachments):
            attachment_path = f"{item_path}.Attachments[{attachment_index}]"
            attachment = require_mapping(
                raw_attachment,
                operation_name=operation,
                fact_path=attachment_path,
            )
            associated_resource = _optional_non_empty_string(
                attachment,
                "AssociatedResource",
                operation_name=operation,
                fact_path=f"{attachment_path}.AssociatedResource",
            )
            instance_owning_service = _optional_non_empty_string(
                attachment,
                "InstanceOwningService",
                operation_name=operation,
                fact_path=f"{attachment_path}.InstanceOwningService",
            )
            instance_value = attachment.get("InstanceId")
            if instance_value is None or instance_value == "":
                if associated_resource is None or instance_owning_service is None:
                    raise CollectorEvidenceError(
                        operation,
                        f"{attachment_path}.InstanceId",
                    )
                instance_id = None
            else:
                instance_id = _validate_id_value(
                    instance_value,
                    operation_name=operation,
                    fact_path=f"{attachment_path}.InstanceId",
                )
                attachment_instance_ids.add(instance_id)
            normalized_attachments.append(
                {
                    "instance_id": instance_id,
                    "state": _optional_non_empty_string(
                        attachment,
                        "State",
                        operation_name=operation,
                        fact_path=f"{attachment_path}.State",
                    ),
                    "device": _optional_string(
                        attachment,
                        "Device",
                        operation_name=operation,
                        fact_path=f"{attachment_path}.Device",
                    ),
                    "associated_resource": associated_resource,
                    "instance_owning_service": instance_owning_service,
                }
            )
        normalized_attachments.sort(
            key=lambda item: (
                str(item["instance_id"] or ""),
                str(item["associated_resource"] or ""),
                str(item["device"] or ""),
                str(item["state"] or ""),
            )
        )

        tags = _normalize_optional_tags(
            volume,
            operation_name=operation,
            fact_path=f"{item_path}.Tags",
        )
        return NormalizedResource(
            account_id=context.collection_account_id,
            service="ec2",
            resource_type="ebs_volume",
            aws_resource_id=volume_id,
            arn=(
                f"arn:{self.client_provider.partition}:ec2:{context.region}:"
                f"{context.collection_account_id}:volume/{volume_id}"
            ),
            name=tags.get("Name"),
            scope=ResourceScope.REGIONAL,
            region=context.region,
            tags=tags,
            configuration={
                "state": state,
                "encrypted": encrypted,
                "kms_key_id": kms_key_id,
                "attachment_instance_ids": sorted(attachment_instance_ids),
                "attachments": normalized_attachments,
            },
            raw_configuration=to_json_safe(volume),
        )

    def _collect_ebs_encryption_default(
        self,
        client: Any,
        context: CollectionContext,
    ) -> SourceObservation:
        error: BaseException | None = None
        value: bool | None = None
        try:
            response = require_mapping(
                client.get_ebs_encryption_by_default(),
                operation_name="get_ebs_encryption_by_default",
                fact_path="response",
            )
            value = require_boolean(
                require_member(
                    response,
                    "EbsEncryptionByDefault",
                    operation_name="get_ebs_encryption_by_default",
                    fact_path="EbsEncryptionByDefault",
                ),
                operation_name="get_ebs_encryption_by_default",
                fact_path="EbsEncryptionByDefault",
            )
        except _EXPECTED_FAILURES as caught:
            error = caught

        state, category = _state_for(error)
        return build_source_observation(
            context=context,
            contract_key="ec2.ebs-encryption-default",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_regional_account_subject(context),
            evidence_kind="ec2.ebs-encryption-default",
            collector="ec2.ebs-defaults",
            collector_version=_COLLECTOR_VERSION,
            source_api="ec2:GetEbsEncryptionByDefault",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=(f"normalized://aws/ec2/{context.region}/ebs-encryption-by-default"),
            evidence_schema="ec2.ebs-encryption-default",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "region": context.region,
                "ebs_encryption_by_default": value,
                "complete": error is None,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )

    def _collect_ebs_default_kms_key(
        self,
        client: Any,
        context: CollectionContext,
    ) -> SourceObservation:
        error: BaseException | None = None
        kms_key_id: str | None = None
        expected_absence = False
        try:
            response = require_mapping(
                client.get_ebs_default_kms_key_id(),
                operation_name="get_ebs_default_kms_key_id",
                fact_path="response",
            )
            if "KmsKeyId" not in response or response["KmsKeyId"] is None:
                expected_absence = True
            else:
                kms_key_id = require_non_empty_string(
                    response["KmsKeyId"],
                    operation_name="get_ebs_default_kms_key_id",
                    fact_path="KmsKeyId",
                )
        except _EXPECTED_FAILURES as caught:
            error = caught

        if error is not None:
            state, category = _state_for(error)
        elif expected_absence:
            state, category = EvidenceSourceState.EXPECTED_ABSENCE, None
        else:
            state, category = EvidenceSourceState.PRESENT, None
        return build_source_observation(
            context=context,
            contract_key="ec2.ebs-default-kms-key",
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_regional_account_subject(context),
            evidence_kind="ec2.ebs-default-kms-key",
            collector="ec2.ebs-defaults",
            collector_version=_COLLECTOR_VERSION,
            source_api="ec2:GetEbsDefaultKmsKeyId",
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=f"normalized://aws/ec2/{context.region}/ebs-default-kms-key",
            evidence_schema="ec2.ebs-default-kms-key",
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "region": context.region,
                "default_kms_key_id": kms_key_id,
                "complete": error is None,
                "expected_absence": expected_absence,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )

    def _build_discovery_observation(
        self,
        *,
        context: CollectionContext,
        source: _SourceCollection,
        contract_key: str,
        evidence_kind: str,
        collector: str,
        source_api: str,
        evidence_reference: str,
        evidence_schema: str,
    ) -> SourceObservation:
        state, category = _state_for(source.error)
        return build_source_observation(
            context=context,
            contract_key=contract_key,
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.DISCOVERY,
            subject=_regional_account_subject(context),
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=_COLLECTOR_VERSION,
            source_api=source_api,
            cardinality=EvidenceCardinality.COLLECTION,
            evidence_reference=evidence_reference,
            evidence_schema=evidence_schema,
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": context.collection_account_id,
                "region": context.region,
                "resource_ids": sorted(resource.aws_resource_id for resource in source.resources),
                "resource_count": len(source.resources),
                "discarded_item_count": source.discarded_item_count,
                "complete": source.error is None,
                "failure_category": category.value if category is not None else None,
            },
            state=state,
            failure_category=category,
        )

    def _build_resource_observation(
        self,
        *,
        context: CollectionContext,
        resource: NormalizedResource,
        contract_key: str,
        evidence_kind: str,
        collector: str,
        source_api: str,
        evidence_reference: str,
        evidence_schema: str,
    ) -> SourceObservation:
        return build_source_observation(
            context=context,
            contract_key=contract_key,
            contract_version=_CONTRACT_VERSION,
            phase=EvidenceCollectionPhase.ENRICHMENT,
            subject=ResourceEvidenceSubject.for_aws_resource(
                scan_id=context.scan_id,
                aws_account_id=resource.account_id,
                service=resource.service,
                resource_type=resource.resource_type,
                aws_resource_id=resource.aws_resource_id,
                scope=resource.scope,
                region=resource.region,
            ),
            evidence_kind=evidence_kind,
            collector=collector,
            collector_version=_COLLECTOR_VERSION,
            source_api=source_api,
            cardinality=EvidenceCardinality.SINGLE,
            evidence_reference=evidence_reference,
            evidence_schema=evidence_schema,
            evidence_schema_version=_EVIDENCE_SCHEMA_VERSION,
            normalized_payload={
                "account_id": resource.account_id,
                "region": resource.region,
                "resource_type": resource.resource_type,
                "resource_id": resource.aws_resource_id,
                "arn": resource.arn,
                "tags": [
                    {"key": key, "value": value} for key, value in sorted(resource.tags.items())
                ],
                "configuration": resource.configuration,
            },
            state=EvidenceSourceState.PRESENT,
            identity_authoritative=True,
        )

    def _instance_relationships(
        self,
        *,
        context: CollectionContext,
        facts: _InstanceFacts,
        observation: SourceObservation,
    ) -> tuple[RelationshipReference, ...]:
        source = _observed_endpoint(context, facts.resource)
        references: list[RelationshipReference] = []
        for group_id in facts.security_group_ids:
            references.append(
                self._relationship_reference(
                    context=context,
                    source=source,
                    relationship_type=RelationshipType.ATTACHED_TO_SECURITY_GROUP,
                    target_resource_type="security_group",
                    target_id=group_id,
                    observation=observation,
                    target_collector_name="security_groups",
                )
            )
        for volume_id in facts.volume_ids:
            references.append(
                self._relationship_reference(
                    context=context,
                    source=source,
                    relationship_type=RelationshipType.USES_VOLUME,
                    target_resource_type="ebs_volume",
                    target_id=volume_id,
                    observation=observation,
                    target_collector_name=self.collector_name,
                    target_evidence_kind="ec2.volumes.discovery",
                    target_owner_known=True,
                )
            )
        if facts.subnet_id is not None:
            references.append(
                self._relationship_reference(
                    context=context,
                    source=source,
                    relationship_type=RelationshipType.IN_SUBNET,
                    target_resource_type="subnet",
                    target_id=facts.subnet_id,
                    observation=observation,
                )
            )
        if facts.vpc_id is not None:
            references.append(
                self._relationship_reference(
                    context=context,
                    source=source,
                    relationship_type=RelationshipType.IN_VPC,
                    target_resource_type="vpc",
                    target_id=facts.vpc_id,
                    observation=observation,
                )
            )
        return tuple(references)

    @staticmethod
    def _relationship_reference(
        *,
        context: CollectionContext,
        source: RelationshipEndpoint,
        relationship_type: RelationshipType,
        target_resource_type: str,
        target_id: str,
        observation: SourceObservation,
        target_collector_name: str | None = None,
        target_evidence_kind: str | None = None,
        target_owner_known: bool = False,
    ) -> RelationshipReference:
        target: RelationshipEndpoint | UnresolvedRelationshipTarget
        if target_owner_known:
            target = RelationshipEndpoint.for_aws_resource(
                aws_account_id=context.collection_account_id,
                service="ec2",
                resource_type=target_resource_type,
                aws_resource_id=target_id,
                scope=ResourceScope.REGIONAL,
                region=context.region,
                observed_in_scan_id=None,
            )
        else:
            target = UnresolvedRelationshipTarget.for_aws_reference(
                service="ec2",
                resource_type=target_resource_type,
                aws_resource_id=target_id,
                scope=ResourceScope.REGIONAL,
                region=context.region,
            )
        return RelationshipReference(
            relationship_type=relationship_type,
            source=source,
            target=target,
            provenance=observation.provenance,
            target_collector_name=target_collector_name,
            target_evidence_kind=target_evidence_kind,
        )


def _regional_account_subject(context: CollectionContext) -> AccountEvidenceSubject:
    return AccountEvidenceSubject(
        aws_account_id=context.collection_account_id,
        scope=ResourceScope.REGIONAL,
        region=context.region,
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


def _state_for(
    error: BaseException | None,
) -> tuple[EvidenceSourceState, EvidenceFailureCategory | None]:
    if error is None:
        return EvidenceSourceState.PRESENT, None
    return source_failure(error)


def _preferred_error(errors: list[BaseException]) -> BaseException | None:
    """Choose a deterministic sanitized state when more than one item was unusable."""

    for expected_type in (CollectorEvidenceConflictError, CollectorEvidenceError):
        for error in errors:
            if isinstance(error, expected_type):
                return error
    return errors[0] if errors else None


def _required_id(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str:
    return _validate_id_value(
        require_member(
            container,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _validate_id_value(value: object, *, operation_name: str, fact_path: str) -> str:
    identifier = require_non_empty_string(
        value,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    if "\x1f" in identifier or "\r" in identifier or "\n" in identifier:
        raise CollectorEvidenceError(operation_name, fact_path)
    return identifier


def _optional_id(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container or container[key] is None:
        return None
    return _validate_id_value(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _required_string_member(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str:
    return require_non_empty_string(
        require_member(
            container,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _optional_string(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container or container[key] is None:
        return None
    return require_string(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _optional_non_empty_string(
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> str | None:
    if key not in container or container[key] is None:
        return None
    return require_non_empty_string(
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _normalize_optional_tags(
    container: Mapping[str, Any],
    *,
    operation_name: str,
    fact_path: str,
) -> dict[str, str]:
    if "Tags" not in container:
        return {}
    tags = require_list(
        container["Tags"],
        operation_name=operation_name,
        fact_path=fact_path,
    )
    return tags_to_dict(
        tags,
        operation_name=operation_name,
        fact_path=fact_path,
        allow_missing_value=True,
    )


def _add_group_ids(
    destination: set[str],
    raw_groups: object,
    *,
    operation_name: str,
    fact_path: str,
) -> None:
    groups = require_list(
        raw_groups,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    for group_index, raw_group in enumerate(groups):
        group_path = f"{fact_path}[{group_index}]"
        group = require_mapping(
            raw_group,
            operation_name=operation_name,
            fact_path=group_path,
        )
        destination.add(
            _required_id(
                group,
                "GroupId",
                operation_name=operation_name,
                fact_path=f"{group_path}.GroupId",
            )
        )


def _add_optional_ipv4(
    destination: set[str],
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> None:
    if key not in container or container[key] is None:
        return
    _add_ipv4_value(
        destination,
        container[key],
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _add_required_ipv4(
    destination: set[str],
    container: Mapping[str, Any],
    key: str,
    *,
    operation_name: str,
    fact_path: str,
) -> None:
    _add_ipv4_value(
        destination,
        require_member(
            container,
            key,
            operation_name=operation_name,
            fact_path=fact_path,
        ),
        operation_name=operation_name,
        fact_path=fact_path,
    )


def _add_ipv4_value(
    destination: set[str],
    value: object,
    *,
    operation_name: str,
    fact_path: str,
) -> None:
    address = require_non_empty_string(
        value,
        operation_name=operation_name,
        fact_path=fact_path,
    )
    try:
        normalized = str(IPv4Address(address))
    except ValueError as error:
        raise CollectorEvidenceError(operation_name, fact_path) from error
    destination.add(normalized)


def _add_association_public_ip(
    destination: set[str],
    container: Mapping[str, Any],
    *,
    operation_name: str,
    fact_path: str,
) -> None:
    if "Association" not in container or container["Association"] is None:
        return
    association = require_mapping(
        container["Association"],
        operation_name=operation_name,
        fact_path=fact_path,
    )
    _add_optional_ipv4(
        destination,
        association,
        "PublicIp",
        operation_name=operation_name,
        fact_path=f"{fact_path}.PublicIp",
    )
