"""Network security group controls."""

from collections.abc import Mapping
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any, ClassVar

from app.rules.base import RuleEvaluationError, SecurityRule
from app.schemas.finding import ControlCategory, FindingCandidate, Severity
from app.schemas.inventory import InventorySnapshot
from app.schemas.resource import NormalizedResource


class _PublicIngressPortRule(SecurityRule):
    """Shared evaluator for an administrative TCP port exposed to the Internet."""

    target_port: ClassVar[int]

    def evaluate(self, snapshot: InventorySnapshot) -> tuple[FindingCandidate, ...]:
        findings: list[FindingCandidate] = []

        resources = sorted(
            (
                resource
                for resource in snapshot.resources
                if resource.service == "ec2" and resource.resource_type == "security_group"
            ),
            key=lambda resource: resource.identity,
        )
        for resource in resources:
            matches = self._matching_ingress(resource)
            if not matches:
                continue

            findings.append(
                self.finding_for_resource(
                    resource,
                    {
                        "group_id": resource.aws_resource_id,
                        "vpc_id": resource.configuration.get("vpc_id"),
                        "region": resource.region,
                        "target_port": self.target_port,
                        "matched_ingress": matches,
                    },
                )
            )

        return tuple(findings)

    def _matching_ingress(self, resource: NormalizedResource) -> list[dict[str, Any]]:
        ingress_rules = _required_list(
            resource.configuration,
            "ingress_rules",
            self,
            resource,
        )
        matches_by_identity: dict[tuple[object, ...], dict[str, Any]] = {}

        for rule_index, raw_rule in enumerate(ingress_rules):
            fact_path = f"configuration.ingress_rules[{rule_index}]"
            if not isinstance(raw_rule, Mapping):
                raise RuleEvaluationError(
                    self.control_id,
                    resource.aws_resource_id,
                    fact_path,
                )

            protocol, from_port, to_port, effective_coverage = self._port_coverage(
                raw_rule,
                resource,
                fact_path,
            )
            if effective_coverage is None:
                continue

            for source_type, list_name, expected_network_type in (
                ("ipv4", "ipv4_ranges", IPv4Network),
                ("ipv6", "ipv6_ranges", IPv6Network),
            ):
                ranges = _required_list(raw_rule, list_name, self, resource, fact_path)
                for range_index, raw_range in enumerate(ranges):
                    range_path = f"{fact_path}.{list_name}[{range_index}]"
                    if not isinstance(raw_range, Mapping):
                        raise RuleEvaluationError(
                            self.control_id,
                            resource.aws_resource_id,
                            range_path,
                        )

                    raw_cidr = raw_range.get("cidr")
                    if not isinstance(raw_cidr, str):
                        raise RuleEvaluationError(
                            self.control_id,
                            resource.aws_resource_id,
                            f"{range_path}.cidr",
                        )
                    try:
                        network = ip_network(raw_cidr, strict=False)
                    except ValueError as error:
                        raise RuleEvaluationError(
                            self.control_id,
                            resource.aws_resource_id,
                            f"{range_path}.cidr",
                        ) from error

                    if not isinstance(network, expected_network_type):
                        raise RuleEvaluationError(
                            self.control_id,
                            resource.aws_resource_id,
                            f"{range_path}.cidr",
                        )
                    if network.prefixlen != 0:
                        continue

                    description = raw_range.get("description")
                    if description is not None and not isinstance(description, str):
                        raise RuleEvaluationError(
                            self.control_id,
                            resource.aws_resource_id,
                            f"{range_path}.description",
                        )

                    match = {
                        "protocol": protocol,
                        "from_port": from_port,
                        "to_port": to_port,
                        "effective_port_coverage": effective_coverage,
                        "source_type": source_type,
                        "cidr": str(network),
                        "description": description,
                    }
                    match_identity = (
                        source_type,
                        str(network),
                        protocol,
                        from_port,
                        to_port,
                        description or "",
                    )
                    matches_by_identity[match_identity] = match

        return [matches_by_identity[key] for key in sorted(matches_by_identity, key=_sort_key)]

    def _port_coverage(
        self,
        rule: Mapping[str, Any],
        resource: NormalizedResource,
        fact_path: str,
    ) -> tuple[str, int | None, int | None, str | None]:
        raw_protocol = rule.get("protocol")
        if not isinstance(raw_protocol, str) or not raw_protocol.strip():
            raise RuleEvaluationError(
                self.control_id,
                resource.aws_resource_id,
                f"{fact_path}.protocol",
            )

        protocol = raw_protocol.casefold()
        raw_from_port = rule.get("from_port")
        raw_to_port = rule.get("to_port")

        if protocol in {"-1", "6"}:
            from_port = _optional_port(raw_from_port, self, resource, fact_path, "from_port")
            to_port = _optional_port(raw_to_port, self, resource, fact_path, "to_port")
            return protocol, from_port, to_port, "all_ports"

        if protocol != "tcp":
            return protocol, None, None, None

        from_port = _required_port(
            raw_from_port,
            self,
            resource,
            f"{fact_path}.from_port",
        )
        to_port = _required_port(
            raw_to_port,
            self,
            resource,
            f"{fact_path}.to_port",
        )
        if from_port > to_port:
            raise RuleEvaluationError(
                self.control_id,
                resource.aws_resource_id,
                f"{fact_path}.port_range",
            )
        if not from_port <= self.target_port <= to_port:
            return protocol, from_port, to_port, None

        return protocol, from_port, to_port, f"{from_port}-{to_port}"


class PublicSSHRule(_PublicIngressPortRule):
    """NET-001: detect security groups exposing SSH to public IP space."""

    control_id = "NET-001"
    title = "Public SSH Access"
    category = ControlCategory.NETWORK
    default_severity = Severity.HIGH
    target_port = 22
    impact = (
        "Internet-exposed SSH can permit brute-force attempts and unauthorized "
        "administrative access."
    )
    recommendation = (
        "Restrict administrative access to approved management networks or use controlled "
        "remote-management mechanisms."
    )


class PublicRDPRule(_PublicIngressPortRule):
    """NET-002: detect security groups exposing RDP to public IP space."""

    control_id = "NET-002"
    title = "Public RDP Access"
    category = ControlCategory.NETWORK
    default_severity = Severity.HIGH
    target_port = 3389
    impact = (
        "Internet-exposed RDP can permit brute-force attempts and unauthorized interactive access."
    )
    recommendation = (
        "Restrict RDP access to approved management networks or use a controlled "
        "remote-management service."
    )


def _required_list(
    container: Mapping[str, Any],
    key: str,
    rule: SecurityRule,
    resource: NormalizedResource,
    prefix: str = "configuration",
) -> list[Any]:
    value = container.get(key)
    if not isinstance(value, list):
        raise RuleEvaluationError(
            rule.control_id,
            resource.aws_resource_id,
            f"{prefix}.{key}",
        )
    return value


def _required_port(
    value: Any,
    rule: SecurityRule,
    resource: NormalizedResource,
    fact_path: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise RuleEvaluationError(
            rule.control_id,
            resource.aws_resource_id,
            fact_path,
        )
    return value


def _optional_port(
    value: Any,
    rule: SecurityRule,
    resource: NormalizedResource,
    fact_path: str,
    field_name: str,
) -> int | None:
    if value is None:
        return None
    return _required_port(value, rule, resource, f"{fact_path}.{field_name}")


def _sort_key(identity: tuple[object, ...]) -> tuple[str, ...]:
    return tuple("" if value is None else str(value) for value in identity)
