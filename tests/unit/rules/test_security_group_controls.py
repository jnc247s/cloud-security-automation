"""Canonical 6D.1 behavior, exact policy and retained-evidence boundaries."""

from copy import deepcopy

import pytest

from app.assessment.evidence_reader import AssessmentEvidenceReader
from app.assessment.models import AssessmentResult
from app.assessment.security_group_controls import network_execution
from app.rules.engine import RuleEngine
from app.rules.registry import resolve_catalog
from tests.fakes import client_error
from tests.network_control_fixtures import (
    network_bundle,
    network_profile,
    network_snapshot,
    permission,
)
from tests.unit.collectors.test_network import _vpc
from tests.unit.collectors.test_security_group_evidence import _security_group


def results(**kwargs):
    return {a.control_id: a.result.value for a in network_bundle(**kwargs)["assessments"]}


@pytest.mark.parametrize(
    "rule,expected3,expected4",
    [
        (permission(), "FAIL", "FAIL"),
        (permission(ipv4=None, ipv6="::/0"), "FAIL", "FAIL"),
        (permission(ipv4="10.0.0.0/8"), "PASS", "PASS"),
        (permission("tcp", 5432, 5432), "PASS", "FAIL"),
        (permission("tcp", 3300, 5500), "PASS", "FAIL"),
        (permission("tcp", 22, 22), "PASS", "PASS"),
        (permission("udp", 5432, 5432), "PASS", "PASS"),
        (permission("6"), "PASS", "FAIL"),
        (permission("tcp", 5432, 5432, ipv4=None, ipv6="::/0"), "PASS", "FAIL"),
        (permission("tcp", 5433, 6378), "PASS", "PASS"),
    ],
)
def test_public_truth_tables(rule, expected3, expected4):
    group = _security_group()
    group["IpPermissions"] = [rule]
    actual = results(groups=[group])
    assert actual == {"NET-003": expected3, "NET-004": expected4, "NET-005": "FAIL"}


@pytest.mark.parametrize(
    "name,ingress,egress,expected",
    [
        ("default", [], [], "PASS"),
        ("default", [permission(ipv4="10.0.0.0/8")], [], "FAIL"),
        ("default", [], [permission()], "FAIL"),
        ("application", [permission()], [permission()], "NOT_APPLICABLE"),
        ("Default", [], [], "NOT_APPLICABLE"),
    ],
)
def test_default_group(name, ingress, egress, expected):
    group = _security_group(group_name=name)
    group.update(IpPermissions=ingress, IpPermissionsEgress=egress)
    assert results(groups=[group])["NET-005"] == expected


def test_complete_empty_is_not_unavailable():
    assert set(results(groups=[]).values()) == {"NOT_APPLICABLE"}
    assert set(
        results(groups=[], group_error=client_error("AccessDenied", "offline")).values()
    ) == {"INSUFFICIENT_EVIDENCE"}


def test_explicit_empty_policy_is_not_missing():
    assert (
        results(profile=network_profile(high_risk_public_tcp_ports=()))["NET-004"]
        == "NOT_APPLICABLE"
    )
    with pytest.raises(ValueError, match="explicit policy"):
        network_profile(high_risk_public_tcp_ports=None)


@pytest.mark.parametrize(
    "field,expected",
    [
        ("group_error", "INSUFFICIENT_EVIDENCE"),
        ("vpc_error", "INSUFFICIENT_EVIDENCE"),
        ("subnet_error", "FAIL"),
        ("flow_error", "FAIL"),
    ],
)
def test_only_required_sources_affect_results(field, expected):
    assert set(results(**{field: client_error("AccessDenied", "offline")}).values()) == {expected}


def test_missing_vpc_edge_is_insufficient():
    assert set(results(vpcs=[]).values()) == {"INSUFFICIENT_EVIDENCE"}


def test_observed_external_owner_is_not_rewritten():
    owner = "210987654321"
    bundle = network_bundle(groups=[_security_group(owner_id=owner)], vpcs=[_vpc(owner_id=owner)])
    assert all(a.account_id == owner for a in bundle["assessments"])
    assert all(
        a.result is not AssessmentResult.INSUFFICIENT_EVIDENCE for a in bundle["assessments"]
    )


@pytest.mark.parametrize("change", ["cidr", "ports", "sources", "name"])
def test_missing_or_malformed_required_facts(change):
    group = _security_group()
    if change == "cidr":
        group["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "not-a-network"}]
    elif change == "ports":
        group["IpPermissions"][0]["FromPort"] = 65536
    elif change == "sources":
        del group["IpPermissions"][0]["Ipv6Ranges"]
    else:
        group.pop("GroupName")
    actual = results(groups=[group])
    if change == "name":
        assert actual["NET-005"] == "INSUFFICIENT_EVIDENCE"
    elif change == "ports":
        assert actual["NET-004"] == "INSUFFICIENT_EVIDENCE"
    else:
        assert set(actual.values()) == {"INSUFFICIENT_EVIDENCE"}


def test_facts_cannot_diverge_from_source():
    snapshot = network_snapshot()
    resources = []
    for resource in snapshot.resources:
        if resource.resource_type == "security_group":
            config = deepcopy(resource.configuration)
            config["ingress_rules"] = []
            resource = resource.model_copy(update={"configuration": config})
        resources.append(resource)
    changed = snapshot.model_copy(update={"resources": tuple(resources)})
    assert set(results(snapshot=changed).values()) == {"INSUFFICIENT_EVIDENCE"}


@pytest.mark.parametrize("result", [AssessmentResult.PASS, AssessmentResult.NOT_APPLICABLE])
def test_forged_results_are_rejected(result):
    bundle = network_bundle()
    for original in bundle["assessments"]:
        forged = original.model_copy(update={"result": result, "evidence_artifacts": ()})
        with pytest.raises(ValueError, match="network result"):
            AssessmentEvidenceReader(bundle["snapshot"]).validate_candidate(
                network_execution(), forged, profile=bundle["profile"]
            )


def test_old_catalogs_and_order_are_preserved():
    bundle = network_bundle()
    catalog, registry = resolve_catalog("aws-cloud-security-controls", "0.6.0")
    previous, _ = resolve_catalog(catalog.catalog_id, "0.5.0")
    assert all(catalog.get(c.control_id) == c for c in previous.controls)
    assert catalog.framework_catalogs[:-1] == previous.framework_catalogs
    snapshot = bundle["snapshot"].model_copy(
        update={"resources": tuple(reversed(bundle["snapshot"].resources))}
    )
    assert (
        RuleEngine(registry, catalog=catalog).assess(snapshot, bundle["profile"])
        == bundle["assessments"]
    )
