"""Catalog digests bind full provenance without depending on a database."""

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.assessment.controls import ControlCatalog, build_default_control_catalog
from app.assessment.provenance import (
    canonical_control_catalog_document,
    control_catalog_sha256,
)


def rich_catalog() -> ControlCatalog:
    """Give every set-like catalog collection at least two members for ordering tests."""

    values = build_default_control_catalog().model_dump(mode="python")
    second_framework = deepcopy(values["framework_catalogs"][0])
    second_version = "2.0-test-fixture"
    second_framework["framework"]["version"] = second_version
    second_framework["source_manifest"]["version"] = second_version
    for reference in second_framework["references"]:
        reference["framework_version"] = second_version
    for mapping in second_framework["mappings"]:
        mapping["framework_version"] = second_version
    values["framework_catalogs"] = (*values["framework_catalogs"], second_framework)
    for control in values["controls"]:
        second_mapping = deepcopy(control["framework_mappings"][0])
        second_mapping["framework_version"] = second_version
        control["framework_mappings"] = (*control["framework_mappings"], second_mapping)
        technical = control["technical"]
        technical["profile_parameters"] = ("enabled_controls", "required_tags")
        technical["limitations"] = (
            *technical["limitations"],
            "Additional synthetic limitation for provenance tests.",
        )
        technical["required_evidence"] = (
            *technical["required_evidence"],
            {
                "fact_path": "configuration.synthetic_provenance_fact",
                "description": "Additional synthetic fact for provenance tests.",
            },
        )
    return ControlCatalog.model_validate(values)


def test_digest_matches_canonical_json_serialization() -> None:
    catalog = build_default_control_catalog()
    document = canonical_control_catalog_document(catalog)
    expected = hashlib.sha256(
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    assert control_catalog_sha256(catalog) == expected
    assert len(expected) == 64
    assert ControlCatalog.model_validate(document)


def test_reordering_every_set_like_catalog_array_preserves_digest() -> None:
    catalog = rich_catalog()
    values = catalog.model_dump(mode="python")
    values["controls"] = tuple(reversed(values["controls"]))
    values["framework_catalogs"] = tuple(reversed(values["framework_catalogs"]))
    for control in values["controls"]:
        for field in ("required_evidence", "profile_parameters", "limitations"):
            control["technical"][field] = tuple(reversed(control["technical"][field]))
        control["framework_mappings"] = tuple(reversed(control["framework_mappings"]))
    for framework in values["framework_catalogs"]:
        framework["references"] = tuple(reversed(framework["references"]))
        framework["mappings"] = tuple(reversed(framework["mappings"]))
    reordered = ControlCatalog.model_validate(values)

    assert reordered != catalog
    assert canonical_control_catalog_document(reordered) == canonical_control_catalog_document(
        catalog
    )
    assert control_catalog_sha256(reordered) == control_catalog_sha256(catalog)


def test_equivalent_utc_offsets_preserve_all_mapping_and_manifest_timestamps() -> None:
    catalog = rich_catalog()
    values = catalog.model_dump(mode="python")
    western_offset = timezone(timedelta(hours=-5))
    eastern_offset = timezone(timedelta(hours=9))
    for control in values["controls"]:
        for mapping in control["framework_mappings"]:
            mapping["verified_at"] = mapping["verified_at"].astimezone(western_offset)
    for framework in values["framework_catalogs"]:
        manifest = framework["source_manifest"]
        manifest["retrieved_at"] = manifest["retrieved_at"].astimezone(eastern_offset)
        for mapping in framework["mappings"]:
            mapping["verified_at"] = mapping["verified_at"].astimezone(eastern_offset)
    equivalent = ControlCatalog.model_validate(values)

    assert control_catalog_sha256(equivalent) == control_catalog_sha256(catalog)
    document = canonical_control_catalog_document(equivalent)
    for control in document["controls"]:
        assert all(item["verified_at"].endswith("+00:00") for item in control["framework_mappings"])
    for framework in document["framework_catalogs"]:
        assert framework["source_manifest"]["retrieved_at"].endswith("+00:00")
        assert all(item["verified_at"].endswith("+00:00") for item in framework["mappings"])


@pytest.mark.parametrize(
    ("path", "changed_value"),
    [
        (("catalog_id",), "changed-catalog"),
        (("version",), "0.2.2"),
        (("controls", 0, "technical", "title"), "Changed title"),
        (("controls", 0, "technical", "measure"), "Changed technical measure"),
        (("controls", 0, "technical", "pass_logic"), "Changed pass logic"),
        (("controls", 0, "technical", "fail_logic"), "Changed fail logic"),
        (("controls", 0, "technical", "impact"), "Changed impact"),
        (("controls", 0, "technical", "remediation_guidance"), "Changed guidance"),
        (("controls", 0, "technical", "required_evidence", 0, "description"), "Changed fact"),
        (("controls", 0, "technical", "profile_parameters"), ("enabled_controls", "required_tags")),
        (("controls", 0, "technical", "limitations"), ("Changed limitation",)),
        (("controls", 0, "framework_mappings", 0, "mapping_rationale"), "Changed rationale"),
        (("controls", 0, "framework_mappings", 0, "mapping_source"), "Changed source"),
        (("controls", 0, "framework_mappings", 0, "mapping_source_version"), "Changed version"),
        (
            ("controls", 0, "framework_mappings", 0, "verified_at"),
            datetime(2027, 1, 1, tzinfo=UTC),
        ),
        (("framework_catalogs", 0, "framework", "name"), "Changed framework name"),
        (("framework_catalogs", 0, "references", 0, "title"), "Changed reference title"),
        (("framework_catalogs", 0, "references", 0, "description"), "Changed description"),
        (("framework_catalogs", 0, "mappings", 0, "mapping_rationale"), "Changed copy"),
        (("framework_catalogs", 0, "source_manifest", "sha256"), "0" * 64),
        (
            ("framework_catalogs", 0, "source_manifest", "retrieved_at"),
            datetime(2027, 1, 1, tzinfo=UTC),
        ),
    ],
)
def test_material_catalog_changes_alter_digest(path: tuple, changed_value: Any) -> None:
    catalog = build_default_control_catalog()
    values = catalog.model_dump(mode="python")
    parent = values
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = changed_value
    changed = ControlCatalog.model_validate(values)

    assert control_catalog_sha256(changed) != control_catalog_sha256(catalog)


@pytest.mark.parametrize("target", ["control_mapping", "framework_mapping", "source_manifest"])
def test_unchecked_naive_timestamps_are_rejected(target: str) -> None:
    catalog = build_default_control_catalog()
    naive = datetime(2026, 9, 3)
    if target == "control_mapping":
        control = catalog.controls[0]
        mapping = control.framework_mappings[0].model_copy(update={"verified_at": naive})
        control = control.model_copy(update={"framework_mappings": (mapping,)})
        catalog = catalog.model_copy(update={"controls": (control, *catalog.controls[1:])})
    else:
        framework = catalog.framework_catalogs[0]
        if target == "framework_mapping":
            mapping = framework.mappings[0].model_copy(update={"verified_at": naive})
            framework = framework.model_copy(
                update={"mappings": (mapping, *framework.mappings[1:])}
            )
        else:
            manifest = framework.source_manifest.model_copy(update={"retrieved_at": naive})
            framework = framework.model_copy(update={"source_manifest": manifest})
        catalog = catalog.model_copy(update={"framework_catalogs": (framework,)})

    with pytest.raises(ValidationError, match="must include a timezone"):
        control_catalog_sha256(catalog)


def test_unchecked_duplicate_controls_are_revalidated() -> None:
    catalog = build_default_control_catalog()
    invalid = catalog.model_copy(update={"controls": (*catalog.controls, catalog.controls[0])})

    with pytest.raises(ValidationError, match="duplicate technical control"):
        canonical_control_catalog_document(invalid)


def test_canonicalization_does_not_deduplicate_or_mutate_content() -> None:
    values = build_default_control_catalog().model_dump(mode="python")
    values["controls"][0]["technical"]["limitations"] = ("Repeated note", "Repeated note")
    catalog = ControlCatalog.model_validate(values)
    before = catalog.model_dump(mode="python")
    document = canonical_control_catalog_document(catalog)

    assert document["controls"][0]["technical"]["limitations"] == ["Repeated note", "Repeated note"]
    document["controls"][0]["technical"]["title"] = "Local document mutation"
    assert catalog.model_dump(mode="python") == before


def test_catalog_provenance_has_no_database_import_dependency() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; "
            "from app.assessment.controls import build_default_control_catalog; "
            "from app.assessment.provenance import control_catalog_sha256; "
            "control_catalog_sha256(build_default_control_catalog()); "
            "assert not any(name == 'app.database' or name.startswith('app.database.') "
            "or name == 'app.models' or name.startswith('app.models.') for name in sys.modules)",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
