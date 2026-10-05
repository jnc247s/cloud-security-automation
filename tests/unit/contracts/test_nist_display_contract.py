"""Pin display DTO literals to the unchanged backend, not to prose or synthetic fixtures."""

import re
from pathlib import Path

from app.assessment.frameworks import FrameworkReferenceLevel
from app.schemas.technical_posture import AssessmentCounts

SOURCE = Path(__file__).resolve().parents[3] / "frontend" / "src" / "nist-api.ts"


def test_nist_display_levels_preserve_backend_serialized_values():
    source = SOURCE.read_text(encoding="utf-8")
    declaration = re.search(r"export type Level = ([^;]+);", source)
    assert declaration is not None
    assert set(re.findall(r"'([^']+)'", declaration[1])) == {
        level.value for level in FrameworkReferenceLevel
    }


def test_nist_display_counts_preserve_all_and_only_four_technical_states():
    source = SOURCE.read_text(encoding="utf-8")
    declaration = re.search(r"export const countFields = \[([^\]]+)\]", source)
    assert declaration is not None
    assert set(re.findall(r"'([^']+)'", declaration[1])) == set(AssessmentCounts.model_fields)
