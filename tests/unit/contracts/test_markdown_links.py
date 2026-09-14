"""Validate repository-local links in canonical Markdown documentation."""

import re
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parents[3]
INLINE_LINK = re.compile(r"!?\[[^\]]*\]\((?P<target>[^)]+)\)")


def _markdown_files() -> tuple[Path, ...]:
    root_documents = tuple(sorted(ROOT.glob("*.md")))
    detailed_documents = tuple(sorted((ROOT / "docs").rglob("*.md")))
    return root_documents + detailed_documents


def _local_targets(document: Path) -> tuple[Path, ...]:
    targets: list[Path] = []
    for match in INLINE_LINK.finditer(document.read_text(encoding="utf-8")):
        target = match.group("target").strip().strip("<>")
        if target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        path_text = unquote(target.split("#", maxsplit=1)[0])
        if path_text:
            targets.append((document.parent / path_text).resolve())
    return tuple(targets)


@pytest.mark.parametrize(
    "document",
    _markdown_files(),
    ids=lambda path: path.relative_to(ROOT).as_posix(),
)
def test_repository_local_markdown_links_resolve(document: Path) -> None:
    missing = [
        target.relative_to(ROOT).as_posix()
        for target in _local_targets(document)
        if not target.exists()
    ]

    assert missing == []
