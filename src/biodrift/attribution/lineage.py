"""Dependency lineage tracking."""

from __future__ import annotations

import ast
from pathlib import Path

from pydantic import BaseModel, Field


class LineageNode(BaseModel):
    name: str
    type: str = "module"
    version: str = ""
    source_path: str = ""
    children: list[LineageNode] = Field(default_factory=list)


def build_import_lineage(package_dir: Path) -> list[LineageNode]:
    """Parse Python files to build import dependency graph.

    ponytail: AST-based import extraction only. Real implementation
    would handle relative imports, conditional imports, and dynamic imports.
    """
    lineage: list[LineageNode] = []

    for py_file in package_dir.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text())
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    lineage.append(
                        LineageNode(
                            name=alias.name,
                            type="import",
                            source_path=str(py_file),
                        )
                    )
            elif isinstance(node, ast.ImportFrom) and node.module:
                lineage.append(
                    LineageNode(
                        name=node.module,
                        type="import_from",
                        source_path=str(py_file),
                    )
                )

    return lineage
