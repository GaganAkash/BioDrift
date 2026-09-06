"""Static analysis: identify sensitive capabilities and candidate security paths."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from biodrift.models import Capability


class AnalysisResult:
    def __init__(
        self,
        package_dir: Path,
        capabilities: list[dict[str, Any]],
        imports: list[str],
        security_paths: list[dict[str, Any]],
    ):
        self.package_dir = package_dir
        self.capabilities = capabilities
        self.imports = imports
        self.security_paths = security_paths

    def summary(self) -> dict[str, Any]:
        return {
            "package_dir": str(self.package_dir),
            "capabilities_found": len(self.capabilities),
            "imports": self.imports[:20],
            "security_paths": len(self.security_paths),
        }


_CAPABILITY_PATTERNS: dict[str, Capability] = {
    "open": Capability.FILE_READ,
    "write": Capability.FILE_WRITE,
    "remove": Capability.FILE_DELETE,
    "unlink": Capability.FILE_DELETE,
    "connect": Capability.NETWORK_CONNECT,
    "bind": Capability.NETWORK_LISTEN,
    "listen": Capability.NETWORK_LISTEN,
    "subprocess": Capability.PROCESS_SPAWN,
    "Popen": Capability.PROCESS_SPAWN,
    "system": Capability.SUBPROCESS_SHELL,
    "exec": Capability.PROCESS_EXEC,
    "eval": Capability.CODE_EXEC,
    "compile": Capability.CODE_EXEC,
    "environ": Capability.ENV_ACCESS,
    "getenv": Capability.ENV_ACCESS,
}


def analyze_package(package_dir: Path) -> AnalysisResult:
    """Perform AST-based static analysis to identify capabilities and imports."""
    capabilities: list[dict[str, Any]] = []
    imports: list[str] = []
    security_paths: list[dict[str, Any]] = []

    for py_file in package_dir.rglob("*.py"):
        try:
            source = py_file.read_text()
            tree = ast.parse(source)
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
            elif isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                for pattern, cap in _CAPABILITY_PATTERNS.items():
                    if pattern in func_name.lower():
                        capabilities.append(
                            {
                                "file": str(py_file),
                                "line": node.lineno,
                                "function": func_name,
                                "capability": cap.value,
                            }
                        )
                        security_paths.append(
                            {
                                "file": str(py_file),
                                "line": node.lineno,
                                "capability": cap.value,
                                "function": func_name,
                            }
                        )

    return AnalysisResult(
        package_dir=package_dir,
        capabilities=capabilities,
        imports=imports,
        security_paths=security_paths,
    )
