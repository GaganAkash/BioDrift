"""Artifact intake: resolve package, digest, capture metadata, isolate candidate."""

from __future__ import annotations

import hashlib
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from biodrift.models import _uuid

try:
    import tomllib
except ImportError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]


class Environment(BaseModel):
    python_version: str = Field(default_factory=lambda: sys.version)
    os_name: str = Field(default_factory=lambda: platform.system())
    os_release: str = Field(default_factory=lambda: platform.release())
    architecture: str = Field(default_factory=lambda: platform.machine())
    executable: str = Field(default_factory=lambda: sys.executable)
    extra: dict[str, Any] = Field(default_factory=dict)


class Artifact(BaseModel):
    artifact_id: str = Field(default_factory=_uuid)
    path: Path
    package_name: str = ""
    version: str = ""
    digest: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    environment: Environment = Field(default_factory=Environment)
    isolated_dir: Path | None = None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_package(package_path: str | Path) -> Artifact:
    """Resolve a package from a path, computing its digest and metadata."""
    path = Path(package_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Package not found: {path}")

    digest = sha256_file(path) if path.is_file() else ""
    metadata: dict[str, Any] = {}

    if path.is_file() and path.suffix == ".whl":
        metadata["type"] = "wheel"
    elif path.is_dir() and (path / "pyproject.toml").exists():
        metadata["type"] = "source"

        with open(path / "pyproject.toml", "rb") as f:
            pyproject = tomllib.load(f)
        proj = pyproject.get("project", {})
        metadata["pyproject"] = {k: proj.get(k) for k in ["name", "version", "dependencies"]}
    elif path.is_dir() and ((path / "setup.py").exists() or (path / "setup.cfg").exists()):
        metadata["type"] = "legacy"

    pkg_name = metadata.get("pyproject", {}).get("name") or path.stem
    version = metadata.get("pyproject", {}).get("version") or "0.0.0"

    return Artifact(
        path=path,
        package_name=str(pkg_name),
        version=str(version),
        digest=digest,
        metadata=metadata,
        environment=Environment(),
    )


def isolate_candidate(artifact: Artifact) -> Path:
    """Copy artifact to a temp directory for safe execution."""
    tmpdir = Path(tempfile.mkdtemp(prefix="biodrift_"))
    if artifact.path.is_file():
        shutil.copy2(artifact.path, tmpdir)
    else:
        shutil.copytree(artifact.path, tmpdir / artifact.path.name, dirs_exist_ok=True)
    artifact.isolated_dir = tmpdir
    return tmpdir
