"""Configuration management for BioDrift."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

_CONFIG_DIR = Path(
    os.environ.get("BIODRIFT_CONFIG", Path(__file__).parent.parent.parent / "config")
)


class ObserverConfig(BaseModel):
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)


class StorageConfig(BaseModel):
    db_path: str = "results/biodrift.db"
    evidence_dir: str = "results/evidence"


class CoverageConfig(BaseModel):
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25,
        }
    )
    threshold: float = 0.8


class DecisionConfig(BaseModel):
    min_attribution_confidence: float = 0.6
    # ponytail: calibrated — must sit above the mandatory-import floor (1/N).
    # 0.5 would admit a 2-cap contract's import-only state (cov=0.50).
    min_coverage: float = 0.8
    conflict_tolerance: float = 0.0


class BioDriftConfig(BaseModel):
    observers: dict[str, ObserverConfig] = Field(default_factory=dict)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    coverage: CoverageConfig = Field(default_factory=CoverageConfig)
    decision: DecisionConfig = Field(default_factory=DecisionConfig)
    verbosity: int = 1


def load_config(config_path: Path | None = None) -> BioDriftConfig:
    """Load config from YAML, falling back to defaults."""
    path = config_path or _CONFIG_DIR / "default.yaml"
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return BioDriftConfig(**data)
    return BioDriftConfig()


def load_observers_config(config_path: Path | None = None) -> dict[str, ObserverConfig]:
    """Load observer configuration."""
    path = config_path or _CONFIG_DIR / "observers.yaml"
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return {k: ObserverConfig(**v) for k, v in data.get("observers", {}).items()}
    return {}
