from __future__ import annotations

from pathlib import Path

from hecavex_radar.quality_artifacts import generate_quality_artifacts

ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_quality_artifacts_are_current_and_deterministic() -> None:
    generate_quality_artifacts(ROOT, check=True)
